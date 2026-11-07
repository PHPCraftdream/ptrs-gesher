use std::{io, sync::Arc, time::Duration};

use percent_encoding::percent_decode_str;
use resocks5_net::connect::{dial_tcp, DialOptions};
use resocks5_net::secure_auth::SecureCredentials;
use resocks5_net::server::Reply;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};
use tokio::net::TcpStream;
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Dead-peer detection on the upstream socket: idle time and probe interval.
const KEEPALIVE: Duration = Duration::from_secs(15);

// One immutable upstream identity per managed PT process; never log its fields.
pub(crate) struct Proxy {
    // Validated once at startup by the SDK; reused by every connection.
    config: ProxyConfig,
}

impl Proxy {
    pub(crate) fn from_env() -> Result<Option<Arc<Self>>, ()> {
        Self::from_os(std::env::var_os("TOR_PT_PROXY"))
    }

    fn from_os(value: Option<std::ffi::OsString>) -> Result<Option<Arc<Self>>, ()> {
        match value {
            None => Ok(None),
            Some(value) if value.is_empty() => Ok(None),
            Some(value) => {
                Self::parse(value.to_str().ok_or(())?).map(|proxy| Some(Arc::new(proxy)))
            }
        }
    }

    /// A `user:password` is accepted only for SOCKS5 and is then proven with
    /// secure auth (SOCKS5 method 0x80): the password never crosses the wire.
    /// HTTP has no such method, so an HTTP proxy with credentials is refused.
    pub(crate) fn parse(input: &str) -> Result<Self, ()> {
        let (protocol, scheme, authority) = if let Some(authority) = input.strip_prefix("socks5://")
        {
            (ProxyProtocol::Socks5, "socks5", authority)
        } else if let Some(authority) = input.strip_prefix("http://") {
            (
                ProxyProtocol::Http,
                "http",
                authority.strip_suffix('/').unwrap_or(authority),
            )
        } else {
            return Err(());
        };
        if authority.is_empty()
            || authority.bytes().any(|byte| {
                byte <= 0x20 || byte == 0x7f || matches!(byte, b'/' | b'?' | b'#' | b'\\')
            })
        {
            return Err(());
        }
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((user, host)) if !user.contains('@') => (Some(user), host),
            Some(_) => return Err(()),
            None => (None, authority),
        };
        let address: std::net::SocketAddr = hostport.parse().map_err(|_| ())?;
        if address.port() == 0 {
            return Err(());
        }
        let parsed = Url::parse(input).map_err(|_| ())?;
        if parsed.scheme() != scheme
            || parsed.host().is_none()
            || parsed.port_or_known_default() != Some(address.port())
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || (!parsed.path().is_empty()
                && !(protocol == ProxyProtocol::Http && parsed.path() == "/"))
        {
            return Err(());
        }
        let mut config = ProxyConfig::new(protocol, address.ip().to_string(), address.port());
        config.validate_node().map_err(|_| ())?;
        if let Some(info) = userinfo {
            if protocol != ProxyProtocol::Socks5 {
                return Err(());
            }
            let (username, password) = info.split_once(':').ok_or(())?;
            let username = decode(username)?;
            let password = decode(password)?;
            // The SDK owns the RFC 1929 field rules (1..=255 bytes each); an
            // empty user-id is refused as well.
            if username.is_empty() {
                return Err(());
            }
            let mut checked = ProxyConfig::new(protocol, "127.0.0.1", 1)
                .try_with_auth(username.clone(), password.clone())
                .map_err(|_| ())?;
            checked.wipe_credentials();
            config = config.with_secure_auth(SecureCredentials::new(username, password));
        }
        Ok(Self { config })
    }

    /// cancel-safe: NO — cancellation discards the owned, partially negotiated stream.
    pub(crate) async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        self.connect_within(host, port, CONNECT_TIMEOUT).await
    }

    /// One `budget` covers the dial and every handshake stage together.
    async fn connect_within(
        &self,
        host: &str,
        port: u16,
        budget: Duration,
    ) -> io::Result<TcpStream> {
        if self.config.protocol == ProxyProtocol::Https
            || !valid_target_host(host)
            || host.len() > 255
            || port == 0
        {
            return Err(failure());
        }
        let options = DialOptions::new()
            .with_connect_timeout(budget)
            .with_handshake_timeout(budget)
            .with_total_timeout(budget)
            .with_nodelay(true)
            .with_keepalive(KEEPALIVE)
            .with_keepalive_interval(KEEPALIVE);
        dial_tcp(&self.config, host, port, &options)
            .await
            .map_err(|error| failure_with(error.suggested_reply()))
    }
}

/// The only thing a failed upstream connection tells the caller: the parent
/// reply that fits best. It carries no address, credential or peer text.
#[derive(Debug)]
pub(crate) struct UpstreamFailure(pub(crate) Reply);

impl std::fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upstream proxy connection failed")
    }
}

impl std::error::Error for UpstreamFailure {}

fn failure() -> io::Error {
    failure_with(Reply::UpstreamUnavailable)
}

fn failure_with(reply: Reply) -> io::Error {
    io::Error::other(UpstreamFailure(reply))
}

/// The parent reply recorded in an error from [`Proxy::connect`], if any.
pub(crate) fn failure_reply(error: &io::Error) -> Option<Reply> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<UpstreamFailure>())
        .map(|failure| failure.0)
}

/// The host is spliced into an HTTP request line, so whitespace and control
/// bytes (CR/LF injection) must never reach the upstream proxy.
fn valid_target_host(host: &str) -> bool {
    !host.is_empty() && !host.bytes().any(|b| b <= 0x20 || b == 0x7f)
}

fn decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_uri_validation_and_credential_decoding() {
        for input in [
            "socks5://127.0.0.1:1080",
            "socks5://user:p%40ss@[::1]:1080",
            "http://127.0.0.1:80",
            "http://127.0.0.1:80/",
        ] {
            assert!(Proxy::parse(input).is_ok());
        }
        let proxy = Proxy::parse("socks5://u%3Aname:p%40ss@127.0.0.1:1080").unwrap();
        // The user name is the upstream's identity; the password lives only
        // inside the secure-auth credentials, never in the clear-text field.
        assert_eq!(proxy.config.user.as_deref(), Some("u:name"));
        assert!(proxy.config.password.is_none());
        assert!(proxy.config.secure_auth.is_some());
        for input in [
            "https://127.0.0.1:1080",
            "socks5://example.com:1080",
            "socks5://u:%XX@127.0.0.1:1080",
            "socks5://u:@127.0.0.1:1080",
            "socks5://:p@127.0.0.1:1080",
            "socks5://127.0.0.1:0",
            "socks5://127.0.0.1:1080/path",
            // HTTP has no secure method: a password would travel in clear text.
            "http://user:p%40ss@[::1]:8080",
            "http://user:@127.0.0.1:8080",
            "http://u%3Aname:p@127.0.0.1:8080",
            "http://user:p%0A@127.0.0.1:8080",
            "http://127.0.0.1:8080/path",
        ] {
            assert!(Proxy::parse(input).is_err());
        }
    }

    #[test]
    fn proxy_uri_degenerate_forms_are_rejected() {
        for input in [
            "socks5://127.0.0.1:1080?x=1",
            "socks5://127.0.0.1:1080#frag",
            "http://127.0.0.1:8080?x=1",
            "socks5://[::1%25eth0]:1080",
            "socks5://a@b@127.0.0.1:1080",
            "socks5://",
            "http://",
            "socks5://@127.0.0.1:1080",
            "socks5://@:1080",
            "socks5://127.0.0.1",
            "http://127.0.0.1",
            "socks5://127.0.0.1:65536",
            "SOCKS5://127.0.0.1:1080",
            "socks5://u:p@127.0.0.1:1080 ",
            "socks5://u:p\r\n@127.0.0.1:1080",
        ] {
            assert!(Proxy::parse(input).is_err(), "{input:?} must be rejected");
        }
    }

    #[test]
    fn socks5_credential_length_boundaries_are_exact() {
        let max = "x".repeat(255);
        let over = "x".repeat(256);
        assert!(Proxy::parse(&format!("socks5://{max}:{max}@127.0.0.1:1080")).is_ok());
        assert!(Proxy::parse(&format!("socks5://{over}:p@127.0.0.1:1080")).is_err());
        assert!(Proxy::parse(&format!("socks5://u:{over}@127.0.0.1:1080")).is_err());
        // 255 decoded bytes may arrive as a longer percent-encoded string.
        let encoded = "%41".repeat(255);
        let proxy = Proxy::parse(&format!("socks5://{encoded}:p@127.0.0.1:1080")).unwrap();
        assert_eq!(proxy.config.user.unwrap(), "A".repeat(255));
    }

    #[test]
    fn proxy_from_os_handles_unset_empty_valid_and_non_unicode_values() {
        use std::ffi::OsString;

        assert!(matches!(Proxy::from_os(None), Ok(None)));
        assert!(matches!(Proxy::from_os(Some(OsString::new())), Ok(None)));
        assert!(matches!(
            Proxy::from_os(Some("socks5://127.0.0.1:1080".into())),
            Ok(Some(_))
        ));
        #[cfg(unix)]
        let non_unicode = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(b"socks5://127.0.0.1:1080/\xff".to_vec())
        };
        #[cfg(windows)]
        let non_unicode = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[0xD800])
        };
        assert!(non_unicode.to_str().is_none());
        assert!(Proxy::from_os(Some(non_unicode)).is_err());
    }

    #[test]
    fn target_host_validation_rejects_injection_bytes() {
        for good in ["carrier.invalid", "2001:db8::1", "192.0.2.1", "a"] {
            assert!(valid_target_host(good), "{good:?}");
        }
        for bad in [
            "",
            " ",
            "a b",
            "a\tb",
            "a\r\nX-Injected: 1",
            "a\nb",
            "a\0b",
            "a\x7fb",
        ] {
            assert!(!valid_target_host(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn connect_rejects_bad_targets_before_touching_the_network() {
        for scheme in ["socks5", "http"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy =
                Proxy::parse(&format!("{scheme}://{}", listener.local_addr().unwrap())).unwrap();
            let oversized = "h".repeat(256);
            for (host, port) in [
                ("carrier.invalid", 0),
                ("", 443),
                (oversized.as_str(), 443),
                ("host\r\nProxy-Authorization: Basic AAAA", 443),
                ("host\nX: y", 443),
                ("ho st", 443),
                ("host\0", 443),
            ] {
                let error = proxy.connect(host, port).await.unwrap_err();
                assert_eq!(error.to_string(), "upstream proxy connection failed");
            }
            // Rejected up front: the proxy never saw a connection attempt.
            let dialed = tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
            assert!(dialed.is_err(), "{scheme}: no connection may be attempted");
        }
    }

    use resocks5_net::secure_auth::{KdfParams, UserSecret};
    use resocks5_net::testing::{MockAuth, MockUpstream, MockUpstreamBuilder, Script};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn proxy_for(scheme: &str, mock: &MockUpstream) -> Proxy {
        Proxy::parse(&format!("{scheme}://{}", mock.addr())).unwrap()
    }

    fn builder(scheme: &str) -> MockUpstreamBuilder {
        if scheme == "socks5" {
            MockUpstream::socks5()
        } else {
            MockUpstream::http()
        }
    }

    /// Secure-auth credentials for user `u`, password `p@ss`.
    fn secure(builder: MockUpstreamBuilder) -> MockUpstreamBuilder {
        builder.auth(MockAuth::Secure {
            user: "u".into(),
            secret: UserSecret::from_password("p@ss", KdfParams::DEFAULT).unwrap(),
        })
    }

    async fn assert_echo(stream: &mut TcpStream) {
        stream.write_all(b"carrier-ready").await.unwrap();
        let mut payload = [0; 13];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"carrier-ready");
    }

    async fn delayed_carrier(
        delay: Duration,
        budget: Duration,
    ) -> (io::Result<TcpStream>, Duration) {
        let mock = MockUpstream::socks5()
            .reply_delay(delay)
            .spawn()
            .await
            .unwrap();
        let proxy = proxy_for("socks5", &mock);
        let started = Instant::now();
        let outcome = proxy.connect_within("carrier.invalid", 443, budget).await;
        (outcome, started.elapsed())
    }

    #[tokio::test]
    async fn carrier_handshake_has_one_whole_operation_deadline() {
        // Real time on purpose: a paused clock can race real socket I/O. The
        // upstream pauses before its greeting reply and before its CONNECT
        // reply, each less than the 2 s budget: a per-stage timer would let
        // both runs finish; only one deadline for the whole handshake tells
        // them apart (2 x 0.6 s fits, 2 x 1.4 s does not).
        let budget = Duration::from_secs(2);
        let (fits, took) = delayed_carrier(Duration::from_millis(600), budget).await;
        assert!(
            fits.is_ok(),
            "a 1.2 s handshake fits in {budget:?}: {fits:?}"
        );
        assert!(took < budget, "{took:?}");

        let (overruns, took) = delayed_carrier(Duration::from_millis(1400), budget).await;
        let error = overruns.expect_err("a 2.8 s handshake must hit the original deadline");
        assert_eq!(error.to_string(), "upstream proxy connection failed");
        assert_eq!(failure_reply(&error), Some(Reply::TimedOut));
        assert!(
            took >= budget && took < Duration::from_millis(2600),
            "the deadline is fixed at the start, not renewed per stage: {took:?}"
        );
    }

    #[tokio::test]
    async fn carrier_preserves_remote_hostname_and_payload() {
        for (scheme, with_password) in [("socks5", false), ("http", false), ("socks5", true)] {
            let mock = if with_password {
                secure(builder(scheme)).spawn().await.unwrap()
            } else {
                builder(scheme).spawn().await.unwrap()
            };
            let uri = if with_password {
                format!("socks5://u:p%40ss@{}", mock.addr())
            } else {
                format!("{scheme}://{}", mock.addr())
            };
            let mut stream = Proxy::parse(&uri)
                .unwrap()
                .connect("carrier.invalid", 443)
                .await
                .unwrap();
            assert_echo(&mut stream).await;
            assert_eq!(
                mock.targets(),
                ["carrier.invalid:443"],
                "{scheme} {with_password}"
            );
        }
    }

    #[tokio::test]
    async fn carrier_formats_ipv6_targets_and_tunes_socket() {
        for scheme in ["socks5", "http"] {
            let mock = builder(scheme).spawn().await.unwrap();
            let stream = proxy_for(scheme, &mock)
                .connect("2001:db8::1", 443)
                .await
                .unwrap();
            assert_eq!(mock.targets(), ["[2001:db8::1]:443"], "{scheme}");
            assert!(stream.nodelay().unwrap());
        }
    }

    #[tokio::test]
    async fn upstream_login_failures_are_our_side_errors_not_target_verdicts() {
        // A wrong password or a refused method is the operator's configuration,
        // so the parent hears "general failure" - never "forbidden".
        let cases = [
            ("socks5", "u:p@", MockAuth::SecureDenied),
            ("socks5", "u:p@", MockAuth::AuthStatus(0xFF)),
            ("socks5", "", MockAuth::NoAcceptableMethod),
            ("http", "", MockAuth::NoAcceptableMethod),
        ];
        for (scheme, userinfo, auth) in cases {
            let label = format!("{scheme} {auth:?}");
            let mock = builder(scheme).auth(auth).spawn().await.unwrap();
            let uri = format!("{scheme}://{userinfo}{}", mock.addr());
            let error = Proxy::parse(&uri)
                .unwrap()
                .connect("carrier.invalid", 443)
                .await
                .expect_err("a failed login must fail the carrier");
            assert_eq!(
                failure_reply(&error),
                Some(Reply::GeneralFailure),
                "{label}"
            );
            assert!(
                mock.targets().is_empty(),
                "{label}: no CONNECT after a failed login"
            );
        }
    }

    #[tokio::test]
    async fn upstream_failing_at_any_stage_is_terminal() {
        let budget = Duration::from_millis(500);
        // Stalls before it spoke its protocol: the upstream is down.
        let silent = MockUpstream::socks5()
            .script(Script::SilentGreeting)
            .spawn()
            .await
            .unwrap();
        let error = proxy_for("socks5", &silent)
            .connect_within("carrier.invalid", 443, budget)
            .await
            .unwrap_err();
        assert_eq!(failure_reply(&error), Some(Reply::UpstreamUnavailable));
        // A stalled CONNECT may be the destination's fault.
        let stalled = MockUpstream::socks5()
            .script(Script::SilentConnect)
            .spawn()
            .await
            .unwrap();
        let error = proxy_for("socks5", &stalled)
            .connect_within("carrier.invalid", 443, budget)
            .await
            .unwrap_err();
        assert_eq!(failure_reply(&error), Some(Reply::TimedOut));
        // A vanished upstream fails promptly, whatever the exact reply.
        let hangup = MockUpstream::socks5()
            .script(Script::Hangup)
            .spawn()
            .await
            .unwrap();
        let started = Instant::now();
        let error = proxy_for("socks5", &hangup)
            .connect_within("carrier.invalid", 443, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(failure_reply(&error).is_some());
        assert!(started.elapsed() < Duration::from_secs(4));
        // Nothing listens: the TCP connect itself fails.
        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let error = Proxy::parse(&format!("socks5://{closed}"))
            .unwrap()
            .connect("carrier.invalid", 443)
            .await
            .unwrap_err();
        assert_eq!(failure_reply(&error), Some(Reply::UpstreamUnavailable));
    }

    #[tokio::test]
    async fn upstream_refusals_reach_the_caller_as_specific_replies() {
        let cases = [
            ("socks5", 1, Reply::GeneralFailure),
            ("socks5", 2, Reply::Forbidden),
            ("socks5", 3, Reply::NetworkUnreachable),
            ("socks5", 4, Reply::UpstreamUnavailable),
            ("socks5", 5, Reply::ConnectionRefused),
            ("socks5", 6, Reply::TimedOut),
            ("http", 403, Reply::Forbidden),
            ("http", 407, Reply::GeneralFailure),
            ("http", 502, Reply::UpstreamUnavailable),
            ("http", 504, Reply::TimedOut),
        ];
        for (scheme, code, expected) in cases {
            let mock = builder(scheme)
                .script(Script::Refuse(code))
                .spawn()
                .await
                .unwrap();
            let error = proxy_for(scheme, &mock)
                .connect("carrier.invalid", 443)
                .await
                .expect_err("a refusing upstream must fail the carrier");
            assert_eq!(error.to_string(), "upstream proxy connection failed");
            assert_eq!(failure_reply(&error), Some(expected), "{scheme} {code}");
        }
    }

    #[tokio::test]
    async fn carrier_handshake_survives_one_byte_replies() {
        // Replies arrive one byte per write: a client that assumes whole
        // replies per `read` fails here.
        for (scheme, with_password) in [("socks5", false), ("http", false), ("socks5", true)] {
            let base = builder(scheme).drip(true);
            let mock = if with_password {
                secure(base).spawn().await.unwrap()
            } else {
                base.spawn().await.unwrap()
            };
            let uri = if with_password {
                format!("socks5://u:p%40ss@{}", mock.addr())
            } else {
                format!("{scheme}://{}", mock.addr())
            };
            let mut stream = Proxy::parse(&uri)
                .unwrap()
                .connect("carrier.invalid", 443)
                .await
                .unwrap();
            assert_echo(&mut stream).await;
        }
    }

    #[tokio::test]
    async fn carrier_never_sends_a_clear_text_password() {
        // Even a server that demands RFC 1929 username/password gets no
        // password: the greeting never offers method 0x02 and nothing follows
        // the server's choice of it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Proxy::parse(&format!(
            "socks5://user:secret-token@{}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0; 2];
            stream.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0; usize::from(head[1])];
            stream.read_exact(&mut methods).await.unwrap();
            assert!(!methods.contains(&2), "offered methods: {methods:?}");
            stream.write_all(&[5, 2]).await.unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            assert!(
                rest.is_empty(),
                "nothing may follow a refused method: {rest:?}"
            );
        };
        let client = async {
            let error = proxy.connect("carrier.invalid", 443).await.unwrap_err();
            assert_eq!(failure_reply(&error), Some(Reply::GeneralFailure));
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("the refused method must terminate the carrier");
    }
}
