use std::{io, sync::Arc, time::Duration};

use percent_encoding::percent_decode_str;
use resocks5_net::connect::{dial_tcp, DialOptions};
use resocks5_net::server::Reply;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};
use tokio::net::TcpStream;
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Dead-peer detection on the upstream socket: idle time and probe interval.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// Selects how a `TOR_PT_PROXY` password is used.
const AUTH_MODE_VAR: &str = "LYREBIRD_PROXY_AUTH";

/// How proxy credentials are presented to the upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthMode {
    /// Any standard proxy: SOCKS5 offers secure auth (0x80) and RFC 1929
    /// (0x02), the upstream picks; HTTP sends `Basic` in the CONNECT.
    Standard,
    /// Only secure auth (SOCKS5 0x80, HTTP `Resocks5-Secure`): an upstream
    /// without it fails before any password byte is sent. No downgrade.
    SecureOnly,
}

impl AuthMode {
    fn from_os(value: Option<std::ffi::OsString>) -> Result<Self, ()> {
        match value.as_deref().map(|value| value.to_str()) {
            None => Ok(Self::Standard),
            Some(Some("" | "standard")) => Ok(Self::Standard),
            Some(Some("secure")) => Ok(Self::SecureOnly),
            Some(_) => Err(()),
        }
    }
}

// One immutable upstream identity per managed PT process; never log its fields.
pub(crate) struct Proxy {
    // Validated once at startup by the SDK; reused by every connection.
    config: ProxyConfig,
}

impl Proxy {
    pub(crate) fn from_env() -> Result<Option<Arc<Self>>, ()> {
        Self::from_os(
            std::env::var_os("TOR_PT_PROXY"),
            std::env::var_os(AUTH_MODE_VAR),
        )
    }

    fn from_os(
        value: Option<std::ffi::OsString>,
        mode: Option<std::ffi::OsString>,
    ) -> Result<Option<Arc<Self>>, ()> {
        // The mode only matters (and is only checked) when a proxy is set.
        match value {
            None => Ok(None),
            Some(value) if value.is_empty() => Ok(None),
            Some(value) => {
                let mode = AuthMode::from_os(mode)?;
                Self::parse_with(value.to_str().ok_or(())?, mode).map(|proxy| Some(Arc::new(proxy)))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn parse(input: &str) -> Result<Self, ()> {
        Self::parse_with(input, AuthMode::Standard)
    }

    /// `user:password` (both 1..=255 bytes) works with SOCKS5 and HTTP; see
    /// [`AuthMode`] for how it reaches the upstream. Secure-only mode without
    /// credentials is a configuration error.
    pub(crate) fn parse_with(input: &str, mode: AuthMode) -> Result<Self, ()> {
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
        match userinfo {
            Some(info) => {
                let (username, password) = info.split_once(':').ok_or(())?;
                let username = decode(username)?;
                let password = decode(password)?;
                // RFC 1929 field limits for both protocols; the SDK adds the
                // HTTP rules (no `:` in the user, no control characters).
                if !(1..=255).contains(&username.len()) || !(1..=255).contains(&password.len()) {
                    return Err(());
                }
                config = config.try_with_auth(username, password).map_err(|_| ())?;
                if mode == AuthMode::SecureOnly {
                    config = config.secure_only();
                }
            }
            None if mode == AuthMode::SecureOnly => return Err(()),
            None => {}
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
        dial_tcp(&self.config, host, port, &dial_options(budget))
            .await
            .map_err(|error| failure_with(error.suggested_reply()))
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // The password is held for the process lifetime; wipe it on the way out.
        self.config.wipe_credentials();
    }
}

/// Stage timers end strictly before the whole-operation deadline: equal
/// deadlines race, and the losing timer decides between REP=4 (silent
/// upstream) and REP=6 (budget spent) at random.
fn dial_options(budget: Duration) -> DialOptions {
    let stage = budget - budget / 10;
    DialOptions::new()
        .with_connect_timeout(stage)
        .with_handshake_timeout(stage)
        .with_total_timeout(budget)
        .with_nodelay(true)
        .with_keepalive(KEEPALIVE)
        .with_keepalive_interval(KEEPALIVE)
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
            "http://user:p%40ss@[::1]:8080",
        ] {
            assert!(Proxy::parse(input).is_ok(), "{input:?}");
        }
        // Standard mode keeps the pair for RFC 1929 / Basic and adds secure
        // credentials so an upstream that knows 0x80 can pick it.
        for (input, user) in [
            ("socks5://u%3Aname:p%40ss@127.0.0.1:1080", "u:name"),
            ("http://user:p%40ss@127.0.0.1:8080", "user"),
        ] {
            let proxy = Proxy::parse(input).unwrap();
            assert_eq!(proxy.config.user.as_deref(), Some(user));
            assert_eq!(proxy.config.password.as_deref(), Some("p@ss"));
            assert!(proxy.config.secure_auth.is_some());
            assert!(!proxy.config.secure_only);
        }
        for input in [
            "https://127.0.0.1:1080",
            "socks5://example.com:1080",
            "socks5://u:%XX@127.0.0.1:1080",
            "socks5://u:@127.0.0.1:1080",
            "socks5://:p@127.0.0.1:1080",
            "socks5://127.0.0.1:0",
            "socks5://127.0.0.1:1080/path",
            "http://user:@127.0.0.1:8080",
            "http://:p@127.0.0.1:8080",
            // Basic splits at the first `:`; a control byte would break the header.
            "http://u%3Aname:p@127.0.0.1:8080",
            "http://user:p%0A@127.0.0.1:8080",
            "http://127.0.0.1:8080/path",
        ] {
            assert!(Proxy::parse(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn secure_only_mode_needs_credentials_and_never_offers_clear_text() {
        for input in ["socks5://u:p@127.0.0.1:1080", "http://u:p@127.0.0.1:8080"] {
            let proxy = Proxy::parse_with(input, AuthMode::SecureOnly).unwrap();
            assert!(proxy.config.secure_only, "{input}");
            assert!(!proxy.config.allow_cleartext, "{input}");
            assert!(proxy.config.secure_auth.is_some(), "{input}");
        }
        // Asking for secure auth without a password is a configuration error.
        for input in ["socks5://127.0.0.1:1080", "http://127.0.0.1:8080"] {
            assert!(Proxy::parse_with(input, AuthMode::SecureOnly).is_err());
        }
    }

    #[test]
    fn auth_mode_variable_accepts_only_known_values() {
        use std::ffi::OsString;

        for (value, mode) in [
            (None, AuthMode::Standard),
            (Some(""), AuthMode::Standard),
            (Some("standard"), AuthMode::Standard),
            (Some("secure"), AuthMode::SecureOnly),
        ] {
            assert_eq!(AuthMode::from_os(value.map(OsString::from)), Ok(mode));
        }
        for value in ["Secure", "secure-only", "basic", " secure"] {
            assert!(AuthMode::from_os(Some(value.into())).is_err(), "{value:?}");
        }
        // Without a proxy the mode is irrelevant: no PROXY-ERROR.
        assert!(matches!(
            Proxy::from_os(None, Some("bogus".into())),
            Ok(None)
        ));
        // A bad mode fails the proxy setup even when the URI is fine.
        assert!(Proxy::from_os(
            Some("socks5://u:p@127.0.0.1:1080".into()),
            Some("bogus".into())
        )
        .is_err());
        assert!(matches!(
            Proxy::from_os(
                Some("socks5://u:p@127.0.0.1:1080".into()),
                Some("secure".into())
            ),
            Ok(Some(proxy)) if proxy.config.secure_only
        ));
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
    fn credential_length_boundaries_are_exact() {
        let max = "x".repeat(255);
        let over = "x".repeat(256);
        for scheme in ["socks5", "http"] {
            let ok = Proxy::parse(&format!("{scheme}://{max}:{max}@127.0.0.1:1080"));
            assert!(ok.is_ok(), "{scheme}");
            let long_user = Proxy::parse(&format!("{scheme}://{over}:p@127.0.0.1:1080"));
            assert!(long_user.is_err(), "{scheme}");
            let long_password = Proxy::parse(&format!("{scheme}://u:{over}@127.0.0.1:1080"));
            assert!(long_password.is_err(), "{scheme}");
        }
        // 255 decoded bytes may arrive as a longer percent-encoded string.
        let encoded = "%41".repeat(255);
        let proxy = Proxy::parse(&format!("socks5://{encoded}:p@127.0.0.1:1080")).unwrap();
        assert_eq!(proxy.config.user.as_deref(), Some("A".repeat(255).as_str()));
    }

    #[test]
    fn proxy_from_os_handles_unset_empty_valid_and_non_unicode_values() {
        use std::ffi::OsString;

        assert!(matches!(Proxy::from_os(None, None), Ok(None)));
        assert!(matches!(
            Proxy::from_os(Some(OsString::new()), None),
            Ok(None)
        ));
        assert!(matches!(
            Proxy::from_os(Some("socks5://127.0.0.1:1080".into()), None),
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
        assert!(Proxy::from_os(Some(non_unicode.clone()), None).is_err());
        assert!(Proxy::from_os(Some("socks5://127.0.0.1:1080".into()), Some(non_unicode)).is_err());
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

    /// A standard proxy: RFC 1929 / `Basic` only, user `u`, password `p@ss`.
    fn cleartext(builder: MockUpstreamBuilder) -> MockUpstreamBuilder {
        builder.auth(MockAuth::Cleartext {
            user: "u".into(),
            password: "p@ss".into(),
        })
    }

    /// Every upstream login this crate must handle, with the URI userinfo.
    fn login_matrix() -> Vec<(&'static str, &'static str, MockUpstreamBuilder)> {
        let mut cases = Vec::new();
        for scheme in ["socks5", "http"] {
            cases.push((scheme, "", builder(scheme)));
            cases.push((scheme, "u:p%40ss@", cleartext(builder(scheme))));
            cases.push((scheme, "u:p%40ss@", secure(builder(scheme))));
        }
        cases
    }

    async fn assert_echo(stream: &mut TcpStream) {
        stream.write_all(b"carrier-ready").await.unwrap();
        let mut payload = [0; 13];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"carrier-ready");
    }

    /// The SDK handshake under [`dial_options`]`(budget)` over an in-memory
    /// pipe to `mock`: the same SOCKS5 handshake and deadlines as
    /// `dial_tcp`, minus the socket. With no real I/O a paused clock is
    /// exact, so the outcome and the instant it lands on cannot depend on
    /// how busy the machine is.
    async fn dial_in_memory(
        mock: &MockUpstream,
        budget: Duration,
    ) -> (Result<(), Reply>, Duration) {
        let proxy = proxy_for("socks5", mock);
        let started = tokio::time::Instant::now();
        let outcome = resocks5_net::connect::dial_chain_over(
            mock.connect_in_memory(),
            &proxy.config,
            "carrier.invalid",
            443,
            &dial_options(budget),
            None,
        )
        .await
        .map(drop)
        .map_err(|error| error.error().suggested_reply());
        (outcome, started.elapsed())
    }

    /// `took` is `expected` up to the paused clock's millisecond rounding.
    fn lands_on(took: Duration, expected: Duration) -> bool {
        took >= expected && took <= expected + Duration::from_millis(2)
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_handshake_has_one_whole_operation_deadline() {
        // The upstream pauses before its greeting reply and before its
        // CONNECT reply, each shorter than the stage timer: a timer renewed
        // per phase would let 2 x 1.4 s run until the 2 s cap; one deadline
        // for the whole handshake ends it at 0.9 of the budget.
        let budget = Duration::from_secs(2);
        let mock = MockUpstream::socks5()
            .reply_delay(Duration::from_millis(600))
            .spawn()
            .await
            .unwrap();
        let (fits, took) = dial_in_memory(&mock, budget).await;
        assert_eq!(fits, Ok(()), "a 1.2 s handshake fits in {budget:?}");
        assert!(lands_on(took, Duration::from_millis(1200)), "{took:?}");

        let mock = MockUpstream::socks5()
            .reply_delay(Duration::from_millis(1400))
            .spawn()
            .await
            .unwrap();
        let (overruns, took) = dial_in_memory(&mock, budget).await;
        assert_eq!(overruns, Err(Reply::TimedOut));
        assert!(
            lands_on(took, budget - budget / 10),
            "the deadline is fixed at the start, not renewed per phase: {took:?}"
        );
    }

    #[tokio::test]
    async fn carrier_preserves_remote_hostname_and_payload() {
        // Anonymous, a standard RFC 1929 / Basic proxy, and a secure-auth peer.
        for (scheme, userinfo, upstream) in login_matrix() {
            let mock = upstream.spawn().await.unwrap();
            let uri = format!("{scheme}://{userinfo}{}", mock.addr());
            let mut stream = Proxy::parse(&uri)
                .unwrap()
                .connect("carrier.invalid", 443)
                .await
                .unwrap_or_else(|error| panic!("{uri}: {error}"));
            assert_echo(&mut stream).await;
            assert_eq!(mock.targets(), ["carrier.invalid:443"], "{uri}");
        }
    }

    #[tokio::test]
    async fn secure_only_mode_works_with_a_secure_auth_peer() {
        for scheme in ["socks5", "http"] {
            let mock = secure(builder(scheme)).spawn().await.unwrap();
            let uri = format!("{scheme}://u:p%40ss@{}", mock.addr());
            let mut stream = Proxy::parse_with(&uri, AuthMode::SecureOnly)
                .unwrap()
                .connect("carrier.invalid", 443)
                .await
                .unwrap_or_else(|error| panic!("{uri}: {error}"));
            assert_echo(&mut stream).await;
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
            (
                "socks5",
                "u:p@",
                builder("socks5").auth(MockAuth::SecureDenied),
            ),
            (
                "socks5",
                "u:p@",
                builder("socks5").auth(MockAuth::AuthStatus(0xFF)),
            ),
            (
                "socks5",
                "",
                builder("socks5").auth(MockAuth::NoAcceptableMethod),
            ),
            (
                "http",
                "",
                builder("http").auth(MockAuth::NoAcceptableMethod),
            ),
            // A standard proxy refusing a wrong password.
            ("socks5", "u:wrong@", cleartext(builder("socks5"))),
            ("http", "u:wrong@", cleartext(builder("http"))),
        ];
        for (scheme, userinfo, upstream) in cases {
            let label = format!("{scheme} {userinfo}");
            let mock = upstream.spawn().await.unwrap();
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

    #[test]
    fn stage_timers_end_before_the_whole_operation_deadline() {
        // Regression: equal timers raced, so a silent upstream got REP=4 or
        // REP=6 depending on which one the runtime polled first.
        for budget in [
            Duration::from_millis(1),
            Duration::from_millis(500),
            CONNECT_TIMEOUT,
        ] {
            let options = dial_options(budget);
            assert_eq!(options.total_timeout, Some(budget));
            assert!(options.connect_timeout < budget, "{budget:?}");
            assert!(options.handshake_timeout < budget, "{budget:?}");
        }
        assert_eq!(
            dial_options(CONNECT_TIMEOUT).handshake_timeout,
            Duration::from_secs(9)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_upstream_is_always_reported_unavailable() {
        // Regression for the same race, end to end: the stage timer must end
        // the dial at 0.9 of the budget and name the silent upstream. With
        // equal timers the dial would run to the full budget instead.
        let silent = MockUpstream::socks5()
            .script(Script::SilentGreeting)
            .spawn()
            .await
            .unwrap();
        let budget = Duration::from_secs(1);
        let (outcome, took) = dial_in_memory(&silent, budget).await;
        assert_eq!(outcome, Err(Reply::UpstreamUnavailable));
        assert!(lands_on(took, budget - budget / 10), "{took:?}");
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
        for (scheme, userinfo, upstream) in login_matrix() {
            let mock = upstream.drip(true).spawn().await.unwrap();
            let uri = format!("{scheme}://{userinfo}{}", mock.addr());
            let mut stream = Proxy::parse(&uri)
                .unwrap()
                .connect("carrier.invalid", 443)
                .await
                .unwrap_or_else(|error| panic!("{uri}: {error}"));
            assert_echo(&mut stream).await;
        }
    }

    #[tokio::test]
    async fn standard_socks5_greeting_offers_secure_auth_before_rfc1929() {
        // The upstream picks: a secure-auth peer takes 0x80, any other
        // password proxy takes 0x02 and gets the plain RFC 1929 exchange.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Proxy::parse(&format!(
            "socks5://user:secret@{}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0; 2];
            stream.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0; usize::from(head[1])];
            stream.read_exact(&mut methods).await.unwrap();
            let secure = methods.iter().position(|&m| m == 0x80);
            let rfc1929 = methods.iter().position(|&m| m == 0x02);
            assert!(
                matches!((secure, rfc1929), (Some(s), Some(r)) if s < r),
                "{methods:?}"
            );
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0; 13];
            stream.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x04user\x06secret");
        };
        let client = async {
            let _ = proxy.connect("carrier.invalid", 443).await;
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("the standard exchange must finish");
    }

    #[tokio::test]
    async fn secure_only_socks5_never_sends_a_clear_text_password() {
        // Even a server that demands RFC 1929 username/password gets no
        // password: the greeting never offers method 0x02 and nothing follows
        // the server's choice of it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Proxy::parse_with(
            &format!(
                "socks5://user:secret-token@{}",
                listener.local_addr().unwrap()
            ),
            AuthMode::SecureOnly,
        )
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

    #[tokio::test]
    async fn secure_only_http_never_sends_basic() {
        // A Basic-only proxy answers 407: the client must not send the
        // password, in the first CONNECT or after the challenge.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Proxy::parse_with(
            &format!(
                "http://user:secret-token@{}",
                listener.local_addr().unwrap()
            ),
            AuthMode::SecureOnly,
        )
        .unwrap();
        let server = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut chunk = [0; 512];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "closed before the head ended");
                seen.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"x\"\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest).await;
            seen.extend_from_slice(&rest);
            let text = String::from_utf8_lossy(&seen).to_ascii_lowercase();
            assert!(!text.contains("proxy-authorization"), "{text}");
            assert!(!text.contains("secret-token"), "{text}");
        };
        let client = async {
            let error = proxy.connect("carrier.invalid", 443).await.unwrap_err();
            assert_eq!(failure_reply(&error), Some(Reply::GeneralFailure));
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("the refused scheme must terminate the carrier");
    }
}
