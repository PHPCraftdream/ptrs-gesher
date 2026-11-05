use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use percent_encoding::percent_decode_str;
use resocks5_net::connect::{http_connect_handshake, socks5_handshake, HostPort};
use resocks5_net::types::{ProxyConfig, ProxyProtocol};
use tokio::{net::TcpStream, time::Instant};
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// One immutable upstream identity per managed PT process; never log its fields.
pub(crate) struct Proxy {
    protocol: ProxyProtocol,
    address: SocketAddr,
    credentials: Option<(String, String)>,
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
        let address: SocketAddr = hostport.parse().map_err(|_| ())?;
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
        let credentials = match userinfo {
            None => None,
            Some(info) => {
                let (username, password) = info.split_once(':').ok_or(())?;
                let username = decode(username)?;
                let password = decode(password)?;
                // RFC 1929 limits SOCKS5 fields; HTTP Basic (RFC 7617) only
                // forbids ':' in the user-id and control characters.
                let invalid = if protocol == ProxyProtocol::Http {
                    username.is_empty()
                        || username.contains(':')
                        || username.bytes().any(|byte| byte.is_ascii_control())
                        || password.bytes().any(|byte| byte.is_ascii_control())
                } else {
                    username.is_empty()
                        || password.is_empty()
                        || username.len() > 255
                        || password.len() > 255
                };
                if invalid {
                    return Err(());
                }
                Some((username, password))
            }
        };
        Ok(Self {
            protocol,
            address,
            credentials,
        })
    }

    /// cancel-safe: NO — cancellation discards the owned, partially negotiated stream.
    pub(crate) async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        if self.protocol == ProxyProtocol::Https
            || !valid_target_host(host)
            || host.len() > 255
            || port == 0
        {
            return Err(failure());
        }
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            let mut stream = TcpStream::connect(self.address)
                .await
                .map_err(|_| failure())?;
            super::tune_outgoing(&stream);
            match self.protocol {
                ProxyProtocol::Socks5 => {
                    let auth = self
                        .credentials
                        .as_ref()
                        .map(|(user, password)| (user.as_str(), password.as_str()));
                    socks5_handshake(stream, host, port, auth)
                        .await
                        .map_err(|_| failure())
                }
                ProxyProtocol::Http => {
                    let mut config = ProxyConfig::new(
                        ProxyProtocol::Http,
                        self.address.ip().to_string(),
                        self.address.port(),
                    );
                    if let Some((user, password)) = &self.credentials {
                        config.user = Some(user.clone());
                        config.password = Some(password.clone());
                    }
                    let target = HostPort::format(host, port);
                    http_connect_handshake(&mut stream, &target, &config)
                        .await
                        .map_err(|_| failure())?;
                    Ok(stream)
                }
                ProxyProtocol::Https => Err(failure()),
            }
        })
        .await
        .map_err(|_| failure())?
    }
}

fn failure() -> io::Error {
    io::Error::other("upstream proxy connection failed")
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
            "http://user:@127.0.0.1:8080",
        ] {
            assert!(Proxy::parse(input).is_ok());
        }
        let proxy = Proxy::parse("socks5://u%3Aname:p%40ss@127.0.0.1:1080").unwrap();
        assert_eq!(proxy.credentials, Some(("u:name".into(), "p@ss".into())));
        for input in [
            "https://127.0.0.1:1080",
            "socks5://example.com:1080",
            "socks5://u:%XX@127.0.0.1:1080",
            "socks5://u:@127.0.0.1:1080",
            "socks5://:p@127.0.0.1:1080",
            "socks5://127.0.0.1:0",
            "socks5://127.0.0.1:1080/path",
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
        assert_eq!(proxy.credentials.unwrap().0, "A".repeat(255));
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

    #[tokio::test(start_paused = true)]
    async fn carrier_handshake_has_one_whole_operation_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Proxy::parse(&format!("socks5://{}", listener.local_addr().unwrap())).unwrap();
        // Accepts and then stays silent for the whole test.
        let silent = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _held = stream;
            std::future::pending::<()>().await;
        });
        let started = Instant::now();
        let mut connect = std::pin::pin!(proxy.connect("carrier.invalid", 443));
        // The first poll starts the handshake and fixes its deadline.
        assert!(futures::FutureExt::now_or_never(connect.as_mut()).is_none());
        tokio::time::advance(CONNECT_TIMEOUT - Duration::from_millis(1)).await;
        assert!(
            futures::FutureExt::now_or_never(connect.as_mut()).is_none(),
            "the handshake must still be pending just before the deadline"
        );
        let error = connect.await.unwrap_err();
        assert_eq!(error.to_string(), "upstream proxy connection failed");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= CONNECT_TIMEOUT && elapsed < CONNECT_TIMEOUT + Duration::from_secs(1),
            "one deadline covers the whole handshake, elapsed {elapsed:?}"
        );
        silent.abort();
    }

    #[test]
    fn http_upstream_credentials_follow_basic_rules_not_rfc1929() {
        let long = "p".repeat(300);
        assert!(Proxy::parse(&format!("http://user:{long}@127.0.0.1:8080")).is_ok());
        assert!(Proxy::parse("http://user:@127.0.0.1:8080").is_ok());
        assert!(Proxy::parse(&format!("socks5://user:{long}@127.0.0.1:1080")).is_err());
        assert!(Proxy::parse("socks5://user:@127.0.0.1:1080").is_err());
    }

    #[tokio::test]
    async fn sdk_carrier_preserves_remote_hostname_and_payload() {
        use resocks5_net::server::{accept, Reply, ServerOptions};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for (scheme, protocol) in [
            ("socks5", resocks5_net::server::Protocol::Socks5),
            ("http", resocks5_net::server::Protocol::Http),
        ] {
            for with_auth in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let uri = if with_auth {
                    format!("{scheme}://u:p%40ss@{address}")
                } else {
                    format!("{scheme}://{address}")
                };
                let proxy = Proxy::parse(&uri).unwrap();
                let server = async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let options = ServerOptions::new(
                        Instant::now() + Duration::from_secs(5),
                        !with_auth,
                        with_auth,
                    );
                    let request = accept(&mut stream, &options, |credentials| {
                        std::future::ready(
                            credentials.username() == "u" && credentials.password() == "p@ss",
                        )
                    })
                    .await
                    .unwrap();
                    assert_eq!(request.protocol(), protocol);
                    assert_eq!(request.username().is_some(), with_auth);
                    assert_eq!(request.target(), "carrier.invalid:443");
                    request
                        .reply(&mut stream, Reply::Established)
                        .await
                        .unwrap();
                    stream.write_all(b"carrier-ready").await.unwrap();
                    stream.flush().await.unwrap();
                };
                let client = async {
                    let mut stream = proxy.connect("carrier.invalid", 443).await.unwrap();
                    let mut payload = [0; 13];
                    stream.read_exact(&mut payload).await.unwrap();
                    assert_eq!(&payload, b"carrier-ready");
                };
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(server, client)
                })
                .await
                .expect("carrier exchange must finish");
            }
        }
    }

    #[tokio::test]
    async fn sdk_carrier_formats_ipv6_targets_and_tunes_socket() {
        use resocks5_net::server::{accept, Reply, ServerOptions};

        for (scheme, protocol) in [
            ("socks5", resocks5_net::server::Protocol::Socks5),
            ("http", resocks5_net::server::Protocol::Http),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy =
                Proxy::parse(&format!("{scheme}://{}", listener.local_addr().unwrap())).unwrap();
            let server = async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let options =
                    ServerOptions::new(Instant::now() + Duration::from_secs(5), true, false);
                let request = accept(&mut stream, &options, |_| std::future::ready(false))
                    .await
                    .unwrap();
                assert_eq!(request.protocol(), protocol);
                assert_eq!(request.target(), "[2001:db8::1]:443");
                request
                    .reply(&mut stream, Reply::Established)
                    .await
                    .unwrap();
            };
            let client = async {
                let stream = proxy.connect("2001:db8::1", 443).await.unwrap();
                assert!(stream.nodelay().unwrap());
            };
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(server, client)
            })
            .await
            .expect("IPv6 carrier exchange must finish");
        }
    }

    #[tokio::test]
    async fn sdk_http_carrier_rejection_is_terminal() {
        use resocks5_net::server::{accept, ServerOptions};
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            Proxy::parse(&format!("http://u:p@{}", listener.local_addr().unwrap())).unwrap();
        let server = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let options = ServerOptions::new(Instant::now() + Duration::from_secs(5), false, true);
            assert!(accept(&mut stream, &options, |_| std::future::ready(false))
                .await
                .is_err());
            let mut byte = [0];
            match stream.read(&mut byte).await {
                Ok(0) => (),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) => {}
                other => panic!("rejected HTTP carrier was not closed: {other:?}"),
            }
        };
        let client = async {
            assert!(proxy.connect("carrier.invalid", 443).await.is_err());
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("HTTP proxy rejection must terminate");
    }

    #[tokio::test]
    async fn sdk_carrier_rejects_no_auth_downgrade_without_connect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = Proxy::parse(&format!("socks5://u:p@{address}")).unwrap();
        let server = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 0]).await.unwrap();
            stream.flush().await.unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        };
        let client = async {
            assert!(proxy.connect("carrier.invalid", 443).await.is_err());
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("rejected carrier must close");
    }

    #[derive(Clone, Copy, Debug)]
    enum UpstreamScript {
        ClosesAfterMethodSelection,
        ClosesMidAuthReply,
        RejectsAuth,
        ClosesAfterAuth,
    }

    #[tokio::test]
    async fn socks5_upstream_failing_at_any_stage_is_terminal() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for script in [
            UpstreamScript::ClosesAfterMethodSelection,
            UpstreamScript::ClosesMidAuthReply,
            UpstreamScript::RejectsAuth,
            UpstreamScript::ClosesAfterAuth,
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy =
                Proxy::parse(&format!("socks5://u:p@{}", listener.local_addr().unwrap())).unwrap();
            let server = async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                stream.write_all(&[5, 2]).await.unwrap();
                if matches!(script, UpstreamScript::ClosesAfterMethodSelection) {
                    return;
                }
                let mut auth = [0; 5];
                stream.read_exact(&mut auth).await.unwrap();
                assert_eq!(auth, [1, 1, b'u', 1, b'p']);
                match script {
                    UpstreamScript::ClosesMidAuthReply => stream.write_all(&[1]).await.unwrap(),
                    UpstreamScript::RejectsAuth => stream.write_all(&[1, 1]).await.unwrap(),
                    _ => stream.write_all(&[1, 0]).await.unwrap(),
                }
                // Dropping the stream closes it before any CONNECT reply.
            };
            let client = async {
                let outcome = proxy.connect("carrier.invalid", 443).await;
                assert!(outcome.is_err(), "{script:?} must fail the carrier");
            };
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(server, client)
            })
            .await
            .unwrap_or_else(|_| panic!("{script:?} must terminate"));
        }
    }

    #[tokio::test]
    async fn carrier_handshake_survives_one_byte_replies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn drip(stream: &mut TcpStream, bytes: &[u8]) {
            for byte in bytes {
                stream.write_all(&[*byte]).await.unwrap();
                stream.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
        }

        // SOCKS5: method selection, auth status and CONNECT reply, byte by byte.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            Proxy::parse(&format!("socks5://u:p@{}", listener.local_addr().unwrap())).unwrap();
        let server = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            drip(&mut stream, &[5, 2]).await;
            let mut auth = [0; 5];
            stream.read_exact(&mut auth).await.unwrap();
            drip(&mut stream, &[1, 0]).await;
            let mut header = [0; 4];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header, [5, 1, 0, 3], "ATYP=3 carries the hostname");
            // length byte + "carrier.invalid" (15) + port (2)
            let mut rest = [0; 1 + 15 + 2];
            stream.read_exact(&mut rest).await.unwrap();
            drip(&mut stream, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            stream.write_all(b"ok").await.unwrap();
        };
        let client = async {
            let mut stream = proxy.connect("carrier.invalid", 443).await.unwrap();
            let mut payload = [0; 2];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ok");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("fragmented SOCKS5 replies must be reassembled");

        // HTTP CONNECT: status line and header terminator byte by byte.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Proxy::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            while !seen.ends_with(b"\r\n\r\n") {
                let mut byte = [0; 1];
                stream.read_exact(&mut byte).await.unwrap();
                seen.push(byte[0]);
            }
            assert!(seen.starts_with(b"CONNECT carrier.invalid:443 HTTP/1.1\r\n"));
            drip(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
            stream.write_all(b"ok").await.unwrap();
        };
        let client = async {
            let mut stream = proxy.connect("carrier.invalid", 443).await.unwrap();
            let mut payload = [0; 2];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ok");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("fragmented HTTP replies must be reassembled");
    }
}
