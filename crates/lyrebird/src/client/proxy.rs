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
        match std::env::var_os("TOR_PT_PROXY") {
            None => Ok(None),
            Some(value) if value.is_empty() => Ok(None),
            Some(value) => {
                Self::parse(value.to_str().ok_or(())?).map(|proxy| Some(Arc::new(proxy)))
            }
        }
    }

    fn parse(input: &str) -> Result<Self, ()> {
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
                if username.is_empty()
                    || password.is_empty()
                    || username.len() > 255
                    || password.len() > 255
                    || (protocol == ProxyProtocol::Http
                        && (username.contains(':')
                            || username.bytes().any(|byte| byte.is_ascii_control())
                            || password.bytes().any(|byte| byte.is_ascii_control())))
                {
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
        if self.protocol == ProxyProtocol::Https || host.is_empty() || host.len() > 255 || port == 0
        {
            return Err(failure());
        }
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            let mut stream = TcpStream::connect(self.address)
                .await
                .map_err(|_| failure())?;
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
                    ) =>
                {
                    ()
                }
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
}
