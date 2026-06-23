//! TLS + HTTP Upgrade handshake for webtunnel.
//!
//! Confirmed from the Go reference implementation (pkg.go.dev and GitHub
//! mirror at blackyblack/webtunnel):
//!
//! - **ALPN**: Go client does NOT set ALPN (`NextProtos` is nil).
//!   We leave ALPN empty for maximum camouflage.
//!
//! - **Sec-WebSocket-Accept**: server does NOT return it — only sends
//!   `Connection: upgrade` + `Upgrade: websocket`. Parser is lenient.
//!
//! - **Sec-WebSocket-Key**: server does NOT validate it. We generate a
//!   proper one (16 random bytes, base64-encoded) for camouflage.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::dns::{DohMode, DohResolver};
use crate::{Error, PrefixStream, WebTunnelConfig, WebTunnelStream};

/// Generate a Sec-WebSocket-Key (16 random bytes, base64-encoded).
pub fn generate_websocket_key() -> String {
    let mut buf = [0u8; 16];
    // getrandom only fails when the system RNG is unavailable — fatal
    // for a transport that depends on randomness.
    getrandom::getrandom(&mut buf)
        .expect("system RNG unavailable — cannot generate Sec-WebSocket-Key");
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Build the HTTP/1.1 Upgrade request bytes.
pub fn build_upgrade_request(config: &WebTunnelConfig) -> String {
    let parsed = url::Url::parse(&config.url).expect("url already validated");
    let path = parsed.path();
    let path = if path.is_empty() { "/" } else { path };

    // Include the query string in the request-target (RFC 7230 §5.3.1).
    // The Go reference implementation sends path?query; omitting the query
    // silently breaks bridges that embed auth tokens / routing in it.
    let request_target = match parsed.query() {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    };

    let host = config.tls_sni().expect("tls_sni already validated");
    let key = generate_websocket_key();

    format!(
        "GET {request_target} HTTP/1.1\r\n\
Host: {host}\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: {key}\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n"
    )
}

/// Parse a complete HTTP response from a byte slice.
///
/// Returns `Ok((status_code, leftover_bytes))` on 101, or an error for
/// any other status / parse failure. Lenient: only checks the status code.
pub fn parse_response(buf: &[u8]) -> Result<(u16, &[u8]), Error> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);

    let body_offset = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return Err(Error::HttpParse("incomplete HTTP response".into()))
        }
        Err(e) => return Err(Error::HttpParse(e.to_string())),
    };

    let code = resp
        .code
        .ok_or_else(|| Error::HttpParse("no status code".into()))?;

    if code != 101 {
        let reason = resp.reason.unwrap_or("(no reason)");
        return Err(Error::Non101(format!("{code} {reason}")));
    }

    Ok((code, &buf[body_offset..]))
}

/// Perform the full webtunnel handshake: TCP → (optional TLS) → HTTP Upgrade.
///
/// # Cancel safety
///
/// This function is **not cancel-safe**. Dropping the returned future
/// mid-handshake may leave the underlying stream in a partially-written
/// state. Wrap in `tokio::spawn` if cancellation is possible.
pub async fn connect(config: &WebTunnelConfig) -> Result<PrefixStream<WebTunnelStream>, Error> {
    let tcp = open_tcp(config).await?;

    if config.use_tls() {
        let tls_stream = tls_connect(config, tcp).await?;
        upgrade_and_return(tls_stream, config).await
    } else {
        upgrade_and_return(tcp, config).await
    }
}

/// Decide how to resolve the bridge URL into a TCP connection. The
/// decision matrix matches the issue-#74-adjacent design captured in
/// the project notes:
///
/// |               | `addr=` set            | `addr=` unset, `doh_mode=Off` | `addr=` unset, `doh_mode=Strict` | `addr=` unset, `doh_mode=Fallback` |
/// |---------------|------------------------|--------------------------------|----------------------------------|------------------------------------|
/// | path          | direct connect to IP   | system DNS via tokio           | DoH-only — `Err` on pool failure | DoH first → system DNS on failure  |
///
/// `addr=` is a censorship-hardened operator override (a literal IP
/// distributed out-of-band); it bypasses both system DNS and DoH.
/// `doh_mode=Off` keeps backwards-compatible behaviour for anyone who
/// explicitly opts out.
async fn open_tcp(config: &WebTunnelConfig) -> Result<TcpStream, Error> {
    let (host, port) = config.connect_host_and_port()?;

    // Operator-supplied raw address — host is almost always an IP, so
    // both `TcpStream::connect((host, port))` and DoH would be wrong:
    // the user has already told us where to dial.
    if config.tcp_addr.is_some() {
        return TcpStream::connect((host.as_str(), port))
            .await
            .map_err(Error::from);
    }

    match config.doh_mode {
        DohMode::Off => TcpStream::connect((host.as_str(), port))
            .await
            .map_err(Error::from),
        DohMode::Strict => {
            let resolver = DohResolver::with_default_pool().map_err(Error::from)?;
            connect_via_doh_strict(&resolver, &host, port).await
        }
        DohMode::Fallback => {
            let resolver = DohResolver::with_default_pool().ok();
            connect_via_doh_fallback(resolver.as_ref(), &host, port).await
        }
    }
}

/// Strict path: DoH only. On any failure (lookup error or every
/// connect attempt failing) return an error — never silently fall back
/// to the system resolver. This is the §F1 invariant the
/// censorship-resistance use case depends on.
///
/// Exposed at `pub(crate)` so tests can drive it with a `DohResolver`
/// built from a known-unreachable pool — that exercises the "all DoH
/// failed" branch without needing a real network outage.
pub(crate) async fn connect_via_doh_strict(
    resolver: &DohResolver,
    host: &str,
    port: u16,
) -> Result<TcpStream, Error> {
    let addrs = resolver.resolve(host, port).await.map_err(Error::from)?;
    connect_first(&addrs).await.map_err(Error::from)
}

/// Fallback path: DoH first, system DNS on full DoH failure. A
/// connect-time failure to a resolved DoH address is treated the same
/// as a DoH lookup failure: try the system resolver before giving up,
/// so a partially-blocked DoH pool does not break webtunnel for a
/// caller who explicitly opted into "best-effort hardening".
///
/// `resolver` is `Option` so the caller can pass `None` when the
/// resolver itself failed to build — fallback still tries the system
/// resolver in that case, matching the "best-effort" contract.
pub(crate) async fn connect_via_doh_fallback(
    resolver: Option<&DohResolver>,
    host: &str,
    port: u16,
) -> Result<TcpStream, Error> {
    if let Some(r) = resolver {
        if let Ok(addrs) = r.resolve(host, port).await {
            if let Ok(stream) = connect_first(&addrs).await {
                return Ok(stream);
            }
        }
    }
    TcpStream::connect((host, port)).await.map_err(Error::from)
}

/// Try each `SocketAddr` in order, returning the first successful TCP
/// connection. If every attempt fails, return the last error.
///
/// This is a thin sequential "happy-eyeballs-lite". A full RFC 8305
/// happy-eyeballs (parallel v6/v4) is intentionally out of scope: at
/// the bridge-handshake layer one extra RTT is acceptable, and the
/// simpler implementation is easier to audit.
async fn connect_first(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last_err: Option<io::Error> = None;
    for &addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no addresses to connect to",
        )
    }))
}

async fn tls_connect(
    config: &WebTunnelConfig,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
    let sni = config.tls_sni()?;
    let server_name = rustls::pki_types::ServerName::try_from(sni)
        .map_err(|e| Error::Tls(format!("invalid SNI: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // No ALPN set — matches the Go client which leaves NextProtos empty.
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Tls(e.to_string()))?;

    Ok(tls)
}

/// Send the HTTP Upgrade request, read the 101 response, return the stream
/// in raw-byte mode. `S` is either `TlsStream<TcpStream>` or `TcpStream`.
async fn upgrade_and_return<S>(
    mut stream: S,
    config: &WebTunnelConfig,
) -> Result<PrefixStream<WebTunnelStream>, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + StreamWrapper + 'static,
{
    let request = build_upgrade_request(config);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| Error::Handshake(format!("write upgrade request: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Handshake(format!("flush: {e}")))?;

    // Read the 101 response. The response is small (a few headers), so
    // a 4096-byte buffer is generous. We loop until httparse reports
    // Status::Complete.
    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    loop {
        if total >= buf.len() {
            return Err(Error::Handshake("response headers too large".into()));
        }
        let n = stream
            .read(&mut buf[total..])
            .await
            .map_err(|e| Error::Handshake(format!("read response: {e}")))?;
        if n == 0 {
            return Err(Error::Handshake("connection closed before 101".into()));
        }
        total += n;

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(&buf[..total]) {
            Ok(httparse::Status::Complete(body_offset)) => {
                let code = resp
                    .code
                    .ok_or_else(|| Error::HttpParse("no status code".into()))?;
                if code != 101 {
                    let reason = resp.reason.unwrap_or("(no reason)");
                    return Err(Error::Non101(format!("{code} {reason}")));
                }

                let leftover: Vec<u8> = buf[body_offset..total].to_vec();
                if !leftover.is_empty() {
                    crate::warn!(
                        "webtunnel: {} trailing bytes after 101 — preserving in stream prefix",
                        leftover.len()
                    );
                }

                let inner = StreamWrapper::wrap(stream)?;
                return Ok(PrefixStream::new(inner, leftover));
            }
            Ok(httparse::Status::Partial) => continue,
            Err(e) => return Err(Error::HttpParse(e.to_string())),
        }
    }
}

/// Trait to convert the inner stream into a `WebTunnelStream`.
/// Implemented separately for `TlsStream<TcpStream>` and `TcpStream`.
trait StreamWrapper: Sized {
    fn wrap(self) -> Result<WebTunnelStream, Error>;
}

impl StreamWrapper for tokio_rustls::client::TlsStream<TcpStream> {
    fn wrap(self) -> Result<WebTunnelStream, Error> {
        Ok(WebTunnelStream::Tls(Box::new(self)))
    }
}

impl StreamWrapper for TcpStream {
    fn wrap(self) -> Result<WebTunnelStream, Error> {
        Ok(WebTunnelStream::Plain(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WebTunnelConfig;
    use ptrs::args::Args;

    fn make_config(url: &str) -> WebTunnelConfig {
        let mut args = Args::new();
        args.add("url", url);
        WebTunnelConfig::from_args(&args).unwrap()
    }

    #[test]
    fn websocket_key_is_base64_24_chars() {
        let key = generate_websocket_key();
        assert_eq!(key.len(), 24);
        assert!(base64::engine::general_purpose::STANDARD
            .decode(&key)
            .is_ok());
    }

    #[test]
    fn websocket_key_is_random() {
        let k1 = generate_websocket_key();
        let k2 = generate_websocket_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn build_upgrade_request_format() {
        let config = make_config("https://example.com/secret");
        let req = build_upgrade_request(&config);
        assert!(req.starts_with("GET /secret HTTP/1.1\r\n"));
        assert!(req.contains("Host: example.com\r\n"));
        assert!(req.contains("Upgrade: websocket\r\n"));
        assert!(req.contains("Connection: Upgrade\r\n"));
        assert!(req.contains("Sec-WebSocket-Key: "));
        assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_upgrade_request_root_path() {
        let config = make_config("https://example.com");
        let req = build_upgrade_request(&config);
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn parse_response_101_ok() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
        let (code, leftover) = parse_response(resp).unwrap();
        assert_eq!(code, 101);
        assert!(leftover.is_empty());
    }

    #[test]
    fn parse_response_101_with_leftover() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nEXTRADATA";
        let (code, leftover) = parse_response(resp).unwrap();
        assert_eq!(code, 101);
        assert_eq!(leftover, b"EXTRADATA");
    }

    #[test]
    fn parse_response_non_101() {
        let resp = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let err = parse_response(resp).unwrap_err();
        assert!(matches!(err, Error::Non101(_)));
    }

    #[test]
    fn parse_response_incomplete() {
        let resp = b"HTTP/1.1 101 Switch";
        let err = parse_response(resp).unwrap_err();
        assert!(matches!(err, Error::HttpParse(_)));
    }

    #[test]
    fn parse_response_malformed() {
        let resp = b"NOT HTTP AT ALL\r\n\r\n";
        let err = parse_response(resp).unwrap_err();
        assert!(matches!(err, Error::HttpParse(_)));
    }

    // -- DoH connect-path tests ------------------------------------------------
    //
    // These tests exercise the strict-vs-fallback decision logic without
    // touching the network. The "unreachable" DoH pool uses 127.0.0.1 as
    // its bootstrap IP: hickory will dial 127.0.0.1:443 to perform the DoH
    // TLS handshake, which fails immediately with `ConnectionRefused` on a
    // host with no service on that port — fast enough that the test never
    // hangs and never has to talk to the real internet.
    //
    // The DoH-resolver build itself is fallible; in production we build
    // anew per connect, so a bad pool can surface either as a build error
    // (caught here by the empty-pool / IP-only test in `dns::resolver`) or
    // a resolve error (caught here). The build-error path of fallback is
    // covered by passing `None` for the resolver — same shape.

    use std::net::{IpAddr, Ipv4Addr};

    use crate::dns::endpoints::DohEndpoint;

    /// A DoH pool whose only "endpoint" dials 127.0.0.1 — no TLS listener
    /// on :443 there, so every lookup terminates with a connection error
    /// without involving the network. Pinned `localhost.invalid` SNI
    /// ensures `rustls` rejects the (non-existent) certificate.
    const UNREACHABLE_ENDPOINT: DohEndpoint = DohEndpoint {
        name: "unreachable-test",
        sni: "localhost.invalid",
        path: Some("/dns-query"),
        bootstrap: &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
    };

    /// §F1: `Strict` MUST surface an error when the DoH pool cannot
    /// resolve. It MUST NOT silently fall through to the system DNS
    /// resolver — that would defeat the censorship-resistance contract.
    ///
    /// We use an `.invalid` host (RFC 2606 reserved TLD — guaranteed
    /// non-resolvable by any honest resolver) so a hypothetical leak
    /// into the system resolver could not "rescue" the call. Combined
    /// with an unreachable DoH pool the only path to success would be
    /// a strict-mode bypass — which is exactly what this test is
    /// guarding against. The companion `fallback_*` tests demonstrate
    /// that the system-resolver path itself is wired up correctly.
    #[tokio::test]
    async fn strict_returns_err_when_doh_pool_unreachable() {
        let resolver =
            DohResolver::from_endpoints(&[UNREACHABLE_ENDPOINT]).expect("unreachable pool builds");

        let result = connect_via_doh_strict(&resolver, "bridge.test.invalid", 443).await;
        assert!(
            result.is_err(),
            "strict must NOT fall through to system DNS or any other resolver, but got Ok",
        );
    }

    /// `Fallback` MUST recover via the system resolver when the DoH
    /// pool is unreachable — that is its entire contract.
    #[tokio::test]
    async fn fallback_recovers_via_system_resolver() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let resolver =
            DohResolver::from_endpoints(&[UNREACHABLE_ENDPOINT]).expect("unreachable pool builds");

        let stream = connect_via_doh_fallback(Some(&resolver), "localhost", port)
            .await
            .expect("fallback must reach the system-resolved localhost");
        // Sanity: stream is connected to the listener.
        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }

    /// `Fallback` with `resolver = None` (resolver-build failed) must
    /// still try the system resolver. Same end behaviour as the case
    /// above, exercising the resolver-absent branch.
    #[tokio::test]
    async fn fallback_with_no_resolver_still_uses_system_resolver() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let stream = connect_via_doh_fallback(None, "localhost", port)
            .await
            .expect("fallback with None resolver must use system DNS");
        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }

    /// `connect_first` picks the first reachable address, skipping
    /// unreachable ones. Two-element list where the first refuses and
    /// the second accepts — must succeed and report the second port.
    #[tokio::test]
    async fn connect_first_picks_reachable_after_skipping_dead() {
        let good = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_port = good.local_addr().unwrap().port();

        // Port 1 on 127.0.0.1 is almost certainly closed; if it isn't,
        // the test would skip past it via the "second succeeds" path.
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let alive: SocketAddr = format!("127.0.0.1:{good_port}").parse().unwrap();

        let stream = connect_first(&[dead, alive]).await.expect("alive must win");
        assert_eq!(stream.peer_addr().unwrap().port(), good_port);
    }

    /// `connect_first` returns the last error when no address is
    /// reachable (and `AddrNotAvailable` for an empty input). The
    /// empty-input shape is the regression guard for the helper's
    /// "no addresses to connect to" branch.
    #[tokio::test]
    async fn connect_first_returns_error_on_empty_input() {
        let err = connect_first(&[]).await.expect_err("empty must fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    }
}
