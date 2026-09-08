#![deny(missing_docs)]
//! WebTunnel pluggable transport client.
//!
//! Implements the webtunnel PT protocol: TLS + HTTP/1.1 WebSocket Upgrade
//! handshake that results in a raw bidirectional byte stream. The protocol
//! is intentionally minimal — no WebSocket framing after the 101 response.

use std::{
    io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    time::Duration,
};

use ptrs::args::Args;
use ptrs::{info, warn, FutureResult as F};
use tokio::io::{AsyncRead, AsyncWrite};

pub mod dns;
pub mod handshake;

pub use dns::DohMode;

/// Transport name constant.
pub const WEBTUNNEL_NAME: &str = "webtunnel";

pub(crate) const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced during WebTunnel configuration or handshake.
///
/// `#[non_exhaustive]`: handshake and TLS failure modes are expected to grow
/// (e.g. utls fingerprinting, ALPN negotiation), so downstream `match`es must
/// keep a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The required `url=` parameter was not provided.
    #[error("missing required parameter: url")]
    MissingUrl,

    /// The URL could not be parsed.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// The HTTP Upgrade handshake failed.
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// The HTTP response could not be parsed.
    #[error("http parse error: {0}")]
    HttpParse(String),

    /// The server returned a non-101 status code.
    #[error("server returned non-101 status: {0}")]
    Non101(String),

    /// A TLS error occurred.
    #[error("tls error: {0}")]
    Tls(String),

    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A catch-all error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Parameters extracted from a webtunnel bridge line's key=value args.
///
/// `#[non_exhaustive]`: the webtunnel bridge-line option set is open-ended
/// (e.g. `utls=` is parsed but not yet stored, and new transport knobs land
/// here), so construct instances via [`WebTunnelConfig::from_args`] rather
/// than a struct literal.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WebTunnelConfig {
    /// Full URL from `url=` (e.g. `https://example.com/secretPath`).
    pub url: String,
    /// Protocol version from `ver=` (e.g. `0.0.3`).
    pub version: Option<String>,
    /// TLS SNI override from `servername=`. Defaults to URL hostname.
    pub servername: Option<String>,
    /// TCP address override from `addr=`. Defaults to URL host:port.
    pub tcp_addr: Option<String>,
    /// DNS-over-HTTPS resolution mode for the bridge URL hostname.
    ///
    /// Defaults to [`DohMode::Fallback`] — additive defence that never
    /// breaks existing webtunnel deployments. Set via the `doh-mode=`
    /// bridge-line argument or [`WebTunnelConfig::with_doh_mode`].
    ///
    /// Literal IP addresses bypass DNS. Hostnames in `tcp_addr` also honor this mode.
    pub doh_mode: DohMode,
}

impl WebTunnelConfig {
    /// Construct a config from the standard `Args` key-value bag.
    pub fn from_args(args: &Args) -> Result<Self, Error> {
        let url_str = args.retrieve("url").ok_or(Error::MissingUrl)?;

        let parsed = url::Url::parse(&url_str)
            .map_err(|e: url::ParseError| Error::InvalidUrl(e.to_string()))?;

        if parsed.host_str().is_none() {
            return Err(Error::InvalidUrl("url has no host".into()));
        }
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::InvalidUrl("url scheme must be http or https".into()));
        }

        let version = args.retrieve("ver");
        let servername = args.retrieve("servername");
        let tcp_addr = args.retrieve("addr");

        let doh_mode = match args.retrieve("doh-mode") {
            Some(s) => s
                .parse::<DohMode>()
                .map_err(|e| Error::InvalidUrl(format!("doh-mode: {e}")))?,
            None => DohMode::default(),
        };

        // Log and ignore `utls=` (TLS fingerprint emulation — deferred).
        if let Some(ref utls) = args.retrieve("utls") {
            info!("utls={utls} parameter accepted but ignored (not yet implemented)");
        }

        let config = Self {
            url: url_str,
            version,
            servername,
            tcp_addr,
            doh_mode,
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        let url = url::Url::parse(&self.url).map_err(|e| Error::InvalidUrl(e.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(Error::InvalidUrl(
                "expected an http or https URL with a host".into(),
            ));
        }
        rustls::pki_types::ServerName::try_from(self.tls_sni()?)
            .map_err(|e| Error::InvalidUrl(format!("invalid servername: {e}")))?;
        self.connect_host_and_port()?;
        Ok(())
    }

    /// Override the DoH resolution mode (chainable).
    pub fn with_doh_mode(mut self, mode: DohMode) -> Self {
        self.doh_mode = mode;
        self
    }

    /// Hostname and port to resolve / connect to. Equivalent to
    /// [`Self::connect_host_port`] but returns the host and port as
    /// separate values so the resolver can hand the hostname to DoH
    /// without re-parsing.
    pub(crate) fn connect_host_and_port(&self) -> Result<(String, u16), Error> {
        if let Some(ref addr) = self.tcp_addr {
            if let Ok(addr) = addr.parse::<SocketAddr>() {
                return Ok((addr.ip().to_string(), addr.port()));
            }
            // `addr=` is a raw `host:port` (typically an IP) — split it
            // for symmetry with the URL-derived path, even though the
            // host part here is almost always already an IP and DoH is
            // bypassed in that case.
            let (host, port) = addr.rsplit_once(':').ok_or_else(|| {
                Error::InvalidUrl(format!("addr= missing ':' (expected host:port): {addr}"))
            })?;
            if host.is_empty() || host.contains([':', '[', ']']) {
                return Err(Error::InvalidUrl(format!("invalid addr= host: {host}")));
            }
            let port: u16 = port
                .parse()
                .map_err(|e| Error::InvalidUrl(format!("addr= invalid port {port:?}: {e}")))?;
            return Ok((host.to_string(), port));
        }
        let parsed = url::Url::parse(&self.url)
            .map_err(|e: url::ParseError| Error::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("url has no host".into()))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| Error::InvalidUrl("cannot determine port from url scheme".into()))?;
        Ok((host, port))
    }

    /// The hostname used for the TLS SNI extension and the HTTP Host header.
    fn tls_sni(&self) -> Result<String, Error> {
        if let Some(ref sni) = self.servername {
            return Ok(sni
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string());
        }
        let parsed = url::Url::parse(&self.url)
            .map_err(|e: url::ParseError| Error::InvalidUrl(e.to_string()))?;
        parsed
            .host_str()
            .map(|host| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            })
            .ok_or_else(|| Error::InvalidUrl("url has no host".into()))
    }

    /// The host:port to actually connect to via TCP. Either `addr=` or the URL's host:port.
    ///
    /// Kept on the test surface only — the production connect path uses
    /// [`Self::connect_host_and_port`], which returns the host and port
    /// separately so DoH can hand the host to the resolver without a
    /// re-parse round-trip.
    #[cfg(test)]
    fn connect_host_port(&self) -> Result<String, Error> {
        if let Some(ref addr) = self.tcp_addr {
            return Ok(addr.clone());
        }
        let parsed = url::Url::parse(&self.url)
            .map_err(|e: url::ParseError| Error::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("url has no host".into()))?;
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| Error::InvalidUrl("cannot determine port from url scheme".into()))?;
        Ok(format!("{host}:{port}"))
    }

    /// Whether TLS should be used (true for `https://`, false for `http://`).
    fn use_tls(&self) -> bool {
        url::Url::parse(&self.url)
            .map(|u| u.scheme().eq_ignore_ascii_case("https"))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// ClientBuilder — implements ptrs::ClientBuilder<TcpStream>
// ---------------------------------------------------------------------------

/// Builder for the WebTunnel client transport.
#[derive(Clone, Debug)]
pub struct WebTunnelBuilder {
    config: Option<WebTunnelConfig>,
    timeout: Duration,
}

impl Default for WebTunnelBuilder {
    fn default() -> Self {
        Self {
            config: None,
            timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

impl WebTunnelBuilder {
    /// Transport name constant.
    pub const NAME: &'static str = WEBTUNNEL_NAME;
}

impl<InRW> ptrs::ClientBuilder<InRW> for WebTunnelBuilder
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientPT = WebTunnelClient;
    type Error = Error;
    type Transport = ();

    fn method_name() -> String {
        WEBTUNNEL_NAME.into()
    }

    fn build(&self) -> Self::ClientPT {
        // The trait requires an infallible `build`, but the config is only
        // populated by a successful `options(..)` call. Rather than panic on
        // an un-configured builder, carry the `None` forward and surface a
        // typed error at connect time (`establish`/`wrap`).
        WebTunnelClient {
            config: self.config.clone(),
            timeout: self.timeout,
        }
    }

    fn options(&mut self, opts: &Args) -> Result<&mut Self, Self::Error> {
        self.config = Some(WebTunnelConfig::from_args(opts)?);
        Ok(self)
    }

    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn timeout(&mut self, timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        self.timeout = timeout.unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT);
        Ok(self)
    }

    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }

    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Ok(self)
    }
}

// ---------------------------------------------------------------------------
// ClientTransport — implements ptrs::ClientTransport<TcpStream, io::Error>
// ---------------------------------------------------------------------------

/// A WebTunnel client that has been configured and is ready to connect.
///
/// `config` is `None` only when the builder was `build()`-ed before a
/// successful `options(..)`; in that case `establish`/`wrap` fail with a
/// typed [`Error`] instead of panicking.
pub struct WebTunnelClient {
    config: Option<WebTunnelConfig>,
    timeout: Duration,
}

impl<InRW, InErr> ptrs::ClientTransport<InRW, InErr> for WebTunnelClient
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    InErr: std::error::Error + Send + Sync + 'static,
{
    type OutRW = PrefixStream<WebTunnelStream>;
    type OutErr = Error;
    type Builder = WebTunnelBuilder;

    fn establish(self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        // Drop `input` WITHOUT awaiting it. The future, if awaited,
        // would open a TCP connection to the SOCKS5-provided address
        // (the cosmetic `bridge.addr`) — which for webtunnel is wrong
        // and may even be unreachable. The real target lives in `url=`
        // and we dial it directly inside `handshake::connect`.
        drop(input);
        Box::pin(async move {
            let config = self.config.ok_or(Error::MissingUrl)?;
            handshake::connect_with_timeout(&config, self.timeout).await
        })
    }

    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        // Same reasoning as `establish`: the pre-connected socket
        // points at the wrong address for webtunnel, so we close it
        // and open a fresh TLS connection to the URL host.
        drop(io);
        Box::pin(async move {
            let config = self.config.ok_or(Error::MissingUrl)?;
            handshake::connect_with_timeout(&config, self.timeout).await
        })
    }

    fn method_name() -> String {
        WEBTUNNEL_NAME.into()
    }
}

/// The result of a successful webtunnel handshake: a TLS stream
/// (or plain TCP for `http://` URLs) that carries raw bytes.
pub enum WebTunnelStream {
    /// A TLS-encrypted stream.
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    /// A plain TCP stream (used for `http://` URLs).
    Plain(tokio::net::TcpStream),
}

impl AsyncRead for WebTunnelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WebTunnelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            WebTunnelStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
            WebTunnelStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Wrapper that drains leftover handshake bytes before delegating to
/// an inner `AsyncRead + AsyncWrite` stream.
pub struct PrefixStream<S> {
    inner: S,
    prefix: Option<std::io::Cursor<Vec<u8>>>,
}

impl<S> PrefixStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new prefix stream. If `prefix` is empty the wrapper is
    /// transparent — reads go straight to `inner`.
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(std::io::Cursor::new(prefix))
            },
        }
    }
}

impl<S> AsyncRead for PrefixStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain the prefix first.
        if let Some(ref mut cursor) = this.prefix {
            let remaining = cursor.get_ref().len() - cursor.position() as usize;
            if remaining > 0 {
                let to_read = remaining.min(buf.remaining());
                let mut tmp = vec![0u8; to_read];
                let n = std::io::Read::read(cursor, &mut tmp[..to_read])
                    .expect("Cursor<Vec<u8>> read cannot fail");
                buf.put_slice(&tmp[..n]);
                return std::task::Poll::Ready(Ok(()));
            }
            this.prefix = None;
        }

        // Delegate to the inner stream.
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
