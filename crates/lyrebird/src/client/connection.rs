use super::*;
use resocks5_net::server::{self as proxy_server, IncomingRequest, Protocol, Reply, ServerOptions};

#[cfg(test)]
pub(super) async fn client_handle_connection<In, C, B>(
    conn: In,
    builder: B,
    client_addr: SocketAddr,
) -> Result<()>
where
    In: AsyncRead + AsyncWrite + Send + Unpin,
    C: ManagedClient,
    B: ptrs::ClientBuilder<TcpStream, ClientPT = C>,
{
    client_handle_connection_with_proxy(conn, builder, client_addr, None).await
}

/// cancel-safe: NO — cancellation closes both owned protocol streams.
pub(super) async fn client_handle_connection_with_proxy<In, C, B>(
    conn: In,
    mut builder: B,
    client_addr: SocketAddr,
    proxy: Option<Arc<proxy::Proxy>>,
) -> Result<()>
where
    In: AsyncRead + AsyncWrite + Send + Unpin,
    C: ManagedClient,
    B: ptrs::ClientBuilder<TcpStream, ClientPT = C>,
{
    // PT-spec section 3.5 carries bridge arguments in RFC 1929 credentials.
    // The SDK parses only; it never dials or sends an established reply.
    let mut parent = tokio::io::BufReader::new(conn);
    let deadline = tokio::time::Instant::now() + SOCKS5_SETUP_TIMEOUT;
    let options = ServerOptions::new(deadline, true, true);
    let mut creds = None;
    let mut request = tokio::time::timeout_at(deadline, async {
        proxy_server::accept(&mut parent, &options, |credentials| {
            creds = Some((
                credentials.username().to_owned(),
                credentials.password().to_owned(),
            ));
            std::future::ready(true)
        })
        .await
        .map_err(|error| match error {
            proxy_server::ServerError::Deadline => anyhow!("proxy negotiation timed out"),
            _ => anyhow!("SOCKS5 parent negotiation failed"),
        })
    })
    .await
    .context("proxy negotiation timed out")??;
    let target_addr = request.target().to_owned();
    let creds = if request.protocol() == Protocol::Http {
        creds.map(|(user, password)| http_credentials(user, password))
    } else {
        creds
    };

    // Hand the reconstructed PT arguments to the transport's `options(&Args)`
    // so the obfs4 ClientBuilder picks up `cert=...` / `iat-mode=...` etc.
    if let Err(error) = configure_builder(&mut builder, creds) {
        reply_failure(&request, &mut parent, Reply::GeneralFailure).await;
        return Err(error);
    }

    // Build the client and let the transport choose its connection path.
    // WebTunnel owns URL dialing; its SOCKS target is only a PT-spec carrier
    // placeholder and must never become a direct dial target.
    let pt_client = builder.build();
    let mut pt_conn =
        match C::managed_connect_with_proxy(pt_client, target_addr, client_addr, proxy).await {
            Ok(conn) => conn,
            Err(error) => {
                reply_failure(&request, &mut parent, Reply::UpstreamUnavailable).await;
                return Err(error);
            }
        };

    // Reply only after the actual transport handshake succeeds.
    tokio::time::timeout(
        SOCKS5_SETUP_TIMEOUT,
        request.reply(&mut parent, Reply::Established),
    )
    .await
    .context("proxy reply timed out")?
    .context("writing established reply to PT parent")?;

    // Payload the SDK already consumed precedes whatever is still buffered or
    // unread, and shares the tunnel's ordinary backpressure policy.
    let pipeline = request.take_pipeline();
    drop(request);
    let mut parent = Prefixed::new(pipeline, parent);
    if let Err(e) = copy_bidirectional(&mut parent, &mut pt_conn).await {
        log_tunnel_closed(client_addr, &e);
    }
    Ok(())
}

/// Structured field names are a contract for log filters: keep `address`.
pub(super) fn log_tunnel_closed(client_addr: SocketAddr, error: &std::io::Error) {
    warn!(
        address = sensitive(client_addr).to_string(),
        "tunnel closed with error: {error:#?}"
    );
}

/// HTTP Basic parsers split at the first `:`, so rejoin the halves. Clients
/// append one `:` (an empty password) after the PT arguments; strip it.
pub(super) fn http_credentials(username: String, password: String) -> (String, String) {
    let mut joined = format!("{username}:{password}");
    if joined.ends_with(':') {
        joined.pop();
    }
    (joined, String::new())
}

/// Apply the parent's PT arguments to `builder`. Errors never carry the
/// submitted values, which may include bridge secrets.
pub(super) fn configure_builder<B>(builder: &mut B, creds: Option<(String, String)>) -> Result<()>
where
    B: ptrs::ClientBuilder<TcpStream>,
{
    let arg_string = arg_string_from_creds(creds);
    let args = if arg_string.is_empty() {
        ptrs::args::Args::default()
    } else {
        ptrs::args::Args::from_str(&arg_string).map_err(|_| anyhow!("invalid PT arguments"))?
    };
    <B as ptrs::ClientBuilder<TcpStream>>::options(builder, &args)
        .map_err(|_| anyhow!("PT arguments rejected by the transport"))?;
    Ok(())
}

/// Best-effort terminal failure reply, bounded so teardown is never held up.
async fn reply_failure<S: AsyncWrite + Unpin>(
    request: &IncomingRequest,
    parent: &mut S,
    reply: Reply,
) {
    let _ = tokio::time::timeout(SOCKS5_SETUP_TIMEOUT, request.reply(parent, reply)).await;
}

/// Serves `prefix` before reading from `inner`; writes pass straight through.
pub(super) struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(super) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.offset < this.prefix.len() {
            let end = (this.offset + buf.remaining()).min(this.prefix.len());
            buf.put_slice(&this.prefix[this.offset..end]);
            this.offset = end;
            return std::task::Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
