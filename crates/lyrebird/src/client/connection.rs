use super::*;
use crate::parent::{self, Credentials, ParentRequest, Protocol};
use resocks5_net::connect::tunnel::tunnel_with_timeouts;
use resocks5_net::server::Reply;

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
    // The parser only reads the request; it never dials or sends an
    // established reply. The arguments are taken once and wiped on drop.
    let mut parent = tokio::io::BufReader::new(conn);
    let deadline = tokio::time::Instant::now() + SOCKS5_SETUP_TIMEOUT;
    let mut request = tokio::time::timeout_at(deadline, async {
        parent::accept(&mut parent)
            .await
            .map_err(|_| anyhow!("SOCKS5 parent negotiation failed"))
    })
    .await
    .context("proxy negotiation timed out")??;
    let target_addr = request.target.clone();
    let arguments = pt_arguments(request.protocol, request.credentials.take());

    // Hand the reconstructed PT arguments to the transport's `options(&Args)`
    // so the obfs4 ClientBuilder picks up `cert=...` / `iat-mode=...` etc.
    let configured = match arguments {
        Ok(arguments) => configure_builder(&mut builder, &arguments),
        Err(()) => Err(anyhow!("invalid PT arguments")),
    };
    if let Err(error) = configured {
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
                reply_failure(&request, &mut parent, reply_for_error(&error)).await;
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

    // Bytes the parser read past the request stay in the buffered reader and
    // are served first, under the tunnel's ordinary backpressure policy.
    // No idle or lifetime cap: a Tor channel may sit quiet for long and its
    // padding is not guaranteed. Dead peers are caught by TCP keepalive.
    match tunnel_with_timeouts(
        &mut parent,
        &mut pt_conn,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    )
    .await
    {
        Ok(outcome) => tracing::debug!(
            to_bridge = outcome.a_to_b,
            to_parent = outcome.b_to_a,
            "tunnel finished"
        ),
        Err(e) => log_tunnel_closed(client_addr, &e),
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

/// Rebuild the PT argument string the parent encoded in its credentials.
/// `Err` means the bytes are not valid UTF-8 even after rejoining the fields.
pub(super) fn pt_arguments(
    protocol: Protocol,
    credentials: Option<Credentials>,
) -> std::result::Result<String, ()> {
    let Some(credentials) = credentials else {
        return Ok(String::new());
    };
    if protocol == Protocol::Http {
        let username = std::str::from_utf8(&credentials.username).map_err(|_| ())?;
        let password = std::str::from_utf8(&credentials.password).map_err(|_| ())?;
        return Ok(http_credentials(username, password));
    }
    pt_arguments_from_bytes(&credentials.username, &credentials.password)
}

/// RFC 1929 form of [`arg_string_from_creds`] on raw bytes: a lone NUL password
/// is the "uname only" marker, otherwise the fields are concatenated.
pub(super) fn pt_arguments_from_bytes(
    username: &[u8],
    password: &[u8],
) -> std::result::Result<String, ()> {
    let mut bytes = username.to_vec();
    if password != [0x00] {
        bytes.extend_from_slice(password);
    }
    String::from_utf8(bytes).map_err(|_| ())
}

/// HTTP Basic parsers split at the first `:`, so rejoin the halves. Clients
/// append one `:` (an empty password) after the PT arguments; strip it.
pub(super) fn http_credentials(username: &str, password: &str) -> String {
    let mut joined = format!("{username}:{password}");
    if joined.ends_with(':') {
        joined.pop();
    }
    joined
}

/// Apply the parent's PT arguments to `builder`. Errors never carry the
/// submitted values, which may include bridge secrets.
pub(super) fn configure_builder<B>(builder: &mut B, arg_string: &str) -> Result<()>
where
    B: ptrs::ClientBuilder<TcpStream>,
{
    let args = if arg_string.is_empty() {
        ptrs::args::Args::default()
    } else {
        ptrs::args::Args::from_str(arg_string).map_err(|_| anyhow!("invalid PT arguments"))?
    };
    <B as ptrs::ClientBuilder<TcpStream>>::options(builder, &args)
        .map_err(|_| anyhow!("PT arguments rejected by the transport"))?;
    Ok(())
}

/// Pick the most specific reply for a failed outgoing connection: the one an
/// upstream proxy's failure maps to, else one derived from the kind of the
/// direct bridge dial's `io::Error`; anything else is "upstream unavailable".
pub(super) fn reply_for_error(error: &anyhow::Error) -> Reply {
    use std::io::ErrorKind;

    let Some(failed) = error.downcast_ref::<DialFailed>() else {
        return Reply::UpstreamUnavailable;
    };
    if let Some(reply) = failed.upstream {
        return reply;
    }
    match failed.kind {
        ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
        ErrorKind::TimedOut => Reply::TimedOut,
        ErrorKind::NetworkUnreachable => Reply::NetworkUnreachable,
        _ => Reply::UpstreamUnavailable,
    }
}

/// Best-effort terminal failure reply, bounded so teardown is never held up.
async fn reply_failure<S: AsyncWrite + Unpin>(
    request: &ParentRequest,
    parent: &mut S,
    reply: Reply,
) {
    let _ = tokio::time::timeout(SOCKS5_SETUP_TIMEOUT, request.reply(parent, reply)).await;
}
