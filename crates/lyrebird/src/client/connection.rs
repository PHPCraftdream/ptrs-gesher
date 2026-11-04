use super::*;
use resocks5_net::server::{self as proxy_server, Reply, ServerOptions};
use tokio::io::AsyncWriteExt;

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

    // Reconstruct the PT-spec argument string from SOCKS5 user/pass and
    // hand it to the transport's `options(&Args)` so the obfs4
    // ClientBuilder picks up `cert=...` / `iat-mode=...` etc.
    let arg_string = arg_string_from_creds(creds);
    let args = if arg_string.is_empty() {
        ptrs::args::Args::default()
    } else {
        ptrs::args::Args::from_str(&arg_string).context("parsing PT arg string")?
    };
    <B as ptrs::ClientBuilder<TcpStream>>::options(&mut builder, &args)
        .map_err(|e| anyhow::anyhow!("applying PT args to builder: {e}"))?;

    // Build the client and let the transport choose its connection path.
    // WebTunnel owns URL dialing; its SOCKS target is only a PT-spec carrier
    // placeholder and must never become a direct dial target.
    let pt_client = builder.build();
    let mut pt_conn =
        C::managed_connect_with_proxy(pt_client, target_addr, client_addr, proxy).await?;

    // Reply only after the actual transport handshake succeeds.
    tokio::time::timeout(
        SOCKS5_SETUP_TIMEOUT,
        request.reply(&mut parent, Reply::Established),
    )
    .await
    .context("proxy reply timed out")?
    .context("writing established reply to PT parent")?;

    let pipeline = request.take_pipeline();
    if !pipeline.is_empty() {
        tokio::time::timeout(SOCKS5_SETUP_TIMEOUT, async {
            pt_conn.write_all(&pipeline).await?;
            pt_conn.flush().await
        })
        .await
        .context("initial payload forwarding timed out")??;
    }
    if let Err(e) = copy_bidirectional(&mut parent, &mut pt_conn).await {
        warn!(
            addres = sensitive(client_addr).to_string(),
            "tunnel closed with error: {e:#?}"
        );
    }
    Ok(())
}
