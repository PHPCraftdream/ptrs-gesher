use super::*;
use futures::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn assert_socks5_setup_timeout(prefix: &[u8]) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.clone().acquire_owned().await.expect("permit");
    let (mut parent, lyrebird_side) = tokio::io::duplex(1024);
    parent
        .write_all(prefix)
        .await
        .expect("partial SOCKS5 write");
    let handler = async move {
        let _permit = permit;
        client_handle_connection(
            lyrebird_side,
            Obfs4PT::client_builder(),
            "127.0.0.1:9050".parse().expect("client address"),
        )
        .await
    };
    tokio::pin!(handler);

    assert!(handler.as_mut().now_or_never().is_none());
    let tick = std::time::Duration::from_millis(1);
    tokio::time::advance(SOCKS5_SETUP_TIMEOUT - tick).await;
    assert!(handler.as_mut().now_or_never().is_none());
    tokio::time::advance(tick).await;
    let error = handler
        .as_mut()
        .now_or_never()
        .expect("SOCKS5 handshake must finish at its deadline")
        .expect_err("silent SOCKS5 clients must time out");
    assert_eq!(
        error.to_string(),
        "proxy negotiation timed out",
        "only the setup deadline should terminate a silent client"
    );
    assert!(semaphore.try_acquire().is_ok(), "permit must be released");

    let mut byte = [0; 1];
    assert_eq!(parent.read(&mut byte).await.expect("socket read"), 0);
}

#[tokio::test(start_paused = true)]
async fn socks5_setup_timeout_drops_socket_and_releases_permit() {
    assert_socks5_setup_timeout(&[]).await;
}

#[tokio::test(start_paused = true)]
async fn partial_socks5_setup_timeout_drops_socket_and_releases_permit() {
    assert_socks5_setup_timeout(&[0x05]).await;
}

#[tokio::test]
async fn sdk_parent_negotiation_prefers_password_for_pt_arguments() {
    let (mut parent, connection) = tokio::io::duplex(1024);
    let handler = client_handle_connection(
        connection,
        Obfs4PT::client_builder(),
        "127.0.0.1:9050".parse().unwrap(),
    );
    let peer = async move {
        parent.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut reply = [0; 2];
        parent.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);
        parent.write_all(&[1, 1, b'u', 1, 0]).await.unwrap();
        parent.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [1, 0]);
        // Closing before CONNECT must terminate without a transport dial.
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(handler, peer)
    })
    .await
    .expect("parent negotiation must terminate");
    assert!(result.is_err());
}

#[tokio::test]
async fn sdk_parent_negotiation_preserves_anonymous_mode() {
    let (mut parent, connection) = tokio::io::duplex(1024);
    let handler = client_handle_connection(
        connection,
        Obfs4PT::client_builder(),
        "127.0.0.1:9050".parse().unwrap(),
    );
    let peer = async move {
        parent.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        parent.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
    };
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(handler, peer)
    })
    .await
    .expect("parent negotiation must terminate");
    assert!(result.is_err());
}

#[tokio::test(start_paused = true)]
async fn partial_http_setup_timeout_drops_socket_and_releases_permit() {
    assert_socks5_setup_timeout(b"CONNECT bridge.invalid:443 HTTP/1.1\r\nHost:").await;
}

#[tokio::test]
async fn http_connect_preserves_pipelined_payload_through_transport() {
    use base64::{engine::general_purpose, Engine as _};

    let server_builder = obfs4::ServerBuilder::<TcpStream>::default();
    let arguments = ptrs::args::Args::parse_smethod_args(&server_builder.client_params())
        .expect("parse bridge parameters")
        .encode_client_parameters();
    let server_transport = server_builder.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge = listener.local_addr().unwrap();
    let (mut parent, connection) = tokio::io::duplex(65_536);
    let payload = b"http-pipelined-payload";
    let bridge_peer = async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = server_transport.wrap(stream).await.unwrap();
        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received.as_slice(), payload);
        stream.write_all(&received).await.unwrap();
        stream.flush().await.unwrap();
        // The payload must have been forwarded exactly once: nothing follows it.
        let mut extra = [0u8; 64];
        let tail =
            tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut extra)).await;
        assert!(
            !matches!(tail, Ok(Ok(count)) if count > 0),
            "unexpected bytes after the forwarded payload"
        );
    };
    let handler = client_handle_connection(
        connection,
        Obfs4PT::client_builder(),
        "127.0.0.1:9050".parse().unwrap(),
    );
    let http_peer = async move {
        let credentials = general_purpose::STANDARD.encode(format!("{arguments}:"));
        let mut request = format!(
            "CONNECT {bridge} HTTP/1.1\r\nHost: {bridge}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
        ).into_bytes();
        request.extend_from_slice(&payload[..10]);
        parent.write_all(&request).await.unwrap();
        parent.flush().await.unwrap();
        let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        let mut response = vec![0; expected.len()];
        parent.read_exact(&mut response).await.unwrap();
        assert_eq!(response.as_slice(), expected);
        parent.write_all(&payload[10..]).await.unwrap();
        parent.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        parent.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed.as_slice(), payload);
        parent.shutdown().await.unwrap();
    };
    let ((), handler_result, ()) =
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(bridge_peer, handler, http_peer)
        })
        .await
        .expect("HTTP CONNECT and pipelined payload must finish");
    handler_result.unwrap();
}

#[test]
fn http_credentials_rejoin_basic_halves_and_strip_marker() {
    // Basic parsers split `url=https://x:` at its first ':'.
    assert_eq!(
        connection::http_credentials("url=https".into(), "//x:".into()),
        ("url=https://x".to_owned(), String::new())
    );
    // Plain arguments followed by the empty-password marker.
    assert_eq!(
        connection::http_credentials("cert=AAA;iat-mode=0".into(), String::new()),
        ("cert=AAA;iat-mode=0".to_owned(), String::new())
    );
    // Arguments sent without the marker keep their interior colons.
    assert_eq!(
        connection::http_credentials("url=https".into(), "//x".into()),
        ("url=https://x".to_owned(), String::new())
    );
}
