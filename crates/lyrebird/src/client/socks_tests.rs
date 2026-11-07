use super::*;
use futures::FutureExt;
use resocks5_net::server::Reply;
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
        connection::http_credentials("url=https", "//x:"),
        "url=https://x"
    );
    // Plain arguments followed by the empty-password marker.
    assert_eq!(
        connection::http_credentials("cert=AAA;iat-mode=0", ""),
        "cert=AAA;iat-mode=0"
    );
    // Arguments sent without the marker keep their interior colons.
    assert_eq!(
        connection::http_credentials("url=https", "//x"),
        "url=https://x"
    );
}

#[test]
fn tunnel_closed_event_uses_the_address_field_name() {
    use std::sync::Mutex;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    #[derive(Default)]
    struct Fields(Arc<Mutex<Vec<String>>>);
    struct Collect<'a>(&'a mut Vec<String>);
    impl tracing::field::Visit for Collect<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, _: &dyn std::fmt::Debug) {
            self.0.push(field.name().to_owned());
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Fields {
        fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
            event.record(&mut Collect(&mut self.0.lock().unwrap()));
        }
    }

    let fields = Fields::default();
    let seen = fields.0.clone();
    let subscriber = tracing_subscriber::registry().with(fields);
    tracing::subscriber::with_default(subscriber, || {
        connection::log_tunnel_closed(
            "127.0.0.1:9050".parse().unwrap(),
            &std::io::Error::other("boom"),
        );
    });
    let seen = seen.lock().unwrap();
    assert!(seen.iter().any(|name| name == "address"), "{seen:?}");
    assert!(!seen.iter().any(|name| name == "addres"), "{seen:?}");
}

#[test]
fn http_credentials_trailing_colon_ambiguity_is_pinned() {
    // Basic carries `user:password`; clients append one ':' after the PT
    // arguments, so exactly one trailing ':' is always treated as that marker.
    // Arguments that genuinely end in ':' must therefore send the marker too.
    assert_eq!(
        connection::http_credentials("k=v", ":"),
        "k=v:",
        "genuine trailing ':' survives when the marker is present"
    );
    // Basic "k=v:" (marker only) and a genuine trailing ':' sent without the
    // marker both split into ("k=v", ""): the latter loses its colon.
    assert_eq!(
        connection::http_credentials("k=v", ""),
        "k=v",
        "a lone marker and an unmarked trailing ':' are indistinguishable"
    );
    assert_eq!(connection::http_credentials("", ""), "");
}

async fn drive_handler_to_reply(parent: &mut tokio::io::DuplexStream, request: &[u8]) -> Vec<u8> {
    parent.write_all(request).await.unwrap();
    parent.flush().await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_exact(&mut reply),
    )
    .await
    .expect("the failure reply should arrive, not hang")
    .expect("read SOCKS5 reply");
    reply.to_vec()
}

#[tokio::test]
async fn parent_domain_target_gets_host_unreachable_without_dns_or_dial() {
    let arguments = encoded_client_arguments();
    assert!(arguments.len() < 255);
    let (mut parent, connection) = tokio::io::duplex(65_536);
    let handler = tokio::spawn(client_handle_connection(
        connection,
        Obfs4PT::client_builder(),
        "127.0.0.1:9050".parse().unwrap(),
    ));

    parent.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    parent.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let mut auth = vec![1, arguments.len() as u8];
    auth.extend_from_slice(arguments.as_bytes());
    auth.extend_from_slice(&[1, 0]);
    parent.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    parent.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0]);

    // ATYP=3: PT targets must be IP literals; names are never resolved.
    let name = b"bridge.invalid";
    let mut connect = vec![5, 1, 0, 3, name.len() as u8];
    connect.extend_from_slice(name);
    connect.extend_from_slice(&443u16.to_be_bytes());
    let reply = drive_handler_to_reply(&mut parent, &connect).await;
    assert_eq!(reply, [5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handler)
        .await
        .expect("handler should finish")
        .expect("handler task panicked");
    assert!(outcome.is_err(), "a domain target must fail the connection");
}

#[tokio::test]
async fn http_connect_without_authorization_never_reports_success() {
    // The listener stays up for the whole test: a dial would sit in its
    // backlog and be seen below, while a refused connection could not.
    let bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge.local_addr().unwrap();
    let (mut parent, connection) = tokio::io::duplex(65_536);
    let handler = tokio::spawn(client_handle_connection(
        connection,
        Obfs4PT::client_builder(),
        "127.0.0.1:9050".parse().unwrap(),
    ));
    parent
        .write_all(
            format!("CONNECT {bridge_addr} HTTP/1.1\r\nHost: {bridge_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    parent.flush().await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_to_end(&mut response),
    )
    .await
    .expect("the handler must close after refusing")
    .expect("read HTTP response");
    let text = String::from_utf8_lossy(&response);
    assert!(
        !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200"),
        "CONNECT without PT arguments must not succeed: {text:?}"
    );
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handler)
        .await
        .expect("handler should finish")
        .expect("handler task panicked");
    // The refusal comes from the missing arguments (rejected by the parent
    // negotiation or by the transport options), not from a failed dial.
    let reason = outcome
        .expect_err("missing PT arguments must fail the connection")
        .to_string();
    assert!(
        matches!(
            reason.as_str(),
            "PT arguments rejected by the transport" | "SOCKS5 parent negotiation failed"
        ),
        "unexpected failure reason: {reason}"
    );
    let dialed = tokio::time::timeout(std::time::Duration::from_millis(100), bridge.accept()).await;
    assert!(dialed.is_err(), "the bridge must never be dialed");
}

#[test]
fn invalid_pt_arguments_error_never_echoes_submitted_values() {
    for arguments in [
        // Parse failure: empty key.
        "=secret-token",
        // Transport rejection: not a valid obfs4 certificate.
        "cert=not-a-valid-certificate-secret-token;iat-mode=0",
    ] {
        let mut builder = Obfs4PT::client_builder();
        let error = connection::configure_builder(&mut builder, arguments)
            .expect_err("invalid PT arguments must be rejected");
        let text = format!("{error:#}");
        assert!(
            !text.contains("secret-token"),
            "error must not echo submitted values: {text}"
        );
    }
}

#[test]
fn raw_socks5_credentials_rejoin_a_character_split_at_255_bytes() {
    // 254 ASCII bytes then a 2-byte character cut between UNAME and PASSWD:
    // each half alone is invalid UTF-8, the concatenation is valid.
    let mut text = "a".repeat(254);
    text.push('é');
    let (head, tail) = text.as_bytes().split_at(255);
    assert!(std::str::from_utf8(head).is_err());
    assert!(std::str::from_utf8(tail).is_err());
    assert_eq!(
        connection::pt_arguments_from_bytes(head, tail).unwrap(),
        text
    );

    // The lone-NUL password is the "uname only" marker; anything else joins.
    assert_eq!(
        connection::pt_arguments_from_bytes(b"cert=A;iat-mode=0", &[0]).unwrap(),
        "cert=A;iat-mode=0"
    );
    assert_eq!(
        connection::pt_arguments_from_bytes(b"cert=A;", b"iat-mode=0").unwrap(),
        "cert=A;iat-mode=0"
    );
    // Still invalid after joining: rejected, never lossily decoded.
    assert!(connection::pt_arguments_from_bytes(b"cert=\xff", &[0]).is_err());
    // Same answer as the string form for valid UTF-8.
    assert_eq!(
        connection::pt_arguments_from_bytes(b"k=v", b";x=y").unwrap(),
        arg_string_from_creds(Some(("k=v".into(), ";x=y".into())))
    );
}

#[test]
fn dial_failures_map_to_the_specific_socks5_replies() {
    use std::io::ErrorKind;

    fn failed(kind: ErrorKind) -> anyhow::Error {
        failed_via(kind, None)
    }
    fn failed_via(kind: ErrorKind, upstream: Option<Reply>) -> anyhow::Error {
        Err::<(), _>(anyhow!("handshake failed"))
            .context(DialFailed { kind, upstream })
            .unwrap_err()
    }
    // A reply recorded from an upstream proxy wins over the dial's kind.
    assert!(matches!(
        connection::reply_for_error(&failed_via(ErrorKind::Other, Some(Reply::Forbidden))),
        Reply::Forbidden
    ));
    assert!(matches!(
        connection::reply_for_error(&failed_via(
            ErrorKind::ConnectionRefused,
            Some(Reply::TimedOut)
        )),
        Reply::TimedOut
    ));
    assert!(matches!(
        connection::reply_for_error(&failed(ErrorKind::ConnectionRefused)),
        Reply::ConnectionRefused
    ));
    assert!(matches!(
        connection::reply_for_error(&failed(ErrorKind::TimedOut)),
        Reply::TimedOut
    ));
    assert!(matches!(
        connection::reply_for_error(&failed(ErrorKind::NetworkUnreachable)),
        Reply::NetworkUnreachable
    ));
    // Anything else, and errors that did not come from the dial, stay REP=4.
    assert!(matches!(
        connection::reply_for_error(&failed(ErrorKind::UnexpectedEof)),
        Reply::UpstreamUnavailable
    ));
    assert!(matches!(
        connection::reply_for_error(&anyhow!("upstream proxy connection failed")),
        Reply::UpstreamUnavailable
    ));
}

#[tokio::test]
async fn refused_bridge_dial_gets_connection_refused_reply() {
    let arguments = encoded_client_arguments();
    // A released port refuses the dial (Windows may take a couple of seconds).
    let bridge_addr = {
        let bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
        bridge.local_addr().unwrap()
    };
    let (mut parent, connection) = tokio::io::duplex(65_536);
    let handler = tokio::spawn(client_handle_connection(
        connection,
        Obfs4PT::client_builder(),
        "127.0.0.1:9050".parse().unwrap(),
    ));
    parent.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    parent.read_exact(&mut method).await.unwrap();
    let mut auth = vec![1, arguments.len() as u8];
    auth.extend_from_slice(arguments.as_bytes());
    auth.extend_from_slice(&[1, 0]);
    parent.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    parent.read_exact(&mut status).await.unwrap();
    let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
    connect.extend_from_slice(&bridge_addr.port().to_be_bytes());
    parent.write_all(&connect).await.unwrap();

    let mut reply = [0u8; 10];
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        parent.read_exact(&mut reply),
    )
    .await
    .expect("the failure reply should arrive, not hang")
    .expect("read SOCKS5 reply");
    assert_eq!(
        reply,
        [5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
        "REP=5 connection refused"
    );
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handler)
        .await
        .expect("handler should finish")
        .expect("handler task panicked");
    assert!(outcome.is_err());
}

/// Fresh throwaway bridge parameters in the form a parent sends them: the
/// server's SMETHOD arguments re-encoded as client parameters.
fn encoded_client_arguments() -> String {
    ptrs::args::Args::parse_smethod_args(
        &obfs4::ServerBuilder::<TcpStream>::default().client_params(),
    )
    .expect("parse bridge parameters")
    .encode_client_parameters()
}

/// Play the PT parent over `parent`: password auth carrying `arguments`, then
/// a CONNECT to the IPv4 `target`. Returns the 10-byte reply.
async fn socks5_parent_connect(
    parent: &mut tokio::io::DuplexStream,
    arguments: &str,
    target: std::net::SocketAddrV4,
) -> [u8; 10] {
    parent.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    parent.read_exact(&mut method).await.unwrap();
    let mut auth = vec![1, arguments.len() as u8];
    auth.extend_from_slice(arguments.as_bytes());
    auth.extend_from_slice(&[1, 0]);
    parent.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    parent.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0]);
    let mut connect = vec![5, 1, 0, 1];
    connect.extend_from_slice(&target.ip().octets());
    connect.extend_from_slice(&target.port().to_be_bytes());
    parent.write_all(&connect).await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        parent.read_exact(&mut reply),
    )
    .await
    .expect("the failure reply should arrive, not hang")
    .expect("read SOCKS5 reply");
    reply
}

#[tokio::test]
async fn upstream_proxy_refusals_are_forwarded_to_the_parent() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // (what the upstream answers to our CONNECT, what the parent must see)
    let cases: [(u8, u8); 4] = [(5, 5), (3, 3), (6, 6), (2, 2)];
    for (upstream_rep, parent_rep) in cases {
        let arguments = encoded_client_arguments();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            proxy::Proxy::parse(&format!("socks5://{}", upstream.local_addr().unwrap())).unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            // Read the whole CONNECT request whatever the address type.
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await.unwrap();
            let rest = match head[3] {
                1 => 4 + 2,
                4 => 16 + 2,
                _ => {
                    let mut length = [0u8; 1];
                    stream.read_exact(&mut length).await.unwrap();
                    usize::from(length[0]) + 2
                }
            };
            let mut tail = vec![0u8; rest];
            stream.read_exact(&mut tail).await.unwrap();
            stream
                .write_all(&[5, upstream_rep, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });
        let (mut parent, connection) = tokio::io::duplex(65_536);
        let handler = tokio::spawn(client_handle_connection_with_proxy(
            connection,
            Obfs4PT::client_builder(),
            "127.0.0.1:9050".parse().unwrap(),
            Some(Arc::new(proxy)),
        ));
        let reply =
            socks5_parent_connect(&mut parent, &arguments, "127.0.0.1:9".parse().unwrap()).await;
        assert_eq!(
            reply,
            [5, parent_rep, 0, 1, 0, 0, 0, 0, 0, 0],
            "upstream REP {upstream_rep}"
        );
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handler)
            .await
            .expect("handler should finish")
            .expect("handler task panicked");
        assert!(outcome.is_err());
        upstream_task.await.expect("upstream task panicked");
    }
}
