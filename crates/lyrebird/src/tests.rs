use super::*;

#[tokio::test(start_paused = true)]
async fn cancellation_interrupts_a_full_connection_limit() {
    use futures::FutureExt;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let _occupied = semaphore.acquire().await.unwrap();
    let cancel = CancellationToken::new();
    let permit = connection_permit(semaphore.clone(), &cancel);
    tokio::pin!(permit);
    assert!(permit.as_mut().now_or_never().is_none());
    cancel.cancel();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), permit).await;
    assert!(matches!(outcome, Ok(None)));
}

#[test]
fn arg_string_uname_only_when_passwd_is_nul() {
    let creds = Some(("cert=AAA;iat-mode=0".to_string(), "\0".to_string()));
    assert_eq!(arg_string_from_creds(creds), "cert=AAA;iat-mode=0");
}

#[test]
fn arg_string_concat_when_passwd_nonempty() {
    let creds = Some(("cert=".to_string(), "AAA;iat-mode=0".to_string()));
    assert_eq!(arg_string_from_creds(creds), "cert=AAA;iat-mode=0");
}

#[test]
fn arg_string_empty_when_no_creds() {
    assert_eq!(arg_string_from_creds(None), "");
}

#[test]
fn arg_string_then_parse_yields_kv_map() {
    // 300-char value split across the two SOCKS5 fields (uname=255,
    // passwd=remainder) — the canonical case the spec is written for.
    let big = "cert=".to_string() + &"A".repeat(250);
    let tail = ";iat-mode=0".to_string();
    let creds = Some((big.clone(), tail.clone()));
    let arg_string = arg_string_from_creds(creds);
    assert_eq!(arg_string, big + &tail);

    let args = ptrs::args::Args::from_str(&arg_string).expect("parse");
    assert!(args.retrieve("cert").is_some());
    assert_eq!(args.retrieve("iat-mode").as_deref(), Some("0"));
}

#[tokio::test]
async fn pt_args_auth_propagates_creds() {
    use fast_socks5::server::Authentication;
    let auth = PtArgsAuth;
    let got = auth
        .authenticate(Some(("u".to_string(), "p".to_string())))
        .await;
    assert_eq!(got, Some(("u".to_string(), "p".to_string())));
}

#[tokio::test]
async fn pt_args_auth_accepts_no_creds() {
    use fast_socks5::server::Authentication;
    let auth = PtArgsAuth;
    let got = auth.authenticate(None).await;
    assert_eq!(got, Some((String::new(), String::new())));
}

// -- dial_bridge socket options ----------------------------------------
//
// The carrier-resilience options (TCP_NODELAY + TCP keepalive) are silent
// safeguards: if the `set_*` lines disappear, nothing breaks at build or
// unit-test time, but the bridge channel becomes susceptible to the same
// mid-bootstrap 10053/10054 tear-downs that motivated `dial_bridge` in
// the first place. These compliance tests catch a regression that drops
// either option.

#[tokio::test]
async fn dial_bridge_sets_tcp_nodelay() {
    // Loopback listener so the dial completes synchronously.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _accept = tokio::spawn(async move { listener.accept().await });

    let stream = dial_bridge(addr).await.expect("dial_bridge");
    assert!(
        stream.nodelay().expect("nodelay() readback"),
        "dial_bridge must enable TCP_NODELAY on the carrier socket"
    );
}

#[tokio::test]
async fn dial_bridge_arms_tcp_keepalive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _accept = tokio::spawn(async move { listener.accept().await });

    let stream = dial_bridge(addr).await.expect("dial_bridge");
    // `keepalive()` returns whether SO_KEEPALIVE is on. Setting the
    // per-keepalive intervals via `socket2::TcpKeepalive` also flips
    // the SO_KEEPALIVE flag, so its presence is the read-back signal
    // that `set_tcp_keepalive(&keepalive)` was actually called.
    let sock = socket2::SockRef::from(&stream);
    assert!(
        sock.keepalive().expect("SO_KEEPALIVE readback"),
        "dial_bridge must arm TCP keepalive on the carrier socket"
    );
}

// -- resolve_target_addr --

#[test]
fn resolve_target_addr_ip() {
    let addr = TargetAddr::Ip("127.0.0.1:9050".parse().unwrap());
    let resolved = resolve_target_addr(&addr).unwrap();
    assert_eq!(resolved.to_string(), "127.0.0.1:9050");
}

#[test]
fn resolve_target_addr_ipv6() {
    let addr = TargetAddr::Ip("[::1]:443".parse().unwrap());
    let resolved = resolve_target_addr(&addr).unwrap();
    assert_eq!(resolved.to_string(), "[::1]:443");
}

#[test]
fn resolve_target_addr_domain_fails() {
    let addr = TargetAddr::Domain("example.com".into(), 443);
    let err = resolve_target_addr(&addr);
    assert!(
        err.is_err(),
        "domain resolution should fail (PT doesn't do DNS)"
    );
}

// -- arg_string edge cases --

#[test]
fn arg_string_empty_uname_and_passwd() {
    let creds = Some((String::new(), String::new()));
    assert_eq!(arg_string_from_creds(creds), "");
}

#[test]
fn arg_string_passwd_is_nul_only() {
    let creds = Some((String::new(), "\0".to_string()));
    assert_eq!(arg_string_from_creds(creds), "");
}

// -- establish_pt_conn (outgoing-dial seam) --
//
// These exercise the client outgoing-connection path
// (`client_handle_connection` → `establish_pt_conn`) that was previously
// unreachable in tests because it created a real `TcpStream::connect`
// inline. The dial is now an injectable `Pin<FutureResult<_, _>>`, so a
// `tokio::io::duplex()` half (or a deliberately-failing future) stands in
// for the OR-port socket. We drive the *ptrs trait* surface end to end:
// build an obfs4 client from a bridge-line arg string exactly the way
// `client_handle_connection` does (`Args` → `ClientBuilder::options` →
// `build`), then run the real obfs4 handshake over the duplex against a
// matching obfs4 `Server`.

use ptrs::ClientBuilder as _;
use tokio::io::DuplexStream;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Build an obfs4 client transport from a bridge-line arg string via the
/// same `ptrs` builder path lyrebird uses for a real SOCKS connection:
/// parse the args, apply them through `ptrs::ClientBuilder::options`, then
/// `build`. The obfs4 builder/transport impls are generic over the socket
/// type, so we pin `InRW = DuplexStream` here (an in-memory stand-in for
/// the OR-port `TcpStream`).
fn obfs4_client_from_args(arg_string: &str) -> obfs4::Client {
    let args = ptrs::args::Args::from_str(arg_string).expect("parse bridge-line args");
    let mut builder = obfs4::ClientBuilder::default();
    <obfs4::ClientBuilder as ptrs::ClientBuilder<DuplexStream>>::options(&mut builder, &args)
        .expect("apply obfs4 args to builder");
    <obfs4::ClientBuilder as ptrs::ClientBuilder<DuplexStream>>::build(&builder)
}

#[tokio::test]
async fn establish_pt_conn_obfs4_handshake_and_proxies_bytes() {
    // A fresh obfs4 server with a random identity and the bridge-line
    // arg string that a client must present to reach it.
    let server_builder = obfs4::ServerBuilder::<DuplexStream>::default();
    let arg_string = server_builder.client_params();
    let server = server_builder.build();

    // In-memory stand-in for the OR-port socket.
    let (client_side, server_side) = tokio::io::duplex(65_536);

    // Server peer: complete the obfs4 handshake, then echo one message.
    let server_task = tokio::spawn(async move {
        let mut s = server.wrap(server_side).await.expect("server handshake");
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.expect("server read");
        s.write_all(&buf[..n]).await.expect("server echo write");
        s.flush().await.expect("server flush");
    });

    // Client: build through the ptrs trait, then drive the seam with a
    // dial future that yields the duplex half instead of a TcpStream.
    let client = obfs4_client_from_args(&arg_string);
    let dial: Pin<ptrs::FutureResult<DuplexStream, std::io::Error>> =
        Box::pin(async move { Ok(client_side) });
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();

    let mut tunnel = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        establish_pt_conn(client, dial, client_addr),
    )
    .await
    .expect("establish_pt_conn timed out")
    .expect("establish_pt_conn should complete the obfs4 handshake");

    // Bytes written into the obfs4 tunnel must come back through the
    // server echo — proving `establish` consumed the injected dial
    // stream and a real encrypted session is in place.
    let msg = b"through-the-obfs4-tunnel";
    tunnel.write_all(msg).await.expect("client write");
    tunnel.flush().await.expect("client flush");

    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tunnel.read_exact(&mut got),
    )
    .await
    .expect("client read timed out")
    .expect("client read");
    assert_eq!(&got, msg, "data must round-trip through the obfs4 tunnel");

    tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("server task timed out")
        .expect("server task panicked");
}

#[tokio::test]
async fn establish_pt_conn_dial_failure_is_error_not_panic() {
    // The dial future itself fails (e.g. OR-port connection refused).
    // `establish` must surface this as an `Err` without panicking — this
    // path is reachable from the network, so a regression to `unwrap`
    // would be a remote DoS.
    let server_builder = obfs4::ServerBuilder::<DuplexStream>::default();
    let arg_string = server_builder.client_params();
    let client = obfs4_client_from_args(&arg_string);

    let dial: Pin<ptrs::FutureResult<DuplexStream, std::io::Error>> = Box::pin(async {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "dial refused",
        ))
    });
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();

    let result = establish_pt_conn(client, dial, client_addr).await;
    assert!(
        result.is_err(),
        "a failed dial must produce an error, not a tunnel"
    );
}

#[tokio::test]
async fn establish_pt_conn_handshake_eof_is_error_not_panic() {
    // The dial succeeds (a socket is produced) but the OR-port peer
    // immediately closes — e.g. the bridge dropped the connection during
    // the handshake. The obfs4 client's first handshake read then hits
    // EOF, which must surface as an `Err` from `establish_pt_conn`,
    // promptly and without panicking. (The client returns `UnexpectedEof`
    // on a 0-byte read rather than blocking until its handshake timeout.)
    // This complements the positive end-to-end test: that one proves the
    // bridge-line args reach the handshake crypto (a wrong/empty cert
    // would make it fail); this one proves the failure branch is handled.
    let server_builder = obfs4::ServerBuilder::<DuplexStream>::default();
    let arg_string = server_builder.client_params();
    let client = obfs4_client_from_args(&arg_string);

    let (client_side, server_side) = tokio::io::duplex(65_536);
    // Close the peer half before the handshake reads anything.
    drop(server_side);

    let dial: Pin<ptrs::FutureResult<DuplexStream, std::io::Error>> =
        Box::pin(async move { Ok(client_side) });
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        establish_pt_conn(client, dial, client_addr),
    )
    .await
    .expect("establish_pt_conn should fail fast on EOF, not block until timeout");

    assert!(
        result.is_err(),
        "a peer that closes mid-handshake must produce an error, not a tunnel"
    );
}

// -- Bug 2 regression: cancel arm must break the accept loop --

/// Verify that `client_accept_loop` exits promptly when the
/// `CancellationToken` is already cancelled before the loop starts.
/// Without the `break` in the cancel arm, `cancelled()` is
/// immediately ready on every iteration and the loop spins forever,
/// causing this test to hit the timeout and fail.
#[tokio::test]
async fn client_accept_loop_exits_on_pre_cancelled_token() {
    // Bind a real listener so the function signature is satisfied.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener for test");

    // Cancel BEFORE entering the loop — simulates shutdown race.
    let cancel = CancellationToken::new();
    cancel.cancel();

    let builder = Obfs4PT::client_builder();
    let proxy_uri = url::Url::parse("data:,").expect("placeholder url");

    // The loop must return within 2 s.  On the old code (no break)
    // it would spin indefinitely and the timeout would fire.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_accept_loop(listener, builder, proxy_uri, cancel),
    )
    .await;

    assert!(
        result.is_ok(),
        "client_accept_loop must exit promptly when the token is cancelled, not spin"
    );
    assert!(
        result.unwrap().is_ok(),
        "client_accept_loop should return Ok(()) on graceful cancel"
    );
}

// -- Bridge-connection regression (fast_socks5 `execute_command`) --
//
// `client_handle_connection` must use fast-socks5 only to *parse* the
// request, never to execute it. With the default `execute_command = true`,
// `upgrade_to_socks5()` would itself open a *plain* TCP connection to the
// bridge and send the SOCKS reply — bypassing obfs4, so no bridge could
// ever be reached through the transport. The fix sets
// `execute_command(false)` and has lyrebird dial obfs4 itself, replying to
// the parent only once the tunnel is up. These tests drive the real SOCKS5
// client protocol against `client_handle_connection` pointed at a real
// loopback "bridge".

/// Play the SOCKS5 client (as arti/tor would) over `parent`: user/pass
/// auth carrying the PT arg string, then a CONNECT to `bridge`. Returns
/// after the CONNECT request is sent; the caller asserts on the reply.
async fn socks5_client_connect(parent: &mut DuplexStream, arg_string: &str, bridge: SocketAddr) {
    // greeting: VER=5, 1 method, user/pass (0x02)
    parent.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    parent.flush().await.unwrap();
    let mut sel = [0u8; 2];
    parent.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x02], "server must select user/pass auth");

    // RFC 1929 user/pass: pack the arg string into UNAME, PASSWD = single
    // NUL (the `arg_string_from_creds` "uname only" form).
    let uname = arg_string.as_bytes();
    assert!(
        uname.len() <= 255,
        "this test packs the arg string into one SOCKS field"
    );
    let mut auth = vec![0x01, uname.len() as u8];
    auth.extend_from_slice(uname);
    auth.extend_from_slice(&[0x01, 0x00]); // PLEN=1, PASSWD=0x00
    parent.write_all(&auth).await.unwrap();
    parent.flush().await.unwrap();
    let mut authresp = [0u8; 2];
    parent.read_exact(&mut authresp).await.unwrap();
    assert_eq!(authresp, [0x01, 0x00], "user/pass auth must succeed");

    // CONNECT: VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), addr, port.
    let (octets, port) = match bridge {
        SocketAddr::V4(v4) => (v4.ip().octets(), v4.port()),
        SocketAddr::V6(_) => unreachable!("test binds IPv4 loopback"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&octets);
    req.extend_from_slice(&port.to_be_bytes());
    parent.write_all(&req).await.unwrap();
    parent.flush().await.unwrap();
}

#[tokio::test]
async fn client_handle_connection_tunnels_through_obfs4_and_replies_itself() {
    // A real loopback "bridge" running an obfs4 *server*. `server.wrap()`
    // completes only if an obfs4 *client* handshake arrives — i.e. the
    // connection that reached the bridge was obfs4, not a plain TCP proxy.
    // On the buggy `execute_command = true` path the bridge would instead
    // receive fast-socks5's plain relay and `wrap()` would never complete,
    // failing this test.
    let server_builder = obfs4::ServerBuilder::<TcpStream>::default();
    let arg_string = server_builder.client_params();
    let server = server_builder.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = listener.local_addr().unwrap();

    let bridge = tokio::spawn(async move {
        let (sock, _peer) = listener.accept().await.expect("bridge accept");
        let mut s = server.wrap(sock).await.expect("bridge obfs4 handshake");
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.expect("bridge read");
        s.write_all(&buf[..n]).await.expect("bridge echo");
        s.flush().await.expect("bridge flush");
    });

    // Parent (arti/tor) side over an in-memory duplex; `lyrebird_side` is
    // the connection `client_handle_connection` serves SOCKS on.
    let (mut parent, lyrebird_side) = tokio::io::duplex(65_536);
    let builder = Obfs4PT::client_builder();
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    let handler = tokio::spawn(client_handle_connection(
        lyrebird_side,
        builder,
        url::Url::parse("data:,").unwrap(),
        client_addr,
    ));

    socks5_client_connect(&mut parent, &arg_string, bridge_addr).await;

    // The reply is the canonical success frame lyrebird writes itself
    // (fast-socks5 sends nothing — execute_command is disabled), and it
    // arrives only because the obfs4 tunnel to the bridge came up.
    let mut reply = [0u8; 10];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_exact(&mut reply),
    )
    .await
    .expect("SOCKS5 reply timed out")
    .expect("read SOCKS5 reply");
    assert_eq!(
        reply,
        [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        "lyrebird must send the SOCKS5 success reply itself after the obfs4 handshake"
    );

    // End-to-end: a probe must round-trip through the obfs4 tunnel.
    let probe = b"bridge-tunnel-probe";
    parent.write_all(probe).await.unwrap();
    parent.flush().await.unwrap();
    let mut got = vec![0u8; probe.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_exact(&mut got),
    )
    .await
    .expect("probe round-trip timed out")
    .expect("read probe echo");
    assert_eq!(
        &got, probe,
        "probe must round-trip through the obfs4 tunnel"
    );

    tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
        .await
        .expect("bridge task timed out")
        .expect("bridge task panicked");
    drop(parent); // let copy_bidirectional see EOF and the handler finish
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handler).await;
}

#[tokio::test]
async fn client_handle_connection_no_success_reply_when_bridge_not_obfs4() {
    // The bridge accepts the TCP connection but is NOT an obfs4 server: it
    // closes immediately, so the obfs4 client handshake fails. lyrebird
    // must therefore NOT report CONNECT success to the parent. The old
    // `execute_command = true` path replied success on the bare TCP
    // connect regardless of whether obfs4 could be established, which is
    // exactly the bug — so this test would fail on it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = listener.local_addr().unwrap();
    let bridge = tokio::spawn(async move {
        let (sock, _peer) = listener.accept().await.expect("bridge accept");
        drop(sock); // not obfs4 — close before any handshake byte
    });

    // A well-formed cert so `options()` succeeds and the failure is the
    // handshake, not arg parsing; this throwaway identity is never honored.
    let arg_string = obfs4::ServerBuilder::<TcpStream>::default().client_params();

    let (mut parent, lyrebird_side) = tokio::io::duplex(65_536);
    let builder = Obfs4PT::client_builder();
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    let handler = tokio::spawn(client_handle_connection(
        lyrebird_side,
        builder,
        url::Url::parse("data:,").unwrap(),
        client_addr,
    ));

    socks5_client_connect(&mut parent, &arg_string, bridge_addr).await;

    // No success reply: the handler returns Err before writing one, so its
    // side of the duplex drops and the parent's read hits EOF rather than a
    // 10-byte success frame.
    let mut reply = [0u8; 10];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_exact(&mut reply),
    )
    .await
    .expect("the read should resolve (EOF), not hang");
    assert!(
        read.is_err(),
        "no SOCKS5 success reply must be sent when the obfs4 handshake fails"
    );

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handler)
        .await
        .expect("handler should finish")
        .expect("handler task panicked");
    assert!(
        outcome.is_err(),
        "client_handle_connection must surface the failed obfs4 dial as an error"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), bridge).await;
}

// -- TOR_PT_PROXY fail-closed (PT-spec §3.3.2) --
//
// `TOR_PT_PROXY` is a parent requirement: every outgoing connection must
// be routed through that upstream proxy. The transport stack has no proxy
// dialer (`dial_bridge` connects directly), so a configured proxy must be
// rejected via `PROXY-ERROR` with setup aborting before any listener is
// bound or any dial can happen -- never silently ignored (the parent
// would believe the route is honored) and never answered with
// `PROXY DONE` (the route would not actually be used). The exact
// control-channel wire sequence is asserted end to end by
// `tests/proxy_error.rs`, which spawns the real binary.

/// Serialize the env-mutating tests below: `TOR_PT_*` variables are
/// process-global state, and `ClientInfo::new()` reads them. A tokio
/// mutex is used because the guarded region spans the awaits of
/// `client_setup` (a std `MutexGuard` held across `.await` is a lint
/// error and a deadlock hazard).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn set_client_env(proxy: Option<&str>) {
    std::env::set_var("TOR_PT_MANAGED_TRANSPORT_VER", "1");
    std::env::set_var("TOR_PT_CLIENT_TRANSPORTS", "obfs4");
    match proxy {
        Some(uri) => std::env::set_var("TOR_PT_PROXY", uri),
        None => std::env::remove_var("TOR_PT_PROXY"),
    }
}

fn clear_client_env() {
    std::env::remove_var("TOR_PT_MANAGED_TRANSPORT_VER");
    std::env::remove_var("TOR_PT_CLIENT_TRANSPORTS");
    std::env::remove_var("TOR_PT_PROXY");
}

#[tokio::test]
async fn client_setup_rejects_configured_upstream_proxy() {
    let _guard = ENV_LOCK.lock().await;
    set_client_env(Some("socks5://user:pass@127.0.0.1:9050"));

    let outcome = client_setup("unused-test-state-dir", CancellationToken::new()).await;

    clear_client_env();

    // The setup must fail closed: an error naming the refused proxy, so
    // the parent process sees a failed configuration instead of a PT that
    // quietly connects directly.
    let err = outcome.expect_err("a configured TOR_PT_PROXY must abort client_setup");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("TOR_PT_PROXY") && msg.contains("127.0.0.1:9050"),
        "the refusal must name the offending variable and proxy URI, got: {msg}"
    );
}

#[tokio::test]
async fn client_setup_without_proxy_completes_and_signals_done() {
    let _guard = ENV_LOCK.lock().await;
    set_client_env(None);

    // Without TOR_PT_PROXY the fail-closed path must not trigger: the
    // normal setup runs (listener bound, CMETHOD announced upstream) and
    // signals completion over the exit channel once shut down.
    let cancel = CancellationToken::new();
    let outcome = client_setup("unused-test-state-dir", cancel.clone()).await;
    let rx = outcome.expect("without TOR_PT_PROXY, client_setup must proceed normally");

    cancel.cancel();
    let finished = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await;
    assert!(
        matches!(finished, Ok(Ok(true))),
        "listener shutdown must resolve the exit channel with true"
    );

    clear_client_env();
}
