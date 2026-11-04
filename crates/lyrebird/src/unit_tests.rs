use super::*;

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

#[test]
fn accept_error_policy_retries_transient_failures() {
    assert!(is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::WouldBlock,
    )));
    assert!(is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::ConnectionAborted,
    )));
    assert!(!is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::PermissionDenied,
    )));
    assert!(!is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::Other,
    )));

    #[cfg(unix)]
    assert!(is_transient_accept_error(
        &std::io::Error::from_raw_os_error(libc::EMFILE,)
    ));

    assert!(accept_retry_delay(0) < accept_retry_delay(1));
    assert_eq!(accept_retry_delay(100), std::time::Duration::from_secs(1));
}

#[tokio::test]
async fn webtunnel_managed_path_ignores_socks_target() {
    let client = <webtunnel::WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::build(
        &webtunnel::WebTunnelBuilder::default(),
    );
    let result = client
        .managed_connect(
            "invalid.example:443".to_owned(),
            "127.0.0.1:1".parse().unwrap(),
        )
        .await;
    let error = match result {
        Ok(_) => panic!("unconfigured WebTunnel must fail before dialing"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("missing required parameter: url"));
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
    let addr = "127.0.0.1:9050";
    let resolved = resolve_target_addr(addr).unwrap();
    assert_eq!(resolved.to_string(), "127.0.0.1:9050");
}

#[test]
fn resolve_target_addr_ipv6() {
    let addr = "[::1]:443";
    let resolved = resolve_target_addr(addr).unwrap();
    assert_eq!(resolved.to_string(), "[::1]:443");
}

#[test]
fn resolve_target_addr_domain_fails() {
    let addr = "example.com:443";
    let err = resolve_target_addr(addr);
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
