use super::*;
use futures::FutureExt;
use tokio::io::{duplex, BufReader};

/// Feed `input` to [`accept`], then close the peer's write side. Returns the
/// outcome, everything lyrebird wrote back, and the reader (to inspect what
/// stayed buffered).
async fn drive(
    input: &[u8],
) -> (
    Result<ParentRequest>,
    Vec<u8>,
    BufReader<tokio::io::DuplexStream>,
) {
    let (mut peer, side) = duplex(65_536);
    peer.write_all(input).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut reader = BufReader::new(side);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), accept(&mut reader))
        .await
        .expect("the parser must not hang on finished input");
    // Whatever lyrebird wrote is already in the pipe.
    let mut written = Vec::new();
    let mut chunk = [0; 256];
    while let Some(Ok(count @ 1..)) = peer.read(&mut chunk).now_or_never() {
        written.extend_from_slice(&chunk[..count]);
    }
    (outcome, written, reader)
}

fn connect_v4(port: u16) -> Vec<u8> {
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn socks(prefix: &[u8], request: &[u8]) -> Vec<u8> {
    [prefix, request].concat()
}

#[tokio::test]
async fn socks5_pt_arguments_come_from_the_rfc1929_fields() {
    let mut input = vec![5, 1, 2, 1, 9];
    input.extend_from_slice(b"cert=AAAA");
    input.extend_from_slice(&[1, 0]);
    input.extend_from_slice(&connect_v4(443));
    let (outcome, written, _) = drive(&input).await;
    let request = outcome.unwrap();
    assert_eq!(request.protocol, Protocol::Socks5);
    assert_eq!(request.target, "127.0.0.1:443");
    let credentials = request.credentials.as_ref().expect("credentials");
    assert_eq!(credentials.username.as_slice(), b"cert=AAAA");
    assert_eq!(credentials.password.as_slice(), [0]);
    // Method 0x02 selected, sub-negotiation accepted, no final reply yet.
    assert_eq!(written, [5, 2, 1, 0]);
}

#[tokio::test]
async fn socks5_prefers_the_password_method_wherever_it_is_listed() {
    for methods in [[5, 2, 0, 2], [5, 2, 2, 0]] {
        let input = socks(&[methods[0], methods[1], methods[2], methods[3]], &{
            let mut rest = vec![1, 1, b'u', 1, b'p'];
            rest.extend_from_slice(&connect_v4(80));
            rest
        });
        let (outcome, written, _) = drive(&input).await;
        let request = outcome.unwrap();
        assert!(request.credentials.is_some(), "{methods:?}");
        assert_eq!(written, [5, 2, 1, 0], "{methods:?}");
    }
}

#[tokio::test]
async fn socks5_anonymous_mode_and_ipv6_target() {
    let mut input = vec![5, 1, 0, 5, 1, 0, 4];
    input.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    input.extend_from_slice(&80u16.to_be_bytes());
    let (outcome, written, _) = drive(&input).await;
    let request = outcome.unwrap();
    assert!(request.credentials.is_none());
    assert_eq!(request.target, "[::1]:80");
    assert_eq!(written, [5, 0]);
}

#[tokio::test]
async fn socks5_without_an_acceptable_method_is_refused() {
    // GSSAPI only: nothing lyrebird offers.
    let (outcome, written, _) = drive(&[5, 1, 1]).await;
    assert!(outcome.is_err());
    assert_eq!(written, [5, 255]);
}

#[tokio::test]
async fn rfc1929_with_a_bad_version_is_refused() {
    let (outcome, written, _) = drive(&[5, 1, 2, 2, 1, b'u', 1, b'p']).await;
    assert!(outcome.is_err());
    assert_eq!(written, [5, 2, 1, 1]);
}

#[tokio::test]
async fn socks5_request_errors_get_the_matching_reply_code() {
    let anonymous = [5, 1, 0];
    let cases: [(&[u8], u8); 4] = [
        // BIND
        (&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80], 7),
        // unknown ATYP
        (&[5, 1, 0, 9], 8),
        // domain with a space
        (&[5, 1, 0, 3, 3, b'a', b' ', b'b', 0, 80], 4),
        // empty domain
        (&[5, 1, 0, 3, 0, 0, 80], 4),
    ];
    for (request, rep) in cases {
        let (outcome, written, _) = drive(&socks(&anonymous, request)).await;
        assert!(outcome.is_err(), "rep {rep}");
        assert_eq!(
            written,
            [&[5, 0][..], &[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]].concat()
        );
    }
    // A wrong request version closes without a reply.
    let (outcome, written, _) = drive(&socks(&anonymous, &[4, 1, 0, 1])).await;
    assert!(outcome.is_err());
    assert_eq!(written, [5, 0]);
}

#[tokio::test]
async fn socks5_domain_target_is_passed_on_unresolved() {
    let name = b"bridge.invalid";
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name);
    request.extend_from_slice(&443u16.to_be_bytes());
    let (outcome, _, _) = drive(&socks(&[5, 1, 0], &request)).await;
    assert_eq!(outcome.unwrap().target, "bridge.invalid:443");
}

#[tokio::test]
async fn truncated_and_unrecognised_input_is_an_error() {
    for input in [
        &b""[..],
        &[5],
        &[5, 2, 0],
        &[5, 1, 2, 1, 5, b'a'],
        &[5, 1, 0, 5, 1, 0, 1, 1, 2],
        &[0x16, 3, 1],
        &[0x00],
    ] {
        let (outcome, _, _) = drive(input).await;
        assert!(outcome.is_err(), "{input:?}");
    }
}

fn connect_head(extra: &str) -> Vec<u8> {
    format!("CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n{extra}\r\n").into_bytes()
}

#[tokio::test]
async fn http_connect_takes_pt_arguments_from_basic() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let encoded = STANDARD.encode("cert=AAAA;iat-mode=0:");
    for header in [
        format!("Proxy-Authorization: Basic {encoded}\r\n"),
        format!("proxy-authorization:   basic   {encoded}  \r\n"),
    ] {
        let (outcome, written, _) = drive(&connect_head(&header)).await;
        let request = outcome.unwrap();
        assert_eq!(request.protocol, Protocol::Http);
        assert_eq!(request.target, "192.0.2.1:443");
        let credentials = request.credentials.as_ref().expect("credentials");
        assert_eq!(credentials.username.as_slice(), b"cert=AAAA;iat-mode=0");
        assert!(credentials.password.is_empty());
        assert!(written.is_empty(), "no reply is sent by the parser");
    }
}

#[tokio::test]
async fn http_basic_splits_at_the_first_colon_only() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    for (plain, user, password) in [
        ("url=https://x:", &b"url=https"[..], &b"//x:"[..]),
        ("onlyuser", b"onlyuser", b""),
        (":p", b"", b"p"),
    ] {
        let header = format!("Proxy-Authorization: Basic {}\r\n", STANDARD.encode(plain));
        let (outcome, _, _) = drive(&connect_head(&header)).await;
        let request = outcome.unwrap();
        let credentials = request.credentials.as_ref().unwrap();
        assert_eq!(credentials.username.as_slice(), user, "{plain}");
        assert_eq!(credentials.password.as_slice(), password, "{plain}");
    }
}

#[tokio::test]
async fn http_connect_without_authorization_has_no_credentials() {
    let (outcome, _, _) = drive(&connect_head("")).await;
    assert!(outcome.unwrap().credentials.is_none());
}

#[tokio::test]
async fn http_pipelined_bytes_stay_buffered_for_the_tunnel() {
    let mut input = connect_head("");
    input.extend_from_slice(b"early-payload");
    let (outcome, _, mut reader) = drive(&input).await;
    outcome.unwrap();
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"early-payload");
}

#[tokio::test]
async fn http_malformed_requests_get_a_closing_error_status() {
    let big = format!("X-Pad: {}\r\n", "a".repeat(MAX_HEAD_BYTES));
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (b"GET / HTTP/1.1\r\n\r\n".to_vec(), "HTTP/1.1 501"),
        (b"CONNECT 192.0.2.1:443\r\n\r\n".to_vec(), "HTTP/1.1 400"),
        (
            b"CONNECT nohostport HTTP/1.1\r\n\r\n".to_vec(),
            "HTTP/1.1 400",
        ),
        (
            b"CONNECT a\x01b:443 HTTP/1.1\r\n\r\n".to_vec(),
            "HTTP/1.1 400",
        ),
        (
            b"CONNECT 192.0.2.1:443 HTTP/1.1\nHost: x\n\n".to_vec(),
            "HTTP/1.1 400",
        ),
        (connect_head("NoColonHeader\r\n"), "HTTP/1.1 400"),
        (
            connect_head("Proxy-Authorization: Bearer abc\r\n"),
            "HTTP/1.1 400",
        ),
        (
            connect_head("Proxy-Authorization: Basic !!!!\r\n"),
            "HTTP/1.1 400",
        ),
        (
            connect_head("Proxy-Authorization: Basic YTpi\r\nProxy-Authorization: Basic YTpi\r\n"),
            "HTTP/1.1 400",
        ),
        (connect_head(&big), "HTTP/1.1 431"),
        (
            b"CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost:".to_vec(),
            "HTTP/1.1 400",
        ),
    ];
    for (input, status) in cases {
        let (outcome, written, _) = drive(&input).await;
        assert!(outcome.is_err(), "{status}");
        let text = String::from_utf8_lossy(&written);
        assert!(text.starts_with(status), "{status}: {text:?}");
        assert!(text.contains("Connection: close"), "{text:?}");
    }
}

#[test]
fn replies_have_the_documented_wire_form() {
    let rep = |code: u8| [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
    let socks = [
        (Reply::Established, 0),
        (Reply::Forbidden, 2),
        (Reply::NetworkUnreachable, 3),
        (Reply::UpstreamUnavailable, 4),
        (Reply::ConnectionRefused, 5),
        (Reply::TimedOut, 6),
        (Reply::GeneralFailure, 1),
        (Reply::Overloaded, 1),
    ];
    for (reply, code) in socks {
        assert_eq!(reply_bytes(Protocol::Socks5, reply), rep(code), "{reply:?}");
    }
    let http = [
        (Reply::Forbidden, "HTTP/1.1 403"),
        (Reply::UpstreamUnavailable, "HTTP/1.1 502"),
        (Reply::ConnectionRefused, "HTTP/1.1 502"),
        (Reply::NetworkUnreachable, "HTTP/1.1 502"),
        (Reply::TimedOut, "HTTP/1.1 504"),
        (Reply::GeneralFailure, "HTTP/1.1 502"),
        (Reply::Overloaded, "HTTP/1.1 503"),
    ];
    for (reply, status) in http {
        let bytes = reply_bytes(Protocol::Http, reply);
        assert!(bytes.starts_with(status.as_bytes()), "{reply:?}");
    }
    assert_eq!(
        reply_bytes(Protocol::Http, Reply::Established),
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
}
