//! In-process obfs4 echo handshake using tokio::io::duplex.
//!
//! Demonstrates a complete obfs4 client↔server handshake plus a single
//! round-trip echo, all in one process and one tokio runtime — no
//! network, no key files. Mirrors the idiom used by the integration
//! tests under `tests/`.

use obfs4::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Spawn a fresh server with random keys. `client_params()` returns
    // a `ClientBuilder` already wired with the server's public material,
    // so the client side does not need any out-of-band configuration.
    let server = Server::getrandom();
    let client = server.client_params().build();

    // An in-memory full-duplex pipe stands in for a TCP connection.
    let (c, s) = tokio::io::duplex(64 * 1024);

    // Server: handshake, then echo one chunk back.
    let server_task = tokio::spawn(async move {
        let mut stream = server.wrap(s).await.expect("server handshake");
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.expect("server read");
        stream.write_all(&buf[..n]).await.expect("server write");
        stream.flush().await.expect("server flush");
    });

    // Client: handshake, send, read echo.
    let mut stream = client.wrap(c).await.expect("client handshake");
    let msg = b"hello obfs4 echo!";
    stream.write_all(msg).await.expect("client write");
    stream.flush().await.expect("client flush");

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.expect("client read");
    assert_eq!(&buf[..n], msg, "echoed data must match");
    println!("Echo OK: {n} bytes round-tripped through obfs4 tunnel");

    server_task.await.expect("server task panicked");
}
