//! Full obfs4 echo server over real TCP sockets on the loopback interface.
//!
//! Unlike the per-crate `echo_handshake` example (which uses `tokio::io::duplex`),
//! this one binds a `TcpListener` to an ephemeral port on 127.0.0.1, performs the
//! obfs4 handshake over actual TCP, and round-trips a message. This is the closest
//! you can get to a real deployment without a Tor daemon on the other end.
//!
//! Run with: `cargo run -p ptrs-gesher-examples --example obfs4_echo_over_tcp`

use obfs4::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // --- Server setup ---
    // Generate a fresh server identity (random x25519 key + node-id).
    let server = Server::getrandom();

    // Derive a client builder that already knows the server's public material.
    let client_builder = server.client_params();

    // Bind to an ephemeral port on loopback.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind should succeed");
    let listen_addr = listener.local_addr().expect("local_addr");
    println!("Listener bound to {listen_addr}");

    // --- Server task: accept one connection, handshake, echo ---
    let server_handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        println!("[server] accepted connection from {peer}");

        let mut obfs4_stream = server.wrap(stream).await.expect("server handshake");
        println!("[server] handshake complete");

        // Echo loop: read one chunk, write it back.
        let mut buf = vec![0u8; 4096];
        let n = obfs4_stream.read(&mut buf).await.expect("server read");
        println!("[server] received {n} bytes");
        obfs4_stream
            .write_all(&buf[..n])
            .await
            .expect("server write");
        obfs4_stream.flush().await.expect("server flush");
        println!("[server] echoed {n} bytes back");
    });

    // --- Client: connect, handshake, send, receive ---
    let tcp_stream = TcpStream::connect(listen_addr)
        .await
        .expect("client connect");
    println!("[client] connected to {listen_addr}");

    let client = client_builder.build();
    let mut obfs4_stream = client.wrap(tcp_stream).await.expect("client handshake");
    println!("[client] handshake complete");

    let message = b"Hello from the obfs4 client over real TCP!";
    obfs4_stream.write_all(message).await.expect("client write");
    obfs4_stream.flush().await.expect("client flush");
    println!("[client] sent {} bytes", message.len());

    let mut buf = vec![0u8; 4096];
    let n = obfs4_stream.read(&mut buf).await.expect("client read");
    assert_eq!(
        &buf[..n],
        message.as_slice(),
        "echoed data must match the original"
    );
    println!("[client] received echo: {} bytes match", n);

    server_handle.await.expect("server task panicked");

    println!("\nOK: {n} bytes round-tripped through obfs4 over TCP on {listen_addr}.");
}
