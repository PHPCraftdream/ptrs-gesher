//! E2E error-path integration tests for obfs4 client↔server through duplex.
//!
//! These exercise scenarios that pure unit tests cannot cover:
//! * Garbage handshake bytes from peer.
//! * Premature connection close mid-handshake.
//! * Client/server using mismatched keys.
//! * Handshake deadline already in the past.
//!
//! Coverage gap: existing `testing.rs` only tests the happy path. Negative
//! paths in `sessions::complete_handshake` (BadServerHandshake, EOF discard,
//! deadline enforcement) had no end-to-end coverage.

use std::time::Duration;

use obfs4::{ClientBuilder, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn server_handshake_fails_on_garbage_input() {
    // Peer sends pure noise instead of a valid client onionskin.
    let (mut peer, server_side) = tokio::io::duplex(65_536);

    let server = Server::getrandom();
    let server_task = tokio::spawn(async move { server.wrap(server_side).await });

    // Send ~8KB of garbage. The server should give up rather than hang or panic.
    let garbage = vec![0xAAu8; 4096];
    peer.write_all(&garbage).await.unwrap();
    peer.write_all(&garbage).await.unwrap();
    peer.flush().await.unwrap();
    drop(peer); // close to force EOF if server still reads

    let result = tokio::time::timeout(HANDSHAKE_LIMIT, server_task)
        .await
        .expect("server hung on garbage input")
        .expect("server task panicked");

    assert!(result.is_err(), "server accepted garbage as a handshake");
}

#[tokio::test]
async fn client_handshake_fails_on_premature_eof() {
    // Peer accepts the client's hello but then closes the connection.
    let (client_side, mut peer) = tokio::io::duplex(65_536);

    let server = Server::getrandom();
    let client = server.client_params().build();

    let client_task = tokio::spawn(async move { client.wrap(client_side).await });

    // Drain the client's hello, then drop the peer half — server-side EOF.
    let mut buf = [0u8; 8192];
    let _ = peer.read(&mut buf).await.unwrap();
    drop(peer);

    let result = tokio::time::timeout(HANDSHAKE_LIMIT, client_task)
        .await
        .expect("client hung on peer EOF")
        .expect("client task panicked");

    assert!(result.is_err(), "client completed handshake despite EOF");
}

#[tokio::test]
async fn client_handshake_fails_on_garbage_server_response() {
    // Peer reads the client hello then sends garbage instead of a valid server
    // onionskin. Client must reject and not silently establish a session.
    let (client_side, mut peer) = tokio::io::duplex(65_536);

    let server = Server::getrandom();
    let client = server.client_params().build();
    let client_task = tokio::spawn(async move { client.wrap(client_side).await });

    let mut buf = [0u8; 8192];
    let _ = peer.read(&mut buf).await.unwrap();
    peer.write_all(&[0xFFu8; 4096]).await.unwrap();
    peer.flush().await.unwrap();
    drop(peer);

    let result = tokio::time::timeout(HANDSHAKE_LIMIT, client_task)
        .await
        .expect("client hung on garbage server response")
        .expect("client task panicked");

    assert!(
        result.is_err(),
        "client accepted garbage server response as valid handshake"
    );
}

#[tokio::test]
async fn client_with_wrong_node_pubkey_fails() {
    // Real server, but the client builds with a different node-pubkey.
    // Without the correct identity key, the ntor exchange cannot
    // produce matching shared secrets and the handshake must fail.
    let (c, mut s) = tokio::io::duplex(65_536);
    let server = Server::getrandom();

    // Server runs its real handshake — it will see the client hello and
    // produce a response, but the client won't be able to verify the AUTH
    // because it was built against a different identity.
    let _server_task = tokio::spawn(async move {
        let _ = server.wrap(&mut s).await;
    });

    // Wrong-key client.
    let mut bad = ClientBuilder::default();
    bad.with_node_pubkey([0xAB; 32])
        .with_node_id([0xCD; 20])
        .with_iat_mode(obfs4::proto::IAT::Off)
        .with_handshake_timeout(Duration::from_secs(2));
    let client = bad.build();

    let result = tokio::time::timeout(HANDSHAKE_LIMIT, client.wrap(c))
        .await
        .expect("client hung against wrong-key server");

    assert!(
        result.is_err(),
        "client built with wrong node-pubkey reported success"
    );
}

#[tokio::test]
async fn client_handshake_short_timeout_is_enforced() {
    // Idle silent peer — server never responds. Client uses a 500ms timeout
    // and must give up well before the test-wide watchdog fires.
    let (c, _idle_peer) = tokio::io::duplex(65_536);

    let server = Server::getrandom();
    let mut cb = server.client_params();
    cb.with_handshake_timeout(Duration::from_millis(500));
    let client = cb.build();

    let start = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(5), client.wrap(c))
        .await
        .expect("client did not honour 500ms timeout");

    assert!(result.is_err(), "client succeeded against silent peer");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(2),
        "client timeout fired at {elapsed:?}, expected ~500ms"
    );
}
