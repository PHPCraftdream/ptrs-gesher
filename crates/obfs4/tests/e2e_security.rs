//! Security-critical E2E tests for obfs4 handshake.
//!
//! Gap: replay_filter is unit-tested in isolation, but its integration
//! with the actual handshake path (sessions → handshake_server → replay_filter)
//! had no end-to-end coverage. A regression that disconnects the filter
//! from the server handshake would go undetected.

use std::time::Duration;

use obfs4::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Capture the raw client hello from a legitimate handshake, then replay
/// those exact bytes to the same server instance. The server's replay
/// filter must reject the second attempt.
///
/// This exercises the full chain: client generates ephemeral key →
/// marshalls handshake → server parses → checks replay filter → rejects.
#[tokio::test]
async fn replayed_client_hello_rejected() {
    let server = Server::getrandom();
    let client_config = server.client_params();

    // --- Step 1: Capture a real client hello ---
    // We connect a real client to a "fake server" duplex half and read
    // whatever the client writes before it expects a server response.
    let (client_side, mut capture_side) = tokio::io::duplex(64 * 1024);
    let client = client_config.build();
    let _client_task = tokio::spawn(async move {
        // Client will write its hello, then wait for server response.
        // We never respond, so eventually the client task dies. That's fine.
        let _ = client.wrap(client_side).await;
    });

    let mut hello = Vec::new();
    let mut buf = [0u8; 8192];
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        match tokio::time::timeout(Duration::from_millis(100), capture_side.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => hello.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    drop(capture_side);

    assert!(
        hello.len() > 64,
        "failed to capture client hello ({} bytes)",
        hello.len()
    );

    // --- Step 2: Feed the captured hello to the real server ---
    // First connection — the server sees these bytes for the first time.
    // It should fail (wrong-key or auth failure) but register them in the
    // replay filter.
    let (mut replay1_write, server_side1) = tokio::io::duplex(64 * 1024);
    let server_clone = server.clone();
    let first_attempt = tokio::spawn(async move { server_clone.wrap(server_side1).await });

    replay1_write.write_all(&hello).await.unwrap();
    replay1_write.flush().await.unwrap();
    // Give server time to process
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(replay1_write);

    let first_result = tokio::time::timeout(Duration::from_secs(3), first_attempt)
        .await
        .expect("first attempt hung")
        .expect("first attempt panicked");
    // First attempt may succeed or fail depending on timing — either way,
    // the bytes are now in the replay filter.

    // --- Step 3: Replay the SAME hello bytes ---
    let (mut replay2_write, server_side2) = tokio::io::duplex(64 * 1024);
    let server_clone2 = server.clone();
    let second_attempt = tokio::spawn(async move { server_clone2.wrap(server_side2).await });

    replay2_write.write_all(&hello).await.unwrap();
    replay2_write.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(replay2_write);

    let second_result = tokio::time::timeout(Duration::from_secs(3), second_attempt)
        .await
        .expect("replay attempt hung")
        .expect("replay attempt panicked");

    assert!(
        second_result.is_err(),
        "server accepted replayed client hello — replay filter not working"
    );
}
