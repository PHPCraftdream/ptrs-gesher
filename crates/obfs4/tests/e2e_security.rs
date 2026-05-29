//! Security-critical E2E tests for obfs4 handshake.
//!
//! Gap: replay_filter is unit-tested in isolation, but its integration
//! with the actual handshake path (sessions → handshake_server → replay_filter)
//! had no end-to-end coverage. A regression that disconnects the filter
//! from the server handshake would go undetected.

use std::time::Duration;

use obfs4::common::ntor_arti::RelayHandshakeError;
use obfs4::{Error, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Capture the raw client hello from a legitimate handshake, then replay
/// those exact bytes to the same server instance. The first delivery must be
/// *accepted* (proving the bytes are a well-formed handshake), and the second,
/// byte-identical delivery must be *rejected* by the replay filter.
///
/// This exercises the full chain: client generates ephemeral key →
/// marshalls handshake → server parses → checks replay filter → rejects.
///
/// The accept-then-reject framing is the load-bearing part of this test:
/// because the *same* bytes are accepted on the first connection, a rejection
/// on the second connection cannot be attributed to malformed input, a wrong
/// key, a timeout, or an I/O error — the only component that turns a
/// previously-valid handshake into a rejected one is the replay filter. That
/// is what makes this a replay test rather than a generic "handshake errored"
/// test.
///
/// On the error *variant*: the replay branch in `handshake_server` raises
/// `RelayHandshakeError::ReplayedHandshake` internally, but
/// `server_handshake_obfs4_no_keygen` currently collapses every non-`EAgain`
/// parse error into `RelayHandshakeError::BadClientHandshake`, so that is the
/// variant that actually escapes to the public API today. We accept either the
/// precise `ReplayedHandshake` (should the flattening be removed later) or the
/// current `BadClientHandshake`, but never `Ok` and never a non-handshake
/// error.
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

    // --- Step 2: Feed the captured hello to the real server (first time) ---
    // The server sees these bytes for the first time. Because the capture is a
    // complete, well-formed client handshake for this exact server, the server
    // accepts it AND registers its MAC in the replay filter.
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

    // The first delivery of a valid hello must succeed. This is what lets us
    // attribute the second-delivery failure specifically to replay detection:
    // identical bytes, accepted once, so any later rejection is the filter.
    assert!(
        first_result.is_ok(),
        "captured hello was not a valid handshake (first delivery failed): {:?}",
        first_result.err()
    );

    // --- Step 3: Replay the SAME hello bytes to a fresh connection ---
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

    // The replayed (previously-accepted) hello must be rejected at the
    // handshake layer. We pin to the replay-specific variant if it surfaces,
    // and otherwise accept the flattened `BadClientHandshake` that the current
    // server code produces for the replay path (see the doc comment above).
    match second_result {
        Err(Error::HandshakeErr(RelayHandshakeError::ReplayedHandshake)) => {
            // Ideal: the precise replay variant escaped to the caller.
        }
        Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake)) => {
            // Current reality: the replay error is flattened to BadClientHandshake
            // by server_handshake_obfs4_no_keygen. Since the identical bytes were
            // accepted in step 2, this rejection is still attributable to the
            // replay filter and to nothing else.
        }
        Err(other) => panic!(
            "previously-accepted hello was rejected, but not at the handshake \
             layer — expected ReplayedHandshake/BadClientHandshake, got: {other:?}"
        ),
        Ok(_) => panic!("server accepted replayed client hello — replay filter not working"),
    }
}
