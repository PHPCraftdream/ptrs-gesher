//! E2E data-path integration tests for obfs4 client↔server.
//!
//! Gap: existing `testing.rs` verifies echo with zero-filled buffers.
//! These tests use patterned data to catch byte-reordering and
//! verify the poll_write chunking loop splits payloads larger than
//! MAX_MESSAGE_PAYLOAD_LENGTH correctly.

use obfs4::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Write a buffer significantly larger than one frame payload through the
/// tunnel and verify byte-perfect echo on the other side. This exercises
/// the `O4Stream::poll_write` chunking loop that splits buffers into
/// `MAX_MESSAGE_PAYLOAD_LENGTH`-sized frames.
#[tokio::test]
async fn large_buffer_split_preserves_all_bytes() {
    // ~100KB of patterned data — many frames needed.
    let size = 100_003; // prime, non-aligned to any block size
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let (c, s) = tokio::io::duplex(64 * 1024);
    let server = Server::getrandom();
    let client = server.client_params().build();

    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let stream = server.wrap(s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let stream = client.wrap(c).await.unwrap();
    let (mut r, mut w) = tokio::io::split(stream);

    let writer = tokio::spawn(async move {
        w.write_all(&payload).await.unwrap();
        w.flush().await.unwrap();
        drop(w);
    });

    let mut received = Vec::with_capacity(size);
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), r.read(&mut buf))
            .await
            .expect("read timed out")
            .expect("read failed");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
        if received.len() >= size {
            break;
        }
    }

    assert_eq!(received.len(), expected.len(), "byte count mismatch");
    assert_eq!(received, expected, "data corruption detected");

    writer.await.unwrap();
    server_task.abort();
}

/// Multiple sequential messages with varying sizes — verifies that the
/// poll_write chunking + message framing handles non-aligned sizes.
#[tokio::test]
async fn sequential_varied_sizes_echo() {
    let sizes = [1, 7, 255, 1024, 4096, 10000, 1];
    let (c, s) = tokio::io::duplex(64 * 1024);
    let server = Server::getrandom();
    let client = server.client_params().build();

    let server_task = tokio::spawn(async move {
        let stream = server.wrap(s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let stream = client.wrap(c).await.unwrap();
    let (mut r, mut w) = tokio::io::split(stream);

    let total: usize = sizes.iter().sum();

    let writer = tokio::spawn(async move {
        for &sz in &sizes {
            let data: Vec<u8> = (0..sz).map(|i| (i % 251) as u8).collect();
            w.write_all(&data).await.unwrap();
            w.flush().await.unwrap();
        }
        drop(w);
    });

    let mut received = Vec::with_capacity(total);
    let mut buf = [0u8; 8192];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), r.read(&mut buf))
            .await
            .expect("read timed out")
            .expect("read error");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
        if received.len() >= total {
            break;
        }
    }

    // Rebuild expected payload from same pattern
    let mut expected = Vec::with_capacity(total);
    for &sz in &sizes {
        for i in 0..sz {
            expected.push((i % 251) as u8);
        }
    }

    assert_eq!(received.len(), expected.len(), "total byte count mismatch");
    assert_eq!(received, expected, "payload content mismatch");

    writer.await.unwrap();
    server_task.abort();
}
