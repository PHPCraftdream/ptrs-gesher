//! Concurrent stress tests for obfs4.
//!
//! Gap: `Server` is `Arc<ServerInner>` with a shared `ReplayFilter` behind
//! `Mutex`. All prior tests use single client↔server pairs. These tests
//! exercise contention: many parallel handshakes and replay attempts against
//! one server, flushing out races, deadlocks, or panics under load.

use std::time::Duration;

use obfs4::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_handshakes_with_echo() {
    let server = Server::getrandom();
    let client_cb = server.client_params();

    let mut handles = Vec::new();
    for i in 0u32..16 {
        let server = server.clone();
        let cb = client_cb.clone();
        handles.push(tokio::spawn(async move {
            let (c, s) = tokio::io::duplex(64 * 1024);

            let srv = server.clone();
            let echo_task = tokio::spawn(async move {
                let stream = srv.wrap(s).await.unwrap();
                let (mut r, mut w) = tokio::io::split(stream);
                tokio::io::copy(&mut r, &mut w).await.unwrap();
            });

            let client = cb.build();
            let mut stream = client
                .wrap(c)
                .await
                .unwrap_or_else(|e| panic!("client {i} handshake failed: {e}"));

            let msg = format!("hello from client {i}");
            stream.write_all(msg.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();

            let mut buf = vec![0u8; msg.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("client {i} echo timed out"))
                .unwrap_or_else(|e| panic!("client {i} echo read failed: {e}"));

            assert_eq!(buf, msg.as_bytes(), "client {i} echo mismatch");
            echo_task.abort();
        }));
    }

    for (i, h) in handles.into_iter().enumerate() {
        h.await
            .unwrap_or_else(|e| panic!("client {i} task panicked: {e}"));
    }
}

/// Helper: capture a client hello from a fresh connection.
async fn capture_hello(server: &Server) -> Vec<u8> {
    let (client_side, mut capture_side) = tokio::io::duplex(64 * 1024);
    let client = server.client_params().build();
    let _client_task = tokio::spawn(async move {
        let _ = client.wrap(client_side).await;
    });

    let mut hello = Vec::new();
    let mut buf = [0u8; 8192];
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(300) {
        match tokio::time::timeout(Duration::from_millis(50), capture_side.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => hello.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    drop(capture_side);
    assert!(hello.len() > 64, "capture too short: {} bytes", hello.len());
    hello
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_replays_at_most_one_succeeds() {
    let server = Server::getrandom();
    let hello = capture_hello(&server).await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let server = server.clone();
        let hello = hello.clone();
        handles.push(tokio::spawn(async move {
            let (mut w, s) = tokio::io::duplex(64 * 1024);
            let srv = server.clone();
            let server_task = tokio::spawn(async move { srv.wrap(s).await });
            w.write_all(&hello).await.unwrap();
            w.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(w);
            tokio::time::timeout(Duration::from_secs(3), server_task)
                .await
                .unwrap()
                .unwrap()
        }));
    }

    let mut successes = 0u32;
    for h in handles {
        if h.await.unwrap().is_ok() {
            successes += 1;
        }
    }
    assert!(
        successes <= 1,
        "replay filter allowed {successes}/8 — must be ≤1"
    );
}
