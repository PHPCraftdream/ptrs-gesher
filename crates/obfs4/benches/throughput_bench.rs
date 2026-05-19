//! Data-path throughput benchmarks: full obfs4 client↔server tunnel through
//! `tokio::io::duplex`, measuring real encrypt/transport/decrypt cost.
//!
//! Coverage gap: existing benchmarks cover only single-frame `encode`/`decode`
//! and individual primitives (DRBG, HMAC). They cannot reveal regressions in
//! the `poll_write` chunking loop, `poll_read` framed-reader loop, IAT/length
//! distribution sampling, or cumulative cost of many frames at runtime.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use obfs4::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

/// Build a runtime once and reuse it across iterations to keep tokio startup
/// out of the measured path.
fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Establish a fresh obfs4 tunnel, run a one-shot N-byte echo, drop the tunnel.
/// Measures *steady-state* throughput because handshake is amortised across
/// the full payload — for handshake latency see `handshake_bench`.
async fn echo_n_bytes(n: usize) {
    let (c, s) = tokio::io::duplex(64 * 1024);
    let server = Server::getrandom();
    let client_cb = server.client_params();

    let server_handle = tokio::spawn(async move {
        let stream = server.wrap(s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let client = client_cb.build();
    let stream = client.wrap(c).await.unwrap();
    let (mut r, mut w) = tokio::io::split(stream);

    let writer = tokio::spawn(async move {
        let chunk = vec![0u8; 4096];
        let mut sent = 0usize;
        while sent < n {
            let remaining = n - sent;
            let take = remaining.min(chunk.len());
            w.write_all(&chunk[..take]).await.unwrap();
            sent += take;
        }
        w.flush().await.unwrap();
        // half-close so the echo loop on the server eventually terminates
        drop(w);
    });

    let mut buf = vec![0u8; 8192];
    let mut received = 0usize;
    while received < n {
        let got = r.read(&mut buf).await.unwrap();
        if got == 0 {
            break;
        }
        received += got;
    }
    assert_eq!(received, n, "echo lost bytes");

    writer.await.unwrap();
    server_handle.abort();
}

fn bench_tunnel_throughput(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("obfs4_tunnel_throughput");
    // Use 1KB and 32KB; the duplex buffer is 64KB so 32KB still fits in one
    // wakeup and lets us see if larger chunks amortise framing overhead.
    for &size in &[1024usize, 32 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt).iter(|| async move {
                echo_n_bytes(black_box(size)).await;
            });
        });
    }
    group.finish();
}

fn bench_handshake_only(c: &mut Criterion) {
    // Pure handshake establishment cost — no data transfer.
    let rt = rt();
    c.bench_function("obfs4_full_handshake_duplex", |b| {
        b.to_async(&rt).iter(|| async {
            let (cs, ss) = tokio::io::duplex(64 * 1024);
            let server = Server::getrandom();
            let client = server.client_params().build();

            let server_handle = tokio::spawn(async move {
                let _ = server.wrap(ss).await.unwrap();
            });

            let _client_stream = client.wrap(cs).await.unwrap();
            server_handle.await.unwrap();
        });
    });
}

criterion_group!(benches, bench_tunnel_throughput, bench_handshake_only);
criterion_main!(benches);
