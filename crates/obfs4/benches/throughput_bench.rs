//! Data-path throughput benchmarks: full obfs4 client↔server tunnel through
//! `tokio::io::duplex`, measuring real encrypt/transport/decrypt cost.
//!
//! Coverage gap: existing benchmarks cover only single-frame `encode`/`decode`
//! and individual primitives (DRBG, HMAC). They cannot reveal regressions in
//! the `poll_write` chunking loop, `poll_read` framed-reader loop, IAT/length
//! distribution sampling, or cumulative cost of many frames at runtime.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use obfs4::{Obfs4Stream, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::runtime::Runtime;

type DuplexObfs4Stream = Obfs4Stream<tokio::io::DuplexStream>;

struct Tunnel {
    reader: ReadHalf<DuplexObfs4Stream>,
    writer: WriteHalf<DuplexObfs4Stream>,
    server: tokio::task::JoinHandle<()>,
    tx: [u8; 4096],
    rx: [u8; 8192],
}

fn fast_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

/// Build a runtime once and reuse it across iterations to keep tokio startup
/// out of the measured path.
fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

async fn establish_tunnel() -> Tunnel {
    let (c, s) = tokio::io::duplex(64 * 1024);
    let server = Server::getrandom();
    let client_cb = server.client_params();

    let server_handle = tokio::spawn(async move {
        let stream = server.wrap(s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
        w.shutdown().await.unwrap();
    });

    let client = client_cb.build();
    let stream = client.wrap(c).await.unwrap();
    let (r, w) = tokio::io::split(stream);

    Tunnel {
        reader: r,
        writer: w,
        server: server_handle,
        tx: [0u8; 4096],
        rx: [0u8; 8192],
    }
}

async fn transfer_n_bytes(tunnel: &mut Tunnel, n: usize) {
    let Tunnel {
        reader,
        writer,
        tx,
        rx,
        ..
    } = tunnel;
    let send = async {
        let mut sent = 0usize;
        while sent < n {
            let take = (n - sent).min(tx.len());
            writer.write_all(&tx[..take]).await.unwrap();
            sent += take;
        }
        writer.flush().await.unwrap();
    };
    let receive = async {
        let mut received = 0usize;
        while received < n {
            let take = (n - received).min(rx.len());
            reader.read_exact(&mut rx[..take]).await.unwrap();
            received += take;
        }
    };
    let ((), ()) = tokio::join!(send, receive);
}

async fn timed_transfers(size: usize, iterations: u64) -> Duration {
    let mut tunnel = establish_tunnel().await;
    let start = tokio::time::Instant::now();
    for _ in 0..iterations {
        transfer_n_bytes(&mut tunnel, size).await;
    }
    let elapsed = start.elapsed();

    tunnel.writer.shutdown().await.unwrap();
    while tunnel.reader.read(&mut tunnel.rx).await.unwrap() != 0 {}
    tunnel.server.await.unwrap();
    elapsed
}

fn bench_tunnel_throughput(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("obfs4_tunnel_throughput");
    let size: usize = 32 * 1024;
    group.throughput(Throughput::Bytes(size as u64));
    group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
        b.to_async(&rt)
            .iter_custom(|iterations| async move { timed_transfers(size, iterations).await });
    });
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
                let mut stream = server.wrap(ss).await.unwrap();
                stream.shutdown().await.unwrap();
            });

            let mut client_stream = client.wrap(cs).await.unwrap();
            let (client_result, server_result) =
                tokio::join!(client_stream.shutdown(), server_handle);
            client_result.unwrap();
            server_result.unwrap();
        });
    });
}

criterion_group! {
    name = benches;
    config = fast_criterion();
    targets = bench_tunnel_throughput, bench_handshake_only
}
criterion_main!(benches);
