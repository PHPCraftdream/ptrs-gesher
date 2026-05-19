use std::str::FromStr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fast_socks5::util::target_addr::TargetAddr;

fn bench_arg_string_from_creds(c: &mut Criterion) {
    // Small payload (single key=value pair, fits in username field alone).
    c.bench_function("arg_string_from_creds_small", |b| {
        let creds = Some(("cert=ABC;iat-mode=0".to_string(), "\0".to_string()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    // Mid-size: full 255-char username + small password.
    c.bench_function("arg_string_from_creds_mid", |b| {
        let username = "cert=".to_string() + &"A".repeat(250);
        let creds = Some((username, ";iat-mode=0".to_string()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    // Worst case for the spec: full 255 + 255 split.
    c.bench_function("arg_string_from_creds_full", |b| {
        let creds = Some(("u".repeat(255), "p".repeat(255)));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    // No creds path (early-return).
    c.bench_function("arg_string_from_creds_none", |b| {
        b.iter(|| lyrebird::arg_string_from_creds(black_box(None)));
    });
}

fn bench_arg_string_then_parse(c: &mut Criterion) {
    // End-to-end: reconstruct arg string from SOCKS5 fields, then parse
    // back into a kv-map — the actual production code path.
    let username = "cert=".to_string() + &"A".repeat(250);
    let creds = Some((username, ";iat-mode=0;public-key=BBB".to_string()));

    c.bench_function("arg_string_then_parse_e2e", |b| {
        b.iter(|| {
            let s = lyrebird::arg_string_from_creds(black_box(creds.clone()));
            ptrs::args::Args::from_str(&s).unwrap()
        });
    });
}

fn bench_resolve_target_addr(c: &mut Criterion) {
    let ipv4 = TargetAddr::Ip("10.0.0.1:9050".parse().unwrap());
    c.bench_function("resolve_target_addr_ipv4", |b| {
        b.iter(|| lyrebird::resolve_target_addr(black_box(&ipv4)).unwrap());
    });

    let ipv6 = TargetAddr::Ip("[::1]:443".parse().unwrap());
    c.bench_function("resolve_target_addr_ipv6", |b| {
        b.iter(|| lyrebird::resolve_target_addr(black_box(&ipv6)).unwrap());
    });

    let domain = TargetAddr::Domain("example.com".into(), 443);
    c.bench_function("resolve_target_addr_domain_rejected", |b| {
        // Always fails — but the failure-path cost is still measurable.
        b.iter(|| {
            let _ = lyrebird::resolve_target_addr(black_box(&domain));
        });
    });
}

fn bench_arg_string_from_creds_edge(c: &mut Criterion) {
    c.bench_function("arg_string_from_creds_empty_strings", |b| {
        let creds = Some((String::new(), String::new()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });

    c.bench_function("arg_string_from_creds_nul_password", |b| {
        let creds = Some(("cert=AABBCC".to_string(), "\0".to_string()));
        b.iter(|| lyrebird::arg_string_from_creds(black_box(creds.clone())));
    });
}

fn bench_bidirectional_copy(c: &mut Criterion) {
    use criterion::{BenchmarkId, Throughput};
    use tokio::io::AsyncWriteExt;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("bidirectional_copy");
    for &size in &[64 * 1024usize, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64 * 2));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt).iter(|| async move {
                let (a_out, a_in) = tokio::io::duplex(64 * 1024);
                let (b_out, b_in) = tokio::io::duplex(64 * 1024);
                let data = vec![0u8; size];
                let d1 = data.clone();
                let d2 = data;
                let wa = tokio::spawn(async move {
                    let mut a = a_out;
                    a.write_all(&d1).await.unwrap();
                    drop(a);
                });
                let wb = tokio::spawn(async move {
                    let mut b = b_out;
                    b.write_all(&d2).await.unwrap();
                    drop(b);
                });
                let _ = lyrebird::bidirectional_copy(a_in, b_in).await.unwrap();
                wa.await.unwrap();
                wb.await.unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_arg_string_from_creds,
    bench_arg_string_then_parse,
    bench_resolve_target_addr,
    bench_arg_string_from_creds_edge,
    bench_bidirectional_copy,
);
criterion_main!(benches);
