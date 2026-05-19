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

criterion_group!(
    benches,
    bench_arg_string_from_creds,
    bench_arg_string_then_parse,
    bench_resolve_target_addr,
    bench_arg_string_from_creds_edge,
);
criterion_main!(benches);
