//! Benchmarks via the flat umbrella API. These exercise the same
//! underlying code as the per-crate benches but go through the
//! `ptrs_gesher::*` re-exports, proving the flat API surface costs no
//! extra runtime and is genuinely zero-cost (compile-time aliases).

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_args_via_umbrella(c: &mut Criterion) {
    c.bench_function("umbrella::Args::parse_client_parameters", |b| {
        b.iter(|| ptrs_gesher::Args::parse_client_parameters(black_box("cert=AAA;iat-mode=0")).unwrap());
    });

    c.bench_function("umbrella::Args::add+retrieve", |b| {
        b.iter(|| {
            let mut args = ptrs_gesher::Args::new();
            args.add("cert", "AAA");
            args.add("iat-mode", "0");
            black_box(args.retrieve("cert"));
            black_box(args.retrieve("iat-mode"));
        });
    });
}

#[cfg(feature = "bridge-line")]
fn bench_bridge_line_via_umbrella(c: &mut Criterion) {
    let line = "obfs4 65.108.147.195:8089 DFF8DBF20F8980C4B74EDBAA9695104D613978CE cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA iat-mode=0";
    c.bench_function("umbrella::BridgeLine::parse_obfs4", |b| {
        b.iter(|| black_box(line).parse::<ptrs_gesher::BridgeLine>().unwrap());
    });
}

#[cfg(feature = "webtunnel")]
fn bench_webtunnel_via_umbrella(c: &mut Criterion) {
    let mut args = ptrs_gesher::Args::new();
    args.add("url", "https://example.com/K2A2utQIMou4Ia2WjVseyDjV");

    c.bench_function("umbrella::WebTunnelConfig::from_args", |b| {
        b.iter(|| ptrs_gesher::WebTunnelConfig::from_args(black_box(&args)).unwrap());
    });
}

#[cfg(all(feature = "bridge-line", feature = "webtunnel"))]
criterion_group!(
    benches,
    bench_args_via_umbrella,
    bench_bridge_line_via_umbrella,
    bench_webtunnel_via_umbrella,
);

#[cfg(all(feature = "bridge-line", not(feature = "webtunnel")))]
criterion_group!(benches, bench_args_via_umbrella, bench_bridge_line_via_umbrella);

#[cfg(all(not(feature = "bridge-line"), feature = "webtunnel"))]
criterion_group!(benches, bench_args_via_umbrella, bench_webtunnel_via_umbrella);

#[cfg(not(any(feature = "bridge-line", feature = "webtunnel")))]
criterion_group!(benches, bench_args_via_umbrella);

criterion_main!(benches);
