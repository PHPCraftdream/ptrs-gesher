use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ptrs::args::Args;

fn make_args() -> Args {
    let mut args = Args::new();
    args.add("url", "https://example.com/K2A2utQIMou4Ia2WjVseyDjV");
    args.add("ver", "0.0.3");
    args
}

fn bench_websocket_key(c: &mut Criterion) {
    c.bench_function("generate_websocket_key", |b| {
        b.iter(webtunnel::handshake::generate_websocket_key);
    });
}

fn bench_config_from_args(c: &mut Criterion) {
    let args = make_args();
    c.bench_function("WebTunnelConfig::from_args", |b| {
        b.iter(|| webtunnel::WebTunnelConfig::from_args(black_box(&args)).unwrap());
    });
}

fn bench_build_upgrade_request(c: &mut Criterion) {
    let args = make_args();
    let config = webtunnel::WebTunnelConfig::from_args(&args).unwrap();
    c.bench_function("build_upgrade_request", |b| {
        b.iter(|| webtunnel::handshake::build_upgrade_request(black_box(&config)));
    });
}

fn bench_config_with_servername(c: &mut Criterion) {
    let mut args = make_args();
    args.add("servername", "cdn.example.com");
    c.bench_function("WebTunnelConfig::from_args_with_sni", |b| {
        b.iter(|| webtunnel::WebTunnelConfig::from_args(black_box(&args)).unwrap());
    });
}

criterion_group!(
    benches,
    bench_websocket_key,
    bench_config_from_args,
    bench_build_upgrade_request,
    bench_config_with_servername,
);
criterion_main!(benches);
