use std::time::Duration;

use bridge_line::BridgeLine;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn fast_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

const OBFS4_LINE: &str = "obfs4 65.108.147.195:8089 DFF8DBF20F8980C4B74EDBAA9695104D613978CE cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA iat-mode=0";
const WEBTUNNEL_LINE: &str = "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/K2A2utQIMou4Ia2WjVseyDjV ver=0.0.3";
const PLAIN_LINE: &str = "192.0.2.3:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01";

fn bench_parse(c: &mut Criterion) {
    c.bench_function("parse_obfs4", |b| {
        b.iter(|| black_box(OBFS4_LINE).parse::<BridgeLine>().unwrap());
    });
    c.bench_function("parse_webtunnel", |b| {
        b.iter(|| black_box(WEBTUNNEL_LINE).parse::<BridgeLine>().unwrap());
    });
    c.bench_function("parse_plain", |b| {
        b.iter(|| black_box(PLAIN_LINE).parse::<BridgeLine>().unwrap());
    });
}

fn bench_display(c: &mut Criterion) {
    let bridge: BridgeLine = OBFS4_LINE.parse().unwrap();
    c.bench_function("display_obfs4", |b| {
        b.iter(|| format!("{}", black_box(&bridge)));
    });
}

criterion_group! {
    name = benches;
    config = fast_criterion();
    targets = bench_parse, bench_display
}
criterion_main!(benches);
