use criterion::{black_box, criterion_group, criterion_main, Criterion};

use obfs4::common::drbg::{Drbg, Seed};
use obfs4::common::probdist::WeightedDist;
use obfs4::common::replay_filter::ReplayFilter;

fn bench_drbg(c: &mut Criterion) {
    let seed = Seed::new().unwrap();
    let mut drbg = Drbg::new(Some(seed)).unwrap();

    c.bench_function("drbg_uint64", |b| {
        b.iter(|| black_box(drbg.uint64()));
    });

    c.bench_function("drbg_next_block", |b| {
        b.iter(|| black_box(drbg.next_block()));
    });
}

fn bench_replay_filter(c: &mut Criterion) {
    let filter = ReplayFilter::new(std::time::Duration::from_secs(60));
    let now = std::time::Instant::now();

    c.bench_function("replay_filter_test_and_set_new", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i += 1;
            filter.test_and_set(now, black_box(i.to_le_bytes()))
        });
    });

    c.bench_function("replay_filter_test_and_set_existing", |b| {
        let payload = b"repeated-payload-for-bench";
        filter.test_and_set(now, payload);
        b.iter(|| filter.test_and_set(now, black_box(payload)));
    });
}

fn bench_weighted_dist(c: &mut Criterion) {
    let seed = Seed::new().unwrap();
    let dist = WeightedDist::new(seed, 0, 1448, false);

    c.bench_function("weighted_dist_sample", |b| {
        b.iter(|| black_box(dist.sample()));
    });
}

fn bench_seed_generation(c: &mut Criterion) {
    c.bench_function("seed_new_from_os_rng", |b| {
        b.iter(|| Seed::new().unwrap());
    });
}

criterion_group!(
    benches,
    bench_drbg,
    bench_replay_filter,
    bench_weighted_dist,
    bench_seed_generation,
);
criterion_main!(benches);
