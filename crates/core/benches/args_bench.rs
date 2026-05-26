use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_args_parse_client_parameters(c: &mut Criterion) {
    let params = "cert=AAA;iat-mode=0";
    c.bench_function("Args::parse_client_parameters", |b| {
        b.iter(|| ptrs::args::Args::parse_client_parameters(black_box(params)).unwrap());
    });
}

fn bench_args_encode_smethod(c: &mut Criterion) {
    let mut args = ptrs::args::Args::new();
    args.add("cert", &"A".repeat(200));
    args.add("iat-mode", "0");
    c.bench_function("Args::encode_smethod_args", |b| {
        b.iter(|| black_box(&args).encode_smethod_args());
    });
}

fn bench_args_add_retrieve(c: &mut Criterion) {
    c.bench_function("Args::add+retrieve(10)", |b| {
        b.iter(|| {
            let mut args = ptrs::args::Args::new();
            for i in 0..10 {
                args.add(&format!("key{i}"), &format!("value{i}"));
            }
            for i in 0..10 {
                black_box(args.retrieve(format!("key{i}")));
            }
        });
    });
}

criterion_group!(
    benches,
    bench_args_parse_client_parameters,
    bench_args_encode_smethod,
    bench_args_add_retrieve
);
criterion_main!(benches);
