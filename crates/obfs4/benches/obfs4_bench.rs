use std::time::Duration;

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

fn bench_replay_filter_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("replay_filter_scaling");
    // Mid-size only; lookup is O(1) so the scaling sweep does not buy
    // signal worth the wall-clock cost.
    let size: u64 = 10_000;
    let filter = ReplayFilter::new(std::time::Duration::from_secs(3600));
    let now = std::time::Instant::now();
    for i in 0..size {
        filter.test_and_set(now, i.to_le_bytes());
    }
    group.bench_function(format!("lookup_after_{size}_inserts"), |b| {
        let mut j = size;
        b.iter(|| {
            j += 1;
            filter.test_and_set(now, black_box(j.to_le_bytes()))
        });
    });
    group.finish();
}

fn bench_framing_build_and_marshall(c: &mut Criterion) {
    use obfs4::framing::build_and_marshall;
    let mut group = c.benchmark_group("framing");
    for &size in &[0usize, 64, 512, 1400] {
        let payload = vec![0xABu8; size];
        group.bench_function(format!("build_and_marshall_{size}B"), |b| {
            b.iter(|| {
                let mut buf = bytes::BytesMut::with_capacity(size + 16);
                build_and_marshall(&mut buf, 0x01, black_box(&payload), 0).unwrap();
                black_box(buf);
            });
        });
    }
    group.finish();
}

fn bench_handshake_marshall(c: &mut Criterion) {
    use hmac::{Hmac, Mac};
    use obfs4::common::x25519_elligator2::PublicRepresentative;
    use obfs4::framing::handshake::{ClientHandshakeMessage, ServerHandshakeMessage};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let repres = PublicRepresentative::from([0x42u8; 32]);
    let hmac_key = [0xAB; 32];

    c.bench_function("client_handshake_marshall", |b| {
        b.iter(|| {
            let h = HmacSha256::new_from_slice(&hmac_key).unwrap();
            let mut msg = ClientHandshakeMessage::new(repres, 128, String::new());
            let mut buf = bytes::BytesMut::with_capacity(256);
            msg.marshall(&mut buf, h).unwrap();
            black_box(buf);
        });
    });

    c.bench_function("server_handshake_marshall", |b| {
        b.iter(|| {
            let h = HmacSha256::new_from_slice(&hmac_key).unwrap();
            let mut msg = ServerHandshakeMessage::new(repres, [0xCC; 32], String::from("0"));
            let mut buf = bytes::BytesMut::with_capacity(256);
            msg.marshall(&mut buf, h).unwrap();
            black_box(buf);
        });
    });
}

fn bench_codec_encrypt_decrypt(c: &mut Criterion) {
    use obfs4::framing::KEY_MATERIAL_LENGTH;
    use tokio_util::codec::{Decoder, Encoder};

    let mut group = c.benchmark_group("codec");
    let enc_km = [0x42u8; KEY_MATERIAL_LENGTH];
    let dec_km = [0x42u8; KEY_MATERIAL_LENGTH];

    for &size in &[64usize, 512, 1400] {
        let payload = vec![0xABu8; size];
        group.bench_function(format!("encode_{size}B"), |b| {
            let mut codec = obfs4::framing::Obfs4Codec::new(enc_km, dec_km);
            b.iter(|| {
                let mut dst = bytes::BytesMut::with_capacity(size + 64);
                codec
                    .encode(
                        bytes::BytesMut::from(black_box(payload.as_slice())),
                        &mut dst,
                    )
                    .unwrap();
                black_box(dst);
            });
        });

        group.bench_function(format!("roundtrip_{size}B"), |b| {
            b.iter_custom(|iters| {
                let mut enc = obfs4::framing::Obfs4Codec::new(enc_km, dec_km);
                let mut dec = obfs4::framing::Obfs4Codec::new(dec_km, enc_km);
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let mut dst = bytes::BytesMut::with_capacity(size + 64);
                    enc.encode(bytes::BytesMut::from(payload.as_slice()), &mut dst)
                        .unwrap();
                    let _ = dec.decode(&mut dst).unwrap();
                }
                start.elapsed()
            });
        });
    }
    group.finish();
}

fn bench_crypto(c: &mut Criterion) {
    use obfs4::common::drbg;
    use obfs4::common::x25519_elligator2::{EphemeralSecret, PublicKey, PublicRepresentative};

    c.bench_function("ephemeral_key_generation", |b| {
        b.iter(|| {
            black_box(EphemeralSecret::random());
        });
    });

    c.bench_function("diffie_hellman_exchange", |b| {
        let bob = EphemeralSecret::random();
        let bob_pk = PublicKey::from(&bob);
        b.iter(|| {
            let alice = EphemeralSecret::random();
            black_box(alice.diffie_hellman(&bob_pk));
        });
    });

    c.bench_function("elligator2_representative_to_pubkey", |b| {
        let secret = EphemeralSecret::random();
        let repr = PublicRepresentative::from(&secret);
        b.iter(|| {
            black_box(PublicKey::from(&repr));
        });
    });

    c.bench_function("drbg_uint64_as_mask", |b| {
        let seed = drbg::Seed::new().unwrap();
        let mut drbg = drbg::Drbg::new(Some(seed)).unwrap();
        b.iter(|| black_box(drbg.uint64()));
    });
}

fn fast_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = fast_criterion();
    targets = bench_drbg,
              bench_replay_filter,
              bench_weighted_dist,
              bench_seed_generation,
              bench_replay_filter_scaling,
              bench_framing_build_and_marshall,
              bench_handshake_marshall,
              bench_codec_encrypt_decrypt,
              bench_crypto
}
criterion_main!(benches);
