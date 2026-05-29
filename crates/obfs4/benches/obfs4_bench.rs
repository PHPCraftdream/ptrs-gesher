use std::time::Duration;

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

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
    // 1426 is the largest body `build_and_marshall` accepts: its guard rejects
    // `data.len() + pad_len >= MAX_MESSAGE_PAYLOAD_LENGTH` (1427), so 1426 is the
    // maximum single-message payload (the on-wire 1448B segment also carries the
    // type/length header and the AEAD tag, which this layer does not add).
    for &size in &[0usize, 64, 512, 1426] {
        let payload = vec![0xABu8; size];
        // Throughput reports MB/s over the marshalled payload bytes. The 0B case
        // has zero throughput by definition, so only attach the counter when
        // there is payload to measure.
        if size > 0 {
            group.throughput(Throughput::Bytes(size as u64));
        }
        group.bench_with_input(BenchmarkId::new("build_and_marshall", size), &size, |b, &size| {
            // The output buffer is allocated in the (untimed) setup so the timed
            // region measures only marshalling, not allocation.
            b.iter_batched(
                || bytes::BytesMut::with_capacity(size + 16),
                |mut buf| {
                    build_and_marshall(&mut buf, 0x01, black_box(&payload), 0).unwrap();
                    black_box(buf);
                },
                BatchSize::SmallInput,
            );
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
    use bytes::{BufMut, BytesMut};
    use obfs4::framing::{KEY_MATERIAL_LENGTH, MessageTypes, Obfs4Codec};
    use tokio_util::codec::{Decoder, Encoder};

    let mut group = c.benchmark_group("codec");
    let enc_km = [0x42u8; KEY_MATERIAL_LENGTH];
    let dec_km = [0x42u8; KEY_MATERIAL_LENGTH];

    // 1430 == MAX_FRAME_PAYLOAD_LENGTH: the largest plaintext a single frame can
    // carry (1448B segment minus the 2B length and 16B Poly1305 tag). This is the
    // size of a fully-packed production data frame, so it is the most
    // representative MAX case for the AEAD hot path.
    for &size in &[64usize, 512, 1430] {
        // Application payload bytes per frame — drives the reported MB/s.
        group.throughput(Throughput::Bytes(size as u64));
        let payload = vec![0xABu8; size];

        // --- encode: time only the seal, not input/output allocation ---
        group.bench_with_input(BenchmarkId::new("encode", size), &size, |b, &size| {
            let mut codec = Obfs4Codec::new(enc_km, dec_km);
            b.iter_batched(
                || {
                    (
                        BytesMut::from(payload.as_slice()),
                        BytesMut::with_capacity(size + 64),
                    )
                },
                |(pt, mut dst)| {
                    codec.encode(pt, &mut dst).unwrap();
                    black_box(dst);
                },
                BatchSize::SmallInput,
            );
        });

        // --- standalone decode: feed a pre-sealed frame, time only the open ---
        // A fresh encoder/decoder pair is built in the (untimed) setup so their
        // nonce counters both start at 1 and the single frame authenticates; the
        // timed routine consumes the frame via `decode`. The plaintext is a
        // hand-built `Payload` message (`type=0x00 || u16 len || bytes`) so the
        // measured path includes the real `try_parse` + payload copy, not just
        // the early-out for an unknown message type.
        group.bench_with_input(BenchmarkId::new("decode", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let mut enc = Obfs4Codec::new(enc_km, dec_km);
                    let dec = Obfs4Codec::new(dec_km, enc_km);
                    let mut plaintext = BytesMut::with_capacity(size + 3);
                    plaintext.put_u8(MessageTypes::Payload.into());
                    plaintext.put_u16(size as u16);
                    plaintext.put_slice(&payload);
                    let mut frame = BytesMut::with_capacity(size + 64);
                    enc.encode(plaintext, &mut frame).unwrap();
                    (dec, frame)
                },
                |(mut dec, mut frame)| {
                    black_box(dec.decode(&mut frame).unwrap());
                },
                BatchSize::SmallInput,
            );
        });

        // --- roundtrip: encode + decode in lockstep (counters stay aligned) ---
        group.bench_with_input(BenchmarkId::new("roundtrip", size), &size, |b, &size| {
            let mut enc = Obfs4Codec::new(enc_km, dec_km);
            let mut dec = Obfs4Codec::new(dec_km, enc_km);
            b.iter_batched(
                || {
                    (
                        BytesMut::from(payload.as_slice()),
                        BytesMut::with_capacity(size + 64),
                    )
                },
                |(pt, mut dst)| {
                    enc.encode(pt, &mut dst).unwrap();
                    black_box(dec.decode(&mut dst).unwrap());
                },
                BatchSize::SmallInput,
            );
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
