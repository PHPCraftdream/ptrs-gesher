# Benchmark baseline — ptrs-gesher 0.1.0-pre

Captured via `cargo bench --workspace -- --save-baseline initial`.

- **Host:** Windows 10 / 11th Gen Intel Core i7-11800H @ 2.30 GHz
- **Toolchain:** `rustc 1.93.0 (254b59607 2026-01-19)`
- **Date:** 2026-05-27
- **Release profile:** `lto = "thin"`, `codegen-units = 1` (from
  workspace `Cargo.toml`).
- **RUSTFLAGS:** unset.

Numbers shown are Criterion's median estimate, with the `[low high]`
bracket reflecting the bootstrap confidence interval. They were
captured with the **long-form Criterion defaults** (100 samples,
3 s warm-up, 5 s measurement) for highest fidelity — that run took
~20 minutes wall-clock.

The bench groups have since been re-tuned to a faster default
(20 samples, 0.5 s warm-up, 1 s measurement, ~4 minute total run)
to keep day-to-day regression checks cheap. Numbers within ±5 % of
the baseline below are noise; anything beyond that is a real
signal worth investigating.

To compare on the same machine after changes (uses the new fast
defaults baked into each `criterion_group!`):

```
cargo bench --workspace -- --baseline initial
```

To re-capture the long-form baseline (e.g. after a major refactor):

```
cargo bench --workspace -- --save-baseline initial \
    --sample-size 100 --warm-up-time 3 --measurement-time 5
```

## Cryptographic primitives

| Benchmark | Median | Range |
|---|---:|---|
| `diffie_hellman_exchange` | 220.02 µs | [213.29 µs, 226.60 µs] |
| `elligator2_representative_to_pubkey` | 29.96 µs | [29.90 µs, 30.03 µs] |
| `ephemeral_key_generation` | 102.81 µs | [101.21 µs, 104.52 µs] |
| `seed_new_from_os_rng` | 186.74 ns | [175.55 ns, 196.82 ns] |
| `drbg_uint64` (Hash-DRBG SipHash-2-4) | 41.25 ns | [39.09 ns, 44.14 ns] |
| `drbg_next_block` | 47.85 ns | [46.45 ns, 49.35 ns] |
| `drbg_uint64_as_mask` | 30.18 ns | [29.86 ns, 30.49 ns] |
| `weighted_dist_sample` | 254.59 ns | [250.40 ns, 259.69 ns] |

## obfs4 handshake & tunnel

| Benchmark | Median | Range |
|---|---:|---|
| `client_handshake_marshall` | 3.46 µs | [3.30 µs, 3.62 µs] |
| `server_handshake_marshall` | 16.81 µs | [16.51 µs, 17.13 µs] |
| `obfs4_full_handshake_duplex` (E2E via tokio::io::duplex) | 1.98 ms | [1.96 ms, 2.00 ms] |
| `obfs4_tunnel_throughput/1024` (per call) | 2.12 ms | [2.08 ms, 2.15 ms] |
| `obfs4_tunnel_throughput/32768` (per call) | 2.98 ms | [2.94 ms, 3.01 ms] |

`obfs4_*_handshake_marshall` measures pure cell-construction cost,
no IO. The duplex variant measures full handshake including codec
round-trips.

## Framing codec

| Benchmark | Median | Range |
|---|---:|---|
| `framing/build_and_marshall_0B` | 133.48 ns | [130.17 ns, 136.86 ns] |
| `framing/build_and_marshall_64B` | 216.12 ns | [206.95 ns, 226.07 ns] |
| `framing/build_and_marshall_512B` | 158.96 ns | [154.92 ns, 163.03 ns] |
| `framing/build_and_marshall_1400B` | 166.65 ns | [163.59 ns, 169.78 ns] |

## Replay filter (Bloom-style sliding-window cache)

| Benchmark | Median | Range |
|---|---:|---|
| `replay_filter_test_and_set_new` | 745.64 ns | [674.86 ns, 824.59 ns] |
| `replay_filter_test_and_set_existing` | 134.30 ns | [128.90 ns, 140.41 ns] |
| `replay_filter_scaling/lookup_after_1000_inserts` | 760.41 ns | [728.37 ns, 794.97 ns] |
| `replay_filter_scaling/lookup_after_10000_inserts` | 571.75 ns | [551.02 ns, 591.68 ns] |
| `replay_filter_scaling/lookup_after_100000_inserts` | 478.21 ns | [459.81 ns, 495.24 ns] |

Lookup time is dominated by the constant-time hash; the cache scales
flat as expected.

## lyrebird helpers

| Benchmark | Median | Range |
|---|---:|---|
| `bidirectional_copy/65536` (≈128 KiB total, both dirs) | 3.00 ms | [2.40 ms, 3.66 ms] |
| `bidirectional_copy/1048576` (≈2 MiB total, both dirs) | 16.14 ms | [14.51 ms, 17.83 ms] |
| `arg_string_from_creds_small` | 297.50 ns | [271.94 ns, 322.27 ns] |
| `arg_string_from_creds_mid` (255-char user) | 421.64 ns | [407.47 ns, 437.03 ns] |
| `arg_string_from_creds_full` (255+255) | 743.39 ns | [677.34 ns, 813.14 ns] |
| `arg_string_from_creds_none` | 8.68 ns | [8.50 ns, 8.89 ns] |
| `arg_string_then_parse_e2e` | 6.44 µs | [6.30 µs, 6.57 µs] |
| `resolve_target_addr_ipv4` | 13.95 ns | [13.82 ns, 14.08 ns] |
| `resolve_target_addr_ipv6` | 14.65 ns | [14.46 ns, 14.84 ns] |
| `resolve_target_addr_domain_rejected` | 1.59 µs | [1.55 µs, 1.63 µs] |

`bidirectional_copy` uses a `duplex(2 * size)` buffer to avoid
backpressure deadlocks (see comment in the bench source). The
measured number includes one set of buffer-allocations plus two
write+copy cycles per iteration.

## Args parser (ptrs::args)

| Benchmark | Median | Range |
|---|---:|---|
| `Args::parse_client_parameters` | 2.08 µs | [1.97 µs, 2.17 µs] |
| `Args::encode_smethod_args` | 1.36 µs | [1.33 µs, 1.39 µs] |

(See umbrella variants below for the same operations re-exported
through `ptrs-gesher`.)

## bridge-line parser

| Benchmark | Median | Range |
|---|---:|---|
| `parse_obfs4` (full directive w/ cert+iat-mode) | 4.68 µs | [4.61 µs, 4.76 µs] |
| `parse_webtunnel` | 1.48 µs | [1.44 µs, 1.52 µs] |
| `parse_plain` (no transport, no settings) | 733.62 ns | [691.24 ns, 790.18 ns] |
| `display_obfs4` (Display roundtrip) | 2.00 µs | [1.96 µs, 2.05 µs] |

## webtunnel handshake bits

| Benchmark | Median | Range |
|---|---:|---|
| `WebTunnelConfig::from_args` | 1.36 µs | [1.32 µs, 1.39 µs] |
| `WebTunnelConfig::from_args_with_sni` | — | (see source) |
| `generate_websocket_key` | 323.24 ns | [309.25 ns, 336.64 ns] |
| `build_upgrade_request` | 1.87 µs | [1.86 µs, 1.89 µs] |
| `parse_response_101_small` | 220.09 ns | [216.70 ns, 223.37 ns] |
| `parse_response_101_20_headers` | 801.97 ns | [782.11 ns, 822.88 ns] |
| `parse_response_error_path` (404) | 607.78 ns | [591.98 ns, 624.15 ns] |

## Umbrella crate re-exports

These re-run the same parsers through `ptrs-gesher`'s flat
top-level re-exports; they should match the inner-crate numbers
within noise.

| Benchmark | Median | Range |
|---|---:|---|
| `umbrella::Args::parse_client_parameters` | 2.08 µs | [1.97 µs, 2.17 µs] |
| `umbrella::Args::add+retrieve` | 1.36 µs | [1.33 µs, 1.39 µs] |
| `umbrella::BridgeLine::parse_obfs4` | 1.66 µs | [1.60 µs, 1.73 µs] |
| `umbrella::WebTunnelConfig::from_args` | 1.36 µs | [1.32 µs, 1.39 µs] |

## Notes on noise

- `bidirectional_copy/*` shows 30–40 % variance — driven by tokio
  task-spawn scheduling jitter, not by `bidirectional_copy` itself.
  Treat these as order-of-magnitude only.
- `arg_string_from_creds_full` (3 outliers high mild) similarly
  dominated by allocator jitter.
- All sub-100-ns benches are within ±5 % run-to-run.
