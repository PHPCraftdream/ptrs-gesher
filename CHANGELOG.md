# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-28

Public-API cleanup (breaking) layered on top of the 0.1.1 security hotfix.
The 0.1.1 changes were never published to crates.io separately and ship as
part of this release.

### Changed (breaking)

- **obfs4**: internal modules (`common`, `framing`, `proto`) are hidden from
  the public API via `#[doc(hidden)]`, and the foreign-crate re-exports
  (`x25519-dalek`, the `curve25519-elligator2` alpha) are removed from the
  surface — alpha dependencies no longer leak into our semver. The public
  stream/config types (`Obfs4Stream`, `IAT`) are re-exported from the crate
  root.
- **obfs4 / bridge-line / webtunnel**: public error types and open-ended
  config types are now `#[non_exhaustive]` (`Error`, `FrameError`, `IAT`,
  `ParseError`, `BridgeLine`, `WebTunnelConfig`).
- **obfs4**: `ClientBuilder` / `ServerBuilder` fields are encapsulated; use
  the existing setters.
- **all crates**: declared MSRV corrected to `1.88` — the resolved dependency
  tree requires it (the earlier `1.75` was inaccurate and never resolved, as
  transitive deps pull in `edition2024` and `serde_with` 3.20).

### Fixed

- **obfs4**: `O4Stream::poll_read` no longer panics when a decoded frame is
  larger than the caller's read buffer; the remainder is buffered and
  delivered across subsequent reads.
- **obfs4**: removed reachable panics in `WeightedDist` sampling,
  `ReplayFilter` lock-poison handling, and the epoch-hour / handshake-pad
  helpers.
- **webtunnel**: `WebTunnelBuilder::build()` no longer panics on a missing
  config; a typed error surfaces at connect time instead.

### Removed

- **obfs4**: 6 dead optional dependencies (`curve25519-dalek`, `anyhow`,
  `async-trait`, `num-bigint`, `simple_asn1`, `filetime`).
- **core, obfs4**: unused `cdylib` crate-type (no C ABI exists).
- Three vacuous tests (asserted nothing).

### Added

- `docs.rs` metadata (`all-features`) for all six published crates.
- CI: MSRV (1.88) check, `rustdoc -D warnings`, and an
  `experimental-server` feature build.

## [0.1.1] - 2026-05-28

Security hotfix (commit `5834832`).

### Security

- **obfs4**: an invalid-length frame now triggers an immediate connection
  reject instead of being tolerated. The upstream Bider-style "swallow and
  resync" countermeasure is unsound for an AEAD stream — a length desync
  cannot be recovered and was a remotely-triggerable corruption vector.
- **obfs4**: `messages_v1::try_parse` now validates the declared length
  against its bound before reading, removing a frame-length-based
  fingerprinting / mis-parse surface.
- **obfs4**: `REPLAY_TTL` raised from 60 s to 30 h so the replay window
  fully covers the ±1 h epoch-MAC slack. Previously a replayed handshake
  could fall outside the filter and be re-accepted.
- **obfs4**: `x25519_elligator2` now returns a `Result` instead of
  panicking, closing a reachable handshake-path DoS.
- **lyrebird**: the server-side PT-manager path is now gated behind the
  optional `experimental-server` feature, preventing an accidental
  unauthenticated open relay in default builds.

### Fixed

- **lyrebird**: removed the broken `tunnel_mgr` module (non-functional
  public API).

### Changed

- **docs/legal**: `SECURITY.md` expanded (embargo, scope, contact);
  `LICENSE-MIT` carries the fork copyright line.

## [0.1.0] - 2026-05-26

### Added

- Initial fork from `jmwample/ptrs`.
- New crate `ptrs-gesher-webtunnel` — TLS + HTTP/1.1 Upgrade transport.
- New crate `ptrs-gesher-bridge-line` — torrc `Bridge` directive parser.
- `lyrebird` refactored into a library (`lyrebird::run()`) + thin binary
  so parent applications can embed the PT-manager loop in-process.
- Property-based tests for `Args`, `BridgeLine`, framing messages,
  webtunnel response parser (incl. 10k-iteration fuzz-like runs).
- obfs4 E2E tests covering data-path, error paths, replay-attack
  resistance, and concurrent stress.
- Benchmarks for handshake latency, tunnel throughput, DH/keygen/
  elligator2, codec encode/decode, args parsing.
- CI coverage workflow via cargo-llvm-cov → Codecov.
- Runnable `examples/` directory in every crate (6 examples total).
- CI gates: `cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo-deny`.
- `#![deny(missing_docs)]` enforced on all six crates.
- Captured benchmark baseline under `docs/BENCHMARKS.md`.

### Changed

- Source-compatible with `jmwample/ptrs` via Cargo `package =` rename.
- API-compatible umbrella crate `ptrs-gesher` re-exporting flat
  top-level types (`Args`, `BridgeLine`, `Obfs4PT`, `WebTunnelBuilder`).
- Workspace MSRV unified to 1.75.
- Bench groups retuned to ~4 min full-run wall-clock (down from ~20 min).

### Fixed

- `Args::parse_client_parameters` panicked on multi-byte UTF-8 input
  (byte/char index confusion). Found via proptest.
- `messages_v1::try_parse` for `PrngSeed` could underflow on a short
  buffer. Found via proptest.
- Resolved 15 pre-existing intra-doc-link and unclosed-HTML-tag warnings in `core` and `obfs4` rustdoc.
- Documented ~103 previously-undocumented public items in obfs4.
- Fixed deadlock in `bidirectional_copy/1048576` bench (duplex-buffer backpressure).

### Removed

- Upstream-WIP `o5`, `o7` transports.
- Lyrebird `fwd/` forward-proxy binary (scope unrelated to bridge
  transport).
