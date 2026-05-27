# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
