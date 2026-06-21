# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **obfs4**: `pad_burst` no longer emits over-sized padding frames that the
  codec rejects. The previous implementation followed a flawed sketch from
  upstream's commented-out draft: a single padding frame whose zero-fill
  was `pad_len - MESSAGE_OVERHEAD`. When `pad_len` was close to
  `MAX_SEGMENT_LENGTH` (≈1430–1447 bytes) the resulting `pad_bytes`
  exceeded `MAX_MESSAGE_PAYLOAD_LENGTH - 1`, and `build_and_marshall`
  returned `Invalid payload length`. The new implementation is a loop
  that splits the requested padding into one or more frames of at most
  `MAX_MESSAGE_PAYLOAD_LENGTH - 1` padding bytes, with a guard that
  refuses to leave a 1- or 2-byte tail the next frame could not express
  (the minimum frame contribution is `MESSAGE_OVERHEAD = 3` bytes); when
  the requested `pad_len` itself falls below `MESSAGE_OVERHEAD` it is
  rolled into the next segment so the final tail still matches the
  caller's target. The doc comment is rewritten to reflect this. The
  bug only surfaced with `iat-mode ∈ {1, 2}` (default is `0/Off`) and
  was missed by the original Etap-2 tests, which sampled only three
  target lengths. New tests close that gap: `pad_burst_hits_target_for_all_lengths`
  enumerates every `target ∈ 0..MAX_SEGMENT_LENGTH` × a representative
  cross-section of starting tails (§F: enumerate, don't sample);
  `pad_burst_padding_frames_round_trip_through_decoder` parses the
  emitted padding frames back through `Messages::try_parse` (§F4: inverse
  round-trip). Negative control verified locally — reverting to the old
  single-frame path makes the exhaustive test fail at `target=1`.

- **obfs4**: `Client::establish` now generates the elligator2-representable
  ephemeral key BEFORE awaiting the stream future (TCP dial), closing
  upstream issue jmwample/ptrs#15. The elligator2 retry loop succeeds with
  ~50% probability per iteration, so doing keygen after the dial inserted a
  variable, network-observable gap between the TCP handshake and the first
  obfs4 byte that a censor could fingerprint.  The dial-keygen order
  invariant is locked in by an order-asserting test (§D1a):
  `establish_runs_keygen_before_stream_fut` instruments a keygen closure
  and a `stream_fut` that records its first poll, then asserts keygen
  completed strictly before the dial began — negative control confirmed by
  inverting the order locally (the test fires
  `keygen MUST complete before stream_fut is first polled`).
  `Client::wrap` is unaffected (the stream is already connected by the
  time it is called).  Internally: `ClientSession::handshake` and
  `ClientSession::complete_handshake` now accept
  `Option<EphemeralSecret>`; when `Some`, the pre-generated key is fed
  through `client_handshake_obfs4_no_keygen` instead of the trait
  `client1()` path.

### Added

- **obfs4**: real IAT (Inter-Arrival Time) delay policy and `pad_burst` in
  the write path — closes the long-standing `proto.rs:210` TODO. IAT delays
  between writes are sampled from `iat_dist` and imposed via a
  `Pin<Box<tokio::time::Sleep>>` gate at the top of `poll_write`; never
  blocks the executor (§B11). `pad_burst` pads the marshalled buffer so
  the trailing wire segment lands on a length sampled from `length_dist`,
  hiding the true payload size. `IAT::Paranoid` additionally sources each
  chunk size from `length_dist` (variable-size segments) instead of always
  using `MAX_MESSAGE_PAYLOAD_LENGTH`. `poll_shutdown` clears pending IAT
  delays so streams close promptly. H3 handshake fix is untouched; the
  upstream `obfs4-features` branch (PR #41) was used as a *design source*,
  not ported — its Sink/Stream migration was deliberately not adopted.
  Covered by 7 new tests including explicit negative controls for
  `pad_burst` and `IAT::Off`/`IAT::Enabled` distinguishability (§D1a).

### Changed

- **obfs4**: bumped `tor-cell`, `tor-llcrypto`, `tor-error`, `tor-bytes` from
  0.25.0 to 0.39.0. Version 0.39.0 is the latest release compatible with the
  project MSRV 1.88 (the tor-* 0.40.0+ line requires Rust 1.89). The MSRV
  contract is deliberately kept at 1.88: the consumed surface (SHA-256/SHAKE-256
  digests, `RsaIdentity`, `SecretBuf`, error types) is stable across 0.39–0.43,
  there is no RUSTSEC advisory against these crates, so raising MSRV to chase
  0.43 buys nothing while breaking downstream tool-chain requirements.
- **obfs4**: removed `tor-basic-utils` dev-dependency. The 0.39.0 release
  exports `TestingRng` built on `rand_core 0.9`, which is incompatible with
  the project's `rand 0.8` (`rand_core 0.6`). Tests that used `testing_rng()`
  now use `rand::thread_rng()` instead.
- **core**: bumped `itertools` from 0.13.0 to 0.14.0 (MSRV 1.63.0, no API
  breakage on the consumed surface `sorted`/`join`/`collect_vec`). Held at
  0.14.0 rather than 0.15.0 on purpose: `tor-cell 0.39.0` already pins
  `itertools ^0.14.0`, so matching that version de-duplicates the dependency
  tree (one `itertools 0.14` node shared instead of an extra 0.15 copy), and
  0.15.0 offers nothing on the surface we use.

## [0.4.0] - 2026-06-10

Synchronized release: every crate is bumped to 0.4.0 in lockstep. This release
collects the fixes from a full `rust-cc-audit` pass. The robustness and
log-hygiene fixes are behaviour-only, but the audit also surfaced public-API
residue whose removal is a breaking change — hence the minor bump rather than a
patch. The 0.3.0 line is superseded.

### Fixed

- **obfs4**: the handshake read loop reused its buffer from index 0 on every
  read, so a server (or client) hello delivered in multiple TCP segments was
  never accumulated — each `EAgain` discarded the previously-read bytes and a
  fragmented handshake could hang until timeout. Both the client
  (`ClientSession::complete_handshake`) and server (`Server::complete_handshake`)
  loops now accumulate into the buffer and reject only once it is full. Covered
  by a regression test that drives the handshake through a 32-byte-per-read
  transport (verified red before the fix).
- **obfs4**: `O4Stream::poll_write` compared `poll_ready(...) == Poll::Pending`,
  silently dropping a `Poll::Ready(Err(_))` from the sink; the framing error is
  now propagated instead of calling `start_send` on a failed sink.
- **obfs4**: `server_state_from_file` built the state-file path by string
  concatenation without a separator (`/dir` + `state.json` → `/dirstate.json`);
  it now uses `Path::join`.
- **webtunnel**: `use_tls()` matched the raw URL with `starts_with("https")`,
  which is case-sensitive (`HTTPS://` was treated as plaintext) and accepted
  bogus schemes (`httpsx://`); it now parses the URL and compares the scheme.

### Security / hygiene

- **obfs4**: removed `trace!`/`debug!` statements that hex-dumped session key
  material (XSalsa20-Poly1305 key material, the ntor `key_seed`, and the
  length-obfuscation seed). These were behind the crate-internal,
  `feature = "debug"`-gated logging macros (never emitted in a default release
  build), but dumping key material into any log is removed regardless.
- **obfs4**: `drbg::Seed` no longer derives `Debug`/`PartialEq`; it now has a
  redacting `Debug` (`drbg::Seed(..)`), a constant-time `PartialEq` via
  `subtle`, and a `Drop` that zeroizes the seed bytes.

### Changed (breaking)

- **core**: `Args` and `Opts` no longer implement `Deref`/`DerefMut` to
  `HashMap` — the full `HashMap` surface (including `insert`/`remove`/`clear`)
  is no longer exposed and callers can no longer bypass `add()`/`parse()`.
  Explicit accessors are provided instead (`get`, `contains_key`, `is_empty`,
  `len`, `iter`, plus `Opts::remove`).
- **core**: the `args!` macro is no longer `#[macro_export]`ed — it was
  unusable outside the crate (it expanded to crate-private paths) and is now
  crate-internal.

### Removed

- **core**: the unused `Conn` / `ConnectExt` traits and their
  `impl Conn for TcpStream`/`UdpSocket` (which hard-coded `127.0.0.1:9000`).
- **lyrebird**: the `bidirectional_copy` helper — production paths already use
  `tokio::io::copy_bidirectional` (which correctly propagates shutdown); the
  helper was only reachable from its own test.

### Tests

- **core**: the `passthrough` tests no longer bind fixed ports (8000–8010) or
  synchronize with `sleep` — they bind `127.0.0.1:0` and pass the address via a
  `oneshot`, and assert the echoed bytes via `write_all`/`read_exact` instead of
  a single unchecked `read`.

## [0.3.0] - 2026-06-04

Synchronized release: every crate is bumped to 0.3.0 in lockstep, so a 0.3.x
crate is guaranteed to interoperate with the other 0.3.x crates. The 0.1.x and
0.2.0 versions are yanked — `ptrs-gesher-lyrebird` 0.2.0 could not connect to
bridges (see below); the transports (`core`, `obfs4`, `webtunnel`,
`bridge-line`) are functionally unchanged from 0.2.0 and are re-published at
0.3.0 only to keep the published line consistent.

### Fixed

- **lyrebird**: the client SOCKS5 handler dialed bridges over plain TCP
  instead of obfs4, so no bridge could be reached through the transport.
  fast-socks5's default `execute_command = true` made `upgrade_to_socks5()`
  execute the CONNECT itself — opening a plain TCP connection to the bridge
  and replying to the parent — bypassing the obfs4 handshake entirely.
  lyrebird now parses the request only (`execute_command(false)`), dials the
  bridge over obfs4 itself, and sends the SOCKS5 success reply only once the
  handshake completes. Covered by two regression tests.

### Added

- `connect_real_bridge` and `connect_real_webtunnel` examples — diagnostics
  that drive the obfs4 / webtunnel clients directly against real bridges (no
  arti, no PT manager), isolating each transport from the embedding glue.

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
