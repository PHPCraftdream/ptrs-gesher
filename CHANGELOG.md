# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-09-18

Published through crates.io Trusted Publishing from the pinned source release;
all six crates move to 0.6.0 in lockstep. Rust 1.89 remains the minimum
supported version.

### Breaking changes

- **webtunnel**: `ClientTransport::wrap` and `establish` now use the supplied
  carrier instead of discarding it and dialing the configured URL. Use
  `WebTunnelClient::connect_url()` for direct URL connections. For non-TCP
  carriers, `OutRW` is now `PrefixStream<WebTunnelStream<Carrier>>`, rather than
  the TCP specialization. Typed consumers must update their output types.
- **core**: client/SOCKS argument parsing, including `Args::from_str`, treats
  only `;` as a separator. SMETHOD parsing uses the explicit
  `Args::parse_smethod_args` API and `,` separator. Commas inside SOCKS URL
  values and semicolons inside SMETHOD values are preserved.
- **bridge-line**: transport names must match `[A-Za-z_][A-Za-z0-9_]*`;
  names beginning with digits or containing hyphens are rejected.
- Unsupported obfs4 bind setters and WebTunnel persistent-state configuration
  return errors. WebTunnel bind addresses apply only to `connect_url`; combining
  them with a supplied carrier is rejected instead of silently ignored.

See [migration to 0.6.0](docs/MIGRATING-0.6.md) for updated call sites and state-file rules.

### Added

- **core**: paired `parse_smethod_args`/`encode_smethod_args` and
  `parse_client_parameters`/`encode_client_parameters` APIs.
- **obfs4**: fallible `try_build`, `try_node_keys`, `try_statefile_path`,
  `try_client_params`, and `try_get_args` APIs; explicit
  `Server::new_from_statefile_at` and `write_statefile_to` operations.
- **lyrebird**: `run_from_env()` lets embedding applications own CLI and logging
  setup while retaining the managed-transport lifecycle.

### Fixed

- **obfs4**: schedule actual ciphertext writes according to IAT mode, rather
  than delaying only plaintext buffering. Flush and shutdown drain accepted
  data; partial writes, Interrupted and terminal errors preserve byte accounting
  and I/O error kinds without duplicating an accepted prefix.
- **obfs4**: implement client parameter parsing, serialization and transactional
  argument updates. Legacy infallible APIs defer configuration errors until
  handshake; their fallible counterparts return errors immediately.
- **obfs4**: apply state-file setters and preserve fieldwise overrides. Go numeric
  IAT values and legacy string values are accepted. Validate supplied key pairs,
  retain configured traffic seeds, and keep advertised client parameters aligned
  with the effective server identity used by subsequent builds.
- **obfs4**: use unique temporary files and atomic state replacement with Unix
  permissions 0600. Sync the parent directory on Unix; a failed durability sync
  after publication can be retried without treating our own write as an external
  replacement or changing the advertised identity.
- **obfs4/webtunnel**: reject overflowing handshake timeouts before polling dial
  futures or starting handshake I/O.
- **webtunnel**: apply IPv4/IPv6 bind addresses to the corresponding URL dial.
  Lyrebird uses explicit URL dialing and does not resolve or connect to the
  cosmetic SOCKS target for this transport.
- **lyrebird**: cancel owned listeners and connections when the run future is
  dropped or aborted, including registration races. Retry transient accept
  errors; a lost listener or listener panic propagates after cleanup.
- **lyrebird**: reconfigure owned logging destinations and filters, including
  active spans and existing callsites, while preserving foreign subscribers,
  external logger levels and safe-logging guard lifetimes.
- **core**: retain explicit default proxy ports after URL normalization; treat
  an empty `TOR_PT_EXTENDED_SERVER_PORT` as absent.
- **bridge-line**: round-trip a transport named `Bridge` with an explicit prefix.
- **obfs4**: convert existing seed bytes without consulting the random source;
  make echo-test content and byte-count assertions observable by the parent test.
- **obfs4**: preserve replay history when caller timestamps arrive out of order;
  checking a duplicate at capacity no longer evicts an unexpired entry.
- **lyrebird**: bound SOCKS5 negotiation to ten seconds, retain the safe-logging
  guard, honor log levels, and preserve an embedding application's subscriber.
- **webtunnel**: give later addresses a chance after a stalled dial and reserve
  time for system-DNS fallback within the overall handshake deadline.
- **obfs4**: accept the maximum valid message body consistently and leave the
  destination unchanged when message construction fails.
- Require `rustls >=0.23.45` within the 0.23 series, including downstream consumers,
  to address
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
- **lyrebird**: keep stdin EOF detection active during graceful shutdown and
  cancel it without leaving a blocking reader behind. Join owned connection
  tasks before returning, including forced shutdown and setup failures.
- **lyrebird**: reject unsupported `TOR_PT_PROXY` values without copying proxy
  credentials or control characters into protocol output and error messages.
  An empty value consistently means that no upstream proxy is configured.

### Changed

- Encode obfs4 payloads through borrowed buffers and reuse padding scratch
  storage. Build alias tables in linear time and sample with one OS RNG call.
- Reuse lazy DNS and TLS state within a WebTunnel builder/client context;
  shared TLS configuration keeps session resumption disabled.
- Reduce temporary allocations in argument parsing and SMETHOD encoding.
- Measure obfs4 throughput on an established tunnel, with concurrent reads and
  writes and fully awaited cleanup. No new performance baseline is claimed.
- Track connection abort handles by task ID instead of rescanning active handles
  for each new connection.
- Pin release sources to an explicit tag/SHA across checks and partial retries;
  verify existing registry versions, archive checksums and VCS revision before
  reporting publish success. Local filesystem errors cannot masquerade as a
  package already present on crates.io.
- Use crates.io Trusted Publishing for all six crates, with fresh short-lived
  OIDC credentials for each publication and no stored registry-token secret.
  One-time configuration is documented in [RELEASING.md](docs/RELEASING.md).
- Add release-tooling regressions and bounded Rust/Go interoperability checks
  in both directions for all IAT modes, including malformed handshake replies.

## [0.5.3] - 2026-09-08

### Fixed

- **obfs4**: preserve absolute handshake deadlines across builder creation and
  delayed use; apply the establishment budget to TCP dialing too. Transport-trait
  timeout setters now take effect, and server defaults use the server timeout.
- **obfs4**: retain payload coalesced with the server handshake, propagate invalid
  buffered-frame errors, and apply later PRNG seeds to both shaping distributions.
  Reading into an empty buffer returns immediately.
- **webtunnel**: bound DNS, TCP, TLS, and HTTP Upgrade by one configurable timeout
  (30 seconds by default). Expiration closes the owned connection.
- **webtunnel**: normalize IPv6 socket/SNI addresses, preserve nondefault ports in
  HTTP Host, reject unsupported URL schemes and invalid server names, and honor
  the configured DNS policy for hostname address overrides.
- **webtunnel**: enable trusted roots for standalone DNS-over-HTTPS resolution;
  trust configuration no longer depends on another crate enabling the feature.
- **lyrebird**: cancellation interrupts admission when the connection limit is full.
- **obfs4**: continue decoding buffered frames after padding or unknown packets.
  Previously request/response streams could stall waiting for bytes already in
  the buffer, and EOF could discard a buffered reply. Regression tests cover an
  open peer socket and EOF; cryptography and wire encoding are unchanged.
- **obfs4**: preserve packet-length padding with `iat-mode=0`, encode padding as
  separate bounded frames, and use the reference implementation's 100-microsecond
  IAT units. Padding a full data frame previously exceeded the frame limit and
  closed the transport. Wire-level tests cover both modes and padding boundaries.

### Changed

- Refresh compatible dependencies while retaining Rust 1.89 support. The lockfile
  includes patched `h2` and non-yanked `chacha20` releases.
- Require this release of internal dependencies so consumers receive the fixes.
- Move stream and WebTunnel tests into separate modules; Rust files remain below
  1000 lines. Correct the description of the reference obfs4 sampling source.

## [0.5.2] - 2026-07-24

### Fixed

- **lyrebird**: honor `TOR_PT_EXIT_ON_STDIN_CLOSE=1` and exit when the
  parent process closes our stdin. PT-spec §3.4 ("Feature #15435")
  defines this as the canonical managed-transport shutdown signal —
  arti's `tor-ptmgr` closes a child PT's stdin when the transport is no
  longer needed (shutdown, reconfigure, transport removal). The Rust port
  was not reading stdin at all: the `pt_should_exit_on_stdin_close()`
  helper already existed in `core` but was never called from lyrebird's
  run loop, so every recreated `TorClient` (or any other PT parent
  restart) left an orphaned PT-child process behind as a zombie. `run()`
  now spawns a `spawn_blocking` watcher (driven by the new
  `ptrs::wait_stdin_close()` / `ptrs::wait_reader_close()` helpers in
  `core`) that cancels a `CancellationToken` on stdin EOF; that token is
  a third arm in both `select!` loops, triggering an immediate clean
  exit. When the env var is unset the watcher is not spawned and the arm
  is pending forever, so the previous "ignore stdin" behavior is
  unchanged. Covered by process-level integration tests that launch the
  real `lyrebird` binary and assert it exits (positive) / keeps running
  (negative) on stdin close.

## [0.5.1] - 2026-07-19

### Fixed

- **lyrebird**: honor the [`NO_COLOR`](https://no-color.org) convention in
  the PT-child console logger. `init_logging_recvr` built its
  `tracing_subscriber::fmt::layer()` with no `.with_ansi(...)` call, so
  ANSI color codes were always emitted to stderr regardless of the
  launching process's own logging configuration — when the parent (e.g.
  a busybox-dispatch host binary) disabled ANSI for its own logs and the
  terminal/sink didn't render escape codes, the PT child's lines showed
  up as raw `\x1b[...m` sequences. The layer now checks `NO_COLOR` (any
  value, including empty, per the convention) and disables ANSI when
  set; a launching process can propagate its own color preference by
  setting `NO_COLOR` in the child's environment before spawning the PT
  binary.

## [0.5.0] - 2026-06-23

Synchronized release: every crate is bumped to 0.5.0 in lockstep. The
public API of every crate is unchanged from 0.4.0 except for the
additive `doh_mode` field on `WebTunnelConfig` and the new
`webtunnel::DohMode` re-export, so this remains an additive minor under
the project's 0.x semver discipline. Themes: obfs4 traffic-signature
hardening + carrier stability fixes uncovered on real TCP, webtunnel
gaining a DNS-over-HTTPS resolver for its bridge-URL hostname, and a
refresh of the arti dependency cluster to the current head.

### Added

- **webtunnel**: DNS-over-HTTPS resolver for the bridge URL hostname.
  Webtunnel is the only ptrs-gesher transport that resolves a domain at
  dial time, so it is the only one with a real DNS-censorship surface.
  Curated pool of ten public providers (Cloudflare, Quad9, Google,
  AdGuard, Mullvad, NextDNS, DNS.SB, ControlD, CleanBrowsing, OpenDNS)
  with pinned v4 + v6 bootstrap IPs — the resolver never depends on
  system DNS to find the DoH server itself. Three modes via the new
  `doh-mode=` bridge-line argument: `off` / `strict` / `fallback`
  (default Fallback). When `addr=` is set, DoH is bypassed. SNI and TLS
  certificate validation continue to run against the URL hostname, not
  the resolved IP. Backed by hickory-resolver 0.26.1 with `https-ring`
  (matches the existing rustls 0.23 + ring stack; no aws-lc-rs is
  pulled in). `use_hosts_file = Never` so Strict cannot be bypassed
  via `/etc/hosts`. Tested with explicit negative controls (§D1a) at
  the resolver layer and the connect layer.

- **obfs4**: real IAT (Inter-Arrival Time) delay policy and `pad_burst`
  in the write path — closes the long-standing `proto.rs:210` TODO.
  IAT delays sampled from `iat_dist` are imposed via a
  `Pin<Box<tokio::time::Sleep>>` gate at the top of `poll_write`;
  never blocks the executor (§B11). `pad_burst` pads the marshalled
  buffer so the trailing wire segment lands on a length sampled from
  `length_dist`. `IAT::Paranoid` additionally sources each chunk size
  from `length_dist`. `poll_shutdown` clears pending IAT delays so
  streams close promptly. H3 handshake fix is untouched.

### Fixed

- **obfs4**: handshake over-read into the data decode buffer. Over a
  real TCP socket the server's hello and the first data frame(s)
  coalesce into one segment, so the handshake read returned extra
  bytes belonging to the data stream. Those bytes had `PrngSeed`
  decoded out of them and the rest was dropped, leaving the data
  decoder one frame short of where the stream actually was — the
  decoder then read a garbage length field and aborted with
  `"invalid frame length out of range"`, tearing the tunnel down
  mid-transfer (seen downstream as os error 10054/10053). In-memory
  `duplex` tests hid this because they preserve write boundaries.
  `O4Stream::new` now takes the post-handshake residual and seeds it
  into the `Framed` read buffer via `read_buffer_mut()`; the client
  passes `remainder`, the server passes empty. Tested with a 3 MiB
  real-TCP loopback transfer plus a 1-byte-at-a-time codec bisect.

- **obfs4**: graceful `decode_eof` instead of `"bytes remaining on
  stream"`. tokio_util's default `decode_eof` raises a hard IO error
  whenever the peer closes the connection with bytes still buffered
  that do not form a complete frame. For obfs4 that is a normal
  end-of-stream — the peer closes the TCP socket leaving a truncated
  trailing frame or inter-frame padding behind. The codec now drains
  any complete frame still buffered and reports a clean EOF
  (`Ok(None)`) rather than an error arti surfaces as unexpected-EOF
  and uses to tear the channel (and its circuits) down mid-bootstrap.
  Four tests cover the common shapes: clean boundary, partial-only,
  complete + partial tail, and N>1 complete + partial tail.

- **lyrebird**: TCP keepalive + `TCP_NODELAY` on the bridge dial. The
  outgoing obfs4 carrier was a bare `TcpStream::connect` with no
  socket options. An idle carrier (e.g. while a one-hop directory
  circuit for a bridge descriptor is being built) was reaped — seen
  as os error 10053 ("connection aborted by the software in your
  host machine") and tore the bridge channel down mid-bootstrap.
  Adds TCP keepalive (15s) and `TCP_NODELAY` via socket2 (already
  in-tree through tokio). Effect in testing: connection resets during
  bootstrap dropped sharply (10054 7→1, 10053 5→1 over a comparable
  window). Two compliance tests guard the silent regression where a
  `set_*` line disappears.

- **obfs4**: `Client::establish` now generates the elligator2-
  representable ephemeral key BEFORE awaiting the stream future (TCP
  dial), closing upstream issue jmwample/ptrs#15. The elligator2
  retry loop succeeds with ~50% probability per iteration, so doing
  keygen after the dial inserted a variable, network-observable gap
  between TCP handshake and the first obfs4 byte that a censor could
  fingerprint. The dial-keygen order invariant is locked in by an
  order-asserting test (§D1a).

- **obfs4**: `pad_burst` no longer emits over-sized padding frames
  that the codec rejects. The previous implementation followed a
  flawed upstream sketch: a single padding frame whose zero-fill was
  `pad_len - MESSAGE_OVERHEAD`. When `pad_len` was close to
  `MAX_SEGMENT_LENGTH` (≈1430–1447 bytes) the resulting `pad_bytes`
  exceeded `MAX_MESSAGE_PAYLOAD_LENGTH - 1` and `build_and_marshall`
  returned `Invalid payload length`. The new implementation is a loop
  that splits the requested padding into one or more frames of at
  most `MAX_MESSAGE_PAYLOAD_LENGTH - 1` padding bytes, with guards
  for the two unexpressible-remainder cases. The doc comment is
  rewritten to reflect this. Bug only surfaced with
  `iat-mode ∈ {1, 2}` (default is `0/Off`). Covered exhaustively
  (§F: enumerate, don't sample) for every `target ∈ 0..MAX_SEGMENT_LENGTH`
  across a representative cross-section of starting tails, plus an
  inverse round-trip through `Messages::try_parse` (§F4).

### Changed

- **obfs4**: bumped `tor-cell` / `tor-llcrypto` / `tor-error` /
  `tor-bytes` from 0.25.0 to 0.43.0 — the current arti dependency
  cluster head. The consumed surface (Sha256/Shake256, RsaIdentity,
  SecretBuf, error types, into_internal, Writer/EncodeResult,
  RSA_ID_LEN) is API-stable across that range, so no obfs4 source
  changes were needed beyond the version pins themselves.
- **all crates**: declared MSRV raised from **1.88 to 1.89**. Required
  by `tor-*` 0.40+. The per-manifest `rust-version` and the CI `MSRV`
  job (now `MSRV (1.89)`) move together.
- **obfs4**: removed `tor-basic-utils` dev-dependency. Its 0.43 release
  exports `TestingRng` built on `rand_core 0.9`, incompatible with the
  workspace's `rand 0.8` (`rand_core 0.6`, pinned by `x25519-dalek
  2.0.1`). Tests that used `testing_rng()` now use `rand::thread_rng()`
  — the RNG is only used for key generation, the assertions don't
  depend on determinism. A migration to `rand 0.9` is blocked on a
  stable `x25519-dalek 3.0` (currently 3.0.0-rc.1) and tracked
  separately.
- **core**: bumped `itertools` from 0.13.0 to 0.14.0 (MSRV 1.63.0, no
  API breakage on the consumed surface). Held at 0.14.0 rather than
  0.15.0 on purpose: `tor-cell 0.43.0` still pins `itertools ^0.14.0`,
  so matching that version de-duplicates the dependency tree.

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
