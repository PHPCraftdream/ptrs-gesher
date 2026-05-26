# ptrs-gesher

<p>
  <a href="https://crates.io/crates/ptrs-gesher">
    <img src="https://img.shields.io/crates/v/ptrs-gesher.svg" alt="crates.io">
  </a>
  <a href="https://docs.rs/ptrs-gesher">
    <img src="https://docs.rs/ptrs-gesher/badge.svg" alt="docs.rs">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/PHPCraftdream/ptrs-gesher/ci.yml?branch=main" alt="CI">
  </a>
  <a href="https://codecov.io/gh/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/codecov/c/github/PHPCraftdream/ptrs-gesher" alt="Codecov">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

Pluggable Transports framework for Rust. Tor-compatible bridges with `obfs4`
and `webtunnel` transports, a reusable PT-manager loop (`lyrebird`), and a
torrc-format bridge-line parser. Forked from
[`jmwample/ptrs`](https://github.com/jmwample/ptrs) and developed
independently.

The name comes from גשר *gesher*, Hebrew for "bridge" — fitting both the
domain (anti-censorship bridges) and the fork relationship with the upstream
project.

## Crates

| Crate | Description |
|---|---|
| [`ptrs-gesher`](./crates/ptrs-gesher) | Umbrella crate re-exporting the rest. |
| [`ptrs-gesher-core`](./crates/core) | Core traits: `ClientBuilder`, `ClientTransport`, `Args`. |
| [`ptrs-gesher-obfs4`](./crates/obfs4) | obfs4 transport. |
| [`ptrs-gesher-webtunnel`](./crates/webtunnel) | WebTunnel transport — TLS + HTTP/1.1 Upgrade. |
| [`ptrs-gesher-lyrebird`](./crates/lyrebird) | PT-manager loop; usable as a library (`lyrebird::run()`) or as a binary. |
| [`ptrs-gesher-bridge-line`](./crates/bridge-line) | torrc `Bridge` directive parser, transport-agnostic. |

All crates are dual-licensed `MIT OR Apache-2.0`.

## Source compatibility with `jmwample/ptrs`

Cross-crate dependencies use Cargo's `package =` rename so consumers continue
to `use ptrs::...`, `use obfs4::...`, etc. — no source-code migration is
needed when moving from `jmwample/ptrs` to `ptrs-gesher`. Adjust only the
`Cargo.toml`:

```toml
[dependencies]
ptrs    = { package = "ptrs-gesher-core",   version = "0.1" }
obfs4   = { package = "ptrs-gesher-obfs4",  version = "0.1" }
webtunnel = "ptrs-gesher-webtunnel"  # new, no upstream equivalent
```

## Differences from upstream

| Change | Why |
|---|---|
| New crate `ptrs-gesher-webtunnel` | Adds WebTunnel transport — TLS + HTTP/1.1 Upgrade, no WebSocket framing. |
| `lyrebird` refactored: `lib.rs` with `pub async fn run()` + thin `main.rs` | Lets parent applications embed the PT loop in-process (busybox-style PT dispatch). |
| `lyrebird::client_setup` dispatches by transport name (`obfs4` / `webtunnel`) | Single PT-manager process serves multiple transports. |
| Dropped: `o5`, `o7`, lyrebird `fwd/` forward-proxy binary | Upstream-WIP / scope unrelated to bridge transport. |
| New crate `ptrs-gesher-bridge-line` | torrc bridge-line parser usable by the transports themselves. |

## Status

- Workspace builds on stable Rust ≥ 1.75.
- 279 tests passing (E2E, property-based, fuzz-like × 10k iterations).
- Not yet published to crates.io; targeting 0.1.0.
- **Interoperability with reference `obfs4proxy` (Go) and the
  WebTunnel reference server has not been smoke-tested at this point.**

## Quickstart

```rust ignore
use ptrs_gesher::{Args, BridgeLine};
use ptrs::ClientBuilder;

// Parse a torrc bridge line:
let bridge: BridgeLine =
    "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=… iat-mode=0"
    .parse()?;

// Convert its key=value params into Args:
let mut args = Args::new();
for (k, v) in &bridge.params { args.add(k, v); }

// Build the obfs4 client:
let mut builder = obfs4::ClientBuilder::default();
builder.options(&args)?;
let client = builder.build();
// client.establish(tcp_future).await yields an AsyncRead+AsyncWrite tunnel.
```

## Threat model — what this protects, what it does not

- **Goal:** make Tor traffic look like something other than Tor to a
  censoring middlebox doing DPI.
- **Not goals:** strong anonymity (that is Tor's job, not the PT's);
  protection against an attacker who controls the bridge; protection
  against traffic-analysis with full visibility of both endpoints.
- A pluggable transport is one obfuscation layer; full security
  requires running Tor on top of it.

## Security

To report a security issue, see `SECURITY.md`.

## Testing

- `cargo test --workspace` — unit + integration tests.
- `cargo test --workspace --release` — recommended for the
  10k-iteration fuzz-like proptest files.
- `cargo bench --workspace` — Criterion benchmarks (HTML reports
  under `target/criterion/`).

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. See [NOTICE](NOTICE) for upstream attribution.
