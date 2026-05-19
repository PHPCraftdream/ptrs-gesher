# ptrs-gesher

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

## License

Dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. See [NOTICE](NOTICE) for upstream attribution.
