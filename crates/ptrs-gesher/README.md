# ptrs-gesher

<p>
  <a href="https://crates.io/crates/ptrs-gesher">
    <img src="https://img.shields.io/crates/v/ptrs-gesher.svg">
  </a>
  <a href="https://docs.rs/ptrs-gesher">
    <img src="https://docs.rs/ptrs-gesher/badge.svg">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

Umbrella crate that re-exports the entire `ptrs-gesher` pluggable
transports framework behind a single dependency.

## What this crate does

`ptrs-gesher` is the single-dependency entry point for the
[ptrs-gesher](https://github.com/PHPCraftdream/ptrs-gesher) framework.
It re-exports core types (`Args`, `ClientBuilder`, `ClientTransport`,
`BridgeLine`, `Obfs4PT`, `WebTunnelBuilder`) at the top level for
convenience, and also exposes the underlying crate modules (`ptrs`,
`obfs4`, `webtunnel`, `bridge_line`, `lyrebird`) for deeper access.

### Feature flags

| Flag           | Default | What it pulls in                           |
|----------------|---------|--------------------------------------------|
| `obfs4`        | **on**  | `ptrs-gesher-obfs4` — obfs4 transport      |
| `webtunnel`    | **on**  | `ptrs-gesher-webtunnel` — WebTunnel        |
| `bridge-line`  | **on**  | `ptrs-gesher-bridge-line` — bridge parser  |
| `lyrebird`     | off     | `ptrs-gesher-lyrebird` — PT-manager loop   |

## Status

Version `0.1.0` — not yet published to crates.io. Interface subject to
change. Not production ready; do not rely on this for security-critical
applications.

## Example

```rust ignore
use ptrs_gesher::{Args, BridgeLine, Obfs4PT, PluggableTransport};
use ptrs::ClientBuilder as _;

// Parse a torrc bridge line.
let bridge: BridgeLine =
    "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
    .parse()
    .unwrap();
assert_eq!(bridge.transport.as_deref(), Some("obfs4"));

// Convert its key=value params into Args for the transport builder.
let mut args = Args::new();
for (k, v) in &bridge.params {
    args.add(k, v);
}

// Look up the transport name.
assert_eq!(Obfs4PT::name(), "obfs4");
```

## License

Dual-licensed under either:

- Apache License, Version 2.0
- MIT license

at your option.
