
# ptrs-gesher-core

<p>
  <a href="https://crates.io/crates/ptrs-gesher-core">
    <img src="https://img.shields.io/crates/v/ptrs-gesher-core.svg">
  </a>
  <a href="https://docs.rs/ptrs-gesher-core">
    <img src="https://docs.rs/ptrs-gesher-core/badge.svg">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

Core traits and helpers for the
[ptrs-gesher](https://github.com/PHPCraftdream/ptrs-gesher) pluggable
transports framework.

This crate defines the transport-agnostic abstractions that every
concrete transport (`obfs4`, `webtunnel`, etc.) implements:

- `ClientTransport` / `ServerTransport` -- connection-oriented trait
  pair that transforms an `AsyncRead + AsyncWrite` stream into an
  obfuscated tunnel.
- `ClientBuilder` / `ServerBuilder` -- configuration and construction
  of transport instances from key-value `Args`.
- `PluggableTransport` -- top-level trait tying builders and
  transports together.
- `Args` -- ordered multimap for PT parameters (`cert=`, `iat-mode=`,
  etc.).

## Status

Version `0.6.0` requires Rust 1.89 or newer. See the
[migration guide](https://github.com/PHPCraftdream/ptrs-gesher/blob/v0.6.0/docs/MIGRATING-0.6.md)
for the separate SOCKS and SMETHOD argument formats.

## Example

```rust ignore
use ptrs::Args;
use obfs4;

let mut args = Args::new();
args.add("cert", "AAAA...");
args.add("iat-mode", "0");

let builder = obfs4::ClientBuilder::from_params(vec![args.encode_client_parameters().into_bytes()])?;
let client = builder.try_build()?;
// client.establish(...) or client.wrap(...) to create the tunnel.
```

## Notes / Resources

- [Pluggable Transport Specification (up to 3.0)](https://github.com/Pluggable-Transports/Pluggable-Transports-spec)
- [PT Spec v1](https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt)
- [Extended ORPort](https://gitweb.torproject.org/torspec.git/tree/proposals/196-transport-control-ports.txt)
- [Tor Extended ORPort Auth](https://gitweb.torproject.org/torspec.git/tree/proposals/217-ext-orport-auth.txt)

## License

Dual-licensed under either:

- Apache License, Version 2.0
- MIT license

at your option.
