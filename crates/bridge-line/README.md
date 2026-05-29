# ptrs-gesher-bridge-line

<p>
  <a href="https://crates.io/crates/ptrs-gesher-bridge-line">
    <img src="https://img.shields.io/crates/v/ptrs-gesher-bridge-line.svg">
  </a>
  <a href="https://docs.rs/ptrs-gesher-bridge-line">
    <img src="https://docs.rs/ptrs-gesher-bridge-line/badge.svg">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

Transport-agnostic parser for Tor `Bridge` directive lines found in
`torrc` configuration files.

## What this crate does

`ptrs-gesher-bridge-line` parses the standard torrc `Bridge` directive
format into a structured `BridgeLine` type with fields for the transport
name, ORPort address, RSA fingerprint, and key-value parameters. The
parser is transport-agnostic — it does **not** validate the contents of
`cert=`, `url=`, or any other transport-specific parameter.

The parsed `BridgeLine` implements `Display` and `FromStr`, so it
round-trips through its string representation exactly. This makes it
suitable for both config-file parsing and generating bridge lines for
distribution.

The crate has **zero dependencies** beyond `thiserror` — it can be used
standalone without pulling in the rest of the `ptrs-gesher` framework.

## Status

Version `0.2.0` — not yet published to crates.io. Interface subject to
change.

## Example

```rust ignore
use bridge_line::BridgeLine;

// Parse an obfs4 bridge line with certificate and IAT mode.
let obfs4_line = "obfs4 65.108.147.195:8089 DFF8DBF20F8980C4B74EDBAA9695104D613978CE cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA iat-mode=0";
let bridge: BridgeLine = obfs4_line.parse().unwrap();
assert_eq!(bridge.transport.as_deref(), Some("obfs4"));
assert_eq!(bridge.params.get("iat-mode").map(String::as_str), Some("0"));
println!("parsed: {bridge:#?}");

// Parse a plain (non-PT) bridge line.
let plain: BridgeLine = "192.0.2.3:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01".parse().unwrap();
assert!(plain.transport.is_none());
println!("plain bridge: {plain}");

// Display round-trips: parse(output) == original.
let rendered = bridge.to_string();
let roundtrip: BridgeLine = rendered.parse().unwrap();
assert_eq!(bridge, roundtrip);
```

## License

Dual-licensed under either:

- Apache License, Version 2.0
- MIT license

at your option.
