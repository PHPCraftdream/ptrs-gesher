# Contributing to ptrs-gesher

Thank you for your interest in contributing! This document covers the
practicalities of building, testing, and submitting changes.

## Building

```sh
cargo build --workspace
```

The workspace requires stable Rust ≥ 1.75.

## Testing

```sh
# Unit + integration tests.
cargo test --workspace

# Recommended for proptest / fuzz-like files (10k iterations).
cargo test --workspace --release
```

## Benchmarking

```sh
cargo bench --workspace
```

HTML reports are written to `target/criterion/`.

## Examples

Each crate ships minimal smoke examples under `crates/*/examples/`.
Longer, end-to-end demonstrations live in the top-level
`ptrs-gesher-examples` crate. Run any of them with:

```sh
cargo run -p ptrs-gesher-examples --example obfs4_echo_over_tcp
cargo run -p ptrs-gesher-examples --example dispatch_bridge
cargo run -p ptrs-gesher-examples --example bridge_line_to_obfs4_client
cargo run -p ptrs-gesher-examples --example args_roundtrip_table
cargo run -p ptrs-gesher-examples --example embed_lyrebird --features embed-lyrebird
```

`cargo build --workspace --examples` is enforced by CI, so adding an
`[[example]]` makes it a public-API regression catcher.

## Code style

- **Formatting:** `cargo fmt` — CI checks `cargo fmt --all -- --check`.
- **Linting:** `cargo clippy --all-targets -- -D warnings` — CI enforces
  this.
- **No trivial tests:** Do not submit tests that merely exercise derived
  traits, getters/setters, assert `is_ok()`/`is_some()` without
  asserting the inner value, or check that `format!(…)` doesn't panic
  without verifying the output. Every test must exercise non-trivial
  logic or an error path and make a concrete assertion.

## CHANGELOG

If your change is user-visible, add an entry under the `[Unreleased]`
heading in `CHANGELOG.md` (see existing entries for the format).

## License

By submitting a patch you agree to license it under both the **MIT** and
**Apache-2.0** licenses (dual-licensed, matching the rest of the
project).
