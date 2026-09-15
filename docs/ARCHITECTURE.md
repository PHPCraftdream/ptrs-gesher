# Architecture

This document describes the internal structure of the `ptrs-gesher`
workspace, the data flow for each transport, and where to look when
adding a new one.

## Crate DAG

Workspace crates and their internal (Cargo `path`) dependencies:

| Crate            | Depends on                                                  |
|------------------|------------------------------------------------------------|
| `ptrs-gesher`    | core, obfs4, webtunnel, bridge-line, lyrebird (all optional) |
| `lyrebird`       | core, obfs4, webtunnel                                     |
| `obfs4`          | core                                                       |
| `webtunnel`      | core                                                       |
| `bridge-line`    | *(standalone)*                                             |
| `core`           | *(standalone)*                                             |

`ptrs-gesher` is the umbrella crate: it re-exports the others, each behind an
optional feature. `core` is published as `ptrs-gesher-core` and consumed
internally as `ptrs`. `bridge-line` and `core` have no in-workspace
dependencies.

## Client data flow (obfs4)

| # | Stage | What happens |
|---|-------|--------------|
| 1 | SOCKS5 client | parent (arti/tor) opens a SOCKS5 connection |
| 2 | lyrebird (SOCKS5 accept loop) | extracts PT args from the SOCKS5 username/password |
| 3 | `ClientBuilder::options(&args)` | parses `cert=` / `iat-mode=` into `station_pubkey` + `station_id` |
| 4 | `ClientTransport::establish(tcp_future)` | generates the ephemeral key before TCP connect, then performs the ntor handshake |
| 5 | `Obfs4Codec` framed tunnel (`AsyncRead` + `AsyncWrite`) | XSalsa20-Poly1305 encryption, optional IAT padding |
| 6 | Tor relay (via the bridge's ORPort) | — |

## Server data flow (obfs4)

The obfs4 library supports server handshakes through `ServerBuilder`. The table
below shows the intended PT-manager integration: Lyrebird's
`experimental-server` path remains incomplete, with the transport handshake and
ORPort forwarding not yet wired into its connection handler.

| # | Stage | What happens |
|---|-------|--------------|
| 1 | TCP listener (bound to `ServerTransportListenAddr`) | accepts inbound bridge connections |
| 2 | lyrebird (server accept loop) | accepts the TCP connection |
| 3 | `ServerTransport::reveal(tcp_stream)` | waits for the client ntor handshake, derives the shared key |
| 4 | `Obfs4Codec` framed tunnel (`AsyncRead` + `AsyncWrite`) | bidirectional copy to the ORPort |
| 5 | Tor ORPort / Extended ORPort | — |

## WebTunnel data flow

| # | Stage | What happens |
|---|-------|--------------|
| 1 | TCP connect to URL `host:port` (or `addr=` override) | dial the bridge front |
| 2 | TLS handshake (tokio-rustls, no ALPN) | SNI = `servername=` or the URL hostname |
| 3 | HTTP/1.1 Upgrade request | `GET <path> HTTP/1.1`, `Upgrade: websocket`, `Connection: Upgrade` |
| 4 | Server responds `101 Switching Protocols` | — |
| 5 | Raw bidirectional byte stream | no WebSocket framing — just bytes |
| 6 | Tor relay (via the bridge's ORPort) | — |

Builder clones share lazy DNS and TLS state within their client context. DNS
resolution and address attempts share the handshake deadline; earlier address
attempts are bounded so later addresses can be tried. TLS session resumption is
disabled when reusing the immutable client configuration.

## Where to add a new transport

1. **Create a new crate** under `crates/<name>/` depending on
   `ptrs-gesher-core`.
2. **Implement the core traits** for your transport:
   - `PluggableTransport<InRW>` — provides `ClientBuilder` and
     `ServerBuilder` types.
   - `ClientBuilder<InRW>` — parses transport-specific args via
     `options(&Args)`.
   - `ClientTransport<InRW, InErr>` — `establish()` and `wrap()` return
     a pinned future that yields the tunnel stream.
   - `ServerBuilder<InRW>` and `ServerTransport<InRW>` — mirror of the
     client side.
3. **Add a feature flag** to `crates/ptrs-gesher/Cargo.toml`.
4. **Register in lyrebird** — add a match arm in
   `lyrebird::client_setup` that dispatches on your transport name and
   creates a builder + listener for it.
5. **Add tests** — E2E tests under `tests/`, property tests under
   `tests/proptest_*.rs` or `tests/fuzz_*.rs`.
6. **Add an example** — see `examples/` (top-level) and
   `crates/*/examples/` for templates. A new transport should ship at
   least a minimal demonstration so users know how to wire it up.

## Test layout

| Location                              | Kind                | Runs on        |
|---------------------------------------|---------------------|----------------|
| `crates/*/src/**/*.rs` (`#[cfg(test)]`) | Unit tests         | `cargo test`   |
| `crates/*/tests/e2e_*.rs`             | End-to-end handshake + data path | `cargo test` |
| `crates/*/tests/proptest_*.rs`        | Property-based tests (proptest)  | `cargo test` |
| `crates/*/tests/fuzz_*.rs`            | 10k-iteration fuzz-like proptest | `cargo test --release` recommended |
| `crates/*/benches/*.rs`               | Criterion benchmarks | `cargo bench` |
