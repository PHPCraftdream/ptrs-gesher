# Architecture

This document describes the internal structure of the `ptrs-gesher`
workspace, the data flow for each transport, and where to look when
adding a new one.

## Crate DAG

```
                    ┌──────────────┐
                    │ ptrs-gesher  │  (umbrella re-exports)
                    └──────┬───────┘
                           │
          ┌────────┬───────┼───────┬────────┐
          ▼        ▼       ▼       ▼        ▼
      ┌───────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌────────┐
      │ core  │ │obfs4│ │ WT  │ │ BL  │ │lyrebird│
      │(ptrs) │ │     │ │     │ │     │ │        │
      └───┬───┘ └──┬──┘ └──┬──┘ └─────┘ └───┬────┘
          │        │       │              ┌──┼──┐
          │        │       │              │  ▼  │
          │        │       │          ┌───────┐ │
          │        │       │          │ core  │ │
          │        │       │          └───────┘ │
          │        │       │          ┌─────┐   │
          │        │       │          │obfs4│   │
          │        │       │          └─────┘   │
          │        │       │          ┌─────┐   │
          │        │       │          │ WT  │   │
          │        │       │          └─────┘   │
          │        │       │          ┌─────┐   │
          │        │       │          │ BL  │   │
          │        │       │          └─────┘   │
          │        │       │          └─────────┘
          ▼        ▼       ▼
       (standalone — no ptrs-gesher deps below this line)

  core = ptrs-gesher-core       WT  = ptrs-gesher-webtunnel
  obfs4 = ptrs-gesher-obfs4     BL  = ptrs-gesher-bridge-line
  lyrebird = ptrs-gesher-lyrebird
```

**Dependency edges (Cargo `path` deps):**

| Crate            | Depends on                            |
|------------------|---------------------------------------|
| `ptrs-gesher`    | core, obfs4, webtunnel, bridge-line, lyrebird (all optional) |
| `lyrebird`       | core, obfs4, webtunnel                |
| `obfs4`          | core                                  |
| `webtunnel`      | core                                  |
| `bridge-line`    | *(standalone)*                        |
| `core`           | *(standalone)*                        |

## Client data flow (obfs4)

```
  SOCKS5 client
       │
       ▼
  lyrebird (SOCKS5 accept loop)
       │  extracts PT args from SOCKS5 username/password
       ▼
  ClientBuilder::options(&args)
       │  parses cert= / iat-mode= into station_pubkey + station_id
       ▼
  ClientTransport::establish(tcp_future)
       │  awaits TCP connect, then performs ntor handshake
       ▼
  Obfs4Codec framed tunnel (AsyncRead + AsyncWrite)
       │  XSalsa20Poly1305 encryption, optional IAT padding
       ▼
  Tor relay (via the bridge's ORPort)
```

## Server data flow (obfs4)

Mirror of the client flow, but entry is via `ServerBuilder`:

```
  TCP listener (bound to ServerTransportListenAddr)
       │
       ▼
  lyrebird (server accept loop)
       │  accepts TCP connection
       ▼
  ServerTransport::reveal(tcp_stream)
       │  waits for client ntor handshake, derives shared key
       ▼
  Obfs4Codec framed tunnel (AsyncRead + AsyncWrite)
       │  bidirectional copy to the ORPort
       ▼
  Tor ORPort / Extended ORPort
```

## WebTunnel data flow

```
  TCP connect to url host:port (or addr= override)
       │
       ▼
  TLS handshake (tokio-rustls, no ALPN)
       │  SNI = servername= or URL hostname
       ▼
  HTTP/1.1 Upgrade request
       │  GET <path> HTTP/1.1
       │  Upgrade: websocket
       │  Connection: Upgrade
       ▼
  Server responds 101 Switching Protocols
       │
       ▼
  Raw bidirectional byte stream
       │  (no WebSocket framing — just bytes)
       ▼
  Tor relay (via the bridge's ORPort)
```

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
