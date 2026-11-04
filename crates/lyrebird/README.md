# ptrs-gesher-lyrebird

<p>
  <a href="https://crates.io/crates/ptrs-gesher-lyrebird">
    <img src="https://img.shields.io/crates/v/ptrs-gesher-lyrebird.svg">
  </a>
  <a href="https://docs.rs/ptrs-gesher-lyrebird">
    <img src="https://docs.rs/ptrs-gesher-lyrebird/badge.svg">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

> **Server-side is experimental and incomplete — do not run in production.**
> The bridge-side (`ServerTransportPlugin`) code path is gated behind the
> `experimental-server` cargo feature, is not built by default, and panics
> with `unimplemented!` at connection time. The PT handshake is not wired
> and there is no ExtORPort dial. Enable it only for development. The client-side
> (`ClientTransportPlugin`) path is usable today.

PT-manager loop for Tor pluggable transports. Usable as a library
(`lyrebird::run_from_env()`) or as a standalone binary. Dispatches `obfs4` and
`webtunnel` transports over the Tor PT protocol (SOCKS5 on the client
side, Extended ORPort on the server side).

## Status

The current crate requires Rust 1.92 or newer. See the
[migration guide](https://github.com/PHPCraftdream/ptrs-gesher/blob/v0.6.0/docs/MIGRATING-0.6.md).

The interface remains subject to change. Not production ready; do not rely on this for security-critical
applications.

For embedding, set the managed-transport environment and call
`lyrebird::run_from_env().await`. This preserves the application's arguments,
tracing subscriber and safelog policy. The existing `lyrebird::run()` entry point
parses standalone CLI options and configures its logging policy. The binary
supports only the options shown below; it does not provide a general-purpose
configuration-file interface.

## Usage (binary)

```txt
Tunnel Tor SOCKS5 traffic through pluggable transport connections

Usage: lyrebird [OPTIONS]

Options:
      --enable-logging         Log to {TOR_PT_STATE_LOCATION}/obfs4proxy.log
      --log-level <LOG_LEVEL>  Log Level (ERROR/WARN/INFO/DEBUG/TRACE) [default: ERROR]
      --unsafe-logging         Disable the address scrubber on logging
  -h, --help                   Print help
  -V, --version                Print version
```

Client side torrc configuration:

```
ClientTransportPlugin obfs4 exec /usr/local/bin/lyrebird
```

Bridge side torrc configuration:

```
# Act as a bridge relay.
BridgeRelay 1

# Enable the Extended ORPort
ExtORPort auto

# Use lyrebird to provide the obfs4 protocol.
ServerTransportPlugin obfs4 exec /usr/local/bin/lyrebird

# (Optional) Listen on the specified address/port for obfs4 connections.
#ServerTransportListenAddr obfs4 0.0.0.0:443
```

## Usage (library)

```text
Embed the PT-manager loop in your own async application:

lyrebird::run_from_env().await?;
```

Call this from an async context after setting the managed-transport environment.

## Proxy protocols

Each managed client listener accepts both SOCKS5 and HTTP CONNECT on its existing
loopback socket. PT control announcements still advertise `socks5` for Tor/Arti
compatibility. These are transport-control listeners: RFC 1929 or HTTP Basic
credential fields carry per-bridge PT arguments, not application user accounts.
Parsing never opens a plain relay or sends success before the PT handshake.
If the transport or upstream proxy cannot be established, the parent receives a
failure reply (SOCKS5 REP=4 or HTTP 502) instead of a bare close.
HTTP pipeline bytes are forwarded once, before unread bytes from the socket.
Bridge-side transport sockets are not HTTP proxy listeners and are unchanged.

`TOR_PT_PROXY` supports `socks5://IP:port` and `http://IP:port`, with optional
percent-encoded `username:password@` user information. Proxy endpoints must be
IP literals; destination hostnames are passed to the proxy without local DNS.
Unsupported configuration fails before listeners are announced. A configured
proxy error never selects a direct carrier. WebTunnel TLS and its HTTP upgrade
run unchanged over the proxy-supplied stream.

HTTP CONNECT and SOCKS5 authentication do not encrypt their credential-bearing
hop. HTTPS-to-proxy is not enabled by this interface. The upstream protocol
implementation comes from `resocks5-net` 0.4.1; no separate SOCKS/HTTP client
parser is maintained here.

## License

Dual-licensed under either:

- Apache License, Version 2.0
- MIT license

at your option.
