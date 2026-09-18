# Migrating from 0.5.x to 0.6.0

All six crates move to 0.6.0 together. Update their dependency requirements;
the Rust minimum stays at 1.89. The old crate aliases (`ptrs`, `obfs4`,
`webtunnel`) remain usable through Cargo's `package` rename.

## WebTunnel carrier and URL dialing

`wrap(carrier)` performs TLS/Upgrade over that carrier. `establish(dial)` awaits
and uses the supplied dial future; its errors and deadline are observable.
Neither method opens a substitute URL connection.

For a direct connection to `url=`, use the explicit method:

```rust,ignore
let tunnel = webtunnel_client.connect_url().await?;
```

For a supplied carrier, retain that carrier in the output type:

```rust
use ptrs::ClientTransport;
use tokio::io::DuplexStream;
use webtunnel::{PrefixStream, WebTunnelClient, WebTunnelStream};

fn use_wrapped_carrier(
    stream: <WebTunnelClient as ClientTransport<DuplexStream, std::io::Error>>::OutRW,
) -> PrefixStream<WebTunnelStream<DuplexStream>> {
    stream
}
```

The default `WebTunnelStream` type still means `WebTunnelStream<TcpStream>`.
Keeping that default for a different carrier no longer compiles. This is an
intentional breaking change that automated semver checks did not detect.
IPv4/IPv6 bind settings apply to `connect_url()`; remove them when passing an
already routed carrier. Lyrebird's managed client has already been migrated.

## Transport arguments and bridge names

Use the matching parse/encode pair for each format:

| Format | Separator | Parse | Encode |
|---|---|---|---|
| SOCKS/client | `;` | `Args::parse_client_parameters` / `FromStr` | `encode_client_parameters` |
| SMETHOD | `,` | `Args::parse_smethod_args` | `encode_smethod_args` |

To pass the result of `ServerBuilder::client_params()` to SOCKS authentication:

```rust,ignore
let smethod_args = server_builder.try_client_params()?;
let socks_args = ptrs::args::Args::parse_smethod_args(&smethod_args)?
    .encode_client_parameters();
```

A comma inside a SOCKS URL is ordinary data. A semicolon inside SMETHOD is also
ordinary data; do not split either string with a universal separator parser.
Transport names must follow `[A-Za-z_][A-Za-z0-9_]*`. A transport literally named
`Bridge` serializes with an additional `Bridge` directive for round-trip safety.

## Configuration errors and persisted state

Prefer `try_build`, `try_node_keys`, `try_client_params`, `try_statefile_path`
and `Client::try_get_args` when the caller should handle errors immediately.
Existing infallible build/get-args methods defer errors until handshake instead
of silently accepting invalid configuration. The legacy static server state
stubs return unsupported; use `new_from_statefile_at` and `write_statefile_to`.

Server state directories use `obfs4_state.json`; client state directories use
`obfs4_client_state.json`. Client import of a server state file is read-only.
Explicit field overrides preserve the remaining loaded state, and advertised
server parameters share the same effective configuration as `build`.
Both numeric Go IAT values and legacy string values are accepted.

State replacement uses a unique temporary file and atomic rename, with private
Unix permissions. Unix directory sync completes durability confirmation;
Windows directory-entry durability remains limited by platform support.
After a post-publication sync error, retry the same builder to retain its
identity and outstanding durability operation. External state writers are not
protected by a cross-process compare-and-swap protocol.

Unsupported obfs4 bind operations and WebTunnel persistent-state configuration
now return errors; callers must handle them instead of assuming the setters
took effect. The experimental managed server remains unfinished and disabled
by default.
