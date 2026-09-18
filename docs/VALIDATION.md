# Local interoperability and release checks

The bounded interoperability runner uses the pinned Go reference implementation
at commit `c3e2d44b1033e03645cc971565175e56d86a8200` ([upstream source](https://gitlab.com/yawning/obfs4/-/tree/c3e2d44b1033e03645cc971565175e56d86a8200)). The module pseudo-version and checksums are recorded in `tools/interop/go/go.mod` and `go.sum`. It performs one loopback
connection for each IAT mode in each direction, exchanges a bounded 4 KiB
request/reply, and runs one malformed-reply check. It is a wire-compatibility
check, not a benchmark or a public bridge test.

The malformed-reply fixture uses the same valid pinned server certificate and
confirms that the Rust peer sends a hello before the invalid reply. Prerequisites
are Rust/Cargo, Python 3.9 or newer, Go 1.20 or newer, and network access for
the pinned Go module on the first run. Run from the repository root:

```text
python tools/interop/run.py
```

Every child process is deadline-bound and owned by the runner; its temporary
state and binaries are removed on exit. A failed handshake or an expired
process deadline fails the command. `--rust-bin` can use an already-built
example for an integration run; that mode reports the skipped build as
incomplete verification.

The local release gates resolve the repository root from the script path and
are separate from publication. They never publish, tag, change versions, or
rewrite `Cargo.lock`; Cargo uses `-j2` by default and each declared non-default
feature is checked:

```text
python .github/scripts/release-check.py
```

The release gate requires `cargo-deny` and `cargo-semver-checks`. Use
`--skip-deny` or `--skip-semver` only when recording an explicitly incomplete
local result. The release workflow uses Trusted Publishing; the one-time
per-crate settings and GitHub environment are listed in [RELEASING.md](RELEASING.md).
Release checks accept `--root` so updated automation can validate the immutable
source checkout, and use the baseline version recorded in workspace metadata.

## Recovery API changes

`WebTunnelClient::wrap` and `establish` now use the supplied carrier. Managed
clients that intend to dial the `url=` endpoint must call `connect_url()`.
Bind addresses apply to URL dialing; supplying them with an existing carrier
returns an unsupported-operation error. Existing TCP stream type annotations
remain valid through the default parameter of `WebTunnelStream<S>`.

`Args::from_str` and `parse_client_parameters` parse SOCKS parameters separated
by semicolons. Pair them with `encode_client_parameters`. Use
`parse_smethod_args` and `encode_smethod_args` for comma-separated SMETHOD
arguments. A comma inside a SOCKS URL remains part of that URL.

Prefer obfs4 builders' `try_build`, `ServerBuilder::try_node_keys`, and
`Client::try_get_args` when configuration errors must be handled immediately.
The existing infallible methods retain configuration errors and reject a
subsequent handshake before dialing. Unsupported bind operations return errors.
`Server::new_from_statefile_at` and `write_statefile_to` provide explicit state
file operations; the old parameterless/static stubs report unsupported use.

Server directories contain `obfs4_state.json`; client directories use
`obfs4_client_state.json`. Manually configured fields override their matching
state-file fields. Importing a server state file as client configuration does
not rewrite the server identity. State replacement uses a unique temporary
file and atomic replacement, with private file permissions on Unix.

Transport names now follow `[A-Za-z_][A-Za-z0-9_]*`. Displaying a transport
named `Bridge` adds the explicit directive prefix needed to parse it again.
