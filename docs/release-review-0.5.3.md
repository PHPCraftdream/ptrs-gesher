# Release review: 0.5.3

This review covers handshake deadlines, buffered transport data, DNS/TLS setup,
connection admission, dependency updates, and the published API. It is a focused
review of these paths, not an audit of every subsystem.

## Findings and fixes

| Finding | Resulting behavior | Regression evidence |
|---|---|---|
| obfs4 converted absolute deadlines into durations at builder creation | The same deadline bounds delayed use and dialing; expired deadlines fail immediately | Five tests failed before the fix and passed after it |
| Transport-trait timeout setters discarded their arguments | Client/server obfs4 and WebTunnel use the configured budget | Pending dial and stalled HTTP Upgrade tests |
| obfs4 consumed the first buffered packet as if it must be a PRNG seed | Every authenticated payload remains readable; invalid buffered frames return errors | Coalesced handshake/payload test failed before the fix |
| Later PRNG seeds were ignored | The client updates both packet-length and IAT distributions | Real encrypted seed/payload exchange checks the resulting tables |
| An empty read could wait for peer data | Empty reads complete immediately | Open-peer regression failed before the fix |
| WebTunnel lacked a complete connection deadline | DNS, TCP, TLS, and Upgrade share one budget; timeout closes the socket | Local peer observes EOF after the configured timeout |
| IPv6 brackets and nondefault HTTP ports were mixed with socket/SNI names | Socket/SNI hosts omit IPv6 brackets; HTTP Host retains brackets and the port | IPv6 and HTTP request tests |
| Invalid schemes and server names reached the handshake | Configuration and connect validation reject them | Unsupported-scheme and header-injection tests |
| Standalone DoH could build an empty trust store | The resolver explicitly enables bundled trusted roots | Standalone strict-DoH + verified TLS + Upgrade succeeded against a real bridge |
| A full connection limit prevented Lyrebird cancellation | Cancellation interrupts the semaphore wait and releases the accepted socket | One occupied permit reproduces the old wait; no bulk connection load is needed |

The obfs4 packet handling follows [the protocol specification, sections 5–6](https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt).
The seed operation uses the existing SHA-256 derivation for the 24-byte IAT seed;
it introduces no new encryption primitive, key schedule, or nonce construction.

The old claim that Go samples directly from the seeded distribution generator
was incorrect: [the reference samples with `csrand`](https://github.com/Yawning/obfs4/blob/master/common/probdist/weighted_dist.go).
Only that documentation was corrected; the sampling algorithm was retained.

## Dependencies and compatibility

Compatible dependency updates preserve the declared Rust 1.89 minimum. The
lockfile now selects `h2` 0.4.19 and non-yanked `chacha20` 0.10.2. No new advisory
exceptions were added. The existing RSA advisory exception remains inherited
from the Tor dependency stack and remains visible in `deny.toml`.

All six packages use version 0.5.3 and require this release of their internal
dependencies. The private examples package retains its version. Existing public
transport interfaces and the `servername` override convention are retained.

## Validation

- Workspace: 361 passing tests, three existing ignored doctests.
- Optimized workspace: the same 361 tests passed, with the same three ignores.
- Lyrebird with `experimental-server`: 20 passing unit tests.
- Formatting and clippy for all workspace targets/features passed.
- Documentation with warnings denied passed.
- The complete workspace builds with Rust 1.89.
- Dependency advisories, bans, licenses, and source checks passed.
- A standalone client completed strict DoH, certificate-verified TLS, and HTTP Upgrade.
- The consuming proxy with 0.5.3 completed two HTTPS 200 responses over WebTunnel,
  switched the same running client to eight obfs4 bridges, and completed two more
  HTTPS 200 responses. Both IP checks returned `IsTor=true`; the obfs4 responses
  took 2.33 and 0.94 seconds within the unchanged 45-second request budget.
- Rust source files remain below 1000 lines.
- API comparison against published 0.5.2 passed for all six packages.
- All six package archives were compiled successfully from their staged registry
  dependencies. Archived Rust sources match the reviewed working tree; the
  archives contain no private machine paths or local checkpoint drafts.

The real-network check establishes functional connectivity at the time tested.
It does not establish uninterrupted availability under every network condition.
