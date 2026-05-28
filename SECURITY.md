# Security Policy

`ptrs-gesher` provides Rust implementations of Tor pluggable transports
(obfs4, webtunnel, lyrebird). Because these crates handle bridge-line
parsing, ntor handshakes, framing, and stream-level cryptography, we treat
all reachability-relevant or confidentiality-relevant bugs as security
issues.

## Supported versions

| Version | Status              | Security fixes |
|---------|---------------------|----------------|
| 0.1.x   | Active development  | Yes            |
| < 0.1   | Pre-release / yanked | No            |

While the project is on the `0.x` line we backport fixes only to the most
recent published `0.1.x` minor; downstream consumers are expected to track
the latest release.

## Reporting a vulnerability

Please report security issues **privately** via [GitHub Security
Advisories](https://github.com/PHPCraftdream/ptrs-gesher/security/advisories/new)
on this repository. **Do not file public issues, pull requests, or
discussion threads for security bugs.**

When reporting, please include where possible:

- Affected crate(s) and version(s) (e.g. `obfs4 0.1.0`).
- A minimal reproducer or proof-of-concept.
- Your assessment of impact (DoS, traffic distinguisher, key recovery,
  memory safety, etc.).
- Whether the issue is already public anywhere.

We will acknowledge new reports on a best-effort basis, typically within
72 hours. This project is in pre-1.0 development and we do **not** offer a
formal SLA while the version is `0.x`.

## Scope

**In scope** (please report privately):

- Cryptographic primitives used by `obfs4`, `webtunnel`, and `lyrebird`
  (ntor handshake, key derivation, nonce/IV handling).
- Framing and message-codec logic, including parser desync, panics on
  attacker-controlled input, and length-confusion bugs.
- Bridge-line / PT argument parsers.
- Replay protection windows and filter behaviour.
- Memory-safety issues (panics, OOB, UAF) reachable from network input
  in any of the above crates.
- Side channels that distinguish PT traffic from cover traffic in a way
  not already documented upstream.

**Out of scope** (please report to the appropriate project):

- Bugs in downstream consumers (e.g. `arti`, `tor-socks5`, application
  glue code) — report to those trackers.
- Bugs in upstream Tor specifications themselves; we track spec changes
  but cannot fix them here.
- Generic dependency advisories already filed against `cargo audit` /
  RustSec without a demonstrated reachable impact in `ptrs-gesher`.
- Build-time or developer-tooling issues without a runtime security
  impact.

## Embargo

Unless the reporter requests otherwise, we follow a **90-day default
embargo** from the date of acknowledgement. We may publish earlier if a
fix is shipped and the issue is already being exploited, or later by
mutual agreement when coordinating with other Tor pluggable-transport
implementations.

## Contact

GitHub Security Advisories are the primary channel. A dedicated PGP /
Signal contact for out-of-band coordination is **TBD** for the `0.1.x`
line and will be published here once available.
