# Releasing ptrs-gesher

All six published crates use the same version. Version changes, commits, pushes,
and publication require the maintainer's authorization.

## Prepare and verify

1. Review source and dependency changes. Keep the declared Rust 1.89 minimum.
2. Move the changelog entries into a dated release section and leave a new
   `[Unreleased]` section above it.
   Before the approved release commit, set the final date and remove any local
   preparation notice; do not change sources after publication has started.
   Update each packaged crate README as well as the workspace README, and
   inspect the README actually included in each archive.
3. Update all six package versions and their internal dependency requirements.
   Refresh `Cargo.lock`; the private examples package keeps its own version.
   Set `workspace.metadata.release.baseline-version` to the previous published
   version (0.5.3 for the 0.6.0 release).
4. Run the release-tool tests and complete local gates. Rust stable, Rust 1.89,
   Go, Python 3.9+, cargo-deny and cargo-semver-checks are required:

```sh
python3 -m unittest discover -s .github/scripts/tests -v
python3 .github/scripts/release-check.py
```

The gates include debug/release tests with all features, MSRV, separate feature
builds, Rust/Go interop, docs, dependency audit, API comparison and package builds.
`--root` selects the source checkout; automation can live at a different ref.
`--go` selects a Go executable when it is not on PATH. The package gate uses
`--allow-dirty` to permit reviewing exact contents before committing.
Inspect the archives and exclude unrelated local drafts from the commit.
Benchmarks are a separate, explicitly requested performance check.

## One-time Trusted Publishing setup

Create the GitHub environment **`crates-io`** in `PHPCraftdream/ptrs-gesher`.
If deployment branch/tag restrictions are enabled, permit release tags `v*`
and `main` for manual recovery workflows. Source checkout remains pinned to
the verified original release SHA in both cases.

On crates.io, open each crate's Settings → Trusted Publishing and add a
**GitHub Actions** publisher with these exact fields:

| Crate | Repository owner | Repository name | Workflow filename | Environment |
|---|---|---|---|---|
| `ptrs-gesher-core` | `PHPCraftdream` | `ptrs-gesher` | `release.yml` | `crates-io` |
| `ptrs-gesher-bridge-line` | `PHPCraftdream` | `ptrs-gesher` | `release.yml` | `crates-io` |
| `ptrs-gesher-obfs4` | `PHPCraftdream` | `ptrs-gesher` | `release.yml` | `crates-io` |
| `ptrs-gesher-webtunnel` | `PHPCraftdream` | `ptrs-gesher` | `release.yml` | `crates-io` |
| `ptrs-gesher-lyrebird` | `PHPCraftdream` | `ptrs-gesher` | `release.yml` | `crates-io` |
| `ptrs-gesher` | `PHPCraftdream` | `ptrs-gesher` | `release.yml` | `crates-io` |

Use the filename `release.yml`, not `.github/workflows/release.yml` or the
display name `Release`. All six existing crates need their own publisher entry.
The publish job has `id-token: write` and obtains a fresh temporary token before
each crate with `rust-lang/crates-io-auth-action@v1`; the action revokes its
tokens on job completion. No `secrets.CARGO_REGISTRY_TOKEN` is used. The env var
with that name holds only the action's short-lived output for its publish step.
After migration, an old long-lived token may be revoked if no other workflow
uses it. Creating publisher entries/environments or revoking tokens is an
external setup step; editing this repository does not perform it.

References: [crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing),
[official authentication action](https://github.com/rust-lang/crates-io-auth-action).

## Publish

Commit the reviewed release and push the branch. Wait for CI to succeed, then
create and push `vX.Y.Z`. The tag triggers `.github/workflows/release.yml`.
The source job resolves the tag to its commit and compares it to the expected
full SHA. Checks and publication both checkout that SHA. Package versions and
internal version requirements must match, and the publish checkout must be
clean. Publication proceeds in dependency order: core, bridge-line, obfs4,
webtunnel, lyrebird, umbrella. Publications of the same version are serialized.

The publish script verifies each registry version and its archive checksum/VCS
revision. A failed Cargo command is not success merely because its text includes
`already exists`. No manual delay between packages is needed. Monitor the workflow through its terminal result,
then verify all six versions on crates.io and create the GitHub release notes.

## Resume a partial publication

Re-run the original workflow, or manually dispatch `Release` with the same
`version` and the full original commit SHA in `source_sha`. The existing tag
must still resolve to that SHA. The workflow logic can come from newer main,
but both jobs keep publishing/testing the original source; matching version
numbers alone do not permit a different checkout.

Before the first upload, the publish job checks all six package names for
conflicting versions from another source SHA. Already published packages are skipped only when their exact crate/version,
non-yanked status, archive checksum and clean VCS SHA are verified. A package
from another commit rejects the retry. Registry lookup failures fail closed.
Rate limits receive up to three attempts with 60/120-second waits per crate;
longer throttling requires another workflow run and fresh OIDC credentials.
If Cargo reports success before the registry lookup can confirm it, retry the
same SHA rather than assuming the release completed.

Never overwrite published package contents or create a
new version merely to retry a failed upload. A source correction to an already
published package needs a separately authorized release.
