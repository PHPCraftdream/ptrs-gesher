# Releasing ptrs-gesher

Step-by-step procedure for publishing a new version to crates.io.

## 1. Pre-flight checks

Ensure the tree is clean and everything passes:

```sh
git diff --exit-code
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release
```

## 2. Update CHANGELOG

Rename the `[Unreleased]` heading in `CHANGELOG.md` to
`[X.Y.Z] - YYYY-MM-DD` and add a fresh `[Unreleased]` section above it.

## 3. Bump versions

Update the `version` field in **all six** `Cargo.toml` files to the same
version number. If workspace inter-dependency versions are pinned (e.g.
`version = "0.1.0"` in `dep.ptrs-gesher-core`), update those too.

Crate paths:
- `crates/core/Cargo.toml`
- `crates/bridge-line/Cargo.toml`
- `crates/obfs4/Cargo.toml`
- `crates/webtunnel/Cargo.toml`
- `crates/lyrebird/Cargo.toml`
- `crates/ptrs-gesher/Cargo.toml`

## 4. Commit and tag

```sh
git add -A
git commit -m "Release vX.Y.Z"
git tag vX.Y.Z
```

## 5. Publish in DAG order

Leaves first, then their dependents. Wait ~30 seconds between batches
for the crates.io index to refresh.

```sh
# Batch 1: leaves (no internal deps)
cargo publish -p ptrs-gesher-core
cargo publish -p ptrs-gesher-bridge-line

# Wait ~30s, then batch 2
cargo publish -p ptrs-gesher-obfs4
cargo publish -p ptrs-gesher-webtunnel

# Wait ~30s, then batch 3
cargo publish -p ptrs-gesher-lyrebird

# Wait ~30s, then the umbrella
cargo publish -p ptrs-gesher
```

## 6. Post-publish

- Push the tag: `git push origin vX.Y.Z`
- Draft a GitHub Release with the relevant `CHANGELOG.md` entry.

## 7. If a publish fails halfway

**Never re-use a version number on crates.io.** Bump to the next patch
version (e.g. `X.Y.(Z+1)`), fix the issue, and retry from step 3.
