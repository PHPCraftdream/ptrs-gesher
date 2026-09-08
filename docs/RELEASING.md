# Releasing ptrs-gesher

All six published crates use the same version. Version changes, commits, pushes,
and publication require the maintainer's authorization.

## Prepare and verify

1. Review source and dependency changes. Keep the declared Rust 1.89 minimum.
2. Move the changelog entries into a dated release section and leave a new
   `[Unreleased]` section above it.
3. Update all six package versions and their internal dependency requirements.
   Refresh `Cargo.lock`; the private examples package keeps its own version.
4. Run the release checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --release
cargo test --locked -p ptrs-gesher-lyrebird --features experimental-server
cargo +1.89 check --workspace --locked
cargo deny --locked check
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --all-features
cargo semver-checks --workspace --exclude ptrs-gesher-examples --baseline-version PREVIOUS_VERSION --all-features
cargo package --locked --workspace --exclude ptrs-gesher-examples --allow-dirty
```

`--allow-dirty` permits reviewing the exact package contents before committing.
Inspect the archives and exclude unrelated local drafts from the commit.
Benchmarks are a separate, explicitly requested performance check.

## Publish

Commit the reviewed release and push the branch. Wait for CI to succeed, then
create and push `vX.Y.Z`. The tag triggers `.github/workflows/release.yml`.
It validates all six versions, builds and tests the workspace, and publishes in
dependency order: core, bridge-line, obfs4, webtunnel, lyrebird, umbrella.

The publish script waits for Cargo's registry acknowledgement. No manual delay
between packages is needed. Monitor the workflow through its terminal result,
then verify all six versions on crates.io and create the GitHub release notes.

## Resume a partial publication

Re-run the failed workflow, or dispatch it manually with the same version and
the intended source revision. Already published packages are skipped; rate limits
receive bounded retries. Never overwrite published package contents or create a
new version merely to retry a failed upload. A source correction to an already
published package needs a separately authorized release.
