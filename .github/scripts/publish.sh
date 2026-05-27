#!/usr/bin/env bash
# Idempotent crates.io publish with rate-limit handling.
#
# Exits 0 on success, on "already published" (skip), and after a clean
# retry sequence on 429.  Exits non-zero on any other failure.
#
# Usage: publish.sh <crate-name>
#
# Requires CARGO_REGISTRY_TOKEN in the environment.

set -euo pipefail

crate=${1:?"usage: publish.sh <crate-name>"}
max_attempts=5
# crates.io rate-limits new crate names at ~1 per 10 minutes for fresh
# accounts; existing-crate version uploads are limited at ~30 per 10
# minutes.  600s gives the window a clean reset.
base_backoff=600

attempt=0
while :; do
  attempt=$((attempt + 1))
  echo "::group::cargo publish -p $crate  (attempt $attempt/$max_attempts)"
  set +e
  out=$(cargo publish -p "$crate" --locked 2>&1)
  ec=$?
  set -e
  printf '%s\n' "$out"
  echo "::endgroup::"

  if [ "$ec" -eq 0 ]; then
    echo "PUBLISHED: $crate"
    exit 0
  fi

  if printf '%s' "$out" | grep -Eqi 'already (uploaded|exists)|crate version is already uploaded|status 409'; then
    echo "ALREADY ON CRATES.IO: $crate (skipping)"
    exit 0
  fi

  if printf '%s' "$out" | grep -Eqi 'Too Many Requests|status 429|rate.?limit'; then
    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "RATE-LIMITED after $attempt attempts: $crate"
      exit 1
    fi
    wait=$((base_backoff * attempt))
    echo "RATE-LIMITED: sleeping ${wait}s before retry $((attempt + 1))/$max_attempts"
    sleep "$wait"
    continue
  fi

  echo "UNKNOWN FAILURE (exit $ec) for $crate"
  exit "$ec"
done
