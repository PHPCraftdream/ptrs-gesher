#!/usr/bin/env bash
# Requires an explicit version and immutable source SHA; see RELEASING.md.
set -euo pipefail
exec python3 "$(dirname "$0")/publish.py" "$@"
