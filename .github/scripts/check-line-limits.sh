#!/usr/bin/env bash
# Fail if any first-party Rust file exceeds MAX_LINES physical lines.
#
# Scope: crates/ and examples/ — these cover all first-party sources in
# this repository. There is no vendored or generated Rust code committed
# here; if one is ever added, exclude it explicitly below.
set -euo pipefail

MAX_LINES=1000

files=$(find crates examples -type f -name '*.rs' | LC_ALL=C sort)

failures=0
while IFS= read -r file; do
    # awk NR counts physical lines exactly, including a missing final newline.
    lines=$(awk 'END { print NR }' "$file")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        echo "::error file=$file::$lines physical lines (limit is $MAX_LINES)"
        failures=$((failures + 1))
    fi
done <<< "$files"

if [ "$failures" -gt 0 ]; then
    echo "$failures file(s) exceed the ${MAX_LINES}-line limit; split them up."
    exit 1
fi
echo "OK: all first-party Rust files are within the ${MAX_LINES}-line limit."
