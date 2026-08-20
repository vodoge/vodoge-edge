#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required" >&2
  exit 1
fi

tree=$(cargo tree -p edge-core --prefix none --edges normal)
if echo "$tree" | grep -E '^(tokio|reqwest|hyper|async-std) v'; then
  echo "edge-core must not depend on I/O runtimes or HTTP clients:" >&2
  echo "$tree" >&2
  exit 1
fi
