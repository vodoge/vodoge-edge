#!/bin/sh
# --- BEGIN CRLF shim (T019) ---
# Checked out on Windows (core.autocrlf=true, no .gitattributes) this file is
# CRLF. A CRLF /bin/sh script dies on its first non-comment line: `set -eu' +
# CR makes dash say "set: Illegal option -" and bash say "set: -: invalid
# option", and both exit 2. Exit 2 reads like "the check ran and failed" when
# in fact not one check had run -- which is how this went unnoticed. Found by
# the T018 edge deploy; see docs/goals/vodoge-theme-black/notes/
# T019-crlf-guard-scripts.md for the measurements.
#
# Fix: if the bytes on disk carry CRs, re-run the very same bytes with the CRs
# stripped. `sh -c CMD NAME ARGS' sets $0=NAME, so "$0" and "$@" both survive
# and the "$0"-derived paths below still resolve. On an LF checkout the branch
# is not taken and nothing about this script changes.
#
# EVERY LINE OF THIS SHIM ENDS IN A COMMENT ON PURPOSE. Under CRLF the trailing
# CR then lands inside that comment, where it is inert. No other line shape
# survives: `fi' + CR is not the keyword `fi', and a blank line becomes the
# command CR ("$'\r': command not found"). If you edit this block, keep the
# trailing comments and re-run the T019 matrix in both checkouts.
if [ "${VODOGE_SH_CR_SHIM-}" = 1 ]; then                 # re-run: clear the mark
  unset VODOGE_SH_CR_SHIM                              # so children start clean
elif [ -n "$(tr -cd '\r' <"$0" 2>/dev/null)" ]; then     # first run: any CR on disk?
  export VODOGE_SH_CR_SHIM=1                           # mark it, so this cannot loop
  exec sh -c "$(tr -d '\r' <"$0")" "$0" "$@"           # same bytes, CR-free
fi                                                       # (keep those comments)
# --- END CRLF shim (T019) ---
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
