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

# ---------------------------------------------------------------------------
# What this check asserts, and what it does not (SN-T027)
# ---------------------------------------------------------------------------
# The CI step that runs this file is called "edge-core has no I/O runtime".
# Until SN-T027 the body under that name was a four-name denylist:
#
#     cargo tree -p edge-core | grep -E '^(tokio|reqwest|hyper|async-std) v'
#
# The denylist was not broken. Injecting `tokio` did turn it red, exactly as
# T019 and T023 recorded. It was four names wide -- and "has no I/O runtime"
# ranges over an open-ended universe that no list of forbidden names can close.
#
# Measured on 16e4468 against the byte-identical script the edge machine was
# running (sha256 c3862b7ceb4bc1fcb9e9297f667d41ed270f6e29f9d23e56ffdd42173973d7de),
# with real crates and a real offline resolve, one dependency added at a time:
#
#     injected       old guard   what it is
#     tokio          RED         positive control -- the four names do work
#     mio            GREEN       the epoll/kqueue event loop tokio is built on
#     socket2        GREEN       raw TCP and UDP sockets
#     tokio-macros   GREEN       `^tokio v` cannot match `tokio-macros v2.7.2`
#
# So the body is an allowlist now. edge-core's transitive normal-dependency
# closure must be a subset of the reviewed set below; anything else fails,
# whether or not whoever wrote this file had ever heard of it. That is the only
# shape under which the step's name is true, because it is the only shape whose
# coverage does not depend on having guessed the right enemies in advance.
#
# It still does not prove the following, and a green run must not be read as if
# it did:
#   * It is a dependency check. edge-core opening std::net::TcpStream or
#     std::fs::File directly is invisible to it.
#   * --edges normal excludes dev- and build-dependencies deliberately: they do
#     not ship in the binary. A build script that talks to the network is not
#     covered here.
#   * It matches crate names, not versions or features. serde with a new
#     feature flag is still `serde`.
# ---------------------------------------------------------------------------

cd "$(dirname "$0")/.."

PKG=edge-core

# The reviewed dependency closure. Field 1 is the crate name; everything after
# it is the reason that crate is allowed, and an entry without a reason is
# rejected below -- an exception nobody had to justify is the next defect.
#
# Derived, not invented: this is `cargo tree -p edge-core --prefix none
# --edges normal` on 16e4468 with the root line removed. Every one of them is a
# data-format, container, or compile-time crate; not one opens a socket or a
# file. Adding a line here is the same decision as adding a dependency to
# edge-core and deserves the same review.
allowlist() {
  cat <<'ALLOWED'
serde          serialisation traits; carries no transport of its own
serde_core     the trait core serde is split over
serde_derive   proc macro, runs at compile time only
serde_json     JSON text to and from values, in memory
serde_spanned  source spans for toml
toml           parses configuration that is already a string
toml_datetime  toml's date and time types
toml_edit      format-preserving toml parser behind `toml`
toml_write     toml serialiser behind `toml`
winnow         parser combinators used by toml_edit
indexmap       order-preserving map used by toml_edit
equivalent     trait glue between indexmap and hashbrown
hashbrown      hash table implementation
itoa           integers to text
zmij           floats to text; serde_json's number formatter
memchr         byte search used by serde_json's parser
proc-macro2    compile-time token trees
quote          compile-time token trees
syn            compile-time Rust parser
unicode-ident  identifier classification for syn
ALLOWED
}

# Names that may never appear in the allowlist above.
#
# This is NOT the coverage mechanism. The allowlist is, and it already rejects
# every one of these. The only job of this line is to stop a known I/O runtime
# from being quietly added to the allowlist to make a red build go away. It is
# deliberately incomplete and that is harmless here: a crate missing from this
# line is still rejected for not being on the allowlist. Do not grow it in the
# belief that doing so widens what the check catches -- it does not.
NEVER_ALLOWED='tokio reqwest hyper async-std mio socket2 ureq curl isahc surf smol axum warp'

die() {
  code=$1
  shift
  for line in "$@"; do
    printf '%s\n' "$line" >&2
  done
  exit "$code"
}

# Exit 1 means the property is violated. Exit 2 means the check could not run,
# or ran over nothing -- it proved neither the property nor its negation. They
# are kept apart because an exit 2 that reads like a failing check is how the
# CRLF bug above stayed invisible for so long.

if ! command -v cargo >/dev/null 2>&1; then
  die 2 "check-core-deps: CANNOT RUN: cargo is required"
fi

# Not `tree=$(cargo tree ...)` on its own: under `set -e` that aborts with
# cargo's exit code, which is 1 -- the code this script reserves for "edge-core
# really does depend on something it must not". A resolver that could not run
# would then be indistinguishable from a violation it found.
set +e
tree=$(cargo tree -p "$PKG" --prefix none --edges normal)
cargo_rc=$?
set -e

if [ "$cargo_rc" != 0 ]; then
  die 2 "check-core-deps: CANNOT RUN: 'cargo tree -p $PKG' exited $cargo_rc." \
        "cargo's own diagnostics are above this line."
fi

# --- the check has to have looked at something -----------------------------
# An empty or unparseable tree satisfies "no crate in here is an I/O runtime"
# vacuously, and a vacuous pass is indistinguishable from a real one.

if [ -z "$tree" ]; then
  die 2 "check-core-deps: CANNOT RUN: cargo tree -p $PKG produced no output"
fi

malformed=$(printf '%s\n' "$tree" | grep -vE '^[A-Za-z0-9_.+-]+ v[0-9]' || true)
if [ -n "$malformed" ]; then
  die 2 "check-core-deps: CANNOT RUN: cargo tree emitted lines this script cannot" \
        "parse. Every line must look like '<crate> v<version>'. Unparsed:" \
        "$malformed"
fi

names=$(printf '%s\n' "$tree" | awk 'NF {print $1}' | sort -u)

if ! printf '%s\n' "$names" | grep -qx "$PKG"; then
  die 2 "check-core-deps: CANNOT RUN: '$PKG' is not the root of the tree that came" \
        "back. cargo tree resolved something else:" \
        "$tree"
fi

deps=$(printf '%s\n' "$names" | grep -vx "$PKG" || true)
dep_count=$(printf '%s\n' "$deps" | awk 'NF' | wc -l | tr -d ' ')

if [ "$dep_count" -lt 1 ]; then
  die 2 "check-core-deps: CANNOT RUN: 0 dependencies of $PKG were examined." \
        "An empty set satisfies every universal claim, so this cannot report" \
        "success. If $PKG genuinely has no dependencies any more, it is this" \
        "floor that needs revisiting, not the tree."
fi

allowed=$(allowlist | awk 'NF {print $1}' | sort -u)
allowed_count=$(printf '%s\n' "$allowed" | awk 'NF' | wc -l | tr -d ' ')

if [ "$allowed_count" -lt 1 ]; then
  die 2 "check-core-deps: CANNOT RUN: the allowlist in this script is empty," \
        "which would reject everything for the wrong reason."
fi

unreasoned=$(allowlist | awk 'NF && NF < 2 {print $1}')
if [ -n "$unreasoned" ]; then
  die 2 "check-core-deps: CANNOT RUN: these allowlist entries carry no reason:" \
        "$unreasoned" \
        "An exception nobody had to justify is the next defect. Write why."
fi

laundered=$(
  {
    printf '%s\n' "$NEVER_ALLOWED" | tr ' ' '\n' | awk 'NF {print "N " $1}'
    printf '%s\n' "$allowed" | awk 'NF {print "A " $1}'
  } | awk '$1 == "N" { never[$2] = 1; next } $1 == "A" && never[$2] { print $2 }'
)
if [ -n "$laundered" ]; then
  die 2 "check-core-deps: CANNOT RUN: a known I/O runtime has been added to the" \
        "allowlist:" \
        "$laundered" \
        "Take it back out. If $PKG genuinely needs it, then this check and the" \
        "claim in its CI step name both have to go -- not just this line."
fi

unexpected=$(
  {
    printf '%s\n' "$allowed" | awk 'NF {print "A " $1}'
    printf '%s\n' "$deps" | awk 'NF {print "D " $1}'
  } | awk '$1 == "A" { ok[$2] = 1; next } $1 == "D" && !ok[$2] { print $2 }'
)

if [ -n "$unexpected" ]; then
  die 1 "edge-core must not depend on I/O runtimes or HTTP clients. Its" \
        "dependency closure is a reviewed set, and these crates are in the" \
        "closure without being on it:" \
        "$unexpected" \
        "" \
        "If a crate above is a data-format, container, or compile-time crate" \
        "that opens no socket and no file, add it to allowlist() together with" \
        "the reason. If it is not, it does not belong in $PKG." \
        "" \
        "Full tree:" \
        "$tree"
fi

printf 'check-core-deps: %s: %s dependencies examined, every one on the reviewed allowlist (%s entries). No I/O runtime.\n' \
  "$PKG" "$dep_count" "$allowed_count"
