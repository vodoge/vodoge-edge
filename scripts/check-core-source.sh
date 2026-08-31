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
# What this check asserts, and what it does not (SN-T032)
# ---------------------------------------------------------------------------
# edge-core/src/lib.rs opens with "This crate intentionally owns no I/O."
# Until this file existed, nothing enforced that sentence. The neighbouring
# check, scripts/check-core-deps.sh (SN-T027), is a DEPENDENCY check: it proves
# edge-core pulls in no I/O runtime. Its own header says, in as many words,
# that edge-core opening std::net::TcpStream or std::fs::File directly is
# invisible to it. This file closes that second path. The two are layers, not
# alternatives; neither subsumes the other.
#
# Shape: an allowlist over the std submodules edge-core's own source names,
# not a denylist of forbidden ones -- the same argument SN-T027 made about
# crates. A denylist's coverage is exactly the modules its author thought of.
#
# The allowlist is affordable here, and that was measured rather than assumed:
# across the crate's entire history at the time of writing (13 commits touching
# edge-core/src, 2026-08-20 to 2026-08-24) the set below changed exactly ONCE
# -- `cmp` arrived in the third commit, d0f747e. The ten commits after it did
# not move the set at all. One reviewed line per thirteen commits is not the
# kind of guard people learn to ignore.
#
# WHY THIS IS NOT A GREP. The obvious implementation is
#
#     grep -rE 'std::(net|fs|process)' edge-core/src
#
# and it is a check named for something it does not do. Rust's grouped use
# declaration defeats it outright:
#
#     use std::{fmt, fs};        <- `grep 'std::fs'` finds NOTHING here
#
# and edge-core/src/matrix.rs already writes its imports in exactly that form,
# spread over four lines. So this file flattens grouped and nested use trees
# before it matches, and the flattener is exercised by an explicit positive
# control in the T032 note. It also strips comments first: 603 of edge-core's
# 3337 source lines are prose, and a guard that reddens because someone wrote
# "we deliberately do not call std::fs here" in a comment is a guard that gets
# switched off.
#
# It does NOT prove the following, and a green run must not be read as if it
# did:
#   * FFI. `extern "C" { fn socket(...) }` behind an `unsafe` block reaches the
#     kernel without naming std and without adding a dependency, so neither
#     this check nor check-core-deps.sh sees it. edge-core has zero `unsafe`
#     and zero `extern` today. Banning them is the cheapest next layer and is
#     deliberately NOT done here: it is a different property with a different
#     review cost, and widening a CI gate past its card is how gates get
#     resented. See the T032 note.
#   * Dependencies. What serde_json does inside itself is check-core-deps.sh's
#     question, not this one.
#   * edge-core/tests/. Integration tests do not ship. Inline `#[cfg(test)]`
#     blocks inside src/ ARE scanned, on purpose: recognising them textually
#     would mean trusting an attribute to decide what gets inspected, and a
#     filter that the defect itself can flip is not a filter. A test that
#     genuinely needs a fixture off disk belongs in edge-core/tests/, which
#     exists.
#   * Macro-generated paths. edge-core defines no macros that build type paths,
#     but a future one could assemble `std` `::` `fs` out of tokens.
# ---------------------------------------------------------------------------

cd "$(dirname "$0")/.."

PKG=edge-core
SRC="$PKG/src"

# The reviewed std surface. Field 1 is the submodule; everything after it is
# the reason it is allowed, and an entry without a reason is rejected below --
# an exception nobody had to justify is the next defect.
#
# Derived, not invented: this is every `std::` path edge-core/src names today,
# extracted by the same flattener that does the checking, with the root removed.
allowlist() {
  cat <<'ALLOWED'
borrow       Cow, for returning owned-or-borrowed text without copying
cmp          Reverse, an ordering adapter used when ranking evidence
collections  BTreeMap and HashMap; in-memory containers
error        the Error trait, so this crate's errors compose
fmt          Display and Formatter; produces strings, never writes them out
mem          take, to move a String out of a local without copying it
sync         Arc, a reference count; no threads are spawned here
ALLOWED
}

# std submodules that may never appear in the allowlist above.
#
# This is NOT the coverage mechanism, exactly as in check-core-deps.sh. The
# allowlist is, and it already rejects every one of these. The only job of this
# line is to stop someone silencing a red build by adding `fs` to the allowlist
# with a plausible-sounding reason. A submodule missing from this line is still
# rejected for not being on the allowlist; do not grow it believing that widens
# what the check catches, because it does not.
NEVER_ALLOWED='net fs process io os'

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
# CRLF bug in the shim above stayed invisible for weeks.

if [ ! -d "$SRC" ]; then
  die 2 "check-core-source: CANNOT RUN: $SRC does not exist (cwd $(pwd))"
fi

files=$(find "$SRC" -name '*.rs' -type f | sort)

if [ -z "$files" ]; then
  die 2 "check-core-source: CANNOT RUN: no .rs files found under $SRC"
fi

file_count=$(printf '%s\n' "$files" | awk 'NF' | wc -l | tr -d ' ')

if [ "$file_count" -lt 1 ]; then
  die 2 "check-core-source: CANNOT RUN: 0 source files examined."
fi

# --- std aliasing ----------------------------------------------------------
# `use std as sys;` makes every later `sys::fs::read` invisible to a scanner
# that keys on the token `std::`. Rust 2021 has few ways to rename a crate
# root, and they are all shaped like this. Without this arm the main check
# below is one line away from being bypassed, which is why it is here and not
# in the list of things this file does not claim.

aliased=$(
  grep -nE '(^|[^A-Za-z0-9_])(use[[:space:]]+(::)?std[[:space:]]+as|extern[[:space:]]+crate[[:space:]]+std[[:space:]]+as|use[[:space:]]+(::)?std::self[[:space:]]+as)[[:space:]]' $files || true
)
if [ -n "$aliased" ]; then
  die 1 "edge-core renames the std crate root, which makes every std path" \
        "after it unreadable to this check:" \
        "$aliased" \
        "" \
        "Write std paths as std:: so they can be reviewed."
fi

# --- the std surface actually named by the source --------------------------

found=$(awk '
function emit(s,   k, ch, id) {
  sub(/^[ \t\r\n]+/, "", s)
  id = ""
  for (k = 1; k <= length(s); k++) {
    ch = substr(s, k, 1)
    if (ch ~ /[A-Za-z0-9_]/) id = id ch
    else break
  }
  if (id != "") mods[id] = 1
}
{
  # Strip line comments, respecting string and char literals so that a "//"
  # inside a literal is not mistaken for the start of prose. State is reset
  # every line, so a malformed literal cannot blind the rest of the file.
  line = $0
  # A CRLF checkout leaves a CR at the end of every line. Left in place it
  # lands at the head of the first item of a multi-line `use std::{` group,
  # where the identifier scan stops on it and the import is silently missed --
  # a CRLF tree would then read as a clean tree. Strip it before anything else.
  gsub(/\r/, "", line)
  out = ""
  n = length(line)
  i = 1
  while (i <= n) {
    c = substr(line, i, 1)
    if (c == "\"") {
      out = out c
      i++
      while (i <= n) {
        d = substr(line, i, 1)
        if (d == "\\") { out = out d substr(line, i + 1, 1); i += 2; continue }
        out = out d
        i++
        if (d == "\"") break
      }
      continue
    }
    if (c == "'"'"'") {
      # char literal, escaped or plain; anything else is a lifetime
      if (substr(line, i + 1, 1) == "\\" && substr(line, i + 3, 1) == "'"'"'") {
        out = out substr(line, i, 4); i += 4; continue
      }
      if (substr(line, i + 2, 1) == "'"'"'") {
        out = out substr(line, i, 3); i += 3; continue
      }
      out = out c
      i++
      continue
    }
    if (c == "/" && substr(line, i + 1, 1) == "/") break
    out = out c
    i++
  }
  buf = buf " " out
}
END {
  n = length(buf)
  i = 1
  while (1) {
    p = index(substr(buf, i), "std::")
    if (p == 0) break
    abs = i + p - 1
    i = abs + 5
    # not a suffix of a longer identifier, e.g. mystd::
    if (abs > 1) {
      c = substr(buf, abs - 1, 1)
      if (c ~ /[A-Za-z0-9_]/) continue
    }
    j = abs + 5
    while (substr(buf, j, 1) == " ") j++
    if (substr(buf, j, 1) == "{") {
      depth = 0
      k = j
      start = j + 1
      while (k <= n) {
        c = substr(buf, k, 1)
        if (c == "{") depth++
        else if (c == "}") { depth--; if (depth == 0) break }
        k++
      }
      if (depth != 0) { print "!UNBALANCED"; exit }
      body = substr(buf, start, k - start)
      d = 0
      cur = ""
      for (t = 1; t <= length(body); t++) {
        c = substr(body, t, 1)
        if (c == "{") { d++; cur = cur c }
        else if (c == "}") { d--; cur = cur c }
        else if (c == "," && d == 0) { emit(cur); cur = "" }
        else cur = cur c
      }
      emit(cur)
    } else {
      emit(substr(buf, j, 64))
    }
  }
  for (m in mods) print m
}
' $files | sort -u)

case "$found" in
  *'!UNBALANCED'*)
    die 2 "check-core-source: CANNOT RUN: a 'use std::{' group in $SRC has no" \
          "matching close brace after comment stripping. This script cannot" \
          "tell what is being imported, so it must not report success."
    ;;
esac

# --- the check has to have looked at something -----------------------------
# Zero std paths satisfies "none of them is an I/O module" vacuously, and a
# vacuous pass is indistinguishable from a real one. This floor is what catches
# a flattener that silently stopped working.

found_count=$(printf '%s\n' "$found" | awk 'NF' | wc -l | tr -d ' ')

if [ "$found_count" -lt 1 ]; then
  die 2 "check-core-source: CANNOT RUN: 0 std:: paths were found across" \
        "$file_count files in $SRC. edge-core has never had zero, so the far" \
        "likelier reading is that the extractor in this script broke. An empty" \
        "set satisfies every universal claim; it cannot be reported as success."
fi

allowed=$(allowlist | awk 'NF {print $1}' | sort -u)
allowed_count=$(printf '%s\n' "$allowed" | awk 'NF' | wc -l | tr -d ' ')

if [ "$allowed_count" -lt 1 ]; then
  die 2 "check-core-source: CANNOT RUN: the allowlist in this script is empty," \
        "which would reject everything for the wrong reason."
fi

unreasoned=$(allowlist | awk 'NF && NF < 2 {print $1}')
if [ -n "$unreasoned" ]; then
  die 2 "check-core-source: CANNOT RUN: these allowlist entries carry no" \
        "reason:" \
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
  die 2 "check-core-source: CANNOT RUN: an I/O module has been added to the" \
        "allowlist in this script:" \
        "$laundered" \
        "Take it back out. If $PKG genuinely needs it, then this check and the" \
        "sentence at the top of $SRC/lib.rs both have to go -- not just this" \
        "line."
fi

unexpected=$(
  {
    printf '%s\n' "$allowed" | awk 'NF {print "A " $1}'
    printf '%s\n' "$found" | awk 'NF {print "F " $1}'
  } | awk '$1 == "A" { ok[$2] = 1; next } $1 == "F" && !ok[$2] { print $2 }'
)

if [ -n "$unexpected" ]; then
  die 1 "$PKG must not reach for I/O itself. Its source names these std" \
        "modules, which are not on the reviewed list in this script:" \
        "$unexpected" \
        "" \
        "If a module above computes in memory and opens nothing, add it to" \
        "allowlist() together with the reason. If it reads a file, opens a" \
        "socket, spawns a process, or asks the operating system anything," \
        "it does not belong in $PKG -- that work belongs one layer up, which" \
        "is what $SRC/lib.rs promises."
fi

printf 'check-core-source: %s: %s files scanned, %s std modules named, every one on the reviewed allowlist (%s entries). No direct I/O.\n' \
  "$PKG" "$file_count" "$found_count" "$allowed_count"
