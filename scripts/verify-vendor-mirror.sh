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
# Verify that vendor-mirror/vowifi-go-1e9c6e6 is byte-identical to
# vowifi-go.git@1e9c6e6.
#
# Why a script and not a convention: T040 and T041 both rest on "not one byte of
# the mirror changed", and that sentence is only worth anything if something
# checks it. It is also why `go build -overlay` is banned: an overlay changes
# what the compiler sees while leaving every file on disk untouched, so this
# check would still pass and the statement would have quietly become false.
#
# The comparison is per blob, not a directory diff:
#   - every path in the commit tree is hashed with `git hash-object --no-filters`
#     and compared to the blob id recorded in the tree
#   - a file the commit knows about but the worktree lacks is drift
#   - a file the worktree has but the commit does not is drift
#
# Line endings are classified, not swept under the rug. --no-filters means the
# hash covers the literal bytes on disk, and a mirror checked out on Windows with
# core.autocrlf=true is CRLF throughout while the upstream blobs are LF. That is
# not a content change, so it is reported as EOL-ONLY rather than as MODIFIED.
# Set VODOGE_VERIFY_STRICT_EOL=1 to make even that fail; CI does, because a Linux
# checkout has no excuse for CRLF.
#
# Exit codes: 0 clean, 1 drift, 2 cannot check (missing mirror or git).
#
# Environment overrides:
#   VODOGE_VENDOR_MIRROR     directory holding vowifi-go.git and the worktree
#   VODOGE_VOWIFI_GITDIR     explicit git dir to compare against
#   VODOGE_VOWIFI_COMMIT     commit to pin (default 1e9c6e6)
#   VODOGE_VERIFY_STRICT_EOL treat EOL-only differences as drift

set -eu

COMMIT="${VODOGE_VOWIFI_COMMIT:-1e9c6e6}"
STRICT_EOL="${VODOGE_VERIFY_STRICT_EOL:-0}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

if [ -n "${VODOGE_VENDOR_MIRROR:-}" ]; then
	mirror_root="$VODOGE_VENDOR_MIRROR"
else
	mirror_root="$repo_root/../vendor-mirror"
fi

worktree="$mirror_root/vowifi-go-$COMMIT"

if ! command -v git >/dev/null 2>&1; then
	echo "verify-vendor-mirror: git not found" >&2
	exit 2
fi

if [ ! -d "$worktree" ]; then
	cat >&2 <<EOF
verify-vendor-mirror: no mirror worktree at
  $worktree

The mirror lives outside this repository on purpose: it is a read-only copy of
github.com/boa-z/vowifi-go, wired in by the replace directive in vowifi/go.mod
and voice/go.mod. Set VODOGE_VENDOR_MIRROR, or materialise it with:

  git clone --bare https://github.com/boa-z/vowifi-go.git "$mirror_root/vowifi-go.git"
  mkdir -p "$worktree"
  GIT_INDEX_FILE="$mirror_root/.verify-index" \\
    git --git-dir="$mirror_root/vowifi-go.git" --work-tree="$worktree" read-tree "$COMMIT"
  GIT_INDEX_FILE="$mirror_root/.verify-index" \\
    git --git-dir="$mirror_root/vowifi-go.git" --work-tree="$worktree" checkout-index -a -f
  rm -f "$mirror_root/.verify-index"
EOF
	exit 2
fi

if [ -n "${VODOGE_VOWIFI_GITDIR:-}" ]; then
	gitdir="$VODOGE_VOWIFI_GITDIR"
elif [ -d "$mirror_root/vowifi-go.git" ]; then
	gitdir="$mirror_root/vowifi-go.git"
elif [ -d "$worktree/.git" ]; then
	gitdir="$worktree/.git"
else
	echo "verify-vendor-mirror: no git dir for the mirror; set VODOGE_VOWIFI_GITDIR" >&2
	exit 2
fi

if ! full_commit=$(git --git-dir="$gitdir" rev-parse --verify "${COMMIT}^{commit}" 2>/dev/null); then
	echo "verify-vendor-mirror: $gitdir does not contain commit $COMMIT" >&2
	exit 2
fi

case "$full_commit" in
"$COMMIT"*) ;;
*)
	echo "verify-vendor-mirror: $COMMIT resolved to $full_commit, which does not start with the pinned prefix" >&2
	exit 2
	;;
esac

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# ls-tree -r emits: mode<SP>type<SP>blob<TAB>path
git --git-dir="$gitdir" ls-tree -r "$full_commit" >"$workdir/tree"
awk -F'\t' '{print $2}' "$workdir/tree" >"$workdir/paths"
awk '{split($0, a, "\t"); split(a[1], b, " "); print b[3]}' "$workdir/tree" >"$workdir/expected"

drift=0
tracked=0
eol_only=0

missing=0
while IFS= read -r path; do
	if [ ! -f "$worktree/$path" ] && [ ! -L "$worktree/$path" ]; then
		echo "MISSING   $path"
		missing=1
		drift=1
	fi
done <"$workdir/paths"

if [ "$missing" -eq 0 ]; then
	# One process for all ~200 files. Relative paths with the worktree as cwd:
	# absolute MSYS-style paths are not portable into Git for Windows.
	(cd "$worktree" && git hash-object --no-filters --stdin-paths) \
		<"$workdir/paths" >"$workdir/actual"

	: >"$workdir/eol"
	while IFS= read -r expected_hash <&3 && IFS= read -r actual_hash <&4 && IFS= read -r path <&5; do
		tracked=$((tracked + 1))
		[ "$expected_hash" = "$actual_hash" ] && continue
		# Re-hash with every CR deleted. A match means the bytes on disk are
		# exactly the blob with CRs inserted, so the content is untouched and
		# only the checkout convention differs. Deletion is used instead of a
		# CRLF-to-LF rewrite because sed and awk both append a trailing newline
		# to a file that lacks one, and the mirror LICENSE is exactly such a
		# file: that alone misreported it as MODIFIED.
		normalized=$(tr -d '\r' <"$worktree/$path" |
			git hash-object --no-filters --stdin)
		if [ "$normalized" = "$expected_hash" ]; then
			eol_only=$((eol_only + 1))
			printf '%s\n' "$path" >>"$workdir/eol"
			continue
		fi
		echo "MODIFIED  $path"
		echo "          expected blob $expected_hash"
		echo "          actual   blob $actual_hash"
		drift=1
	done 3<"$workdir/expected" 4<"$workdir/actual" 5<"$workdir/paths"
fi

# Anything on disk the commit does not know about is drift too. .git is skipped:
# a worktree produced by `git clone` carries one and it is not part of the tree.
(cd "$worktree" && find . -type f -not -path './.git/*' -print) |
	sed 's|^\./||' | LC_ALL=C sort >"$workdir/on-disk"
LC_ALL=C sort "$workdir/paths" >"$workdir/expected-paths"

if extra=$(LC_ALL=C comm -23 "$workdir/on-disk" "$workdir/expected-paths"); [ -n "$extra" ]; then
	printf '%s\n' "$extra" | while IFS= read -r path; do
		[ -n "$path" ] && echo "UNTRACKED $path"
	done
	drift=1
fi

if [ "$eol_only" -gt 0 ]; then
	echo "EOL-ONLY  $eol_only file(s) match the commit content but are CRLF on disk"
	echo "          first few:"
	head -n 3 "$workdir/eol" | sed 's/^/            /'
	echo "          cause: this worktree was checked out with core.autocrlf=true."
	echo "          content is unchanged; VODOGE_VERIFY_STRICT_EOL=1 rejects it anyway."
	if [ "$STRICT_EOL" = "1" ]; then
		drift=1
	fi
fi

if [ "$drift" -ne 0 ]; then
	cat >&2 <<EOF

verify-vendor-mirror: DRIFT against vowifi-go.git@$COMMIT

  worktree $worktree
  git dir  $gitdir

T041 forbids editing the mirror. If a change looks necessary there, the injection
seams are the answer instead -- see
docs/goals/vodoge-vowifi-call/notes/T041-injection-seams.md. Do not reach for
go build -overlay to make this green: an overlay leaves every file on disk
untouched, so this check would pass while the compiled artifact no longer matches
the source tree. That is the most expensive kind of lie to debug.
EOF
	exit 1
fi

if [ "$eol_only" -gt 0 ]; then
	echo "verify-vendor-mirror: clean, $tracked file(s) match vowifi-go.git@$full_commit ($eol_only CRLF-only)"
else
	echo "verify-vendor-mirror: clean, $tracked file(s) byte-identical to vowifi-go.git@$full_commit"
fi
exit 0
