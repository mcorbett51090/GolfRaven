#!/usr/bin/env bash
# tools/db/check-no-migration-owner-refs.sh
#
# H2 (post-P3a gate) static check: no migration file may reference the harness-only `migration_owner` role by name in ACTIVE SQL. A real deploy's own migration role is
# never literally called that, and 0016/0017 both did this before the fix (GRANT ... TO migration_owner), failing outright on a real deploy. `migration_owner` belongs ONLY
# in supabase/tests/shim.sql (the harness's own bootstrap). `--` comment lines are stripped first (the prose of a fix legitimately names the role when it describes the
# bug it fixed): a real reference is one that survives the strip.
#
# This used to be an inline loop in tools/db/test.sh:
#
#     if grep -v '^\s*--' "$f" | grep -q 'migration_owner'; then ...
#
# and it FAILED OPEN. Under `set -o pipefail`, `grep -q` exits at its first match; for a file larger than the pipe buffer (64 KB; 7 of the migrations are) the writer, `grep -v`,
# is still writing, takes SIGPIPE and exits 141, `pipefail` makes 141 the pipeline's status, and the `if` reads a MATCH as no match. Measured on a must-fail fixture (a violation
# on line 2 of a 670 KB file): detected in 0 of 1500 runs, against 1500 of 1500 for the form below. Nothing had been missed (a scan of all 107 migrations finds no violation),
# but a gate that can pass on the very thing it exists to catch is not a gate. The second `grep` below has no `-q` and sends its output to /dev/null, so it reads all of its input
# and the writer never takes the signal.
#
# Usage:
#   tools/db/check-no-migration-owner-refs.sh [<migrations dir>]     (default: supabase/migrations next to this script's repo root)
#   tools/db/check-no-migration-owner-refs.sh --self-test            (must-fail and must-pass fixtures, including large files)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# 0 if an ACTIVE (non-comment) line of $1 names migration_owner. No early-exit reader: see the header.
references_migration_owner() {
  grep -v '^\s*--' "$1" | grep 'migration_owner' >/dev/null
}

# Prints the files of $1/*.sql that reference it, space-separated (empty if none).
scan() {
  local dir="$1" hits="" f
  for f in "$dir"/*.sql; do
    [ -e "$f" ] || continue
    if references_migration_owner "$f"; then
      hits="$hits $f"
    fi
  done
  printf '%s' "$hits"
}

self_test() {
  local scratch
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/check-no-migration-owner-refs-selftest.XXXXXX")"
  # Double-quoted so $scratch is expanded NOW (a single-quoted trap would defer it past this function's scope, where `set -u` would fail).
  trap "rm -rf '$scratch'" EXIT

  # filler: far more than the 64 KB pipe buffer, so the writer is certainly still writing when an early-exit reader would have quit
  filler() { local i; for i in $(seq 1 6000); do echo "CREATE TABLE IF NOT EXISTS app.zz_filler_$i (id int); -- padding past the pipe buffer"; done; }

  { echo "-- header"; echo "GRANT SELECT ON app.offer TO migration_owner;"; filler; } > "$scratch/big_early_violation.sql"
  { echo "-- header"; filler; echo "GRANT SELECT ON app.offer TO migration_owner;"; } > "$scratch/big_late_violation.sql"
  { echo "GRANT SELECT ON app.offer TO migration_owner;"; } > "$scratch/small_violation.sql"
  { echo "-- header"; filler; } > "$scratch/big_clean.sql"
  { echo "-- migration_owner is the harness role (prose in a comment)"; echo "   -- an indented comment naming migration_owner"; echo "SELECT 1;"; } > "$scratch/comment_only.sql"
  : > "$scratch/empty.sql"

  local got expected
  got="$(scan "$scratch" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
  expected="$(printf '%s\n' "$scratch/big_early_violation.sql" "$scratch/big_late_violation.sql" "$scratch/small_violation.sql" | sort | tr '\n' ' ' | sed 's/ $//')"
  if [ "$got" != "$expected" ]; then
    echo "tools/db/check-no-migration-owner-refs.sh --self-test: FAILED — the fixtures were not classified as expected." >&2
    echo "  expected (the three violations, and ONLY those): $expected" >&2
    echo "  got:                                             $got" >&2
    exit 1
  fi
  echo "tools/db/check-no-migration-owner-refs.sh --self-test: a violation near the top of a >64 KB file, one at the bottom and a small one are all detected; a large clean file, a comment-only mention and an empty file are not"
  echo "tools/db/check-no-migration-owner-refs.sh --self-test: OK"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

DIR="${1:-$ROOT_DIR/supabase/migrations}"
if [ ! -d "$DIR" ]; then
  echo "tools/db/check-no-migration-owner-refs.sh: not a directory: $DIR" >&2
  exit 2
fi
COUNT="$(find "$DIR" -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ')"
if [ "$COUNT" -eq 0 ]; then
  echo "tools/db/check-no-migration-owner-refs.sh: no *.sql files under $DIR — refusing to report a vacuous pass" >&2
  exit 2
fi
HITS="$(scan "$DIR")"
if [ -n "$HITS" ]; then
  echo "tools/db/check-no-migration-owner-refs.sh: FAILED (H2) — the migration file(s) below reference 'migration_owner' by name outside a comment; a real deploy has no such role (use CURRENT_USER instead):$HITS" >&2
  exit 1
fi
echo "tools/db/check-no-migration-owner-refs.sh: OK — none of ${COUNT} migration file(s) names migration_owner outside a comment."
