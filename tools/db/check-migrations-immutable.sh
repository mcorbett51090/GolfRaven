#!/usr/bin/env bash
# tools/db/check-migrations-immutable.sh
#
# P3d gate round 3, blocking B1: "0021 was edited in place after #13
# merged it to main (34d00dc)." A merged migration is never edited in
# place, full stop, regardless of how good the reason — `CREATE OR
# REPLACE` (for a function/view) or a brand-new migration file is always
# the fix. This is not merely a style rule: a real database that already
# applied 0021's original bytes has no mechanism to notice or re-apply an
# in-place edit to that same filename (`supabase db push`, and this
# repo's own `tools/db/test.sh`, both apply every migrations/*.sql file
# it hasn't already recorded as applied, by filename — never re-diffing
# an already-applied file's content) — so an in-place edit silently
# diverges the deployed schema from what the repo says it is, invisible
# to the exact mechanism that is supposed to keep them in sync.
#
# This script is the enforcement CI gate for that rule: every file under
# supabase/migrations/ that ALREADY EXISTS on the base ref (default:
# origin/main) must be BYTE-IDENTICAL here. A file present on base but
# MISSING here (renamed or deleted) is also a failure — renaming a
# merged migration is the same class of mistake as editing it in place.
#
# Usage:
#   tools/db/check-migrations-immutable.sh [--base <ref>]
#   tools/db/check-migrations-immutable.sh --self-test
#
#   --base <ref>   Defaults to origin/main (falls back to main if
#                   origin/main does not resolve — e.g. a local checkout
#                   with no origin remote). Compared against the CURRENT
#                   working tree (uncommitted changes included, so a
#                   violation is caught before it is even committed).
#   --self-test     Proves this script actually catches the bug class it
#                   exists for: a must-fail fixture (a real, base-ref
#                   migration file's content, with ONE byte appended in a
#                   /tmp-only scratch copy — the real working tree is
#                   NEVER touched) and a must-pass fixture (the same
#                   file's content, byte-for-byte, unmodified). Exits
#                   nonzero if EITHER proof does not behave as expected —
#                   a self-test that cannot fail is not a self-test.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

resolve_base_ref() {
  if git rev-parse --verify --quiet origin/main >/dev/null 2>&1; then
    echo "origin/main"
  elif git rev-parse --verify --quiet main >/dev/null 2>&1; then
    echo "main"
  else
    echo "tools/db/check-migrations-immutable.sh: could not resolve origin/main or main as a base ref (is this a shallow checkout with no origin remote configured?)" >&2
    exit 2
  fi
}

# Compares a base ref's blob for one path against a real file on disk.
# Prints nothing on a match; prints ONE line describing the mismatch and
# returns non-zero otherwise. Never writes to the repo — the "disk_file"
# argument may point anywhere, including a /tmp scratch copy (used by
# --self-test below), never assumed to be the real working-tree path.
compare_path_to_base() {
  local base_ref="$1" repo_path="$2" disk_file="$3"
  if [ ! -f "$disk_file" ]; then
    echo "MISSING (present on ${base_ref}, absent here): ${repo_path}"
    return 1
  fi
  if ! diff -q <(git show "${base_ref}:${repo_path}") "$disk_file" >/dev/null 2>&1; then
    echo "MODIFIED (differs from ${base_ref}): ${repo_path}"
    return 1
  fi
  return 0
}

self_test() {
  local base_ref
  base_ref="$(resolve_base_ref)"
  local sample
  sample="$(git ls-tree -r --name-only "$base_ref" -- supabase/migrations/ | head -n1)"
  if [ -z "$sample" ]; then
    echo "tools/db/check-migrations-immutable.sh --self-test: no migration files found on ${base_ref} to build a fixture from" >&2
    exit 2
  fi

  local scratch
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/check-migrations-immutable-selftest.XXXXXX")"
  # Double-quoted so $scratch is expanded NOW, embedding the literal path
  # into the trap command — a single-quoted trap would defer expansion
  # to exit time, by which point this function's own `local scratch` has
  # gone out of scope (`set -u` then fails with "unbound variable").
  trap "rm -rf '$scratch'" EXIT

  # Must-fail fixture: base content + one planted line, in a /tmp-only
  # scratch copy. The real working tree is never touched — no planted marker
  # marker is ever written anywhere under this repo.
  git show "${base_ref}:${sample}" > "$scratch/mutated.sql"
  printf -- '-- SELF-TEST-PLANTED-EDIT (self-test only, /tmp scratch copy — never written to the repo)\n' >> "$scratch/mutated.sql"
  if compare_path_to_base "$base_ref" "$sample" "$scratch/mutated.sql" >/dev/null 2>&1; then
    echo "tools/db/check-migrations-immutable.sh --self-test: FAILED — the must-fail fixture (a planted edit) was NOT detected" >&2
    exit 1
  fi
  echo "tools/db/check-migrations-immutable.sh --self-test: must-fail fixture correctly detected (${sample} + one planted line, /tmp scratch copy)"

  # Must-pass fixture: the SAME file's content, byte-for-byte, unmodified.
  git show "${base_ref}:${sample}" > "$scratch/clean.sql"
  if ! compare_path_to_base "$base_ref" "$sample" "$scratch/clean.sql" >/dev/null 2>&1; then
    echo "tools/db/check-migrations-immutable.sh --self-test: FAILED — the must-pass fixture (byte-identical content) was WRONGLY flagged" >&2
    exit 1
  fi
  echo "tools/db/check-migrations-immutable.sh --self-test: must-pass fixture correctly passed clean (${sample}, unmodified)"

  echo "tools/db/check-migrations-immutable.sh --self-test: OK"
}

BASE_REF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --base)
      BASE_REF="$2"
      shift 2
      ;;
    --self-test)
      self_test
      exit 0
      ;;
    -h | --help)
      echo "Usage: $0 [--base <ref>] | --self-test"
      exit 0
      ;;
    *)
      echo "tools/db/check-migrations-immutable.sh: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[ -z "$BASE_REF" ] && BASE_REF="$(resolve_base_ref)"

echo "tools/db/check-migrations-immutable.sh: comparing supabase/migrations/ on the working tree against ${BASE_REF}"

FAILURES=0
while IFS= read -r path; do
  [ -z "$path" ] && continue
  if ! compare_path_to_base "$BASE_REF" "$path" "$ROOT_DIR/$path"; then
    FAILURES=$((FAILURES + 1))
  fi
done < <(git ls-tree -r --name-only "$BASE_REF" -- supabase/migrations/ 2>/dev/null || true)

if [ "$FAILURES" -gt 0 ]; then
  echo "tools/db/check-migrations-immutable.sh: ${FAILURES} merged migration file(s) changed — a migration already on ${BASE_REF} must never be edited or removed in place. Restore it (git checkout ${BASE_REF} -- <path>) and move any real fix into a NEW migration file instead." >&2
  exit 1
fi

echo "tools/db/check-migrations-immutable.sh: OK — every supabase/migrations/ file present on ${BASE_REF} is byte-identical here."
