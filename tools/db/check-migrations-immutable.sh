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

  # P3d gate round 4, S-a1: must-fail case — a --base that does not
  # resolve to a real commit at all (typo, unfetched branch, a
  # `push`-event `before` SHA that happens to be all-zero). This script
  # itself (not this self_test function) is what must reject it — invoke
  # the ACTUAL executable, in its OWN process, exactly as CI would.
  if bash "${BASH_SOURCE[0]}" --base "refs/heads/this-ref-does-not-exist-check-migrations-immutable-selftest" >/dev/null 2>&1; then
    echo "tools/db/check-migrations-immutable.sh --self-test: FAILED — a nonexistent --base was NOT rejected (the real check ran, potentially vacuously, against a ref that does not exist)" >&2
    exit 1
  fi
  echo "tools/db/check-migrations-immutable.sh --self-test: a nonexistent --base is correctly rejected"

  # P3d gate round 4, S-a1: must-fail case — a --base that DOES resolve
  # to a real commit, but one that lists ZERO files under
  # supabase/migrations/ (the "vacuous pass" shape this whole fix exists
  # to close). Built from git's own well-known empty-tree object via
  # `commit-tree`, so it needs no repo-history assumption (no "the first
  # commit predates migrations/" fragility) — a real, valid, but
  # deliberately empty commit object, never referenced by any branch, tag
  # or ref, so it neither touches the working tree nor becomes reachable
  # history (ordinary git garbage collection reclaims it over time, the
  # same as any other unreferenced object this session's own probing
  # already creates incidentally).
  local empty_tree="4b825dc642cb6eb9a060e54bf8d69288fbee4904"
  local empty_commit
  empty_commit="$(git commit-tree "$empty_tree" -m "check-migrations-immutable.sh --self-test: empty scratch commit, never referenced by any ref" 2>/dev/null)"
  if [ -z "$empty_commit" ]; then
    echo "tools/db/check-migrations-immutable.sh --self-test: FAILED — could not construct the empty-base scratch commit (git commit-tree itself failed)" >&2
    exit 1
  fi
  if bash "${BASH_SOURCE[0]}" --base "$empty_commit" >/dev/null 2>&1; then
    echo "tools/db/check-migrations-immutable.sh --self-test: FAILED — a --base with ZERO supabase/migrations/ files was NOT rejected (a vacuous pass)" >&2
    exit 1
  fi
  echo "tools/db/check-migrations-immutable.sh --self-test: a --base with zero migration files is correctly rejected (not a vacuous pass)"

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

# ⛔ FIX (P3d gate round 4, S-a1): "the immutability gate passes
# vacuously on a bad base." A `--base` naming a ref that doesn't exist
# (typo, a branch not fetched, `event.before`'s all-zero SHA on a
# force-pushed/first push) previously fell through to `git ls-tree`
# below, which SILENTLY prints nothing for an unresolvable ref — the
# `while` loop then iterates zero paths, `FAILURES` stays 0, and the
# script reports "OK" having compared against NOTHING. Validated
# explicitly now, with `^{commit}` (not a bare `rev-parse --verify`) so
# a ref that resolves to something OTHER than a commit (a blob, a tree)
# is ALSO rejected, not silently accepted as a comparison base.
if ! git rev-parse --verify --quiet "${BASE_REF}^{commit}" >/dev/null 2>&1; then
  echo "tools/db/check-migrations-immutable.sh: --base '${BASE_REF}' does not resolve to a real commit — refusing to run a check that would otherwise pass vacuously against nothing" >&2
  exit 2
fi

echo "tools/db/check-migrations-immutable.sh: comparing supabase/migrations/ on the working tree against ${BASE_REF}"

# ⛔ FIX (P3d gate round 4, S-a1, same finding): the `|| true` below used
# to swallow ANY `git ls-tree` failure (a corrupt/incomplete shallow
# checkout, a pack error) into an empty, silently-successful list — the
# SAME "passes vacuously" shape as the unvalidated ref above, just
# reached a different way. A failure now propagates (this script already
# runs under `set -euo pipefail`); the loop below additionally checks
# for a base that resolves cleanly but genuinely lists ZERO migration
# files (a real, if unlikely, shape for a bad/empty base ref) and fails
# loudly rather than reporting a vacuous "OK".
MIGRATION_COUNT=0
FAILURES=0
while IFS= read -r path; do
  [ -z "$path" ] && continue
  MIGRATION_COUNT=$((MIGRATION_COUNT + 1))
  if ! compare_path_to_base "$BASE_REF" "$path" "$ROOT_DIR/$path"; then
    FAILURES=$((FAILURES + 1))
  fi
done < <(git ls-tree -r --name-only "$BASE_REF" -- supabase/migrations/)

if [ "$MIGRATION_COUNT" -eq 0 ]; then
  echo "tools/db/check-migrations-immutable.sh: ${BASE_REF} lists ZERO files under supabase/migrations/ — refusing to report a vacuous pass; this is almost certainly the wrong base ref" >&2
  exit 2
fi

if [ "$FAILURES" -gt 0 ]; then
  echo "tools/db/check-migrations-immutable.sh: ${FAILURES} merged migration file(s) changed — a migration already on ${BASE_REF} must never be edited or removed in place. Restore it (git checkout ${BASE_REF} -- <path>) and move any real fix into a NEW migration file instead." >&2
  exit 1
fi

echo "tools/db/check-migrations-immutable.sh: OK — every one of ${MIGRATION_COUNT} supabase/migrations/ file(s) present on ${BASE_REF} is byte-identical here."
