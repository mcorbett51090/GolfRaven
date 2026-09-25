#!/usr/bin/env bash
# tools/db/test-deno-integration.sh
#
# P3c gate round 2, item 0 (required first): "Add a Deno integration test
# suite that runs the REAL privileged.ts and the handlers against the
# harness cluster tools/db/test.sh builds. Wire it into the db-tests CI
# job for BOTH harness modes." The reviewer's own finding was that every
# one of the 12 HIGH/MEDIUM items was found ONLY by running privileged.ts
# for real under Deno against a real Postgres cluster — CI never did that
# (it only ran pgTAP + vitest against a fake in-memory Repo). This script
# closes that gap.
#
# Usage (same convention as test-replay-concurrency.sh /
# test-money-path-concurrency.sh — tools/db/test.sh calls this the same
# way, against the SAME live cluster/database, after the pgTAP matrix and
# the two concurrency scripts, before teardown):
#
#   PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... PATH="$PG_BIN_DIR:$PATH" \
#     bash tools/db/test-deno-integration.sh
#
# `deno` must already be resolvable — via DENO_BIN (an explicit path), or
# on PATH. DENO_DIR (optional) is forwarded through as-is if set — Deno's
# own module-cache-location env var, useful when the caller (tools/db/
# test.sh) runs this as a DIFFERENT OS user (e.g. `postgres`, under
# `su`) than the one that already has outbound-network/cert access: a
# `deno cache` warmed up front, into a DENO_DIR that user can also read,
# lets this step run entirely from that cache with no network call of its
# own. Unlike the "gitleaks/pg_prove not found" style soft-skips
# elsewhere in this tree, a MISSING deno here is a HARD FAILURE, not a
# skip: this script exists specifically because the reviewer found real
# bugs that only running this suite could catch (see the header above) —
# a silently-skipped run is indistinguishable, from this script's own
# exit code, from a clean pass, which is exactly the blind spot item 0 is
# closing. (Contrast with tools/db/test.sh's own "FAILED — node/dist
# missing" hard-fail discipline for service-role-lint, added the same
# round for the identical reason.)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPABASE_DIR="$ROOT_DIR/supabase"
INTEGRATION_DIR="$SUPABASE_DIR/tests/integration"
DENO_CONFIG="$SUPABASE_DIR/functions/deno.json"
DENO_LOCK="$ROOT_DIR/deno.lock"

: "${PGHOST:?tools/db/test-deno-integration.sh: PGHOST must be set (see the header comment in this file)}"
: "${PGPORT:?tools/db/test-deno-integration.sh: PGPORT must be set}"
: "${PGUSER:?tools/db/test-deno-integration.sh: PGUSER must be set}"
: "${PGDATABASE:?tools/db/test-deno-integration.sh: PGDATABASE must be set}"

DENO_BIN="${DENO_BIN:-deno}"
if ! command -v "$DENO_BIN" >/dev/null 2>&1; then
  echo "tools/db/test-deno-integration.sh: FAILED — '$DENO_BIN' is not on PATH and DENO_BIN was not set to an explicit path. This is a hard failure, not a skip (see this script's own header)." >&2
  exit 1
fi

# should-fix (P3c gate round 2, "supply chain"): run against the committed
# lockfile with --frozen once one exists, so transitive drift (e.g. a
# dependency's own dependency quietly moving) fails loudly instead of
# resolving silently. Falls back to --no-lock (this round's prior
# behaviour) only if deno.lock genuinely isn't there yet — never silently
# ignores a PRESENT lockfile.
LOCK_ARGS=(--no-lock)
if [ -f "$DENO_LOCK" ]; then
  LOCK_ARGS=(--lock="$DENO_LOCK" --frozen)
fi

echo "tools/db/test-deno-integration.sh: running against PGHOST=$PGHOST PGPORT=$PGPORT PGUSER=$PGUSER PGDATABASE=$PGDATABASE"
"$DENO_BIN" test \
  --config "$DENO_CONFIG" \
  "${LOCK_ARGS[@]}" \
  --allow-net --allow-env --allow-read --allow-write \
  "$INTEGRATION_DIR"

echo "tools/db/test-deno-integration.sh: all Deno integration tests passed"
