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
# on PATH. DENO_DIR (optional) is forwarded through as-is if the CALLER
# already set one (e.g. a real pre-warmed cache, deliberately reused
# across runs); if not, this script creates and owns its own scoped,
# throwaway one (see the should-fix fix below for why "own" specifically
# matters when tools/db/test.sh's `run_as_pg` runs this as a DIFFERENT
# OS user, e.g. `postgres` under `su`, than the one that invoked
# tools/db/test.sh itself). Unlike the "gitleaks/pg_prove not found"
# style soft-skips elsewhere in this tree, a MISSING deno here is a HARD
# FAILURE, not a skip: this script exists specifically because the
# reviewer found real bugs that only running this suite could catch (see
# the header above) — a silently-skipped run is indistinguishable, from
# this script's own exit code, from a clean pass, which is exactly the
# blind spot item 0 is closing. (Contrast with tools/db/test.sh's own
# "FAILED — node/dist missing" hard-fail discipline for service-role
# -lint, added the same round for the identical reason.)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPABASE_DIR="$ROOT_DIR/supabase"
INTEGRATION_DIR="$SUPABASE_DIR/tests/integration"
DENO_CONFIG="$SUPABASE_DIR/functions/deno.json"
# supabase/tests/, deliberately NOT supabase/functions/ (tools/service-
# role-lint's own point 8 validates every deno.lock found UNDER
# functionsRoot against a strict "every remote key is itself an exact
# pinned target" rule — unsatisfiable for a REAL lockfile's full
# transitive graph, confirmed this round) and NOT the repo root or any
# other ancestor of supabase/functions/ up to it (the SAME lint's point 7
# bans a config/lockfile's mere PRESENCE anywhere on that path,
# regardless of content — also confirmed this round, and the repo root IS
# on that path). supabase/tests/ is a SIBLING of supabase/functions/, so
# it is invisible to both checks while still being an obvious, discoverable
# place next to the other test-only assets.
DENO_LOCK="$SUPABASE_DIR/tests/deno.lock"

: "${PGHOST:?tools/db/test-deno-integration.sh: PGHOST must be set (see the header comment in this file)}"
: "${PGPORT:?tools/db/test-deno-integration.sh: PGPORT must be set}"
: "${PGUSER:?tools/db/test-deno-integration.sh: PGUSER must be set}"
: "${PGDATABASE:?tools/db/test-deno-integration.sh: PGDATABASE must be set}"

DENO_BIN="${DENO_BIN:-deno}"
if ! command -v "$DENO_BIN" >/dev/null 2>&1; then
  echo "tools/db/test-deno-integration.sh: FAILED — '$DENO_BIN' is not on PATH and DENO_BIN was not set to an explicit path. This is a hard failure, not a skip (see this script's own header)." >&2
  exit 1
fi

# ⛔ FIX (P3c gate round 3, should-fix): "make it work when run as the
# postgres OS user without a pre-warmed DENO_DIR... don't hardcode this
# sandbox's paths." The prior version only ever FORWARDED a
# caller-supplied `DENO_DIR` — with none given, `deno`'s own default
# module-cache location is under the invoking OS user's home directory,
# which the CALLER (tools/db/test.sh's `run_as_pg`, `su postgres -s
# /bin/bash -c ...`) may not have one of, or may not be able to write to.
# When the caller hasn't already provided one, this script now creates
# its OWN scoped, throwaway cache directory — via `mktemp`, so it is
# ALWAYS created (and therefore owned/writable) by whichever OS user
# actually executes this exact script, never assumed to already exist or
# be pre-warmed by a DIFFERENT user first. Cleaned up on exit, but only
# when THIS script is the one that created it — a caller-supplied
# DENO_DIR (e.g. a real pre-warmed cache, deliberately reused across
# runs) is left alone.
CREATED_DENO_DIR=0
if [ -z "${DENO_DIR:-}" ]; then
  DENO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/golfraven-deno-integration-cache.XXXXXX")"
  CREATED_DENO_DIR=1
fi
export DENO_DIR
cleanup_deno_dir() {
  if [ "$CREATED_DENO_DIR" -eq 1 ]; then
    rm -rf "$DENO_DIR" 2>/dev/null || true
  fi
}
trap cleanup_deno_dir EXIT

# ⛔ FIX (P3c gate round 3, should-fix, same item): "pass the CA via
# DENO_CERT from the environment's standard CA path when it's set and
# readable." `DENO_CERT` is Deno's OWN native env var for this — if the
# invoking user's environment already has a USABLE one (set AND actually
# readable BY THIS USER; a proxy CA bundle can be readable-in-principle
# but unreachable if it lives under a directory the invoking user can't
# traverse — this is the exact shape this repo's own sandbox hit:
# `/root/.ccr/ca-bundle.crt` itself was world-readable, but `/root` was
# not, blocking the `postgres` OS user from ever reaching it, regardless
# of DENO_CERT being set at all) — nothing further to do; Deno already
# consumes `DENO_CERT` from its own process environment automatically.
# Otherwise, check the SAME small set of conventional CA-bundle env vars
# a proxied sandbox commonly sets (never a hardcoded path of any ONE
# sandbox) and adopt whichever ONE is BOTH set and readable by this
# user. If none qualify, DENO_CERT is explicitly UNSET (never left
# pointing at the already-known-unreadable path it may have inherited) —
# Deno then falls back to its own default trust store, which may or may
# not suffice for this particular network; an honest gap rather than a
# silently-assumed path, and a cleaner failure mode than handing Deno a
# path its own `access()` check will just reject anyway.
if [ -z "${DENO_CERT:-}" ] || [ ! -r "${DENO_CERT:-/nonexistent}" ]; then
  unset DENO_CERT
  for candidate_var in NODE_EXTRA_CA_CERTS SSL_CERT_FILE CURL_CA_BUNDLE; do
    candidate_path="${!candidate_var:-}"
    if [ -n "$candidate_path" ] && [ -r "$candidate_path" ]; then
      export DENO_CERT="$candidate_path"
      break
    fi
  done
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
