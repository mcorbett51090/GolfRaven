#!/usr/bin/env bash
# tools/db/test.sh
#
# Local/CI test harness for the player-plane database (build plan §10 P3,
# docs/golf-trails/02-build-plan.md:2758: "Deliverables ... pgTAP + API
# authorization matrix"). No Docker, no Supabase CLI in this environment —
# see supabase/tests/shim.sql for what that means we reproduce by hand.
#
# What it does, in order:
#   1. initdb a THROWAWAY Postgres 16 cluster under a fresh temp dir (never
#      touches the system's 16/main cluster — safe to run repeatedly and in
#      parallel CI jobs).
#   2. Create the postgis / pgtap / pgcrypto extensions (bootstrap-as-
#      superuser — postgis/pgtap are not `trusted` extensions, confirmed
#      this session via their .control files, so only a superuser can
#      CREATE them, in EITHER harness mode).
#   3. Apply supabase/tests/shim.sql (the local Supabase stand-in: auth
#      schema, anon/authenticated/service_role/authenticator roles, the
#      migration_owner role, storage schema, an empty supabase_realtime
#      publication) — also always bootstrap-as-superuser (S1, gate round
#      3: "Extensions and shim provisioning stay bootstrap-as-superuser").
#   4. Apply every supabase/migrations/*.sql file, in filename order — the
#      exact same files a real `supabase db push` would apply, unmodified.
#   5. Apply supabase/tests/helpers.sql (seeded actors + catalog rows the
#      matrix tests exercise), as service_role (SET ROLE, in the same
#      session — service_role already has full DML + BYPASSRLS, matching
#      how these rows would really be written by an Edge Function).
#   6. Run every supabase/tests/matrix/*.sql file with pg_prove (falls back
#      to psql + runtests() if pg_prove is unavailable).
#   7. Tear the cluster down (trap on EXIT, so a failed run still cleans
#      up).
#
# Exit code is pg_prove's / the fallback's — non-zero on any test failure,
# so this is safe to wire straight into CI (`.github/workflows/ci.yml`).
#
# HARNESS_MODE (S1, gate round 3 close-out — "add a harness mode where
# tests run as a NOSUPERUSER NOBYPASSRLS owner/test role. ... An RLS test
# that only passes under superuser is a false pass."):
#   - `superuser` (default): steps 4-6 connect as the cluster bootstrap
#     role (`postgres`), a true Postgres superuser — the original
#     behaviour, unchanged.
#   - `restricted`: steps 4-6 connect as `migration_owner` instead
#     (supabase/tests/shim.sql: LOGIN, CREATEDB, CREATEROLE, explicitly
#     NOSUPERUSER NOBYPASSRLS, owns the test database). Steps 2-3 stay on
#     the bootstrap superuser connection either way (extensions/shim
#     provisioning, per the directive above). Run BOTH modes — this
#     script does not run them both itself, since each is a full,
#     independent cluster lifecycle; invoke it twice
#     (`HARNESS_MODE=superuser tools/db/test.sh && HARNESS_MODE=restricted
#     tools/db/test.sh`), as CI's db-tests job now does.
#
# Env overrides: PG_BIN_DIR (default: autodetected via pg_config, falls
# back to /usr/lib/postgresql/16/bin), PGPORT (default: 5477), HARNESS_MODE
# (default: superuser).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPABASE_DIR="$ROOT_DIR/supabase"

PG_BIN_DIR="${PG_BIN_DIR:-}"
if [ -z "$PG_BIN_DIR" ]; then
  # should-fix (post-P3a re-gate): PostgreSQL 17 is the pinned major
  # version (supabase/config.toml `[db] major_version`) — prefer it
  # explicitly over whatever `pg_config` happens to resolve to (a host
  # can have multiple PG majors installed side by side, and pg_config
  # reflects the FIRST one on PATH, not necessarily the pinned one).
  # Falls back to `pg_config`, then a bare PostgreSQL 16 install, so this
  # still works on a host that only has 16 (verified locally this session
  # against PostgreSQL 17.11 from PGDG; the 16 fallback is the harness's
  # prior, still-supported behaviour).
  if [ -d /usr/lib/postgresql/17/bin ]; then
    PG_BIN_DIR="/usr/lib/postgresql/17/bin"
  elif command -v pg_config >/dev/null 2>&1 && [ -x "$(pg_config --bindir 2>/dev/null)/initdb" ]; then
    # `pg_config` itself commonly lives in /usr/bin as a thin wrapper, NOT
    # alongside initdb/pg_ctl/psql — always ask it for --bindir rather than
    # dirname-ing pg_config's own path (confirmed this session: on this
    # Debian/Ubuntu-style layout, pg_config is in /usr/bin while
    # initdb/pg_ctl live in /usr/lib/postgresql/<major>/bin).
    PG_BIN_DIR="$(pg_config --bindir)"
  elif [ -d /usr/lib/postgresql/16/bin ]; then
    PG_BIN_DIR="/usr/lib/postgresql/16/bin"
  else
    echo "tools/db/test.sh: cannot find a PostgreSQL bin directory (set PG_BIN_DIR)" >&2
    exit 1
  fi
fi

PGPORT="${PGPORT:-5477}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/golfraven-db-test.XXXXXX")"
PGDATA="$WORKDIR/data"
PGSOCK="$WORKDIR/run"
DBNAME="golfraven_test"

HARNESS_MODE="${HARNESS_MODE:-superuser}"
case "$HARNESS_MODE" in
  superuser|restricted) ;;
  *)
    echo "tools/db/test.sh: HARNESS_MODE must be 'superuser' or 'restricted' (got '$HARNESS_MODE')" >&2
    exit 1
    ;;
esac
# The role that steps 4-6 (migrations, fixtures, pgTAP matrix) connect as.
# Bootstrap (extensions + shim.sql) always connects as `postgres`,
# regardless of mode — see the file header.
if [ "$HARNESS_MODE" = "restricted" ]; then
  DBUSER="migration_owner"
else
  DBUSER="postgres"
fi
echo "tools/db/test.sh: HARNESS_MODE=$HARNESS_MODE (migrations/tests connect as '$DBUSER')"

# Every actual `psql`/`initdb`/`pg_ctl` call below runs as the `postgres`
# OS user when this script itself is root — PostgreSQL refuses to start as
# root, and a throwaway cluster under /tmp needs an owner that isn't root
# either way. When already non-root, run directly.
run_as_pg() {
  if [ "$(id -u)" -eq 0 ]; then
    su postgres -s /bin/bash -c "$*"
  else
    bash -c "$*"
  fi
}

PG_CTL_STARTED=0
cleanup() {
  if [ "$PG_CTL_STARTED" -eq 1 ]; then
    run_as_pg "'$PG_BIN_DIR/pg_ctl' -D '$PGDATA' -m fast stop" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "tools/db/test.sh: throwaway cluster at $PGDATA (port $PGPORT)"

mkdir -p "$PGSOCK"
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p "$PGDATA"
  chown -R postgres:postgres "$WORKDIR"
  chmod 700 "$PGDATA"
fi

run_as_pg "'$PG_BIN_DIR/initdb' -D '$PGDATA' -U postgres --auth=trust >/dev/null"

run_as_pg "'$PG_BIN_DIR/pg_ctl' -D '$PGDATA' -l '$WORKDIR/postgres.log' -o \"-p $PGPORT -k '$PGSOCK' -c listen_addresses=''\" start"
PG_CTL_STARTED=1

# Wait for readiness (initdb/pg_ctl start returns before the socket always
# exists under heavy CI load).
for _ in $(seq 1 30); do
  if run_as_pg "'$PG_BIN_DIR/pg_isready' -h '$PGSOCK' -p '$PGPORT'" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

PSQL=("$PG_BIN_DIR/psql" -h "$PGSOCK" -p "$PGPORT" -U postgres -v ON_ERROR_STOP=1 -q)

# H2 (post-P3a gate) static check: no migration file may reference the
# harness-only `migration_owner` role by name in ACTIVE SQL — a real
# deploy's own migration role is never literally called that, and
# 0016/0017 both did this before the fix (GRANT ... TO migration_owner),
# failing outright on a real deploy. `migration_owner` belongs ONLY in
# supabase/tests/shim.sql (the harness's own bootstrap). Strips `--`
# comment lines first (this fix's own explanatory prose legitimately
# names `migration_owner` when describing the bug it fixed) — a real
# reference is one that survives the strip.
H2_HITS=""
for f in "$SUPABASE_DIR"/migrations/*.sql; do
  if grep -v '^\s*--' "$f" | grep -q 'migration_owner'; then
    H2_HITS="$H2_HITS $f"
  fi
done
if [ -n "$H2_HITS" ]; then
  echo "tools/db/test.sh: FAILED (H2) — the migration file(s) below reference 'migration_owner' by name outside a comment; a real deploy has no such role (use CURRENT_USER instead):$H2_HITS" >&2
  exit 1
fi

run_as_pg "'$PG_BIN_DIR/createdb' -h '$PGSOCK' -p '$PGPORT' -U postgres '$DBNAME'"

echo "tools/db/test.sh: creating extensions (postgis, pgtap, pgcrypto)"
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -c \"CREATE EXTENSION IF NOT EXISTS postgis; CREATE EXTENSION IF NOT EXISTS pgtap; CREATE EXTENSION IF NOT EXISTS pgcrypto;\""

# H2 (post-P3a gate) dynamic check: a FULLY SEPARATE throwaway cluster
# (its own script manages its own initdb/start/stop), not a sibling
# database inside this cluster — confirmed empirically this session that
# sharing a cluster lets the check's own postgres-driven private_definer
# creation collide with the real restricted-mode run's later, idempotent
# one (roles are cluster-global, not per-database), breaking THAT run in
# a confusing way. See the script's own header for the full diagnosis.
echo "tools/db/test.sh: H2 check — migrations with no migration_owner role in the cluster (superuser)"
H2_MODE=superuser bash "$ROOT_DIR/tools/db/test-migrations-no-migration-owner.sh"
# should-fix (post-P3a re-gate): ALSO run it as a NOSUPERUSER CREATEROLE
# CREATEDB role that owns the database — approximating Supabase's real,
# non-superuser project `postgres` role, not just this harness's own
# cluster-bootstrap superuser. Sequential, same script, own fresh cluster
# each time (it tears its own down on exit) — see that script's own
# H2_MODE comment.
echo "tools/db/test.sh: H2 check — migrations with no migration_owner role in the cluster (approximation of Supabase's non-superuser postgres role)"
H2_MODE=approximation bash "$ROOT_DIR/tools/db/test-migrations-no-migration-owner.sh"

echo "tools/db/test.sh: applying supabase/tests/shim.sql"
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -f '$SUPABASE_DIR/tests/shim.sql'"

echo "tools/db/test.sh: applying migrations (as $DBUSER)"
for f in "$SUPABASE_DIR"/migrations/*.sql; do
  echo "  -> $(basename "$f")"
  run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U '$DBUSER' -v ON_ERROR_STOP=1 -d '$DBNAME' -f '$f'"
done

# SET ROLE service_role first, in the SAME session (`-c` before `-f` — psql
# runs multiple -c/-f actions in the order given, on one connection): these
# fixtures are wide, cross-actor test data with no natural per-row scope,
# and service_role already has full DML + BYPASSRLS (shim.sql) for exactly
# this "server-side/administrative write" shape — the same identity that
# would really write this data (Edge Functions running as service_role,
# 0009's own comment). Harmless under HARNESS_MODE=superuser (postgres
# already bypasses everything either way); necessary under `restricted`,
# where $DBUSER (migration_owner) now genuinely owns and is FORCE-RLS'd on
# every table these fixtures write to.
echo "tools/db/test.sh: seeding test fixtures (supabase/tests/helpers.sql, as service_role)"
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U '$DBUSER' -v ON_ERROR_STOP=1 -d '$DBNAME' -c 'SET ROLE service_role;' -f '$SUPABASE_DIR/tests/helpers.sql'"

echo "tools/db/test.sh: running the pgTAP authorization matrix (as $DBUSER)"
if command -v pg_prove >/dev/null 2>&1 || run_as_pg "command -v pg_prove" >/dev/null 2>&1; then
  run_as_pg "cd '$ROOT_DIR' && pg_prove --host '$PGSOCK' --port '$PGPORT' --username '$DBUSER' --dbname '$DBNAME' '$SUPABASE_DIR'/tests/matrix/*.sql"
else
  echo "tools/db/test.sh: pg_prove not found — falling back to psql + TAP-line inspection" >&2
  FAILED=0
  for f in "$SUPABASE_DIR"/tests/matrix/*.sql; do
    echo "  -> $(basename "$f")"
    OUTPUT="$(run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U '$DBUSER' -A -t -d '$DBNAME' -f '$f'" 2>&1)"
    echo "$OUTPUT"
    if echo "$OUTPUT" | grep -qE '^not ok|ERROR|Looks like you (failed|planned)'; then
      echo "FAILED: $f" >&2
      FAILED=1
    fi
  done
  if [ "$FAILED" -ne 0 ]; then
    exit 1
  fi
fi

echo "tools/db/test.sh: all pgTAP matrix files passed"

echo "tools/db/test.sh: replay/idempotency concurrency check (B4, AT(3), as $DBUSER)"
run_as_pg "PGHOST='$PGSOCK' PGPORT='$PGPORT' PGUSER='$DBUSER' PGDATABASE='$DBNAME' PATH=\"$PG_BIN_DIR:\$PATH\" bash '$ROOT_DIR/tools/db/test-replay-concurrency.sh'"

echo "tools/db/test.sh: money-path concurrency checks (H3 + should-fix, as $DBUSER)"
run_as_pg "PGHOST='$PGSOCK' PGPORT='$PGPORT' PGUSER='$DBUSER' PGDATABASE='$DBNAME' PATH=\"$PG_BIN_DIR:\$PATH\" bash '$ROOT_DIR/tools/db/test-money-path-concurrency.sh'"

echo "tools/db/test.sh: function inventory + search_path check (B2, standalone)"
PGHOST="$PGSOCK" PGPORT="$PGPORT" PGUSER=postgres PGDATABASE="$DBNAME" PATH="$PG_BIN_DIR:$PATH" \
  node "$ROOT_DIR/tools/db/verify-function-inventory.mjs"

# ⛔ FIX (should-fix, post-P3a gate): "test.sh must fail, not soft-skip,
# when the lint dist is missing." A missing/unbuilt dist/cli.js used to
# just print a warning and move on with exit 0 — a lint that silently
# never ran is indistinguishable, from this script's own exit code, from
# one that ran clean; CI's build step normally builds it first
# (.github/workflows/ci.yml), so hitting this path at all means
# something upstream already broke, and papering over that with a
# skip hides it. `command -v node` is still checked (a genuinely
# node-less environment is a different, honestly-reported failure, not
# this script's job to install Node), but a present Node with a missing
# dist is now a hard failure.
if ! command -v node >/dev/null 2>&1; then
  echo "tools/db/test.sh: FAILED — node is not on PATH, cannot run service-role-lint" >&2
  exit 1
fi
if [ ! -f "$ROOT_DIR/tools/service-role-lint/dist/cli.js" ]; then
  echo "tools/db/test.sh: FAILED — tools/service-role-lint/dist/cli.js is not built; run 'pnpm --filter @golfraven/service-role-lint build' first" >&2
  exit 1
fi
echo "tools/db/test.sh: service-role lint over supabase/functions (B5)"
node "$ROOT_DIR/tools/service-role-lint/dist/cli.js" "$SUPABASE_DIR/functions"
