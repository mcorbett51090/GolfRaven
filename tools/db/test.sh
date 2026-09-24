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
  if command -v pg_config >/dev/null 2>&1 && [ -x "$(pg_config --bindir 2>/dev/null)/initdb" ]; then
    # `pg_config` itself commonly lives in /usr/bin as a thin wrapper, NOT
    # alongside initdb/pg_ctl/psql — always ask it for --bindir rather than
    # dirname-ing pg_config's own path (confirmed this session: on this
    # Debian/Ubuntu-style layout, pg_config is in /usr/bin while
    # initdb/pg_ctl live in /usr/lib/postgresql/16/bin).
    PG_BIN_DIR="$(pg_config --bindir)"
  elif [ -d /usr/lib/postgresql/16/bin ]; then
    PG_BIN_DIR="/usr/lib/postgresql/16/bin"
  else
    echo "tools/db/test.sh: cannot find a PostgreSQL 16 bin directory (set PG_BIN_DIR)" >&2
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

run_as_pg "'$PG_BIN_DIR/createdb' -h '$PGSOCK' -p '$PGPORT' -U postgres '$DBNAME'"

echo "tools/db/test.sh: creating extensions (postgis, pgtap, pgcrypto)"
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -c \"CREATE EXTENSION IF NOT EXISTS postgis; CREATE EXTENSION IF NOT EXISTS pgtap; CREATE EXTENSION IF NOT EXISTS pgcrypto;\""

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

echo "tools/db/test.sh: function inventory + search_path check (B2, standalone)"
PGHOST="$PGSOCK" PGPORT="$PGPORT" PGUSER=postgres PGDATABASE="$DBNAME" PATH="$PG_BIN_DIR:$PATH" \
  node "$ROOT_DIR/tools/db/verify-function-inventory.mjs"

if command -v node >/dev/null 2>&1 && [ -f "$ROOT_DIR/tools/service-role-lint/dist/cli.js" ]; then
  echo "tools/db/test.sh: service-role lint over supabase/functions (B5)"
  node "$ROOT_DIR/tools/service-role-lint/dist/cli.js" "$SUPABASE_DIR/functions"
else
  echo "tools/db/test.sh: tools/service-role-lint/dist/cli.js not built — run 'pnpm --filter @golfraven/service-role-lint build' first; skipping this step" >&2
fi
