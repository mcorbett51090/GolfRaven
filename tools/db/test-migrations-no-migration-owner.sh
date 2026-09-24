#!/usr/bin/env bash
# tools/db/test-migrations-no-migration-owner.sh
#
# H2 (post-P3a gate): "0016:64 and 0017:307-309 depend on the harness-only
# role migration_owner, so a real deploy fails at 0016. ... Add a CI or
# harness check that applies the migrations as a superuser on a cluster
# with no migration_owner role."
#
# This is the dynamic half of that check (the static half is the grep in
# tools/db/test.sh: no supabase/migrations/*.sql file may reference
# `migration_owner` by name at all, outside a comment). It proves it at
# runtime: it runs supabase/tests/shim.sql (which, in the harness, always
# creates `migration_owner` — see its own 1a comment), then REASSIGNS
# database ownership and DROPS that role before applying a single
# migration, so every migration file genuinely runs against a cluster
# where `migration_owner` does not exist — the real-deploy shape H2
# reproduced the failure against.
#
# ⛔ Runs in its OWN, fully separate throwaway Postgres cluster (its own
# initdb, own port), not a sibling database inside test.sh's main
# cluster. Confirmed empirically this session why that matters:
# PostgreSQL roles are CLUSTER-GLOBAL, not per-database — an earlier
# version of this script ran against a second database in the SAME
# cluster as the main HARNESS_MODE run, and 0016's own `CREATE ROLE
# private_definer` there (run as postgres, superuser, for THIS check)
# left a private_definer role that then ALREADY EXISTED, globally, by
# the time the real restricted-mode run reached its own (idempotent,
# `IF NOT EXISTS`) private_definer creation in 0016 against $DBNAME — so
# 0016's role-creation step silently skipped, leaving the REAL run's
# fresh migration_owner with no admin_option on a private_definer role
# someone else (postgres, in this check) actually created, and the very
# next statement (`GRANT private_definer TO CURRENT_USER`) failed with
# "permission denied to grant role ... Only roles with the ADMIN option
# ... may grant this role" — reproduced and diagnosed this session. A
# fully separate cluster has no such cross-contamination path.
#
# Migrations only (no fixtures, no pgTAP matrix) — this is a fast,
# targeted pre-flight, not a second full harness run.
#
# Usage: PG_BIN_DIR=... bash tools/db/test-migrations-no-migration-owner.sh
# (tools/db/test.sh calls this once, before the main HARNESS_MODE run.)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPABASE_DIR="$ROOT_DIR/supabase"

PG_BIN_DIR="${PG_BIN_DIR:-}"
if [ -z "$PG_BIN_DIR" ]; then
  if command -v pg_config >/dev/null 2>&1 && [ -x "$(pg_config --bindir 2>/dev/null)/initdb" ]; then
    PG_BIN_DIR="$(pg_config --bindir)"
  elif [ -d /usr/lib/postgresql/16/bin ]; then
    PG_BIN_DIR="/usr/lib/postgresql/16/bin"
  else
    echo "tools/db/test-migrations-no-migration-owner.sh: cannot find a PostgreSQL 16 bin directory (set PG_BIN_DIR)" >&2
    exit 1
  fi
fi

PGPORT="${H2_PGPORT:-5488}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/golfraven-db-test-h2.XXXXXX")"
PGDATA="$WORKDIR/data"
PGSOCK="$WORKDIR/run"
DBNAME="golfraven_h2_no_owner"

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

mkdir -p "$PGSOCK"
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p "$PGDATA"
  chown -R postgres:postgres "$WORKDIR"
  chmod 700 "$PGDATA"
fi

run_as_pg "'$PG_BIN_DIR/initdb' -D '$PGDATA' -U postgres --auth=trust >/dev/null"
run_as_pg "'$PG_BIN_DIR/pg_ctl' -D '$PGDATA' -l '$WORKDIR/postgres.log' -o \"-p $PGPORT -k '$PGSOCK' -c listen_addresses=''\" start"
PG_CTL_STARTED=1

for _ in $(seq 1 30); do
  if run_as_pg "'$PG_BIN_DIR/pg_isready' -h '$PGSOCK' -p '$PGPORT'" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

PSQL=("$PG_BIN_DIR/psql" -h "$PGSOCK" -p "$PGPORT" -U postgres -v ON_ERROR_STOP=1 -q)

run_as_pg "'$PG_BIN_DIR/createdb' -h '$PGSOCK' -p '$PGPORT' -U postgres '$DBNAME'"
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -c \"CREATE EXTENSION IF NOT EXISTS postgis; CREATE EXTENSION IF NOT EXISTS pgtap; CREATE EXTENSION IF NOT EXISTS pgcrypto;\""

echo "tools/db/test-migrations-no-migration-owner.sh: applying supabase/tests/shim.sql"
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -f '$SUPABASE_DIR/tests/shim.sql'" >/dev/null

echo "tools/db/test-migrations-no-migration-owner.sh: dropping migration_owner (H2 — proving migrations don't need it)"
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -c \"ALTER DATABASE \\\"$DBNAME\\\" OWNER TO postgres;\""
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -d '$DBNAME' -c 'REASSIGN OWNED BY migration_owner TO postgres;'" || true
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -d '$DBNAME' -c 'DROP OWNED BY migration_owner;'" || true
run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -c 'DROP ROLE migration_owner;'"

STILL_EXISTS=$(run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -d '$DBNAME' -t -A -c \"SELECT 1 FROM pg_roles WHERE rolname = 'migration_owner'\"")
if [ "$STILL_EXISTS" = "1" ]; then
  echo "tools/db/test-migrations-no-migration-owner.sh: FAILED — migration_owner still exists after DROP ROLE" >&2
  exit 1
fi

echo "tools/db/test-migrations-no-migration-owner.sh: applying migrations as postgres with migration_owner ABSENT"
for f in "$SUPABASE_DIR"/migrations/*.sql; do
  echo "  -> $(basename "$f")"
  run_as_pg "'${PSQL[0]}' -h '$PGSOCK' -p '$PGPORT' -U postgres -v ON_ERROR_STOP=1 -d '$DBNAME' -f '$f'" >/dev/null
done

echo "tools/db/test-migrations-no-migration-owner.sh: PASS — every migration applied with no migration_owner role in the cluster"
