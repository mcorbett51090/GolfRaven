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
# `migration_owner` by name at all, in EITHER direction, so a future
# migration can't reintroduce the same defect). This script proves it at
# runtime: it runs supabase/tests/shim.sql (which, in the harness, always
# creates `migration_owner` — see its own 1a comment), then REASSIGNS
# database ownership and DROPS that role before applying a single
# migration, so every migration file genuinely runs against a cluster
# where `migration_owner` does not exist — the real-deploy shape H2
# reproduced the failure against.
#
# Migrations only (no fixtures, no pgTAP matrix) — this is a fast,
# targeted pre-flight, not a second full harness run.
#
# Usage: PGHOST=... PGPORT=... PGUSER=postgres PGDATABASE=... PATH=...
#   bash tools/db/test-migrations-no-migration-owner.sh
# (tools/db/test.sh sets these and calls this script once, before the
# main HARNESS_MODE run, against its own throwaway cluster.)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUPABASE_DIR="$ROOT_DIR/supabase"

: "${PGHOST:?PGHOST must be set}"
: "${PGPORT:?PGPORT must be set}"
: "${PGUSER:?PGUSER must be set}"
: "${PGDATABASE:?PGDATABASE must be set}"

PSQL=(psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -v ON_ERROR_STOP=1 -q -d "$PGDATABASE")

echo "tools/db/test-migrations-no-migration-owner.sh: applying supabase/tests/shim.sql"
"${PSQL[@]}" -f "$SUPABASE_DIR/tests/shim.sql" >/dev/null

echo "tools/db/test-migrations-no-migration-owner.sh: dropping migration_owner (H2 — proving migrations don't need it)"
"${PSQL[@]}" -c "ALTER DATABASE \"$PGDATABASE\" OWNER TO $PGUSER;"
"${PSQL[@]}" -c "REASSIGN OWNED BY migration_owner TO $PGUSER;" || true
"${PSQL[@]}" -c "DROP OWNED BY migration_owner;" || true
"${PSQL[@]}" -c "DROP ROLE migration_owner;"

if "${PSQL[@]}" -c "SELECT 1 FROM pg_roles WHERE rolname = 'migration_owner'" -t -A | grep -q 1; then
  echo "tools/db/test-migrations-no-migration-owner.sh: FAILED — migration_owner still exists after DROP ROLE" >&2
  exit 1
fi

echo "tools/db/test-migrations-no-migration-owner.sh: applying migrations as '$PGUSER' with migration_owner ABSENT"
for f in "$SUPABASE_DIR"/migrations/*.sql; do
  echo "  -> $(basename "$f")"
  "${PSQL[@]}" -f "$f" >/dev/null
done

echo "tools/db/test-migrations-no-migration-owner.sh: PASS — every migration applied with no migration_owner role in the cluster"
