#!/usr/bin/env bash
# tools/db/spikes/partner-sig/run.sh
#
# Runs the database-side signature spike (docs/security/partner-auth-design.md, slice S0, PA-0c) on a THROWAWAY PostgreSQL cluster and prints the
# numbers: partner_sig_spike.sql (ES256 and RS256 verifiers in PL/pgSQL `numeric`, no extension) is loaded, gen-vectors.ts produces fresh real
# signatures and one-fault mutations of them, and bench.sql checks every verdict and times every call.
#
#   bash tools/db/spikes/partner-sig/run.sh            # 15 timed calls per vector
#   RUNS=40 bash tools/db/spikes/partner-sig/run.sh
#
# Needs: PostgreSQL 17 binaries (PG_BIN_DIR, default /usr/lib/postgresql/17/bin; the repo pins major 17) and `deno` (any 2.x; no network, no lockfile).
# It touches nothing but one directory (SPIKE_PG_DIR, default ${TMPDIR:-/tmp}/gr-s0-pg), which it creates, refuses to reuse, and deletes on exit. It
# is NOT part of CI or of tools/db/test.sh, and it never touches supabase/migrations or any database but its own. Exit status is non-zero when any
# algorithm fails the criterion (a wrong verdict, or a warm call at or above 200 ms) so a later device or CI session can use it as a gate.
#
# The cluster follows tools/db/test.sh's own conventions (initdb --auth=trust, a unix socket only, `su postgres` when run as root).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_BIN_DIR="${PG_BIN_DIR:-/usr/lib/postgresql/17/bin}"
PGPORT="${PGPORT:-5478}"
RUNS="${RUNS:-15}"
WORKDIR="${SPIKE_PG_DIR:-${TMPDIR:-/tmp}/gr-s0-pg}"
PGDATA="$WORKDIR/data"
PGSOCK="$WORKDIR/run"
DBNAME="spike_sig_db"

[ -x "$PG_BIN_DIR/initdb" ] || { echo "run.sh: no initdb in PG_BIN_DIR=$PG_BIN_DIR (set PG_BIN_DIR to a PostgreSQL 17 bin directory)" >&2; exit 2; }
command -v deno >/dev/null 2>&1 || { echo "run.sh: deno is not on PATH" >&2; exit 2; }
if [ -e "$WORKDIR" ]; then
  echo "run.sh: $WORKDIR already exists; refusing to reuse or delete it (remove it, or set SPIKE_PG_DIR)" >&2
  exit 2
fi

run_as_pg() {
  if [ "$(id -u)" -eq 0 ]; then
    su postgres -s /bin/bash -c "$*"
  else
    bash -c "$*"
  fi
}

STARTED=0
cleanup() {
  if [ "$STARTED" -eq 1 ]; then
    run_as_pg "'$PG_BIN_DIR/pg_ctl' -D '$PGDATA' -m fast stop" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$PGSOCK" "$PGDATA"
if [ "$(id -u)" -eq 0 ]; then
  chown -R postgres:postgres "$WORKDIR"
fi
chmod 700 "$PGDATA"

run_as_pg "'$PG_BIN_DIR/initdb' -D '$PGDATA' -U postgres --auth=trust >/dev/null"
run_as_pg "'$PG_BIN_DIR/pg_ctl' -D '$PGDATA' -l '$WORKDIR/postgres.log' -o \"-p $PGPORT -k '$PGSOCK' -c listen_addresses=''\" start" >/dev/null
STARTED=1
for _ in $(seq 1 30); do
  run_as_pg "'$PG_BIN_DIR/pg_isready' -h '$PGSOCK' -p '$PGPORT'" >/dev/null 2>&1 && break
  sleep 0.5
done
run_as_pg "'$PG_BIN_DIR/createdb' -h '$PGSOCK' -p '$PGPORT' -U postgres '$DBNAME'"

# every file goes in on stdin: the postgres OS user need not be able to read the checkout
psql_in() {
  run_as_pg "'$PG_BIN_DIR/psql' -h '$PGSOCK' -p '$PGPORT' -U postgres -d '$DBNAME' -X -q -v ON_ERROR_STOP=1 $* -f -"
}

echo "run.sh: $("$PG_BIN_DIR/postgres" --version), cluster at $PGDATA (port $PGPORT), $RUNS timed calls per vector"
echo "run.sh: loading the verifiers (no extension is created)"
psql_in < "$HERE/partner_sig_spike.sql" >/dev/null
echo "run.sh: generating vectors (real signatures, fresh keys)"
deno run --no-config --no-remote "$HERE/gen-vectors.ts" | psql_in >/dev/null
echo "run.sh: running the harness (this takes a minute)"
psql_in "-P pager=off -v runs=$RUNS" < "$HERE/bench.sql"

FAILS="$(run_as_pg "'$PG_BIN_DIR/psql' -h '$PGSOCK' -p '$PGPORT' -U postgres -d '$DBNAME' -X -tA -c 'SELECT count(*) FROM spike_sig.verdict WHERE NOT pass'")"
if [ "$FAILS" != "0" ]; then
  echo "run.sh: FAIL: $FAILS algorithm(s) did not meet the criterion (see the VERDICT table above)" >&2
  exit 1
fi
echo "run.sh: both algorithms met the criterion on this machine"
