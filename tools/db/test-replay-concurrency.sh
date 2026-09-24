#!/usr/bin/env bash
# tools/db/test-replay-concurrency.sh
#
# build plan §10 P3 AT(3) (docs/golf-trails/02-build-plan.md:2759): "A
# replayed evidence payload yields one row and one play." B4 (gate round
# 2): "Add an AT(3) test: a replayed payload, sequential and concurrent
# (two sessions), gives exactly 1 evidence row and 1 play."
#
# pgTAP tests run inside ONE transaction on ONE connection, so they cannot
# exercise a genuine two-session race — this script is the part of AT(3)
# that needs two REAL, concurrent psql connections. It simulates the
# idempotent-insert shape an ingestion Edge Function is specified to use
# (INSERT ... ON CONFLICT ... DO NOTHING, keyed on the constraints B4's
# other fix — evidence.source_ref NOT NULL — makes meaningful) directly
# against a running database.
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash
#   tools/db/test-replay-concurrency.sh
# (tools/db/test.sh sets these and calls this script after the pgTAP
# matrix, against the same throwaway cluster/database, before teardown.)

set -euo pipefail

# S1 restricted-mode fix: this script's INSERTs simulate an ingestion Edge
# Function, whose real production identity is service_role (matching
# 09_delete_my_data.sql / 07_rate_limit.sql's own fix, same session) — not
# whatever PGUSER the harness connects as. Under HARNESS_MODE=restricted
# that connecting role is migration_owner (NOSUPERUSER NOBYPASSRLS, no
# grants on app.evidence/app.play), so without this these INSERTs would
# fail on a table with FORCE ROW LEVEL SECURITY and no matching policy.
# `-c` flags run as sequential statements on ONE session, so this ONE
# extra `-c` covers every call site below without editing each one.
PSQL=(psql -v ON_ERROR_STOP=1 -A -t -q -c "SET ROLE service_role;")
USER_ID="00000000-0000-0000-0000-00000000000a"
DEVICE_ID="20000000-0000-0000-0000-000000000001"
FAILED=0

count() {
  "${PSQL[@]}" -c "$1" | tr -d '[:space:]'
}

echo "tools/db/test-replay-concurrency.sh: seeding a fresh evidence source_ref"
SOURCE_REF="concurrency-test-$(date +%s%N)"

# ---------------------------------------------------------------------------
# 1. Sequential replay: the SAME payload inserted twice, one after the
#    other, must yield exactly one row.
# ---------------------------------------------------------------------------
"${PSQL[@]}" -c "
  INSERT INTO app.evidence (user_id, device_id, source, source_ref, status, catalog_version)
  VALUES ('$USER_ID', '$DEVICE_ID', 'foreground_checkin', '${SOURCE_REF}-seq', 'accepted', 1)
  ON CONFLICT (user_id, source, source_ref) DO NOTHING;
" >/dev/null
"${PSQL[@]}" -c "
  INSERT INTO app.evidence (user_id, device_id, source, source_ref, status, catalog_version)
  VALUES ('$USER_ID', '$DEVICE_ID', 'foreground_checkin', '${SOURCE_REF}-seq', 'accepted', 1)
  ON CONFLICT (user_id, source, source_ref) DO NOTHING;
" >/dev/null
N=$(count "SELECT count(*) FROM app.evidence WHERE user_id = '$USER_ID' AND source_ref = '${SOURCE_REF}-seq'")
if [ "$N" != "1" ]; then
  echo "FAIL: sequential replay of the same evidence source_ref produced $N rows, expected 1" >&2
  FAILED=1
else
  echo "PASS: sequential replay -> exactly 1 evidence row"
fi

# ---------------------------------------------------------------------------
# 2. Concurrent replay: TWO real, simultaneous connections racing the same
#    insert. Both are launched together (backgrounded, then waited on) so
#    they genuinely overlap rather than serializing at the client.
# ---------------------------------------------------------------------------
CONC_REF="${SOURCE_REF}-conc"
INSERT_SQL="INSERT INTO app.evidence (user_id, device_id, source, source_ref, status, catalog_version)
  VALUES ('$USER_ID', '$DEVICE_ID', 'foreground_checkin', '$CONC_REF', 'accepted', 1)
  ON CONFLICT (user_id, source, source_ref) DO NOTHING;"

"${PSQL[@]}" -c "$INSERT_SQL" >/dev/null &
PID1=$!
"${PSQL[@]}" -c "$INSERT_SQL" >/dev/null &
PID2=$!
wait "$PID1" "$PID2"

N=$(count "SELECT count(*) FROM app.evidence WHERE user_id = '$USER_ID' AND source_ref = '$CONC_REF'")
if [ "$N" != "1" ]; then
  echo "FAIL: concurrent replay (2 real sessions) of the same evidence source_ref produced $N rows, expected 1" >&2
  FAILED=1
else
  echo "PASS: concurrent replay (2 real sessions) -> exactly 1 evidence row"
fi

# ---------------------------------------------------------------------------
# 3. The same shape for `play` — its own idempotency key is
#    unique(user_id, course_id, play_date), already NOT-NULL-safe (no
#    nullable column in that tuple, unlike evidence's source_ref before
#    the B4 fix).
# ---------------------------------------------------------------------------
PLAY_DATE=$(date -u +%Y-%m-%d)
PLAY_SQL="INSERT INTO app.play (user_id, course_id, facility_id, play_date, policy_version, status)
  VALUES ('$USER_ID', 'crs_y1', 'fac_y', '$PLAY_DATE', 'concurrency-test-v1', 'confirmed')
  ON CONFLICT (user_id, course_id, play_date) DO NOTHING;"

"${PSQL[@]}" -c "$PLAY_SQL" >/dev/null &
PID3=$!
"${PSQL[@]}" -c "$PLAY_SQL" >/dev/null &
PID4=$!
wait "$PID3" "$PID4"

N=$(count "SELECT count(*) FROM app.play WHERE user_id = '$USER_ID' AND course_id = 'crs_y1' AND play_date = '$PLAY_DATE'")
if [ "$N" != "1" ]; then
  echo "FAIL: concurrent replay (2 real sessions) of the same play key produced $N rows, expected 1" >&2
  FAILED=1
else
  echo "PASS: concurrent replay (2 real sessions) -> exactly 1 play row"
fi

# Clean up (this script runs against the shared throwaway DB, before
# tools/db/test.sh tears the whole cluster down anyway, but leave no trace
# in case a future step reuses the same database within one run).
"${PSQL[@]}" -c "DELETE FROM app.evidence WHERE user_id = '$USER_ID' AND source_ref LIKE '${SOURCE_REF}%';" >/dev/null
"${PSQL[@]}" -c "DELETE FROM app.play WHERE user_id = '$USER_ID' AND course_id = 'crs_y1' AND play_date = '$PLAY_DATE';" >/dev/null

if [ "$FAILED" -ne 0 ]; then
  echo "tools/db/test-replay-concurrency.sh: FAILED" >&2
  exit 1
fi
echo "tools/db/test-replay-concurrency.sh: all replay/idempotency checks passed"
