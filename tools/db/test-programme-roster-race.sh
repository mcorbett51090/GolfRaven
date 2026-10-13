#!/usr/bin/env bash
# tools/db/test-programme-roster-race.sh
#
# P5 section 140 (0110): "a roster change racing the programme editor". The editor (private.partner_facility_programme_upsert_for_partner) refuses a facility that is not on the trail's LATEST roster
# version. pgTAP runs inside ONE transaction on ONE connection, so it cannot show what happens when the importer commits a new roster version while an upsert is in flight; this script is the part that
# needs TWO REAL, concurrent sessions. The ACTION session is a real `edge_gateway` login (trust-authenticated in the harness cluster) that switches to edge_partner, binds a real partner session (an
# operator of the test trail, at aal 2 with a live second factor) and calls the definer; the IMPORTER session is the harness role acting as service_role, writing roster versions the way the catalogue
# importer does (a new version row and its members, in one transaction).
#
# WHAT THE CHECK RELIES ON (stated, then proved below):
#   * READ COMMITTED. partner_authorize, the first statement of the definer, refuses any other isolation level (42501), so the roster is always read in the snapshot of the CHECK'S OWN statement, never in
#     an older transaction snapshot.
#   * The check takes no lock on any roster row. A roster version is immutable and is written whole in one transaction, so a reader sees either the old latest version or the new one, never half of one.
#   * Consequence, and the one thing it does NOT promise: an upsert that passes the check and commits just BEFORE the importer commits a version that drops the facility leaves a programme row for a facility
#     that is no longer on the roster. That is the same state "upsert, then import" produces serially (an import never deletes programme rows), so it is not a race the editor can or should close; the owner's
#     off-roster query (tools/db/facility-programme-off-roster.sql) lists such rows.
#
#   R1. REPEATABLE READ is refused by the definer (42501): the roster can never be judged against a stale transaction snapshot. READ COMMITTED (control) passes.
#   R2. An importer transaction that has written a new latest version (dropping facility A, adding B) and is still OPEN: the upsert for A is ok and does NOT wait for it (it finishes before the importer
#       commits); the upsert for B is refused (the open version is not visible). After the importer commits, A is refused and B is accepted; the row written in between stays as it was.
#   R3. A version committed AFTER the action has bound its session and BEFORE it calls the definer is seen by the call (it is refused), while the same sequence with no importer is ok: the check is made at
#       the CALL, not at BEGIN.
#   R4. The editor never makes an import wait: an upsert transaction held open after a successful write does not block the importer, which commits a new version while it is open (no lock wait seen in
#       pg_locks).
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash tools/db/test-programme-roster-race.sh
# (tools/db/test.sh calls it with the harness role in PGUSER, after the stock concurrency step, against the same throwaway cluster and database.)
# No secret: ids are synthetic, the session token hash is random per run and the edge login is trust-authenticated in this cluster. Re-runnable: everything it commits is removed by the EXIT trap, except the
# audit_log rows its successful upserts write (that table is insert-only by trigger).

set -euo pipefail

: "${PGHOST:?tools/db/test-programme-roster-race.sh: PGHOST must be set}"
: "${PGPORT:?}"
: "${PGUSER:?}"
: "${PGDATABASE:?}"

HARNESS_PSQL=(psql -v ON_ERROR_STOP=1 -A -t -q)
IMP_PSQL=(env PGAPPNAME=race_imp psql -v ON_ERROR_STOP=1 -A -t -q)
FAILED=0
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/golfraven-roster-race.XXXXXX")"

U="ee40f000-0000-0000-0000-0000000000a1"; ORG="ee40f000-0000-0000-0000-0000000000b1"; CRED="ee40f000-0000-0000-0000-0000000000c1"; SESS="ee40f000-0000-0000-0000-0000000000d1"
TRAIL="trl_race140"; FA="fac_race140_a"; FB="fac_race140_b"; FC="fac_race140_c"; FD="fac_race140_d"
TH="$(printf '%s' "race140-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"

hq() { "${HARNESS_PSQL[@]}" -c "$1" | tr -d '[:space:]'; }
hx() { "${HARNESS_PSQL[@]}" -c "$1" >/dev/null; }
edge() { env PGAPPNAME="$1" PGUSER=edge_gateway psql -v ON_ERROR_STOP=1 -A -t -q; }
epoch() { hq "SELECT extract(epoch FROM clock_timestamp())"; }
fail() { echo "FAIL: $*" >&2; FAILED=1; }

# The access this script grants CURRENT_USER is temporary; never taken back from a role that OWNS the table (the owner's implicit privileges are not the script's to remove).
revoke_temp_grants() {
  local t
  for t in "$@"; do
    hx "DO \$\$ BEGIN IF (SELECT relowner FROM pg_class WHERE oid = '$t'::regclass) IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname = CURRENT_USER) THEN REVOKE ALL ON $t FROM CURRENT_USER; END IF; END \$\$;" 2>/dev/null || true
  done
}
cleanup() {
  set +e
  hx "ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg; ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;" 2>/dev/null
  hx "DELETE FROM app.partner_session WHERE id = '$SESS'; DELETE FROM app.partner_credential WHERE id = '$CRED';" 2>/dev/null
  hx "SET ROLE service_role;
      DELETE FROM app.facility_programme WHERE trail_id = '$TRAIL';
      DELETE FROM app.catalog_roster_member WHERE trail_id = '$TRAIL';
      DELETE FROM app.catalog_roster_version WHERE trail_id = '$TRAIL';
      DELETE FROM app.trail_programme WHERE trail_id = '$TRAIL';
      DELETE FROM app.partner_member WHERE org_id = '$ORG'; DELETE FROM app.partner_scope WHERE org_id = '$ORG'; DELETE FROM app.partner_org WHERE id = '$ORG';
      DELETE FROM app.catalog_course WHERE id LIKE 'crs_race140%';
      DELETE FROM app.catalog_facility WHERE id IN ('$FA', '$FB', '$FC', '$FD');
      DELETE FROM app.catalog_trail WHERE id = '$TRAIL';
      DELETE FROM app.catalog_id_ledger WHERE id IN ('$TRAIL', '$FA', '$FB', '$FC', '$FD') OR id LIKE 'crs_race140%';" 2>/dev/null
  hx "SET ROLE service_role; SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id = '$U';" 2>/dev/null
  hx "DROP POLICY IF EXISTS zz40r_cred ON app.partner_credential; DROP POLICY IF EXISTS zz40r_sess ON app.partner_session; DROP POLICY IF EXISTS zz40r_audit ON app.audit_log;" 2>/dev/null
  revoke_temp_grants app.partner_credential app.partner_session
  rm -rf "$OUT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Seed (committed; removed by the trap): a trail with a roster (version 1: facility A) and a programme, an operator of it with a live credential and a session at aal 2 with a live second factor.
# ---------------------------------------------------------------------------
hx "
  GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
  DROP POLICY IF EXISTS zz40r_cred ON app.partner_credential;
  DROP POLICY IF EXISTS zz40r_sess ON app.partner_session;
  CREATE POLICY zz40r_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  CREATE POLICY zz40r_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  SET ROLE service_role;
  INSERT INTO auth.users (id, email) VALUES ('$U', 'race140@partner.test') ON CONFLICT (id) DO NOTHING;
  INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES
    ('$TRAIL', 'trail', 'verified', 1), ('$FA', 'facility', 'verified', 1), ('$FB', 'facility', 'verified', 1), ('$FC', 'facility', 'verified', 1), ('$FD', 'facility', 'verified', 1);
  INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES ('$TRAIL', 'trl-race140', 'Race trail', 1);
  INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version) VALUES
    ('$FA', 'fac-race140-a', 'Race A', 'US-TN', 'America/Chicago', 1), ('$FB', 'fac-race140-b', 'Race B', 'US-TN', 'America/Chicago', 1),
    ('$FC', 'fac-race140-c', 'Race C', 'US-TN', 'America/Chicago', 1), ('$FD', 'fac-race140-d', 'Race D', 'US-TN', 'America/Chicago', 1);
  INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('$TRAIL', 1, 'facility', 'facility', now());
  INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, facility_id, stop_order) VALUES ('$TRAIL', 1, 'facility', '$FA', 1);
  INSERT INTO app.trail_programme (trail_id, status) VALUES ('$TRAIL', 'live');
  INSERT INTO app.partner_org (id, kind, name) VALUES ('$ORG', 'operator', 'race org');
  INSERT INTO app.partner_scope (org_id, trail_id) VALUES ('$ORG', '$TRAIL');
  INSERT INTO app.partner_member (user_id, org_id, role, created_at) VALUES ('$U', '$ORG', 'operator', now() - interval '60 days');
  RESET ROLE;
  INSERT INTO app.partner_credential (id, user_id, credential_id, public_key, alg)
    VALUES ('$CRED', '$U', decode(md5('race140-c') || md5('race140-cb'), 'hex'), decode(md5('race140-k') || md5('race140-kb'), 'hex'), -7);"
# the INSERT guard (S1.1a gate M2) refuses a back-dated session; off for the seeding only
hx "ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;"
hx "INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
    VALUES ('$SESS', '$TH', '$U', '$CRED', 1, now() - interval '1 hour', now(), now() + interval '8 hours', 'sign_in', decode(md5('race140-n') || md5('race140-nb'), 'hex'),
            decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'));"
hx "ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;"
# step-up state a session cannot be born with (aal 2 and a live second factor, class A3): written by the owner with the update guard off for that statement only
hx "ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg; UPDATE app.partner_session SET aal = 2, mfa_until = now() + interval '40 minutes' WHERE id = '$SESS'; ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;"
hx "GRANT SELECT ON app.audit_log TO CURRENT_USER; DROP POLICY IF EXISTS zz40r_audit ON app.audit_log; CREATE POLICY zz40r_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);"

# an upsert of facility $2 as the bound operator, in a transaction that is bound first, then waits $1 seconds, calls the definer, then holds $3 seconds more
action_sql() { # $1 = seconds to wait BEFORE the call, $2 = facility id, $3 = seconds to hold the transaction open AFTER the call, $4 = optional isolation clause
  cat <<SQL
BEGIN ${4:-};
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session('$TH');
SELECT pg_sleep($1);
SELECT 'called:' || extract(epoch FROM clock_timestamp());
SELECT 'status:' || o_status FROM private.partner_facility_programme_upsert_for_partner('$TRAIL', '$2', 'accepted', true, false, 'ok', true, NULL, 'rotating');
SELECT 'done:' || extract(epoch FROM clock_timestamp());
SELECT pg_sleep($3);
SELECT 'action_end:' || extract(epoch FROM clock_timestamp());
COMMIT;
SQL
}
status_of() { sed -n 's/^status://p' "$1" | head -1; }
refused() { grep -q "the facility must be on the current roster of this trail" "$1"; }
roster_version_sql() { # $1 = version, $2 = facility id (or '') of its single member, $3 = seconds to hold the importer transaction open BEFORE the commit
  cat <<SQL
BEGIN;
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('$TRAIL', $1, 'facility', 'facility', now());
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, facility_id, stop_order) SELECT '$TRAIL', $1, 'facility', f, 1 FROM (SELECT NULLIF('$2', '') AS f) x WHERE f IS NOT NULL;
SELECT 'imported:' || extract(epoch FROM clock_timestamp());
SELECT pg_sleep($3);
SELECT 'import_end:' || extract(epoch FROM clock_timestamp());
COMMIT;
SQL
}
programme_row() { hq "SET ROLE service_role; SELECT participation::text || '/' || qr_mode::text FROM app.facility_programme WHERE trail_id = '$TRAIL' AND facility_id = '$1'" | tail -1; }
before_after() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a != "" && b != "" && a < b) }'; }

# ---------------------------------------------------------------------------
# R1. REPEATABLE READ is refused; READ COMMITTED (control) passes
# ---------------------------------------------------------------------------
echo "tools/db/test-programme-roster-race.sh: R1. REPEATABLE READ is refused by the definer"
set +e
action_sql 0 "$FA" 0 "ISOLATION LEVEL REPEATABLE READ" | edge race_a >"$OUT_DIR/r1.out" 2>"$OUT_DIR/r1.err"; RR=$?
action_sql 0 "$FA" 0 | edge race_a >"$OUT_DIR/r1c.out" 2>"$OUT_DIR/r1c.err"; RC=$?
set -e
if [ "$RR" -eq 0 ] || ! grep -q "requires a READ COMMITTED transaction" "$OUT_DIR/r1.err"; then fail "R1: the upsert under REPEATABLE READ was not refused with 'requires a READ COMMITTED transaction' (exit $RR): $(cat "$OUT_DIR/r1.err")"
elif [ "$RC" -ne 0 ] || [ "$(status_of "$OUT_DIR/r1c.out")" != "ok" ]; then fail "R1: the READ COMMITTED control was not ok (exit $RC): $(cat "$OUT_DIR/r1c.err")"
else echo "PASS: R1 -> REPEATABLE READ is refused (42501), so the roster is only ever read in the snapshot of the check's own statement; READ COMMITTED (control) writes the row for facility A"; fi

# ---------------------------------------------------------------------------
# R2. An importer transaction that is still OPEN (version 2: B only) is neither seen nor waited for
# ---------------------------------------------------------------------------
echo "tools/db/test-programme-roster-race.sh: R2. an open importer transaction is neither seen nor waited for"
roster_version_sql 2 "$FB" 4 | "${IMP_PSQL[@]}" >"$OUT_DIR/imp2.out" 2>"$OUT_DIR/imp2.err" &
PI=$!
sleep 1.2 # the importer has written version 2 and holds its transaction open
set +e
action_sql 0 "$FA" 0 | edge race_a >"$OUT_DIR/r2a.out" 2>"$OUT_DIR/r2a.err"; SA=$?
action_sql 0 "$FB" 0 | edge race_a >"$OUT_DIR/r2b.out" 2>"$OUT_DIR/r2b.err"; SB=$?
set -e
A_DONE=$(sed -n 's/^done://p' "$OUT_DIR/r2a.out")
OPEN_NOW=$(hq "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'race_imp' AND state <> 'idle'")
set +e; wait "$PI"; SI=$?; set -e
I_END=$(sed -n 's/^import_end://p' "$OUT_DIR/imp2.out")
if [ "$SI" -ne 0 ]; then fail "R2: the importer transaction failed: $(cat "$OUT_DIR/imp2.err")"
elif [ "$SA" -ne 0 ] || [ "$(status_of "$OUT_DIR/r2a.out")" != "ok" ]; then fail "R2: the upsert for A (on version 1, the latest COMMITTED version) was not ok while version 2 was open: $(cat "$OUT_DIR/r2a.err")"
elif [ "$OPEN_NOW" != "1" ] || ! before_after "$A_DONE" "$I_END"; then fail "R2: the upsert for A finished at $A_DONE, not before the importer committed at $I_END (it waited for the open transaction, or the importer was not open: $OPEN_NOW)"
elif [ "$SB" -eq 0 ] || ! refused "$OUT_DIR/r2b.err"; then fail "R2: the upsert for B was not refused while version 2 was uncommitted (exit $SB): $(cat "$OUT_DIR/r2b.out" "$OUT_DIR/r2b.err")"
else
  echo "PASS: R2a -> while an importer transaction (version 2: B only) was open, the upsert for A was ok and finished BEFORE the importer committed (it did not wait), and the upsert for B was refused (version 2 is not visible)"
  # after the commit the new latest version rules: A is refused, B is accepted, and A's row (written in between) is untouched
  set +e
  action_sql 0 "$FA" 0 | edge race_a >"$OUT_DIR/r2c.out" 2>"$OUT_DIR/r2c.err"; SC=$?
  action_sql 0 "$FB" 0 | edge race_a >"$OUT_DIR/r2d.out" 2>"$OUT_DIR/r2d.err"; SD=$?
  set -e
  if [ "$SC" -eq 0 ] || ! refused "$OUT_DIR/r2c.err"; then fail "R2: after the importer committed version 2 the upsert for A was not refused (exit $SC)"
  elif [ "$SD" -ne 0 ] || [ "$(status_of "$OUT_DIR/r2d.out")" != "ok" ]; then fail "R2: after the importer committed version 2 the upsert for B was not ok: $(cat "$OUT_DIR/r2d.err")"
  elif [ "$(programme_row "$FA")" != "accepted/rotating" ]; then fail "R2: facility A's row (written while version 1 was latest) is not as written: $(programme_row "$FA")"
  else echo "PASS: R2b -> once version 2 committed, A is refused and B accepted; A's row, written in between, is left as it was (the state 'upsert, then import' also produces)"; fi
fi

# ---------------------------------------------------------------------------
# R3. A version committed AFTER the action bound its session and BEFORE it calls the definer is seen by the call
# ---------------------------------------------------------------------------
echo "tools/db/test-programme-roster-race.sh: R3. the check is made at the call, not at BEGIN"
# control: no importer; version 2 (B) is latest, so B after a 2.5 s wait is ok
action_sql 2.5 "$FB" 0 | edge race_a >"$OUT_DIR/r3c.out" 2>"$OUT_DIR/r3c.err" || true
action_sql 2.5 "$FB" 0 | edge race_a >"$OUT_DIR/r3.out" 2>"$OUT_DIR/r3.err" &
PA=$!
sleep 0.8 # the action has begun and bound; it is sleeping before the call
roster_version_sql 3 "$FC" 0 | "${IMP_PSQL[@]}" >"$OUT_DIR/imp3.out" 2>"$OUT_DIR/imp3.err"
set +e; wait "$PA"; S3=$?; set -e
if [ "$(status_of "$OUT_DIR/r3c.out")" != "ok" ]; then fail "R3: the control (no importer) was not ok: $(cat "$OUT_DIR/r3c.err")"
elif [ "$S3" -eq 0 ] || ! refused "$OUT_DIR/r3.err"; then fail "R3: version 3 (C only) committed while the action slept, and the call for B was still accepted (exit $S3): $(cat "$OUT_DIR/r3.out" "$OUT_DIR/r3.err")"
else echo "PASS: R3 -> the control (no importer) is ok; with version 3 committed between the bind and the call, the same call is refused: the roster is read when the definer runs, not when the transaction began"; fi

# ---------------------------------------------------------------------------
# R4. The editor never makes an import wait
# ---------------------------------------------------------------------------
echo "tools/db/test-programme-roster-race.sh: R4. an open upsert transaction does not block the importer"
action_sql 0 "$FC" 4 | edge race_a >"$OUT_DIR/r4.out" 2>"$OUT_DIR/r4.err" &
PA=$!
sleep 1.5 # the upsert for C (latest version 3: C) has written its row and holds its transaction open
IM_START=$(epoch)
roster_version_sql 4 "$FD" 0 | "${IMP_PSQL[@]}" >"$OUT_DIR/imp4.out" 2>"$OUT_DIR/imp4.err" &
PB=$!
WAITED=no
for _ in $(seq 1 10); do
  n=$(hq "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE a.application_name = 'race_imp' AND NOT l.granted")
  [ "$n" != "0" ] && { WAITED=yes; break; }
  sleep 0.1
done
set +e; wait "$PB"; SB=$?; wait "$PA"; SA=$?; set -e
IM_END=$(sed -n 's/^import_end://p' "$OUT_DIR/imp4.out"); A_END=$(sed -n 's/^action_end://p' "$OUT_DIR/r4.out")
if [ "$SA" -ne 0 ] || [ "$(status_of "$OUT_DIR/r4.out")" != "ok" ]; then fail "R4: the upsert for C was not ok: $(cat "$OUT_DIR/r4.err")"
elif [ "$SB" -ne 0 ]; then fail "R4: the importer failed: $(cat "$OUT_DIR/imp4.err")"
elif [ "$WAITED" = "yes" ]; then fail "R4: the importer was seen WAITING on a lock while the upsert transaction was open"
elif ! before_after "$IM_END" "$A_END"; then fail "R4: the importer committed at $IM_END, not before the upsert transaction ended at $A_END (it waited)"
else echo "PASS: R4 -> the importer wrote and committed version 4 while an upsert transaction was open: never seen waiting, and it finished before the upsert transaction did (the check takes no lock on the roster)"; fi

if [ "$FAILED" -ne 0 ]; then echo "tools/db/test-programme-roster-race.sh: FAILED" >&2; exit 1; fi
echo "tools/db/test-programme-roster-race.sh: all programme roster race cases passed"
