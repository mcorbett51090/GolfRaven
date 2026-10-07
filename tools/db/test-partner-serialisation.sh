#!/usr/bin/env bash
# tools/db/test-partner-serialisation.sh
#
# P5.1a S1.1a (0047), PA-4 and PA-4c (the two-connection half): "an authority change cannot land half-way through a partner action". pgTAP runs inside ONE
# transaction on ONE connection, so it cannot show a WAIT; this script is the part that needs TWO REAL, concurrent sessions. The ACTION session is a real
# `edge_gateway` login (the harness cluster authenticates with `trust`, so no password is needed or used) that switches to edge_partner, binds a partner session
# and calls a planted `*_for_partner` definer, which goes through private.partner_authorize (the session row is locked FOR SHARE and held to commit); the CHANGE
# session is the migrating role, acting as service_role, revoking a member or deleting a scope. The lock is on the SESSION ROW and nothing else (partner-auth-design 4.2).
#
#   1. MEMBER REVOKE vs an open action: the action holds its transaction open; the revoke, issued from a second connection, WAITS (seen in pg_locks, by
#      application_name) and completes only after the action commits; the action itself succeeds (it started before the revoke); the session is then revoked
#      ('authority_changed') and the next bind is refused.
#   2. SCOPE DELETE vs an open action: the same shape; the delete WAITS, completes after the commit, TOUCHES the session without revoking it, and the next
#      authorize call is refused (no scope).
#   3. REVOKER FIRST: the revoke transaction holds the session lock (its trigger updated the row) and is held open; an action started meanwhile WAITS on the
#      lock, and when the revoke commits it SEES the revoke and is refused (42501) -- it never acts on stale authority.
#   4. THE PLANTED GUC: while an action is open the change session plants every GUC the repository has ever keyed a policy on; the action's reach is unchanged
#      (it still reads only its own session) -- an edge-reachable policy keyed on a settable GUC is the hard rule, and the single-connection half is PA-4c in
#      supabase/tests/matrix/25_partner_auth_spine.sql.
#
#   6. THE SIGN-IN MINT (S1.1b, 0048): real concurrent sessions as edge_gateway -> edge_partner_minter calling private.partner_session_mint with REAL ES256 assertions generated at run time by
#      supabase/tests/partner-sign-helpers.sql (no key is stored anywhere):
#        6a  PA-7: TWELVE concurrent mints of ONE challenge give exactly one `ok` and eleven `replayed`: one session, one used nonce, the counter advanced once.
#        6b  PA-9: the counter compare-and-set. A mints counter 9 and holds its transaction open; B (counter 8, a different challenge) WAITS on the credential row (pg_locks), then, once A commits,
#            is refused as `counter_regression`: the counter ends at 9, never 8. The refusal's alarm and audit rows are COMMITTED (read from another connection afterwards).
#        6c  PA-9: the same race with the HIGHER second counter (12, then 13): both succeed, in order; the counter ends at 13 and each made its session.
#        6d  the signature alarm commits with the refusal: a tampered signature returns `signature_invalid` and its alarm and audit rows are visible to another connection (a status, not a RAISE:
#            nothing rolled back), while no nonce was spent and no session exists.
#        6e  a credential revoked WHILE a mint waits on its row (the revoker holds the lock) is answered unknown_credential: no session, no counter move, no alarm.
#        6f  the 60-per-hour limit under concurrency: 8 concurrent mints at 58 sessions give exactly 2 ok and 6 rate_limited (60 sessions), a mint seen waiting on the credential row in pg_locks.
#      The audit_log rows these write cannot be deleted (the table is insert-only by trigger); the other rows are removed by the EXIT trap.
#
#   7. THE SIGN-IN FAILURE COUNTER UNDER CONCURRENCY (S1.3, the S1.2 gate's L1): THIRTY parallel private.partner_sign_in_failure_record calls for one credential count EXACTLY FOUR and answer `cooldown` to the other
#      twenty-six (the 5th failure starts the cooldown). Without the row lock (`FOR UPDATE`) concurrent calls read the same count and lose updates, so the case fails. The burst limit this leaves is stated in the design,
#      18.9: N concurrent forgeries are ALL VERIFIED before the cooldown applies (a CPU-only cost), because the cooldown is read by the lookup that precedes the verification.
#   8. THE STEP-UP PIN UNDER CONCURRENCY (S1.3, PA-18): TWENTY concurrent WRONG derived keys for one member evaluate at most five (here exactly three: the third starts the 30 s backoff, the other seventeen are refused
#      `retry_after` without being evaluated); with the PIN one failure from locking and no backoff running, twenty concurrent wrong keys lock it ONCE (one `locked` audit row, nineteen plain `locked`). Without the
#      row lock (`FOR UPDATE` in private.partner_pin_attempt) every call reads the same count and evaluates, so both cases fail.
#   9. SAME-SESSION CONCURRENCY (S1.3 gate LOW-1): eight parallel CORRECT verifies on ONE freshly-seen session all answer ok and none deadlocks. Under class A0 each call took the session row FOR SHARE and then
#      UPDATEd it (the grant): two FOR SHARE holders that both upgrade deadlock. Class A0_WRITE takes FOR NO KEY UPDATE up front, so the calls queue. 9b: the same for four deliberately overlapping session locks (class SESSION).
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash tools/db/test-partner-serialisation.sh
# (tools/db/test.sh calls it with the harness role in PGUSER, after the signin concurrency step, against the same throwaway cluster and database.)
# No secret: ids are synthetic; the session token hashes are random per run and the edge login is trust-authenticated in this cluster. Re-runnable: everything it
# commits is removed by the EXIT trap (a temporary CURRENT_USER policy on each FORCE-RLS table, and one planted definer).

set -euo pipefail

: "${PGHOST:?tools/db/test-partner-serialisation.sh: PGHOST must be set}"
: "${PGPORT:?}"
: "${PGUSER:?}"
: "${PGDATABASE:?}"

HARNESS_PSQL=(psql -v ON_ERROR_STOP=1 -A -t -q)
SVC_PSQL=(env PGAPPNAME=ser_b psql -v ON_ERROR_STOP=1 -A -t -q)
FAILED=0
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/golfraven-partner-ser.XXXXXX")"

ORG1="ee24f000-0000-0000-0000-0000000000a1"; ORG2="ee24f000-0000-0000-0000-0000000000a2"; ORG3="ee24f000-0000-0000-0000-0000000000a3"; ORG4="ee24f000-0000-0000-0000-0000000000a4"; ORG5="ee24f000-0000-0000-0000-0000000000a5"; ORG6="ee24f000-0000-0000-0000-0000000000a6"; ORG7="ee24f000-0000-0000-0000-0000000000a7"
U1="ee24f000-0000-0000-0000-0000000000b1"; U2="ee24f000-0000-0000-0000-0000000000b2"; U3="ee24f000-0000-0000-0000-0000000000b3"; U4="ee24f000-0000-0000-0000-0000000000b4"; U5="ee24f000-0000-0000-0000-0000000000b5"; U6="ee24f000-0000-0000-0000-0000000000b6"
C1="ee24f000-0000-0000-0000-0000000000c1"; C2="ee24f000-0000-0000-0000-0000000000c2"; C3="ee24f000-0000-0000-0000-0000000000c3"; C4="ee24f000-0000-0000-0000-0000000000c4"; C5="ee24f000-0000-0000-0000-0000000000c5"; C6="ee24f000-0000-0000-0000-0000000000c6"
S1="ee24f000-0000-0000-0000-0000000000d1"; S2="ee24f000-0000-0000-0000-0000000000d2"; S3="ee24f000-0000-0000-0000-0000000000d3"; S4="ee24f000-0000-0000-0000-0000000000d4"; S5="ee24f000-0000-0000-0000-0000000000d5"; S6="ee24f000-0000-0000-0000-0000000000d6"
H1="$(printf '%s' "ser1-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"
H2="$(printf '%s' "ser2-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"
H3="$(printf '%s' "ser3-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"
H4="$(printf '%s' "ser4-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"
H5="$(printf '%s' "ser5-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"
H6="$(printf '%s' "ser6-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"

hq() { "${HARNESS_PSQL[@]}" -c "$1" | tr -d '[:space:]'; }
hx() { "${HARNESS_PSQL[@]}" -c "$1" >/dev/null; }
edge() { env PGAPPNAME="$1" PGUSER=edge_gateway psql -v ON_ERROR_STOP=1 -A -t -q; }
epoch() { hq "SELECT extract(epoch FROM clock_timestamp())"; }

# The access this script grants CURRENT_USER is temporary, so the cleanup takes it back -- but never from a role that OWNS the table: the owner's implicit privileges are not the
# script's to remove, and `REVOKE ALL ... FROM CURRENT_USER` on an owned table strips them (after a restricted migration the owner holds arwdDxtm; the previous cleanup left it with
# none (gate N-3).
revoke_temp_grants() {
  local t
  for t in "$@"; do
    hx "DO \$\$ BEGIN IF (SELECT relowner FROM pg_class WHERE oid = '$t'::regclass) IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname = CURRENT_USER) THEN REVOKE ALL ON $t FROM CURRENT_USER; END IF; END \$\$;" 2>/dev/null
  done
}

cleanup() {
  set +e
  # one statement batch per concern: a refusal in one must not roll back the others
  hx "ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;" 2>/dev/null
  hx "SET ROLE private_definer; DROP FUNCTION IF EXISTS private.zz24s_action(text, text); DROP FUNCTION IF EXISTS private.zz24s_writer(uuid);" 2>/dev/null
  hx "DELETE FROM app.partner_session WHERE id::text LIKE 'ee24f000-%'; DELETE FROM app.partner_credential WHERE id::text LIKE 'ee24f000-%';" 2>/dev/null
  hx "SET ROLE service_role; DELETE FROM app.partner_member WHERE org_id::text LIKE 'ee24f000-%'; DELETE FROM app.partner_scope WHERE org_id::text LIKE 'ee24f000-%'; DELETE FROM app.partner_org WHERE id::text LIKE 'ee24f000-%';" 2>/dev/null
  hx "SET ROLE service_role; SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id::text LIKE 'ee24f000-%';" 2>/dev/null
  hx "DELETE FROM app.partner_session WHERE user_id::text LIKE 'ee26f000-%'; DELETE FROM app.partner_auth_challenge WHERE user_id::text LIKE 'ee26f000-%'; DELETE FROM app.partner_auth_alarm WHERE credential_id::text LIKE 'ee26f000-%'; DELETE FROM app.partner_credential WHERE user_id::text LIKE 'ee26f000-%';" 2>/dev/null
  hx "SET ROLE service_role; SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id::text LIKE 'ee26f000-%';" 2>/dev/null
  if [ "${RP_INSERTED:-0}" = 1 ]; then hx "DELETE FROM app.partner_rp_config;" 2>/dev/null; fi
  hx "DROP POLICY IF EXISTS zz26s_chal ON app.partner_auth_challenge; DROP POLICY IF EXISTS zz26s_alarm ON app.partner_auth_alarm; DROP POLICY IF EXISTS zz26s_rp ON app.partner_rp_config; DROP POLICY IF EXISTS zz26s_audit ON app.audit_log; " 2>/dev/null
  revoke_temp_grants app.partner_auth_challenge app.partner_auth_alarm app.partner_rp_config
  hx "DROP POLICY IF EXISTS zz24s_cred ON app.partner_credential; DROP POLICY IF EXISTS zz24s_sess ON app.partner_session; " 2>/dev/null
  revoke_temp_grants app.partner_credential app.partner_session
  hx "DELETE FROM app.partner_sign_in_failure WHERE credential_id::text LIKE 'ee26f000-%'; DELETE FROM app.partner_pin WHERE user_id::text LIKE 'ee24f000-%';" 2>/dev/null
  hx "DROP POLICY IF EXISTS zz27s_fail ON app.partner_sign_in_failure; DROP POLICY IF EXISTS zz28s_pin ON app.partner_pin;" 2>/dev/null
  revoke_temp_grants app.partner_sign_in_failure app.partner_pin
  rm -rf "$OUT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Seed (committed; removed by the trap). Four principals, each staff of its own facility org on fac_x, each with a live credential and a live session.
# ---------------------------------------------------------------------------
hx "
  GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
  DROP POLICY IF EXISTS zz24s_cred ON app.partner_credential;
  DROP POLICY IF EXISTS zz24s_sess ON app.partner_session;
  CREATE POLICY zz24s_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  CREATE POLICY zz24s_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  GRANT CREATE ON SCHEMA private TO private_definer;
  SET ROLE private_definer;
  CREATE OR REPLACE FUNCTION private.zz24s_action(p_fac text, p_class text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS \$z\$
  BEGIN
    RETURN private.partner_authorize(p_fac, NULL, ARRAY['staff']::app.partner_role[], p_class);
  END
  \$z\$;
  REVOKE EXECUTE ON FUNCTION private.zz24s_action(text, text) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION private.zz24s_action(text, text) TO edge_partner;
  CREATE OR REPLACE FUNCTION private.zz24s_writer(p_victim uuid) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS \$z\$
  DECLARE n int; v int;
  BEGIN
    UPDATE app.partner_session SET revoked_at = clock_timestamp(), revoke_reason = 'planted' WHERE id = p_victim;
    GET DIAGNOSTICS n = ROW_COUNT;
    SELECT count(*) INTO v FROM app.partner_session WHERE id = p_victim;
    RETURN 'rows=' || n || ' visible=' || v;
  END
  \$z\$;
  REVOKE EXECUTE ON FUNCTION private.zz24s_writer(uuid) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION private.zz24s_writer(uuid) TO edge_partner;
  RESET ROLE;
  REVOKE CREATE ON SCHEMA private FROM private_definer;
  SET ROLE service_role;
  INSERT INTO auth.users (id, email) VALUES ('$U1', 'ser1@partner.test'), ('$U2', 'ser2@partner.test'), ('$U3', 'ser3@partner.test'), ('$U4', 'ser4@partner.test'), ('$U5', 'ser5@partner.test'), ('$U6', 'ser6@partner.test')
    ON CONFLICT (id) DO NOTHING;
  INSERT INTO app.partner_org (id, kind, name) VALUES ('$ORG1', 'facility', 'ser org 1'), ('$ORG2', 'facility', 'ser org 2'), ('$ORG3', 'facility', 'ser org 3'), ('$ORG4', 'facility', 'ser org 4'), ('$ORG5', 'facility', 'ser org 5'), ('$ORG6', 'facility', 'ser org 6'), ('$ORG7', 'facility', 'ser org 7');
  INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$ORG1', 'fac_x'), ('$ORG2', 'fac_x'), ('$ORG3', 'fac_x'), ('$ORG4', 'fac_x'), ('$ORG5', 'fac_x');
  INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('$U1', '$ORG1', 'staff'), ('$U2', '$ORG2', 'staff'), ('$U3', '$ORG3', 'staff'), ('$U4', '$ORG1', 'staff'), ('$U5', '$ORG4', 'staff'), ('$U6', '$ORG5', 'staff');
  RESET ROLE;"
# the INSERT guards (S1.1a gate M2) refuse a back-dated session (S5 and S6 are last seen 5 minutes ago): off for the seeding only, back on right after
hx "ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;"
for n in 1 2 3 4 5 6; do
  eval "u=\$U$n; c=\$C$n; s=\$S$n; h=\$H$n"
  seen="now()"; { [ "$n" = 5 ] || [ "$n" = 6 ]; } && seen="now() - interval '5 minutes'"  # S5's last_seen_at is old enough that the action WRITES it (FOR NO KEY UPDATE path)
  hx "
    INSERT INTO app.partner_credential (id, user_id, credential_id, public_key, alg)
    VALUES ('$c', '$u', decode(md5('ser-c$n') || md5('ser-cb$n'), 'hex'), decode(md5('ser-k$n') || md5('ser-kb$n'), 'hex'), -7);
    INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash,
                                     mint_authenticator_data, mint_client_data_json, mint_signature)
    VALUES ('$s', '$h', '$u', '$c', 1, now() - interval '1 hour', $seen, now() + interval '8 hours', 'sign_in', decode(md5('ser-n$n') || md5('ser-nb$n'), 'hex'),
            decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'));"
done
hx "ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;"

action_sql() { # $1 = token hash, $2 = seconds to hold the transaction open after the authorize, $3 = optional extra statement
  cat <<SQL
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session('$1');
SELECT 'authorized:' || private.zz24s_action('fac_x', 'A0');
${3:-SELECT 1;}
SELECT pg_sleep($2);
SELECT 'action_end:' || extract(epoch FROM clock_timestamp());
COMMIT;
SQL
}

waits() { # $1 = application_name; polls up to ~3 s for that session to be waiting on a lock (pg_locks, not granted)
  local i n
  for i in $(seq 1 30); do
    n=$(hq "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE a.application_name = '$1' AND NOT l.granted")
    [ "$n" != "0" ] && { echo yes; return 0; }
    sleep 0.1
  done
  echo no
}

fail() { echo "FAIL: $*" >&2; FAILED=1; }
session_revoked() { hq "SELECT coalesce(revoked_at IS NOT NULL, false)::text FROM app.partner_session WHERE id = '$1'"; }
session_touched() { hq "SELECT coalesce(authority_touched_at IS NOT NULL, false)::text FROM app.partner_session WHERE id = '$1'"; }

run_change_after_action() { # $1 label, $2 token hash, $3 change SQL (run as service_role), $4 victim session id
  action_sql "$2" 4 | edge ser_a >"$OUT_DIR/a.out" 2>"$OUT_DIR/a.err" &
  local pa=$!
  sleep 1.0 # the action has bound, authorized and is sleeping with the session row FOR SHARE
  "${SVC_PSQL[@]}" -c "SET ROLE service_role; $3; SELECT 'change_end:' || extract(epoch FROM clock_timestamp());" >"$OUT_DIR/b.out" 2>"$OUT_DIR/b.err" &
  local pb=$!
  local w; w=$(waits ser_b)
  set +e; wait "$pa"; local sa=$?; wait "$pb"; local sb=$?; set -e
  local a_end b_end
  a_end=$(sed -n 's/^action_end://p' "$OUT_DIR/a.out"); b_end=$(sed -n 's/^change_end://p' "$OUT_DIR/b.out")
  if [ "$sa" -ne 0 ] || ! grep -q "^authorized:" "$OUT_DIR/a.out" || [ "$sb" -ne 0 ]; then
    fail "$1: expected the action to succeed (it began before the change) and the change to complete, got action=$sa change=$sb"; cat "$OUT_DIR/a.err" "$OUT_DIR/b.err" >&2 || true; return 1
  fi
  if [ "$w" != "yes" ]; then fail "$1: the change was never seen WAITING in pg_locks while the action was open"; return 1; fi
  if ! awk -v a="$a_end" -v b="$b_end" 'BEGIN { exit !(a != "" && b != "" && b >= a) }'; then
    fail "$1: the change completed (at $b_end) BEFORE the action committed (at $a_end)"; return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 1. A member REVOKE issued during an open action waits for it
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 1. member revoke during an open action"
if run_change_after_action "member revoke" "$H1" "UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '$U1'" "$S1"; then
  if [ "$(session_revoked "$S1")" != "true" ]; then fail "member revoke: the member's session was not revoked once the revoke committed"
  elif ! { NEXT1=$(printf '%s\n' "BEGIN;" "SET LOCAL ROLE edge_partner;" "SELECT private.bind_partner_session('$H1');" "COMMIT;" | edge ser_n 2>&1 || true); printf '%s' "$NEXT1" | grep -q partner_session_refused; }; then
    fail "member revoke: the revoked member's next bind was not refused"
  else
    echo "PASS: member revoke -> waited in pg_locks, completed only after the action committed, the session is revoked, the next bind is refused"
  fi
fi

# ---------------------------------------------------------------------------
# 2. A scope DELETE issued during an open action waits for it
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 2. scope delete during an open action"
if run_change_after_action "scope delete" "$H2" "DELETE FROM app.partner_scope WHERE org_id = '$ORG2'" "$S2"; then
  if [ "$(session_touched "$S2")" != "true" ] || [ "$(session_revoked "$S2")" != "false" ]; then
    fail "scope delete: expected the session TOUCHED and not revoked, got touched=$(session_touched "$S2") revoked=$(session_revoked "$S2")"
  else
    NEXT=$(printf '%s\n' "BEGIN;" "SET LOCAL ROLE edge_partner;" "SELECT private.bind_partner_session('$H2');" "SELECT private.zz24s_action('fac_x', 'A0');" "COMMIT;" | edge ser_n 2>&1 || true)
    if printf '%s' "$NEXT" | grep -q "partner_authorize: no scope"; then
      echo "PASS: scope delete -> waited in pg_locks, completed only after the action committed, touched (not revoked) the session, and the next authorize call is refused (no scope)"
    else
      fail "scope delete: the next call after the scope row went was not refused with 'no scope': $NEXT"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2b. The WRITE path: an action whose session was last seen more than a minute ago updates last_seen_at, so it locks FOR NO KEY UPDATE (not FOR SHARE); a member revoke
#     issued during it must wait just the same
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 2b. member revoke during an open WRITING action (FOR NO KEY UPDATE)"
if run_change_after_action "member revoke (write path)" "$H5" "UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '$U5'" "$S5"; then
  if [ "$(session_revoked "$S5")" != "true" ]; then fail "member revoke (write path): the member's session was not revoked once the revoke committed"
  else echo "PASS: member revoke during a writing action -> waited in pg_locks, completed only after the action committed, the session is revoked"; fi
fi

# ---------------------------------------------------------------------------
# 3. The REVOKER holds the session lock first: the action waits, then sees the revoke
# ---------------------------------------------------------------------------
revoker_first() { # $1 label, $2 token hash, $3 user id
  "${SVC_PSQL[@]}" -c "BEGIN; SET LOCAL ROLE service_role; UPDATE app.partner_member SET revoked_at = now() WHERE user_id = '$3'; SELECT pg_sleep(3.5); SELECT 'revoke_end:' || extract(epoch FROM clock_timestamp()); COMMIT;" >"$OUT_DIR/b.out" 2>"$OUT_DIR/b.err" &
  local pb=$!
  sleep 1.0 # the revoke's trigger has updated the session row: the lock is held
  action_sql "$2" 0 | edge ser_a >"$OUT_DIR/a.out" 2>"$OUT_DIR/a.err" &
  local pa=$!
  local w; w=$(waits ser_a)
  set +e; wait "$pa"; local sa=$?; wait "$pb"; local sb=$?; set -e
  if [ "$sb" -ne 0 ]; then fail "$1: the revoke transaction itself failed"; cat "$OUT_DIR/b.err" >&2 || true
  elif [ "$w" != "yes" ]; then fail "$1: the action was never seen WAITING in pg_locks while the revoker held the session lock"
  elif [ "$sa" -eq 0 ] || grep -q "^authorized:" "$OUT_DIR/a.out"; then fail "$1: the action was AUTHORIZED although the revoke committed first (stale authority)"
  elif ! grep -q "partner_authorize: the session is not live" "$OUT_DIR/a.err" && ! grep -q "partner_authorize: no active membership" "$OUT_DIR/a.err" && ! grep -q "partner_session_refused" "$OUT_DIR/a.err"; then
    fail "$1: the action was refused, but not for the revoke:"; cat "$OUT_DIR/a.err" >&2
  else
    echo "PASS: $1 -> the action waited in pg_locks and, once the revoke committed, was refused (it never acted on stale authority)"
  fi
}
echo "tools/db/test-partner-serialisation.sh: 3. the revoker holds the session lock; the action waits and then sees the revoke"
revoker_first "revoker first (read path)" "$H3" "$U3"
echo "tools/db/test-partner-serialisation.sh: 3b. the same, for an action that WRITES last_seen_at (the explicit FOR NO KEY UPDATE must be the first statement to wait)"
revoker_first "revoker first (write path)" "$H6" "$U6"

# ---------------------------------------------------------------------------
# 3c. The one-facility-scope invariant under CONCURRENT writers (S1.1a gate L8): two sessions each add a DIFFERENT facility scope to the SAME facility org (so the unique key cannot
#     help). Without the per-org advisory lock both commit and the org holds two scopes; with it the second WAITS (seen in pg_locks) and then sees the first's row and is refused.
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 3c. two concurrent scope inserts for one facility org"
env PGAPPNAME=ser_a psql -v ON_ERROR_STOP=1 -A -t -q -c "BEGIN; SET LOCAL ROLE service_role; INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$ORG6', 'fac_x'); SELECT pg_sleep(3.5); COMMIT;" >"$OUT_DIR/a.out" 2>"$OUT_DIR/a.err" &
PA=$!
sleep 1.0
"${SVC_PSQL[@]}" -c "SET ROLE service_role; INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$ORG6', 'fac_y');" >"$OUT_DIR/b.out" 2>"$OUT_DIR/b.err" &
PB=$!
W=$(waits ser_b)
set +e; wait "$PA"; SA=$?; wait "$PB"; SB=$?; set -e
N=$(hq "SET ROLE service_role; SELECT count(*) FROM app.partner_scope WHERE org_id = '$ORG6'" | tail -1)
if [ "$SA" -ne 0 ]; then fail "scope invariant: the first insert failed"; cat "$OUT_DIR/a.err" >&2 || true
elif [ "$W" != "yes" ]; then fail "scope invariant: the second insert was never seen WAITING in pg_locks (no per-org lock)"
elif [ "$SB" -eq 0 ] || ! grep -q "a facility org holds at most one scope row" "$OUT_DIR/b.err"; then fail "scope invariant: the second insert was not refused as 'at most one scope row' (status $SB): $(cat "$OUT_DIR/b.err")"
elif [ "$N" != "1" ]; then fail "scope invariant: the org holds $N scope rows, expected exactly 1"
else echo "PASS: concurrent scope inserts for one facility org -> the second waited on the per-org lock and was refused; the org holds exactly one scope"; fi

# ---------------------------------------------------------------------------
# 4. The planted GUC: the change session's GUCs do not widen an open action's reach
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 4. planted GUCs during an open action"
# (the delete_my_data window pairs on the partner tables are closed under a partner binding, 0047.) The action is bound as U4 (live). S2 is ANOTHER user's LIVE session (the scope-delete case only touched it). The action plants every GUC at that user and session and
# then, as a partner-bound private_definer, tries to revoke it: no policy admits it, so the row stays live.
EXTRA="SELECT set_config('app.delete_my_data.target_user_id', '$U2', true), set_config('app.partner.session_id', '$S2', true), set_config('app.partner.authority_touch', 'on', true), set_config('app.signin.proof_purge', 'on', true), set_config('app.edge.purge_fix_coords', 'on', true);
SELECT 'writer:' || private.zz24s_writer('$S2');"
if [ "$(session_revoked "$S2")" != "false" ]; then fail "planted GUC: precondition: the victim session must be live"; fi
set +e
action_sql "$H4" 0 "$EXTRA" | edge ser_a >"$OUT_DIR/a.out" 2>"$OUT_DIR/a.err"
SA=$?
set -e
if [ "$SA" -ne 0 ] || ! grep -q "^authorized:" "$OUT_DIR/a.out"; then
  fail "planted GUC: the action failed: $(cat "$OUT_DIR/a.err")"
elif ! grep -q "^writer:rows=0 visible=0$" "$OUT_DIR/a.out"; then
  fail "planted GUC: a partner-bound private_definer writer with every GUC planted reached another user's session: $(grep '^writer:' "$OUT_DIR/a.out")"
elif [ "$(session_revoked "$S2")" != "false" ]; then
  fail "planted GUC: another user's LIVE session was revoked by a partner-bound private_definer writer with every GUC planted"
else
  echo "PASS: planted GUCs -> a partner-bound private_definer writer with every GUC planted at another user's live session changed 0 rows and could not see it (the delete_my_data window is closed under a partner binding); the session is still live"
fi

# ---------------------------------------------------------------------------
# 5. READ COMMITTED only (S1.1a gate, the unstated reliance): the seam and the scope invariant both depend on a fresh snapshot per statement, so a REPEATABLE READ transaction is refused
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 5. REPEATABLE READ is refused by the seam and by the scope invariant"
RR1=$(printf '%s\n' "BEGIN ISOLATION LEVEL REPEATABLE READ;" "SET LOCAL ROLE edge_partner;" "SELECT private.bind_partner_session('$H4');" "SELECT private.zz24s_action('fac_x', 'A0');" "COMMIT;" | edge ser_n 2>&1 || true)
RR1B=$(printf '%s\n' "BEGIN;" "SET LOCAL ROLE edge_partner;" "SELECT private.bind_partner_session('$H4');" "SELECT 'rc_ok:' || private.zz24s_action('fac_x', 'A0');" "COMMIT;" | edge ser_n 2>&1 || true)
RR2=$("${HARNESS_PSQL[@]}" -c "BEGIN ISOLATION LEVEL REPEATABLE READ; SET LOCAL ROLE service_role; INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$ORG7', 'fac_x'); COMMIT;" 2>&1 || true)
RR2B=$("${HARNESS_PSQL[@]}" -c "BEGIN; SET LOCAL ROLE service_role; INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$ORG7', 'fac_x'); COMMIT;" 2>&1 || true)
if ! printf '%s' "$RR1" | grep -q "partner_authorize: requires a READ COMMITTED transaction"; then fail "authorize under REPEATABLE READ was not refused: $RR1"
elif ! printf '%s' "$RR1B" | grep -q "rc_ok:"; then fail "authorize under READ COMMITTED (control) was refused: $RR1B"
elif ! printf '%s' "$RR2" | grep -q "written under READ COMMITTED only"; then fail "a facility scope insert under REPEATABLE READ was not refused: $RR2"
elif [ "$(hq "SET ROLE service_role; SELECT count(*) FROM app.partner_scope WHERE org_id = '$ORG7'" | tail -1)" != "1" ]; then fail "the READ COMMITTED control scope insert did not land exactly once: $RR2B"
else echo "PASS: REPEATABLE READ is refused by partner_authorize and by the scope invariant; READ COMMITTED (control) passes"; fi

# ---------------------------------------------------------------------------
# 6. THE SIGN-IN MINT (S1.1b): real concurrent sessions, real signatures
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 6. the sign-in mint: concurrent replays, the counter race, the alarm that commits"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MU1="ee26f000-0000-0000-0000-0000000000b1"; MU2="ee26f000-0000-0000-0000-0000000000b2"; MU3="ee26f000-0000-0000-0000-0000000000b3"; MU4="ee26f000-0000-0000-0000-0000000000b4"; MU5="ee26f000-0000-0000-0000-0000000000b5"; MU6="ee26f000-0000-0000-0000-0000000000b6"
RP_INSERTED=0
hx "
  GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_auth_challenge, app.partner_auth_alarm, app.partner_rp_config TO CURRENT_USER;
  DROP POLICY IF EXISTS zz26s_chal ON app.partner_auth_challenge; CREATE POLICY zz26s_chal ON app.partner_auth_challenge FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  DROP POLICY IF EXISTS zz26s_alarm ON app.partner_auth_alarm; CREATE POLICY zz26s_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  DROP POLICY IF EXISTS zz26s_rp ON app.partner_rp_config; CREATE POLICY zz26s_rp ON app.partner_rp_config FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  DROP POLICY IF EXISTS zz26s_audit ON app.audit_log; CREATE POLICY zz26s_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);"
RP_COUNT=$(hq "SELECT count(*) FROM app.partner_rp_config")
if [ "$RP_COUNT" = "0" ]; then hx "INSERT INTO app.partner_rp_config (rp_id, origin) VALUES ('partners.example.test', 'https://partners.example.test');"; RP_INSERTED=1; fi
RP_ID="$(hq "SELECT rp_id FROM app.partner_rp_config")"; RP_ORIGIN="$(hq "SELECT origin FROM app.partner_rp_config")"

# One psql session: load the signer helpers (pg_temp, so they vanish with it), make four credentials (each for its own person) with fresh keys, and print one line per assertion:
#   label|credential id|nonce|exp|mac|authenticatorData|clientDataJSON|signature     (all hex but exp)
# The private keys exist only inside this session.
PREP_OUT="$OUT_DIR/prep.txt"
# (the helpers are loaded AS private_definer: they are called as it, and a function in the temp schema is not executable by another role)
( cd "$ROOT_DIR" && "${HARNESS_PSQL[@]}" -c 'SET ROLE private_definer' -f supabase/tests/partner-sign-helpers.sql -c 'RESET ROLE' -f - ) >"$PREP_OUT" <<SQL
SET ROLE service_role;
INSERT INTO auth.users (id, email) VALUES ('$MU1', 'mint1@partner.test'), ('$MU2', 'mint2@partner.test'), ('$MU3', 'mint3@partner.test'), ('$MU4', 'mint4@partner.test'), ('$MU5', 'mint5@partner.test'), ('$MU6', 'mint6@partner.test') ON CONFLICT (id) DO NOTHING;
RESET ROLE;
CREATE TEMP TABLE mk (label text, uid uuid, d numeric, cred_id bytea);
CREATE FUNCTION pg_temp.mkcred(p_label text, p_uid uuid) RETURNS void LANGUAGE plpgsql AS \$f\$
DECLARE d numeric; pub numeric[]; cose bytea; cid bytea := public.gen_random_bytes(32);
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  d := private.partner_sig_os2ip(public.gen_random_bytes(32)) % (private.partner_sig_p256_n() - 1) + 1;
  pub := pg_temp.ps_pub(d);
  cose := pg_temp.ps_cose_es256(pub[1], pub[2]);
  EXECUTE 'RESET ROLE';
  INSERT INTO app.partner_credential (id, user_id, credential_id, public_key, alg) VALUES (('ee26f000-0000-0000-0000-0000000000c' || right(p_label, 1))::uuid, p_uid, cid, cose, -7);
  INSERT INTO mk VALUES (p_label, p_uid, d, cid);
END
\$f\$;
CREATE FUNCTION pg_temp.emit(p_label text, p_mk text, p_counter bigint, p_opts jsonb DEFAULT '{}'::jsonb) RETURNS text LANGUAGE plpgsql AS \$f\$
DECLARE m record; a record;
BEGIN
  SELECT * INTO m FROM mk WHERE label = p_mk;
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT * INTO a FROM pg_temp.ps_assertion(m.d, '$RP_ID', '$RP_ORIGIN', p_counter, p_opts);
  EXECUTE 'RESET ROLE';
  RETURN p_label || '|' || encode(m.cred_id, 'hex') || '|' || encode(a.o_nonce, 'hex') || '|' || a.o_exp || '|' || encode(a.o_mac, 'hex') || '|' || encode(a.o_ad, 'hex') || '|' || encode(a.o_cd, 'hex') || '|' || encode(a.o_sig, 'hex');
END
\$f\$;
SELECT pg_temp.mkcred('m1', '$MU1'); SELECT pg_temp.mkcred('m2', '$MU2'); SELECT pg_temp.mkcred('m3', '$MU3'); SELECT pg_temp.mkcred('m4', '$MU4'); SELECT pg_temp.mkcred('m5', '$MU5'); SELECT pg_temp.mkcred('m6', '$MU6');
SELECT pg_temp.emit('race', 'm1', 1);
SELECT pg_temp.emit('lose_a', 'm2', 9);
SELECT pg_temp.emit('lose_b', 'm2', 8);
SELECT pg_temp.emit('win_a', 'm3', 12);
SELECT pg_temp.emit('win_b', 'm3', 13);
SELECT pg_temp.emit('bad_sig', 'm4', 1, '{"sig_tamper": true}');
SELECT pg_temp.emit('revoked_mid', 'm5', 1);
SELECT pg_temp.emit('f1', 'm6', 0);
SELECT pg_temp.emit('f2', 'm6', 0);
SELECT pg_temp.emit('f3', 'm6', 0);
SELECT pg_temp.emit('f4', 'm6', 0);
SELECT pg_temp.emit('f5', 'm6', 0);
SELECT pg_temp.emit('f6', 'm6', 0);
SELECT pg_temp.emit('f7', 'm6', 0);
SELECT pg_temp.emit('f8', 'm6', 0);
SQL
declare -A A_CRED A_NONCE A_EXP A_MAC A_AD A_CD A_SIG
while IFS='|' read -r lbl cred nonce exp mac ad cd sig; do
  case "$lbl" in race|lose_a|lose_b|win_a|win_b|bad_sig|revoked_mid|f1|f2|f3|f4|f5|f6|f7|f8) A_CRED[$lbl]=$cred; A_NONCE[$lbl]=$nonce; A_EXP[$lbl]=$exp; A_MAC[$lbl]=$mac; A_AD[$lbl]=$ad; A_CD[$lbl]=$cd; A_SIG[$lbl]=$sig;; esac
done < "$PREP_OUT"
if [ -z "${A_SIG[race]:-}" ] || [ -z "${A_SIG[bad_sig]:-}" ]; then fail "the mint cases: the assertion preparation produced no assertions: $(cat "$PREP_OUT" | head -c 600)"; fi

mint_sql() { # $1 = assertion label, $2 = token hash, $3 = seconds to hold the transaction open AFTER the mint
  local l="$1"
  cat <<SQL
BEGIN;
SET LOCAL ROLE edge_partner_minter;
SELECT 'status:' || o_status FROM private.partner_session_mint('$2', '\\x${A_CRED[$l]}', '\\x${A_NONCE[$l]}', ${A_EXP[$l]}, '\\x${A_MAC[$l]}', '\\x${A_AD[$l]}', '\\x${A_CD[$l]}', '\\x${A_SIG[$l]}');
SELECT pg_sleep($3);
COMMIT;
SQL
}
tokhash() { printf '%s' "mint-$1-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1; }
status_of() { sed -n 's/^status://p' "$1" | head -1; }

# 6a. TWELVE concurrent mints of ONE challenge: exactly one wins
if [ -n "${A_SIG[race]:-}" ]; then
  RPIDS=()
  for i in $(seq 1 12); do
    mint_sql race "$(tokhash "race$i")" 0 | edge "ser_m$i" >"$OUT_DIR/m$i.out" 2>"$OUT_DIR/m$i.err" &
    RPIDS+=($!)
  done
  for pid in "${RPIDS[@]}"; do wait "$pid" || true; done
  OKN=0; REPN=0; OTHERN=0
  for i in $(seq 1 12); do
    st="$(status_of "$OUT_DIR/m$i.out")"
    case "$st" in ok) OKN=$((OKN + 1));; replayed) REPN=$((REPN + 1));; *) OTHERN=$((OTHERN + 1)); echo "  mint $i: '${st}' $(head -c 300 "$OUT_DIR/m$i.err")" >&2;; esac
  done
  SESS=$(hq "SELECT count(*) FROM app.partner_session WHERE user_id = '$MU1'")
  NONC=$(hq "SELECT count(*) FROM app.partner_auth_challenge WHERE user_id = '$MU1'")
  CNT=$(hq "SELECT sign_count FROM app.partner_credential WHERE user_id = '$MU1'")
  if [ "$OKN" -ne 1 ] || [ "$REPN" -ne 11 ] || [ "$OTHERN" -ne 0 ]; then fail "6a: twelve concurrent mints of one challenge gave ok=$OKN replayed=$REPN other=$OTHERN, expected 1 / 11 / 0"
  elif [ "$SESS" != "1" ] || [ "$NONC" != "1" ] || [ "$CNT" != "1" ]; then fail "6a: expected one session, one used nonce and a counter of 1, got sessions=$SESS nonces=$NONC counter=$CNT"
  else echo "PASS: 12 concurrent mints of one challenge -> exactly one ok and eleven replayed; one session, one used nonce, the counter advanced once (PA-7)"; fi
fi

# 6b. The counter race, the LOWER second counter: A (9) holds its transaction, B (8) waits on the credential row and is refused
aud_count() { hq "SELECT count(*) FROM app.audit_log WHERE action = '$1' AND subject_id LIKE 'ee26f000-%'"; }  # audit_log is insert-only: rows of an earlier run stay, so compare before and after
if [ -n "${A_SIG[lose_a]:-}" ]; then
  AUD0=$(aud_count partner.mint.counter_regression)
  mint_sql lose_a "$(tokhash la)" 3.5 | edge ser_ma >"$OUT_DIR/ma.out" 2>"$OUT_DIR/ma.err" &
  PA=$!
  sleep 1.2 # A has verified, recorded its nonce, advanced the counter to 9 and is sleeping with the credential row locked
  mint_sql lose_b "$(tokhash lb)" 0 | edge ser_mb >"$OUT_DIR/mb.out" 2>"$OUT_DIR/mb.err" &
  PB=$!
  W=$(waits ser_mb)
  set +e; wait "$PA"; SA=$?; wait "$PB"; SB=$?; set -e
  CNT=$(hq "SELECT sign_count FROM app.partner_credential WHERE user_id = '$MU2'")
  ALM=$(hq "SELECT count(*) FROM app.partner_auth_alarm WHERE kind = 'counter_regression' AND credential_id = (SELECT id FROM app.partner_credential WHERE user_id = '$MU2')")
  AUD=$(( $(aud_count partner.mint.counter_regression) - AUD0 ))
  if [ "$SA" -ne 0 ] || [ "$SB" -ne 0 ]; then fail "6b: a mint session failed: A=$SA B=$SB $(cat "$OUT_DIR/ma.err" "$OUT_DIR/mb.err")"
  elif [ "$W" != "yes" ]; then fail "6b: the second mint was never seen WAITING in pg_locks (no compare-and-set row lock)"
  elif [ "$(status_of "$OUT_DIR/ma.out")" != "ok" ] || [ "$(status_of "$OUT_DIR/mb.out")" != "counter_regression" ]; then fail "6b: expected A=ok and B=counter_regression, got A=$(status_of "$OUT_DIR/ma.out") B=$(status_of "$OUT_DIR/mb.out")"
  elif [ "$CNT" != "9" ]; then fail "6b: the stored counter ended at $CNT, expected 9 (it must never go DOWN to 8)"
  elif [ "$ALM" != "1" ] || [ "$AUD" != "1" ]; then fail "6b: the regression's alarm and audit rows were not COMMITTED (alarms=$ALM audits=$AUD, each expected 1)"
  else echo "PASS: counter race (9 then 8) -> the second mint waited on the credential row, was refused as counter_regression, the counter stayed 9, and its alarm and audit rows are committed (PA-9)"; fi
fi

# 6c. The counter race, the HIGHER second counter: both succeed, in order
if [ -n "${A_SIG[win_a]:-}" ]; then
  mint_sql win_a "$(tokhash wa)" 3.5 | edge ser_ma >"$OUT_DIR/ma.out" 2>"$OUT_DIR/ma.err" &
  PA=$!
  sleep 1.2
  mint_sql win_b "$(tokhash wb)" 0 | edge ser_mb >"$OUT_DIR/mb.out" 2>"$OUT_DIR/mb.err" &
  PB=$!
  W=$(waits ser_mb)
  set +e; wait "$PA"; SA=$?; wait "$PB"; SB=$?; set -e
  CNT=$(hq "SELECT sign_count FROM app.partner_credential WHERE user_id = '$MU3'")
  SESS=$(hq "SELECT count(*) FROM app.partner_session WHERE user_id = '$MU3'")
  if [ "$SA" -ne 0 ] || [ "$SB" -ne 0 ]; then fail "6c: a mint session failed: A=$SA B=$SB $(cat "$OUT_DIR/ma.err" "$OUT_DIR/mb.err")"
  elif [ "$W" != "yes" ]; then fail "6c: the second mint was never seen WAITING in pg_locks"
  elif [ "$(status_of "$OUT_DIR/ma.out")" != "ok" ] || [ "$(status_of "$OUT_DIR/mb.out")" != "ok" ]; then fail "6c: expected both ok, got A=$(status_of "$OUT_DIR/ma.out") B=$(status_of "$OUT_DIR/mb.out")"
  elif [ "$CNT" != "13" ] || [ "$SESS" != "2" ]; then fail "6c: expected counter 13 and two sessions, got counter=$CNT sessions=$SESS"
  else echo "PASS: counter race (12 then 13) -> the second mint waited, then succeeded; the counter is 13 and both made a session (PA-9)"; fi
fi

# 6d. The signature alarm COMMITS with the refusal (a status, not a RAISE)
if [ -n "${A_SIG[bad_sig]:-}" ]; then
  AUD0=$(aud_count partner.mint.signature_invalid)
  mint_sql bad_sig "$(tokhash bs)" 0 | edge ser_md >"$OUT_DIR/md.out" 2>"$OUT_DIR/md.err" || true
  ALM=$(hq "SELECT count(*) FROM app.partner_auth_alarm WHERE kind = 'signature_invalid' AND credential_id = (SELECT id FROM app.partner_credential WHERE user_id = '$MU4')")
  AUD=$(( $(aud_count partner.mint.signature_invalid) - AUD0 ))
  SESS=$(hq "SELECT count(*) FROM app.partner_session WHERE user_id = '$MU4'")
  NONC=$(hq "SELECT count(*) FROM app.partner_auth_challenge WHERE user_id = '$MU4'")
  if [ "$(status_of "$OUT_DIR/md.out")" != "signature_invalid" ]; then fail "6d: expected signature_invalid, got '$(status_of "$OUT_DIR/md.out")': $(cat "$OUT_DIR/md.err")"
  elif [ "$ALM" != "1" ] || [ "$AUD" != "1" ]; then fail "6d: the alarm and audit rows did not survive the refusal (alarms=$ALM audits=$AUD)"
  elif [ "$SESS" != "0" ] || [ "$NONC" != "0" ]; then fail "6d: a refused signature left a session or spent a nonce (sessions=$SESS nonces=$NONC)"
  else echo "PASS: a tampered signature -> signature_invalid, and its alarm and audit rows are committed and visible to another connection; no session, no spent nonce (PA-9b / the 0020 lesson)"; fi
fi

# 6e. A credential REVOKED while a mint is in flight is not minted for. The revoker takes the credential's row lock first and holds it; the mint (whose credential read saw the old row, as READ COMMITTED does)
# verifies, records its nonce and WAITS at the counter's compare-and-set; when the revoke commits the update re-checks its WHERE (revoked_at IS NULL), touches nothing, and the answer is
# unknown_credential: no session, no counter move, and NO counter_regression alarm (a revoked credential is not a clone indicator).
if [ -n "${A_SIG[revoked_mid]:-}" ]; then
  ALM0=$(hq "SELECT count(*) FROM app.partner_auth_alarm WHERE credential_id = (SELECT id FROM app.partner_credential WHERE user_id = '$MU5')")
  printf 'BEGIN;\nUPDATE app.partner_credential SET revoked_at = clock_timestamp() WHERE user_id = '"'"'%s'"'"';\nSELECT pg_sleep(3.5);\nCOMMIT;\n' "$MU5" | "${HARNESS_PSQL[@]}" -q -f - >"$OUT_DIR/rv.out" 2>"$OUT_DIR/rv.err" &
  PR=$!
  sleep 1.0 # the revoke holds the row lock
  mint_sql revoked_mid "$(tokhash rm)" 0 | edge ser_mr >"$OUT_DIR/mr.out" 2>"$OUT_DIR/mr.err" &
  PM=$!
  W=$(waits ser_mr)
  set +e; wait "$PR"; SR=$?; wait "$PM"; SM=$?; set -e
  SESS=$(hq "SELECT count(*) FROM app.partner_session WHERE user_id = '$MU5'")
  CNT=$(hq "SELECT sign_count FROM app.partner_credential WHERE user_id = '$MU5'")
  ALM=$(( $(hq "SELECT count(*) FROM app.partner_auth_alarm WHERE credential_id = (SELECT id FROM app.partner_credential WHERE user_id = '$MU5')") - ALM0 ))
  if [ "$SR" -ne 0 ] || [ "$SM" -ne 0 ]; then fail "6e: a session failed: revoker=$SR mint=$SM $(cat "$OUT_DIR/rv.err" "$OUT_DIR/mr.err")"
  elif [ "$W" != "yes" ]; then fail "6e: the mint was never seen WAITING on the credential row in pg_locks"
  elif [ "$(status_of "$OUT_DIR/mr.out")" != "unknown_credential" ]; then fail "6e: expected unknown_credential for a credential revoked mid-mint, got '$(status_of "$OUT_DIR/mr.out")': $(cat "$OUT_DIR/mr.err")"
  elif [ "$SESS" != "0" ] || [ "$CNT" != "0" ]; then fail "6e: a revoked credential was minted for or its counter moved (sessions=$SESS counter=$CNT)"
  elif [ "$ALM" != "0" ]; then fail "6e: a revoked credential raised an alarm ($ALM): it is not a counter regression"
  else echo "PASS: credential revoked while a mint waited on its row -> unknown_credential, no session, the counter unmoved and no alarm (the compare-and-set re-checks revoked_at)"; fi
fi

# 6f. THE 60-PER-HOUR LIMIT UNDER CONCURRENCY (the S1.1b gate's M-1). A credential with 58 sign-in sessions in the last hour; eight concurrent mints, each with its own valid challenge and counter 0 (so the counter's
# compare-and-set serialises nothing). Without a per-credential lock between the count and the insert all eight read 58 and all succeed (66 sessions); with the credential's row lock exactly two succeed and six are
# rate_limited, so the credential ends at EXACTLY 60. The first mint holds its transaction open, so the others are seen WAITING on the credential row in pg_locks.
if [ -n "${A_SIG[f1]:-}" ]; then
  hx "ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
      INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
      SELECT encode(sha256(convert_to('6f-' || g || '-' || random()::text, 'UTF8')), 'hex'), '$MU6', c.id, 1, now() - interval '10 minutes', now() - interval '10 minutes', now() + interval '8 hours', 'sign_in',
             sha256(convert_to('6fn-' || g || random()::text, 'UTF8')), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex')
      FROM app.partner_credential c, generate_series(1, 58) g WHERE c.user_id = '$MU6';
      SET CONSTRAINTS ALL IMMEDIATE;
      ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;"
  mint_sql f1 "$(tokhash f1)" 3.5 | edge ser_f1 >"$OUT_DIR/f1.out" 2>"$OUT_DIR/f1.err" &
  FP=($!)
  sleep 1.2 # f1 has taken the credential's lock and is sleeping inside its transaction
  for i in 2 3 4 5 6 7 8; do
    mint_sql "f$i" "$(tokhash f$i)" 0 | edge "ser_f$i" >"$OUT_DIR/f$i.out" 2>"$OUT_DIR/f$i.err" &
    FP+=($!)
  done
  W=no
  for w in 2 3 4 5 6 7 8; do [ "$(waits ser_f$w)" = yes ] && { W=yes; break; }; done
  set +e; for pid in "${FP[@]}"; do wait "$pid"; done; set -e
  FOK=0; FRL=0; FOTH=0
  for i in 1 2 3 4 5 6 7 8; do
    st="$(status_of "$OUT_DIR/f$i.out")"
    case "$st" in ok) FOK=$((FOK + 1));; rate_limited) FRL=$((FRL + 1));; *) FOTH=$((FOTH + 1)); echo "  mint f$i: '${st}' $(head -c 300 "$OUT_DIR/f$i.err")" >&2;; esac
  done
  FSESS=$(hq "SELECT count(*) FROM app.partner_session WHERE user_id = '$MU6' AND mint_kind = 'sign_in'")
  if [ "$W" != "yes" ]; then fail "6f: no concurrent mint was ever seen WAITING in pg_locks (the per-credential lock is missing)"
  elif [ "$FOK" -ne 2 ] || [ "$FRL" -ne 6 ] || [ "$FOTH" -ne 0 ]; then fail "6f: eight concurrent mints at 58 sessions gave ok=$FOK rate_limited=$FRL other=$FOTH, expected 2 / 6 / 0"
  elif [ "$FSESS" != "60" ]; then fail "6f: the credential ended at $FSESS sessions in the hour, expected exactly 60"
  else echo "PASS: 8 concurrent mints at 58 sessions -> a concurrent mint waited on the credential row, exactly 2 ok and 6 rate_limited, the credential ends at exactly 60 (S0-L5 under concurrency)"; fi
fi


# ---------------------------------------------------------------------------
# 7. THE SIGN-IN FAILURE COUNTER UNDER CONCURRENCY (the S1.2 gate's L1). Thirty parallel failures of ONE credential: exactly 4 `counted`, the 5th starts the cooldown, the other 26 are `cooldown`.
#    Every transaction stays open for 0.1 s after the call, so without the row lock all thirty overlap and read the same count (lost updates: far more than 4 `counted`).
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 7. thirty parallel sign-in failures of one credential"
MU7="ee26f000-0000-0000-0000-0000000000b7"; CRED7="ee26f000-0000-0000-0000-0000000000c7"
CID7="$(printf '%s' "ser7-$$-$RANDOM" | md5sum | cut -d' ' -f1)$(printf '%s' "ser7b-$$-$RANDOM" | md5sum | cut -d' ' -f1)"
hx "GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_sign_in_failure TO CURRENT_USER;
    DROP POLICY IF EXISTS zz27s_fail ON app.partner_sign_in_failure; CREATE POLICY zz27s_fail ON app.partner_sign_in_failure FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
    SET ROLE service_role; INSERT INTO auth.users (id, email) VALUES ('$MU7', 'mint7@partner.test') ON CONFLICT (id) DO NOTHING; RESET ROLE;
    INSERT INTO app.partner_credential (id, user_id, credential_id, public_key, alg) VALUES ('$CRED7', '$MU7', decode('$CID7', 'hex'), decode(md5('ser7k') || md5('ser7kb'), 'hex'), -7);"
fail_sql() { # $1 = hold open (seconds) after the call
  printf '%s\n' "BEGIN;" "SET LOCAL ROLE edge_partner_minter;" "SELECT 'status:' || o_status FROM private.partner_sign_in_failure_record('\\x$CID7');" "SELECT pg_sleep($1);" "COMMIT;"
}
FPIDS=()
for i in $(seq 1 30); do
  fail_sql 0.1 | edge "ser_l1_$i" >"$OUT_DIR/l1_$i.out" 2>"$OUT_DIR/l1_$i.err" &
  FPIDS+=($!)
done
set +e; for pid in "${FPIDS[@]}"; do wait "$pid"; done; set -e
L1_COUNTED=0; L1_COOL=0; L1_OTHER=0
for i in $(seq 1 30); do
  st="$(status_of "$OUT_DIR/l1_$i.out")"
  case "$st" in counted) L1_COUNTED=$((L1_COUNTED + 1));; cooldown) L1_COOL=$((L1_COOL + 1));; *) L1_OTHER=$((L1_OTHER + 1)); echo "  failure $i: '${st}' $(head -c 300 "$OUT_DIR/l1_$i.err")" >&2;; esac
done
L1_ROW="$(hq "SELECT failed_count || ',' || (cooldown_until IS NOT NULL)::text FROM app.partner_sign_in_failure WHERE credential_id = '$CRED7'")"
if [ "$L1_COUNTED" -ne 4 ] || [ "$L1_COOL" -ne 26 ] || [ "$L1_OTHER" -ne 0 ]; then fail "7: thirty parallel failures of one credential gave counted=$L1_COUNTED cooldown=$L1_COOL other=$L1_OTHER, expected 4 / 26 / 0"
elif [ "$L1_ROW" != "0,true" ]; then fail "7: expected the cooldown running with the counter reset to 0 (the 5th started it), got '$L1_ROW'"
else echo "PASS: 30 parallel sign-in failures of one credential -> exactly 4 counted and 26 cooldown; the cooldown is running (the row lock serialises the counter, S1.2 gate L1)"; fi

# ---------------------------------------------------------------------------
# 8. THE STEP-UP PIN UNDER CONCURRENCY (PA-18)
# ---------------------------------------------------------------------------
echo "tools/db/test-partner-serialisation.sh: 8. twenty concurrent wrong PIN keys"
ORG8="ee24f000-0000-0000-0000-0000000000a8"; U8="ee24f000-0000-0000-0000-0000000000b8"; C8="ee24f000-0000-0000-0000-0000000000c8"; S8="ee24f000-0000-0000-0000-0000000000d8"
H8="$(printf '%s' "ser8-$$-$RANDOM-$(date +%s%N)" | sha256sum | cut -d' ' -f1)"
GOOD8="$(printf '11%.0s' $(seq 1 32))"; BAD8="$(printf '22%.0s' $(seq 1 32))"
hx "SET ROLE service_role;
    INSERT INTO auth.users (id, email) VALUES ('$U8', 'ser8@partner.test') ON CONFLICT (id) DO NOTHING;
    INSERT INTO app.partner_org (id, kind, name) VALUES ('$ORG8', 'facility', 'ser org 8');
    INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$ORG8', 'fac_x');
    INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('$U8', '$ORG8', 'staff');
    RESET ROLE;
    INSERT INTO app.partner_credential (id, user_id, credential_id, public_key, alg) VALUES ('$C8', '$U8', decode(md5('ser-c8') || md5('ser-cb8'), 'hex'), decode(md5('ser-k8') || md5('ser-kb8'), 'hex'), -7);
    ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
    INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
    VALUES ('$S8', '$H8', '$U8', '$C8', 1, now() - interval '1 hour', now(), now() + interval '8 hours', 'sign_in', decode(md5('ser-n8') || md5('ser-nb8'), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'));
    SET CONSTRAINTS ALL IMMEDIATE;
    ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;
    GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_pin TO CURRENT_USER;
    DROP POLICY IF EXISTS zz28s_pin ON app.partner_pin; CREATE POLICY zz28s_pin ON app.partner_pin FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
    DROP POLICY IF EXISTS zz26s_audit ON app.audit_log; CREATE POLICY zz26s_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);"
seed_pin8() { # $1 = failed_count, $2 = next_attempt_at SQL (a timestamptz expression or NULL)
  hx "DELETE FROM app.partner_pin WHERE user_id = '$U8';
      INSERT INTO app.partner_pin (user_id, salt, iterations, verifier, failed_count, failed_today, failed_day, next_attempt_at)
      SELECT '$U8', decode(repeat('0a', 16), 'hex'), 600000,
             public.hmac(convert_to('golfraven/partner-pin/v1', 'UTF8') || decode('00', 'hex') || decode(replace('$U8', '-', ''), 'hex') || decode('$GOOD8', 'hex'), convert_to(s.decrypted_secret, 'UTF8'), 'sha256'),
             $1, $1, (clock_timestamp() AT TIME ZONE 'UTC')::date, $2
      FROM vault.decrypted_secrets s WHERE s.name = 'partner_pin_pepper';"
}
pin_sql() { # $1 = derived hex, $2 = hold open (seconds) after the call
  printf '%s\n' "BEGIN;" "SET LOCAL ROLE edge_partner;" "SELECT private.bind_partner_session('$H8');" \
    "SELECT 'status:' || o_status || '|' || o_retry_after FROM private.partner_pin_verify_for_partner('\\x$1');" "SELECT pg_sleep($2);" "COMMIT;"
}
pin_run() { # $1 = how many concurrent calls, $2 = derived hex, prints nothing; outputs in $OUT_DIR/pin_<i>.out
  local n=$1 i; local pids=()
  for i in $(seq 1 "$n"); do
    pin_sql "$2" 0.1 | edge "ser_pin_$i" >"$OUT_DIR/pin_$i.out" 2>"$OUT_DIR/pin_$i.err" &
    pids+=($!)
  done
  set +e; for pid in "${pids[@]}"; do wait "$pid"; done; set -e
}
pin_tally() { # $1 = count; echoes "wrong=a retry=b locked=c other=d"
  local n=$1 i st w=0 r=0 l=0 o=0
  for i in $(seq 1 "$n"); do
    st="$(status_of "$OUT_DIR/pin_$i.out")"
    case "$st" in wrong\|*) w=$((w + 1));; retry_after\|*) r=$((r + 1));; locked\|*) l=$((l + 1));; *) o=$((o + 1)); echo "  pin call $i: '${st}' $(head -c 300 "$OUT_DIR/pin_$i.err")" >&2;; esac
  done
  echo "wrong=$w retry=$r locked=$l other=$o"
}
# 8a. a fresh PIN, twenty concurrent WRONG keys: at most five evaluated (exactly three, then the 30 s backoff)
seed_pin8 0 NULL
PIN_AUD0=$(hq "SELECT count(*) FROM app.audit_log WHERE subject_id = '$U8' AND action = 'partner.pin.wrong'")
pin_run 20 "$BAD8"
T8A="$(pin_tally 20)"
ROW8A="$(hq "SELECT failed_count || ',' || (locked_at IS NOT NULL)::text || ',' || (next_attempt_at IS NOT NULL)::text FROM app.partner_pin WHERE user_id = '$U8'")"
AUD8A=$(( $(hq "SELECT count(*) FROM app.audit_log WHERE subject_id = '$U8' AND action = 'partner.pin.wrong'") - PIN_AUD0 ))
if [ "$T8A" != "wrong=3 retry=17 locked=0 other=0" ]; then fail "8a: twenty concurrent wrong keys gave $T8A, expected exactly wrong=3 retry=17 locked=0 (at most five evaluated: the third starts the backoff)"
elif [ "$ROW8A" != "3,false,true" ]; then fail "8a: expected the counter at 3, not locked, a backoff running; got '$ROW8A'"
elif [ "$AUD8A" != "3" ]; then fail "8a: expected exactly three audit rows for the three evaluated wrong keys, got $AUD8A"
else echo "PASS: 20 concurrent wrong PIN keys -> exactly 3 evaluated (wrong), 17 refused retry_after without being evaluated; the counter is 3 and committed, a backoff is running (PA-18, FOR UPDATE on the PIN row)"; fi
# 8b. one failure from the lock and no backoff running: twenty concurrent wrong keys lock the PIN ONCE
seed_pin8 4 NULL
LOCK_AUD0=$(hq "SELECT count(*) FROM app.audit_log WHERE subject_id = '$U8' AND action = 'partner.pin.locked'")
pin_run 20 "$BAD8"
T8B="$(pin_tally 20)"
ROW8B="$(hq "SELECT failed_count || ',' || (locked_at IS NOT NULL)::text FROM app.partner_pin WHERE user_id = '$U8'")"
AUD8B=$(( $(hq "SELECT count(*) FROM app.audit_log WHERE subject_id = '$U8' AND action = 'partner.pin.locked'") - LOCK_AUD0 ))
if [ "$T8B" != "wrong=0 retry=0 locked=20 other=0" ]; then fail "8b: expected all twenty answers locked (the one evaluated wrong key locks; the rest are refused locked), got $T8B"
elif [ "$ROW8B" != "5,true" ]; then fail "8b: expected the counter at 5 and the PIN locked, got '$ROW8B'"
elif [ "$AUD8B" != "1" ]; then fail "8b: the lock must be recorded ONCE (one partner.pin.locked audit row), got $AUD8B"
else echo "PASS: 20 concurrent wrong keys one failure from the lock -> the PIN locks exactly once (one lock audit row), the counter ends at 5, every answer is locked"; fi
# 8c. the CORRECT key is refused once locked, even concurrently
pin_run 5 "$GOOD8"
T8C="$(pin_tally 5)"
if [ "$T8C" != "wrong=0 retry=0 locked=5 other=0" ]; then fail "8c: the CORRECT key on a locked PIN was not refused as locked: $T8C"
else echo "PASS: the correct key on a locked PIN is refused (locked) on every concurrent attempt"; fi

# ---------------------------------------------------------------------------
# 9. SAME-SESSION CONCURRENCY (S1.3 gate LOW-1): N parallel CORRECT verifies on ONE session
# ---------------------------------------------------------------------------
# The session was last seen a moment ago, so partner_authorize does not bump last_seen_at: under class A0 it took the session row FOR SHARE and the verify definer then UPDATEd the row (pin_grant_until). Two FOR
# SHARE holders that both upgrade DEADLOCK (the gate saw 2 or 3 of 4 parallel verifies die with 40P01). Class A0_WRITE takes FOR NO KEY UPDATE up front, so the calls queue on the lock instead. Every call must answer
# ok, and no call may report a deadlock. Three rounds of eight, because a deadlock needs the calls to overlap and one round can miss.
echo "tools/db/test-partner-serialisation.sh: 9. parallel correct PIN verifies on one session"
for round in 1 2 3; do
  seed_pin8 0 NULL
  hx "UPDATE app.partner_session SET last_seen_at = now() WHERE id = '$S8'"
  pin_run 8 "$GOOD8"
  OK9=0; OTHER9=0; DEAD9=0
  for i in $(seq 1 8); do
    st="$(status_of "$OUT_DIR/pin_$i.out")"
    if [ "$st" = "ok|0" ]; then OK9=$((OK9 + 1)); else OTHER9=$((OTHER9 + 1)); echo "  verify $i (round $round): '${st}' $(head -c 300 "$OUT_DIR/pin_$i.err")" >&2; fi
    if grep -qi "deadlock" "$OUT_DIR/pin_$i.err" 2>/dev/null; then DEAD9=$((DEAD9 + 1)); fi
  done
  if [ "$DEAD9" -ne 0 ] || [ "$OK9" -ne 8 ]; then fail "9 (round $round): eight parallel correct verifies on one session gave ok=$OK9 other=$OTHER9 deadlocks=$DEAD9, expected ok=8 and no deadlock (partner_authorize must lock the session row FOR NO KEY UPDATE up front for a definer that writes it)"; break; fi
done
if [ "$FAILED" -eq 0 ]; then echo "PASS: 3 rounds of 8 parallel correct verifies on one session -> all ok, no deadlock (A0_WRITE locks the session row FOR NO KEY UPDATE up front)"; fi
# 9b. the same shape on the two SESSION-class writers (S1.2's sign-out and lock): the lock clears a standing PIN grant, an UPDATE of the session row. A lock is too quick for a plain race to overlap, so the overlap is
# MADE: each of four sessions first authorizes (class SESSION, through the planted action definer: it takes the row lock and keeps it to commit), sleeps, and only then calls the real lock definer, which UPDATEs the
# row. Under FOR SHARE all four hold a share when the first UPDATE asks for the row (deadlock); under FOR NO KEY UPDATE the second session waits at its authorize and never holds a share.
lock_sql() { # $1 = seconds to hold the row lock between the authorize and the lock's write
  printf '%s\n' "BEGIN;" "SET LOCAL ROLE edge_partner;" "SELECT private.bind_partner_session('$H8');" "SELECT 'authorized:' || private.zz24s_action('fac_x', 'SESSION');" "SELECT pg_sleep($1);" \
    "SELECT private.partner_session_lock_for_partner();" "SELECT 'status:locked';" "COMMIT;"
}
for round in 1 2 3; do
  seed_pin8 0 NULL
  hx "UPDATE app.partner_session SET last_seen_at = now() WHERE id = '$S8'"
  pin_run 1 "$GOOD8"
  if [ "$(status_of "$OUT_DIR/pin_1.out")" != "ok|0" ]; then fail "9b (round $round): the seeding verify was not ok: '$(status_of "$OUT_DIR/pin_1.out")'"; break; fi
  pids=()
  for i in 1 2 3 4; do
    lock_sql 0.6 | edge "ser_lock_$i" >"$OUT_DIR/lock_$i.out" 2>"$OUT_DIR/lock_$i.err" &
    pids+=($!)
  done
  set +e; for pid in "${pids[@]}"; do wait "$pid"; done; set -e
  OKL=0; DEADL=0
  for i in 1 2 3 4; do
    [ "$(status_of "$OUT_DIR/lock_$i.out")" = "locked" ] && OKL=$((OKL + 1)) || echo "  lock $i (round $round): $(head -c 300 "$OUT_DIR/lock_$i.err")" >&2
    if grep -qi "deadlock" "$OUT_DIR/lock_$i.err" 2>/dev/null; then DEADL=$((DEADL + 1)); fi
  done
  if [ "$DEADL" -ne 0 ] || [ "$OKL" -ne 4 ]; then fail "9b (round $round): four overlapping session locks gave ok=$OKL deadlocks=$DEADL (class SESSION must lock the session row FOR NO KEY UPDATE up front)"; break; fi
done
if [ "$FAILED" -eq 0 ]; then echo "PASS: 3 rounds of 4 overlapping session locks (each clearing a standing PIN grant) -> all ok, no deadlock"; fi

if [ "$FAILED" -ne 0 ]; then
  echo "tools/db/test-partner-serialisation.sh: FAILED" >&2
  exit 1
fi
echo "tools/db/test-partner-serialisation.sh: all partner serialisation checks passed"
