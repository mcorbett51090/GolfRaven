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
#      supabase/tests/matrix/24_partner_auth_spine.sql.
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

ORG1="ee24f000-0000-0000-0000-0000000000a1"; ORG2="ee24f000-0000-0000-0000-0000000000a2"; ORG3="ee24f000-0000-0000-0000-0000000000a3"; ORG4="ee24f000-0000-0000-0000-0000000000a4"; ORG5="ee24f000-0000-0000-0000-0000000000a5"
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

cleanup() {
  set +e
  # one statement batch per concern: a refusal in one must not roll back the others
  hx "SET ROLE private_definer; DROP FUNCTION IF EXISTS private.zz24s_action(text, text); DROP FUNCTION IF EXISTS private.zz24s_writer(uuid);" 2>/dev/null
  hx "DELETE FROM app.partner_session WHERE id::text LIKE 'ee24f000-%'; DELETE FROM app.partner_credential WHERE id::text LIKE 'ee24f000-%';" 2>/dev/null
  hx "SET ROLE service_role; DELETE FROM app.partner_member WHERE org_id::text LIKE 'ee24f000-%'; DELETE FROM app.partner_scope WHERE org_id::text LIKE 'ee24f000-%'; DELETE FROM app.partner_org WHERE id::text LIKE 'ee24f000-%';" 2>/dev/null
  hx "SET ROLE service_role; SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id::text LIKE 'ee24f000-%';" 2>/dev/null
  hx "DROP POLICY IF EXISTS zz24s_cred ON app.partner_credential; DROP POLICY IF EXISTS zz24s_sess ON app.partner_session; REVOKE ALL ON app.partner_credential, app.partner_session FROM CURRENT_USER;" 2>/dev/null
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
  INSERT INTO app.partner_org (id, kind, name) VALUES ('$ORG1', 'facility', 'ser org 1'), ('$ORG2', 'facility', 'ser org 2'), ('$ORG3', 'facility', 'ser org 3'), ('$ORG4', 'facility', 'ser org 4'), ('$ORG5', 'facility', 'ser org 5');
  INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$ORG1', 'fac_x'), ('$ORG2', 'fac_x'), ('$ORG3', 'fac_x'), ('$ORG4', 'fac_x'), ('$ORG5', 'fac_x');
  INSERT INTO app.partner_member (user_id, org_id, role) VALUES ('$U1', '$ORG1', 'staff'), ('$U2', '$ORG2', 'staff'), ('$U3', '$ORG3', 'staff'), ('$U4', '$ORG1', 'staff'), ('$U5', '$ORG4', 'staff'), ('$U6', '$ORG5', 'staff');
  RESET ROLE;"
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

if [ "$FAILED" -ne 0 ]; then
  echo "tools/db/test-partner-serialisation.sh: FAILED" >&2
  exit 1
fi
echo "tools/db/test-partner-serialisation.sh: all partner serialisation checks passed"
