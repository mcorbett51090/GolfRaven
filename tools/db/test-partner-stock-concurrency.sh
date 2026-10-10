#!/usr/bin/env bash
# tools/db/test-partner-stock-concurrency.sh
#
# P5.1a S5 (0058), AT(8) and AT(21): "the race for the last unit". pgTAP runs inside ONE transaction on ONE connection, so it cannot show two hand-overs contending for one stock
# row, nor the deferred 0017 entitlement_play_guard at a REAL commit; this script is the part that needs TWO REAL, concurrent sessions. Every racer is a real `edge_gateway` login
# (the harness cluster authenticates with `trust`) that switches to edge_partner, binds a partner session and calls the real private.partner_entitlement_redeem_for_partner (class A1:
# each racer spends its own PIN grant). The overlap is not left to timing: a HOLDER session (service_role) locks the contested row first, both racers are seen WAITING on a lock in
# pg_locks, and only then does the holder commit, so both are released into the critical section together.
#
#   1. THE LAST UNIT. Stock on_hand = 1 and TWO entitlements of two different players, each with its own hand-over token; two staff members redeem at the same instant, both parked on the
#      stock row. Exactly ONE answers ok and ONE answers out_of_stock; on_hand ends at 0 (never -1); exactly one entitlement is redeemed and the other is UNCHANGED (redeemable) with its
#      token UNCONSUMED; one redeemed movement and one special_marker_handover attestation. Repeated ROUNDS times.
#   2. THE SAME ENTITLEMENT, TWICE. Stock is plentiful and ONE entitlement is redeemed by two staff members at once with the same hand-over token, both parked on the entitlement row:
#      exactly one ok, the other is a refusal that changed nothing (once redeemed the row is no longer visible to the UPDATE policy of a staff binding: not_found, or not_redeemable or
#      replayed); the stock goes down by ONE unit, one redeemed movement, one attestation.
#   3. THE PLAY GUARD AT A REAL COMMIT. An entitlement backed by a confirmed play is redeemed and COMMITTED. The 0017 deferred guard re-reads the play at commit through the binding-keyed
#      policy of 0058 (its own GUC window is closed under a partner binding); read back from ANOTHER connection the entitlement is redeemed.
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash tools/db/test-partner-stock-concurrency.sh
# (tools/db/test.sh calls it with the harness role in PGUSER, after the partner serialisation step, against the same throwaway cluster and database.)
# Ids carry a per-run nonce, so it is re-runnable; what it commits is removed by the EXIT trap, except what no role may delete (consumed_nonce tombstones, audit_log). The stock row of
# trl_v at fac_x is created here (no fixture owns it) and removed with the run.

set -euo pipefail

: "${PGHOST:?tools/db/test-partner-stock-concurrency.sh: PGHOST must be set}"
: "${PGPORT:?}"
: "${PGUSER:?}"
: "${PGDATABASE:?}"

ROUNDS="${ROUNDS:-6}"
HARNESS_PSQL=(psql -v ON_ERROR_STOP=1 -A -t -q)
FAILED=0
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/golfraven-stock-conc.XXXXXX")"
RUN="$(printf '%04x' $((RANDOM % 65536)))"
TRAIL="trl_v"
FAC="fac_x"
P="ee58$RUN" # the uuid prefix of everything this run creates

hq() { "${HARNESS_PSQL[@]}" -c "$1" | tr -d '[:space:]'; }
hx() { "${HARNESS_PSQL[@]}" -c "$1" >/dev/null; }
# a READ as service_role: the stock, entitlement and movement tables are FORCE RLS for their owner, which holds no policy on them
sq() { "${HARNESS_PSQL[@]}" -c "SET ROLE service_role; $1" | tr -d '[:space:]'; }
svc() { "${HARNESS_PSQL[@]}" -c "SET ROLE service_role; $1" >/dev/null; }
edge() { env PGAPPNAME="$1" PGUSER=edge_gateway psql -v ON_ERROR_STOP=1 -A -t -q; }
fail() { echo "FAIL: $*" >&2; FAILED=1; }
sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
uid() { printf '%s-0000-0000-%04x-%012x' "$P" "$1" "$2"; } # $1 = group, $2 = slot

# The access this script grants CURRENT_USER is temporary, so the cleanup takes it back, but never from a role that OWNS the table (its implicit privileges are not ours to remove).
revoke_temp_grants() {
  local t
  for t in "$@"; do
    hx "DO \$\$ BEGIN IF (SELECT relowner FROM pg_class WHERE oid = '$t'::regclass) IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname = CURRENT_USER) THEN REVOKE ALL ON $t FROM CURRENT_USER; END IF; END \$\$;" 2>/dev/null
  done
}

STOCK_INSERTED=0
cleanup() {
  set +e
  hx "ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg; ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;" 2>/dev/null
  hx "DELETE FROM app.partner_handover_token WHERE issued_by::text LIKE '$P-%';" 2>/dev/null
  svc "DELETE FROM app.special_marker_stock_movement WHERE by_member::text LIKE '$P-%';" 2>/dev/null
  svc "UPDATE app.entitlement SET play_id = NULL WHERE user_id::text LIKE '$P-%';" 2>/dev/null
  svc "DELETE FROM app.entitlement WHERE user_id::text LIKE '$P-%'; DELETE FROM app.play WHERE user_id::text LIKE '$P-%';" 2>/dev/null
  svc "DELETE FROM app.staff_activity WHERE staff_user_id::text LIKE '$P-%';" 2>/dev/null
  hx "DELETE FROM app.partner_session WHERE user_id::text LIKE '$P-%'; DELETE FROM app.partner_credential WHERE user_id::text LIKE '$P-%';" 2>/dev/null
  svc "DELETE FROM app.partner_member WHERE org_id::text LIKE '$P-%'; DELETE FROM app.partner_scope WHERE org_id::text LIKE '$P-%'; DELETE FROM app.partner_org WHERE id::text LIKE '$P-%';" 2>/dev/null
  svc "SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id::text LIKE '$P-%';" 2>/dev/null
  if [ "$STOCK_INSERTED" = 1 ]; then svc "DELETE FROM app.special_marker_stock_movement WHERE trail_id = '$TRAIL' AND facility_id = '$FAC'; DELETE FROM app.special_marker_availability WHERE trail_id = '$TRAIL' AND facility_id = '$FAC'; DELETE FROM app.special_marker_stock WHERE trail_id = '$TRAIL' AND facility_id = '$FAC';" 2>/dev/null; fi
  hx "DROP POLICY IF EXISTS zz58c_cred ON app.partner_credential; DROP POLICY IF EXISTS zz58c_sess ON app.partner_session; DROP POLICY IF EXISTS zz58c_tok ON app.partner_handover_token; DROP POLICY IF EXISTS zz58c_att ON app.attestation;" 2>/dev/null
  revoke_temp_grants app.partner_credential app.partner_session app.partner_handover_token app.attestation
  rm -rf "$OUT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Seed (committed; removed by the trap): two staff members, each of its own facility org on fac_x, each with a live credential and a live session, and the stock row of trl_v at fac_x.
# ---------------------------------------------------------------------------
if [ "$(sq "SELECT count(*) FROM app.special_marker_stock WHERE trail_id = '$TRAIL' AND facility_id = '$FAC'")" != "0" ]; then
  echo "tools/db/test-partner-stock-concurrency.sh: $TRAIL already has a stock row at $FAC (a fixture owns it); this script needs it free" >&2
  exit 1
fi
STOCK_INSERTED=1

SA="$(uid 1 1)"; SB="$(uid 1 2)"
OA="$P-0000-0000-0000-00000000000a"; OB="$P-0000-0000-0000-00000000000b"
CA="$P-0000-0000-0000-0000000000ca"; CB="$P-0000-0000-0000-0000000000cb"
SSA="$P-0000-0000-0000-0000000000a5"; SSB="$P-0000-0000-0000-0000000000b5"
HA="$(sha "conc58-session-a-$RUN-$$")"; HB="$(sha "conc58-session-b-$RUN-$$")"

hx "
  GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_handover_token TO CURRENT_USER;
  GRANT SELECT ON app.attestation TO CURRENT_USER;
  DROP POLICY IF EXISTS zz58c_cred ON app.partner_credential; DROP POLICY IF EXISTS zz58c_sess ON app.partner_session; DROP POLICY IF EXISTS zz58c_tok ON app.partner_handover_token; DROP POLICY IF EXISTS zz58c_att ON app.attestation;
  CREATE POLICY zz58c_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  CREATE POLICY zz58c_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  CREATE POLICY zz58c_tok ON app.partner_handover_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
  CREATE POLICY zz58c_att ON app.attestation FOR SELECT TO CURRENT_USER USING (true);"
svc "
  INSERT INTO auth.users (id, email) VALUES ('$SA', 'conc58a-$RUN@partner.test'), ('$SB', 'conc58b-$RUN@partner.test');
  INSERT INTO app.partner_org (id, kind, name) VALUES ('$OA', 'facility', 'conc58 org a'), ('$OB', 'facility', 'conc58 org b');
  INSERT INTO app.partner_scope (org_id, facility_id) VALUES ('$OA', '$FAC'), ('$OB', '$FAC');
  INSERT INTO app.partner_member (user_id, org_id, role, created_at) VALUES ('$SA', '$OA', 'staff', now() - interval '60 days'), ('$SB', '$OB', 'staff', now() - interval '60 days');
  INSERT INTO app.special_marker_stock (trail_id, facility_id, on_hand, low_threshold) VALUES ('$TRAIL', '$FAC', 0, 3);"
# the INSERT guard refuses a back-dated session: off for the seeding only, back on right after
hx "ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;"
hx "
  INSERT INTO app.partner_credential (id, user_id, credential_id, public_key, alg) VALUES
    ('$CA', '$SA', decode(md5('conc58-ca$RUN') || md5('conc58-cab$RUN'), 'hex'), decode(md5('conc58-ka$RUN') || md5('conc58-kab$RUN'), 'hex'), -7),
    ('$CB', '$SB', decode(md5('conc58-cb$RUN') || md5('conc58-cbb$RUN'), 'hex'), decode(md5('conc58-kb$RUN') || md5('conc58-kbb$RUN'), 'hex'), -7);
  INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature) VALUES
    ('$SSA', '$HA', '$SA', '$CA', 1, now() - interval '1 hour', now(), now() + interval '8 hours', 'sign_in', decode(md5('conc58-na$RUN') || md5('conc58-nab$RUN'), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex')),
    ('$SSB', '$HB', '$SB', '$CB', 1, now() - interval '1 hour', now(), now() + interval '8 hours', 'sign_in', decode(md5('conc58-nb$RUN') || md5('conc58-nbb$RUN'), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'));"
hx "ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_insert_guard_trg;"

# a PIN grant a session cannot be born with: the guard is off for the seeding only (one grant per A1 action)
pin_grants() {
  hx "ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg;
      UPDATE app.partner_session SET pin_grant_until = clock_timestamp() + interval '50 seconds' WHERE id IN ('$SSA', '$SSB');
      ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg;"
}

# one player with a redeemable entitlement and a minted hand-over token: $1 group, $2 slot -> echoes "entitlement token_hash"
mk_player() {
  local u e h
  u="$(uid "$1" "$2")"; e="$P-0000-0000-$(printf '%04x' "$1")-e$(printf '%011x' "$2")"; h="$(sha "conc58-token-$RUN-$1-$2")"
  svc "INSERT INTO auth.users (id, email) VALUES ('$u', 'conc58p$1x$2-$RUN@partner.test');
       INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, activated_at) VALUES ('$e', '$u', 'special_marker', '$TRAIL', 'redeemable', now());"
  hx "INSERT INTO app.partner_handover_token (token_hash, entitlement_id, facility_id, issued_by, created_at, expires_at) VALUES ('$h', '$e', '$FAC', '$SA', now(), now() + interval '10 minutes');"
  echo "$e $h"
}

redeem_sql() { # $1 session token hash, $2 entitlement, $3 hand-over token hash
  cat <<SQL
BEGIN;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session('$1');
SELECT 'R:' || r.o_status FROM private.partner_entitlement_redeem_for_partner('$FAC', '$2', 'hand_over_token', '$3') r;
COMMIT;
SQL
}

waiting() { # $1 = application_name; polls up to ~5 s for that session to be waiting on a lock
  local i n
  for i in $(seq 1 50); do
    n=$(hq "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE a.application_name = '$1' AND NOT l.granted")
    [ "$n" != "0" ] && { echo yes; return 0; }
    sleep 0.1
  done
  echo no
}

# one race: $1 label, $2 the statement the holder locks with, $3 entitlement A, $4 token A, $5 entitlement B, $6 token B. Sets RES_A and RES_B (the status each racer answered).
race() {
  local label="$1" lock="$2" ea="$3" ta="$4" eb="$5" tb="$6" hpid pa pb wa wb sa sb
  pin_grants
  env PGAPPNAME=conc_holder "${HARNESS_PSQL[@]}" -c "SET ROLE service_role; BEGIN; $lock; SELECT pg_sleep(4); COMMIT;" >"$OUT_DIR/holder.out" 2>"$OUT_DIR/holder.err" &
  hpid=$!
  sleep 0.5
  redeem_sql "$HA" "$ea" "$ta" | edge conc_a >"$OUT_DIR/a.out" 2>"$OUT_DIR/a.err" &
  pa=$!
  redeem_sql "$HB" "$eb" "$tb" | edge conc_b >"$OUT_DIR/b.out" 2>"$OUT_DIR/b.err" &
  pb=$!
  wa="$(waiting conc_a)"; wb="$(waiting conc_b)"
  set +e; wait "$hpid"; wait "$pa"; sa=$?; wait "$pb"; sb=$?; set -e
  if [ "$wa" != "yes" ] || [ "$wb" != "yes" ]; then fail "$label: the two racers were not both seen WAITING on the contested row (a=$wa b=$wb): the overlap is not proven"; fi
  if [ "$sa" -ne 0 ] || [ "$sb" -ne 0 ]; then fail "$label: a racer exited non-zero (a=$sa b=$sb)"; cat "$OUT_DIR/a.err" "$OUT_DIR/b.err" "$OUT_DIR/holder.err" >&2 || true; fi
  RES_A="$(sed -n 's/^R://p' "$OUT_DIR/a.out")"; RES_B="$(sed -n 's/^R://p' "$OUT_DIR/b.out")"
}

# ---------------------------------------------------------------------------
# 1. THE LAST UNIT
# ---------------------------------------------------------------------------
for r in $(seq 1 "$ROUNDS"); do
  read -r EA TA <<<"$(mk_player "$((10 + r))" 1)"
  read -r EB TB <<<"$(mk_player "$((10 + r))" 2)"
  svc "UPDATE app.special_marker_stock SET on_hand = 1 WHERE trail_id = '$TRAIL' AND facility_id = '$FAC';"
  race "round $r (last unit)" "SELECT 1 FROM app.special_marker_stock WHERE trail_id = '$TRAIL' AND facility_id = '$FAC' FOR UPDATE" "$EA" "$TA" "$EB" "$TB"
  oks=0; outs=0
  for v in "$RES_A" "$RES_B"; do [ "$v" = "ok" ] && oks=$((oks + 1)); [ "$v" = "out_of_stock" ] && outs=$((outs + 1)); done
  { [ "$oks" -eq 1 ] && [ "$outs" -eq 1 ]; } || fail "round $r: expected exactly one ok and one out_of_stock, got a='$RES_A' b='$RES_B'"
  [ "$(sq "SELECT on_hand FROM app.special_marker_stock WHERE trail_id = '$TRAIL' AND facility_id = '$FAC'")" = "0" ] || fail "round $r: on_hand is not 0 afterwards"
  [ "$(sq "SELECT count(*) FROM app.entitlement WHERE id IN ('$EA', '$EB') AND state = 'redeemed'")" = "1" ] || fail "round $r: not exactly one of the two entitlements is redeemed"
  [ "$(sq "SELECT count(*) FROM app.entitlement WHERE id IN ('$EA', '$EB') AND state = 'redeemable' AND redeemed_at IS NULL AND redeemed_by_staff IS NULL")" = "1" ] || fail "round $r: the loser's entitlement was changed"
  [ "$(hq "SELECT count(*) FROM app.partner_handover_token WHERE entitlement_id IN ('$EA', '$EB') AND consumed_at IS NOT NULL")" = "1" ] || fail "round $r: not exactly one token was consumed (the loser's token must be unconsumed)"
  [ "$(sq "SELECT count(*) FROM app.special_marker_stock_movement WHERE entitlement_id IN ('$EA', '$EB') AND kind = 'redeemed' AND qty = -1")" = "1" ] || fail "round $r: not exactly one redeemed movement"
  [ "$(hq "SELECT count(*) FROM app.attestation WHERE kind = 'special_marker_handover' AND token_jti IN ('smh:handover:$TA', 'smh:handover:$TB')")" = "1" ] || fail "round $r: not exactly one hand-over attestation"
done
echo "1. last unit: $ROUNDS rounds, each exactly one ok and one out_of_stock, on_hand 0, the loser untouched"

# ---------------------------------------------------------------------------
# 2. THE SAME ENTITLEMENT, TWICE
# ---------------------------------------------------------------------------
read -r EC TC <<<"$(mk_player 30 1)"
svc "UPDATE app.special_marker_stock SET on_hand = 5 WHERE trail_id = '$TRAIL' AND facility_id = '$FAC';"
race "same entitlement" "SELECT 1 FROM app.entitlement WHERE id = '$EC' FOR UPDATE" "$EC" "$TC" "$EC" "$TC"
oks=0; refused=0
for v in "$RES_A" "$RES_B"; do
  [ "$v" = "ok" ] && oks=$((oks + 1))
  { [ "$v" = "not_found" ] || [ "$v" = "not_redeemable" ] || [ "$v" = "replayed" ]; } && refused=$((refused + 1))
done
{ [ "$oks" -eq 1 ] && [ "$refused" -eq 1 ]; } || fail "same entitlement: expected exactly one ok and one refusal, got a='$RES_A' b='$RES_B'"
[ "$(sq "SELECT on_hand FROM app.special_marker_stock WHERE trail_id = '$TRAIL' AND facility_id = '$FAC'")" = "4" ] || fail "same entitlement: the stock did not go down by exactly one unit"
[ "$(sq "SELECT count(*) FROM app.special_marker_stock_movement WHERE entitlement_id = '$EC' AND kind = 'redeemed'")" = "1" ] || fail "same entitlement: not exactly one redeemed movement"
[ "$(hq "SELECT count(*) FROM app.attestation WHERE token_jti = 'smh:handover:$TC'")" = "1" ] || fail "same entitlement: not exactly one attestation"
echo "2. same entitlement twice: one ok, one refusal ($RES_A / $RES_B), the stock went down by one"

# ---------------------------------------------------------------------------
# 3. THE PLAY GUARD AT A REAL COMMIT
# ---------------------------------------------------------------------------
PU="$(uid 40 1)"; PLAY="$P-0000-0000-0028-$(printf '%012x' 1)"; EP="$P-0000-0000-0028-$(printf '%012x' 2)"; HP="$(sha "conc58-token-$RUN-play")"
svc "INSERT INTO auth.users (id, email) VALUES ('$PU', 'conc58play-$RUN@partner.test');
     INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status) VALUES ('$PLAY', '$PU', 'crs_x1', '$FAC', current_date, 'v1', 'confirmed');
     INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, activated_at, play_id) VALUES ('$EP', '$PU', 'special_marker', '$TRAIL', 'redeemable', now(), '$PLAY');
     UPDATE app.special_marker_stock SET on_hand = 3 WHERE trail_id = '$TRAIL' AND facility_id = '$FAC';"
hx "INSERT INTO app.partner_handover_token (token_hash, entitlement_id, facility_id, issued_by, created_at, expires_at) VALUES ('$HP', '$EP', '$FAC', '$SA', now(), now() + interval '10 minutes');"
pin_grants
redeem_sql "$HA" "$EP" "$HP" | edge conc_play >"$OUT_DIR/p.out" 2>"$OUT_DIR/p.err" || { fail "play guard: the redeem (or its COMMIT) failed"; cat "$OUT_DIR/p.err" >&2; }
[ "$(sed -n 's/^R://p' "$OUT_DIR/p.out")" = "ok" ] || fail "play guard: the redeem of a play-backed entitlement did not answer ok"
[ "$(sq "SELECT state FROM app.entitlement WHERE id = '$EP'")" = "redeemed" ] || fail "play guard: the entitlement is not redeemed after the commit (read from another connection)"
echo "3. play guard: a play-backed entitlement redeemed and committed"

if [ "$FAILED" -ne 0 ]; then echo "tools/db/test-partner-stock-concurrency.sh: FAILED" >&2; exit 1; fi
echo "tools/db/test-partner-stock-concurrency.sh: ok ($ROUNDS last-unit rounds, the same-entitlement race, the play guard at a real commit)"
