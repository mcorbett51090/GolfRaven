#!/usr/bin/env bash
# tools/db/test-signin-proof-concurrency.sh
#
# Edge role PR4a (0039): "a concurrent double-consume of one email-OTP link proof yields exactly one link." pgTAP runs inside ONE transaction on
# ONE connection, so it cannot race a proof; this script is the part that needs TWO REAL, concurrent sessions, each connecting as the real
# `edge_gateway` login (the harness cluster authenticates with `trust`, so no password is needed or used), switching to edge_actor, binding the
# SAME caller and calling private.signin_link_identity_with_proof_for_actor on the SAME proof.
#
#   1. The BLOCKING case: session A redeems and then HOLDS its transaction open (pg_sleep) before it commits; session B starts after A has the
#      locks and must WAIT (the per-account advisory lock, then the proof row's FOR UPDATE), then, once A commits, find the proof consumed and be
#      refused with SQLSTATE 28000. Exactly one session succeeds; the target holds exactly one apple identity and one grant; and B really waited.
#   2. The SYMMETRIC case, repeated: two sessions fired together, no hold; across N rounds, every round has exactly one winner.
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash tools/db/test-signin-proof-concurrency.sh
# (tools/db/test.sh calls it with the harness role in PGUSER, against the same throwaway cluster/database, after the pgTAP matrix.)
# No secret: ids are synthetic, ciphertexts are filler, the edge login is trust-authenticated in this cluster.

set -euo pipefail

: "${PGHOST:?tools/db/test-signin-proof-concurrency.sh: PGHOST must be set}"
: "${PGPORT:?}"
: "${PGUSER:?}"
: "${PGDATABASE:?}"

HARNESS_PSQL=(psql -v ON_ERROR_STOP=1 -A -t -q -c "SET ROLE service_role;")
EDGE_PSQL=(env PGUSER=edge_gateway psql -v ON_ERROR_STOP=1 -A -t -q)
FAILED=0
ROUNDS=6

CALLER="5a5a1902-0000-0000-0000-0000000000c1"
TARGET="5a5a1902-0000-0000-0000-0000000000a1"
TARGET_EMAIL="p19c-pt@signin.test"
TARGET_SESSION="5a5a1902-0000-0000-0000-0000000005a1"
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/golfraven-proof-conc.XXXXXX")"
cleanup() {
  "${HARNESS_PSQL[@]}" -c "SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id IN ('$CALLER', '$TARGET'); DELETE FROM auth.identities WHERE user_id IN ('$CALLER', '$TARGET'); DELETE FROM auth.sessions WHERE user_id IN ('$CALLER', '$TARGET');" >/dev/null 2>&1 || true
  rm -rf "$OUT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

count() { "${HARNESS_PSQL[@]}" -c "$1" | tr -d '[:space:]'; }

seed() {
  # (re)create the two accounts clean; the target has just "signed in" per GoTrue's stamp (what the proof minter corroborates)
  "${HARNESS_PSQL[@]}" -c "
    SELECT private.delete_my_data(u.id) FROM auth.users u WHERE u.id IN ('$CALLER', '$TARGET');
    DELETE FROM auth.identities WHERE user_id IN ('$CALLER', '$TARGET');
    DELETE FROM auth.sessions WHERE user_id IN ('$CALLER', '$TARGET');
    INSERT INTO auth.users (id, email) VALUES ('$CALLER', 'p19c-pc@signin.test'), ('$TARGET', '$TARGET_EMAIL') ON CONFLICT (id) DO NOTHING;
    INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
      ('p19c-pc@signin.test', '$CALLER', '{\"email\":\"p19c-pc@signin.test\"}', 'email'),
      ('$TARGET_EMAIL', '$TARGET', '{\"email\":\"$TARGET_EMAIL\"}', 'email');
    UPDATE auth.users SET last_sign_in_at = clock_timestamp() WHERE id = '$TARGET';
    INSERT INTO auth.sessions (id, user_id, created_at) VALUES ('$TARGET_SESSION', '$TARGET', clock_timestamp());" >/dev/null
}

mint() { # $1 = subject; prints the proof id (minted as edge_signin_minter in its own committed transaction; the address and the subject go in RAW, 0041)
  "${EDGE_PSQL[@]}" -c "BEGIN; SET LOCAL ROLE edge_signin_minter; SELECT private.signin_record_email_proof('$CALLER', '$TARGET', '$TARGET_EMAIL', 'apple', '$1', '$TARGET_SESSION'); COMMIT;" | grep -E '^[0-9a-f-]{36}$'
}

redeem_sql() { # $1 = proof id, $2 = subject, $3 = seconds to hold the transaction open after the link (0 = none)
  cat <<SQL
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('$CALLER');
SELECT private.signin_link_identity_with_proof_for_actor('$1'::uuid, 'apple', '$2', '$TARGET_EMAIL', true, false, decode(repeat('e1', 40), 'hex'), decode(repeat('e2', 70), 'hex'), 'e19');
SELECT pg_sleep($3);
COMMIT;
SQL
}

check_one_link() { # $1 label, $2 subject
  local ids tokens
  ids=$(count "SELECT count(*) FROM auth.identities WHERE user_id = '$TARGET' AND provider = 'apple' AND provider_id = '$2'")
  tokens=$(count "SELECT count(*) FROM app.signin_provider_token WHERE user_id = '$TARGET' AND provider = 'apple'")
  local caller_ids
  caller_ids=$(count "SELECT count(*) FROM auth.identities WHERE user_id = '$CALLER' AND provider = 'apple'")
  if [ "$ids" != "1" ] || [ "$tokens" != "1" ] || [ "$caller_ids" != "0" ]; then
    echo "FAIL: $1: expected exactly 1 apple identity and 1 grant on the TARGET and none on the caller, got identities=$ids grants=$tokens caller_identities=$caller_ids" >&2
    FAILED=1
    return 1
  fi
}

# ---------------------------------------------------------------------------
# 1. The blocking case
# ---------------------------------------------------------------------------
echo "tools/db/test-signin-proof-concurrency.sh: blocking case (A holds the locks; B must wait, then be refused)"
seed
SUB="p19c-sub-block"
PID="$(mint "$SUB")"
redeem_sql "$PID" "$SUB" 2 | "${EDGE_PSQL[@]}" >"$OUT_DIR/a.out" 2>"$OUT_DIR/a.err" &
PA=$!
sleep 0.7 # A has bound, linked and is sleeping inside its transaction with the advisory lock and the proof row lock held
B_START=$(date +%s%N)
set +e
redeem_sql "$PID" "$SUB" 0 | "${EDGE_PSQL[@]}" >"$OUT_DIR/b.out" 2>"$OUT_DIR/b.err"
B_STATUS=$?
set -e
B_MS=$(( ( $(date +%s%N) - B_START ) / 1000000 ))
set +e
wait "$PA"
A_STATUS=$?
set -e
if [ "$A_STATUS" -ne 0 ] || [ "$B_STATUS" -eq 0 ]; then
  echo "FAIL: blocking case: expected A to succeed and B to be refused, got A=$A_STATUS B=$B_STATUS" >&2
  cat "$OUT_DIR/a.err" "$OUT_DIR/b.err" >&2 || true
  FAILED=1
elif ! grep -q "email_proof_refused: that proof was already used" "$OUT_DIR/b.err"; then
  echo "FAIL: blocking case: B was refused, but not as 'already used':" >&2
  cat "$OUT_DIR/b.err" >&2
  FAILED=1
elif [ "$B_MS" -lt 800 ]; then
  echo "FAIL: blocking case: B returned after only ${B_MS} ms: it did not wait for A's locks" >&2
  FAILED=1
else
  check_one_link "blocking case" "$SUB" && echo "PASS: blocking case -> A linked, B waited ${B_MS} ms then was refused (28000, already used), exactly one identity and one grant on the target"
fi

# ---------------------------------------------------------------------------
# 2. The symmetric race, repeated
# ---------------------------------------------------------------------------
for round in $(seq 1 "$ROUNDS"); do
  seed
  SUB="p19c-sub-race-$round"
  PID="$(mint "$SUB")"
  redeem_sql "$PID" "$SUB" 0 | "${EDGE_PSQL[@]}" >"$OUT_DIR/r1.out" 2>"$OUT_DIR/r1.err" &
  P1=$!
  redeem_sql "$PID" "$SUB" 0 | "${EDGE_PSQL[@]}" >"$OUT_DIR/r2.out" 2>"$OUT_DIR/r2.err" &
  P2=$!
  set +e
  wait "$P1"; S1=$?
  wait "$P2"; S2=$?
  set -e
  WINNERS=0
  [ "$S1" -eq 0 ] && WINNERS=$((WINNERS + 1))
  [ "$S2" -eq 0 ] && WINNERS=$((WINNERS + 1))
  if [ "$WINNERS" -ne 1 ]; then
    echo "FAIL: symmetric round $round: expected exactly 1 winner, got $WINNERS (statuses $S1 $S2)" >&2
    cat "$OUT_DIR/r1.err" "$OUT_DIR/r2.err" >&2 || true
    FAILED=1
  elif ! cat "$OUT_DIR/r1.err" "$OUT_DIR/r2.err" | grep -q "email_proof_refused: that proof was already used"; then
    echo "FAIL: symmetric round $round: the loser was not refused as 'already used'" >&2
    cat "$OUT_DIR/r1.err" "$OUT_DIR/r2.err" >&2 || true
    FAILED=1
  else
    check_one_link "symmetric round $round" "$SUB" || true
  fi
done
if [ "$FAILED" -eq 0 ]; then
  echo "PASS: symmetric race x$ROUNDS (2 real sessions each) -> exactly one winner per round, one identity and one grant on the target, none on the caller"
fi

if [ "$FAILED" -ne 0 ]; then
  echo "tools/db/test-signin-proof-concurrency.sh: FAILED" >&2
  exit 1
fi
echo "tools/db/test-signin-proof-concurrency.sh: all proof-redemption concurrency checks passed"
