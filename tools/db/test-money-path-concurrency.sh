#!/usr/bin/env bash
# tools/db/test-money-path-concurrency.sh
#
# H3 + should-fix (post-P3a gate): "Add a concurrent two-session test
# (same approach as test-replay-concurrency.sh)" for max_redemptions, and
# "Add money-path concurrency tests (max_redemptions, budget, dedupe) to
# the harness." pgTAP tests run inside ONE transaction on ONE connection,
# so — same reasoning as test-replay-concurrency.sh — a genuine two-
# session race needs two REAL, concurrent psql connections, which this
# script provides for all three money-path race conditions the gate
# named.
#
# Usage: PGHOST=... PGPORT=... PGUSER=... PGDATABASE=... bash
#   tools/db/test-money-path-concurrency.sh
# (tools/db/test.sh sets these and calls this script after
# test-replay-concurrency.sh, against the same throwaway cluster/
# database, before teardown.)

set -euo pipefail

# Same reasoning as test-replay-concurrency.sh's own fix: these
# operations' real production identity is service_role, not whatever
# PGUSER the harness connects as (migration_owner under
# HARNESS_MODE=restricted — NOSUPERUSER NOBYPASSRLS, no grants on the
# tables/functions this script touches).
PSQL=(psql -v ON_ERROR_STOP=1 -A -t -q -c "SET ROLE service_role;")
FAILED=0

count() {
  "${PSQL[@]}" -c "$1" | tr -d '[:space:]'
}

TAG="mpconc-$(date +%s%N)"

echo "tools/db/test-money-path-concurrency.sh: max_redemptions race (H3)"
OFFER_ID="c1a00000-0000-0000-0000-000000000001"
"${PSQL[@]}" -c "
  INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, max_redemptions, valid_from, valid_to, status)
  VALUES ('$OFFER_ID'::uuid, 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 1000, 1, current_date, current_date + 30, 'live')
  ON CONFLICT (id) DO UPDATE SET max_redemptions = 1, budget_cap = 1000, budget_used = 0, budget_reserved = 0, status = 'live', valid_from = current_date, valid_to = current_date + 30;
" >/dev/null
"${PSQL[@]}" -c "DELETE FROM app.offer_code WHERE offer_id = '$OFFER_ID';" >/dev/null

INSERT_A="INSERT INTO app.offer_code (offer_id, user_id, facility_id, state)
  VALUES ('$OFFER_ID', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned')
  ON CONFLICT DO NOTHING;"
INSERT_B="INSERT INTO app.offer_code (offer_id, user_id, facility_id, state)
  VALUES ('$OFFER_ID', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'earned')
  ON CONFLICT DO NOTHING;"
"${PSQL[@]}" -c "$INSERT_A" >/dev/null 2>/tmp/mpconc-a.err &
PID1=$!
"${PSQL[@]}" -c "$INSERT_B" >/dev/null 2>/tmp/mpconc-b.err &
PID2=$!
wait "$PID1" "$PID2" || true

N=$(count "SELECT count(*) FROM app.offer_code WHERE offer_id = '$OFFER_ID'")
if [ "$N" != "1" ]; then
  echo "FAIL: max_redemptions=1 race allowed $N offer_code rows against the same offer (expected 1)" >&2
  cat /tmp/mpconc-a.err /tmp/mpconc-b.err >&2 || true
  FAILED=1
else
  echo "PASS: concurrent redemption race -> exactly 1 offer_code row (max_redemptions=1 held)"
fi
"${PSQL[@]}" -c "DELETE FROM app.offer_code WHERE offer_id = '$OFFER_ID'; DELETE FROM app.offer WHERE id = '$OFFER_ID';" >/dev/null

echo "tools/db/test-money-path-concurrency.sh: offer budget reservation race (should-fix)"
BUDGET_OFFER_ID="c1a00000-0000-0000-0000-000000000002"
"${PSQL[@]}" -c "
  INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, valid_from, valid_to, status)
  VALUES ('$BUDGET_OFFER_ID'::uuid, 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, current_date, current_date + 30, 'live')
  ON CONFLICT (id) DO UPDATE SET budget_cap = 100, budget_used = 0, budget_reserved = 0, status = 'live', valid_from = current_date, valid_to = current_date + 30;
" >/dev/null

RESERVE_60="SELECT app.reserve_offer_budget('$BUDGET_OFFER_ID'::uuid, 60);"
"${PSQL[@]}" -c "$RESERVE_60" >/tmp/mpconc-r1.out 2>/tmp/mpconc-r1.err &
PID3=$!
"${PSQL[@]}" -c "$RESERVE_60" >/tmp/mpconc-r2.out 2>/tmp/mpconc-r2.err &
PID4=$!
wait "$PID3" "$PID4" || true

RESERVED=$(count "SELECT budget_reserved FROM app.offer WHERE id = '$BUDGET_OFFER_ID'")
# Two concurrent reservations of 60 against a cap of 100: at most ONE can
# succeed (60 <= 100, but 60+60=120 > 100) -- budget_reserved must land at
# exactly 60.00, never 120.00 (both succeeding) and never 0.00 (both
# failing when one legitimately should have succeeded). budget_reserved
# is numeric(10,2), so the raw text is "60.00", not "60".
if [ "$RESERVED" != "60.00" ]; then
  echo "FAIL: concurrent reserve_offer_budget race left budget_reserved=$RESERVED, expected exactly 60.00 (one success, one rejection)" >&2
  cat /tmp/mpconc-r1.out /tmp/mpconc-r2.out /tmp/mpconc-r1.err /tmp/mpconc-r2.err >&2 || true
  FAILED=1
else
  echo "PASS: concurrent reserve_offer_budget race -> budget_reserved=60 exactly (row lock held)"
fi
"${PSQL[@]}" -c "DELETE FROM app.offer WHERE id = '$BUDGET_OFFER_ID';" >/dev/null

echo "tools/db/test-money-path-concurrency.sh: receipt phash dedupe race, SAME user (M4)"
"${PSQL[@]}" -c "DELETE FROM app.purchase_evidence WHERE id::text LIKE 'c1a00002%'; DELETE FROM app.receipt_fingerprint WHERE phash = '$TAG';" >/dev/null 2>&1 || true
PE_1="c1a00002-0000-0000-0000-000000000001"
PE_2="c1a00002-0000-0000-0000-000000000002"
"${PSQL[@]}" -c "
  INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
  VALUES ('$PE_1'::uuid, '00000000-0000-0000-0000-00000000000a', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid'),
         ('$PE_2'::uuid, '00000000-0000-0000-0000-00000000000a', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')
  ON CONFLICT (id) DO NOTHING;
" >/dev/null

# ⛔ FIX (post-P3a re-gate, cross-user griefing): dedupe_receipt_fingerprint
# now only auto-voids a phash match from the SAME user (a genuine retry) --
# this race proves that path is still race-safe under two REAL concurrent
# sessions, same as before the fix.
DEDUPE_1="SELECT app.dedupe_receipt_fingerprint('$PE_1'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid, '$TAG', 'fac_x', current_date);"
DEDUPE_2="SELECT app.dedupe_receipt_fingerprint('$PE_2'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid, '$TAG', 'fac_x', current_date);"
"${PSQL[@]}" -c "$DEDUPE_1" >/tmp/mpconc-d1.out 2>/tmp/mpconc-d1.err &
PID5=$!
"${PSQL[@]}" -c "$DEDUPE_2" >/tmp/mpconc-d2.out 2>/tmp/mpconc-d2.err &
PID6=$!
wait "$PID5" "$PID6" || true

FP_COUNT=$(count "SELECT count(*) FROM app.receipt_fingerprint WHERE phash = '$TAG'")
VOID_COUNT=$(count "SELECT count(*) FROM app.purchase_evidence WHERE id IN ('$PE_1', '$PE_2') AND status = 'void' AND void_reason = 'duplicate'")
if [ "$FP_COUNT" != "1" ] || [ "$VOID_COUNT" != "1" ]; then
  echo "FAIL: concurrent SAME-USER dedupe_receipt_fingerprint race left $FP_COUNT fingerprint row(s) and $VOID_COUNT void(void_reason=duplicate) purchase(s), expected exactly 1 and 1" >&2
  cat /tmp/mpconc-d1.out /tmp/mpconc-d2.out /tmp/mpconc-d1.err /tmp/mpconc-d2.err >&2 || true
  FAILED=1
else
  echo "PASS: concurrent SAME-USER receipt-phash dedupe race -> exactly 1 fingerprint row, exactly 1 purchase voided (void_reason=duplicate)"
fi
"${PSQL[@]}" -c "DELETE FROM app.receipt_fingerprint WHERE phash = '$TAG'; DELETE FROM app.purchase_evidence WHERE id IN ('$PE_1', '$PE_2');" >/dev/null

echo "tools/db/test-money-path-concurrency.sh: receipt phash dedupe race, CROSS user (post-P3a re-gate)"
TAG_XU="${TAG}-xu"
"${PSQL[@]}" -c "DELETE FROM app.purchase_evidence WHERE id::text LIKE 'c1a00004%'; DELETE FROM app.receipt_fingerprint WHERE phash = '$TAG_XU'; DELETE FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id::text LIKE 'c1a00004%';" >/dev/null 2>&1 || true
PE_3="c1a00004-0000-0000-0000-000000000001"
PE_4="c1a00004-0000-0000-0000-000000000002"
"${PSQL[@]}" -c "
  INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
  VALUES ('$PE_3'::uuid, '00000000-0000-0000-0000-00000000000a', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid'),
         ('$PE_4'::uuid, '00000000-0000-0000-0000-00000000000b', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')
  ON CONFLICT (id) DO NOTHING;
" >/dev/null

DEDUPE_3="SELECT app.dedupe_receipt_fingerprint('$PE_3'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid, '$TAG_XU', 'fac_x', current_date);"
DEDUPE_4="SELECT app.dedupe_receipt_fingerprint('$PE_4'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid, '$TAG_XU', 'fac_x', current_date);"
"${PSQL[@]}" -c "$DEDUPE_3" >/tmp/mpconc-d3.out 2>/tmp/mpconc-d3.err &
PID7=$!
"${PSQL[@]}" -c "$DEDUPE_4" >/tmp/mpconc-d4.out 2>/tmp/mpconc-d4.err &
PID8=$!
wait "$PID7" "$PID8" || true

FP_COUNT_XU=$(count "SELECT count(*) FROM app.receipt_fingerprint WHERE phash = '$TAG_XU'")
VOID_COUNT_XU=$(count "SELECT count(*) FROM app.purchase_evidence WHERE id IN ('$PE_3', '$PE_4') AND status = 'void'")
PENDING_COUNT_XU=$(count "SELECT count(*) FROM app.purchase_evidence WHERE id IN ('$PE_3', '$PE_4') AND status = 'pending'")
REVIEW_COUNT_XU=$(count "SELECT count(*) FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id IN ('$PE_3', '$PE_4')")
if [ "$FP_COUNT_XU" != "1" ] || [ "$VOID_COUNT_XU" != "0" ] || [ "$PENDING_COUNT_XU" != "2" ] || [ "$REVIEW_COUNT_XU" -lt "1" ]; then
  echo "FAIL: concurrent CROSS-USER dedupe_receipt_fingerprint race: fp=$FP_COUNT_XU void=$VOID_COUNT_XU pending=$PENDING_COUNT_XU review=$REVIEW_COUNT_XU (expected fp=1 void=0 pending=2 review>=1 -- neither purchase should be auto-voided across users)" >&2
  cat /tmp/mpconc-d3.out /tmp/mpconc-d4.out /tmp/mpconc-d3.err /tmp/mpconc-d4.err >&2 || true
  FAILED=1
else
  echo "PASS: concurrent CROSS-USER receipt-phash dedupe race -> exactly 1 fingerprint row, ZERO voided, both left pending, review_item opened (no griefing)"
fi
"${PSQL[@]}" -c "DELETE FROM app.receipt_fingerprint WHERE phash = '$TAG_XU'; DELETE FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id IN ('$PE_3', '$PE_4'); DELETE FROM app.purchase_evidence WHERE id IN ('$PE_3', '$PE_4');" >/dev/null

echo "tools/db/test-money-path-concurrency.sh: receipt OCR dedupe race, CROSS user (post-P3a re-gate correction)"
# ⛔ FIX (post-P3a re-gate, correction): an OCR collision is the SAME
# griefing vector as a phash collision when it's the SAME physical
# receipt (both the phash AND the OCR number match) -- this race proves
# the OCR path is ALSO race-safe under two real concurrent sessions,
# same as the phash path above. Different phashes on purpose (so this
# exercises the OCR unique-index/EXCEPTION path specifically, not the
# phash SELECT path).
TAG_OCR_XU="OCR-${TAG}-xu"
"${PSQL[@]}" -c "DELETE FROM app.purchase_evidence WHERE id::text LIKE 'c1a00005%'; DELETE FROM app.receipt_fingerprint WHERE receipt_number_ocr = '$TAG_OCR_XU'; DELETE FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id::text LIKE 'c1a00005%';" >/dev/null 2>&1 || true
PE_5="c1a00005-0000-0000-0000-000000000001"
PE_6="c1a00005-0000-0000-0000-000000000002"
"${PSQL[@]}" -c "
  INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
  VALUES ('$PE_5'::uuid, '00000000-0000-0000-0000-00000000000a', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid'),
         ('$PE_6'::uuid, '00000000-0000-0000-0000-00000000000b', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')
  ON CONFLICT (id) DO NOTHING;
" >/dev/null

DEDUPE_5="SELECT app.dedupe_receipt_fingerprint('$PE_5'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid, '${TAG}-ocr-xu-a', 'fac_x', current_date, '$TAG_OCR_XU');"
DEDUPE_6="SELECT app.dedupe_receipt_fingerprint('$PE_6'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid, '${TAG}-ocr-xu-b', 'fac_x', current_date, '$TAG_OCR_XU');"
"${PSQL[@]}" -c "$DEDUPE_5" >/tmp/mpconc-d5.out 2>/tmp/mpconc-d5.err &
PID9=$!
"${PSQL[@]}" -c "$DEDUPE_6" >/tmp/mpconc-d6.out 2>/tmp/mpconc-d6.err &
PID10=$!
wait "$PID9" "$PID10" || true

FP_COUNT_OCR_XU=$(count "SELECT count(*) FROM app.receipt_fingerprint WHERE receipt_number_ocr = '$TAG_OCR_XU'")
VOID_COUNT_OCR_XU=$(count "SELECT count(*) FROM app.purchase_evidence WHERE id IN ('$PE_5', '$PE_6') AND status = 'void'")
PENDING_COUNT_OCR_XU=$(count "SELECT count(*) FROM app.purchase_evidence WHERE id IN ('$PE_5', '$PE_6') AND status = 'pending'")
REVIEW_COUNT_OCR_XU=$(count "SELECT count(*) FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id IN ('$PE_5', '$PE_6')")
if [ "$FP_COUNT_OCR_XU" != "1" ] || [ "$VOID_COUNT_OCR_XU" != "0" ] || [ "$PENDING_COUNT_OCR_XU" != "2" ] || [ "$REVIEW_COUNT_OCR_XU" -lt "1" ]; then
  echo "FAIL: concurrent CROSS-USER OCR dedupe race: fp=$FP_COUNT_OCR_XU void=$VOID_COUNT_OCR_XU pending=$PENDING_COUNT_OCR_XU review=$REVIEW_COUNT_OCR_XU (expected fp=1 void=0 pending=2 review>=1)" >&2
  cat /tmp/mpconc-d5.out /tmp/mpconc-d6.out /tmp/mpconc-d5.err /tmp/mpconc-d6.err >&2 || true
  FAILED=1
else
  echo "PASS: concurrent CROSS-USER OCR dedupe race -> exactly 1 fingerprint row, ZERO voided, both left pending, review_item opened (no griefing)"
fi
"${PSQL[@]}" -c "DELETE FROM app.receipt_fingerprint WHERE receipt_number_ocr = '$TAG_OCR_XU'; DELETE FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id IN ('$PE_5', '$PE_6'); DELETE FROM app.purchase_evidence WHERE id IN ('$PE_5', '$PE_6');" >/dev/null

echo "tools/db/test-money-path-concurrency.sh: dedupe_receipt_fingerprint isolation-level guard (M4)"
# M4 fix 1: dedupe_receipt_fingerprint asserts transaction_isolation =
# read committed and raises otherwise -- pgTAP cannot exercise this (its
# whole matrix runs in one already-open transaction, and
# `SET TRANSACTION ISOLATION LEVEL` must be the first statement of a
# transaction), so it's checked here, on a real, fresh session that sets
# REPEATABLE READ *before* opening its transaction via `-c`'s own BEGIN.
PE_ISO="c1a00003-0000-0000-0000-000000000001"
"${PSQL[@]}" -c "DELETE FROM app.purchase_evidence WHERE id = '$PE_ISO'::uuid;" >/dev/null 2>&1 || true
"${PSQL[@]}" -c "
  INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
  VALUES ('$PE_ISO'::uuid, '00000000-0000-0000-0000-00000000000a', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')
  ON CONFLICT (id) DO NOTHING;
" >/dev/null
ISO_ERR=$(psql -v ON_ERROR_STOP=1 -A -t -q \
  -c "SET ROLE service_role;" \
  -c "BEGIN ISOLATION LEVEL REPEATABLE READ;" \
  -c "SELECT app.dedupe_receipt_fingerprint('$PE_ISO'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid, '$TAG-iso', 'fac_x', current_date);" \
  -c "COMMIT;" 2>&1) || true
if echo "$ISO_ERR" | grep -qi "read committed"; then
  echo "PASS: dedupe_receipt_fingerprint rejects a call under REPEATABLE READ isolation"
else
  echo "FAIL: dedupe_receipt_fingerprint did not reject a call under REPEATABLE READ isolation" >&2
  echo "$ISO_ERR" >&2
  FAILED=1
fi
"${PSQL[@]}" -c "DELETE FROM app.purchase_evidence WHERE id = '$PE_ISO'::uuid;" >/dev/null

rm -f /tmp/mpconc-*.out /tmp/mpconc-*.err 2>/dev/null || true

if [ "$FAILED" -ne 0 ]; then
  echo "tools/db/test-money-path-concurrency.sh: FAILED" >&2
  exit 1
fi
echo "tools/db/test-money-path-concurrency.sh: all money-path concurrency checks passed"
