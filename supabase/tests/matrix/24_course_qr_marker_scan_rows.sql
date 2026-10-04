-- 24_course_qr_marker_scan_rows.sql
-- 0046: the rows 24_course_qr_marker_scan_edge.sql COMMITTED (pg_prove runs it first, in file order), read back as service_role, then exported and deleted, and everything the
-- edge file seeded is cleaned up (the ee240000- accounts, the fac_s24* / trl_s24* catalog and programme rows, the QR registry, the tokens, the keys, the alarm, the counters and the pepper).
-- ⛔ WATCH (the silent class edge_actor introduces): under RLS an UPDATE or DELETE with no matching policy affects ZERO rows and raises nothing, and edge_actor holds no SELECT on
-- the purchase / credit tables, so every "it was written" claim of the edge file is proven HERE by reading the row back as a role that may read it.
-- Scenarios C1..C8 are listed in the edge file (section 11a). Today's date is the facility-LOCAL date (America/Chicago for fac_s24a / b / e / h).

\set QUIET 1
SELECT plan(71);
SET ROLE service_role;

-- ----------------------------------------------------------------------------
-- C1 PA: a rotating token + an attested fix -> valid / credited on both trails
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0'), 2, 'C1: PA has exactly two purchase rows (one per eligible trail), written by the scan');
SELECT is((SELECT array_agg(trail_id ORDER BY trail_id) FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0'), ARRAY['trl_s24a', 'trl_s24b'], 'C1: on the facility''s two trails');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0' AND method = 'course_qr' AND qr_variant = 'rotating' AND status = 'valid' AND facility_id = 'fac_s24a'
             AND offline = false AND no_cosignal_reason IS NULL AND ip_region_match IS NULL AND ref_id = encode(sha256(convert_to('s24-tok-10', 'UTF8')), 'hex')), 2, 'C1: method course_qr, variant rotating, valid, ref = the token''s nonce HASH (never the nonce), not offline');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0' AND local_date = (now() AT TIME ZONE 'America/Chicago')::date), 2, 'C1: the purchase carries the facility-LOCAL date');
SELECT is((SELECT array_agg(DISTINCT cosignal ->> 'grade' || '/' || (cosignal ->> 'fixId') || '/' || (cosignal ->> 'evidenceId')) FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0'),
  ARRAY['attested/fixN1/ee240000-0000-0000-0000-00000000f101'], 'C1: the purchase records the co-signal (grade, fix id, and the evidence row the fix was counted as)');
SELECT is((SELECT (cosignal ? 'awaiting') FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0' AND trail_id = 'trl_s24a'), false, 'C1: a completed purchase awaits nothing');
SELECT is((SELECT count(*)::int FROM app.marker_credit c JOIN app.purchase_evidence p ON p.id = c.purchase_evidence_id WHERE c.user_id = 'ee240000-0000-0000-0000-0000000000a0' AND c.status = 'credited' AND c.facility_id = 'fac_s24a'), 2, 'C1: two credited credits, each linked to its own purchase');
SELECT is((SELECT used_by_user FROM app.course_qr_token WHERE nonce_hash = encode(sha256(convert_to('s24-tok-10', 'UTF8')), 'hex')), 'ee240000-0000-0000-0000-0000000000a0'::uuid, 'C1: the token is consumed, by PA (the buyer, not the staff member who minted it)');
SELECT is((SELECT used_at IS NOT NULL FROM app.course_qr_token WHERE nonce_hash = encode(sha256(convert_to('s24-tok-10', 'UTF8')), 'hex')), true, 'C1: and has a use time');
SELECT is((SELECT count(*)::int FROM app.course_qr_token WHERE nonce_hash IN (SELECT encode(sha256(convert_to('s24-tok-' || n, 'UTF8')), 'hex') FROM generate_series(1, 22) n) AND used_at IS NOT NULL), 6,
  'only the tokens a COMMITTED scan consumed are used (10, 11, 12, 13, 20, 21): every rolled-back scan left its token unused');

-- ----------------------------------------------------------------------------
-- C2 PB: no fix -> pending / pending, with the window a later fix must fall in
-- ----------------------------------------------------------------------------
SELECT is((SELECT array_agg(status::text) FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000b0' AND facility_id = 'fac_s24a'), ARRAY['pending', 'pending'], 'C2 (AT(3)): the no-fix scan is a PENDING purchase, on both trails');
SELECT is((SELECT array_agg(c.status::text) FROM app.marker_credit c WHERE c.user_id = 'ee240000-0000-0000-0000-0000000000b0' AND c.facility_id = 'fac_s24a'), ARRAY['pending', 'pending'], 'C2 (AT(3)): and the credits are `pending` (never credited without a co-signal)');
SELECT is((SELECT count(*)::int FROM app.marker_credit c JOIN app.purchase_evidence p ON p.id = c.purchase_evidence_id WHERE c.user_id = 'ee240000-0000-0000-0000-0000000000b0' AND c.facility_id = 'fac_s24a'), 2, 'C2: each credit is linked to its purchase');
SELECT is((SELECT count(DISTINCT cosignal)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000b0' AND facility_id = 'fac_s24a'), 1, 'C2: both trails'' rows carry the same awaiting window (one scan)');
SELECT is((SELECT (SELECT abs(extract(epoch FROM (p.cosignal -> 'awaiting' ->> 'from')::timestamptz - (t.issued_at - interval '120 seconds'))) < 0.002 AND abs(extract(epoch FROM (p.cosignal -> 'awaiting' ->> 'to')::timestamptz - (t.issued_at + interval '120 seconds'))) < 0.002
                  FROM app.purchase_evidence p WHERE p.user_id = 'ee240000-0000-0000-0000-0000000000b0' AND p.facility_id = 'fac_s24a' AND p.trail_id = 'trl_s24a')
           FROM app.course_qr_token t WHERE t.nonce_hash = encode(sha256(convert_to('s24-tok-11', 'UTF8')), 'hex')), true, 'C2: the window is 120 s either side of the token''s ISSUE time (plan §4.6(q))');
SELECT is((SELECT abs(extract(epoch FROM (p.cosignal -> 'awaiting' ->> 'until')::timestamptz - (p.created_at + interval '7 days'))) < 1 FROM app.purchase_evidence p WHERE p.user_id = 'ee240000-0000-0000-0000-0000000000b0' AND p.facility_id = 'fac_s24a' AND p.trail_id = 'trl_s24a'), true,
  'C2: and the 7-day deadline runs from the scan');
SELECT is((SELECT used_by_user FROM app.course_qr_token WHERE nonce_hash = encode(sha256(convert_to('s24-tok-11', 'UTF8')), 'hex')), 'ee240000-0000-0000-0000-0000000000b0'::uuid, 'C2: a no-fix scan consumed the token');

-- ----------------------------------------------------------------------------
-- C3 PC: a no-fix scan completed by a later fix (the reconnect)
-- ----------------------------------------------------------------------------
SELECT is((SELECT array_agg(status::text) FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000c0' AND facility_id = 'fac_s24a'), ARRAY['valid', 'valid'], 'C3: the later fix made the purchases valid');
SELECT is((SELECT array_agg(status::text) FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-0000000000c0' AND facility_id = 'fac_s24a'), ARRAY['credited', 'credited'], 'C3: and the credits credited ...');
SELECT is((SELECT count(*)::int FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-0000000000c0' AND facility_id = 'fac_s24a'), 2, 'C3: ... UPDATED in place, not duplicated (two rows in all)');
SELECT is((SELECT array_agg(DISTINCT cosignal ->> 'fixId' || '/' || (cosignal ->> 'evidenceId')) FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000c0' AND facility_id = 'fac_s24a'), ARRAY['fixN3/ee240000-0000-0000-0000-00000000f103'],
  'C3: the purchase now records the fix that completed it, and no longer awaits one');
SELECT is((SELECT status::text FROM app.purchase_evidence WHERE id = 'ee240000-0000-0000-0000-00000000e302'), 'pending', 'C3: PC''s OTHER row (the stand-in whose 7-day deadline had passed) stayed pending');

-- ----------------------------------------------------------------------------
-- C4 PD: the printed QR, no fix
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000d0'), 1, 'C4: one purchase (fac_s24e is on one trail)');
SELECT is((SELECT qr_variant::text || '/' || status::text || '/' || ref_id FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000d0'),
  'static_pin/pending/pin:fac_s24e:' || to_char((now() AT TIME ZONE 'America/Chicago')::date, 'YYYY-MM-DD') || ':0', 'C4: static_pin, pending, the ref is the PIN''s facility, date and epoch (never the PIN)');
SELECT is((SELECT (cosignal -> 'awaiting' ->> 'from')::timestamptz = (date_trunc('day', now() AT TIME ZONE 'America/Chicago')) AT TIME ZONE 'America/Chicago'
              AND (cosignal -> 'awaiting' ->> 'to')::timestamptz = ((date_trunc('day', now() AT TIME ZONE 'America/Chicago') + interval '1 day') AT TIME ZONE 'America/Chicago') - interval '1 millisecond'
           FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000d0'), true, 'C4: for the printed QR the window is the facility-local DAY (local midnight to the millisecond before the next; DST-safe)');
SELECT is((SELECT status::text FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-0000000000d0' AND facility_id = 'fac_s24e'), 'pending', 'C4: the credit is pending');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE ref_id ~* '^pin:' AND ref_id ~ '[0-9]{4}$' AND ref_id !~ ':[0-9]{1,3}$'), 0, 'no purchase ref ends in a 4-digit PIN (only the epoch, a short integer, is in it)');

-- ----------------------------------------------------------------------------
-- C5 PE: an unattestable fix -> held_review
-- ----------------------------------------------------------------------------
SELECT is((SELECT array_agg(DISTINCT status::text) FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000e0' AND facility_id = 'fac_s24a'), ARRAY['held_review'], 'C5 (AT(19)): an unattestable presence fix sends the purchase to held_review');
SELECT is((SELECT array_agg(DISTINCT status::text) FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-0000000000e0' AND facility_id = 'fac_s24a'), ARRAY['held_review'], 'C5 (AT(19)): and the credit');
SELECT is((SELECT array_agg(DISTINCT cosignal ->> 'grade') FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000e0' AND facility_id = 'fac_s24a'), ARRAY['unattestable'], 'C5: the grade that routed it is on the row');

-- ----------------------------------------------------------------------------
-- C6 PF: the printed QR + an attested fix
-- ----------------------------------------------------------------------------
SELECT is((SELECT status::text || '/' || qr_variant::text FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000f0' AND facility_id = 'fac_s24e'), 'valid/static_pin', 'C6: the printed QR + the PIN + an attested fix is valid');
SELECT is((SELECT status::text FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-0000000000f0' AND facility_id = 'fac_s24e'), 'credited', 'C6: and credited');

-- ----------------------------------------------------------------------------
-- C7 PB: AT(13), the offline-code purchase completed by the player's co-signal
-- ----------------------------------------------------------------------------
SELECT is((SELECT status::text FROM app.purchase_evidence WHERE id = 'ee240000-0000-0000-0000-00000000e301'), 'valid', 'C7 (AT(13)): the staff_scan row S3 will write becomes valid when the player''s co-signal arrives');
SELECT is((SELECT method::text || '/' || offline::text || '/' || ref_id FROM app.purchase_evidence WHERE id = 'ee240000-0000-0000-0000-00000000e301'),
  'staff_scan/true/offline:ee240000-0000-0000-0000-00000000b001:1:' || floor(extract(epoch FROM (SELECT created_at FROM app.purchase_evidence WHERE id = 'ee240000-0000-0000-0000-00000000e301')) / 600)::bigint, 'C7: and the method, the offline flag and the step reference S3 wrote are untouched');
SELECT is((SELECT cosignal ->> 'fixId' FROM app.purchase_evidence WHERE id = 'ee240000-0000-0000-0000-00000000e301'), 'fixN7', 'C7: it records the completing fix');
SELECT is((SELECT status::text FROM app.marker_credit WHERE id = 'ee240000-0000-0000-0000-00000000ec01'), 'credited', 'C7: its (pre-existing, pending) credit is credited ...');
SELECT is((SELECT count(*)::int FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-0000000000b0' AND facility_id = 'fac_s24b'), 1, 'C7: ... not duplicated');
SELECT is((SELECT status::text FROM app.purchase_evidence WHERE id = 'ee240000-0000-0000-0000-00000000e303'), 'pending', 'C7: the stand-ins whose window or deadline did not fit a fix stayed pending (e303: window over)');

-- ----------------------------------------------------------------------------
-- C8 PG: a second purchase at a shop the player is already credited at
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-000000000010' AND facility_id = 'fac_s24b' AND status = 'valid'), 2, 'C8: both purchases are on file, valid');
SELECT is((SELECT count(*)::int FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-000000000010' AND facility_id = 'fac_s24b'), 1, 'C8: and there is ONE credit for the shop (a second would add nothing; the partial unique index forbids it)');
SELECT is((SELECT status::text FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-000000000010' AND facility_id = 'fac_s24b'), 'credited', 'C8: credited');

-- ----------------------------------------------------------------------------
-- The invariants AT(3) and AT(4) are about
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM app.marker_credit c JOIN app.purchase_evidence p ON p.id = c.purchase_evidence_id
           WHERE c.user_id::text LIKE 'ee240000-%' AND c.status = 'credited' AND p.method = 'course_qr' AND p.cosignal ->> 'grade' IS DISTINCT FROM 'attested'), 0,
  'AT(3): not one credited course_qr credit rests on a purchase without an ATTESTED co-signal');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence p WHERE p.user_id::text LIKE 'ee240000-%' AND p.method = 'course_qr' AND p.status = 'valid' AND (p.cosignal ->> 'fixId') IS NULL), 0, 'AT(3): and not one valid course_qr purchase lacks a fix');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence p WHERE p.user_id::text LIKE 'ee240000-%' AND p.method = 'course_qr' AND p.status = 'pending' AND (p.cosignal ? 'awaiting') IS NOT TRUE), 0, 'every pending course_qr purchase records the window it awaits a co-signal in');
SELECT is((SELECT count(*)::int FROM app.play WHERE user_id::text LIKE 'ee240000-%'), 0, 'AT(4): a marker purchase alone creates NO play (not one app.play row for any account of this file)');
SELECT is((SELECT count(*)::int FROM app.evidence WHERE user_id::text LIKE 'ee240000-%' AND source_ref <> 'edge24-pa-queued'), 0, 'AT(4): and the database scan writes no play evidence (the fix''s foreground_checkin row is the Edge''s, once: supabase/tests/integration/marker-scan.deno.test.ts)');

-- ----------------------------------------------------------------------------
-- The alarm (11c): 30 wrong PINs from six players at fac_s24h
-- ----------------------------------------------------------------------------
SELECT is((SELECT pin_epoch FROM app.facility_programme WHERE facility_id = 'fac_s24h'), 1, 'AT(19): the 30th wrong PIN at fac_s24h rotated its PIN (pin_epoch 0 -> 1)');
SELECT is((SELECT count(*)::int FROM app.course_pin_alarm WHERE facility_id = 'fac_s24h' AND local_date = (now() AT TIME ZONE 'America/Chicago')::date AND pin_epoch_before = 0 AND pin_epoch_after = 1 AND failures = 30), 1, 'AT(19): and the operator alert (one alarm row: facility, local date, epoch 0 -> 1, 30 failures)');
SELECT is((SELECT count(*)::int FROM app.course_pin_alarm WHERE facility_id <> 'fac_s24h'), 0, 'no other facility raised an alarm (the rolled-back 30th failure at fac_s24a left no alarm)');
SELECT is((SELECT array_agg(pin_epoch ORDER BY facility_id) FROM app.facility_programme WHERE facility_id IN ('fac_s24a', 'fac_s24e')), ARRAY[0, 0, 0], 'the other facilities'' epochs are untouched (including both trail rows of fac_s24a)');
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key LIKE 'marker-scan:pin-fail:u:ee240000-%:fac_s24h:%' AND count = 5), 6, 'the counters of the six players are the committed failures: five each');
SELECT is((SELECT sum(count)::int FROM private.rate_limit_bucket WHERE bucket_key = 'marker-scan:pin-fail:f:fac_s24h:' || to_char((now() AT TIME ZONE 'America/Chicago')::date, 'YYYY-MM-DD') || ':0'), 30, 'and the facility counter of that epoch is 30');
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key LIKE 'marker-scan:pin-fail:%' AND bucket_key ~ ':[0-9]{4}$' AND bucket_key !~ ':[0-9]{4}-[0-9]{2}-[0-9]{2}$' AND bucket_key !~ ':[0-9]{1,3}$'), 0, 'no counter key contains a PIN');

-- ----------------------------------------------------------------------------
-- Export: the purchase and the credit are the subject's own data; the nonce hash is not
-- ----------------------------------------------------------------------------
SELECT is((SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys((private.export_my_data('ee240000-0000-0000-0000-0000000000a0'::uuid) -> 'purchase_evidence') -> 0) k),
  ARRAY['cosignal', 'created_at', 'facility_id', 'id', 'ip_region_match', 'local_date', 'method', 'no_cosignal_reason', 'offline', 'qr_variant', 'status', 'trail_id', 'user_id'], 'export: the purchase_evidence block (ref_id, the consumed token''s nonce hash, stays out of it)');
SELECT is(jsonb_array_length(private.export_my_data('ee240000-0000-0000-0000-0000000000a0'::uuid) -> 'purchase_evidence'), 2, 'export: PA''s two purchases');
SELECT is((SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('ee240000-0000-0000-0000-0000000000a0'::uuid) -> 'purchase_evidence') e WHERE e -> 'cosignal' ->> 'fixId' = 'fixN1'), 2, 'export: with the co-signal the player produced (their own fix id)');
SELECT is(jsonb_array_length(private.export_my_data('ee240000-0000-0000-0000-0000000000a0'::uuid) -> 'marker_credit'), 2, 'export: and PA''s two credits');
SELECT is((private.export_my_data('ee240000-0000-0000-0000-0000000000a0'::uuid)::text ~* encode(sha256(convert_to('s24-tok-10', 'UTF8')), 'hex')), false, 'export: PA''s WHOLE export contains no token nonce hash');
SELECT is((SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('ee240000-0000-0000-0000-0000000000b0'::uuid) -> 'purchase_evidence') e WHERE e ->> 'user_id' <> 'ee240000-0000-0000-0000-0000000000b0'), 0, 'export: PB''s export holds only PB''s rows');
SELECT is((private.export_my_data('ee240000-0000-0000-0000-0000000000a0'::uuid)::text ~* 'course_pin_pepper|golfraven/course-pin'), false, 'export: nor the pepper or the derivation label');

-- ----------------------------------------------------------------------------
-- Delete: PA's rows go with the account (and the token PA consumed); everyone else's stay
-- ----------------------------------------------------------------------------
SELECT lives_ok($$SELECT private.delete_my_data('ee240000-0000-0000-0000-0000000000a0')$$, 'delete: delete_my_data(PA) completes (its fail-closed post-condition re-reads each classified table)');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0'), 0, 'delete: none of PA''s purchases remain');
SELECT is((SELECT count(*)::int FROM app.marker_credit WHERE user_id = 'ee240000-0000-0000-0000-0000000000a0'), 0, 'delete: nor credits');
SELECT is((SELECT count(*)::int FROM app.course_qr_token WHERE used_by_user = 'ee240000-0000-0000-0000-0000000000a0'), 0, 'delete: nor the token PA consumed (delete_row, 0014)');
SELECT is((SELECT count(*)::int FROM app.course_qr_token WHERE used_by_user = 'ee240000-0000-0000-0000-0000000000b0'), 1, 'delete: while PB''s consumed token is untouched');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id = 'ee240000-0000-0000-0000-0000000000b0'), 3, 'delete: and PB''s purchases are untouched (the two pending rows and the stand-in)');
SELECT is((SELECT count(*)::int FROM app.course_qr_key), 3, 'delete: the PUBLIC key table is not personal data and is untouched');

-- ----------------------------------------------------------------------------
-- Cleanup
-- ----------------------------------------------------------------------------
SELECT lives_ok($$SELECT private.delete_my_data(u) FROM (VALUES ('ee240000-0000-0000-0000-0000000000b0'::uuid), ('ee240000-0000-0000-0000-0000000000c0'), ('ee240000-0000-0000-0000-0000000000d0'), ('ee240000-0000-0000-0000-0000000000e0'),
  ('ee240000-0000-0000-0000-0000000000f0'), ('ee240000-0000-0000-0000-000000000010'), ('ee240000-0000-0000-0000-000000000020')) v(u)$$, 'cleanup: delete_my_data for the remaining ee240000- accounts');
DELETE FROM private.rate_limit_bucket WHERE bucket_key LIKE 'marker-scan:pin-fail:%';
DELETE FROM app.course_qr_token WHERE nonce_hash IN (SELECT encode(sha256(convert_to('s24-tok-' || n, 'UTF8')), 'hex') FROM generate_series(1, 22) n);
DELETE FROM app.facility_qr WHERE facility_id LIKE 'fac\_s24%';
DELETE FROM app.facility_programme WHERE facility_id LIKE 'fac\_s24%';
DELETE FROM app.trail_programme WHERE trail_id LIKE 'trl\_s24%';
RESET ROLE;
-- the tables service_role may not write: a temporary CURRENT_USER policy, dropped again. A POLICY ONLY, never a GRANT / REVOKE: under HARNESS_MODE=restricted the connecting role OWNS these
-- tables, and `REVOKE DELETE ... FROM CURRENT_USER` strips the owner's own privilege (the Deno suite, which runs on a copy of this database, then cannot clean up its own keys).
CREATE POLICY current_user_clean_course_qr_key_24 ON app.course_qr_key FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY current_user_clean_course_pin_alarm_24 ON app.course_pin_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
DELETE FROM app.course_qr_key WHERE kid IN ('rk1', 'rk0', 'pq1');
DELETE FROM app.course_pin_alarm WHERE facility_id LIKE 'fac\_s24%';
DROP POLICY current_user_clean_course_qr_key_24 ON app.course_qr_key;
DROP POLICY current_user_clean_course_pin_alarm_24 ON app.course_pin_alarm;
DELETE FROM vault.secrets WHERE name = 'course_pin_pepper';
SET ROLE service_role;
DELETE FROM app.catalog_facility WHERE id LIKE 'fac\_s24%';
DELETE FROM app.catalog_trail WHERE id LIKE 'trl\_s24%';
DELETE FROM app.catalog_id_ledger WHERE id LIKE 'fac\_s24%' OR id LIKE 'trl\_s24%';
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE user_id::text LIKE 'ee240000-%' OR facility_id LIKE 'fac\_s24%'), 0, 'cleanup: no purchase row of this file survives');
SELECT is((SELECT count(*)::int FROM app.catalog_facility WHERE id LIKE 'fac\_s24%') + (SELECT count(*)::int FROM app.course_qr_token WHERE nonce_hash IN (SELECT encode(sha256(convert_to('s24-tok-' || n, 'UTF8')), 'hex') FROM generate_series(1, 22) n)), 0, 'cleanup: no catalog facility and no token of this file survives');
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key LIKE 'marker-scan:%'), 0, 'cleanup: no counter survives');
RESET ROLE;

SELECT * FROM finish();
