-- 24_course_qr_marker_scan_edge.sql
-- 0046, the edge_actor lane of the course QR (P5.1a S2a): run as a REAL `edge_gateway` login that SET LOCAL ROLEs into `edge_actor` and binds an actor with private.bind_actor,
-- exactly as 23_offline_totp_seed_edge.sql (read its header: `SET ROLE` is judged by the SESSION user, so every assertion lives in the edge_gateway session, reached by `\c`).
-- The structure and the PIN derivation vectors are 24_course_qr_marker_scan.sql; the rows this file COMMITS are read back, exported, deleted and cleaned up by
-- 24_course_qr_marker_scan_rows.sql, which pg_prove runs next (file order).
--
-- BUILD PLAN CLAUSES COVERED (docs/golf-trails/02-build-plan.md, P5 acceptance tests):
--   AT(19) course QR (O5): a rotating token with a qualifying co-signal -> a `valid` course_qr purchase and a `credited` credit; the same token again -> 409 (qr_used); a token more
--          than 120 s from the FIX time -> 422 qr_expired (judged against the fix, in both directions); no fix -> `pending` credit, credited only if a qualifying fix arrives within 7 days
--          (within 120 s of issue for a rotating token, the same local date for the printed QR); the printed QR with yesterday's or another facility's PIN -> 422; a user's sixth wrong PIN at
--          one facility in a day -> 429 until the next local day; 30 wrong PINs at one facility in a day rotate that PIN and alert the operator; an `unattestable` fix -> `held_review`.
--          (The forged printed-QR signature -> 422 + fraud_signal, the fix counted once as a foreground_checkin and the purchase never scoring as play are Edge-code properties:
--          supabase/tests/unit/marker-scan-handler.test.ts and supabase/tests/integration/marker-scan.deno.test.ts. `staff@X cannot mint a token or read the PIN for Y` is S2b's;
--          what S2a owes is section 9: no edge role reaches the PIN, the key table or the tokens, and no player-lane function returns a PIN.)
--   AT(3)  a `marker_purchase` scan without a co-signal yields a `pending` credit, never `credited` (section 3, and the invariant query in section 11).
--   AT(4)  a marker purchase alone never creates or raises a play (section 11: not one app.play row, not one evidence row, is written by the scan).
--   AT(13) offline marker purchase: a pending `staff_scan` row (what S3 will insert; here a stand-in) plus the player's prefetched-challenge co-signal inside the +-10 minute window of the
--          code's step becomes valid / credited on the player's reconnect (section 8); the same without the co-signal stays pending; another account's row, a fix outside the window and a
--          fix after the 7-day deadline join nothing. (A replayed code STEP is 0045's offline_code_step primary key, proven in 23_offline_totp_seed_edge.sql; its 409 mapping is S3's.)
--
-- ⛔ WATCH (the silent class edge_actor introduces): under RLS an UPDATE or DELETE with no matching policy affects ZERO rows and raises nothing, so every "it was written / it was
-- consumed" claim is proven by READING the row back: inside the transaction as the actor where the actor may see it, and in phase 2 as service_role.
-- All ids start ee240000-; PA..PH are players; the staff principals are helpers.sql's. Re-runnable on the same cluster (24_..._rows.sql cleans up).

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset

-- ============================================================================
-- PHASE 0: seed (harness role -> service_role; committed)
-- ============================================================================
SET ROLE service_role;
BEGIN;
INSERT INTO auth.users (id) VALUES
  ('ee240000-0000-0000-0000-0000000000a0'), ('ee240000-0000-0000-0000-0000000000b0'), ('ee240000-0000-0000-0000-0000000000c0'), ('ee240000-0000-0000-0000-0000000000d0'),
  ('ee240000-0000-0000-0000-0000000000e0'), ('ee240000-0000-0000-0000-0000000000f0'), ('ee240000-0000-0000-0000-000000000010'), ('ee240000-0000-0000-0000-000000000020'),
  ('ee240000-0000-0000-0000-000000000030'), ('ee240000-0000-0000-0000-000000000040')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.profile (user_id, handle) VALUES
  ('ee240000-0000-0000-0000-0000000000a0', 'edge24_pa'), ('ee240000-0000-0000-0000-0000000000b0', 'edge24_pb'), ('ee240000-0000-0000-0000-0000000000c0', 'edge24_pc'), ('ee240000-0000-0000-0000-0000000000d0', 'edge24_pd'),
  ('ee240000-0000-0000-0000-0000000000e0', 'edge24_pe'), ('ee240000-0000-0000-0000-0000000000f0', 'edge24_pf'), ('ee240000-0000-0000-0000-000000000010', 'edge24_pg'), ('ee240000-0000-0000-0000-000000000020', 'edge24_ph'),
  ('ee240000-0000-0000-0000-000000000030', 'edge24_pi'), ('ee240000-0000-0000-0000-000000000040', 'edge24_pj');

-- The catalog and the programme. Two trails on fac_s24a (a facility can sit on more than one trail's programme); fac_s24b takes ONLY the rotating token; fac_s24e ONLY the printed QR;
-- fac_s24c has an `invited` (not accepted) row; fac_s24d's trail is `off`; fac_s24f's printed QR is revoked; fac_s24g is in New Zealand (its local date is far from the UTC date); fac_s24h
-- is the facility the committed 30-failure alarm rotates; fac_s24p is a programme_marker trail (the course QR is the any_purchase path).
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES
  ('trl_s24a', 'trail', 'verified', 1), ('trl_s24b', 'trail', 'verified', 1), ('trl_s24c', 'trail', 'verified', 1), ('trl_s24p', 'trail', 'verified', 1),
  ('fac_s24a', 'facility', 'verified', 1), ('fac_s24b', 'facility', 'verified', 1), ('fac_s24c', 'facility', 'verified', 1), ('fac_s24d', 'facility', 'verified', 1), ('fac_s24e', 'facility', 'verified', 1),
  ('fac_s24f', 'facility', 'verified', 1), ('fac_s24g', 'facility', 'verified', 1), ('fac_s24h', 'facility', 'verified', 1), ('fac_s24p', 'facility', 'verified', 1)
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES
  ('trl_s24a', 'trail-s24a', 'Trail S24A', 1), ('trl_s24b', 'trail-s24b', 'Trail S24B', 1), ('trl_s24c', 'trail-s24c', 'Trail S24C', 1), ('trl_s24p', 'trail-s24p', 'Trail S24P', 1)
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version) VALUES
  ('fac_s24a', 'facility-s24a', 'Facility S24A', 'US-TN', 'America/Chicago', 1), ('fac_s24b', 'facility-s24b', 'Facility S24B', 'US-TN', 'America/Chicago', 1),
  ('fac_s24c', 'facility-s24c', 'Facility S24C', 'US-TN', 'America/Chicago', 1), ('fac_s24d', 'facility-s24d', 'Facility S24D', 'US-TN', 'America/Chicago', 1),
  ('fac_s24e', 'facility-s24e', 'Facility S24E', 'US-TN', 'America/Chicago', 1), ('fac_s24f', 'facility-s24f', 'Facility S24F', 'US-TN', 'America/Chicago', 1),
  ('fac_s24g', 'facility-s24g', 'Facility S24G', 'NZ', 'Pacific/Auckland', 1), ('fac_s24h', 'facility-s24h', 'Facility S24H', 'US-TN', 'America/Chicago', 1),
  ('fac_s24p', 'facility-s24p', 'Facility S24P', 'US-TN', 'America/Chicago', 1)
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.trail_programme (trail_id, status, marker_source) VALUES
  ('trl_s24a', 'live', 'any_purchase'), ('trl_s24b', 'pilot', 'any_purchase'), ('trl_s24c', 'off', 'any_purchase'), ('trl_s24p', 'live', 'programme_marker')
ON CONFLICT (trail_id) DO NOTHING;
INSERT INTO app.facility_programme (trail_id, facility_id, participation, qr_mode) VALUES
  ('trl_s24a', 'fac_s24a', 'accepted', 'both'), ('trl_s24b', 'fac_s24a', 'accepted', 'both'),
  ('trl_s24a', 'fac_s24b', 'accepted', 'rotating'),
  ('trl_s24a', 'fac_s24c', 'invited', 'both'),
  ('trl_s24c', 'fac_s24d', 'accepted', 'both'),
  ('trl_s24a', 'fac_s24e', 'accepted', 'static_pin'),
  ('trl_s24a', 'fac_s24f', 'accepted', 'both'),
  ('trl_s24a', 'fac_s24g', 'accepted', 'static_pin'),
  ('trl_s24a', 'fac_s24h', 'accepted', 'static_pin'),
  ('trl_s24p', 'fac_s24p', 'accepted', 'both')
ON CONFLICT (trail_id, facility_id) DO NOTHING;
-- the printed QRs: fac_s24a / e / g / h carry the current kid pq1; fac_s24f's was revoked
INSERT INTO app.facility_qr (facility_id, qr_kid, sig, revoked_at) VALUES
  ('fac_s24a', 'pq1', 'test-signature-a', NULL), ('fac_s24e', 'pq1', 'test-signature-e', NULL), ('fac_s24g', 'pq1', 'test-signature-g', NULL),
  ('fac_s24h', 'pq1', 'test-signature-h', NULL), ('fac_s24f', 'pq0', 'test-signature-f', now())
ON CONFLICT (facility_id) DO NOTHING;
-- the rotating tokens (a staff member's "Marker sold" taps; S2b writes these in production). Issued NOW, so a scan inside this file is inside their 120 s.
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
SELECT encode(sha256(convert_to('s24-tok-' || n, 'UTF8')), 'hex'), CASE WHEN n IN (20, 21) THEN 'fac_s24b' ELSE 'fac_s24a' END, '00000000-0000-0000-0000-1000000000a1', 'rk1', now(), now() + interval '120 seconds'
FROM generate_series(1, 21) n ON CONFLICT (nonce_hash) DO NOTHING;
-- a token issued THREE DAYS ago (an offline player scanned it then and uploads now: the 120 s rule is judged against the FIX, not the upload)
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
VALUES (encode(sha256(convert_to('s24-tok-22', 'UTF8')), 'hex'), 'fac_s24a', '00000000-0000-0000-0000-1000000000a1', 'rk1', now() - interval '3 days', now() - interval '3 days' + interval '120 seconds')
ON CONFLICT (nonce_hash) DO NOTHING;
-- PA's device and a queued evidence row, so edge_system can bind a system delegate (the cells: a delegate-bound transaction may use none of the wrappers)
INSERT INTO app.device (id, user_id, platform) VALUES ('ee240000-0000-0000-0000-00000000a001', 'ee240000-0000-0000-0000-0000000000a0', 'android') ON CONFLICT (id) DO NOTHING;
INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) VALUES
  ('ee240000-0000-0000-0000-0000000a0e24', 'ee240000-0000-0000-0000-0000000000a0', 'ee240000-0000-0000-0000-00000000a001', 'foreground_checkin', 'edge24-pa-queued', 'h-24a', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb)
ON CONFLICT (id) DO NOTHING;
-- the AT(13) stand-in: what the S3 staff lane inserts for an offline-code marker purchase (method staff_scan, offline, pending), with the +-10 min window of the code's step
-- (step time = the start of the 10-minute step the code was valid for) and the 7-day deadline; a pending credit linked to it. PB owns it; PA has none.
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, ref_id, offline, cosignal, local_date, status) VALUES
  ('ee240000-0000-0000-0000-00000000e301', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24b', 'trl_s24a', 'staff_scan', 'offline:ee240000-0000-0000-0000-00000000b001:1:' || floor(extract(epoch FROM now()) / 600)::bigint, true,
   jsonb_build_object('awaiting', jsonb_build_object(
     'from', to_char((to_timestamp(floor(extract(epoch FROM now()) / 600) * 600) - interval '10 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
     'to', to_char((to_timestamp(floor(extract(epoch FROM now()) / 600) * 600) + interval '20 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
     'until', to_char((now() + interval '7 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))),
   (now() AT TIME ZONE 'America/Chicago')::date, 'pending'),
  -- a second stand-in whose 7-day deadline has PASSED, and a third whose window is a day away
  ('ee240000-0000-0000-0000-00000000e302', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24b', 'trl_s24a', 'staff_scan', 'offline:ee240000-0000-0000-0000-00000000c001:1:1', true,
   jsonb_build_object('awaiting', jsonb_build_object('from', to_char((now() - interval '1 hour') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'to', to_char((now() + interval '1 hour') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
     'until', to_char((now() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))),
   (now() AT TIME ZONE 'America/Chicago')::date, 'pending');
-- ... and a fourth (PH) whose window ended two hours ago, so a fix NOW is AFTER the window (a fix cannot be dated in the future, so the end of a live window cannot be probed)
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, ref_id, offline, cosignal, local_date, status) VALUES
  ('ee240000-0000-0000-0000-00000000e303', 'ee240000-0000-0000-0000-000000000020', 'fac_s24b', 'trl_s24a', 'staff_scan', 'offline:ee240000-0000-0000-0000-00000000d001:1:2', true,
   jsonb_build_object('awaiting', jsonb_build_object('from', to_char((now() - interval '3 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'to', to_char((now() - interval '2 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
     'until', to_char((now() + interval '6 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))),
   (now() AT TIME ZONE 'America/Chicago')::date, 'pending');
INSERT INTO app.marker_credit (id, user_id, trail_id, facility_id, purchase_evidence_id, status) VALUES
  ('ee240000-0000-0000-0000-00000000ec01', 'ee240000-0000-0000-0000-0000000000b0', 'trl_s24a', 'fac_s24b', 'ee240000-0000-0000-0000-00000000e301', 'pending');
-- The review follow-ups' fixtures (M1, M2, L1, L2, L5). PI and PJ are extra players (the stand-in rows below must not interfere with PA..PH's cells).
--   fac_s24r  a printed-QR facility that ROTATED twice: epoch 1 took effect t0 - 3 h, epoch 2 at t0 - 1 h (the log rows are seeded below, as the owner)
--   fac_s24m  a facility whose two programme rows sit at DIFFERENT epochs (0 and 3): the current epoch is the HIGHEST (max, not min); its failure counter is seeded at 29 for epoch 3
--   crs_s24a1 a catalog course at fac_s24a (a co-signal's evidence row is facility-level: it must carry no course)
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('fac_s24r', 'facility', 'verified', 1), ('fac_s24m', 'facility', 'verified', 1), ('crs_s24a1', 'course', 'verified', 1) ON CONFLICT (id) DO NOTHING;
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version) VALUES
  ('fac_s24r', 'facility-s24r', 'Facility S24R', 'US-TN', 'America/Chicago', 1), ('fac_s24m', 'facility-s24m', 'Facility S24M', 'US-TN', 'America/Chicago', 1) ON CONFLICT (id) DO NOTHING;
INSERT INTO app.catalog_course (id, facility_id, name, verification_status, catalog_version) VALUES ('crs_s24a1', 'fac_s24a', 'Course S24A1', 'play-verified', 1) ON CONFLICT (id) DO NOTHING;
INSERT INTO app.facility_programme (trail_id, facility_id, participation, qr_mode, pin_epoch) VALUES
  ('trl_s24a', 'fac_s24r', 'accepted', 'static_pin', 2), ('trl_s24a', 'fac_s24m', 'accepted', 'static_pin', 0), ('trl_s24b', 'fac_s24m', 'accepted', 'static_pin', 3)
ON CONFLICT (trail_id, facility_id) DO NOTHING;
INSERT INTO app.facility_qr (facility_id, qr_kid, sig) VALUES ('fac_s24r', 'pq1', 'test-signature-r'), ('fac_s24m', 'pq1', 'test-signature-m') ON CONFLICT (facility_id) DO NOTHING;
-- more rotating tokens (30..49), issued at t0 like the first batch: the boundary, the evidence and the L1 cells each use their own
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
SELECT encode(sha256(convert_to('s24-tok-' || n, 'UTF8')), 'hex'), 'fac_s24a', '00000000-0000-0000-0000-1000000000a1', 'rk1', now(), now() + interval '120 seconds' FROM generate_series(30, 49) n ON CONFLICT (nonce_hash) DO NOTHING;
-- stand-ins (L2). PI: TWO pending scans (refs ref-s24-a, created 2 h ago, and ref-s24-b, 1 h ago), two trails each, every window holding t0: ONE fix completes the EARLIEST scan only.
-- PJ: a pending purchase (e405) beside a purchase that already holds the shop's credited credit (e406 / ec03): completing e405 must VOID its redundant pending credit (ec02).
WITH w AS (SELECT jsonb_build_object('awaiting', jsonb_build_object('from', to_char((now() - interval '1 day') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
                    'to', to_char((now() + interval '1 day') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'until', to_char((now() + interval '7 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))) AS j)
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, ref_id, offline, cosignal, local_date, status, created_at)
SELECT v.id::uuid, v.u::uuid, 'fac_s24a', v.trail, 'course_qr', 'rotating', v.ref, false, w.j, (now() AT TIME ZONE 'America/Chicago')::date, 'pending', now() - v.age::interval
FROM w, (VALUES
  ('ee240000-0000-0000-0000-00000000e401', 'ee240000-0000-0000-0000-000000000030', 'trl_s24a', 'ref-s24-a', '2 hours'), ('ee240000-0000-0000-0000-00000000e402', 'ee240000-0000-0000-0000-000000000030', 'trl_s24b', 'ref-s24-a', '2 hours'),
  ('ee240000-0000-0000-0000-00000000e403', 'ee240000-0000-0000-0000-000000000030', 'trl_s24a', 'ref-s24-b', '1 hour'),  ('ee240000-0000-0000-0000-00000000e404', 'ee240000-0000-0000-0000-000000000030', 'trl_s24b', 'ref-s24-b', '1 hour'),
  ('ee240000-0000-0000-0000-00000000e405', 'ee240000-0000-0000-0000-000000000040', 'trl_s24a', 'ref-s24-m14', '1 hour')) v(id, u, trail, ref, age);
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, ref_id, offline, cosignal, local_date, status, created_at) VALUES
  ('ee240000-0000-0000-0000-00000000e406', 'ee240000-0000-0000-0000-000000000040', 'fac_s24a', 'trl_s24a', 'course_qr', 'rotating', 'ref-s24-m14-old', false,
   jsonb_build_object('fixId', 'fixO0', 'grade', 'attested'), (now() AT TIME ZONE 'America/Chicago')::date, 'valid', now() - interval '3 hours');
INSERT INTO app.marker_credit (id, user_id, trail_id, facility_id, purchase_evidence_id, status) VALUES
  ('ee240000-0000-0000-0000-00000000ec03', 'ee240000-0000-0000-0000-000000000040', 'trl_s24a', 'fac_s24a', 'ee240000-0000-0000-0000-00000000e406', 'credited'),
  ('ee240000-0000-0000-0000-00000000ec02', 'ee240000-0000-0000-0000-000000000040', 'trl_s24a', 'fac_s24a', 'ee240000-0000-0000-0000-00000000e405', 'pending');
-- The co-signals' EVIDENCE ROWS (what the Edge writes before it calls the scan: the database reads each one back, private.marker_cosignal_check). One accepted, facility-level foreground_checkin row
-- per fix id used below, owned by the player that uses it, at its facility, with the claimed grade and the fix's captured time (the same `now()` the tokens above were issued at: t0).
SELECT now() AS t0 \gset
-- The DERIVED FIX a qualifying co-signal's evidence row carries (what the Edge's gradeFix writes into summary.fix): from the app, not simulated, foreground, a live challenge, 10 m accuracy, a
-- polygon geometry of a play-verified facility, inside the buffer, with an attestation token of the row's grade. The database checks every one of these (marker_cosignal_check).
CREATE FUNCTION pg_temp.qfix(p_fix text, p_fac text, p_grade text, p_at timestamptz, p_ld date) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $f$
  SELECT jsonb_build_object('fixId', p_fix, 'facilityId', p_fac, 'fromApp', true, 'simulated', false, 'foreground', true, 'challenge', 'live', 'token', jsonb_build_object('present', true, 'grade', p_grade),
    'verificationTier', 'play-verified', 'geometryKind', 'polygon', 'insideBuffer', true, 'accuracyMeters', 10, 'capturedAt', (extract(epoch FROM p_at) * 1000)::bigint, 'localDate', p_ld::text)
$f$;
INSERT INTO app.evidence (id, user_id, source, source_ref, facility_id, summary, attestation_grade, local_date, input_hash, status)
SELECT v.ev, v.u::uuid, 'foreground_checkin', 'fix:' || v.fix, v.fac, jsonb_build_object('localDate', ((v.at AT TIME ZONE f.tz)::date)::text, 'fix', pg_temp.qfix(v.fix, v.fac, v.grade, v.at, (v.at AT TIME ZONE f.tz)::date)),
       v.grade::app.attestation_grade, (v.at AT TIME ZONE f.tz)::date, 'h-' || v.fix, 'accepted'
FROM (VALUES
  ('fixA1', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, 'ee240000-0000-0000-0000-00000000f001'),
  ('fixA2', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixA2')::uuid),
  ('fixA3', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() + interval '135 seconds')::timestamptz, md5('ev-fixA3')::uuid),
  ('fixA4', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() - interval '135 seconds')::timestamptz, md5('ev-fixA4')::uuid),
  ('fixA5', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() + interval '100 seconds')::timestamptz, md5('ev-fixA5')::uuid),
  ('fixA20', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixA20')::uuid),
  ('fixA21', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() - interval '3 days' + interval '20 seconds')::timestamptz, md5('ev-fixA21')::uuid),
  ('fixA22', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() - interval '3 days' + interval '20 seconds')::timestamptz, md5('ev-fixA22')::uuid),
  ('fixA6', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixA6')::uuid),
  ('fixA7', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixA7')::uuid),
  ('fixA8', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixA8')::uuid),
  ('fixA9', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24c', 'attested', (now())::timestamptz, md5('ev-fixA9')::uuid),
  ('fixA10', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24d', 'attested', (now())::timestamptz, md5('ev-fixA10')::uuid),
  ('fixA11', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24p', 'attested', (now())::timestamptz, md5('ev-fixA11')::uuid),
  ('fixA12', 'ee240000-0000-0000-0000-0000000000a0', 'fac_nope', 'attested', (now())::timestamptz, md5('ev-fixA12')::uuid),
  ('fixA13', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixA13')::uuid),
  ('fixA14', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixA14')::uuid),
  ('fixB1', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixB1')::uuid),
  ('fixB2', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() + interval '60 seconds')::timestamptz, md5('ev-fixB2')::uuid),
  ('fixB3', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() + interval '60 seconds')::timestamptz, md5('ev-fixB3')::uuid),
  ('fixC1', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() + interval '130 seconds')::timestamptz, md5('ev-fixC1')::uuid),
  ('fixC2', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() - interval '130 seconds')::timestamptz, md5('ev-fixC2')::uuid),
  ('fixC3', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixC3')::uuid),
  ('fixC4', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixC4')::uuid),
  ('fixD1', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixD1')::uuid),
  ('fixE1', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixE1')::uuid),
  ('fixE2', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixE2')::uuid),
  ('fixF1', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24a', 'unattestable', (now())::timestamptz, md5('ev-fixF1')::uuid),
  ('fixF4', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24a', 'unattestable', (now())::timestamptz, md5('ev-fixF4')::uuid),
  ('fixG1', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixG1')::uuid),
  ('fixG2', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixG2')::uuid),
  ('fixG3', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixG3')::uuid),
  ('fixG4', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixG4')::uuid),
  ('fixG5', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixG5')::uuid),
  ('fixG6', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24f', 'attested', (now())::timestamptz, md5('ev-fixG6')::uuid),
  ('fixG7', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixG7')::uuid),
  ('fixG8', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24g', 'attested', (now())::timestamptz, md5('ev-fixG8')::uuid),
  ('fixG9', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24g', 'attested', (now())::timestamptz, md5('ev-fixG9')::uuid),
  ('fixG10', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24h', 'attested', (now() - interval '1 day')::timestamptz, md5('ev-fixG10')::uuid),
  ('fixH1', 'ee240000-0000-0000-0000-0000000000d0', 'fac_s24e', 'attested', (now() - interval '1 day')::timestamptz, md5('ev-fixH1')::uuid),
  ('fixH2', 'ee240000-0000-0000-0000-0000000000d0', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixH2')::uuid),
  ('fixI1', 'ee240000-0000-0000-0000-000000000010', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixI1')::uuid),
  ('fixI2', 'ee240000-0000-0000-0000-000000000010', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixI2')::uuid),
  ('fixJ0', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24a', 'attested', (now() - interval '6 minutes')::timestamptz, md5('ev-fixJ0')::uuid),
  ('fixJ1', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24b', 'attested', (now() - interval '6 minutes')::timestamptz, md5('ev-fixJ1')::uuid),
  ('fixJ3', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24b', 'attested', (now() - interval '25 minutes')::timestamptz, md5('ev-fixJ3')::uuid),
  ('fixJ4', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24b', 'unattestable', (now())::timestamptz, md5('ev-fixJ4')::uuid),
  ('fixJ2', 'ee240000-0000-0000-0000-000000000020', 'fac_s24b', 'attested', (now())::timestamptz, md5('ev-fixJ2')::uuid),
  ('fixJ5', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', (now() - interval '6 minutes')::timestamptz, md5('ev-fixJ5')::uuid),
  ('fixJ6', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', (now() - interval '6 minutes')::timestamptz, md5('ev-fixJ6')::uuid),
  ('fixL2', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now() - interval '8 days')::timestamptz, md5('ev-fixL2')::uuid),
  ('fixM1', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixM1')::uuid),
  ('fixN1', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', (now())::timestamptz, 'ee240000-0000-0000-0000-00000000f101'),
  ('fixN3', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24a', 'attested', (now())::timestamptz, 'ee240000-0000-0000-0000-00000000f103'),
  ('fixN5', 'ee240000-0000-0000-0000-0000000000e0', 'fac_s24a', 'unattestable', (now())::timestamptz, 'ee240000-0000-0000-0000-00000000f105'),
  ('fixN6', 'ee240000-0000-0000-0000-0000000000f0', 'fac_s24e', 'attested', (now())::timestamptz, 'ee240000-0000-0000-0000-00000000f106'),
  ('fixN7', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24b', 'attested', (now() - interval '6 minutes')::timestamptz, 'ee240000-0000-0000-0000-00000000f107'),
  ('fixN8a', 'ee240000-0000-0000-0000-000000000010', 'fac_s24b', 'attested', (now())::timestamptz, 'ee240000-0000-0000-0000-00000000f108'),
  ('fixN8b', 'ee240000-0000-0000-0000-000000000010', 'fac_s24b', 'attested', (now())::timestamptz, 'ee240000-0000-0000-0000-00000000f109'),
  ('fixN2', 'ee240000-0000-0000-0000-000000000020', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixN2')::uuid),
  ('fixN4', 'ee240000-0000-0000-0000-000000000020', 'fac_s24a', 'attested', (now())::timestamptz, md5('ev-fixN4')::uuid),
  ('fixN9', 'ee240000-0000-0000-0000-000000000020', 'fac_s24e', 'attested', (now())::timestamptz, md5('ev-fixN9')::uuid)
) v(fix, u, fac, grade, at, ev) JOIN app.catalog_facility f ON f.id = v.fac;
-- extra evidence rows: pg_temp.seed_ev(fix, user, facility, grade, captured at[, source, source_ref, status, local date, course]); the deviations the database must REFUSE are the M2 negatives (fixZ_*)
CREATE FUNCTION pg_temp.seed_ev(p_fix text, p_u uuid, p_fac text, p_grade text, p_cap timestamptz, p_src text DEFAULT 'foreground_checkin', p_ref text DEFAULT NULL, p_st text DEFAULT 'accepted', p_ld date DEFAULT NULL, p_crs text DEFAULT NULL, p_patch jsonb DEFAULT '{}'::jsonb)
RETURNS void LANGUAGE plpgsql AS $f$
DECLARE v_ld date;
BEGIN
  v_ld := COALESCE(p_ld, (p_cap AT TIME ZONE (SELECT f.tz FROM app.catalog_facility f WHERE f.id = p_fac))::date);
  INSERT INTO app.evidence (id, user_id, source, source_ref, facility_id, course_id, summary, attestation_grade, local_date, input_hash, status)
  VALUES (md5('ev-' || p_fix)::uuid, p_u, p_src::app.evidence_source, COALESCE(p_ref, 'fix:' || p_fix), p_fac, p_crs,
          jsonb_build_object('localDate', v_ld::text, 'fix', pg_temp.qfix(p_fix, p_fac, p_grade, p_cap, v_ld) || p_patch), p_grade::app.attestation_grade, v_ld, 'h-' || p_fix, p_st::app.evidence_status);
END
$f$;
-- M1: fac_s24r, one scan per player, each fix captured while a DIFFERENT epoch was live (t0 - 4 h: epoch 0; t0 - 2 h: epoch 1; t0: epoch 2; yesterday: epoch 0)
SELECT pg_temp.seed_ev('fixR_a', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24r', 'attested', :'t0'::timestamptz - interval '4 hours');
SELECT pg_temp.seed_ev('fixR_b', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24r', 'attested', :'t0'::timestamptz - interval '2 hours');
SELECT pg_temp.seed_ev('fixR_c', 'ee240000-0000-0000-0000-0000000000c0', 'fac_s24r', 'attested', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixR_d', 'ee240000-0000-0000-0000-0000000000d0', 'fac_s24r', 'attested', :'t0'::timestamptz - interval '1 day');
SELECT pg_temp.seed_ev('fixR_e', 'ee240000-0000-0000-0000-0000000000e0', 'fac_s24r', 'attested', :'t0'::timestamptz - interval '2 hours');
SELECT pg_temp.seed_ev('fixR_f', 'ee240000-0000-0000-0000-0000000000f0', 'fac_s24r', 'attested', :'t0'::timestamptz - interval '1 day');
SELECT pg_temp.seed_ev('fixR_g', 'ee240000-0000-0000-0000-000000000010', 'fac_s24r', 'attested', :'t0'::timestamptz - interval '2 hours');
-- M2: PA's evidence with ONE thing wrong each (all at fac_s24a, captured at t0, attested, unless it is the point)
SELECT pg_temp.seed_ev('fixZ_ok', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixZ_ok2', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixZ_tol', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz + interval '700 milliseconds');
SELECT pg_temp.seed_ev('fixZ_src', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, 'self_report');
SELECT pg_temp.seed_ev('fixZ_ref', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, 'foreground_checkin', 'fix:some-other-fix');
SELECT pg_temp.seed_ev('fixZ_fac', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24b', 'attested', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixZ_status', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, 'foreground_checkin', NULL, 'flagged');
SELECT pg_temp.seed_ev('fixZ_grade', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'unattestable', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixZ_failed', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'failed', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixZ_date', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, 'foreground_checkin', NULL, 'accepted', ((:'t0'::timestamptz AT TIME ZONE 'America/Chicago')::date) - 1);
SELECT pg_temp.seed_ev('fixZ_time', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz + interval '5 seconds');
SELECT pg_temp.seed_ev('fixZ_course', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, 'foreground_checkin', NULL, 'accepted', NULL, 'crs_s24a1');
SELECT pg_temp.seed_ev('fixZ_owner', 'ee240000-0000-0000-0000-0000000000b0', 'fac_s24a', 'attested', :'t0'::timestamptz);
-- LOW 1 (the read-back checks QUALIFICATION, not only identity): PA's evidence rows whose DERIVED FIX is wrong in ONE way each (every other field qualifying), and the controls that qualify
SELECT pg_temp.seed_ev('fixQ_radius', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"geometryKind":"radius"}');
SELECT pg_temp.seed_ev('fixQ_unver', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"verificationTier":"unverified"}');
SELECT pg_temp.seed_ev('fixQ_listed', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"verificationTier":"listed-verified"}');
SELECT pg_temp.seed_ev('fixQ_outside', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"insideBuffer":false}');
SELECT pg_temp.seed_ev('fixQ_sim', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"simulated":true}');
SELECT pg_temp.seed_ev('fixQ_bg', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"foreground":false}');
SELECT pg_temp.seed_ev('fixQ_app', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"fromApp":false}');
SELECT pg_temp.seed_ev('fixQ_none', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"challenge":"none"}');
SELECT pg_temp.seed_ev('fixQ_acc80', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"accuracyMeters":80}');
SELECT pg_temp.seed_ev('fixQ_acc505', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"accuracyMeters":50.5}');
SELECT pg_temp.seed_ev('fixQ_accneg', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"accuracyMeters":-1}');
SELECT pg_temp.seed_ev('fixQ_accstr', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"accuracyMeters":"10"}');
SELECT pg_temp.seed_ev('fixQ_notok', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"token":{"present":false,"hardwareSupportsAttestation":true}}');
SELECT pg_temp.seed_ev('fixQ_notokg', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"token":{"present":false,"grade":"attested"}}');
SELECT pg_temp.seed_ev('fixQ_tokgrade', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"token":{"present":true,"grade":"unattestable"}}');
SELECT pg_temp.seed_ev('fixQ_facs', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"facilityId":"fac_s24b"}');
SELECT pg_temp.seed_ev('fixQ_fixid', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"fixId":"another-fix"}');
SELECT pg_temp.seed_ev('fixQ_endpoint', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"geometryKind":"radius","verificationTier":"unverified","insideBuffer":false}');
SELECT pg_temp.seed_ev('fixQ_nofix', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz);
UPDATE app.evidence SET summary = summary - 'fix' WHERE source_ref = 'fix:fixQ_nofix';
SELECT pg_temp.seed_ev('fixQ_pref', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz, p_patch => '{"challenge":"prefetched"}');
SELECT pg_temp.seed_ev('fixQ_acc50', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'unattestable', :'t0'::timestamptz, p_patch => '{"accuracyMeters":50}');
-- LOW 2 (the +5 minute future bound WITH a co-signal): tokens issued, and co-signal rows captured, 4.5 and 6 minutes from now: everything else valid, so only the bound decides
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
VALUES (encode(sha256(convert_to('s24-tok-50', 'UTF8')), 'hex'), 'fac_s24a', '00000000-0000-0000-0000-1000000000a1', 'rk1', :'t0'::timestamptz + interval '270 seconds', :'t0'::timestamptz + interval '6 minutes'),
       (encode(sha256(convert_to('s24-tok-51', 'UTF8')), 'hex'), 'fac_s24a', '00000000-0000-0000-0000-1000000000a1', 'rk1', :'t0'::timestamptz + interval '6 minutes', :'t0'::timestamptz + interval '8 minutes');
SELECT pg_temp.seed_ev('fixFut4', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz + interval '270 seconds');
SELECT pg_temp.seed_ev('fixFut6', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz + interval '6 minutes');
-- L2 m12: the 120 s boundary, judged against the FIX time (each at fac_s24a, one token each)
SELECT pg_temp.seed_ev('fixT_p120', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz + interval '120 seconds');
SELECT pg_temp.seed_ev('fixT_p121', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz + interval '121 seconds');
SELECT pg_temp.seed_ev('fixT_m120', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz - interval '120 seconds');
SELECT pg_temp.seed_ev('fixT_m121', 'ee240000-0000-0000-0000-0000000000a0', 'fac_s24a', 'attested', :'t0'::timestamptz - interval '121 seconds');
-- L2 m01 / m02 (PI) and m14 (PJ)
SELECT pg_temp.seed_ev('fixQ1', 'ee240000-0000-0000-0000-000000000030', 'fac_s24a', 'attested', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixQ2', 'ee240000-0000-0000-0000-000000000030', 'fac_s24a', 'attested', :'t0'::timestamptz);
SELECT pg_temp.seed_ev('fixO1', 'ee240000-0000-0000-0000-000000000040', 'fac_s24a', 'attested', :'t0'::timestamptz);
COMMIT;
RESET ROLE;

-- The Vault pepper (a run-time constant, never a secret literal) and the PUBLIC verification keys (temporary CURRENT_USER policy, dropped again: the table has no policy for the harness role).
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40));
CREATE POLICY current_user_seed_course_qr_key_24e ON app.course_qr_key FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url, revoked_at) VALUES
  ('rotating_token', 'rk1', repeat('A', 43), NULL), ('rotating_token', 'rk0', repeat('B', 43), now()), ('printed_qr', 'pq1', repeat('C', 43), NULL);
DROP POLICY current_user_seed_course_qr_key_24e ON app.course_qr_key;
-- the rotation log of fac_s24r (a POLICY only: the table's owner has the privilege; the restricted harness role must keep its own)
CREATE POLICY current_user_seed_epoch_log_24e ON app.course_pin_epoch_log FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO app.course_pin_epoch_log (facility_id, pin_epoch, previous_epoch, effective_from) VALUES
  ('fac_s24r', 1, 0, :'t0'::timestamptz - interval '3 hours'), ('fac_s24r', 2, 1, :'t0'::timestamptz - interval '1 hour');
DROP POLICY current_user_seed_epoch_log_24e ON app.course_pin_epoch_log;

-- Today's PINs (the facility's LOCAL date), computed by the one function that may: as private_definer, never from the edge session. A wrong PIN is "correct + 1".
BEGIN;
SET LOCAL ROLE private_definer;
SELECT private.course_pin_derive('fac_s24a', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_a \gset
SELECT private.course_pin_derive('fac_s24a', (now() AT TIME ZONE 'America/Chicago')::date - 1, 0) AS pin_a_yday \gset
SELECT private.course_pin_derive('fac_s24a', (now() AT TIME ZONE 'America/Chicago')::date, 1) AS pin_a_e1 \gset
SELECT private.course_pin_derive('fac_s24e', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_e \gset
SELECT private.course_pin_derive('fac_s24e', (now() AT TIME ZONE 'America/Chicago')::date - 1, 0) AS pin_e_yday \gset
SELECT private.course_pin_derive('fac_s24g', (now() AT TIME ZONE 'Pacific/Auckland')::date, 0) AS pin_g \gset
SELECT private.course_pin_derive('fac_s24g', (now() AT TIME ZONE 'Pacific/Auckland')::date - 1, 0) AS pin_g_yday \gset
SELECT private.course_pin_derive('fac_s24g', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_g_utcday \gset
SELECT private.course_pin_derive('fac_s24h', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_h \gset
-- fac_s24r: the PIN displayed at each instant, under the epoch live then, for the facility-local date OF THAT INSTANT
SELECT private.course_pin_derive('fac_s24r', ((:'t0'::timestamptz - interval '4 hours') AT TIME ZONE 'America/Chicago')::date, 0) AS pin_r_a \gset
SELECT private.course_pin_derive('fac_s24r', ((:'t0'::timestamptz - interval '2 hours') AT TIME ZONE 'America/Chicago')::date, 1) AS pin_r_b \gset
SELECT private.course_pin_derive('fac_s24r', (:'t0'::timestamptz AT TIME ZONE 'America/Chicago')::date, 2) AS pin_r_c \gset
SELECT private.course_pin_derive('fac_s24r', ((:'t0'::timestamptz - interval '1 day') AT TIME ZONE 'America/Chicago')::date, 0) AS pin_r_d \gset
SELECT private.course_pin_derive('fac_s24m', (now() AT TIME ZONE 'America/Chicago')::date, 3) AS pin_m \gset
SELECT private.course_pin_derive('fac_s24h', (now() AT TIME ZONE 'America/Chicago')::date - 1, 0) AS pin_h_yday \gset
SELECT private.course_pin_derive('fac_s24h', (now() AT TIME ZONE 'America/Chicago')::date, 1) AS pin_h_e1 \gset
SELECT private.course_pin_derive('fac_s24f', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_f \gset
SELECT private.course_pin_derive('fac_s24p', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_p \gset
ROLLBACK;
-- a PIN that is wrong for every facility above today (built from a correct one: +1, +2 mod 10000, so it cannot be a typo of the same value)
SELECT lpad(((:'pin_m'::int + 1) % 10000)::text, 4, '0') AS wrong_m \gset
SELECT lpad(((:'pin_a'::int + 1) % 10000)::text, 4, '0') AS wrong1, lpad(((:'pin_a'::int + 2) % 10000)::text, 4, '0') AS wrong2 \gset
-- another facility's PIN: fac_s24e's PIN at fac_s24a (a collision of the two 4-digit values would make the cell vacuous, so assert it cannot)
SELECT (:'pin_e' <> :'pin_a' AND :'pin_a_yday' <> :'pin_a' AND :'pin_a_e1' <> :'pin_a' AND :'pin_e' <> :'wrong1' AND :'pin_e' <> :'wrong2' AND :'pin_a_yday' <> :'wrong1' AND :'pin_a_yday' <> :'wrong2') AS vectors_distinct \gset
SELECT :'vectors_distinct'::boolean AS ok_distinct \gset
-- the facility-wide counter, seeded at 29 failures in TWO UTC windows (20 yesterday + 9 today: a facility-local date can straddle two UTC days, so the count is the SUM over the key)
SET ROLE service_role;
DELETE FROM private.rate_limit_bucket WHERE bucket_key LIKE 'marker-scan:pin-fail:%';
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES
  ('marker-scan:pin-fail:f:fac_s24a:' || to_char((now() AT TIME ZONE 'America/Chicago')::date, 'YYYY-MM-DD') || ':0', date_trunc('day', now() - interval '1 day'), 20),
  ('marker-scan:pin-fail:f:fac_s24a:' || to_char((now() AT TIME ZONE 'America/Chicago')::date, 'YYYY-MM-DD') || ':0', date_trunc('day', now()), 9);
-- PG's counter for fac_s24e on YESTERDAY's facility-local date: nine failures. The cap is per facility-local date of the ATTEMPT, so yesterday's failures must not lock PG today.
SET ROLE service_role;
-- fac_s24m: 29 failures at epoch 3 (the facility's HIGHEST epoch: its rows sit at 0 and 3)
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES
  ('marker-scan:pin-fail:f:fac_s24m:' || to_char((now() AT TIME ZONE 'America/Chicago')::date, 'YYYY-MM-DD') || ':3', date_trunc('day', now()), 29);
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES
  ('marker-scan:pin-fail:u:ee240000-0000-0000-0000-000000000010:fac_s24e:' || to_char((now() AT TIME ZONE 'America/Chicago')::date - 1, 'YYYY-MM-DD'), date_trunc('day', now() - interval '1 day'), 9);
RESET ROLE;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(348);
CREATE FUNCTION pg_temp.h(s text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT encode(sha256(convert_to(s, 'UTF8')), 'hex') $f$;
-- t0: the instant phase 0 ran (the tokens were issued, and each co-signal's evidence row was captured, AT t0); a co-signal's p_at is expressed relative to it (the database ties p_at to the evidence row's
-- captured time, so a cell cannot use its own now()). ev(fix): the evidence row's id for a fix id (phase 0 inserted it with the same formula).
SELECT format('CREATE FUNCTION pg_temp.t0() RETURNS timestamptz LANGUAGE sql IMMUTABLE AS %L', 'SELECT ' || quote_literal(:'t0') || '::timestamptz') \gexec
CREATE FUNCTION pg_temp.ev(p_fix text) RETURNS uuid LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('ev-' || p_fix)::uuid $f$;
-- the PINs as a pg_temp lookup, for the bodies of throws_ok (psql does not interpolate :'vars' inside dollar quotes)
CREATE TABLE pg_temp.pins (k text PRIMARY KEY, v text NOT NULL);
INSERT INTO pg_temp.pins VALUES ('pin_e', :'pin_e'), ('pin_g', :'pin_g'), ('pin_h', :'pin_h'), ('pin_h_yday', :'pin_h_yday'), ('wrong1', :'wrong1'), ('pin_r_d', :'pin_r_d');
GRANT SELECT ON pg_temp.pins TO PUBLIC;
CREATE FUNCTION pg_temp.p(p_k text) RETURNS text LANGUAGE sql STABLE AS $f$ SELECT v FROM pg_temp.pins WHERE k = p_k $f$;
-- n PIN attempts in a row, one call each (a LATERAL function scan with no outer reference is evaluated ONCE by the planner and rescanned from a tuplestore: it would not repeat the call)
CREATE FUNCTION pg_temp.pin_tries(p_fac text, p_pin text, p_n integer) RETURNS text[] LANGUAGE plpgsql AS $f$
DECLARE r text; o text[] := '{}'; i integer;
BEGIN
  FOR i IN 1..p_n LOOP
    SELECT a.o_result INTO r FROM private.course_pin_attempt_for_actor(p_fac, p_pin, now()) a;
    o := o || r;
  END LOOP;
  RETURN o;
END
$f$;

-- ============================================================================
-- 1. Nothing bound: every wrapper refuses
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.course_qr_public_key_for_actor('rk1', 'rotating_token')$$, '42501', 'course_qr_public_key_for_actor: no actor is bound in this transaction', 'unbound: the key read refuses');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24a', '0000', now())$$, '42501', 'course_pin_attempt_for_actor: no actor is bound in this transaction', 'unbound: the PIN gate refuses');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), 'rk1', NULL, now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: no actor is bound in this transaction', 'unbound: the scan refuses');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fix1', pg_temp.ev('fix1'))$$, '42501', 'marker_cosignal_attach_for_actor: no actor is bound in this transaction', 'unbound: the co-signal intake refuses');
ROLLBACK;

-- ============================================================================
-- 2. The public keys: a kid, a purpose, revoked flagged, nothing else
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_public_key_b64url FROM private.course_qr_public_key_for_actor('rk1', 'rotating_token')), repeat('A', 43), 'the rotating-token key of rk1');
SELECT is((SELECT o_revoked FROM private.course_qr_public_key_for_actor('rk1', 'rotating_token')), false, 'rk1 is not revoked');
SELECT is((SELECT o_revoked FROM private.course_qr_public_key_for_actor('rk0', 'rotating_token')), true, 'rk0 is REVOKED (returned flagged: the caller refuses it)');
SELECT is((SELECT count(*)::int FROM private.course_qr_public_key_for_actor('rk1', 'printed_qr')), 0, 'purpose is part of the key: rk1 is a rotating-token kid, not a printed-QR one');
SELECT is((SELECT o_public_key_b64url FROM private.course_qr_public_key_for_actor('pq1', 'printed_qr')), repeat('C', 43), 'the printed-QR key of pq1');
SELECT is((SELECT count(*)::int FROM private.course_qr_public_key_for_actor('nope', 'printed_qr')), 0, 'an unknown kid: zero rows (the Edge answers invalid_qr)');
SELECT throws_ok($$SELECT * FROM private.course_qr_public_key_for_actor('rk1', 'hand_over')$$, '22023', NULL, 'an unknown purpose is refused');
SELECT throws_ok($$SELECT * FROM private.course_qr_public_key_for_actor(NULL, 'printed_qr')$$, '22023', NULL, 'a NULL kid is refused');
ROLLBACK;

-- ============================================================================
-- 3. AT(19) / AT(3): the rotating token (Q1)
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
-- 3a. a qualifying (attested) co-signal: purchase valid, credit credited, on BOTH trails of the facility (one row per eligible trail)
-- (edge_actor holds no SELECT on the purchase / credit tables, so what is written is proven by what the definer RETURNS here, and by the COMMITTED scenarios of section 11 read back as
-- service_role in 24_course_qr_marker_scan_rows.sql.)
SELECT is((SELECT array_agg(o_result || '/' || o_trail_id || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id)
           FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA1', 'ee240000-0000-0000-0000-00000000f001')),
  ARRAY['accepted/trl_s24a/valid/credited', 'accepted/trl_s24b/valid/credited'], 'AT(19): a rotating token with an attested co-signal -> a `valid` purchase and a `credited` credit, one per eligible trail');
-- 3b. the token is consumed: it cannot be scanned again
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA2', pg_temp.ev('fixA2'))), 'qr_used', 'AT(19): the SAME token scanned again -> qr_used (409)');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), 'rk1', NULL, now(), NULL, NULL, NULL) WHERE o_result = 'qr_used'), 1, 'and without a fix too (one refusal row, no purchase)');
-- 3c. a token scanned by someone else is used for everyone
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA (second transaction)');
-- 3d. the 120 s rule is judged against the FIX's time, in both directions
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-2'), 'rk1', NULL, pg_temp.t0() + interval '135 seconds', 'attested', 'fixA3', pg_temp.ev('fixA3')) LIMIT 1), 'qr_expired',
  'AT(19): a token issued more than 120 s BEFORE the fix -> 422 qr_expired');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-2'), 'rk1', NULL, pg_temp.t0() - interval '135 seconds', 'attested', 'fixA4', pg_temp.ev('fixA4')) LIMIT 1), 'qr_expired',
  'AT(19): ... and a fix taken more than 120 s BEFORE the token was issued is equally outside the rule (the rule is distance, not direction)');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-2'), 'rk1', NULL, pg_temp.t0() + interval '100 seconds', 'attested', 'fixA5', pg_temp.ev('fixA5'))), ARRAY['accepted', 'accepted'],
  'control: a fix 100 s from the issue is inside the rule (and the earlier refusals did NOT consume the token)');
ROLLBACK;
-- the UPLOAD time does not matter (plan §7.6: "the token's 120 s window is judged against the fix's time, not the upload time"): token 22 was issued THREE DAYS ago
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA (an offline upload, three days late)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-22'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA20', pg_temp.ev('fixA20')) LIMIT 1), 'qr_expired', 'a fix taken NOW against a token issued three days ago: qr_expired');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-22'), 'rk1', NULL, pg_temp.t0() - interval '3 days' + interval '20 seconds', 'attested', 'fixA21', pg_temp.ev('fixA21'))),
  ARRAY['accepted/valid/credited', 'accepted/valid/credited'], 'AT(19)/§7.6: the same token with a fix taken 20 s after its issue three days ago (uploaded now) is accepted: valid / credited, judged against the FIX');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-22'), 'rk1', NULL, pg_temp.t0() - interval '3 days' + interval '20 seconds', 'attested', 'fixA22', pg_temp.ev('fixA22'))), 'qr_used', 'and it is still single use');
ROLLBACK;
-- 3e. wrong facility / unknown nonce / no programme
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-20'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA6', pg_temp.ev('fixA6')) LIMIT 1), 'qr_wrong_facility',
  'a token minted for ANOTHER facility (fac_s24b) is refused at fac_s24a (AT(19): "another facility" -> 422)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('no-such-token'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA7', pg_temp.ev('fixA7'))), 'qr_unknown', 'an unknown nonce: qr_unknown (the Edge answers invalid_qr)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-20'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA8', pg_temp.ev('fixA8'))), 'accepted', 'control: the same token at its own facility is accepted');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24c', 'rotating', pg_temp.h('s24-tok-3'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA9', pg_temp.ev('fixA9'))), 'no_programme', 'a facility whose programme row is only `invited`: no_programme');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24d', 'rotating', pg_temp.h('s24-tok-3'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA10', pg_temp.ev('fixA10'))), 'no_programme', 'a facility whose trail programme is `off`: no_programme');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24p', 'rotating', pg_temp.h('s24-tok-3'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA11', pg_temp.ev('fixA11'))), 'no_programme', 'a programme_marker trail takes no course-QR purchase (code cards are its path)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_nope', 'rotating', pg_temp.h('s24-tok-3'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA12', pg_temp.ev('fixA12'))), 'no_facility', 'a facility that does not exist: no_facility');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'rotating', pg_temp.h('s24-tok-3'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixA13', pg_temp.ev('fixA13'))), 'variant_disabled', 'a printed-QR-only facility does not take a rotating token: variant_disabled');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24b', 'static_pin', NULL, 'pq1', :'pin_a', pg_temp.t0(), 'attested', 'fixA14', pg_temp.ev('fixA14'))), 'variant_disabled', 'a rotating-only facility does not take the printed QR: variant_disabled');
ROLLBACK;
-- 3f. AT(19)/AT(3): no co-signal -> a PENDING credit, never credited; the token is consumed (the window a later fix must fall in is read back from the committed scan, section 11)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-4'), 'rk1', NULL, now(), NULL, NULL, NULL)),
  ARRAY['accepted/pending/pending', 'accepted/pending/pending'], 'AT(3)/AT(19): a scan with NO co-signal -> a `pending` purchase and a `pending` credit, never `credited`');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-4'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixB1', pg_temp.ev('fixB1')) LIMIT 1), 'qr_used', 'a no-fix scan consumed the token (single use)');
-- 3g. AT(19): the pending credit is credited only by a qualifying fix inside the window (the co-signal intake)
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0() + interval '60 seconds', 'attested', 'fixB2', pg_temp.ev('fixB2'))),
  ARRAY['attached/valid/credited', 'attached/valid/credited'], 'AT(19): a qualifying fix inside the 120 s window completes the scan: valid / credited (both trails)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0() + interval '60 seconds', 'attested', 'fixB3', pg_temp.ev('fixB3')) LIMIT 1), 'no_pending_purchase', 'a SECOND fix finds nothing to complete: one fix completes one scan, one scan takes one fix');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-5'), 'rk1', NULL, now(), NULL, NULL, NULL)), 2, 'a pending scan again (token 5)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0() + interval '130 seconds', 'attested', 'fixC1', pg_temp.ev('fixC1')) LIMIT 1), 'no_pending_purchase',
  'AT(19): a fix MORE than 120 s from the token''s issue does not complete it (the rotating window is judged against the issue time)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0() - interval '130 seconds', 'attested', 'fixC2', pg_temp.ev('fixC2')) LIMIT 1), 'no_pending_purchase', '... in either direction');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0(), 'attested', 'fixC3', pg_temp.ev('fixC3')) LIMIT 1), 'no_pending_purchase', 'a fix at ANOTHER facility completes nothing');
SELECT is((SELECT array_agg(o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixC4', pg_temp.ev('fixC4'))), ARRAY['valid/credited', 'valid/credited'], 'control: after those three refusals the pending scan is intact, and a qualifying fix at its own facility inside the window still completes it');
ROLLBACK;
-- 3h. AT(19): the 7-day deadline. A scan older than seven days no longer takes a fix (the row stays pending). The scan is made, then its deadline is moved into the past
-- in a SEPARATE committed fixture row (e302, seeded already past its deadline), so the intake is exercised against a real past deadline.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC (owner of the stand-in whose 7-day deadline has passed)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0(), 'attested', 'fixD1', pg_temp.ev('fixD1'))), 'no_pending_purchase', 'AT(19): a fix that arrives AFTER the 7-day deadline completes nothing (the window holds the fix, the deadline does not)');
ROLLBACK;
-- 3i. a repeat credit at a shop the player is already credited at: the purchase is recorded, no second credit exists
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-20'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixE1', pg_temp.ev('fixE1'))), 'credited', 'the first scan at fac_s24b credits');
SELECT is((SELECT o_purchase_status || '/' || o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-21'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixE2', pg_temp.ev('fixE2'))), 'valid/credited',
  'a SECOND purchase at the same shop (another token): the purchase is recorded valid, and the player is reported credited ...');
ROLLBACK;

-- ============================================================================
-- 4. AT(19): an `unattestable` co-signal -> held_review (never a silent refusal), a `failed` one is not a co-signal at all
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'bind PB');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-6'), 'rk1', NULL, pg_temp.t0(), 'unattestable', 'fixF1', pg_temp.ev('fixF1'))),
  ARRAY['accepted/held_review/held_review', 'accepted/held_review/held_review'], 'AT(19): an unattestable presence fix sends the purchase AND the credit to held_review');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-7'), 'rk1', NULL, now(), 'failed', 'fixF2', gen_random_uuid())$$, '22023', NULL,
  'a `failed` grade is not a co-signal: the definer refuses it as an argument (the Edge never passes one: a failed fix is not a co-signal, nothing is earned on it)');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-7'), 'rk1', NULL, now(), 'attested', NULL, gen_random_uuid())$$, '22023', NULL, 'a co-signal with no fix id is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-7'), 'rk1', NULL, now(), 'attested', 'fixF3', NULL)$$, '22023', NULL, 'a co-signal with no evidence id is refused');
-- an unattestable fix that completes a PENDING scan -> held_review too
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-8'), 'rk1', NULL, now(), NULL, NULL, NULL)), 2, 'a pending scan (token 8)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'unattestable', 'fixF4', pg_temp.ev('fixF4'))),
  ARRAY['attached/held_review/held_review', 'attached/held_review/held_review'], 'an unattestable fix that completes a pending scan routes it to held_review as well');
ROLLBACK;

-- ============================================================================
-- 5. AT(19): the printed QR (Q2) and today's PIN
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', pg_temp.t0())), 'ok', 'today''s PIN for the facility: ok');
SELECT is((SELECT o_retry_after_seconds FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', pg_temp.t0())), NULL, 'an ok carries no retry hint');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', pg_temp.t0(), 'attested', 'fixG1', pg_temp.ev('fixG1'))),
  ARRAY['accepted/valid/credited'], 'AT(19): the printed QR + today''s PIN + an attested fix: valid / credited');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('pin_e'), pg_temp.t0(), 'attested', 'fixG2', pg_temp.ev('fixG2'))$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'the accepted scan CONSUMED its proof: a second scan in the same transaction needs a second gate (one gate, one scan)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', pg_temp.t0())), 'ok', 'the gate again');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', pg_temp.t0(), 'attested', 'fixG2', pg_temp.ev('fixG2'))), 'duplicate', 'the same player scanning the same shop on the same local day again: duplicate (409)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC (second transaction)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e_yday', now())), 'wrong', 'AT(19): YESTERDAY''s PIN -> wrong (422)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_a', now())), 'wrong', 'AT(19): ANOTHER facility''s PIN -> wrong (422)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', pg_temp.t0())), 'ok', 'the right PIN for today: ok (and the PIN gate''s proof the scan below requires)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e_yday', pg_temp.t0(), 'attested', 'fixG3', pg_temp.ev('fixG3'))), 'pin_wrong', 'the scan itself re-checks the PIN: yesterday''s is refused there too (the gate is not only the counter)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_a', pg_temp.t0(), 'attested', 'fixG4', pg_temp.ev('fixG4'))), 'pin_wrong', 'and another facility''s PIN');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq9', :'pin_e', pg_temp.t0(), 'attested', 'fixG5', pg_temp.ev('fixG5'))), 'qr_revoked', 'a printed QR with a kid that is not the facility''s current one: qr_revoked (a reprint revokes the old kid)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24f', 'static_pin', NULL, 'pq0', :'pin_f', pg_temp.t0(), 'attested', 'fixG6', pg_temp.ev('fixG6'))), 'qr_revoked', 'a revoked printed QR is refused even with the right PIN');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24b', 'static_pin', NULL, 'pq1', :'pin_a', pg_temp.t0(), 'attested', 'fixG7', pg_temp.ev('fixG7'))), 'variant_disabled', 'a facility that takes only the rotating token');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24g', :'pin_g', pg_temp.t0())), 'ok', 'the New Zealand local-date PIN passes the gate (the proof)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24g', 'static_pin', NULL, 'pq1', :'pin_g_utcday', pg_temp.t0(), 'attested', 'fixG8', pg_temp.ev('fixG8'))), 'pin_wrong', 'the PIN''s day is the FACILITY''s local date, not the UTC date or another zone''s (fac_s24g is in New Zealand)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24g', 'static_pin', NULL, 'pq1', :'pin_g', pg_temp.t0(), 'attested', 'fixG9', pg_temp.ev('fixG9'))), 'accepted', 'control: the New Zealand local-date PIN is accepted there');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24h', :'pin_h', pg_temp.t0() - interval '1 day')), 'wrong', 'a fix dated YESTERDAY needs YESTERDAY''s PIN: today''s is a wrong PIN for it (the gate)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24h', :'pin_h_yday', pg_temp.t0() - interval '1 day')), 'ok', 'and yesterday''s PIN is right for it (the gate judges the date of the FIX, not today)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24h', 'static_pin', NULL, 'pq1', :'pin_h', pg_temp.t0() - interval '1 day', 'attested', 'fixG10', pg_temp.ev('fixG10'))), 'pin_wrong', 'the scan itself re-checks: today''s PIN is refused for a fix dated yesterday');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24h', 'static_pin', NULL, 'pq1', :'pin_h_yday', pg_temp.t0() - interval '1 day', 'attested', 'fixG10', pg_temp.ev('fixG10'))), 'accepted', 'and yesterday''s PIN is accepted (a printed-QR scan queued offline and uploaded the next day)');
ROLLBACK;
-- the printed QR with no co-signal: pending, window = the facility-local day
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0')$$, 'bind PD');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'the PIN gate for today (the proof)');
SELECT is((SELECT array_agg(o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), NULL, NULL, NULL)), ARRAY['pending/pending'], 'AT(3): the printed QR + the PIN with no fix: pending, pending');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24e', pg_temp.t0() - interval '1 day', 'attested', 'fixH1', pg_temp.ev('fixH1'))), 'no_pending_purchase', 'AT(19): a fix from the PREVIOUS local date does not complete a printed-QR scan');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24e', pg_temp.t0(), 'attested', 'fixH2', pg_temp.ev('fixH2'))), ARRAY['attached/valid/credited'],
  'AT(19): a qualifying fix on the SAME facility-local date does (hours after the scan: the printed QR has no 120 s)');
ROLLBACK;

-- ============================================================================
-- 6. AT(19): five wrong PINs per user per facility per facility-local date, then 429 until the next local day
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0')$$, 'bind PE');
SELECT is(pg_temp.pin_tries('fac_s24e', :'wrong1', 5), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong'],
  'AT(19): the first five wrong PINs are answered `wrong` (422)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'wrong2', now())), 'locked', 'AT(19): the SIXTH wrong PIN -> locked (429)');
SELECT is((SELECT o_retry_after_seconds BETWEEN 1 AND 90000 FROM private.course_pin_attempt_for_actor('fac_s24e', :'wrong2', now())), true, 'the 429 carries a retry hint of at least 1 s and at most a day and an hour (until the facility-local midnight)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'locked', 'AT(19): and the CORRECT PIN is refused too once locked (a correct sixth guess is what the cap exists to stop)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'wrong1', now())), 'wrong', 'the lock is per FACILITY: the same player may still try fac_s24a');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e_yday', now() - interval '1 day')), 'locked', 'the cap counts the attempts of the facility-local day they are MADE: naming an older fix date (with that day''s right PIN) buys no extra tries');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000010')$$, 'bind PG (nine failures on YESTERDAY''s counter)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'AT(19): "429 until the next local day": yesterday''s failures do not lock today (the counter is per facility-local date)');
SELECT is(pg_temp.pin_tries('fac_s24e', :'wrong1', 6), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong', 'locked'], 'and today''s own five failures are still allowed');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000f0')$$, 'bind PF (a different player)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'another PLAYER is not locked by PE''s failures (the cap is per user)');
SELECT is(pg_temp.pin_tries('fac_s24e', :'pin_e', 10), ARRAY['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok'],
  'a correct PIN consumes nothing: only FAILURES are counted (ten right ones in a row, still ok)');
SELECT is(pg_temp.pin_tries('fac_s24e', :'wrong1', 6), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong', 'locked'],
  'and after those, five failures are still allowed and the sixth is locked');
ROLLBACK;
-- the attempt function never returns the PIN, and refuses nonsense
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000f0')$$, 'bind PF');
SELECT is((SELECT count(*)::int FROM private.course_pin_attempt_for_actor('fac_nope', '1234', now())), 1, 'an unknown facility answers one row ...');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_nope', '1234', now())), 'no_facility', '... no_facility (counted nowhere)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24d', '1234', now())), 'no_programme', 'a facility with no active programme: no_programme (counted nowhere)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24b', '1234', now())), 'no_programme', 'a rotating-only facility takes no PIN: no_programme');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '12345', now())$$, '22023', NULL, 'a 5-digit PIN is refused');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', 'abcd', now())$$, '22023', NULL, 'a non-numeric PIN is refused');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', NULL, now())$$, '22023', NULL, 'a NULL PIN is refused');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '1234', NULL)$$, '22023', NULL, 'a NULL time is refused');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '1234', now() - interval '8 days')$$, '22023', NULL, 'a fix time older than 7 days is refused (no fresh counters for a date the scan would refuse anyway)');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '1234', now() + interval '10 minutes')$$, '22023', NULL, 'and one from the future');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'course_pin_attempt_for_actor' AND p.prorettype = 'record'::regtype AND pg_get_function_result(p.oid) ~* 'pin text'), 0, 'its result has no PIN column (ok | wrong | locked | no_facility | no_programme only)');
ROLLBACK;

-- ============================================================================
-- 7. AT(19): 30 wrong PINs at one facility in a day rotate the PIN and alert the operator
-- ============================================================================
-- fac_s24a's facility counter was seeded at 29 failures in two UTC windows (20 + 9). The next wrong PIN is the 30th.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000010')$$, 'bind PG');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'pin_a', now())), 'ok', 'before the alarm today''s epoch-0 PIN works');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'wrong1', now())), 'wrong', 'AT(19): the 30th wrong PIN at the facility is itself answered `wrong` ...');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'pin_a', now())), 'wrong', '... and the OLD PIN is now wrong: the PIN was rotated (the 29 + 1 = 30 counted the two windows as ONE local day)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'pin_a_e1', now())), 'ok', 'the NEW PIN (epoch 1) is the one that works');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'static_pin', NULL, 'pq1', :'pin_a', now(), NULL, NULL, NULL)), 'pin_wrong', 'a scan made NOW with the rotated-out PIN is refused by the scan too');
-- THE QUEUED SCAN (M1): a fix taken at t0, BEFORE the rotation, still verifies with the PIN displayed at t0 (epoch 0), and is not counted as a failure
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'pin_a', pg_temp.t0())), 'ok', 'M1: a fix captured BEFORE the rotation is judged under the epoch live then: the old PIN is ok for it (a queued scan uploaded after a rotation)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'pin_a_e1', pg_temp.t0())), 'wrong', 'M1: ... and the NEW PIN was not displayed at t0: wrong for that fix');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'static_pin', NULL, 'pq1', :'pin_a_e1', pg_temp.t0(), 'attested', 'fixI1', pg_temp.ev('fixI1'))), 'pin_wrong', 'M1: the scan judges the same way: the new PIN is wrong for a fix taken before the rotation');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24a', 'static_pin', NULL, 'pq1', :'pin_a', pg_temp.t0(), 'attested', 'fixI2', pg_temp.ev('fixI2'))), ARRAY['accepted', 'accepted'], 'M1: and accepts the old one for that fix (both trails): the rotation did not break the queued scan');
ROLLBACK;
-- the alarm itself and the epoch were written (committed state is read in phase 2): here, one more failure after the rotation does not rotate AGAIN, in a fresh transaction
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000020')$$, 'bind PH');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24a', :'wrong1', now())), 'wrong', 'the rolled-back transaction above left the epoch at 0: a wrong PIN here is the 30th again');
ROLLBACK;

-- ============================================================================
-- 8. AT(13): the offline marker purchase: the S3 stand-in row + the player's prefetched-challenge co-signal inside the +-10 min window
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'bind PB (the stand-in e301 belongs to PB)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0() - interval '6 minutes', 'attested', 'fixJ0', pg_temp.ev('fixJ0'))), 'no_pending_purchase', 'AT(13): without a co-signal at the row''s facility the offline-code scan stays pending (a fix at ANOTHER facility joins nothing)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0() - interval '6 minutes', 'attested', 'fixJ1', pg_temp.ev('fixJ1'))),
  ARRAY['attached/valid/credited'], 'AT(13): the co-signal 6 minutes later (inside +-10 min of the step) -> the row becomes valid and the credit credited on reconnect');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'bind PB');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0() - interval '25 minutes', 'attested', 'fixJ3', pg_temp.ev('fixJ3'))), 'no_pending_purchase', 'AT(13): a fix OUTSIDE the +-10 min window (before it) completes nothing');
SELECT is((SELECT array_agg(o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0(), 'unattestable', 'fixJ4', pg_temp.ev('fixJ4'))), ARRAY['held_review/held_review'], 'an unattestable prefetched-challenge fix routes the offline purchase to held_review');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000020')$$, 'bind PH (owner of the stand-in whose window ended two hours ago)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0(), 'attested', 'fixJ2', pg_temp.ev('fixJ2'))), 'no_pending_purchase', 'AT(13): a fix AFTER the +-10 min window completes nothing either');
ROLLBACK;
-- another account's pending row is invisible: the explicit filters, and the GUC windows planted as the attacker give no access
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA (not the stand-in''s owner)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0() - interval '6 minutes', 'attested', 'fixJ5', pg_temp.ev('fixJ5'))), 'no_pending_purchase', 'PA cannot complete PB''s pending purchase with PA''s own fix');
SELECT set_config('app.delete_my_data.target_user_id', 'ee240000-0000-0000-0000-0000000000b0', true);
SELECT set_config('app.offline_code.target_device_id', 'ee240000-0000-0000-0000-00000000b001', true);
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0() - interval '6 minutes', 'attested', 'fixJ6', pg_temp.ev('fixJ6'))), 'no_pending_purchase', 'HARD RULE: with the delete_my_data and offline_code windows PLANTED as PB, PA still cannot reach PB''s row (the policies are keyed on the binding)');
ROLLBACK;

-- ============================================================================
-- 9. No edge role can reach the PIN, the keys, the alarm table or the tokens; a staff member gets nothing a player does not
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'bind staff-x (a staff member at fac_x)');
SELECT throws_ok($$SELECT private.course_pin_derive('fac_x', current_date, 0)$$, '42501', NULL, 'AT(19) staff@X: the PIN derivation is not reachable even to a staff member (S2b adds a scope-checked wrapper)');
SELECT throws_ok($$SELECT * FROM vault.decrypted_secrets$$, '42501', NULL, 'direct: edge_actor cannot read the Vault (the pepper)');
SELECT throws_ok($$SELECT count(*) FROM app.course_qr_key$$, '42501', NULL, 'direct: edge_actor cannot read the key table');
SELECT throws_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', 'evil', repeat('Z', 43))$$, '42501', NULL, 'direct: nor register a key (a forged QR would verify)');
SELECT throws_ok($$SELECT count(*) FROM app.course_pin_alarm$$, '42501', NULL, 'direct: edge_actor cannot read the alarm table');
SELECT throws_ok($$INSERT INTO app.course_pin_alarm (facility_id, local_date, pin_epoch_before, pin_epoch_after, failures) VALUES ('fac_s24a', current_date, 0, 1, 30)$$, '42501', NULL, 'direct: nor raise (or forge) an alarm');
SELECT throws_ok($$SELECT count(*) FROM app.course_qr_token$$, '42501', NULL, 'AT(19) staff@X: edge_actor cannot read the rotating tokens');
SELECT throws_ok($$INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, expires_at) VALUES (repeat('a', 64), 'fac_x', '00000000-0000-0000-0000-1000000000a1', 'rk1', now() + interval '120 seconds')$$, '42501', NULL,
  'AT(19) staff@X: staff-x cannot MINT a token through edge_actor (the minting is S2b''s staff lane, behind a passkey session)');
SELECT throws_ok($$UPDATE app.course_qr_token SET used_at = now(), used_by_user = '00000000-0000-0000-0000-1000000000a1'$$, '42501', NULL, 'direct: nor mark one used');
SELECT throws_ok($$SELECT count(*) FROM app.facility_qr$$, '42501', NULL, 'direct: edge_actor cannot read the printed-QR registry');
SELECT throws_ok($$UPDATE app.facility_programme SET pin_epoch = 99$$, '42501', NULL, 'direct: nor set a PIN epoch');
SELECT throws_ok($$SELECT count(*) FROM app.facility_programme$$, '42501', NULL, 'direct: nor read the programme');
SELECT throws_ok($$INSERT INTO app.purchase_evidence (user_id, facility_id, trail_id, method, qr_variant, local_date, status) VALUES ('00000000-0000-0000-0000-1000000000a1', 'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')$$, '42501', NULL, 'direct: nor write a purchase row');
SELECT throws_ok($$UPDATE app.purchase_evidence SET status = 'valid'$$, '42501', NULL, 'direct: nor complete one');
SELECT throws_ok($$INSERT INTO app.marker_credit (user_id, trail_id, facility_id, status) VALUES ('00000000-0000-0000-0000-1000000000a1', 'trl_t', 'fac_x', 'credited')$$, '42501', NULL, 'direct: nor credit themselves');
SELECT throws_ok($$UPDATE app.marker_credit SET status = 'credited'$$, '42501', NULL, 'direct: nor upgrade a credit');
-- a staff member at fac_x is just a player to the scan: bound as staff-x, the player-lane definers work for them as a buyer, and reveal no PIN
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'wrong1', now())), 'wrong', 'staff-x scanning as a BUYER: a wrong PIN is just `wrong` (the answer carries no PIN and no hint of it)');
ROLLBACK;
-- a system delegate may use none of them
BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), 'rk1', NULL, now(), NULL, NULL, NULL)$$, '42501', NULL, 'edge_system holds no EXECUTE on the scan');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '1234', now())$$, '42501', NULL, 'nor on the PIN gate');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixK1', pg_temp.ev('fixK1'))$$, '42501', NULL, 'nor on the co-signal intake');
SELECT throws_ok($$SELECT * FROM private.course_qr_public_key_for_actor('rk1', 'rotating_token')$$, '42501', NULL, 'nor on the key read');
ROLLBACK;
-- argument shape: every nonsense input is refused (22023), not silently accepted
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor(NULL, 'rotating', NULL, NULL, NULL, now(), NULL, NULL, NULL)$$, '22023', NULL, 'a NULL facility is refused (22023)');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'carrier_pigeon', pg_temp.h('x'), NULL, NULL, now(), NULL, NULL, NULL)$$, '22023', NULL, 'an unknown variant is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', 'not-a-hash', NULL, NULL, now(), NULL, NULL, NULL)$$, '22023', NULL, 'a nonce hash that is not 64 hex characters is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', NULL, NULL, NULL, now(), NULL, NULL, NULL)$$, '22023', NULL, 'a rotating scan with no nonce hash is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, NULL, '1234', now(), NULL, NULL, NULL)$$, '22023', NULL, 'a printed-QR scan with no kid is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', NULL, now(), NULL, NULL, NULL)$$, '22023', NULL, 'a printed-QR scan with no PIN is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), 'rk1', NULL, NULL, NULL, NULL, NULL)$$, '22023', NULL, 'a NULL time is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), 'rk1', NULL, now() - interval '8 days', NULL, NULL, NULL)$$, '22023', NULL, 'a fix older than 7 days is refused (the deadline is the database''s, not the client''s)');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), 'rk1', NULL, now() + interval '10 minutes', NULL, NULL, NULL)$$, '22023', NULL, 'and one from the future');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), NULL, 'fixL1', gen_random_uuid())$$, '22023', NULL, 'the co-signal intake needs a qualifying grade');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0() - interval '8 days', 'attested', 'fixL2', pg_temp.ev('fixL2'))$$, '22023', NULL, 'and a time within 7 days');
ROLLBACK;
-- a system delegate binding is refused by every wrapper
BEGIN;
SET LOCAL ROLE edge_system;
SELECT private.bind_delegate_for_queued_evidence('ee240000-0000-0000-0000-0000000a0e24');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), 'rk1', NULL, now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a system delegate may not record a marker purchase', 'delegate: a system-delegate binding cannot record a purchase');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '1234', now())$$, '42501', 'course_pin_attempt_for_actor: a system delegate may not attempt a course PIN', 'delegate: nor attempt a PIN');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixM1', pg_temp.ev('fixM1'))$$, '42501', 'marker_cosignal_attach_for_actor: a system delegate may not attach a co-signal', 'delegate: nor attach a co-signal');
SELECT throws_ok($$SELECT * FROM private.course_qr_public_key_for_actor('rk1', 'rotating_token')$$, '42501', 'course_qr_public_key_for_actor: a system delegate may not read a course QR key', 'delegate: nor read a key');
ROLLBACK;

-- ============================================================================
-- 10. A binding does not outlive its transaction
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'stale: bind PA in transaction 1 ...');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), 'rk1', NULL, now(), NULL, NULL, NULL)$$, '42501',
  'marker_scan_for_actor: no actor is bound in this transaction', '... transaction 2 inherits NO actor (the binding is per transaction)');
ROLLBACK;

-- ============================================================================
-- 10b. THE GATE'S FOLLOW-UPS (M1, M2, L1, L2, L5, NITs)
-- ============================================================================
-- M1. A ROTATION MUST NOT BREAK A QUEUED OFFLINE SCAN. fac_s24r rotated twice (epoch 1 at t0 - 3 h, epoch 2 at t0 - 1 h). The PIN of a fix is the one DISPLAYED when the fix was taken: the date of the fix
-- under the epoch live at its instant. A right PIN is `ok` and counts nothing; a PIN of another epoch, tried for that instant, is a wrong guess (counted).
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_a', pg_temp.t0() - interval '4 hours')), 'ok', 'M1: a fix at t0 - 4 h (epoch 0, before both rotations): the PIN displayed then is ok, and the epoch live then is the one it is judged under');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', :'pin_r_a', pg_temp.t0() - interval '4 hours', 'attested', 'fixR_a', pg_temp.ev('fixR_a'))), ARRAY['accepted/valid/credited'], 'M1: and the scan is accepted (valid / credited)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'bind PB');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_b', pg_temp.t0() - interval '2 hours')), 'ok', 'M1: a fix at t0 - 2 h (epoch 1: between the two rotations of one day): the PIN displayed then is ok, and the epoch live then is the one it is judged under');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', :'pin_r_b', pg_temp.t0() - interval '2 hours', 'attested', 'fixR_b', pg_temp.ev('fixR_b'))), ARRAY['accepted/valid/credited'], 'M1: and the scan is accepted (valid / credited)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_c', pg_temp.t0())), 'ok', 'M1: a fix at t0 (epoch 2, the current one): the PIN displayed then is ok, and the epoch live then is the one it is judged under');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', :'pin_r_c', pg_temp.t0(), 'attested', 'fixR_c', pg_temp.ev('fixR_c'))), ARRAY['accepted/valid/credited'], 'M1: and the scan is accepted (valid / credited)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0')$$, 'bind PD');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_d', pg_temp.t0() - interval '1 day')), 'ok', 'M1: a fix dated YESTERDAY (epoch 0), uploaded after TWO rotations today: the PIN displayed then is ok, and the epoch live then is the one it is judged under');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', :'pin_r_d', pg_temp.t0() - interval '1 day', 'attested', 'fixR_d', pg_temp.ev('fixR_d'))), ARRAY['accepted/valid/credited'], 'M1: and the scan is accepted (valid / credited)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0')$$, 'bind PE');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_a', pg_temp.t0() - interval '2 hours')), 'wrong', 'M1: the epoch-0 PIN was NOT on display at t0 - 2 h (epoch 1 was): a wrong guess for that instant');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_c', pg_temp.t0() - interval '2 hours')), 'wrong', 'M1: nor was the epoch-2 PIN (the future one)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_b', now())), 'wrong', 'M1: a PIN of a rotated-out epoch tried NOW is a wrong guess (counted: making it free would be an uncounted brute-force oracle)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_b', pg_temp.t0() - interval '2 hours')), 'ok', 'M1: control: the epoch-1 PIN at its own instant');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0')$$, 'bind PE (a second purchase after a rotation)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_b', pg_temp.t0() - interval '2 hours')), 'ok', 'NIT: the first purchase, a fix captured under epoch 1');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', :'pin_r_b', pg_temp.t0() - interval '2 hours', 'attested', 'fixR_e', pg_temp.ev('fixR_e'))), ARRAY['accepted'], 'NIT: accepted');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_c', now())), 'ok', 'NIT: later the same local day, under the NEW epoch');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', :'pin_r_c', now(), NULL, NULL, NULL)), 'duplicate', 'NIT: the dedupe key has no epoch: a rotation does NOT allow a second same-day purchase at the shop');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000f0')$$, 'bind PF');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_d', pg_temp.t0() - interval '1 day')), 'ok', 'L1: the gate for a fix dated yesterday');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', pg_temp.p('pin_r_d'), pg_temp.t0() - interval '1 day', NULL, NULL, NULL)$$, '22023', 'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)', 'L1: WITHOUT a co-signal a scan dated yesterday is refused: a client cannot pick the PIN date (or the scan instant) with an unqualified time');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0')$$, 'bind PE (fac_s24m: two programme rows at epochs 0 and 3)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24m', :'pin_m', now())), 'ok', 'M1/m10: with no rotation ever logged the live epoch is the HIGHEST over the facility''s rows (3, not 0): its PIN is ok');
ROLLBACK;
-- M2. THE DATABASE TIES A CO-SIGNAL TO ITS EVIDENCE ROW. PA scans token 30 at t0 with an evidence row that is wrong in ONE way each; every refusal is a returned status and consumes nothing,
-- so the same token serves them all, then the right row is accepted and a second use of it is refused.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_src', pg_temp.ev('fixZ_src')) LIMIT 1), 'cosignal_invalid', 'M2: the row is not a foreground_checkin (self_report): refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_ref', pg_temp.ev('fixZ_ref')) LIMIT 1), 'cosignal_invalid', 'M2: the row is for another fix id (source_ref fix:some-other-fix): refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_fac', pg_temp.ev('fixZ_fac')) LIMIT 1), 'cosignal_invalid', 'M2: the row is at another facility: refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_status', pg_temp.ev('fixZ_status')) LIMIT 1), 'cosignal_invalid', 'M2: the row is not accepted (flagged): refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_grade', pg_temp.ev('fixZ_grade')) LIMIT 1), 'cosignal_invalid', 'M2: the row says unattestable, the call says attested: refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_failed', pg_temp.ev('fixZ_failed')) LIMIT 1), 'cosignal_invalid', 'M2: the row says failed: refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_date', pg_temp.ev('fixZ_date')) LIMIT 1), 'cosignal_invalid', 'M2: the row is dated yesterday: refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_time', pg_temp.ev('fixZ_time')) LIMIT 1), 'cosignal_invalid', 'M2: the row was captured 5 s from the scan instant: refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_course', pg_temp.ev('fixZ_course')) LIMIT 1), 'cosignal_invalid', 'M2: the row is course-anchored (a co-signal row is facility-level): refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_owner', pg_temp.ev('fixZ_owner')) LIMIT 1), 'cosignal_invalid', 'M2: the row belongs to ANOTHER account (PB): refused');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_nowhere', gen_random_uuid()) LIMIT 1), 'cosignal_invalid', 'M2: an evidence id that names no row: refused (an invented fix id and uuid no longer pass)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'unattestable', 'fixZ_ok', pg_temp.ev('fixZ_ok')) LIMIT 1), 'cosignal_invalid', 'M2: the row says attested, the call says unattestable: refused (the grade is the row''s, not the caller''s)');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_ok', pg_temp.ev('fixZ_ok')) WHERE o_result = 'qr_used'), 0, 'M2: none of those refusals consumed the token');
ROLLBACK;
-- LOW 1. THE READ-BACK CHECKS QUALIFICATION. Each row below is accepted, facility-level, PA's own, for this fix and facility, with the right grade, date and time: wrong in exactly ONE field of its derived fix.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_radius', pg_temp.ev('fixQ_radius')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a RADIUS-fallback geometry (no polygon match): refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_unver', pg_temp.ev('fixQ_unver')) LIMIT 1), 'cosignal_invalid', 'LOW 1: an `unverified` facility tier: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_listed', pg_temp.ev('fixQ_listed')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a `listed-verified` (not play-verified) facility tier: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_outside', pg_temp.ev('fixQ_outside')) LIMIT 1), 'cosignal_invalid', 'LOW 1: outside the polygon plus buffer (insideBuffer false): refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_sim', pg_temp.ev('fixQ_sim')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a simulated fix: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_bg', pg_temp.ev('fixQ_bg')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a background fix: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_app', pg_temp.ev('fixQ_app')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a fix not from the app: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_none', pg_temp.ev('fixQ_none')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a fix bound to NO challenge: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_acc80', pg_temp.ev('fixQ_acc80')) LIMIT 1), 'cosignal_invalid', 'LOW 1: 80 m accuracy (over the 50 m ceiling): refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_acc505', pg_temp.ev('fixQ_acc505')) LIMIT 1), 'cosignal_invalid', 'LOW 1: 50.5 m accuracy (just over the ceiling): refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_accneg', pg_temp.ev('fixQ_accneg')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a negative accuracy: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_accstr', pg_temp.ev('fixQ_accstr')) LIMIT 1), 'cosignal_invalid', 'LOW 1: an accuracy that is a string, not a number: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_notok', pg_temp.ev('fixQ_notok')) LIMIT 1), 'cosignal_invalid', 'LOW 1: no attestation token on the fix: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_notokg', pg_temp.ev('fixQ_notokg')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a token marked NOT present that still carries the claimed grade: refused (present is checked on its own)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_tokgrade', pg_temp.ev('fixQ_tokgrade')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a derived fix whose token grade (unattestable) is not the rows and the calls (attested): refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_facs', pg_temp.ev('fixQ_facs')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a derived fix naming another facility than the row: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_fixid', pg_temp.ev('fixQ_fixid')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a derived fix with another fix id: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_endpoint', pg_temp.ev('fixQ_endpoint')) LIMIT 1), 'cosignal_invalid', 'LOW 1: the evidence-endpoint shape (radius + unverified + outside the buffer): a real, accepted check-in that is NO co-signal: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_nofix', pg_temp.ev('fixQ_nofix')) LIMIT 1), 'cosignal_invalid', 'LOW 1: a summary with no derived fix at all: refused (the row''s own derived fix must QUALIFY, not merely exist)');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-40'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixQ_pref', pg_temp.ev('fixQ_pref')) WHERE o_result = 'accepted'), 2, 'LOW 1 control: a PREFETCHED challenge qualifies (accepted on both trails)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-41'), 'rk1', NULL, pg_temp.t0(), 'unattestable', 'fixQ_acc50', pg_temp.ev('fixQ_acc50'))), ARRAY['accepted/held_review', 'accepted/held_review'], 'LOW 1 control: accuracy of exactly 50 m qualifies (the ceiling is inclusive), an unattestable grade stays held_review');
ROLLBACK;
-- LOW 2. The scan's +5 minute future bound WITH a co-signal: 4.5 minutes ahead (a co-signal row, a token issued then) is accepted, 6 minutes ahead is refused outright, whatever else is valid.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-50'), 'rk1', NULL, pg_temp.t0() + interval '270 seconds', 'attested', 'fixFut4', pg_temp.ev('fixFut4'))), ARRAY['accepted', 'accepted'], 'LOW 2 (m08) control: a scan 4.5 minutes ahead of now, backed by a co-signal, is inside the bound');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-51'), 'rk1', NULL, pg_temp.t0() + interval '6 minutes', 'attested', 'fixFut6', pg_temp.ev('fixFut6'))$$, '22023',
  'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)', 'LOW 2 (m08): 6 minutes ahead is refused even with a complete, valid co-signal and token: the future bound holds WITH a co-signal');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-51'), 'rk1', NULL, pg_temp.t0() + interval '2 days', 'attested', 'fixFut6', pg_temp.ev('fixFut6'))$$, '22023',
  'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)', 'LOW 2: and 2 days ahead');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_ok', pg_temp.ev('fixZ_ok'))), ARRAY['accepted/valid/credited', 'accepted/valid/credited'], 'M2: control: the right evidence row is accepted');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-31'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_ok', pg_temp.ev('fixZ_ok')) LIMIT 1), 'cosignal_used', 'M2: the SAME evidence row cannot back a second scan (a second token, the same co-signal): cosignal_used');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-31'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_tol', pg_temp.ev('fixZ_tol'))), ARRAY['accepted', 'accepted'], 'M2: a row captured 0.7 s from p_at is inside the 1 s tolerance (accepted)');
ROLLBACK;
-- HARD RULE: the check reads the BOUND actor's evidence by an explicit user filter. With 0016's GUC-keyed delete window PLANTED as PB, PA still cannot present PB's evidence row (fixZ_owner: PB's, at fac_s24a, attested, t0).
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT set_config('app.delete_my_data.target_user_id', 'ee240000-0000-0000-0000-0000000000b0', true);
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-30'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixZ_owner', pg_temp.ev('fixZ_owner')) LIMIT 1), 'cosignal_invalid', 'HARD RULE: with the delete_my_data window PLANTED as PB, PA still cannot back a scan with PB''s evidence row (the explicit user filter is the boundary: that window is GUC-keyed)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_owner', pg_temp.ev('fixZ_owner')) LIMIT 1), 'cosignal_invalid', 'HARD RULE: and the same for the intake');
ROLLBACK;
-- M2 on the intake: a pending scan first, then the same ways to be wrong
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-32'), 'rk1', NULL, now(), NULL, NULL, NULL)), 2, 'a pending scan (token 32)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_src', pg_temp.ev('fixZ_src')) LIMIT 1), 'cosignal_invalid', 'M2 intake: fixZ_src: refused');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_fac', pg_temp.ev('fixZ_fac')) LIMIT 1), 'cosignal_invalid', 'M2 intake: fixZ_fac: refused');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_grade', pg_temp.ev('fixZ_grade')) LIMIT 1), 'cosignal_invalid', 'M2 intake: fixZ_grade: refused');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_time', pg_temp.ev('fixZ_time')) LIMIT 1), 'cosignal_invalid', 'M2 intake: fixZ_time: refused');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_course', pg_temp.ev('fixZ_course')) LIMIT 1), 'cosignal_invalid', 'M2 intake: fixZ_course: refused');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_owner', pg_temp.ev('fixZ_owner')) LIMIT 1), 'cosignal_invalid', 'M2 intake: fixZ_owner: refused');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_nowhere', gen_random_uuid()) LIMIT 1), 'cosignal_invalid', 'M2 intake: an evidence id that names no row: refused');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_ok2', pg_temp.ev('fixZ_ok2'))), ARRAY['attached/valid/credited', 'attached/valid/credited'], 'M2 intake: control: the right row completes the scan');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-33'), 'rk1', NULL, now(), NULL, NULL, NULL)), 2, 'a second pending scan (token 33)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_ok2', pg_temp.ev('fixZ_ok2')) LIMIT 1), 'cosignal_used', 'M2 intake: the SAME row cannot complete a second scan: cosignal_used');
ROLLBACK;
-- L1. THE SCAN INSTANT IS NOT THE CLIENT'S. Without a co-signal the database refuses a p_at more than 5 minutes from now: an unqualified time may not drive the 120 s rule, the PIN date or the local date.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-34'), 'rk1', NULL, now() - interval '6 minutes', NULL, NULL, NULL)$$, '22023', 'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)', 'L1: no co-signal and p_at 6 minutes ago: refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-34'), 'rk1', NULL, now() - interval '1 day', NULL, NULL, NULL)$$, '22023', 'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)', 'L1: ... and a day ago (a photographed token cannot be burned days later as `pending`)');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-34'), 'rk1', NULL, now() + interval '6 minutes', NULL, NULL, NULL)$$, '22023', 'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)', 'L1: ... and 6 minutes ahead');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-34'), 'rk1', NULL, now() - interval '4 minutes', NULL, NULL, NULL)), 'qr_expired', 'L1: control: 4 minutes is inside the allowance (the 120 s rule then judges it: qr_expired)');
ROLLBACK;
-- L2 (m12). THE 120 s BOUNDARY, judged against the FIX: exactly 120 s from the token's issue is accepted in both directions, 121 s is not.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-35'), 'rk1', NULL, pg_temp.t0() + interval '120 seconds', 'attested', 'fixT_p120', pg_temp.ev('fixT_p120')) LIMIT 1), 'accepted', 'm12: a fix exactly 120 s AFTER the token''s issue: accepted');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-36'), 'rk1', NULL, pg_temp.t0() + interval '121 seconds', 'attested', 'fixT_p121', pg_temp.ev('fixT_p121')) LIMIT 1), 'qr_expired', 'm12: 121 s after: qr_expired');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-37'), 'rk1', NULL, pg_temp.t0() - interval '120 seconds', 'attested', 'fixT_m120', pg_temp.ev('fixT_m120')) LIMIT 1), 'accepted', 'm12: exactly 120 s BEFORE: accepted');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-38'), 'rk1', NULL, pg_temp.t0() - interval '121 seconds', 'attested', 'fixT_m121', pg_temp.ev('fixT_m121')) LIMIT 1), 'qr_expired', 'm12: 121 s before: qr_expired');
ROLLBACK;
-- L2 (m01, m02). ONE FIX COMPLETES ONE SCAN, THE EARLIEST: PI has two pending scans at fac_s24a (ref-s24-a created 2 h ago: e401 / e402; ref-s24-b 1 h ago: e403 / e404), every window holding t0.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000030')$$, 'bind PI');
SELECT is((SELECT array_agg(o_purchase_id::text ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixQ1', pg_temp.ev('fixQ1'))), ARRAY['ee240000-0000-0000-0000-00000000e401', 'ee240000-0000-0000-0000-00000000e402'], 'm01 / m02: the first fix completes the EARLIEST scan (both trails of ref-s24-a) and ONLY that scan');
SELECT is((SELECT array_agg(o_purchase_id::text ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixQ2', pg_temp.ev('fixQ2'))), ARRAY['ee240000-0000-0000-0000-00000000e403', 'ee240000-0000-0000-0000-00000000e404'], 'm01: a SECOND fix completes the second scan');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixZ_ok', gen_random_uuid()) LIMIT 1), 'cosignal_invalid', 'a third fix of PI''s with an evidence row PI does not own is refused before anything is joined');
ROLLBACK;
-- L5. THE SCAN DEFINER IS NEVER AN UNCOUNTED PIN ORACLE: a printed-QR scan needs the PIN gate's PROOF in the same transaction (the right PIN, for this facility and this fix date, after the lockout and the counters).
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('pin_e'), now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'L5: no PIN attempt in this transaction: refused, even with the RIGHT PIN');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('wrong1'), now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'L5: and with a WRONG one the answer is the same (no pin_wrong: the scan reveals nothing about a PIN it was not allowed to check)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'wrong1', now())), 'wrong', 'a wrong PIN at the gate (counted) ...');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('pin_e'), now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'L5: ... leaves no proof: the scan refuses (it cannot be reached after a failed gate)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'the gate passes at fac_s24e');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24h', 'static_pin', NULL, 'pq1', pg_temp.p('pin_h'), now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'L5: the proof is for ONE facility: the scan at another facility of the SAME time zone and day is refused');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24h', :'pin_h', now())), 'ok', 'the gate passes for TODAY at fac_s24h');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24h', 'static_pin', NULL, 'pq1', pg_temp.p('pin_h_yday'), pg_temp.t0() - interval '1 day', 'attested', 'fixG10', pg_temp.ev('fixG10'))$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'L5: ... and for ONE date: a scan dated yesterday needs yesterday''s proof');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'the gate passes at the instant now()');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('pin_e'), now() + interval '1 second', NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'NIT: the proof is for ONE INSTANT: a scan judged one second later than the gate is refused (the gate and the scan never judge two instants)');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('pin_e'), now(), NULL, NULL, NULL)), ARRAY['accepted'], 'NIT: control: the same instant is accepted');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'a gate at now() ...');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now() + interval '1 second')), 'ok', '... and a second gate one second later REPLACES the first proof (the proof is for the LAST instant judged)');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('pin_e'), now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'NIT: so the scan at the FIRST instant is refused');
ROLLBACK;
-- THE PIN PROOF DOES NOT OUTLIVE ITS TRANSACTION (the medium of the second review): this gate COMMITS with no scan after it; the rows file reads private.course_pin_proof afterwards as the owner and finds NO row
-- (a deferred constraint trigger deletes the backend's rows at COMMIT), and the next transaction of this backend still has no proof.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'the gate passes in this transaction (which COMMITS with no scan after it: a failed gate counts nothing, a right one writes only the proof) ...');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', pg_temp.p('pin_e'), now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a printed-QR scan needs course_pin_attempt_for_actor to have accepted the PIN in this transaction', 'L5: ... and the proof does NOT outlive its transaction');
ROLLBACK;
-- NIT. A rotating token presented under a kid it was not minted under is not that token (the Edge verified the signature under the kid it sends; the row names the kid it was minted under).
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-39'), 'rk0', NULL, now(), NULL, NULL, NULL)), 'qr_unknown', 'NIT: token 39 was minted under rk1; presented under rk0 it is qr_unknown');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-39'), NULL, NULL, now(), NULL, NULL, NULL)$$, '22023', 'marker_scan_for_actor: invalid arguments (a facility, rotating+nonce hash+kid or static_pin+kid+PIN, a time within 7 days, a complete co-signal or none, and a time within 5 minutes of now without a co-signal)', 'NIT: a rotating scan must name its kid');
ROLLBACK;

-- ============================================================================
-- 11. COMMITTED writes, for phase 2 (token consumption, the alarm, the credited invariant, no play and no evidence row)
-- ============================================================================
-- 11a. The scenarios phase 2 READS BACK (each a distinct player, token and shop, so the rows are attributable):
--   C1 PA   tok-10 at fac_s24a, attested fix            -> valid / credited on both trails; the token consumed by PA
--   C2 PB   tok-11 at fac_s24a, NO fix                  -> pending / pending; the 240 s window and the 7-day deadline recorded
--   C3 PC   tok-12 at fac_s24a, NO fix, then a fix      -> pending, then (second transaction) valid / credited; the credits UPDATED, not duplicated
--   C4 PD   the printed QR at fac_s24e, NO fix          -> pending / pending; the window is the facility-local day
--   C5 PE   tok-13 at fac_s24a, UNATTESTABLE fix        -> held_review / held_review
--   C6 PF   the printed QR at fac_s24e, attested fix    -> valid / credited; ref = pin:<facility>:<date>:<epoch>
--   C7 PB   the S3 stand-in e301 + a fix 6 min later    -> valid / credited (AT(13)); its pending credit credited, not duplicated
--   C8 PG   tok-20 then tok-21 at fac_s24b              -> credited, then a SECOND valid purchase with ONE credit for the shop
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'C1: bind PA');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-10'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixN1', 'ee240000-0000-0000-0000-00000000f101')), 2, 'C1 committed: PA''s scan (two trails)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'C2: bind PB');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-11'), 'rk1', NULL, now(), NULL, NULL, NULL)), 2, 'C2 committed: PB''s no-fix scan (two trails): pending / pending');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'C3: bind PC');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-12'), 'rk1', NULL, now(), NULL, NULL, NULL)), 2, 'C3 committed: PC''s no-fix scan');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'C3: bind PC again (the reconnect)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixN3', 'ee240000-0000-0000-0000-00000000f103')),
  ARRAY['attached/valid/credited', 'attached/valid/credited'], 'C3 committed: the fix completes the earlier scan');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0')$$, 'C4: bind PD');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'C4: the PIN gate');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), NULL, NULL, NULL)), 1, 'C4 committed: PD''s printed-QR scan with no fix');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0')$$, 'C5: bind PE');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-13'), 'rk1', NULL, pg_temp.t0(), 'unattestable', 'fixN5', 'ee240000-0000-0000-0000-00000000f105')), 2, 'C5 committed: PE''s unattestable scan');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000f0')$$, 'C6: bind PF');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', pg_temp.t0())), 'ok', 'C6: the PIN gate (for the fix''s instant)');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', pg_temp.t0(), 'attested', 'fixN6', 'ee240000-0000-0000-0000-00000000f106')), 1, 'C6 committed: PF''s printed-QR scan with an attested fix');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'C7: bind PB (owner of the stand-in)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24b', pg_temp.t0() - interval '6 minutes', 'attested', 'fixN7', 'ee240000-0000-0000-0000-00000000f107')),
  ARRAY['attached/valid/credited'], 'C7 committed (AT(13)): the offline-code purchase completed by the player''s co-signal');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000010')$$, 'C8: bind PG');
SELECT is((SELECT o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-20'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixN8a', 'ee240000-0000-0000-0000-00000000f108')), 'credited', 'C8 committed: the first purchase at fac_s24b');
SELECT is((SELECT o_purchase_status || '/' || o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-21'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixN8b', 'ee240000-0000-0000-0000-00000000f109')), 'valid/credited', 'C8 committed: the second purchase at the same shop');
COMMIT;
-- 11b. a token another account consumed (committed) is qr_used for everyone, and so is one a NO-FIX scan consumed
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000020')$$, 'bind PH');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-10'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixN2', pg_temp.ev('fixN2'))), 'qr_used', 'AT(19): a token another account consumed (committed) is qr_used for PH as well');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-11'), 'rk1', NULL, pg_temp.t0(), 'attested', 'fixN4', pg_temp.ev('fixN4'))), 'qr_used', 'and a token consumed by a NO-FIX scan too');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', pg_temp.t0())), 'ok', 'the PIN gate');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', pg_temp.t0(), 'attested', 'fixN9', pg_temp.ev('fixN9'))), 'accepted', 'while the printed QR carries no token: PH may scan the shop PD and PF scanned (the PIN is the day''s, shared by design; the fix is the player''s own)');
ROLLBACK;
-- 11c. the committed 30-failure alarm on fac_s24h: six players, five wrong PINs each. The 30th rotates the PIN; nothing before it does.
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0');
SELECT is(pg_temp.pin_tries('fac_s24h', :'wrong1', 5), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong'], 'alarm: PA, 5 wrong at fac_s24h');
COMMIT;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0');
SELECT is(pg_temp.pin_tries('fac_s24h', :'wrong1', 5), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong'], 'alarm: PB, 5 wrong');
COMMIT;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0');
SELECT is(pg_temp.pin_tries('fac_s24h', :'wrong1', 5), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong'], 'alarm: PC, 5 wrong');
COMMIT;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0');
SELECT is(pg_temp.pin_tries('fac_s24h', :'wrong1', 5), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong'], 'alarm: PD, 5 wrong');
COMMIT;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0');
SELECT is(pg_temp.pin_tries('fac_s24h', :'wrong1', 5), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong'], 'alarm: PE, 5 wrong (25 so far)');
COMMIT;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-000000000010');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24h', :'pin_h', now())), 'ok', 'the PIN is still epoch 0''s: nothing has rotated at 25 (a player who has not failed: ok)');
ROLLBACK;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000f0');
SELECT is(pg_temp.pin_tries('fac_s24h', :'wrong1', 5), ARRAY['wrong', 'wrong', 'wrong', 'wrong', 'wrong'], 'alarm: PF, 5 wrong: the 30th is among them');
COMMIT;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee240000-0000-0000-0000-000000000010');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24h', :'pin_h', now())), 'wrong', 'AT(19): after 30 wrong PINs from six players the OLD PIN no longer works (a player who has not failed once)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24h', :'pin_h_e1', now())), 'ok', 'and the NEW (epoch 1) PIN does');
COMMIT;
-- 11d. (follow-ups) COMMITTED, read back in phase 2:
--   C9  PD  a printed-QR scan whose fix is dated YESTERDAY, uploaded after two rotations: ok, accepted, and NOT ONE failure counted (M1)
--   C10 PJ  a pending purchase completed while the player already holds the shop's credit: the redundant pending credit is VOIDED (m14)
--   C11 PD  fac_s24m (rows at epochs 0 and 3, counter seeded at 29 for epoch 3): the 30th failure rotates from the HIGHEST epoch: BOTH rows to 4 (m10)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0')$$, 'C9: bind PD');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_d', pg_temp.t0() - interval '1 day')), 'ok', 'C9: the gate for yesterday''s fix');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24r', 'static_pin', NULL, 'pq1', :'pin_r_d', pg_temp.t0() - interval '1 day', 'attested', 'fixR_d', pg_temp.ev('fixR_d'))), 'accepted', 'C9 committed: a queued printed-QR scan survives two rotations');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000040')$$, 'C10: bind PJ');
SELECT is((SELECT o_credit_id::text || '/' || o_credit_status FROM private.marker_cosignal_attach_for_actor('fac_s24a', pg_temp.t0(), 'attested', 'fixO1', pg_temp.ev('fixO1'))), 'ee240000-0000-0000-0000-00000000ec03/credited',
  'C10 committed: completing the pending purchase answers the player''s EXISTING credit (the pending one is redundant)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0')$$, 'C11: bind PD');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24m', :'wrong_m', now())), 'wrong', 'C11 committed: the 30th failure at fac_s24m (counted against the HIGHEST epoch, 3)');
COMMIT;
-- C12 PE: a WRONG PIN for an instant when epoch 1 was live (t0 - 2 h), while the facility is at epoch 2: counted against the facility's CURRENT epoch (2), not the epoch the PIN was judged under (m: the counter key)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0')$$, 'C12: bind PE');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24r', :'pin_r_a', pg_temp.t0() - interval '2 hours')), 'wrong', 'C12 committed: a wrong PIN for an instant under epoch 1');
COMMIT;

SELECT * FROM finish();
