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
  ('ee240000-0000-0000-0000-0000000000e0'), ('ee240000-0000-0000-0000-0000000000f0'), ('ee240000-0000-0000-0000-000000000010'), ('ee240000-0000-0000-0000-000000000020')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.profile (user_id, handle) VALUES
  ('ee240000-0000-0000-0000-0000000000a0', 'edge24_pa'), ('ee240000-0000-0000-0000-0000000000b0', 'edge24_pb'), ('ee240000-0000-0000-0000-0000000000c0', 'edge24_pc'), ('ee240000-0000-0000-0000-0000000000d0', 'edge24_pd'),
  ('ee240000-0000-0000-0000-0000000000e0', 'edge24_pe'), ('ee240000-0000-0000-0000-0000000000f0', 'edge24_pf'), ('ee240000-0000-0000-0000-000000000010', 'edge24_pg'), ('ee240000-0000-0000-0000-000000000020', 'edge24_ph');

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
COMMIT;
RESET ROLE;

-- The Vault pepper (a run-time constant, never a secret literal) and the PUBLIC verification keys (temporary CURRENT_USER policy, dropped again: the table has no policy for the harness role).
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40));
CREATE POLICY current_user_seed_course_qr_key_24e ON app.course_qr_key FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url, revoked_at) VALUES
  ('rotating_token', 'rk1', repeat('A', 43), NULL), ('rotating_token', 'rk0', repeat('B', 43), now()), ('printed_qr', 'pq1', repeat('C', 43), NULL);
DROP POLICY current_user_seed_course_qr_key_24e ON app.course_qr_key;

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
SELECT private.course_pin_derive('fac_s24h', (now() AT TIME ZONE 'America/Chicago')::date, 1) AS pin_h_e1 \gset
SELECT private.course_pin_derive('fac_s24f', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_f \gset
SELECT private.course_pin_derive('fac_s24p', (now() AT TIME ZONE 'America/Chicago')::date, 0) AS pin_p \gset
ROLLBACK;
-- a PIN that is wrong for every facility above today (built from a correct one: +1, +2 mod 10000, so it cannot be a typo of the same value)
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
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES
  ('marker-scan:pin-fail:u:ee240000-0000-0000-0000-000000000010:fac_s24e:' || to_char((now() AT TIME ZONE 'America/Chicago')::date - 1, 'YYYY-MM-DD'), date_trunc('day', now() - interval '1 day'), 9);
RESET ROLE;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(196);
CREATE FUNCTION pg_temp.h(s text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT encode(sha256(convert_to(s, 'UTF8')), 'hex') $f$;
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
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), NULL, NULL, now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: no actor is bound in this transaction', 'unbound: the scan refuses');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), 'attested', 'fix1', gen_random_uuid())$$, '42501', 'marker_cosignal_attach_for_actor: no actor is bound in this transaction', 'unbound: the co-signal intake refuses');
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
           FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), NULL, NULL, now(), 'attested', 'fixA1', 'ee240000-0000-0000-0000-00000000f001')),
  ARRAY['accepted/trl_s24a/valid/credited', 'accepted/trl_s24b/valid/credited'], 'AT(19): a rotating token with an attested co-signal -> a `valid` purchase and a `credited` credit, one per eligible trail');
-- 3b. the token is consumed: it cannot be scanned again
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), NULL, NULL, now(), 'attested', 'fixA2', gen_random_uuid())), 'qr_used', 'AT(19): the SAME token scanned again -> qr_used (409)');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-1'), NULL, NULL, now(), NULL, NULL, NULL) WHERE o_result = 'qr_used'), 1, 'and without a fix too (one refusal row, no purchase)');
-- 3c. a token scanned by someone else is used for everyone
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA (second transaction)');
-- 3d. the 120 s rule is judged against the FIX's time, in both directions
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-2'), NULL, NULL, now() + interval '135 seconds', 'attested', 'fixA3', gen_random_uuid()) LIMIT 1), 'qr_expired',
  'AT(19): a token issued more than 120 s BEFORE the fix -> 422 qr_expired');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-2'), NULL, NULL, now() - interval '135 seconds', 'attested', 'fixA4', gen_random_uuid()) LIMIT 1), 'qr_expired',
  'AT(19): ... and a fix taken more than 120 s BEFORE the token was issued is equally outside the rule (the rule is distance, not direction)');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-2'), NULL, NULL, now() + interval '100 seconds', 'attested', 'fixA5', gen_random_uuid())), ARRAY['accepted', 'accepted'],
  'control: a fix 100 s from the issue is inside the rule (and the earlier refusals did NOT consume the token)');
ROLLBACK;
-- the UPLOAD time does not matter (plan §7.6: "the token's 120 s window is judged against the fix's time, not the upload time"): token 22 was issued THREE DAYS ago
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA (an offline upload, three days late)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-22'), NULL, NULL, now(), 'attested', 'fixA20', gen_random_uuid()) LIMIT 1), 'qr_expired', 'a fix taken NOW against a token issued three days ago: qr_expired');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-22'), NULL, NULL, now() - interval '3 days' + interval '20 seconds', 'attested', 'fixA21', gen_random_uuid())),
  ARRAY['accepted/valid/credited', 'accepted/valid/credited'], 'AT(19)/§7.6: the same token with a fix taken 20 s after its issue three days ago (uploaded now) is accepted: valid / credited, judged against the FIX');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-22'), NULL, NULL, now() - interval '3 days' + interval '20 seconds', 'attested', 'fixA22', gen_random_uuid())), 'qr_used', 'and it is still single use');
ROLLBACK;
-- 3e. wrong facility / unknown nonce / no programme
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-20'), NULL, NULL, now(), 'attested', 'fixA6', gen_random_uuid()) LIMIT 1), 'qr_wrong_facility',
  'a token minted for ANOTHER facility (fac_s24b) is refused at fac_s24a (AT(19): "another facility" -> 422)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('no-such-token'), NULL, NULL, now(), 'attested', 'fixA7', gen_random_uuid())), 'qr_unknown', 'an unknown nonce: qr_unknown (the Edge answers invalid_qr)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-20'), NULL, NULL, now(), 'attested', 'fixA8', gen_random_uuid())), 'accepted', 'control: the same token at its own facility is accepted');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24c', 'rotating', pg_temp.h('s24-tok-3'), NULL, NULL, now(), 'attested', 'fixA9', gen_random_uuid())), 'no_programme', 'a facility whose programme row is only `invited`: no_programme');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24d', 'rotating', pg_temp.h('s24-tok-3'), NULL, NULL, now(), 'attested', 'fixA10', gen_random_uuid())), 'no_programme', 'a facility whose trail programme is `off`: no_programme');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24p', 'rotating', pg_temp.h('s24-tok-3'), NULL, NULL, now(), 'attested', 'fixA11', gen_random_uuid())), 'no_programme', 'a programme_marker trail takes no course-QR purchase (code cards are its path)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_nope', 'rotating', pg_temp.h('s24-tok-3'), NULL, NULL, now(), 'attested', 'fixA12', gen_random_uuid())), 'no_facility', 'a facility that does not exist: no_facility');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'rotating', pg_temp.h('s24-tok-3'), NULL, NULL, now(), 'attested', 'fixA13', gen_random_uuid())), 'variant_disabled', 'a printed-QR-only facility does not take a rotating token: variant_disabled');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24b', 'static_pin', NULL, 'pq1', :'pin_a', now(), 'attested', 'fixA14', gen_random_uuid())), 'variant_disabled', 'a rotating-only facility does not take the printed QR: variant_disabled');
ROLLBACK;
-- 3f. AT(19)/AT(3): no co-signal -> a PENDING credit, never credited; the token is consumed (the window a later fix must fall in is read back from the committed scan, section 11)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-4'), NULL, NULL, now(), NULL, NULL, NULL)),
  ARRAY['accepted/pending/pending', 'accepted/pending/pending'], 'AT(3)/AT(19): a scan with NO co-signal -> a `pending` purchase and a `pending` credit, never `credited`');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-4'), NULL, NULL, now(), 'attested', 'fixB1', gen_random_uuid()) LIMIT 1), 'qr_used', 'a no-fix scan consumed the token (single use)');
-- 3g. AT(19): the pending credit is credited only by a qualifying fix inside the window (the co-signal intake)
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', now() + interval '60 seconds', 'attested', 'fixB2', gen_random_uuid())),
  ARRAY['attached/valid/credited', 'attached/valid/credited'], 'AT(19): a qualifying fix inside the 120 s window completes the scan: valid / credited (both trails)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', now() + interval '60 seconds', 'attested', 'fixB3', gen_random_uuid()) LIMIT 1), 'no_pending_purchase', 'a SECOND fix finds nothing to complete: one fix completes one scan, one scan takes one fix');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-5'), NULL, NULL, now(), NULL, NULL, NULL)), 2, 'a pending scan again (token 5)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', now() + interval '130 seconds', 'attested', 'fixC1', gen_random_uuid()) LIMIT 1), 'no_pending_purchase',
  'AT(19): a fix MORE than 120 s from the token''s issue does not complete it (the rotating window is judged against the issue time)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', now() - interval '130 seconds', 'attested', 'fixC2', gen_random_uuid()) LIMIT 1), 'no_pending_purchase', '... in either direction');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', now(), 'attested', 'fixC3', gen_random_uuid()) LIMIT 1), 'no_pending_purchase', 'a fix at ANOTHER facility completes nothing');
SELECT is((SELECT array_agg(o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), 'attested', 'fixC4', gen_random_uuid())), ARRAY['valid/credited', 'valid/credited'], 'control: after those three refusals the pending scan is intact, and a qualifying fix at its own facility inside the window still completes it');
ROLLBACK;
-- 3h. AT(19): the 7-day deadline. A scan older than seven days no longer takes a fix (the row stays pending). The scan is made, then its deadline is moved into the past
-- in a SEPARATE committed fixture row (e302, seeded already past its deadline), so the intake is exercised against a real past deadline.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC (owner of the stand-in whose 7-day deadline has passed)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', now(), 'attested', 'fixD1', gen_random_uuid())), 'no_pending_purchase', 'AT(19): a fix that arrives AFTER the 7-day deadline completes nothing (the window holds the fix, the deadline does not)');
ROLLBACK;
-- 3i. a repeat credit at a shop the player is already credited at: the purchase is recorded, no second credit exists
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-20'), NULL, NULL, now(), 'attested', 'fixE1', gen_random_uuid())), 'credited', 'the first scan at fac_s24b credits');
SELECT is((SELECT o_purchase_status || '/' || o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-21'), NULL, NULL, now(), 'attested', 'fixE2', gen_random_uuid())), 'valid/credited',
  'a SECOND purchase at the same shop (another token): the purchase is recorded valid, and the player is reported credited ...');
ROLLBACK;

-- ============================================================================
-- 4. AT(19): an `unattestable` co-signal -> held_review (never a silent refusal), a `failed` one is not a co-signal at all
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'bind PB');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-6'), NULL, NULL, now(), 'unattestable', 'fixF1', gen_random_uuid())),
  ARRAY['accepted/held_review/held_review', 'accepted/held_review/held_review'], 'AT(19): an unattestable presence fix sends the purchase AND the credit to held_review');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-7'), NULL, NULL, now(), 'failed', 'fixF2', gen_random_uuid())$$, '22023', NULL,
  'a `failed` grade is not a co-signal: the definer refuses it as an argument (the Edge never passes one: a failed fix is not a co-signal, nothing is earned on it)');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-7'), NULL, NULL, now(), 'attested', NULL, gen_random_uuid())$$, '22023', NULL, 'a co-signal with no fix id is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-7'), NULL, NULL, now(), 'attested', 'fixF3', NULL)$$, '22023', NULL, 'a co-signal with no evidence id is refused');
-- an unattestable fix that completes a PENDING scan -> held_review too
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-8'), NULL, NULL, now(), NULL, NULL, NULL)), 2, 'a pending scan (token 8)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), 'unattestable', 'fixF4', gen_random_uuid())),
  ARRAY['attached/held_review/held_review', 'attached/held_review/held_review'], 'an unattestable fix that completes a pending scan routes it to held_review as well');
ROLLBACK;

-- ============================================================================
-- 5. AT(19): the printed QR (Q2) and today's PIN
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), 'ok', 'today''s PIN for the facility: ok');
SELECT is((SELECT o_retry_after_seconds FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e', now())), NULL, 'an ok carries no retry hint');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), 'attested', 'fixG1', gen_random_uuid())),
  ARRAY['accepted/valid/credited'], 'AT(19): the printed QR + today''s PIN + an attested fix: valid / credited');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), 'attested', 'fixG2', gen_random_uuid())), 'duplicate', 'the same player scanning the same shop on the same local day again: duplicate (409)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'bind PC (second transaction)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_e_yday', now())), 'wrong', 'AT(19): YESTERDAY''s PIN -> wrong (422)');
SELECT is((SELECT o_result FROM private.course_pin_attempt_for_actor('fac_s24e', :'pin_a', now())), 'wrong', 'AT(19): ANOTHER facility''s PIN -> wrong (422)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e_yday', now(), 'attested', 'fixG3', gen_random_uuid())), 'pin_wrong', 'the scan itself re-checks the PIN: yesterday''s is refused there too (the gate is not only the counter)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_a', now(), 'attested', 'fixG4', gen_random_uuid())), 'pin_wrong', 'and another facility''s PIN');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq9', :'pin_e', now(), 'attested', 'fixG5', gen_random_uuid())), 'qr_revoked', 'a printed QR with a kid that is not the facility''s current one: qr_revoked (a reprint revokes the old kid)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24f', 'static_pin', NULL, 'pq0', :'pin_f', now(), 'attested', 'fixG6', gen_random_uuid())), 'qr_revoked', 'a revoked printed QR is refused even with the right PIN');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24b', 'static_pin', NULL, 'pq1', :'pin_a', now(), 'attested', 'fixG7', gen_random_uuid())), 'variant_disabled', 'a facility that takes only the rotating token');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24g', 'static_pin', NULL, 'pq1', :'pin_g_utcday', now(), 'attested', 'fixG8', gen_random_uuid())), 'pin_wrong', 'the PIN''s day is the FACILITY''s local date, not the UTC date or another zone''s (fac_s24g is in New Zealand)');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24g', 'static_pin', NULL, 'pq1', :'pin_g', now(), 'attested', 'fixG9', gen_random_uuid())), 'accepted', 'control: the New Zealand local-date PIN is accepted there');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24h', 'static_pin', NULL, 'pq1', :'pin_h', now() - interval '1 day', 'attested', 'fixG10', gen_random_uuid())), 'pin_wrong', 'a fix dated YESTERDAY needs YESTERDAY''s PIN: today''s is refused for it');
ROLLBACK;
-- the printed QR with no co-signal: pending, window = the facility-local day
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0')$$, 'bind PD');
SELECT is((SELECT array_agg(o_purchase_status || '/' || o_credit_status) FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), NULL, NULL, NULL)), ARRAY['pending/pending'], 'AT(3): the printed QR + the PIN with no fix: pending, pending');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24e', now() - interval '1 day', 'attested', 'fixH1', gen_random_uuid())), 'no_pending_purchase', 'AT(19): a fix from the PREVIOUS local date does not complete a printed-QR scan');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24e', now(), 'attested', 'fixH2', gen_random_uuid())), ARRAY['attached/valid/credited'],
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
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'static_pin', NULL, 'pq1', :'pin_a', now(), 'attested', 'fixI1', gen_random_uuid())), 'pin_wrong', 'the scan refuses the rotated-out PIN too');
SELECT is((SELECT array_agg(o_result) FROM private.marker_scan_for_actor('fac_s24a', 'static_pin', NULL, 'pq1', :'pin_a_e1', now(), 'attested', 'fixI2', gen_random_uuid())), ARRAY['accepted', 'accepted'], 'and accepts the new one (both trails)');
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
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24a', now() - interval '6 minutes', 'attested', 'fixJ0', gen_random_uuid())), 'no_pending_purchase', 'AT(13): without a co-signal at the row''s facility the offline-code scan stays pending (a fix at ANOTHER facility joins nothing)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24b', now() - interval '6 minutes', 'attested', 'fixJ1', gen_random_uuid())),
  ARRAY['attached/valid/credited'], 'AT(13): the co-signal 6 minutes later (inside +-10 min of the step) -> the row becomes valid and the credit credited on reconnect');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'bind PB');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', now() - interval '25 minutes', 'attested', 'fixJ3', gen_random_uuid())), 'no_pending_purchase', 'AT(13): a fix OUTSIDE the +-10 min window (before it) completes nothing');
SELECT is((SELECT array_agg(o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24b', now(), 'unattestable', 'fixJ4', gen_random_uuid())), ARRAY['held_review/held_review'], 'an unattestable prefetched-challenge fix routes the offline purchase to held_review');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000020')$$, 'bind PH (owner of the stand-in whose window ended two hours ago)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', now(), 'attested', 'fixJ2', gen_random_uuid())), 'no_pending_purchase', 'AT(13): a fix AFTER the +-10 min window completes nothing either');
ROLLBACK;
-- another account's pending row is invisible: the explicit filters, and the GUC windows planted as the attacker give no access
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000a0')$$, 'bind PA (not the stand-in''s owner)');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', now() - interval '6 minutes', 'attested', 'fixJ5', gen_random_uuid())), 'no_pending_purchase', 'PA cannot complete PB''s pending purchase with PA''s own fix');
SELECT set_config('app.delete_my_data.target_user_id', 'ee240000-0000-0000-0000-0000000000b0', true);
SELECT set_config('app.offline_code.target_device_id', 'ee240000-0000-0000-0000-00000000b001', true);
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_s24b', now() - interval '6 minutes', 'attested', 'fixJ6', gen_random_uuid())), 'no_pending_purchase', 'HARD RULE: with the delete_my_data and offline_code windows PLANTED as PB, PA still cannot reach PB''s row (the policies are keyed on the binding)');
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
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), NULL, NULL, now(), NULL, NULL, NULL)$$, '42501', NULL, 'edge_system holds no EXECUTE on the scan');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '1234', now())$$, '42501', NULL, 'nor on the PIN gate');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), 'attested', 'fixK1', gen_random_uuid())$$, '42501', NULL, 'nor on the co-signal intake');
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
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), NULL, NULL, NULL, NULL, NULL, NULL)$$, '22023', NULL, 'a NULL time is refused');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), NULL, NULL, now() - interval '8 days', NULL, NULL, NULL)$$, '22023', NULL, 'a fix older than 7 days is refused (the deadline is the database''s, not the client''s)');
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), NULL, NULL, now() + interval '10 minutes', NULL, NULL, NULL)$$, '22023', NULL, 'and one from the future');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), NULL, 'fixL1', gen_random_uuid())$$, '22023', NULL, 'the co-signal intake needs a qualifying grade');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', now() - interval '8 days', 'attested', 'fixL2', gen_random_uuid())$$, '22023', NULL, 'and a time within 7 days');
ROLLBACK;
-- a system delegate binding is refused by every wrapper
BEGIN;
SET LOCAL ROLE edge_system;
SELECT private.bind_delegate_for_queued_evidence('ee240000-0000-0000-0000-0000000a0e24');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), NULL, NULL, now(), NULL, NULL, NULL)$$, '42501', 'marker_scan_for_actor: a system delegate may not record a marker purchase', 'delegate: a system-delegate binding cannot record a purchase');
SELECT throws_ok($$SELECT * FROM private.course_pin_attempt_for_actor('fac_s24e', '1234', now())$$, '42501', 'course_pin_attempt_for_actor: a system delegate may not attempt a course PIN', 'delegate: nor attempt a PIN');
SELECT throws_ok($$SELECT * FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), 'attested', 'fixM1', gen_random_uuid())$$, '42501', 'marker_cosignal_attach_for_actor: a system delegate may not attach a co-signal', 'delegate: nor attach a co-signal');
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
SELECT throws_ok($$SELECT * FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-9'), NULL, NULL, now(), NULL, NULL, NULL)$$, '42501',
  'marker_scan_for_actor: no actor is bound in this transaction', '... transaction 2 inherits NO actor (the binding is per transaction)');
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
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-10'), NULL, NULL, now(), 'attested', 'fixN1', 'ee240000-0000-0000-0000-00000000f101')), 2, 'C1 committed: PA''s scan (two trails)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'C2: bind PB');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-11'), NULL, NULL, now(), NULL, NULL, NULL)), 2, 'C2 committed: PB''s no-fix scan (two trails): pending / pending');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'C3: bind PC');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-12'), NULL, NULL, now(), NULL, NULL, NULL)), 2, 'C3 committed: PC''s no-fix scan');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000c0')$$, 'C3: bind PC again (the reconnect)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status ORDER BY o_trail_id) FROM private.marker_cosignal_attach_for_actor('fac_s24a', now(), 'attested', 'fixN3', 'ee240000-0000-0000-0000-00000000f103')),
  ARRAY['attached/valid/credited', 'attached/valid/credited'], 'C3 committed: the fix completes the earlier scan');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000d0')$$, 'C4: bind PD');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), NULL, NULL, NULL)), 1, 'C4 committed: PD''s printed-QR scan with no fix');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000e0')$$, 'C5: bind PE');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-13'), NULL, NULL, now(), 'unattestable', 'fixN5', 'ee240000-0000-0000-0000-00000000f105')), 2, 'C5 committed: PE''s unattestable scan');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000f0')$$, 'C6: bind PF');
SELECT is((SELECT count(*)::int FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), 'attested', 'fixN6', 'ee240000-0000-0000-0000-00000000f106')), 1, 'C6 committed: PF''s printed-QR scan with an attested fix');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-0000000000b0')$$, 'C7: bind PB (owner of the stand-in)');
SELECT is((SELECT array_agg(o_result || '/' || o_purchase_status || '/' || o_credit_status) FROM private.marker_cosignal_attach_for_actor('fac_s24b', now() - interval '6 minutes', 'attested', 'fixN7', 'ee240000-0000-0000-0000-00000000f107')),
  ARRAY['attached/valid/credited'], 'C7 committed (AT(13)): the offline-code purchase completed by the player''s co-signal');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000010')$$, 'C8: bind PG');
SELECT is((SELECT o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-20'), NULL, NULL, now(), 'attested', 'fixN8a', 'ee240000-0000-0000-0000-00000000f108')), 'credited', 'C8 committed: the first purchase at fac_s24b');
SELECT is((SELECT o_purchase_status || '/' || o_credit_status FROM private.marker_scan_for_actor('fac_s24b', 'rotating', pg_temp.h('s24-tok-21'), NULL, NULL, now(), 'attested', 'fixN8b', 'ee240000-0000-0000-0000-00000000f109')), 'valid/credited', 'C8 committed: the second purchase at the same shop');
COMMIT;
-- 11b. a token another account consumed (committed) is qr_used for everyone, and so is one a NO-FIX scan consumed
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee240000-0000-0000-0000-000000000020')$$, 'bind PH');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-10'), NULL, NULL, now(), 'attested', 'fixN2', gen_random_uuid())), 'qr_used', 'AT(19): a token another account consumed (committed) is qr_used for PH as well');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24a', 'rotating', pg_temp.h('s24-tok-11'), NULL, NULL, now(), 'attested', 'fixN4', gen_random_uuid())), 'qr_used', 'and a token consumed by a NO-FIX scan too');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_s24e', 'static_pin', NULL, 'pq1', :'pin_e', now(), 'attested', 'fixN9', gen_random_uuid())), 'accepted', 'while the printed QR carries no token: PH may scan the shop PD and PF scanned (the PIN is the day''s, shared by design; the fix is the player''s own)');
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

SELECT * FROM finish();
