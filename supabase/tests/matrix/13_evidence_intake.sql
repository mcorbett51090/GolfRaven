-- 13_evidence_intake.sql
-- P3c: the DB-side primitives supabase/functions/_shared/privileged.ts's
-- Repo implementation relies on for POST /v1/evidence (+ batch) and
-- POST /v1/checkin/challenge + checkin-token. Exercises the exact SQL
-- shapes privileged.ts runs, directly, against a real Postgres (the
-- "integration tests against the local Postgres harness" the task asks
-- for, since privileged.ts itself is Deno-only and can't run in this
-- harness).

BEGIN;
SELECT plan(24);

-- ============================================================================
-- 1. app.catalog_signing_key / app.checkin_token: no client role can read
--    or write (0019's "nobody" convention) — belt-and-suspenders on top of
--    01_rls_enabled.sql / 02_grants_trust.sql's already-generic coverage.
-- ============================================================================
SELECT is(
  (SELECT count(*)::int FROM information_schema.role_table_grants
   WHERE table_schema = 'app' AND table_name IN ('catalog_signing_key', 'checkin_token')
     AND grantee IN ('anon', 'authenticated')),
  0,
  'no anon/authenticated grant on catalog_signing_key or checkin_token'
);

SELECT tests.authenticate_as('authenticated', jsonb_build_object('sub', '00000000-0000-0000-0000-00000000000a'));
SELECT throws_ok(
  $$SELECT count(*) FROM app.checkin_token$$,
  '42501',
  NULL,
  'authenticated has no SELECT grant at all on app.checkin_token (not merely RLS-filtered — no policy AND no grant)'
);
SELECT throws_ok(
  $$INSERT INTO app.checkin_token (challenge_id, user_id, device_id, attestation_grade, challenge_kind, expires_at)
    VALUES (gen_random_uuid(), '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'unattestable', 'live', now() + interval '15 minutes')$$,
  '42501',
  NULL,
  'authenticated cannot INSERT into app.checkin_token (no grant at all)'
);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ============================================================================
-- 2. app.catalog_signing_key: empty by default (0019's own doc — the key
--    -rotation workflow is out of scope; verification fails closed with
--    no row present).
-- ============================================================================
SELECT is((SELECT count(*)::int FROM app.catalog_signing_key), 0, 'catalog_signing_key ships empty (no keys provisioned this round)');

-- ============================================================================
-- 3. app.checkin_challenge -> app.checkin_token: single-use consumption
--    (Repo#consumeChallenge's own SQL shape).
-- ============================================================================
INSERT INTO app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind)
VALUES ('60000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'nonce-hash-1', now() + interval '2 minutes', 'live');

-- A data-modifying WITH must be the top-level statement (Postgres does
-- not allow one nested inside a scalar-subquery argument to is()) — so
-- each UPDATE/INSERT below runs as its own bare top-level statement, and
-- the assertion checks the resulting STATE afterward instead of the
-- RETURNING row count inline.
UPDATE app.checkin_challenge SET used_at = now() WHERE id = '60000000-0000-0000-0000-000000000001' AND used_at IS NULL;
SELECT is(
  (SELECT used_at IS NOT NULL FROM app.checkin_challenge WHERE id = '60000000-0000-0000-0000-000000000001'),
  true,
  'consumeChallenge: first consumption sets used_at'
);
UPDATE app.checkin_challenge SET used_at = now() WHERE id = '60000000-0000-0000-0000-000000000001' AND used_at IS NULL;
SELECT is(
  (SELECT count(*)::int FROM app.checkin_challenge WHERE id = '60000000-0000-0000-0000-000000000001' AND used_at IS NULL),
  0,
  'consumeChallenge: a SECOND consumption of the same (already-used) challenge matches 0 rows (single-use, not an error)'
);

-- Also proves the checkin_challenge_used_at_once trigger (0017) still
-- fires correctly against a row this migration set produced normally.
SELECT throws_ok(
  $$UPDATE app.checkin_challenge SET used_at = now() - interval '1 minute' WHERE id = '60000000-0000-0000-0000-000000000001'$$,
  '23514',
  NULL,
  'checkin_challenge.used_at cannot be changed once set (0017''s own trigger, unaffected by 0019)'
);

INSERT INTO app.checkin_token (challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, expires_at)
VALUES ('60000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'unattestable', 'live', now() + interval '15 minutes');
SELECT is(
  (SELECT count(*)::int FROM app.checkin_token WHERE challenge_id = '60000000-0000-0000-0000-000000000001'),
  1,
  'checkin_token insert succeeds'
);

-- H1: deleting the checkin_challenge row cascades to checkin_token
-- (0019's own ON DELETE CASCADE — proven directly, not just via
-- 09_delete_my_data.sql's generic FK-shape check).
DELETE FROM app.checkin_challenge WHERE id = '60000000-0000-0000-0000-000000000001';
SELECT is(
  (SELECT count(*)::int FROM app.checkin_token WHERE challenge_id = '60000000-0000-0000-0000-000000000001'),
  0,
  'deleting the parent checkin_challenge row cascades to app.checkin_token (ON DELETE CASCADE)'
);

-- ============================================================================
-- 3b. P3c gate round 2, item 4: Repo#checkinToken.consumeForFix's own
--     single atomic UPDATE — ownership + single-use + device match +
--     challenge-window clamp (issued_at <= capturedAt <= expires_at), all
--     in ONE WHERE clause (see privileged.ts's own doc).
-- ============================================================================
INSERT INTO app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind)
VALUES ('61000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'nonce-hash-consume-1', now() + interval '2 minutes', 'live');
UPDATE app.checkin_challenge SET used_at = now() WHERE id = '61000000-0000-0000-0000-000000000001';
INSERT INTO app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at)
VALUES ('61100000-0000-0000-0000-000000000001', '61000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'fac_x', 'unattestable', 'live', now() - interval '1 minute', now() + interval '14 minutes');

-- A DIFFERENT device than the token's own device_id: consumeForFix's
-- WHERE clause must reject it (0 rows updated), never fall back to
-- matching on user_id/jti alone.
UPDATE app.checkin_token SET consumed_at = now()
WHERE jti = '61100000-0000-0000-0000-000000000001'
  AND user_id = '00000000-0000-0000-0000-00000000000a'
  AND device_id = '20000000-0000-0000-0000-000000000099' -- wrong device
  AND consumed_at IS NULL AND expires_at > now();
SELECT is(
  (SELECT consumed_at FROM app.checkin_token WHERE jti = '61100000-0000-0000-0000-000000000001'),
  NULL,
  'consumeForFix-shape UPDATE: a device mismatch matches 0 rows (consumed_at stays NULL)'
);

-- A capturedAt OUTSIDE [issued_at, expires_at] (e.g. before issued_at):
-- also 0 rows, even with the RIGHT device.
UPDATE app.checkin_token SET consumed_at = now()
WHERE jti = '61100000-0000-0000-0000-000000000001'
  AND user_id = '00000000-0000-0000-0000-00000000000a'
  AND device_id = '20000000-0000-0000-0000-000000000001'
  AND consumed_at IS NULL AND expires_at > now()
  AND issued_at <= (now() - interval '10 minutes') AND (now() - interval '10 minutes') <= expires_at;
SELECT is(
  (SELECT consumed_at FROM app.checkin_token WHERE jti = '61100000-0000-0000-0000-000000000001'),
  NULL,
  'consumeForFix-shape UPDATE: a capturedAt before issued_at matches 0 rows (window clamp)'
);

-- The RIGHT device, WITHIN the window: succeeds, exactly once.
UPDATE app.checkin_token SET consumed_at = now()
WHERE jti = '61100000-0000-0000-0000-000000000001'
  AND user_id = '00000000-0000-0000-0000-00000000000a'
  AND device_id = '20000000-0000-0000-0000-000000000001'
  AND consumed_at IS NULL AND expires_at > now()
  AND issued_at <= now() AND now() <= expires_at;
SELECT is(
  (SELECT consumed_at IS NOT NULL FROM app.checkin_token WHERE jti = '61100000-0000-0000-0000-000000000001'),
  true,
  'consumeForFix-shape UPDATE: right device + within window succeeds'
);
-- A SECOND attempt (single-use): 0 rows, even though device/window are
-- both still fine.
UPDATE app.checkin_token SET consumed_at = now()
WHERE jti = '61100000-0000-0000-0000-000000000001'
  AND user_id = '00000000-0000-0000-0000-00000000000a'
  AND device_id = '20000000-0000-0000-0000-000000000001'
  AND consumed_at IS NULL AND expires_at > now()
  AND issued_at <= now() AND now() <= expires_at;
SELECT is(
  (SELECT count(*)::int FROM app.checkin_token WHERE jti = '61100000-0000-0000-0000-000000000001' AND consumed_at IS NULL),
  0,
  'consumeForFix-shape UPDATE: a second consumption attempt matches 0 rows (single-use)'
);

-- ============================================================================
-- 3c. P3c gate round 2, item 1: app.evidence.local_date is a REAL column
--     that Repo#evidence.listForPlay filters on directly — proven here as
--     the exact query shape, not the fail-open coalesce it replaced.
-- ============================================================================
INSERT INTO app.evidence (user_id, device_id, source, source_ref, input_hash, facility_id, course_id, status, attestation_grade, catalog_version, summary, local_date)
VALUES ('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'self_report', 'p3c-localdate-day1', encode(digest('p3c-localdate-day1', 'sha256'), 'hex'), 'fac_x', 'crs_x1', 'accepted', 'unattestable', 1, '{}'::jsonb, '2026-06-01'),
       ('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'self_report', 'p3c-localdate-day2', encode(digest('p3c-localdate-day2', 'sha256'), 'hex'), 'fac_x', 'crs_x1', 'accepted', 'unattestable', 1, '{}'::jsonb, '2026-06-02');
SELECT is(
  (SELECT count(*)::int FROM app.evidence WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND facility_id = 'fac_x'
     AND (course_id = 'crs_x1' OR course_id IS NULL) AND local_date = '2026-06-01' AND status = 'accepted'
     AND source_ref = 'p3c-localdate-day1'),
  1,
  'listForPlay-shape query: day-1 row matches a day-1 query'
);
SELECT is(
  (SELECT count(*)::int FROM app.evidence WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND facility_id = 'fac_x'
     AND (course_id = 'crs_x1' OR course_id IS NULL) AND local_date = '2026-06-01' AND status = 'accepted'
     AND source_ref = 'p3c-localdate-day2'),
  0,
  'listForPlay-shape query: day-2 row does NOT match a day-1 query (no fail-open coalesce)'
);

-- ============================================================================
-- 4. app.evidence idempotent insert (Repo#insertEvidenceIdempotent's own
--    ON CONFLICT (user_id, source, source_ref) DO NOTHING shape) — AT(3):
--    "a replayed evidence payload yields one row and one play."
-- ============================================================================
INSERT INTO app.evidence (user_id, device_id, source, source_ref, input_hash, facility_id, course_id, status, attestation_grade, catalog_version, summary, local_date)
VALUES ('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'self_report', 'p3c-test-ref-1', encode(digest('p3c-test-ref-1', 'sha256'), 'hex'), 'fac_x', 'crs_x1', 'accepted', 'unattestable', 1, '{}'::jsonb, current_date)
ON CONFLICT (user_id, source, source_ref) DO NOTHING;
SELECT is(
  (SELECT count(*)::int FROM app.evidence WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND source = 'self_report' AND source_ref = 'p3c-test-ref-1'),
  1,
  'first insert of a (user, source, source_ref) triple succeeds'
);
-- REPLAY: the exact same insert again.
INSERT INTO app.evidence (user_id, device_id, source, source_ref, input_hash, facility_id, course_id, status, attestation_grade, catalog_version, summary, local_date)
VALUES ('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'self_report', 'p3c-test-ref-1', encode(digest('p3c-test-ref-1', 'sha256'), 'hex'), 'fac_x', 'crs_x1', 'accepted', 'unattestable', 1, '{}'::jsonb, current_date)
ON CONFLICT (user_id, source, source_ref) DO NOTHING;
SELECT is(
  (SELECT count(*)::int FROM app.evidence WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND source = 'self_report' AND source_ref = 'p3c-test-ref-1'),
  1,
  'a REPLAYED insert of the SAME (user, source, source_ref) triple is a no-op -- exactly one row still exists (AT(3))'
);

-- ============================================================================
-- 5. app.play idempotent upsert (Repo#upsertPlayFromScore's own
--    ON CONFLICT (user_id, course_id, play_date) DO UPDATE shape).
-- ============================================================================
INSERT INTO app.play (user_id, course_id, facility_id, play_date, score_badge, score_monetary, hard_signal, presence_signal, money, held_review, policy_version, status)
VALUES ('00000000-0000-0000-0000-00000000000a', 'crs_x1', 'fac_x', '2026-06-02', 0.30, 0.00, false, false, false, false, '1', 'confirmed')
ON CONFLICT (user_id, course_id, play_date) DO UPDATE SET score_badge = excluded.score_badge;
SELECT is((SELECT count(*)::int FROM app.play WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND course_id = 'crs_x1' AND play_date = '2026-06-02'), 1, 'play upsert: first call inserts exactly one row');

INSERT INTO app.play (user_id, course_id, facility_id, play_date, score_badge, score_monetary, hard_signal, presence_signal, money, held_review, policy_version, status)
VALUES ('00000000-0000-0000-0000-00000000000a', 'crs_x1', 'fac_x', '2026-06-02', 0.50, 0.00, false, true, false, false, '1', 'confirmed')
ON CONFLICT (user_id, course_id, play_date) DO UPDATE SET score_badge = excluded.score_badge, presence_signal = excluded.presence_signal;
SELECT is((SELECT count(*)::int FROM app.play WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND course_id = 'crs_x1' AND play_date = '2026-06-02'), 1, 'play upsert: a REPLAY (same user/course/date) updates the SAME row, never inserts a second one');
SELECT is((SELECT score_badge FROM app.play WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND course_id = 'crs_x1' AND play_date = '2026-06-02'), 0.50, 'play upsert: the second call''s score wins (re-score folds in new evidence)');

-- ============================================================================
-- 6. Real PostGIS containment (Repo#matchFix's own ST_DWithin shape,
--    build plan §4.5 "inside the facility''s polygon + 50m"; §4.4's
--    catalog_course.boundary/GiST index -- NOT a stub, see derive-fix.ts's
--    own header comment).
-- ============================================================================
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('crs_geom1', 'course', 'verified', 1);
-- A ~200m x 200m square roughly centered on (-86.7816, 36.1467) (Nashville, TN --
-- an arbitrary real-world point, no significance beyond being valid lon/lat).
INSERT INTO app.catalog_course (id, facility_id, name, verification_status, geometry_kind, boundary, catalog_version)
VALUES (
  'crs_geom1', 'fac_x', 'Geometry Test Course', 'play-verified', 'polygon',
  ST_SetSRID(ST_MakePolygon(ST_MakeLine(ARRAY[
    ST_MakePoint(-86.7826, 36.1457),
    ST_MakePoint(-86.7806, 36.1457),
    ST_MakePoint(-86.7806, 36.1477),
    ST_MakePoint(-86.7826, 36.1477),
    ST_MakePoint(-86.7826, 36.1457)
  ])), 4326),
  1
);

SELECT is(
  (SELECT ST_DWithin(boundary::geography, ST_SetSRID(ST_MakePoint(-86.7816, 36.1467), 4326)::geography, 50) FROM app.catalog_course WHERE id = 'crs_geom1'),
  true,
  'matchFix: a point well inside the polygon is inside the +50m buffer'
);
SELECT is(
  (SELECT ST_DWithin(boundary::geography, ST_SetSRID(ST_MakePoint(-86.6000, 36.1467), 4326)::geography, 50) FROM app.catalog_course WHERE id = 'crs_geom1'),
  false,
  'matchFix: a point ~16km away is NOT inside the polygon + 50m buffer'
);

-- A radius-fallback course (listed-verified, no polygon): capped scoring
-- lives in packages/rules, but the CONTAINMENT check itself is exercised
-- here the same way.
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('crs_radius1', 'course', 'verified', 1);
INSERT INTO app.catalog_course (id, facility_id, name, verification_status, geometry_kind, radius_center, radius_m, catalog_version)
VALUES ('crs_radius1', 'fac_x', 'Radius Test Course', 'listed-verified', 'radius', ST_SetSRID(ST_MakePoint(-86.7816, 36.1467), 4326), 200, 1);

SELECT is(
  (SELECT ST_DWithin(radius_center::geography, ST_SetSRID(ST_MakePoint(-86.7816, 36.1467), 4326)::geography, coalesce(radius_m, 0) + 50) FROM app.catalog_course WHERE id = 'crs_radius1'),
  true,
  'matchFix: the radius center itself is inside its own radius + 50m buffer'
);
SELECT is(
  (SELECT ST_DWithin(radius_center::geography, ST_SetSRID(ST_MakePoint(-86.6000, 36.1467), 4326)::geography, coalesce(radius_m, 0) + 50) FROM app.catalog_course WHERE id = 'crs_radius1'),
  false,
  'matchFix: a point ~16km from the radius center is NOT inside radius + 50m'
);

SELECT * FROM finish();
ROLLBACK;
