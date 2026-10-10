-- 46_receipt_cosignal_promote.sql
-- 0068_receipt_cosignal_promote.sql: cosignal attach promotes receipt_green_fee to approved.

\set QUIET 1
BEGIN;
SELECT plan(10);

GRANT edge_actor TO CURRENT_USER WITH SET TRUE;

-- Qualifying AppFix shape (mirrors matrix 24 / scan-handler derived fix).
CREATE FUNCTION pg_temp.qfix(p_fix text, p_fac text, p_grade text, p_at timestamptz, p_ld date) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $f$
  SELECT jsonb_build_object(
    'fixId', p_fix, 'facilityId', p_fac, 'fromApp', true, 'simulated', false, 'foreground', true,
    'challenge', 'live', 'token', jsonb_build_object('present', true, 'grade', p_grade),
    'verificationTier', 'play-verified', 'geometryKind', 'polygon', 'insideBuffer', true,
    'accuracyMeters', 10, 'capturedAt', (extract(epoch FROM p_at) * 1000)::bigint, 'localDate', p_ld::text
  )
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.qfix(text, text, text, timestamptz, date) TO PUBLIC;

CREATE FUNCTION pg_temp.seed_fix(p_fix text, p_u uuid, p_fac text, p_grade text, p_at timestamptz)
RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE v_ld date; v_id uuid;
BEGIN
  v_ld := (p_at AT TIME ZONE (SELECT f.tz FROM app.catalog_facility f WHERE f.id = p_fac))::date;
  v_id := md5('ev46-' || p_fix)::uuid;
  INSERT INTO app.evidence (id, user_id, source, source_ref, facility_id, summary, attestation_grade, local_date, input_hash, status)
  VALUES (
    v_id, p_u, 'foreground_checkin', 'fix:' || p_fix, p_fac,
    jsonb_build_object('localDate', v_ld::text, 'fix', pg_temp.qfix(p_fix, p_fac, p_grade, p_at, v_ld)),
    p_grade::app.attestation_grade, v_ld, 'h46-' || p_fix, 'accepted'
  );
  RETURN v_id;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.seed_fix(text, uuid, text, text, timestamptz) TO PUBLIC;

-- ----------------------------------------------------------------------------
-- 1. Policy shape
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM pg_policies
    WHERE schemaname = 'app' AND tablename = 'evidence' AND policyname = 'pd_receipt_evidence_update'),
  1,
  'pd_receipt_evidence_update exists'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policies
    WHERE schemaname = 'app' AND tablename = 'review_item' AND policyname = 'pd_receipt_review_select'),
  1,
  'pd_receipt_review_select exists'
);

SAVEPOINT s46_root;

-- ----------------------------------------------------------------------------
-- 2. Clean receipt + attested cosignal → evidence approved with coSignalFix
-- Seed the fix evidence first (service_role), then one edge_actor binding for intake+attach.
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s46_root;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT pg_temp.seed_fix('fix46a', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'attested', now()) AS ev46a \gset

SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor(
    'fac_x', 'phash-rgf-promote-46a',
    'receipts/00000000-0000-0000-0000-00000000000a/promote-a.jpg', NULL, NULL
  ) LIMIT 1),
  'ok',
  'clean receipt intake is ok'
);
SELECT is(
  (SELECT o_result || '/' || o_purchase_status FROM private.marker_cosignal_attach_for_actor(
    'fac_x', now(), 'attested', 'fix46a', :'ev46a'::uuid
  ) LIMIT 1),
  'attached/valid',
  'attested cosignal attaches the receipt purchase as valid'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT e.summary->>'status' || '|' || (e.summary ? 'coSignalFix')::text || '|' || (e.summary->'coSignalFix'->>'fixId')
     FROM app.evidence e
    WHERE e.user_id = '00000000-0000-0000-0000-00000000000a'
      AND e.source = 'receipt_green_fee'
      AND e.source_ref = 'receipt:fac_x:phash-rgf-promote-46a'),
  'approved|true|fix46a',
  'evidence promoted to approved with coSignalFix from the cosignal fix'
);

-- ----------------------------------------------------------------------------
-- 3. Unattestable cosignal → held_review purchase; evidence stays pending
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s46_root;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT pg_temp.seed_fix('fix46b', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'unattestable', now()) AS ev46b \gset

SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT private.receipt_intake_for_actor(
  'fac_x', 'phash-rgf-held-46b',
  'receipts/00000000-0000-0000-0000-00000000000a/held-b.jpg', NULL, NULL
);
SELECT is(
  (SELECT o_purchase_status FROM private.marker_cosignal_attach_for_actor(
    'fac_x', now(), 'unattestable', 'fix46b', :'ev46b'::uuid
  ) LIMIT 1),
  'held_review',
  'unattestable cosignal holds the purchase'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT e.summary->>'status' FROM app.evidence e
    WHERE e.source_ref = 'receipt:fac_x:phash-rgf-held-46b'),
  'pending',
  'unattestable path does not promote evidence'
);

-- ----------------------------------------------------------------------------
-- 4. Cross-user open review blocks promotion
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s46_root;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT pg_temp.seed_fix('fix46c', '00000000-0000-0000-0000-00000000000b', 'fac_x', 'attested', now()) AS ev46c \gset

SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor(
    'fac_x', 'phash1',
    'receipts/00000000-0000-0000-0000-00000000000b/xu-promote.jpg', NULL, NULL
  ) LIMIT 1),
  'review',
  'cross-user intake is review'
);
SELECT is(
  (SELECT o_result || '/' || o_purchase_status FROM private.marker_cosignal_attach_for_actor(
    'fac_x', now(), 'attested', 'fix46c', :'ev46c'::uuid
  ) LIMIT 1),
  'attached/valid',
  'cross-user purchase can still become valid via cosignal'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT e.summary->>'status' FROM app.evidence e
    WHERE e.user_id = '00000000-0000-0000-0000-00000000000b'
      AND e.source_ref = 'receipt:fac_x:phash1'),
  'pending',
  'open receipt_cross_user_match blocks evidence promotion'
);

SELECT finish();
ROLLBACK;
