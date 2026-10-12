-- 45_receipt_green_fee_evidence.sql
-- 0067_receipt_green_fee_evidence.sql: receipt_intake writes receipt_green_fee evidence.

\set QUIET 1
BEGIN;
SELECT plan(13);

GRANT edge_actor TO CURRENT_USER WITH SET TRUE;

-- ----------------------------------------------------------------------------
-- 1. Policy / grant shape
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM pg_policies
    WHERE schemaname = 'app' AND tablename = 'evidence' AND policyname = 'pd_receipt_evidence_insert'),
  1,
  'pd_receipt_evidence_insert exists on app.evidence'
);

SELECT is(
  has_column_privilege('private_definer', 'app.evidence', 'source', 'INSERT'),
  true,
  'private_definer may INSERT app.evidence.source (column grant + policy)'
);

SAVEPOINT s45_root;

-- ----------------------------------------------------------------------------
-- 2. Clean upload → one pending receipt_green_fee evidence row
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s45_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor(
    'fac_x', 'phash-rgf-clean-45a',
    'receipts/00000000-0000-0000-0000-00000000000a/rgf-a.jpg', NULL, NULL
  ) LIMIT 1),
  'ok',
  'clean intake still returns ok'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT e.source::text || '|' || e.status::text || '|' || (e.course_id IS NULL)::text || '|'
          || (e.summary->>'status') || '|' || (e.summary->>'fingerprint')
     FROM app.evidence e
    WHERE e.user_id = '00000000-0000-0000-0000-00000000000a'
      AND e.source = 'receipt_green_fee'
      AND e.source_ref = 'receipt:fac_x:phash-rgf-clean-45a'),
  'receipt_green_fee|accepted|true|pending|phash-rgf-clean-45a',
  'clean intake writes accepted facility-level evidence with summary.status=pending'
);

-- ----------------------------------------------------------------------------
-- 3. Same phash re-upload → purchases void; evidence stays the original pending (ON CONFLICT)
-- Actor binding from §2 is still live in this transaction (bind_actor is once per xact).
-- ----------------------------------------------------------------------------
SET LOCAL ROLE edge_actor;
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor(
    'fac_x', 'phash-rgf-clean-45a',
    'receipts/00000000-0000-0000-0000-00000000000a/rgf-a-dup.jpg', NULL, NULL
  ) LIMIT 1),
  'duplicate',
  'same-user re-upload is duplicate'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT count(*)::int FROM app.evidence e
    WHERE e.user_id = '00000000-0000-0000-0000-00000000000a'
      AND e.source = 'receipt_green_fee'
      AND e.source_ref = 'receipt:fac_x:phash-rgf-clean-45a'),
  1,
  're-upload does not insert a second evidence row'
);
SELECT is(
  (SELECT e.summary->>'status' FROM app.evidence e
    WHERE e.user_id = '00000000-0000-0000-0000-00000000000a'
      AND e.source_ref = 'receipt:fac_x:phash-rgf-clean-45a'),
  'pending',
  'original pending evidence survives same-user re-upload (ON CONFLICT DO NOTHING)'
);

-- ----------------------------------------------------------------------------
-- 4. Seeded fingerprint same-user (no prior evidence) → void + voidReason=duplicate
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s45_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor(
    'fac_x', 'phash1',
    'receipts/00000000-0000-0000-0000-00000000000a/seed-dup.jpg', NULL, NULL
  ) LIMIT 1),
  'duplicate',
  'seeded phash1 is same-user duplicate'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT e.summary->>'status' || '|' || coalesce(e.summary->>'voidReason', '')
     FROM app.evidence e
    WHERE e.user_id = '00000000-0000-0000-0000-00000000000a'
      AND e.source = 'receipt_green_fee'
      AND e.source_ref = 'receipt:fac_x:phash1'),
  'void|duplicate',
  'first evidence write on a same-user duplicate is void with voidReason=duplicate'
);

-- ----------------------------------------------------------------------------
-- 5. Cross-user → B gets pending evidence; review_item unchanged
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s45_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor(
    'fac_x', 'phash1',
    'receipts/00000000-0000-0000-0000-00000000000b/xu-rgf.jpg', NULL, NULL
  ) LIMIT 1),
  'review',
  'cross-user match is still review'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT e.summary->>'status' FROM app.evidence e
    WHERE e.user_id = '00000000-0000-0000-0000-00000000000b'
      AND e.source = 'receipt_green_fee'
      AND e.source_ref = 'receipt:fac_x:phash1'),
  'pending',
  'cross-user intake writes pending evidence for the new uploader (not auto-voided)'
);

-- ----------------------------------------------------------------------------
-- 6. Refusal paths write no evidence
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s45_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor('fac_nope', 'phash-nf-45', 'receipts/a/nope.jpg', NULL, NULL) LIMIT 1),
  'no_facility',
  'unknown facility is still no_facility'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT count(*)::int FROM app.evidence e
    WHERE e.source = 'receipt_green_fee' AND e.source_ref LIKE 'receipt:fac_nope:%'),
  0,
  'no_facility writes no receipt_green_fee evidence'
);

SELECT finish();
ROLLBACK;
