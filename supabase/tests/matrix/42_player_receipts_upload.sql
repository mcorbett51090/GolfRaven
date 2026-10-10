-- 42_player_receipts_upload.sql
-- 0064_player_receipts_upload.sql: player-lane receipt intake + dedupe policies.

\set QUIET 1
BEGIN;
SELECT plan(13);

GRANT edge_actor TO CURRENT_USER WITH SET TRUE;

-- ----------------------------------------------------------------------------
-- 1. EXECUTE matrix
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('edge_actor'), ('edge_partner'), ('edge_system'), ('service_role')) r(n)
   WHERE has_function_privilege(r.n, 'private.receipt_intake_for_actor(text, text, text, date, text)', 'EXECUTE')),
  ARRAY['edge_actor'],
  'only edge_actor may EXECUTE receipt_intake_for_actor (among edge roles; owner private_definer holds EXECUTE by ownership)'
);

SELECT is(
  has_function_privilege('edge_actor', 'app.dedupe_receipt_fingerprint(uuid, uuid, text, text, date, text)', 'EXECUTE'),
  false,
  'edge_actor must not EXECUTE app.dedupe_receipt_fingerprint directly'
);

SELECT is(
  has_function_privilege('private_definer', 'app.dedupe_receipt_fingerprint(uuid, uuid, text, text, date, text)', 'EXECUTE'),
  true,
  'private_definer may EXECUTE app.dedupe_receipt_fingerprint (invoked from receipt_intake)'
);

SAVEPOINT s42_root;

-- ----------------------------------------------------------------------------
-- 2. Happy path (player A, new phash)
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s42_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor('fac_x', 'phash-rcpt-new-42a', 'receipts/00000000-0000-0000-0000-00000000000a/obj-a.jpg', NULL, NULL) LIMIT 1),
  'ok',
  'player A: clean phash intake is ok'
);
SELECT is(
  (SELECT o_dedupe FROM private.receipt_intake_for_actor('fac_x', 'phash-rcpt-new-42b', 'receipts/00000000-0000-0000-0000-00000000000a/obj-b.jpg', NULL, NULL) LIMIT 1),
  'clean',
  'o_dedupe is clean on first insert'
);
SELECT is(
  (SELECT o_purchase_status FROM private.receipt_intake_for_actor('fac_x', 'phash-rcpt-new-42c', 'receipts/00000000-0000-0000-0000-00000000000a/obj-c.jpg', NULL, NULL) LIMIT 1),
  'pending',
  'purchase stays pending when clean'
);

-- ----------------------------------------------------------------------------
-- 3. Same-user duplicate (helpers seed phash1 for player A)
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s42_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor('fac_x', 'phash1', 'receipts/00000000-0000-0000-0000-00000000000a/dup-a.jpg', NULL, NULL) LIMIT 1),
  'duplicate',
  'player A: matching phash1 is duplicate (same user)'
);
SELECT is(
  (SELECT o_purchase_status FROM private.receipt_intake_for_actor('fac_x', 'phash1', 'receipts/00000000-0000-0000-0000-00000000000a/dup-a.jpg', NULL, NULL) LIMIT 1),
  'void',
  'duplicate voids the new purchase'
);

-- ----------------------------------------------------------------------------
-- 4. Cross-user match (player B, phash1)
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s42_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000b'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor('fac_x', 'phash1', 'receipts/00000000-0000-0000-0000-00000000000b/xu.jpg', NULL, NULL) LIMIT 1),
  'review',
  'player B: phash1 match is review (cross user)'
);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT count(*)::int FROM app.review_item ri WHERE ri.kind = 'receipt_cross_user_match' AND ri.subject_id = (
    SELECT pe.id FROM app.purchase_evidence pe
    WHERE pe.user_id = '00000000-0000-0000-0000-00000000000b' AND pe.method = 'receipt'
    ORDER BY pe.created_at DESC LIMIT 1
  )),
  1,
  'cross-user intake opens a receipt_cross_user_match review_item'
);

-- ----------------------------------------------------------------------------
-- 5. Review account (body carries the 0051 refusal; behavioural cell is 29d_review_gate_open_edge.sql)
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM pg_proc p WHERE p.oid = 'private.receipt_intake_for_actor(text, text, text, date, text)'::regprocedure AND p.prosrc LIKE '%review_account%'),
  1,
  'receipt_intake_for_actor returns review_account for the demo account (0051 pattern)'
);

-- ----------------------------------------------------------------------------
-- 6. No facility
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s42_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor('fac_nope', 'phash-nf', 'receipts/a/nope.jpg', NULL, NULL) LIMIT 1),
  'no_facility',
  'unknown facility is no_facility'
);

-- ----------------------------------------------------------------------------
-- 7. Bad args
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s42_root;
SET LOCAL ROLE edge_actor;
SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a'::uuid);
SELECT is(
  (SELECT o_status FROM private.receipt_intake_for_actor('', 'phash', 'obj', NULL, NULL) LIMIT 1),
  'bad_args',
  'empty facility is bad_args'
);

SELECT finish();
ROLLBACK;
