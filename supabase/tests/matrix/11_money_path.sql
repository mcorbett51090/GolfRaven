-- 11_money_path.sql
-- Money-path security review queue (0017_money_path_hardening.sql).
-- Runs as service_role throughout (SET LOCAL ROLE via authenticate_as):
-- every assertion here is about a CHECK/trigger/function's OWN
-- enforcement, which fires regardless of caller role/RLS, not about an
-- RLS authorization boundary — matching 07_rate_limit.sql/
-- 09_delete_my_data.sql's own reasoning for the same choice.

BEGIN;
SELECT plan(159);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- Fixture ids reused from supabase/tests/helpers.sql:
--   player A = 00000000-0000-0000-0000-00000000000a
--   player B = 00000000-0000-0000-0000-00000000000b
--   device (A) = 20000000-0000-0000-0000-000000000001
--   evidence (A) = 30000000-0000-0000-0000-000000000001
--   play (A) = 40000000-0000-0000-0000-000000000001
--   offer #1 (trl_t/fac_x, budget_cap=100) = 60000000-0000-0000-0000-000000000001
--   offer_code #1 (A, offer #1, earned) = 70000000-0000-0000-0000-000000000001
--   purchase_evidence (A) = 90000000-0000-0000-0000-000000000001
--   receipt_fingerprint (A, phash='phash1', fac_x) = 80000000-0000-0000-0000-000000000001

-- ---------------------------------------------------------------------------
-- 1. play_evidence: UNIQUE(evidence_id) + play.user_id = evidence.user_id.
-- ---------------------------------------------------------------------------
-- helpers.sql already seeds (play 40000000-...-1, evidence 30000000-...-1)
-- for player A, so a NEW evidence row is used here to isolate each
-- assertion cleanly rather than colliding with that existing pair.
SELECT lives_ok(
  $$INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version, local_date)
    VALUES ('32000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'self_report', 'money-path-seed-a2', 'accepted', 1, current_date)$$,
  'setup: a second evidence row owned by player A'
);
SELECT lives_ok(
  $$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES
    ('40000000-0000-0000-0000-000000000001', '32000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a')$$,
  'play_evidence: evidence backing its OWN owner''s play succeeds'
);

-- A SECOND play for player A (same owner, so the UNIQUE(evidence_id)
-- violation below is isolated from the user-match trigger -- both plays
-- are player A's own).
SELECT lives_ok(
  $$INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status)
    VALUES ('42000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a',
            'crs_x1', 'fac_x', current_date - 1, 'v1', 'confirmed')$$,
  'setup: a second play row, also for player A'
);
SELECT throws_ok(
  $$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES
    ('42000000-0000-0000-0000-000000000099', '32000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a')$$,
  '23505',
  NULL,
  'play_evidence: the SAME evidence_id cannot back a second play, even the SAME owner''s own second play (UNIQUE(evidence_id))'
);

-- A second play for player B (used by the user-match assertions below).
SELECT lives_ok(
  $$INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status)
    VALUES ('41000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000b',
            'crs_x1', 'fac_x', current_date - 1, 'v1', 'confirmed')$$,
  'setup: a play row for player B'
);

-- A play for player B, evidence for player A: ownership mismatch.
SELECT lives_ok(
  $$INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version, local_date)
    VALUES ('31000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000b',
            NULL, 'self_report', 'money-path-seed-b', 'accepted', 1, current_date)$$,
  'setup: an evidence row owned by player B'
);
-- A THIRD evidence row for player A, not yet linked to anything (30000000-
-- ...-1 and 32000000-...-99 are both already linked by this point, which
-- would trip the UNIQUE(evidence_id) constraint first and mask the FK
-- violation these two tests are isolating).
SELECT lives_ok(
  $$INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version, local_date)
    VALUES ('33000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'self_report', 'money-path-seed-a3', 'accepted', 1, current_date)$$,
  'setup: a THIRD evidence row owned by player A, not yet linked'
);

-- Both play_evidence composite FKs are DEFERRABLE INITIALLY DEFERRED
-- (matching every other app-internal FK, 0014 §3 / 0017), so a violating
-- INSERT/UPDATE would not raise until COMMIT by default -- which this
-- test file's outer transaction never reaches (it ROLLBACKs). Switching
-- JUST these two constraints to IMMEDIATE checking (not ALL constraints,
-- so delete_my_data's OWN reliance on deferred checking elsewhere in
-- this same file, H1's test below, is unaffected) makes every violation
-- from here on raise at the statement itself, where throws_ok can see it.
-- SET CONSTRAINTS needs the constraint names SCHEMA-QUALIFIED here
-- (confirmed empirically this session: the bare names, though correct
-- and visible in pg_constraint, raised "constraint ... does not exist" —
-- `app` is not on this session's search_path).
SELECT lives_ok(
  $$SET CONSTRAINTS app.play_evidence_play_user_fk, app.play_evidence_evidence_user_fk IMMEDIATE$$,
  'setup: check the play_evidence composite FKs immediately for the M1 tests below'
);

-- ⛔ FIX (M1, post-P3a gate): the OLD plpgsql trigger silently PASSED this
-- exact case when the trigger's own two independent SELECTs raced a
-- deferred-FK-ordering NULL lookup (both sides NULL -> `IS DISTINCT FROM`
-- is false) — confirmed empirically this session by reproducing it
-- against the pre-fix code. The composite-FK design has no such gap: a
-- caller building this row has to pick SOME user_id, and whichever parent
-- it does NOT match rejects it outright as a plain foreign-key violation
-- (23503), deferred-FK ordering or not, because MATCH SIMPLE's NULL
-- exemption only applies when one of THIS row's own key columns is NULL
-- — none of play_evidence's are.
SELECT throws_ok(
  $$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES
    ('41000000-0000-0000-0000-000000000099', '33000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000b')$$,
  '23503',
  NULL,
  'play_evidence: player B''s play cannot be backed by player A''s evidence (composite FK to app.evidence(id,user_id) rejects it)'
);
SELECT throws_ok(
  $$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES
    ('40000000-0000-0000-0000-000000000001', '31000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a')$$,
  '23503',
  NULL,
  'play_evidence: player A''s play cannot be backed by player B''s evidence (composite FK to app.evidence(id,user_id) rejects it, reverse direction)'
);

-- M1 bypass 2 (post-P3a gate): re-owning AFTER a valid link exists. The
-- old trigger only checked ownership at LINK TIME — nothing stopped
-- play.user_id being changed afterward, silently detaching the pair
-- without ever re-checking (confirmed as the second named bypass). The
-- composite FK blocks the re-own AT THE SOURCE: play_evidence (play A,
-- evidence2 A) from test 2 above still references app.play(id=play A,
-- user_id=A); changing play.user_id now hits the FK's default ON UPDATE
-- NO ACTION.
SELECT throws_ok(
  $$UPDATE app.play SET user_id = '00000000-0000-0000-0000-00000000000b' WHERE id = '40000000-0000-0000-0000-000000000001'$$,
  '23503',
  NULL,
  'play_evidence: re-owning a play that still has a linked play_evidence row is rejected (composite FK ON UPDATE)'
);
SELECT throws_ok(
  $$UPDATE app.evidence SET user_id = '00000000-0000-0000-0000-00000000000b' WHERE id = '32000000-0000-0000-0000-000000000099'$$,
  '23503',
  NULL,
  'play_evidence: re-owning evidence that still has a linked play_evidence row is rejected (composite FK ON UPDATE)'
);

-- ---------------------------------------------------------------------------
-- 2. evidence.attestation_grade: typed column, NOT NULL, defaults to
--    'unattestable', accepts every app.attestation_grade value.
-- ---------------------------------------------------------------------------
SELECT is(
  (SELECT attestation_grade::text FROM app.evidence WHERE id = '30000000-0000-0000-0000-000000000001'),
  'unattestable',
  'evidence.attestation_grade defaults to ''unattestable'''
);
SELECT lives_ok(
  $$UPDATE app.evidence SET attestation_grade = 'attested' WHERE id = '30000000-0000-0000-0000-000000000001'$$,
  'evidence.attestation_grade accepts a real app.attestation_grade value'
);
SELECT throws_ok(
  $$UPDATE app.evidence SET attestation_grade = NULL WHERE id = '30000000-0000-0000-0000-000000000001'$$,
  '23502',
  NULL,
  'evidence.attestation_grade is NOT NULL'
);

-- ---------------------------------------------------------------------------
-- 3. Scorer decision columns exist (play/offer_code/entitlement).
-- ---------------------------------------------------------------------------
SELECT has_column('app', 'play', 'money', 'app.play.money exists');
SELECT has_column('app', 'play', 'held_review', 'app.play.held_review exists');
SELECT has_column('app', 'play', 'hard_signal_reason', 'app.play.hard_signal_reason exists (see 0017''s flagged naming note re: existing hard_signal boolean)');
SELECT has_column('app', 'play', 'input_digest', 'app.play.input_digest exists');
SELECT has_column('app', 'offer_code', 'play_id', 'app.offer_code.play_id exists');
SELECT has_column('app', 'offer_code', 'policy_version', 'app.offer_code.policy_version exists');
SELECT has_column('app', 'offer_code', 'basis', 'app.offer_code.basis exists');
SELECT has_column('app', 'entitlement', 'play_id', 'app.entitlement.play_id exists');
SELECT has_column('app', 'entitlement', 'policy_version', 'app.entitlement.policy_version exists');
SELECT has_column('app', 'purchase_evidence', 'void_reason', 'app.purchase_evidence.void_reason exists (post-P3a re-gate: cross-user receipt-dedupe griefing fix)');

-- ---------------------------------------------------------------------------
-- 4. Offer budgets: CHECK, max_redemptions, locked reserve function.
-- ---------------------------------------------------------------------------
SELECT throws_ok(
  $$UPDATE app.offer SET budget_used = 60, budget_reserved = 45 WHERE id = '60000000-0000-0000-0000-000000000001'$$,
  '23514',
  NULL,
  'app.offer rejects budget_used + budget_reserved > budget_cap (CHECK)'
);

SELECT lives_ok(
  $$UPDATE app.offer SET max_redemptions = 1 WHERE id = '60000000-0000-0000-0000-000000000001'$$,
  'setup: offer #1 capped at max_redemptions = 1 (offer_code #1 already counts as its one redemption)'
);
SELECT throws_ok(
  $$INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state)
    VALUES ('71000000-0000-0000-0000-000000000099', '60000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-00000000000b', 'fac_x', 'earned')$$,
  '23514',
  NULL,
  'app.offer_code rejects a redemption once the offer''s max_redemptions is reached'
);

SELECT is(
  app.reserve_offer_budget('60000000-0000-0000-0000-000000000001'::uuid, 10),
  true,
  'reserve_offer_budget succeeds when the reservation fits under budget_cap'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '60000000-0000-0000-0000-000000000001'),
  10::numeric,
  'reserve_offer_budget actually incremented budget_reserved'
);
SELECT is(
  app.reserve_offer_budget('60000000-0000-0000-0000-000000000001'::uuid, 1000),
  false,
  'reserve_offer_budget returns false (not an exception) when the reservation would exceed budget_cap, and leaves budget_reserved unchanged'
);
SELECT is(
  (SELECT budget_reserved FROM app.offer WHERE id = '60000000-0000-0000-0000-000000000001'),
  10::numeric,
  'a rejected reserve_offer_budget call left budget_reserved unchanged'
);

-- ---------------------------------------------------------------------------
-- 5. Receipt dedupe: partial unique index + serialized dedupe function.
-- ---------------------------------------------------------------------------
SELECT lives_ok(
  $$INSERT INTO app.receipt_fingerprint (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date)
    VALUES (NULL, '00000000-0000-0000-0000-00000000000b', 'phash-dupe-ocr', 'OCR-DUPE-1', 'fac_x', current_date)$$,
  'setup: seed one receipt_fingerprint row with a real OCR number'
);
SELECT throws_ok(
  $$INSERT INTO app.receipt_fingerprint (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date)
    VALUES (NULL, '00000000-0000-0000-0000-00000000000b', 'phash-dupe-ocr-2', 'OCR-DUPE-1', 'fac_x', current_date)$$,
  '23505',
  NULL,
  'receipt_fingerprint: the same (receipt_number_ocr, facility_id) cannot repeat (partial unique index)'
);
SELECT lives_ok(
  $$INSERT INTO app.receipt_fingerprint (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date)
    VALUES (NULL, '00000000-0000-0000-0000-00000000000b', 'phash-null-ocr-a', NULL, 'fac_x', current_date)$$,
  'setup: a receipt_fingerprint row with a NULL receipt_number_ocr'
);
SELECT lives_ok(
  $$INSERT INTO app.receipt_fingerprint (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date)
    VALUES (NULL, '00000000-0000-0000-0000-00000000000b', 'phash-null-ocr-b', NULL, 'fac_x', current_date)$$,
  'receipt_fingerprint: a SECOND NULL receipt_number_ocr row does NOT collide with the first (partial index excludes NULL)'
);

SELECT lives_ok(
  $$INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
    VALUES ('91000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000b',
            'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')$$,
  'setup: a second purchase_evidence row (player B) to dedupe against player A''s seeded phash1'
);
-- ⛔ FIX (post-P3a re-gate, cross-user receipt griefing): this is a
-- CROSS-USER match (player B''s new purchase vs player A''s seeded
-- phash1, helpers.sql) -- must NOT auto-void either side any more (that
-- was the griefing vector: whoever submits first, across two DIFFERENT
-- people, used to void the other's legitimate upload). Instead: a
-- review_item + a receipt_cross_user_match fraud_signal, both purchases
-- left pending.
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000099'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash1', 'fac_x', current_date
  ),
  false,
  'dedupe_receipt_fingerprint returns false for a CROSS-USER phash match (helpers.sql seeds phash1 for player A''s purchase 90000000-...-1, this call is player B''s)'
);
SELECT is(
  (SELECT status::text FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000099'),
  'pending',
  'CROSS-USER match: the NEW (player B) purchase is left pending, NOT voided'
);
-- should-fix (post-P3a re-gate): the EARLIER purchase's status is left
-- ALONE once it's already 'valid' — demoting an already-accepted purchase
-- just because a LATER, different user's submission collided with it is
-- its own griefing shape; it stays referenced via matched_purchase_
-- evidence_id in the review_item/fraud_signal instead (asserted below).
SELECT is(
  (SELECT status::text FROM app.purchase_evidence WHERE id = '90000000-0000-0000-0000-000000000001'),
  'valid',
  'CROSS-USER match: the EXISTING, already-VALID (player A) purchase is left alone, not demoted to pending'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'receipt_cross_user_match' AND user_id = '00000000-0000-0000-0000-00000000000b'),
  1,
  'a cross-user phash match writes exactly one fraud_signal row (kind=receipt_cross_user_match)'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'receipt_phash_duplicate' AND user_id = '00000000-0000-0000-0000-00000000000b'),
  0,
  'a cross-user match does NOT write a receipt_phash_duplicate fraud_signal (that kind is same-user only)'
);
SELECT is(
  (SELECT count(*)::int FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id = '91000000-0000-0000-0000-000000000099'),
  1,
  'a cross-user phash match opens exactly one review_item (kind=receipt_cross_user_match)'
);
-- ⛔ FIX (M2, post-P3a re-gate): this used to assert detail->>'matched_
-- user_id' equals player A's raw uuid — exactly the leak M2 closes.
-- matched_receipt_fingerprint_id (asserted above) is what a reviewer
-- follows to find the OTHER party now; no user uuid is ever embedded.
SELECT is(
  (SELECT detail ? 'user_id' OR detail ? 'matched_user_id' FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id = '91000000-0000-0000-0000-000000000099'),
  false,
  'the review_item''s detail does NOT embed either party''s raw user uuid (M2 fix)'
);
-- marker_credit b0000000-...-1 (helpers.sql) backs player A's purchase
-- 90000000-...-1 and is already 'credited' (terminal) -- a cross-user
-- match must not touch it at all (it isn't even in the same-user
-- duplicate branch that does any marker_credit detaching).
SELECT is(
  (SELECT purchase_evidence_id FROM app.marker_credit WHERE id = 'b0000000-0000-0000-0000-000000000001'),
  '90000000-0000-0000-0000-000000000001'::uuid,
  'a cross-user match leaves an already-credited marker_credit''s purchase_evidence_id untouched'
);
-- Restore player A's purchase to 'valid' (this test file reuses
-- 90000000-...-1's fingerprint identity in the H1 data test further down,
-- and 'pending' is this SPECIFIC test's own transient assertion, not a
-- state later sections should have to account for).
SELECT lives_ok(
  $$UPDATE app.purchase_evidence SET status = 'valid' WHERE id = '90000000-0000-0000-0000-000000000001'$$,
  'cleanup: restore player A''s purchase_evidence to valid after the cross-user test above'
);

-- SAME-USER match (a genuine retry/duplicate submission): still
-- auto-voids the NEWER one, now tagged void_reason='duplicate', and (M2-
-- style belt-and-suspenders) detaches any non-terminal marker_credit.
SELECT lives_ok(
  $$INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
    VALUES ('91000000-0000-0000-0000-000000000096', '00000000-0000-0000-0000-00000000000b',
            'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')$$,
  'setup: a SECOND purchase_evidence row for player B (same user as the one seeded above), for the same-user dedupe test'
);
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000096'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash-same-user-dupe', 'fac_x', current_date
  ),
  true,
  'setup: first submission of phash-same-user-dupe (player B) records cleanly'
);
SELECT lives_ok(
  $$INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
    VALUES ('91000000-0000-0000-0000-000000000095', '00000000-0000-0000-0000-00000000000b',
            'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')$$,
  'setup: a THIRD purchase_evidence row for player B, the same-user RETRY of the same receipt'
);
SELECT lives_ok(
  $$INSERT INTO app.marker_credit (id, user_id, trail_id, facility_id, purchase_evidence_id, status)
    VALUES ('b0000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000b',
            'trl_t', 'fac_x', '91000000-0000-0000-0000-000000000095', 'pending')$$,
  'setup: a PENDING (non-terminal) marker_credit backing the retry purchase, to prove it gets detached'
);
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000095'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash-same-user-dupe', 'fac_x', current_date
  ),
  false,
  'SAME-USER match: the retry submission is rejected (auto-voided), unlike the cross-user case above'
);
SELECT is(
  (SELECT status::text FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000095'),
  'void',
  'SAME-USER match: the retry purchase IS voided'
);
SELECT is(
  (SELECT void_reason::text FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000095'),
  'duplicate',
  'SAME-USER match: void_reason is ''duplicate'' (not NULL/''reviewer'', not ''fraud'')'
);
SELECT is(
  (SELECT purchase_evidence_id FROM app.marker_credit WHERE id = 'b0000000-0000-0000-0000-000000000099'),
  NULL,
  'SAME-USER match: the non-terminal (pending) marker_credit backing the voided retry is detached (purchase_evidence_id nulled)'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'receipt_phash_duplicate' AND user_id = '00000000-0000-0000-0000-00000000000b'),
  1,
  'SAME-USER match: exactly one receipt_phash_duplicate fraud_signal (the same-user kind, not the cross-user one)'
);
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000099'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash-genuinely-new', 'fac_x', current_date
  ),
  true,
  'dedupe_receipt_fingerprint returns true (and records the fingerprint) for a genuinely new phash'
);

-- M4 fix 4 (post-P3a gate): p_user_id checked against the purchase
-- evidence's OWN user_id.
SELECT throws_ok(
  $$SELECT app.dedupe_receipt_fingerprint(
      '91000000-0000-0000-0000-000000000099'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid,
      'phash-mismatched-caller', 'fac_x', current_date
    )$$,
  NULL,
  NULL,
  'dedupe_receipt_fingerprint rejects a p_user_id that does not match the purchase_evidence row''s own user_id (91000000-...-99 belongs to player B, not A)'
);

-- M4 fix 2 (post-P3a gate): UNIQUE(purchase_evidence_id) makes a retry
-- idempotent -- the SAME call twice must not error the second time, and
-- must not mint a second fingerprint row.
SELECT lives_ok(
  $$INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
    VALUES ('91000000-0000-0000-0000-000000000098', '00000000-0000-0000-0000-00000000000b',
            'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')$$,
  'setup: a third purchase_evidence row (player B), for the idempotent-retry test'
);
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000098'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash-retry-me', 'fac_x', current_date
  ),
  true,
  'dedupe_receipt_fingerprint (retry test): first call succeeds'
);
SELECT lives_ok(
  $$SELECT app.dedupe_receipt_fingerprint(
      '91000000-0000-0000-0000-000000000098'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
      'phash-retry-me', 'fac_x', current_date
    )$$,
  'dedupe_receipt_fingerprint (retry test): a SECOND call with the SAME purchase_evidence_id/phash does not error (UNIQUE(purchase_evidence_id) + ON CONFLICT DO NOTHING makes the retry idempotent)'
);
SELECT is(
  (SELECT count(*)::int FROM app.receipt_fingerprint WHERE purchase_evidence_id = '91000000-0000-0000-0000-000000000098'),
  1,
  'dedupe_receipt_fingerprint (retry test): exactly one fingerprint row exists after the retry, not two'
);

-- M4 fix 3 (post-P3a gate): an OCR-index collision is handled (void +
-- fraud_signal) like a phash duplicate, not surfaced as a raw 23505.
SELECT lives_ok(
  $$INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
    VALUES ('91000000-0000-0000-0000-000000000097', '00000000-0000-0000-0000-00000000000b',
            'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')$$,
  'setup: a fourth purchase_evidence row (player B), for the OCR-collision test'
);
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000097'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash-ocr-collision-test', 'fac_x', current_date, 'OCR-DUPE-1'
  ),
  false,
  'dedupe_receipt_fingerprint returns false (not a 23505 exception) on an OCR-index collision (OCR-DUPE-1 already claimed above by a different purchase)'
);
SELECT is(
  (SELECT status::text FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000097'),
  'void',
  'an OCR-duplicate purchase is voided by dedupe_receipt_fingerprint, same as a phash duplicate'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'receipt_ocr_duplicate' AND user_id = '00000000-0000-0000-0000-00000000000b'),
  1,
  'an OCR-duplicate purchase writes exactly one fraud_signal row (kind=receipt_ocr_duplicate)'
);
SELECT is(
  (SELECT void_reason::text FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000097'),
  'duplicate',
  'SAME-USER OCR match: void_reason is ''duplicate'''
);

-- ⛔ FIX (post-P3a re-gate, correction): a CROSS-USER OCR collision is the
-- SAME griefing vector as a cross-user phash match -- if two users
-- photograph the SAME physical receipt, the printed OCR number matches
-- too, not just the phash. Must NOT auto-void either side.
SELECT lives_ok(
  $$INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
    VALUES ('91000000-0000-0000-0000-000000000094', '00000000-0000-0000-0000-00000000000a',
            'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid')$$,
  'setup: a purchase_evidence row for player A, for the CROSS-USER OCR-collision test'
);
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000094'::uuid, '00000000-0000-0000-0000-00000000000a'::uuid,
    'phash-ocr-collision-cross-user', 'fac_x', current_date, 'OCR-DUPE-1'
  ),
  false,
  'CROSS-USER OCR match: dedupe_receipt_fingerprint returns false (OCR-DUPE-1 belongs to player B, this call is player A)'
);
SELECT is(
  (SELECT status::text FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000094'),
  'pending',
  'CROSS-USER OCR match: the NEW (player A) purchase is left pending, NOT voided'
);
SELECT is(
  (SELECT void_reason FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000094'),
  NULL,
  'CROSS-USER OCR match: void_reason stays NULL (never voided at all)'
);
SELECT is(
  (SELECT count(*)::int FROM app.review_item WHERE kind = 'receipt_cross_user_match' AND subject_id = '91000000-0000-0000-0000-000000000094' AND detail->>'match_basis' = 'receipt_number_ocr'),
  1,
  'CROSS-USER OCR match: exactly one review_item opened, tagged match_basis=receipt_number_ocr'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'receipt_cross_user_match' AND user_id = '00000000-0000-0000-0000-00000000000a' AND detail->>'match_basis' = 'receipt_number_ocr'),
  1,
  'CROSS-USER OCR match: exactly one receipt_cross_user_match fraud_signal, tagged match_basis=receipt_number_ocr'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'receipt_ocr_duplicate' AND user_id = '00000000-0000-0000-0000-00000000000a'),
  0,
  'CROSS-USER OCR match: does NOT write a receipt_ocr_duplicate (same-user-only) fraud_signal'
);

-- ---------------------------------------------------------------------------
-- 6. Nonce uniqueness: checkin_challenge.nonce_hash (global) +
--    used_at one-way transition.
-- ---------------------------------------------------------------------------
SELECT lives_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at, kind)
    VALUES ('a1000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-1', now() + interval '5 minutes', 'live')$$,
  'setup: seed one checkin_challenge row'
);
-- The consumed-nonce tombstone trigger (should-fix, added below) fires
-- BEFORE the table's own UNIQUE constraint is even reached, so a repeat
-- insert of an already-consumed nonce now raises 23514 (tombstoned), not
-- 23505 -- this still proves the same thing (global uniqueness, not
-- per-user), just via the stricter of the two mechanisms.
SELECT throws_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at, kind)
    VALUES ('a1000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-1', now() + interval '5 minutes', 'live')$$,
  '23514',
  NULL,
  'checkin_challenge.nonce_hash is globally unique across users (tombstone ledger + the table''s own UNIQUE both agree, not per-user)'
);
SELECT lives_ok(
  $$UPDATE app.checkin_challenge SET used_at = now() WHERE id = 'a1000000-0000-0000-0000-000000000001'$$,
  'checkin_challenge.used_at can be set once (NULL -> a timestamp)'
);
SELECT throws_ok(
  $$UPDATE app.checkin_challenge SET used_at = now() WHERE id = 'a1000000-0000-0000-0000-000000000001'$$,
  '23514',
  NULL,
  'checkin_challenge.used_at cannot be changed once set (replay-protection trigger)'
);

-- M4/should-fix: attestation.token_jti and checkin_challenge.nonce_hash
-- go through the SAME consumed-nonce tombstone ledger (private.
-- consumed_nonce) -- a DELETE then re-INSERT of the identical nonce/jti
-- must still be rejected, not just a plain duplicate while the original
-- row exists (which the table's own UNIQUE constraint already covered).
SELECT lives_ok(
  $$DELETE FROM app.checkin_challenge WHERE id = 'a1000000-0000-0000-0000-000000000001'$$,
  'setup: delete the checkin_challenge row seeded above (freeing its nonce_hash from the table''s own UNIQUE constraint)'
);
SELECT throws_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at, kind)
    VALUES ('a1000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-1', now() + interval '5 minutes', 'live')$$,
  '23514',
  NULL,
  'checkin_challenge: a DELETEd-then-re-INSERTed nonce_hash is still rejected by the consumed-nonce tombstone ledger, not just the table''s own UNIQUE constraint'
);

-- should-fix (post-P3a re-gate): nonce_hash/token_jti immutability closes
-- the UPDATE-revive gap the tombstone-on-INSERT triggers alone leave open
-- (an UPDATE changing an EXISTING row's nonce_hash/token_jti was never
-- checked against private.consumed_nonce at all). A DEDICATED, fresh row
-- -- id a1000000-...-003 does NOT exist at this point (its own earlier
-- INSERT attempt, above, was itself rejected/rolled back by the tombstone
-- ledger, so an UPDATE targeting it would silently match zero rows and
-- prove nothing).
SELECT lives_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at, kind)
    VALUES ('a1000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-immutable', now() + interval '5 minutes', 'live')$$,
  'setup: a fresh checkin_challenge row for the immutability test'
);
SELECT throws_ok(
  $$UPDATE app.checkin_challenge SET nonce_hash = 'nonce-money-path-immutable-revive-attempt' WHERE id = 'a1000000-0000-0000-0000-000000000004'$$,
  '23514',
  NULL,
  'checkin_challenge.nonce_hash is immutable after insert (UPDATE-revive gap closed)'
);
SELECT throws_ok(
  $$UPDATE app.attestation SET token_jti = 'jti-1-revive-attempt' WHERE id = 'a0000000-0000-0000-0000-000000000001'$$,
  '23514',
  NULL,
  'attestation.token_jti is immutable after insert (UPDATE-revive gap closed)'
);
-- A no-op UPDATE (new value IS NOT DISTINCT FROM old) must still succeed
-- -- the trigger checks for an actual CHANGE, not merely that the column
-- was named in the UPDATE's SET clause.
SELECT lives_ok(
  $$UPDATE app.checkin_challenge SET nonce_hash = nonce_hash WHERE id = 'a1000000-0000-0000-0000-000000000004'$$,
  'checkin_challenge.nonce_hash: a no-op UPDATE (same value) is allowed'
);

-- ⛔ FIX (should-fix, post-P3a re-gate: "consumed_nonce DELETE
-- regression"): service_role no longer has DELETE on private.
-- consumed_nonce at all (revoked above) — the ONLY way to remove a
-- tombstone is private.purge_consumed_nonce, a SECURITY DEFINER function
-- owned by private_definer, gated by a narrow RLS policy hardcoding a
-- floor of 7 days past each row's own source expiry (not a
-- caller-suppliable parameter any more).
SELECT throws_ok(
  $$DELETE FROM private.consumed_nonce WHERE nonce_hash = 'nonce-money-path-1'$$,
  '42501',
  NULL,
  'delete-then-replay is refused at the grant level: service_role has NO DELETE on private.consumed_nonce (only purge_consumed_nonce, as private_definer, can ever remove a tombstone)'
);

-- private.purge_consumed_nonce TTL purge: cutoff is 7 days past each
-- row's own expires_at (source expiry), COALESCEd to consumed_at only
-- for rows with no stored expiry (attestation-sourced).
SELECT lives_ok(
  $$INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at, expires_at)
    VALUES ('purge-test-old-nonce', 'checkin_challenge', now() - interval '31 days', now() - interval '8 days')$$,
  'setup: a consumed_nonce row whose SOURCE EXPIRY was 8 days ago (older than the 7-day-past-expiry floor)'
);
SELECT lives_ok(
  $$INSERT INTO private.consumed_nonce (nonce_hash, source, consumed_at, expires_at)
    VALUES ('purge-test-recent-nonce', 'checkin_challenge', now() - interval '31 days', now() - interval '1 hour')$$,
  'setup: a consumed_nonce row CONSUMED 31 days ago but whose SOURCE EXPIRY was only 1 hour ago -- proves the cutoff is expires_at-based, not consumed_at-based (the OLD design would have purged this)'
);
SELECT is(
  (SELECT private.purge_consumed_nonce()),
  1::bigint,
  'purge_consumed_nonce() deletes exactly the one row more than 7 days past its own source expiry'
);
SELECT is(
  (SELECT count(*)::int FROM private.consumed_nonce WHERE nonce_hash = 'purge-test-old-nonce'),
  0,
  'the row 8 days past its source expiry is gone after purge'
);
SELECT is(
  (SELECT count(*)::int FROM private.consumed_nonce WHERE nonce_hash = 'purge-test-recent-nonce'),
  1,
  'the row only 1 hour past its source expiry survives purge, DESPITE being consumed 31 days ago (expires_at-based, not consumed_at-based)'
);
SELECT is(
  (SELECT count(*)::int FROM private.consumed_nonce WHERE nonce_hash = 'nonce-money-path-1'),
  1,
  'a REAL (non-test-seeded) consumed_nonce row from this file''s own earlier tests also survives purge (its source expires_at is minutes in the FUTURE)'
);

-- should-fix: "an over-long TTL is refused" — app.checkin_challenge's new
-- CHECK constraint bounds expires_at to at most 24 hours past issued_at.
SELECT throws_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at, kind)
    VALUES ('a1000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-overlong-ttl', now() + interval '30 days', 'live')$$,
  '23514',
  NULL,
  'checkin_challenge rejects an over-long TTL (expires_at more than 24 hours past issued_at) -- a 30-day challenge is no longer accepted'
);

-- ⛔ FIX (should-fix 3, post-P3a re-gate): "a future issued_at sidesteps
-- the 24h cap." A caller who is free to pick issued_at could satisfy the
-- 24h-GAP CHECK above while pushing the whole challenge, and therefore
-- private.consumed_nonce's expiry-anchored purge floor, arbitrarily far
-- into the future (issued_at = now() + 10 days, expires_at = issued_at +
-- 5 minutes -- well inside the 24h gap, but nowhere near "now"). The new
-- checkin_challenge_issued_at_not_future CHECK closes this independently
-- of the gap CHECK.
SELECT throws_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, issued_at, expires_at, kind)
    VALUES ('a1000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-future-issued-at',
            now() + interval '10 days', now() + interval '10 days' + interval '5 minutes', 'live')$$,
  '23514',
  NULL,
  'checkin_challenge rejects a FUTURE issued_at, even though expires_at stays well within the 24h gap CHECK -- closes the "push the whole window out" sidestep (should-fix 3, post-P3a re-gate)'
);

-- ---------------------------------------------------------------------------
-- H1 (post-P3a gate) data test: delete_my_data must succeed when
-- offer_code.play_id or entitlement.play_id is set. Dedicated player C
-- (a fresh auth.users row, not player A/B) so this doesn't interact with
-- 09_delete_my_data.sql's own player A/staff@X flow.
-- ---------------------------------------------------------------------------
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000c0000001', 'player-c@example.test')$$,
  'setup: player C''s auth.users row'
);
SELECT lives_ok(
  $$INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status)
    VALUES ('43000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000c0000001',
            'crs_x1', 'fac_x', current_date - 2, 'v1', 'confirmed')$$,
  'setup: a play row for player C'
);
-- offer #1 (60000000-...-1) was capped at max_redemptions=1 by the H3
-- test earlier in this same file and already holds its one redemption —
-- offer #2 (60000000-...-2, trl_u/fac_x) is untouched, so it's used here
-- instead.
SELECT lives_ok(
  $$INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, play_id)
    VALUES ('72000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000002',
            '00000000-0000-0000-0000-0000c0000001', 'fac_x', 'earned', '43000000-0000-0000-0000-000000000001')$$,
  'setup: an offer_code for player C with play_id SET (H1''s exact reproduction shape)'
);
SELECT lives_ok(
  $$INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, play_id)
    VALUES ('52000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000c0000001',
            'special_marker', 'trl_t', 'redeemable', '43000000-0000-0000-0000-000000000001')$$,
  'setup: an entitlement for player C with play_id SET (H1''s exact reproduction shape)'
);
-- Settle the M2 composite FKs/constraint triggers for THESE two inserts
-- right now, while player C's play still exists — otherwise the deferred
-- check stays queued against the ORIGINAL (still-valid) INSERT values and
-- would only fire later (at this file's own M2 SET CONSTRAINTS IMMEDIATE,
-- or COMMIT), by which point delete_my_data(C) below has deleted player
-- C's play/offer_code outright (both are `delete_row`), so the queued
-- check would evaluate a now-STALE key pair and raise a false positive —
-- confirmed empirically this session (test 90 died with a spurious
-- "play not found" for player C's already-deleted offer_code once the
-- M2 section forced IMMEDIATE checking much later in this same
-- transaction). Settling here matches real usage: the INSERT's own
-- transaction would already have committed, resolving its deferred
-- check, long before a LATER, separate delete_my_data call.
SELECT lives_ok(
  $$SET CONSTRAINTS app.offer_code_play_user_fk, app.entitlement_play_user_fk,
      app.offer_code_play_guard_trg, app.entitlement_play_guard_trg IMMEDIATE$$,
  'setup: settle the M2 composite FKs/guards for player C''s H1 setup rows before delete_my_data runs'
);
SELECT lives_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000c0000001'::uuid)$$,
  'H1: delete_my_data succeeds when offer_code.play_id/entitlement.play_id are set (FK is deferrable + ON DELETE SET NULL, and delete_my_data nulls both explicitly too)'
);
SELECT is(
  (SELECT count(*)::int FROM app.offer_code WHERE id = '72000000-0000-0000-0000-000000000001'),
  0, 'the offer_code row (offer_code.user_id = delete_row) is deleted outright, play_id and all'
);
SELECT is(
  (SELECT play_id FROM app.entitlement WHERE id = '52000000-0000-0000-0000-000000000001'),
  NULL, 'the surviving entitlement row (entitlement.user_id = special, never deleted) has play_id nulled'
);

-- ---------------------------------------------------------------------------
-- M1 (post-P3a re-gate): the pseudonym HMAC key, on Supabase Vault, not a
-- GUC (0015/0018/shim.sql).
-- ---------------------------------------------------------------------------

-- anon and authenticated cannot obtain the key.
SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT throws_ok(
  $$SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'pseudonym_hmac_v1'$$,
  NULL,
  NULL,
  'anon cannot read vault.decrypted_secrets at all'
);
SELECT tests.clear_actor();
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000a'::uuid));
SELECT throws_ok(
  $$SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'pseudonym_hmac_v1'$$,
  NULL,
  NULL,
  'authenticated cannot read vault.decrypted_secrets at all'
);
SELECT tests.clear_actor();
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
-- should-fix (post-P3a re-gate): "vault grant contradiction" -- pin the
-- resolution (no grant to service_role; access only via private_definer)
-- so a future shim.sql edit that re-adds it fails this test immediately.
SELECT throws_ok(
  $$SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'pseudonym_hmac_v1'$$,
  NULL,
  NULL,
  'service_role ALSO cannot read vault.decrypted_secrets directly (access is only ever through private_definer, e.g. inside private.delete_my_data)'
);

-- SET LOCAL has no effect on the result: delete_my_data no longer reads
-- ANY GUC for the key (confirmed by grep -- there is no
-- `current_setting('app.pseudonym_hmac' ...)` left in 0015 at all), so
-- setting one, even to a plausible-looking name, changes nothing about
-- what gets computed/matched. Player D, dedicated, so this doesn't
-- interact with A/B/C's own fixture state.
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000d0000001', 'player-d@example.test')$$,
  'setup: player D''s auth.users row'
);
SELECT lives_ok(
  $$INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle)
    VALUES ('fac_x', 'presence', 'player_d',
            encode(hmac('00000000-0000-0000-0000-0000d0000001', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex'),
            'a0000000-1111-0000-0000-000000000001', 'staff_x_handle')$$,
  'setup: an attestation_shift_log row for player D, keyed with pseudonym_hmac_v1'
);
SELECT lives_ok(
  $$SET LOCAL app.pseudonym_hmac = 'attacker-controlled-value-that-should-be-completely-ignored'$$,
  'setup: set a rogue app.pseudonym_hmac GUC (SET LOCAL) before calling delete_my_data'
);
SELECT lives_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000d0000001'::uuid)$$,
  'delete_my_data succeeds despite the rogue SET LOCAL app.pseudonym_hmac'
);
SELECT is(
  (SELECT player_handle_snapshot FROM app.attestation_shift_log WHERE player_pseudonym = encode(hmac('00000000-0000-0000-0000-0000d0000001', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex')),
  'deleted player',
  'the SET LOCAL GUC had NO effect: the row was still found and updated using the REAL vault key, not the rogue GUC value'
);

-- ⛔ FIX (should-fix 4, post-P3a re-gate): "match on each row's recorded
-- hmac id and raise if that key is missing." delete_my_data now
-- discovers the SET of hmac ids ACTUALLY REFERENCED anywhere in
-- attestation_shift_log (not "every vault row named pseudonym_hmac%"),
-- so simulating "missing" now means the referenced vault row is
-- genuinely GONE, not merely renamed (renaming no longer matters at all
-- — id-based lookup doesn't care what a key is currently named, closing
-- the exact "rename v1 to retired_v1" gap the should-fix names). This is
-- deliberately conservative/fail-closed: since the discovery scan is
-- table-wide (it has to be — it doesn't know which rows belong to the
-- deletion target until it's tried every referenced key), a SINGLE
-- unresolvable historical key blocks delete_my_data for EVERY user,
-- not just one whose data used that key. A dedicated player D3 + a
-- dedicated throwaway key isolate this from every other test's own
-- data.
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000d0000003', 'player-d3@example.test')$$,
  'setup: player D3''s auth.users row (should-fix 4 tests)'
);
SELECT lives_ok(
  $$INSERT INTO vault.secrets (id, name, secret) VALUES ('a0000000-1111-0000-0000-000000000098', 'pseudonym_hmac_throwaway', 'shim-test-only-pseudonym-hmac-throwaway-32bytes-minimum-wwwwwwwwwwww')$$,
  'setup: a dedicated throwaway pseudonym_hmac key, for the missing-key test'
);
SELECT lives_ok(
  $$INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle)
    VALUES ('fac_x', 'presence', 'player_d3',
            encode(hmac('00000000-0000-0000-0000-0000d0000003', 'shim-test-only-pseudonym-hmac-throwaway-32bytes-minimum-wwwwwwwwwwww', 'sha256'), 'hex'),
            'a0000000-1111-0000-0000-000000000098', 'staff_x_handle')$$,
  'setup: an attestation_shift_log row keyed with the dedicated throwaway key'
);
-- Delete the vault row the row above references -- possible at all only
-- because should-fix 6 (post-P3a re-gate) dropped the FK into
-- vault.secrets; this is exactly the scenario that FK's removal was for
-- (validating the reference programmatically, inside the definer,
-- instead of relying on referential integrity to prevent it going
-- stale).
SELECT lives_ok(
  $$DELETE FROM vault.secrets WHERE id = 'a0000000-1111-0000-0000-000000000098'$$,
  'setup: delete the throwaway key from vault.secrets entirely (no FK blocks this any more)'
);
SELECT throws_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000d0000003'::uuid)$$,
  NULL,
  NULL,
  'delete_my_data raises when a REFERENCED pseudonym_hmac id no longer resolves in vault.decrypted_secrets at all (deleted, not just renamed)'
);

-- a short key raises an error (same dedicated row, key re-added short).
SELECT lives_ok(
  $$INSERT INTO vault.secrets (id, name, secret) VALUES ('a0000000-1111-0000-0000-000000000098', 'pseudonym_hmac_throwaway', 'too-short')$$,
  'setup: re-add the throwaway key, this time shorter than 32 bytes'
);
SELECT throws_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000d0000003'::uuid)$$,
  NULL,
  NULL,
  'delete_my_data raises when a REFERENCED pseudonym_hmac in the vault is shorter than 32 bytes'
);
-- cleanup: detach the dedicated row from the throwaway key.
SELECT lives_ok(
  $$DELETE FROM app.attestation_shift_log WHERE player_pseudonym_hmac_id = 'a0000000-1111-0000-0000-000000000098'$$,
  'cleanup: remove the dedicated attestation_shift_log row'
);
-- ⛔ FIX (M1 BLOCKING, post-P3a re-gate correction): the PRIOR version of
-- this cleanup DELETEd the throwaway key from vault.secrets outright,
-- then DELETEd its row from private.pseudonym_key_registry directly as
-- service_role -- exactly the M1 finding: service_role holding
-- INSERT/DELETE on the registry let a key be silently dropped from
-- future deletions' discovery, and this round's fix REMOVES that grant
-- and REVOKEs private_definer's own DELETE policy on the table too (the
-- registry is now append-only, by design: nothing but the write-time
-- SECURITY DEFINER validator ever inserts, and NOTHING ever deletes).
-- There is therefore no longer any privileged path in this test (or in
-- production) to remove a registry row at all -- cleanup instead
-- RESTORES the vault key to a valid (>=32 byte) secret, so any LATER
-- delete_my_data call that resolves this now-permanent registry entry
-- succeeds (a harmless no-op against it -- no OTHER row's pseudonym will
-- ever match a key computed under THIS throwaway secret) instead of
-- raising "does not resolve".
SELECT lives_ok(
  $$UPDATE vault.secrets SET secret = 'shim-test-only-pseudonym-hmac-throwaway-restored-32bytes-min-yyyyyyyyyyyy' WHERE id = 'a0000000-1111-0000-0000-000000000098'$$,
  'cleanup: restore the throwaway key to a valid secret (>=32 bytes) instead of deleting it -- its private.pseudonym_key_registry row can never be removed now, by design (M1, post-P3a re-gate correction)'
);

-- rotation: a row written with key 1 is still found after key 2 AND a
-- brand-new key 3 are both active — id-based resolution means rotation
-- (adding new keys) never affects an EXISTING row's own recorded id.
SELECT lives_ok(
  $$INSERT INTO vault.secrets (id, name, secret) VALUES ('a0000000-1111-0000-0000-000000000003', 'pseudonym_hmac_v3', 'shim-test-only-pseudonym-hmac-three-32bytes-minimum-zzzzzzzzzzzzzzzzzzz')$$,
  'setup: rotate in a THIRD active pseudonym_hmac (key 1 never stops being active -- rotation adds, this design never retires a key on its own)'
);
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000d0000002', 'player-d2@example.test')$$,
  'setup: player D2''s auth.users row'
);
SELECT lives_ok(
  $$INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle)
    VALUES ('fac_x', 'presence', 'player_d2',
            encode(hmac('00000000-0000-0000-0000-0000d0000002', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex'),
            'a0000000-1111-0000-0000-000000000001', 'staff_x_handle')$$,
  'setup: an attestation_shift_log row for player D2, written under key 1 -- BEFORE key 3 existed'
);
SELECT lives_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000d0000002'::uuid)$$,
  'delete_my_data succeeds with 3 active keys (1, 2, 3) in the vault'
);
SELECT is(
  (SELECT player_handle_snapshot FROM app.attestation_shift_log WHERE player_pseudonym = encode(hmac('00000000-0000-0000-0000-0000d0000002', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex')),
  'deleted player',
  'ROTATION: the row written under key 1 is still found and updated after key 2 AND key 3 were added later -- resolved by its OWN recorded key id, unaffected by later keys existing'
);
SELECT lives_ok(
  $$DELETE FROM vault.secrets WHERE name = 'pseudonym_hmac_v3'$$,
  'cleanup: remove the rotation test''s key 3'
);

-- ---------------------------------------------------------------------------
-- M2 (post-P3a re-gate): held_review/owner guard, all four bypasses, both
-- tables.
-- ---------------------------------------------------------------------------
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000e0000001', 'player-e@example.test')$$,
  'setup: player E''s auth.users row (M2 tests)'
);
SELECT lives_ok(
  $$INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status)
    VALUES ('44000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000e0000001',
            'crs_x1', 'fac_x', current_date - 3, 'v1', 'confirmed')$$,
  'setup: a play row for player E, held_review=false'
);

-- (a) the play is placed on hold AFTER the code/entitlement was issued.
-- Offer #3 (60000000-...-3), not offer #2 — helpers.sql already seeds
-- player A an offer_code against offer #2 (70000000-...-2), so bypass (c)
-- below (re-owning this row TO player A) would otherwise collide with
-- UNIQUE(user_id, offer_id) instead of raising the FK violation it's
-- testing for (confirmed empirically this session).
SELECT lives_ok(
  $$INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, play_id)
    VALUES ('73000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000003',
            '00000000-0000-0000-0000-0000e0000001', 'fac_x', 'earned', '44000000-0000-0000-0000-000000000001')$$,
  'setup: an offer_code for player E, backed by the NOT-YET-held play, state=earned'
);
-- trl_v, not trl_t/trl_u — helpers.sql already seeds player A entitlements
-- on BOTH of those trails, so bypass (c) below (re-owning this row TO
-- player A) would otherwise collide with UNIQUE(user_id, kind, trail_id)
-- instead of raising the FK violation it's testing for.
SELECT lives_ok(
  $$INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, play_id)
    VALUES ('53000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000e0000001',
            'special_marker', 'trl_v', 'redeemable', '44000000-0000-0000-0000-000000000001')$$,
  'setup: an entitlement for player E, backed by the SAME play, state=redeemable'
);
SELECT lives_ok(
  $$UPDATE app.play SET held_review = true WHERE id = '44000000-0000-0000-0000-000000000001'$$,
  'M2 bypass (a) setup: the play is placed on hold AFTER both were issued'
);
SELECT is(
  (SELECT state::text FROM app.offer_code WHERE id = '73000000-0000-0000-0000-000000000001'),
  'held_review',
  'M2 bypass (a) CLOSED: offer_code moved into held_review when its backing play went on hold, without offer_code itself ever being touched directly'
);
SELECT is(
  (SELECT state::text FROM app.entitlement WHERE id = '53000000-0000-0000-0000-000000000001'),
  'held_review',
  'M2 bypass (a) CLOSED: entitlement moved into held_review the same way'
);

-- Force the composite FKs + constraint triggers to check immediately for
-- the rest of these tests (same reasoning as M1's own use of this,
-- above) — otherwise a violation from an UPDATE/INSERT alone would not
-- raise until COMMIT, which this file's outer transaction never reaches.
SELECT lives_ok(
  $$SET CONSTRAINTS app.offer_code_play_user_fk, app.entitlement_play_user_fk,
      app.offer_code_play_guard_trg, app.entitlement_play_guard_trg IMMEDIATE$$,
  'setup: check the M2 composite FKs + constraint triggers immediately for the bypass tests below'
);

-- (b) deferred insert ordering: play_id pointing at a play that, at
-- INSERT time, does not exist yet. Under the OLD plain-BEFORE-trigger
-- design this silently passed (NOT FOUND -> RETURN NEW); the composite
-- FK + CONSTRAINT TRIGGER design raises once checked.
-- Offer #2 (60000000-...-2), not offer #3 (already claimed by player E's
-- (a)-test offer_code above) — a second offer_code for the SAME
-- (user_id, offer_id) pair would hit UNIQUE(user_id, offer_id) before the
-- FK check even gets a chance to run, masking the 23503 this test wants
-- (confirmed empirically this session). Player A separately holds an
-- offer_code against offer #2 too, but that's a different user_id, so it
-- doesn't collide with player E's (user_id, offer_id) pair here.
SELECT throws_ok(
  $$INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, play_id)
    VALUES ('73000000-0000-0000-0000-000000000099', '60000000-0000-0000-0000-000000000002',
            '00000000-0000-0000-0000-0000e0000001', 'fac_x', 'earned', '44000000-0000-0000-0000-000000000099')$$,
  '23503',
  NULL,
  'M2 bypass (b) CLOSED (offer_code): a play_id pointing at a non-existent play is rejected once checked, not silently passed through'
);
SELECT throws_ok(
  $$INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, play_id)
    VALUES ('53000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-0000e0000001',
            'special_marker', 'trl_t', 'redeemable', '44000000-0000-0000-0000-000000000099')$$,
  '23503',
  NULL,
  'M2 bypass (b) CLOSED (entitlement): same, for entitlement'
);

-- (c) UPDATE offer_code.user_id / entitlement.user_id to a different
-- owner without touching play_id at all.
SELECT throws_ok(
  $$UPDATE app.offer_code SET user_id = '00000000-0000-0000-0000-00000000000a' WHERE id = '73000000-0000-0000-0000-000000000001'$$,
  '23503',
  NULL,
  'M2 bypass (c) CLOSED (offer_code): re-owning offer_code.user_id while it still has a linked play_id is rejected (composite FK)'
);
SELECT throws_ok(
  $$UPDATE app.entitlement SET user_id = '00000000-0000-0000-0000-00000000000a' WHERE id = '53000000-0000-0000-0000-000000000001'$$,
  '23503',
  NULL,
  'M2 bypass (c) CLOSED (entitlement): same, for entitlement'
);

-- (d) UPDATE play.user_id without touching offer_code/entitlement at all.
SELECT throws_ok(
  $$UPDATE app.play SET user_id = '00000000-0000-0000-0000-00000000000a' WHERE id = '44000000-0000-0000-0000-000000000001'$$,
  '23503',
  NULL,
  'M2 bypass (d) CLOSED: re-owning play.user_id while offer_code AND entitlement still reference it is rejected (composite FK ON UPDATE)'
);

-- should-fix (post-P3a re-gate): "a reviewer cannot set offer_code/
-- entitlement to void or expired while it is held." Both rows are still
-- held_review at this point (every bypass attempt above failed). A
-- reviewer resolving the review must be able to move them straight to a
-- terminal state.
SELECT lives_ok(
  $$UPDATE app.offer_code SET state = 'expired' WHERE id = '73000000-0000-0000-0000-000000000001'$$,
  'a HELD offer_code can be resolved straight to expired by a reviewer (was previously blocked, only held_review itself was accepted)'
);
SELECT lives_ok(
  $$UPDATE app.entitlement SET state = 'void' WHERE id = '53000000-0000-0000-0000-000000000001'$$,
  'a HELD entitlement can be resolved straight to void by a reviewer (entitlement_state has no separate expired)'
);

-- ---------------------------------------------------------------------------
-- ⛔ FIX (should-fix 4, post-P3a re-gate: "stale NEW guard"). Player F,
-- dedicated, so this doesn't interact with any other player's fixture
-- state. Repro shape: entitlement.play_id is explicitly SET (queues a
-- deferred guard firing carrying THAT NEW.play_id), and in the SAME
-- transaction, still BEFORE that firing ever runs, private.
-- delete_my_data both detaches play_id back to NULL AND deletes the
-- play row outright -- under the OLD (stale-NEW) code, the FIRST
-- firing's own fresh `SELECT ... FROM app.play WHERE id = <the STALE
-- captured play_id>` would find NOT FOUND (the row really is gone by
-- then) and RAISE, failing an entirely legitimate deletion.
-- ---------------------------------------------------------------------------
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000f0000001', 'player-f@example.test')$$,
  'setup: player F''s auth.users row (should-fix 4 test)'
);
SELECT lives_ok(
  $$INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status)
    VALUES ('46000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000f0000001',
            'crs_x1', 'fac_x', current_date - 1, 'v1', 'confirmed')$$,
  'setup: a play row for player F, held_review=false'
);
SELECT lives_ok(
  $$INSERT INTO app.entitlement (id, user_id, kind, trail_id, state)
    VALUES ('54000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-0000f0000001',
            'special_marker', 'trl_t', 'redeemable')$$,
  'setup: an entitlement for player F, play_id NOT YET set'
);
SELECT lives_ok(
  $$UPDATE app.entitlement SET play_id = '46000000-0000-0000-0000-000000000001' WHERE id = '54000000-0000-0000-0000-000000000001'$$,
  'should-fix 4 repro step 1: explicitly SET entitlement.play_id -- queues a DEFERRED guard firing carrying this exact NEW.play_id, which will go STALE the moment the row changes again'
);
SELECT lives_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000f0000001'::uuid)$$,
  'should-fix 4 repro step 2, SAME transaction: delete_my_data detaches play_id back to NULL AND deletes the play row outright -- the step 1 firing''s captured NEW.play_id is now stale relative to both'
);
SELECT lives_ok(
  $$SET CONSTRAINTS app.offer_code_play_user_fk, app.entitlement_play_user_fk,
      app.offer_code_play_guard_trg, app.entitlement_play_guard_trg IMMEDIATE$$,
  'should-fix 4 FIXED: forcing every deferred check to fire now (including step 1''s stale-NEW firing) raises NOTHING -- the guard re-reads the row by id and finds play_id already NULL, instead of trusting the stale captured NEW and raising "play not found" over a row that is legitimately gone'
);
SELECT is(
  (SELECT state::text FROM app.entitlement WHERE id = '54000000-0000-0000-0000-000000000001'),
  'void',
  'player F''s entitlement (special_marker, was redeemable) is voided by delete_my_data as normal -- the stale-NEW fix did not change the deletion''s own outcome, only stopped it from spuriously raising'
);

-- ---------------------------------------------------------------------------
-- M3 BLOCKING (post-P3a re-gate): "guard RLS fail-open." Repro:
-- service_role (bypasses RLS) inserts an `earned` offer_code for an
-- ALREADY-held play -- the deferred guard check queues, unrun. BEFORE it
-- ever fires, the active role switches to player B, an unrelated
-- authenticated user whose OWN row-scoped RLS cannot see player G's
-- offer_code at all. Forcing the deferred check now (AS PLAYER B) is
-- exactly the moment the OLD (should-fix-4-only) re-read broke: it ran
-- under player B's RLS, got NOT FOUND, and (wrongly) concluded the row
-- was deleted. Player G, dedicated -- the play guard trigger was forced
-- to IMMEDIATE for the REST of this transaction by the M2 bypass tests
-- above, so it is switched back to DEFERRED for this one block only.
-- ---------------------------------------------------------------------------
SELECT lives_ok(
  $$SET CONSTRAINTS app.offer_code_play_guard_trg DEFERRED$$,
  'setup (M3): switch the offer_code play guard back to DEFERRED for this repro (every earlier test in this file left it forced IMMEDIATE)'
);
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-100000000001', 'player-g@example.test')$$,
  'setup: player G''s auth.users row (M3 test)'
);
SELECT lives_ok(
  $$INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status, held_review)
    VALUES ('47000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-100000000001',
            'crs_x1', 'fac_x', current_date - 1, 'v1', 'confirmed', true)$$,
  'setup: a play row for player G, ALREADY held_review=true at insert time'
);
SELECT lives_ok(
  $$INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, play_id)
    VALUES ('74000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000002',
            '00000000-0000-0000-0000-100000000001', 'fac_x', 'earned', '47000000-0000-0000-0000-000000000001')$$,
  'M3 repro step 1 (as service_role, bypasses RLS): insert an earned offer_code for the ALREADY-held play -- the deferred guard check queues, not yet run'
);
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000b'::uuid));
SELECT is(
  (SELECT count(*)::int FROM app.offer_code WHERE id = '74000000-0000-0000-0000-000000000001'),
  0,
  'precondition confirms the fail-open mechanism is real: player B''s OWN row-scoped RLS genuinely cannot see player G''s offer_code row at all'
);
SELECT throws_ok(
  $$SET CONSTRAINTS app.offer_code_play_guard_trg IMMEDIATE$$,
  '23514',
  NULL,
  'M3 FIXED: forcing the deferred guard check now, AS PLAYER B (not the role that inserted the row), still raises -- the guard''s own re-read is SECURITY DEFINER (private_definer), independent of the committing role''s RLS, so a row merely INVISIBLE to player B is correctly never treated as "deleted"'
);
SELECT tests.clear_actor();
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT lives_ok(
  $$UPDATE app.offer_code SET state = 'held_review' WHERE id = '74000000-0000-0000-0000-000000000001'$$,
  'cleanup (M3): resolve player G''s offer_code to held_review so it does not leave an unresolved held row dangling for the rest of this file'
);

-- ---------------------------------------------------------------------------
-- Follow-up (post-P3a re-gate round 2): "narrow the three guard-read
-- policies using the GUC pattern ... add a test that private_definer
-- can't read other rows outside the guard context." migration_owner
-- (HARNESS_MODE=restricted) / postgres (HARNESS_MODE=superuser) both hold
-- SET-only membership in private_definer (`GRANT private_definer TO
-- CURRENT_USER WITH INHERIT FALSE, SET TRUE`, 0016) -- ASSUMING it
-- directly, with no app.guard.* GUC ever set in this fresh SET ROLE
-- context, proves the narrowed policies genuinely admit ZERO rows
-- outside the one window each guard function itself controls, not merely
-- that the guard's OWN re-read (already proven above) still works.
-- ---------------------------------------------------------------------------
-- app.offer_code/app.entitlement ALSO carry OTHER, pre-existing
-- private_definer SELECT policies for delete_my_data's own purposes
-- (pd_setnull_offer_code_redeemed_by_staff_r /
-- pd_setnull_entitlement_redeemed_by_staff_r), each with its own "OR
-- redeemed_by_staff IS NULL" branch that is GUC-independent and matches
-- most fixture rows regardless of this round's change -- a whole-table
-- count would conflate THEIR pre-existing visibility with the guard-read
-- policy this test is actually about. Isolate player G's own rows from
-- that unrelated branch first (a non-NULL, non-matching redeemed_by_staff)
-- so the ONLY policy left that could possibly admit them is the new
-- guard-scoped one.
SELECT lives_ok(
  $$UPDATE app.offer_code SET redeemed_by_staff = '00000000-0000-0000-0000-1000000000a1' WHERE id = '74000000-0000-0000-0000-000000000001'$$,
  'setup (follow-up test): isolate player G''s offer_code from the unrelated pd_setnull_offer_code_redeemed_by_staff_r policy''s own OR-IS-NULL branch'
);
SELECT lives_ok(
  $$INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, redeemed_by_staff)
    VALUES ('55000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-100000000001',
            'special_marker', 'trl_u', 'redeemable', '00000000-0000-0000-0000-1000000000a1')$$,
  'setup (follow-up test): a dedicated entitlement for player G, redeemed_by_staff set the same way to isolate it from pd_setnull_entitlement_redeemed_by_staff_r'
);
SELECT tests.clear_actor();
SELECT lives_ok(
  $$SET ROLE private_definer$$,
  'setup (follow-up test): assume private_definer directly (migration_owner/postgres holds SET-only membership, 0016) to probe its own RLS visibility with no guard context active'
);
SELECT is(
  (SELECT count(*)::int FROM app.offer_code WHERE id = '74000000-0000-0000-0000-000000000001'),
  0,
  'private_definer cannot see player G''s offer_code row via the guard-read policy with no app.guard.offer_code_id GUC set, once isolated from the unrelated redeemed-by-staff policy (follow-up, post-P3a re-gate round 2)'
);
SELECT is(
  (SELECT count(*)::int FROM app.entitlement WHERE id = '55000000-0000-0000-0000-000000000001'),
  0,
  'same for the dedicated entitlement row, via app.guard.entitlement_id'
);
SELECT is(
  (SELECT count(*)::int FROM app.play WHERE id = '47000000-0000-0000-0000-000000000001'),
  0,
  'same for player G''s play row, via app.guard.play_id (app.play carries no OTHER private_definer SELECT policy that could also admit it here)'
);
SELECT lives_ok(
  $$RESET ROLE$$,
  'cleanup (follow-up test): return to the connecting role'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

SELECT tests.clear_actor();
SELECT * FROM finish();
ROLLBACK;
