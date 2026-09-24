-- 11_money_path.sql
-- Money-path security review queue (0017_money_path_hardening.sql).
-- Runs as service_role throughout (SET LOCAL ROLE via authenticate_as):
-- every assertion here is about a CHECK/trigger/function's OWN
-- enforcement, which fires regardless of caller role/RLS, not about an
-- RLS authorization boundary — matching 07_rate_limit.sql/
-- 09_delete_my_data.sql's own reasoning for the same choice.

BEGIN;
SELECT plan(38);

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
  $$INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version)
    VALUES ('32000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'self_report', 'money-path-seed-a2', 'accepted', 1)$$,
  'setup: a second evidence row owned by player A'
);
SELECT lives_ok(
  $$INSERT INTO app.play_evidence (play_id, evidence_id) VALUES
    ('40000000-0000-0000-0000-000000000001', '32000000-0000-0000-0000-000000000099')$$,
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
  $$INSERT INTO app.play_evidence (play_id, evidence_id) VALUES
    ('42000000-0000-0000-0000-000000000099', '32000000-0000-0000-0000-000000000099')$$,
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

-- A play for player B, evidence for player A: ownership-mismatch trigger.
SELECT lives_ok(
  $$INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version)
    VALUES ('31000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000b',
            NULL, 'self_report', 'money-path-seed-b', 'accepted', 1)$$,
  'setup: an evidence row owned by player B'
);
SELECT throws_ok(
  $$INSERT INTO app.play_evidence (play_id, evidence_id) VALUES
    ('41000000-0000-0000-0000-000000000099', '30000000-0000-0000-0000-000000000001')$$,
  '23514',
  NULL,
  'play_evidence: player B''s play cannot be backed by player A''s evidence (user-match trigger)'
);
-- (the row above was already rejected by the UNIQUE constraint test two
-- assertions up — re-asserted here against player B's OWN evidence id to
-- isolate the user-match trigger specifically, independent of UNIQUE.)
SELECT throws_ok(
  $$INSERT INTO app.play_evidence (play_id, evidence_id) VALUES
    ('40000000-0000-0000-0000-000000000001', '31000000-0000-0000-0000-000000000099')$$,
  '23514',
  NULL,
  'play_evidence: player A''s play cannot be backed by player B''s evidence (user-match trigger, reverse direction)'
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
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000099'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash1', 'fac_x', current_date
  ),
  false,
  'dedupe_receipt_fingerprint returns false for a phash matching an EXISTING different purchase (helpers.sql seeds phash1 for player A''s purchase 90000000-...-1)'
);
SELECT is(
  (SELECT status::text FROM app.purchase_evidence WHERE id = '91000000-0000-0000-0000-000000000099'),
  'void',
  'a phash-duplicate purchase is voided by dedupe_receipt_fingerprint'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'receipt_phash_duplicate' AND user_id = '00000000-0000-0000-0000-00000000000b'),
  1,
  'a phash-duplicate purchase writes exactly one fraud_signal row'
);
SELECT is(
  app.dedupe_receipt_fingerprint(
    '91000000-0000-0000-0000-000000000099'::uuid, '00000000-0000-0000-0000-00000000000b'::uuid,
    'phash-genuinely-new', 'fac_x', current_date
  ),
  true,
  'dedupe_receipt_fingerprint returns true (and records the fingerprint) for a genuinely new phash'
);

-- ---------------------------------------------------------------------------
-- 6. Nonce uniqueness: checkin_challenge.nonce_hash (global) +
--    used_at one-way transition.
-- ---------------------------------------------------------------------------
SELECT lives_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at)
    VALUES ('a1000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-1', now() + interval '5 minutes')$$,
  'setup: seed one checkin_challenge row'
);
SELECT throws_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at)
    VALUES ('a1000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-1', now() + interval '5 minutes')$$,
  '23505',
  NULL,
  'checkin_challenge.nonce_hash is globally unique across users (already a plain table-wide UNIQUE, not per-user)'
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

SELECT tests.clear_actor();
SELECT * FROM finish();
ROLLBACK;
