-- 11_money_path.sql
-- Money-path security review queue (0017_money_path_hardening.sql).
-- Runs as service_role throughout (SET LOCAL ROLE via authenticate_as):
-- every assertion here is about a CHECK/trigger/function's OWN
-- enforcement, which fires regardless of caller role/RLS, not about an
-- RLS authorization boundary — matching 07_rate_limit.sql/
-- 09_delete_my_data.sql's own reasoning for the same choice.

BEGIN;
SELECT plan(96);

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
  $$INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version)
    VALUES ('31000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000b',
            NULL, 'self_report', 'money-path-seed-b', 'accepted', 1)$$,
  'setup: an evidence row owned by player B'
);
-- A THIRD evidence row for player A, not yet linked to anything (30000000-
-- ...-1 and 32000000-...-99 are both already linked by this point, which
-- would trip the UNIQUE(evidence_id) constraint first and mask the FK
-- violation these two tests are isolating).
SELECT lives_ok(
  $$INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version)
    VALUES ('33000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'self_report', 'money-path-seed-a3', 'accepted', 1)$$,
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
-- The consumed-nonce tombstone trigger (should-fix, added below) fires
-- BEFORE the table's own UNIQUE constraint is even reached, so a repeat
-- insert of an already-consumed nonce now raises 23514 (tombstoned), not
-- 23505 -- this still proves the same thing (global uniqueness, not
-- per-user), just via the stricter of the two mechanisms.
SELECT throws_ok(
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at)
    VALUES ('a1000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000b',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-1', now() + interval '5 minutes')$$,
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
  $$INSERT INTO app.checkin_challenge (id, user_id, device_id, nonce_hash, expires_at)
    VALUES ('a1000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000a',
            '20000000-0000-0000-0000-000000000001', 'nonce-money-path-1', now() + interval '5 minutes')$$,
  '23514',
  NULL,
  'checkin_challenge: a DELETEd-then-re-INSERTed nonce_hash is still rejected by the consumed-nonce tombstone ledger, not just the table''s own UNIQUE constraint'
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

-- a missing key raises an error.
SELECT lives_ok(
  $$INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-0000d0000002', 'player-d2@example.test')$$,
  'setup: player D2''s auth.users row'
);
-- RENAME out of the pseudonym_hmac% match, not DELETE: app.attestation's
-- player_pseudonym_hmac_id/staff_pseudonym_hmac_id (0018) FK to
-- vault.secrets(id), and helpers.sql's seeded attestation row references
-- key 1 — a real DELETE here hits a 23503, not the "no active key"
-- 23514/fail-closed path this test wants (confirmed empirically this
-- session). Renaming makes delete_my_data's own `name LIKE
-- 'pseudonym_hmac%'` lookup find nothing, without touching referential
-- integrity at all.
-- PREFIX the name (not suffix — `name || '_suffix'` still starts with
-- 'pseudonym_hmac' and so still matches the SAME `LIKE 'pseudonym_hmac%'`
-- prefix pattern delete_my_data itself uses, confirmed empirically this
-- session: the first version of this fix left the rows matching after
-- all).
SELECT lives_ok(
  $$UPDATE vault.secrets SET name = 'hidden_for_test_' || name WHERE name LIKE 'pseudonym_hmac%'$$,
  'setup: hide every pseudonym_hmac from the vault (renamed, not deleted)'
);
SELECT throws_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000d0000002'::uuid)$$,
  NULL,
  'delete_my_data: no active pseudonym_hmac found in vault.decrypted_secrets',
  'delete_my_data raises when the vault has NO active pseudonym_hmac (fail-closed, not a silent leave-PII-behind)'
);

-- a short key raises an error.
SELECT lives_ok(
  $$INSERT INTO vault.secrets (id, name, secret) VALUES ('a0000000-1111-0000-0000-000000000099', 'pseudonym_hmac_short', 'too-short')$$,
  'setup: seed a pseudonym_hmac shorter than 32 bytes'
);
SELECT throws_ok(
  $$SELECT private.delete_my_data('00000000-0000-0000-0000-0000d0000002'::uuid)$$,
  NULL,
  NULL,
  'delete_my_data raises when a pseudonym_hmac in the vault is shorter than 32 bytes'
);
SELECT lives_ok(
  $$DELETE FROM vault.secrets WHERE name = 'pseudonym_hmac_short'$$,
  'cleanup: remove the short key'
);
SELECT lives_ok(
  $$UPDATE vault.secrets SET name = 'pseudonym_hmac_v1' WHERE id = 'a0000000-1111-0000-0000-000000000001'$$,
  'cleanup: restore pseudonym_hmac_v1''s name (hidden above for the missing-key test)'
);
SELECT lives_ok(
  $$UPDATE vault.secrets SET name = 'pseudonym_hmac_v2' WHERE id = 'a0000000-1111-0000-0000-000000000002'$$,
  'cleanup: restore pseudonym_hmac_v2''s name'
);

-- rotation: a row written with key 1 is still found after key 2 (already
-- restored above) AND a brand-new key 3 are both active.
SELECT lives_ok(
  $$INSERT INTO vault.secrets (id, name, secret) VALUES ('a0000000-1111-0000-0000-000000000003', 'pseudonym_hmac_v3', 'shim-test-only-pseudonym-hmac-three-32bytes-minimum-zzzzzzzzzzzzzzzzzzz')$$,
  'setup: rotate in a THIRD active pseudonym_hmac (key 1 never stops being active -- rotation adds, this design never retires a key on its own)'
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
  'ROTATION: the row written under key 1 is still found and updated after key 2 AND key 3 were added later -- delete_my_data tried every active key, not just the newest'
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

SELECT tests.clear_actor();
SELECT * FROM finish();
ROLLBACK;
