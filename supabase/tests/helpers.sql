-- supabase/tests/helpers.sql
-- Shared pgTAP test fixtures: seeded actors (players, staff, managers,
-- operators, admin, demo account) and catalog rows, referenced by every
-- file in supabase/tests/matrix/*.sql. Applied once per test run, after
-- the shim + all migrations, before the matrix files (tools/db/test.sh).
--
-- Actor set mirrors build plan §4.7.7's row list exactly (docs/golf-trails
-- /02-build-plan.md:1315-1318): anon, player A, player B, staff@X,
-- staff@X acting on their own player account, staff@X (revoked),
-- manager@X, manager@X (revoked), operator@T, operator@T (revoked),
-- admin, app-review demo account, service. (sponsor@S is P6 — out of
-- scope; no row seeded for it.)

BEGIN;

-- Player accounts (auth.users)
INSERT INTO auth.users (id, email) VALUES
  ('00000000-0000-0000-0000-00000000000a', 'player-a@example.test'),
  ('00000000-0000-0000-0000-00000000000b', 'player-b@example.test'),
  ('00000000-0000-0000-0000-1000000000a1', 'staff-x@example.test'),
  ('00000000-0000-0000-0000-1000000000a2', 'staff-x-revoked@example.test'),
  ('00000000-0000-0000-0000-2000000000b1', 'manager-x@example.test'),
  ('00000000-0000-0000-0000-2000000000b2', 'manager-x-revoked@example.test'),
  ('00000000-0000-0000-0000-3000000000c1', 'operator-t@example.test'),
  ('00000000-0000-0000-0000-3000000000c2', 'operator-t-revoked@example.test'),
  ('00000000-0000-0000-0000-4000000000d0', 'admin@example.test'),
  ('00000000-0000-0000-0000-5000000000e0', 'app-review-demo@example.test'),
  ('00000000-0000-0000-0000-1000000000a3', 'staff-y@example.test'); -- for cross-facility must-fail cells

INSERT INTO app.profile (user_id, handle) VALUES
  ('00000000-0000-0000-0000-00000000000a', 'player_a'),
  ('00000000-0000-0000-0000-00000000000b', 'player_b'),
  ('00000000-0000-0000-0000-5000000000e0', 'demo_player');

INSERT INTO app.admin_user (user_id) VALUES ('00000000-0000-0000-0000-4000000000d0');
INSERT INTO app.app_review_demo_account (user_id) VALUES ('00000000-0000-0000-0000-5000000000e0');

-- Catalog: one trail (T), two facilities (X, Y), one course each.
INSERT INTO app.catalog_version (version, contract_version, sha256, kid, published_at)
VALUES (1, 'v1', repeat('a', 64), 'kid1', now());

INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES
  ('trl_t', 'trail', 'verified', 1),
  ('fac_x', 'facility', 'verified', 1),
  ('fac_y', 'facility', 'verified', 1),
  ('crs_x1', 'course', 'verified', 1),
  ('crs_y1', 'course', 'verified', 1);

INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES ('trl_t', 'trail-t', 'Trail T', 1);
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version) VALUES
  ('fac_x', 'facility-x', 'Facility X', 'US-TN', 'America/Chicago', 1),
  ('fac_y', 'facility-y', 'Facility Y', 'US-TN', 'America/Chicago', 1);
INSERT INTO app.catalog_course (id, facility_id, name, verification_status, catalog_version) VALUES
  ('crs_x1', 'fac_x', 'Course X1', 'play-verified', 1),
  ('crs_y1', 'fac_y', 'Course Y1', 'play-verified', 1);

INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from)
VALUES ('trl_t', 1, 'course', 'facility', now());
INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, course_id, stop_order) VALUES
  ('trl_t', 1, 'course', 'crs_x1', 1),
  ('trl_t', 1, 'course', 'crs_y1', 2);

-- Partner orgs: X (facility org for staff/manager), operator org for T.
INSERT INTO app.partner_org (id, kind, name) VALUES
  ('10000000-0000-0000-0000-000000000001', 'facility', 'Facility X Pro Shop'),
  ('10000000-0000-0000-0000-000000000002', 'facility', 'Facility Y Pro Shop'),
  ('10000000-0000-0000-0000-000000000003', 'operator', 'Trail T Operator');

INSERT INTO app.partner_scope (org_id, facility_id) VALUES
  ('10000000-0000-0000-0000-000000000001', 'fac_x'),
  ('10000000-0000-0000-0000-000000000002', 'fac_y');
INSERT INTO app.partner_scope (org_id, trail_id) VALUES
  ('10000000-0000-0000-0000-000000000003', 'trl_t');

INSERT INTO app.partner_member (user_id, org_id, role, revoked_at) VALUES
  ('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-000000000001', 'staff', NULL),
  ('00000000-0000-0000-0000-1000000000a2', '10000000-0000-0000-0000-000000000001', 'staff', now()),
  ('00000000-0000-0000-0000-1000000000a3', '10000000-0000-0000-0000-000000000002', 'staff', NULL),
  ('00000000-0000-0000-0000-2000000000b1', '10000000-0000-0000-0000-000000000001', 'manager', NULL),
  ('00000000-0000-0000-0000-2000000000b2', '10000000-0000-0000-0000-000000000001', 'manager', now()),
  ('00000000-0000-0000-0000-3000000000c1', '10000000-0000-0000-0000-000000000003', 'operator', NULL),
  ('00000000-0000-0000-0000-3000000000c2', '10000000-0000-0000-0000-000000000003', 'operator', now());

-- Programme + stock, so the special-marker matrix has real rows.
INSERT INTO app.trail_programme (trail_id, status) VALUES ('trl_t', 'live');
INSERT INTO app.facility_programme (trail_id, facility_id, participation, holds_special_marker)
VALUES ('trl_t', 'fac_x', 'accepted', true);
INSERT INTO app.special_marker_stock (trail_id, facility_id, on_hand, low_threshold)
VALUES ('trl_t', 'fac_x', 5, 3);
INSERT INTO app.special_marker_availability (trail_id, facility_id, status)
VALUES ('trl_t', 'fac_x', 'in_stock');

-- One evidence/play/entitlement/offer_code row each for player A, so
-- "player B reads A's X" has something real to fail to read.
INSERT INTO app.device (id, user_id, platform) VALUES
  ('20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a', 'ios');
INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, status, catalog_version)
VALUES ('30000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
        '20000000-0000-0000-0000-000000000001', 'foreground_checkin', 'checkin-seed-1', 'accepted', 1);
INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status)
VALUES ('40000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
        'crs_x1', 'fac_x', current_date, 'v1', 'confirmed');
-- Second trail (trl_u) so player A can hold a SECOND entitlement row —
-- unique(user_id, kind, trail_id) forbids two under the same trail. Used
-- to seed both an ACTIVATED (redeemable, device-attached) and a REDEEMED
-- entitlement, per the gate's B3 instruction ("must seed activated and
-- redeemed rows").
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('trl_u', 'trail', 'verified', 1);
INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES ('trl_u', 'trail-u', 'Trail U', 1);

-- entitlement #1: ACTIVATED (redeemable, device-attached) — exercises the
-- RESTRICT FK on activated_device_id (B3).
INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, activated_device_id, activated_at)
VALUES ('50000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
        'special_marker', 'trl_t', 'redeemable', '20000000-0000-0000-0000-000000000001', now());
-- entitlement #2: REDEEMED (terminal) — must survive delete_my_data
-- unvoided, with its device link still detached.
INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, activated_device_id, redeemed_at, redeemed_facility_id, redeemed_by_staff, redemption_method, redemption_jti)
VALUES ('50000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000a',
        'special_marker', 'trl_u', 'redeemed', '20000000-0000-0000-0000-000000000001', now(),
        'fac_x', '00000000-0000-0000-0000-1000000000a1', 'staff_scan', 'jti-redeem-1');

INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, valid_from, valid_to, status)
VALUES ('60000000-0000-0000-0000-000000000001', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, current_date, current_date + 30, 'live');
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, valid_from, valid_to, status)
VALUES ('60000000-0000-0000-0000-000000000002', 'trl_u', 'fac_x', '{}'::jsonb, 'operator', 100, current_date, current_date + 30, 'live');
-- offer_code #1: earned (untouched state)
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state)
VALUES ('70000000-0000-0000-0000-000000000001', '60000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned');
-- offer_code #2: REDEEMED, device-attached (B3's "seed ... redeemed rows").
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, activated_device_id, activated_at, redeemed_at, redeemed_by_staff)
VALUES ('70000000-0000-0000-0000-000000000002', '60000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-00000000000a', 'fac_x', 'redeemed', '20000000-0000-0000-0000-000000000001',
        now(), now(), '00000000-0000-0000-0000-1000000000a1');
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, local_date, status)
VALUES ('90000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
        'fac_x', 'trl_t', 'course_qr', 'rotating', current_date, 'valid');

INSERT INTO app.receipt_fingerprint (id, purchase_evidence_id, user_id, phash, facility_id, local_date)
VALUES ('80000000-0000-0000-0000-000000000001', '90000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-00000000000a', 'phash1', 'fac_x', current_date);

-- player_pseudonym = a KEYED HMAC of user_id (line 841), NOT of the
-- handle — it must stay derivable from user_id alone so delete_my_data
-- can find it without depending on a handle that may have since changed
-- (B3, gate round 2). ⛔ FIX (should-fix, post-P3a gate): this used to be
-- an unkeyed digest(), which is precomputable offline by anyone who can
-- guess/enumerate uids (they are not secret) — now hmac() with the same
-- `app.pseudonym_key` database-level setting shim.sql configures (which
-- private.delete_my_data, 0015, itself now reads), so a seeded fixture
-- pseudonym and a delete_my_data-COMPUTED one for the same uid are
-- guaranteed to match.
INSERT INTO app.attestation (id, facility_id, staff_user_id, staff_pseudonym, player_user_id, player_pseudonym, kind, token_jti, cosignal_ok)
VALUES ('a0000000-0000-0000-0000-000000000001', 'fac_x', '00000000-0000-0000-0000-1000000000a1',
        encode(hmac('00000000-0000-0000-0000-1000000000a1', current_setting('app.pseudonym_key'), 'sha256'), 'hex'),
        '00000000-0000-0000-0000-00000000000a',
        encode(hmac('00000000-0000-0000-0000-00000000000a', current_setting('app.pseudonym_key'), 'sha256'), 'hex'),
        'presence', 'jti-1', true);

INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, staff_handle)
VALUES ('fac_x', 'presence', 'player_a',
        encode(hmac('00000000-0000-0000-0000-00000000000a', current_setting('app.pseudonym_key'), 'sha256'), 'hex'),
        'staff_x_handle');

INSERT INTO app.staff_activity (staff_user_id, facility_id, day, attests, activations)
VALUES ('00000000-0000-0000-0000-1000000000a1', 'fac_x', current_date, 1, 0);

INSERT INTO app.marker_credit (id, user_id, trail_id, facility_id, purchase_evidence_id, status)
VALUES ('b0000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
        'trl_t', 'fac_x', '90000000-0000-0000-0000-000000000001', 'credited');

INSERT INTO app.special_marker_stock_movement (id, trail_id, facility_id, kind, qty, by_member)
VALUES ('c0000000-0000-0000-0000-000000000001', 'trl_t', 'fac_x', 'delivered', 5,
        '00000000-0000-0000-0000-2000000000b1');

INSERT INTO app.operator_rollup (trail_id, month, metric, value, cohort_n)
VALUES ('trl_t', date_trunc('month', now())::date, 'completions', 12, 10);

INSERT INTO app.sponsorship (id, sponsor_org_id, trail_id, category, scope, attribution_name, status)
VALUES ('d0000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000003',
        'trl_t', 'equipment', 'special_marker', 'Test Sponsor', 'approved');
INSERT INTO app.sponsor_rollup (sponsorship_id, month, metric, value, cohort_n)
VALUES ('d0000000-0000-0000-0000-000000000001', date_trunc('month', now())::date, 'markers_earned', 11, 10);

INSERT INTO app.connector_account (id, user_id, provider, external_user_id, refresh_token_ciphertext, dek_wrapped, kek_id)
VALUES ('e0000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
        'garmin', 'ext-1', '\xdeadbeef'::bytea, '\xdeadbeef'::bytea, 'kek-1');

INSERT INTO app.signin_provider_token (user_id, provider, refresh_token_ciphertext, dek_wrapped, kek_id)
VALUES ('00000000-0000-0000-0000-00000000000a', 'apple', '\xdeadbeef'::bytea, '\xdeadbeef'::bytea, 'kek-1');

INSERT INTO app.push_token (user_id, device_id, expo_token)
VALUES ('00000000-0000-0000-0000-00000000000a', '20000000-0000-0000-0000-000000000001', 'ExponentPushToken[test]');

INSERT INTO app.play_evidence (play_id, evidence_id)
VALUES ('40000000-0000-0000-0000-000000000001', '30000000-0000-0000-0000-000000000001');

-- M5 (post-P3a gate): player A's opted-in public projection row, so
-- delete_my_data's "public_profile_projection is removed" post-condition
-- has something real to actually remove, not merely nothing to fail to
-- find.
INSERT INTO app.public_profile_projection (handle) VALUES ('player_a');

INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version)
VALUES ('ach_first_round', 'achievement', 'verified', 1);
INSERT INTO app.catalog_achievement_def (id, trail_id, kind, min_confidence, catalog_version)
VALUES ('ach_first_round', 'trl_t', 'venue', 0.50, 1);
INSERT INTO app.user_achievement (user_id, achievement_id, award_key, basis)
VALUES ('00000000-0000-0000-0000-00000000000a', 'ach_first_round', '', '{}'::jsonb);

INSERT INTO app.booking (id, user_id, provider, provider_ref, facility_id, tee_time)
VALUES ('f0000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000a',
        'golfnow', 'ref-1', 'fac_x', now() + interval '1 day');

-- B3 gate-round-2 additions: partner_member / partner_invite / audit_log /
-- storage.objects rows for player A, so delete_my_data's coverage of each
-- is actually exercised, not merely asserted against nothing.
INSERT INTO app.partner_member (user_id, org_id, role, invited_by) VALUES
  ('00000000-0000-0000-0000-00000000000a', '10000000-0000-0000-0000-000000000001', 'staff',
   '00000000-0000-0000-0000-1000000000a1');
INSERT INTO app.partner_invite (id, org_id, role, invited_by, invitee_email, token_hash, expires_at) VALUES
  ('11100000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001', 'staff',
   '00000000-0000-0000-0000-00000000000a', 'staff-y@example.test', 'th-a-invites-y', now() + interval '7 days'),
  ('11100000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000002', 'staff',
   '00000000-0000-0000-0000-1000000000a3', 'player-a@example.test', 'th-y-invites-a', now() + interval '7 days');
INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id) VALUES
  ('00000000-0000-0000-0000-00000000000a', 'evidence.insert', 'app.evidence', '30000000-0000-0000-0000-000000000001');
-- M5 (post-P3a gate): a fraud_signal row for player A, so
-- delete_my_data's "fraud_signal.user_id is nulled" post-condition has
-- something real to actually null.
INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES
  ('00000000-0000-0000-0000-00000000000a', 'manual_review_seed', '{}'::jsonb);
INSERT INTO storage.objects (bucket_id, name, owner) VALUES
  ('receipts', 'receipts/00000000-0000-0000-0000-00000000000a/r1.jpg', '00000000-0000-0000-0000-00000000000a');

COMMIT;

-- Claim builder (tests.claims) moved to supabase/tests/shim.sql, next to
-- tests.authenticate_as/tests.clear_actor (S1, gate round 3): this file
-- now runs its fixture INSERTs as service_role (tools/db/test.sh, via
-- `SET ROLE`, not `SET LOCAL ROLE`, so it persists for this whole psql
-- session/connection, past this file's own COMMIT above) — a CREATE
-- FUNCTION here would need CREATE on schema `tests`, which only the
-- bootstrap role (schema owner) has, and would also miss the PUBLIC
-- EXECUTE that tests.authenticate_as/tests.clear_actor already get by
-- being created (in shim.sql) before 0001_schemas.sql's global
-- `ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` ever
-- runs. Grouping all three in shim.sql keeps that property for all of
-- them, not just two.
