-- 39_at10_issuance_staff_gate.sql
-- P5.1b / 0061: AT(10) ISSUANCE STAFF GATE. A facility with no active staff/manager cannot
-- first-issue an earned offer_code (held_review / heldFor=no_active_staff). Happy path on fac_x
-- still issues. Already-issued re-activate is not gated. Approve that would issue is refused.
--
-- HOW THIS FILE RUNS. One transaction, rolled back at the end. Calls app.activate_offer_code /
-- app.resolve_held_offer_code as service_role (the EXECUTE surface). Inventory / grant cells as
-- service_role. Partner apply status cell binds an admin with A3.

\set QUIET 1
BEGIN;
SELECT plan(14);

GRANT private_definer TO CURRENT_USER WITH SET TRUE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ----------------------------------------------------------------------------
-- 0. Setup: facility with no active staff (org + scope, only a revoked member)
-- ----------------------------------------------------------------------------
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version)
VALUES ('fac_z', 'facility', 'verified', 1);
INSERT INTO app.catalog_facility (id, slug, name, region, tz, catalog_version)
VALUES ('fac_z', 'facility-z', 'Facility Z', 'US-TN', 'America/Chicago', 1);
INSERT INTO app.partner_org (id, kind, name)
VALUES ('10000000-0000-0000-0000-0000000000z1', 'facility', 'Facility Z Pro Shop');
INSERT INTO app.partner_scope (org_id, facility_id)
VALUES ('10000000-0000-0000-0000-0000000000z1', 'fac_z');
INSERT INTO app.partner_member (user_id, org_id, role, revoked_at)
VALUES ('00000000-0000-0000-0000-1000000000a1', '10000000-0000-0000-0000-0000000000z1', 'staff', now());

INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status) VALUES
  ('61000000-0000-0000-0000-0000000000z1', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'),
  ('61000000-0000-0000-0000-0000000000z2', 'trl_t', 'fac_z', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'),
  ('61000000-0000-0000-0000-0000000000z3', 'trl_t', 'fac_z', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live'),
  ('61000000-0000-0000-0000-0000000000z4', 'trl_t', 'fac_z', '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live');

INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at) VALUES
  ('71000000-0000-0000-0000-0000000000z1', '61000000-0000-0000-0000-0000000000z1', '00000000-0000-0000-0000-00000000000a', 'fac_x', 'earned', now() - interval '1 day', now() + interval '20 days'),
  ('71000000-0000-0000-0000-0000000000z2', '61000000-0000-0000-0000-0000000000z2', '00000000-0000-0000-0000-00000000000a', 'fac_z', 'earned', now() - interval '1 day', now() + interval '20 days'),
  ('71000000-0000-0000-0000-0000000000z3', '61000000-0000-0000-0000-0000000000z3', '00000000-0000-0000-0000-00000000000a', 'fac_z', 'issued', now() - interval '1 day', now() + interval '20 days'),
  ('71000000-0000-0000-0000-0000000000z4', '61000000-0000-0000-0000-0000000000z4', '00000000-0000-0000-0000-00000000000a', 'fac_z', 'held_review', now() - interval '1 day', now() + interval '20 days');

-- Plant device + token on the issued and held codes so re-activate / approve-to-issue are meaningful.
UPDATE app.offer_code SET
  activated_device_id = '20000000-0000-0000-0000-000000000001',
  devicecheck_token_hash = 'tok-z3',
  activated_at = now() - interval '1 hour',
  reserved_amount = 10
WHERE id = '71000000-0000-0000-0000-0000000000z3';
UPDATE app.offer SET budget_reserved = budget_reserved + 10 WHERE id = '61000000-0000-0000-0000-0000000000z3';

UPDATE app.offer_code SET
  activated_device_id = '20000000-0000-0000-0000-000000000001',
  devicecheck_token_hash = 'tok-z4',
  activated_at = now() - interval '1 hour',
  hold_detail = jsonb_build_object('heldFor', 'no_active_staff'),
  reserved_amount = 10,
  expiry_paused_at = now()
WHERE id = '71000000-0000-0000-0000-0000000000z4';
UPDATE app.offer SET budget_reserved = budget_reserved + 10 WHERE id = '61000000-0000-0000-0000-0000000000z4';

-- ----------------------------------------------------------------------------
-- 1. Helper + grants
-- ----------------------------------------------------------------------------
SELECT ok(private.facility_has_active_staff('fac_x'), 'fac_x has active staff/manager');
SELECT ok(NOT private.facility_has_active_staff('fac_z'), 'fac_z has no active staff/manager (revoked only)');
SELECT ok(has_function_privilege('service_role', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE'), 'service_role EXECUTEs facility_has_active_staff');
SELECT ok(has_function_privilege('private_definer', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE'), 'private_definer EXECUTEs facility_has_active_staff');
SELECT ok(NOT has_function_privilege('edge_actor', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE'), 'edge_actor cannot EXECUTE facility_has_active_staff');
SELECT ok(
  (SELECT expected_service_role AND NOT expected_edge_actor AND NOT expected_edge_partner
   FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'facility_has_active_staff'),
  'inventory: facility_has_active_staff is service_role only (not edge)');

-- ----------------------------------------------------------------------------
-- 2. Activate path
-- ----------------------------------------------------------------------------
SELECT is(
  app.activate_offer_code(
    '71000000-0000-0000-0000-0000000000z1', '00000000-0000-0000-0000-00000000000a',
    '20000000-0000-0000-0000-000000000001', 'tok-z1', 'activate'),
  'issued'::app.offer_code_state,
  'AT(10) happy: earned at fac_x (active staff) issues');

SELECT is(
  app.activate_offer_code(
    '71000000-0000-0000-0000-0000000000z2', '00000000-0000-0000-0000-00000000000a',
    '20000000-0000-0000-0000-000000000001', 'tok-z2', 'activate'),
  'held_review'::app.offer_code_state,
  'AT(10): earned at fac_z (no active staff) is held_review');

SELECT is(
  (SELECT hold_detail ->> 'heldFor' FROM app.offer_code WHERE id = '71000000-0000-0000-0000-0000000000z2'),
  'no_active_staff',
  'AT(10): hold_detail.heldFor = no_active_staff');

SELECT is(
  app.activate_offer_code(
    '71000000-0000-0000-0000-0000000000z3', '00000000-0000-0000-0000-00000000000a',
    '20000000-0000-0000-0000-000000000001', 'tok-z3b', 'activate'),
  'issued'::app.offer_code_state,
  'AT(10): already-issued re-activate at fac_z is NOT gated (stays issued)');

-- ----------------------------------------------------------------------------
-- 3. Resolve path (approve would issue)
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$SELECT app.resolve_held_offer_code(
      '71000000-0000-0000-0000-0000000000z4', true, '00000000-0000-0000-0000-4000000000d0')$$,
  '23514',
  'resolve_held_offer_code: facility fac_z has no active staff; cannot issue (AT(10) no_active_staff)',
  'AT(10): approve that would issue without active staff raises 23514');

SELECT is(
  (SELECT state::text FROM app.offer_code WHERE id = '71000000-0000-0000-0000-0000000000z4'),
  'held_review',
  'AT(10): refused approve leaves the code held');

-- Partner apply maps the same refusal to status no_active_staff (EXECUTE: owner only).
SET LOCAL ROLE private_definer;
SELECT is(
  (SELECT o_status FROM private.partner_resolve_held_offer_code_apply(
     '71000000-0000-0000-0000-0000000000z4', true, '00000000-0000-0000-0000-4000000000d0')),
  'no_active_staff',
  'AT(10): partner apply maps the refusal to status no_active_staff');
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
