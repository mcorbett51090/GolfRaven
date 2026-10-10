-- 43_rollups_refresh.sql
-- 0065_rollups_refresh.sql: edge_system refresh of operator/sponsor rollups with k-anonymity.
-- Inventory / allow-list reads run as service_role (FORCE RLS on the registry). Seed writes use
-- temporary CURRENT_USER policies (restricted harness: migration_owner has no BYPASSRLS).

\set QUIET 1
BEGIN;
SELECT plan(14);

GRANT edge_system TO CURRENT_USER WITH SET TRUE;
GRANT edge_actor TO CURRENT_USER WITH SET TRUE;
GRANT edge_partner TO CURRENT_USER WITH SET TRUE;

GRANT SELECT, INSERT, UPDATE, DELETE ON app.catalog_id_ledger, app.catalog_achievement_def,
  app.user_achievement, app.entitlement, app.operator_rollup, app.sponsor_rollup TO CURRENT_USER;
CREATE POLICY zz43_ledger ON app.catalog_id_ledger FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz43_achdef ON app.catalog_achievement_def FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz43_ua ON app.user_achievement FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz43_ent ON app.entitlement FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz43_or ON app.operator_rollup FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz43_sr ON app.sponsor_rollup FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

-- ----------------------------------------------------------------------------
-- 1. EXECUTE matrix + registries
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('edge_actor'), ('edge_partner'), ('edge_system'), ('service_role')) r(n)
   WHERE has_function_privilege(r.n, 'private.refresh_rollups(date)', 'EXECUTE')),
  ARRAY['edge_system'],
  'only edge_system may EXECUTE refresh_rollups (among edge roles; owner private_definer holds EXECUTE by ownership)'
);

SELECT ok(
  EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'entitlement' AND column_name = 'earned_at'),
  'app.entitlement.earned_at exists'
);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd_rollups_refresh_%'),
  11,
  'eleven rollups-refresh policies are in definer_policy_allowlist'
);
SELECT tests.clear_actor();

SAVEPOINT s43_root;

-- ----------------------------------------------------------------------------
-- 2. Sub-threshold: refresh removes seeded completions when cohort would be < 10
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s43_root;
SET LOCAL ROLE edge_system;
SELECT is(
  (SELECT o_operator_removed FROM private.refresh_rollups(date_trunc('month', timezone('UTC', now()))::date)),
  1,
  'refresh removes helpers completions row when live completion awards are below k-anonymity'
);
RESET ROLE;
SELECT is(
  (SELECT count(*)::int FROM app.operator_rollup WHERE trail_id = 'trl_t' AND metric = 'completions' AND month = date_trunc('month', timezone('UTC', now()))::date),
  0,
  'completions row absent after sub-threshold refresh'
);

-- ----------------------------------------------------------------------------
-- 3. Happy path: 10 distinct users with completion awards + markers_earned
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s43_root;

INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version)
VALUES ('ach_trl_t_completion', 'achievement', 'verified', 1)
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.catalog_achievement_def (id, trail_id, kind, min_confidence, catalog_version)
VALUES ('ach_trl_t_completion', 'trl_t', 'trail_completion', 0.50, 1)
ON CONFLICT (id) DO NOTHING;

-- Ten helper actors (not the demo account alone): enough for cohort_n = 10.
INSERT INTO app.user_achievement (user_id, achievement_id, award_key, awarded_at, basis)
SELECT u, 'ach_trl_t_completion', 'v1', timezone('UTC', now()), '{}'::jsonb
FROM unnest(ARRAY[
  '00000000-0000-0000-0000-00000000000a'::uuid,
  '00000000-0000-0000-0000-00000000000b'::uuid,
  '00000000-0000-0000-0000-1000000000a1'::uuid,
  '00000000-0000-0000-0000-1000000000a2'::uuid,
  '00000000-0000-0000-0000-1000000000a3'::uuid,
  '00000000-0000-0000-0000-2000000000b1'::uuid,
  '00000000-0000-0000-0000-2000000000b2'::uuid,
  '00000000-0000-0000-0000-3000000000c1'::uuid,
  '00000000-0000-0000-0000-3000000000c2'::uuid,
  '00000000-0000-0000-0000-4000000000d0'::uuid
]) AS u
ON CONFLICT (user_id, achievement_id, award_key) DO UPDATE SET awarded_at = EXCLUDED.awarded_at, revoked_at = NULL;

-- Player A already holds trl_t entitlement: attach the helpers sponsorship.
UPDATE app.entitlement
SET sponsorship_id = 'd0000000-0000-0000-0000-000000000001',
    earned_at = timezone('UTC', now())
WHERE id = '50000000-0000-0000-0000-000000000001';

INSERT INTO app.entitlement (id, user_id, kind, trail_id, sponsorship_id, state, earned_at)
SELECT
  ('51000000-0000-0000-0000-0000000000' || lpad(i::text, 2, '0'))::uuid,
  u,
  'special_marker',
  'trl_v',
  'd0000000-0000-0000-0000-000000000001',
  'earned',
  timezone('UTC', now())
FROM unnest(ARRAY[
  '00000000-0000-0000-0000-00000000000b'::uuid,
  '00000000-0000-0000-0000-1000000000a1'::uuid,
  '00000000-0000-0000-0000-1000000000a2'::uuid,
  '00000000-0000-0000-0000-1000000000a3'::uuid,
  '00000000-0000-0000-0000-2000000000b1'::uuid,
  '00000000-0000-0000-0000-2000000000b2'::uuid,
  '00000000-0000-0000-0000-3000000000c1'::uuid,
  '00000000-0000-0000-0000-3000000000c2'::uuid,
  '00000000-0000-0000-0000-4000000000d0'::uuid
]) WITH ORDINALITY AS t(u, i)
ON CONFLICT (user_id, kind, trail_id) DO UPDATE
SET sponsorship_id = EXCLUDED.sponsorship_id, earned_at = EXCLUDED.earned_at, state = 'earned';

SET LOCAL ROLE edge_system;
SELECT ok(
  (SELECT o_operator_written FROM private.refresh_rollups(date_trunc('month', timezone('UTC', now()))::date)) >= 1,
  'refresh writes operator completions when cohort_n >= 10'
);
SELECT ok(
  (SELECT o_sponsor_written FROM private.refresh_rollups(date_trunc('month', timezone('UTC', now()))::date)) >= 1,
  'refresh writes sponsor markers_earned when cohort_n >= 10'
);
RESET ROLE;

SELECT is(
  (SELECT cohort_n FROM app.operator_rollup
   WHERE trail_id = 'trl_t' AND metric = 'completions' AND month = date_trunc('month', timezone('UTC', now()))::date),
  10,
  'operator completions cohort_n is 10'
);
SELECT is(
  (SELECT value::int FROM app.operator_rollup
   WHERE trail_id = 'trl_t' AND metric = 'completions' AND month = date_trunc('month', timezone('UTC', now()))::date),
  10,
  'operator completions value is 10 awards'
);
SELECT is(
  (SELECT cohort_n FROM app.sponsor_rollup
   WHERE sponsorship_id = 'd0000000-0000-0000-0000-000000000001'
     AND metric = 'markers_earned'
     AND month = date_trunc('month', timezone('UTC', now()))::date),
  10,
  'sponsor markers_earned cohort_n is 10'
);

-- ----------------------------------------------------------------------------
-- 4. Drop below threshold: revoke awards -> completions row removed
-- ----------------------------------------------------------------------------
UPDATE app.user_achievement
SET revoked_at = timezone('UTC', now())
WHERE achievement_id = 'ach_trl_t_completion'
  AND user_id IN (
    '00000000-0000-0000-0000-3000000000c1',
    '00000000-0000-0000-0000-3000000000c2',
    '00000000-0000-0000-0000-4000000000d0'
  );

SET LOCAL ROLE edge_system;
SELECT is(
  (SELECT o_operator_removed FROM private.refresh_rollups(date_trunc('month', timezone('UTC', now()))::date)),
  1,
  'refresh removes completions when cohort drops below 10'
);
RESET ROLE;
SELECT is(
  (SELECT count(*)::int FROM app.operator_rollup
   WHERE trail_id = 'trl_t' AND metric = 'completions' AND month = date_trunc('month', timezone('UTC', now()))::date),
  0,
  'completions gone after cohort drop'
);

-- ----------------------------------------------------------------------------
-- 5. Other roles cannot call
-- ----------------------------------------------------------------------------
ROLLBACK TO SAVEPOINT s43_root;
SET LOCAL ROLE edge_actor;
SELECT throws_ok(
  $$SELECT * FROM private.refresh_rollups(NULL)$$,
  '42501',
  NULL,
  'edge_actor cannot EXECUTE refresh_rollups'
);
RESET ROLE;

SET LOCAL ROLE edge_partner;
SELECT throws_ok(
  $$SELECT * FROM private.refresh_rollups(NULL)$$,
  '42501',
  NULL,
  'edge_partner cannot EXECUTE refresh_rollups'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
