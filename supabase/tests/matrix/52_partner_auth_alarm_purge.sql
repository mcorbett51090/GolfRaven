-- 52_partner_auth_alarm_purge.sql
-- 0074_partner_auth_alarm_purge.sql (P5 §60): edge_system purge for
-- partner_auth_alarm (90 d past raised_at). Proved here:
--   1. structure / ACLs (edge_system only; InitPlan ANY ARRAY batch; floors);
--   2. purge / keep / idempotent;
--   3. edge_actor / anon cannot EXECUTE.
-- Every group is its own BEGIN ... ROLLBACK.
-- Restricted harness: inventory via authenticate_as inside a transaction.

SELECT plan(12);

CREATE FUNCTION pg_temp.can_exec(p_role text, p_names text[]) RETURNS int LANGUAGE sql STABLE AS $f$
  SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = ANY (p_names) AND has_function_privilege(p_role, p.oid, 'EXECUTE')
$f$;

CREATE FUNCTION pg_temp.purge_as(p_role text, p_name text) RETURNS bigint LANGUAGE plpgsql AS $f$
DECLARE v bigint;
BEGIN
  EXECUTE format('SET LOCAL ROLE %I', p_role);
  EXECUTE format('SELECT private.%I()', p_name) INTO v;
  RESET ROLE;
  RETURN v;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Structure and privileges
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.can_exec('edge_system', ARRAY['purge_partner_auth_alarms']), 1,
  'privileges: edge_system CAN run purge_partner_auth_alarms');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['purge_partner_auth_alarms'])
        + pg_temp.can_exec('edge_partner', ARRAY['purge_partner_auth_alarms'])
        + pg_temp.can_exec('anon', ARRAY['purge_partner_auth_alarms'])
        + pg_temp.can_exec('authenticated', ARRAY['purge_partner_auth_alarms'])
        + pg_temp.can_exec('service_role', ARRAY['purge_partner_auth_alarms']), 0,
  'privileges: nobody else may EXECUTE it');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname = 'purge_partner_auth_alarms'
             AND p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer' AND 'search_path=""' = ANY (p.proconfig)
             AND p.prosrc ~ 'v_limit constant int := 5000' AND p.prosrc ~ '= ANY \(ARRAY\('), 1,
  'structure: SECURITY DEFINER / private_definer / search_path='''' / constant 5000 / InitPlan ANY ARRAY');
SELECT is((SELECT count(*)::int FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'app' AND pol.polname LIKE 'pd\_purge\_partner\_auth\_alarm%'), 2,
  'structure: two purge policies (DELETE + SELECT companion)');
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.function_inventory
           WHERE function_name = 'purge_partner_auth_alarms'
             AND expected_edge_system AND NOT expected_edge_actor AND NOT expected_service_role), 1,
  'inventory: one row, edge_system only');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 2. purge / keep / idempotent
-- ----------------------------------------------------------------------------
BEGIN;
GRANT SELECT, INSERT, DELETE ON app.partner_auth_alarm TO CURRENT_USER;
CREATE POLICY zz52_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO app.partner_auth_alarm (kind, credential_id, minute_bucket, raised_at) VALUES
  ('signature_invalid', 'a1000000-0000-0000-0000-000000000052', 1, now() - interval '200 days'),
  ('counter_regression', 'a1000000-0000-0000-0000-000000000052', 2, now() - interval '100 days'),
  ('signature_invalid', 'a1000000-0000-0000-0000-000000000052', 3, now() - interval '10 days'),
  ('counter_regression', 'b2000000-0000-0000-0000-000000000052', 4, now() - interval '5 days');
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_auth_alarms')::int, 2,
  'purge_partner_auth_alarms deletes alarms raised more than 90 days ago');
SELECT is((SELECT count(*)::int FROM app.partner_auth_alarm
           WHERE credential_id IN ('a1000000-0000-0000-0000-000000000052', 'b2000000-0000-0000-0000-000000000052')),
  2, '... and keeps the two younger than 90 days');
SELECT is(pg_temp.purge_as('edge_system', 'purge_partner_auth_alarms')::int, 0,
  'a second alarm purge is idempotent');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_partner_auth_alarms' AND p.prosrc ~ 'interval ''90 days'''), 1,
  'alarm purge body carries the 90-day floor');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_purge_partner_auth_alarm'
             AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%90 days%'), 1,
  'DELETE policy repeats the 90-day floor');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. Refusal
-- ----------------------------------------------------------------------------
BEGIN;
GRANT edge_actor TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.purge_partner_auth_alarms()$$, '42501', NULL, 'edge_actor cannot run purge_partner_auth_alarms');
RESET ROLE;
SET LOCAL ROLE anon;
SELECT throws_ok($$SELECT private.purge_partner_auth_alarms()$$, '42501', NULL, 'anon cannot run purge_partner_auth_alarms');
RESET ROLE;
ROLLBACK;

SELECT * FROM finish();
