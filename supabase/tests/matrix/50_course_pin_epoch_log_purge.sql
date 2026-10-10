-- 50_course_pin_epoch_log_purge.sql
-- 0072_course_pin_epoch_log_purge.sql (P5 §58): edge_system purge for
-- course_pin_epoch_log (90 d past effective_from; latest epoch per facility
-- always kept). Proved here:
--   1. structure / ACLs (edge_system only; FOR-loop composite batch; floors);
--   2. purge / keep / idempotent; latest-per-facility never deleted;
--   3. edge_actor / anon cannot EXECUTE.
-- Every group is its own BEGIN ... ROLLBACK. No secret: synthetic ids fac_50*.
-- Restricted harness: inventory via authenticate_as inside a transaction;
-- epoch_log seeded through a temporary CURRENT_USER policy (SELECT-only for
-- service_role; matrix 32 / 49 pattern).

SELECT plan(17);

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
SELECT is(pg_temp.can_exec('edge_system', ARRAY['purge_course_pin_epoch_log']), 1,
  'privileges: edge_system CAN run purge_course_pin_epoch_log');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['purge_course_pin_epoch_log'])
        + pg_temp.can_exec('edge_partner', ARRAY['purge_course_pin_epoch_log'])
        + pg_temp.can_exec('anon', ARRAY['purge_course_pin_epoch_log'])
        + pg_temp.can_exec('authenticated', ARRAY['purge_course_pin_epoch_log'])
        + pg_temp.can_exec('service_role', ARRAY['purge_course_pin_epoch_log']), 0,
  'privileges: nobody else may EXECUTE it');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname = 'purge_course_pin_epoch_log'
             AND p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer' AND 'search_path=""' = ANY (p.proconfig)
             AND p.prosrc ~ 'v_limit constant int := 5000' AND p.prosrc ~ 'FOR v_row IN'), 1,
  'structure: SECURITY DEFINER / private_definer / search_path='''' / constant 5000 / FOR-loop composite batch');
SELECT is((SELECT count(*)::int FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'app' AND pol.polname LIKE 'pd\_purge\_course\_pin\_epoch\_log%'), 2,
  'structure: two purge policies (DELETE + SELECT companion)');
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.function_inventory
           WHERE function_name = 'purge_course_pin_epoch_log'
             AND expected_edge_system AND NOT expected_edge_actor AND NOT expected_service_role), 1,
  'inventory: one row, edge_system only');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 2. purge / keep / keep-latest / idempotent
-- ----------------------------------------------------------------------------
BEGIN;
GRANT SELECT, INSERT, DELETE ON app.course_pin_epoch_log TO CURRENT_USER;
CREATE POLICY zz50_epoch_log ON app.course_pin_epoch_log FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
-- helpers.sql facilities (fac_x / fac_y). High pin_epoch avoids collisions.
INSERT INTO app.course_pin_epoch_log (facility_id, pin_epoch, previous_epoch, effective_from) VALUES
  -- fac_x: two old superseded + a recent latest → purge the two old
  ('fac_x', 501, 500, now() - interval '200 days'),
  ('fac_x', 502, 501, now() - interval '100 days'),
  ('fac_x', 503, 502, now() - interval '10 days'),
  -- fac_y: two old rows, latest is still old → purge 501, keep 502
  ('fac_y', 501, 500, now() - interval '120 days'),
  ('fac_y', 502, 501, now() - interval '100 days');
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_epoch_log')::int, 3,
  'purge_course_pin_epoch_log deletes exactly three superseded rows older than 90 days');
SELECT is((SELECT array_agg(facility_id || ':' || pin_epoch ORDER BY facility_id, pin_epoch)
           FROM app.course_pin_epoch_log WHERE facility_id IN ('fac_x', 'fac_y') AND pin_epoch BETWEEN 501 AND 503),
  ARRAY['fac_x:503', 'fac_y:502'],
  '... keeps the recent latest on fac_x and the old-but-latest on fac_y');
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_epoch_log')::int, 0,
  'a second epoch-log purge is idempotent');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. Role refusals
-- ----------------------------------------------------------------------------
BEGIN;
GRANT edge_actor TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.purge_course_pin_epoch_log()$$, '42501', NULL, 'edge_actor cannot run purge_course_pin_epoch_log');
ROLLBACK;

BEGIN;
GRANT edge_partner TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.purge_course_pin_epoch_log()$$, '42501', NULL, 'edge_partner cannot run purge_course_pin_epoch_log');
ROLLBACK;

BEGIN;
SET LOCAL ROLE anon;
SELECT throws_ok($$SELECT private.purge_course_pin_epoch_log()$$, '42501', NULL, 'anon cannot run purge_course_pin_epoch_log');
ROLLBACK;

-- floors in body + policies
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_course_pin_epoch_log' AND p.prosrc ~ 'interval ''90 days'''), 1, 'body carries the 90-day floor');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_course_pin_epoch_log' AND p.prosrc ~ 'max\(l\.pin_epoch\)'), 1, 'body keeps the latest epoch per facility');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_purge_course_pin_epoch_log' AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%90 days%'), 1, 'DELETE policy repeats the 90-day floor');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_purge_course_pin_epoch_log' AND pg_get_expr(pol.polqual, pol.polrelid) NOT LIKE '%max%'), 1, 'DELETE policy has no same-table keep-latest subquery (would recurse under FORCE RLS)');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_purge_course_pin_epoch_log_r'), 1, 'SELECT companion policy exists');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_course_pin_epoch_log' AND p.prosrc ~ 'v_limit constant int := 5000'), 1, 'body carries the 5000 batch bound');

SELECT * FROM finish();
