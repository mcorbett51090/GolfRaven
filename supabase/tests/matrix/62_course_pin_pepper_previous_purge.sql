-- 62_course_pin_pepper_previous_purge.sql
-- 0084_course_pin_pepper_previous_purge.sql (P5 §71): edge_system wrapper
-- that calls private.course_pin_pepper_rotate('retire_previous'). Proved:
--   1. structure / ACLs (edge_system EXECUTE on purge; rotate still no edge);
--   2. too_early → 0; after 7d → 1 and previous gone; previous_absent → 0;
--   3. audit stays operator.course_pin_pepper.rotate (no system.* invent);
--   4. edge_actor / anon cannot EXECUTE.
-- Every group is its own BEGIN ... ROLLBACK.
-- Restricted harness: inventory via authenticate_as inside a transaction.

SELECT plan(14);

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
SELECT is(pg_temp.can_exec('edge_system', ARRAY['purge_course_pin_pepper_previous']), 1,
  'privileges: edge_system CAN run purge_course_pin_pepper_previous');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['purge_course_pin_pepper_previous'])
        + pg_temp.can_exec('edge_partner', ARRAY['purge_course_pin_pepper_previous'])
        + pg_temp.can_exec('anon', ARRAY['purge_course_pin_pepper_previous'])
        + pg_temp.can_exec('authenticated', ARRAY['purge_course_pin_pepper_previous'])
        + pg_temp.can_exec('service_role', ARRAY['purge_course_pin_pepper_previous']), 0,
  'privileges: nobody else may EXECUTE the purge wrapper');
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n)
   FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'),
                ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
   WHERE has_function_privilege(r.n, 'private.course_pin_pepper_rotate(text)'::regprocedure, 'EXECUTE')),
  NULL,
  'EXECUTE: rotate still has NO edge/client/service_role grant (wrapper only)'
);
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname = 'purge_course_pin_pepper_previous'
             AND p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer' AND 'search_path=""' = ANY (p.proconfig)
             AND p.prosrc ~ 'course_pin_pepper_rotate' AND p.prosrc ~ 'retire_previous'), 1,
  'structure: SECURITY DEFINER / private_definer / search_path='''' / calls retire_previous');
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.function_inventory
           WHERE function_name = 'purge_course_pin_pepper_previous'
             AND expected_edge_system AND NOT expected_edge_actor AND NOT expected_service_role
             AND NOT expected_edge_partner AND NOT expected_edge_partner_minter), 1,
  'inventory: one row, expected_edge_system only');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 2. Status → count mapping (too_early / ok / previous_absent)
-- ----------------------------------------------------------------------------
BEGIN;
GRANT private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON vault.secrets TO CURRENT_USER;
GRANT SELECT ON vault.decrypted_secrets TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.course_pin_pepper_epoch, app.audit_log TO CURRENT_USER;
CREATE POLICY zz62_pepper_epoch ON app.course_pin_pepper_epoch FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz62_audit ON app.audit_log FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

DELETE FROM vault.secrets WHERE name IN ('course_pin_pepper', 'course_pin_pepper_previous');
DELETE FROM app.course_pin_pepper_epoch;
DELETE FROM app.audit_log WHERE action = 'operator.course_pin_pepper.rotate';
INSERT INTO vault.secrets (name, secret) VALUES
  ('course_pin_pepper', repeat('e', 40)),
  ('course_pin_pepper_previous', repeat('f', 40));
INSERT INTO app.course_pin_pepper_epoch (effective_from, recorded_at)
VALUES (now() - interval '1 day', now() - interval '1 day');

GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_pepper_previous')::int, 0,
  'too_early → 0');
SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'course_pin_pepper_previous'), 1,
  'too_early: previous still present');

DELETE FROM app.course_pin_pepper_epoch;
INSERT INTO app.course_pin_pepper_epoch (effective_from, recorded_at)
VALUES (now() - interval '8 days', now() - interval '8 days');

SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_pepper_previous')::int, 1,
  'after 7d → 1');
SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'course_pin_pepper_previous'), 0,
  'after 7d: previous gone');
SELECT is((SELECT count(*)::int FROM app.audit_log
           WHERE action = 'operator.course_pin_pepper.rotate' AND detail->>'mode' = 'retire_previous'), 1,
  'ok path: one operator.course_pin_pepper.rotate audit (no system.* invent)');

SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_pepper_previous')::int, 0,
  'previous_absent → 0');
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_pepper_previous')::int, 0,
  'previous_absent again is idempotent (still 0)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. Refusal
-- ----------------------------------------------------------------------------
BEGIN;
GRANT edge_actor TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.purge_course_pin_pepper_previous()$$, '42501', NULL,
  'edge_actor cannot run purge_course_pin_pepper_previous');
RESET ROLE;
SET LOCAL ROLE anon;
SELECT throws_ok($$SELECT private.purge_course_pin_pepper_previous()$$, '42501', NULL,
  'anon cannot run purge_course_pin_pepper_previous');
RESET ROLE;
ROLLBACK;

SELECT * FROM finish();
