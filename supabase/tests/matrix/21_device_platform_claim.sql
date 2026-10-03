-- 21_device_platform_claim.sql
-- 0042: app.device.platform is NULL (unknown) for a device first seen by an endpoint that carries no platform, and the first platform-bearing
-- use sets it through private.claim_device_platform_for_actor (first wins). Proven AS A REAL `edge_gateway` login that SET LOCAL ROLEs into
-- `edge_actor` and binds an actor with private.bind_actor, exactly as 17_attest_key_registration_edge.sql (read its header: `SET ROLE` is
-- judged by the SESSION user, so every assertion lives in the edge_gateway session, reached by `\c`).
--
-- ⛔ WATCH (the silent class edge_actor introduces): under RLS an UPDATE with no matching policy affects ZERO rows and raises nothing, so every
-- "it was set" claim below is proven by READING the row back.
-- All ids start ee210000-; UA is the actor, UB someone else. Re-runnable on the same cluster.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset

-- ============================================================================
-- PHASE 0: seed (harness role -> service_role; committed)
-- ============================================================================
SET ROLE service_role;
BEGIN;
INSERT INTO auth.users (id) VALUES
  ('ee210000-0000-0000-0000-0000000000a0'),
  ('ee210000-0000-0000-0000-0000000000b0')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.profile (user_id, handle) VALUES
  ('ee210000-0000-0000-0000-0000000000a0', 'edge21_ua'),
  ('ee210000-0000-0000-0000-0000000000b0', 'edge21_ub');
-- UA: a1, a2 unknown (a3 too, for the no-actor / delegate cells), a4 'ios', a5 'android'. UB: b1 unknown.
INSERT INTO app.device (id, user_id, platform) VALUES
  ('ee210000-0000-0000-0000-00000000a001', 'ee210000-0000-0000-0000-0000000000a0', NULL),
  ('ee210000-0000-0000-0000-00000000a002', 'ee210000-0000-0000-0000-0000000000a0', NULL),
  ('ee210000-0000-0000-0000-00000000a003', 'ee210000-0000-0000-0000-0000000000a0', NULL),
  ('ee210000-0000-0000-0000-00000000a004', 'ee210000-0000-0000-0000-0000000000a0', 'ios'),
  ('ee210000-0000-0000-0000-00000000a005', 'ee210000-0000-0000-0000-0000000000a0', 'android'),
  ('ee210000-0000-0000-0000-00000000b001', 'ee210000-0000-0000-0000-0000000000b0', NULL);
INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) VALUES
  ('ee210000-0000-0000-0000-0000000a0e03', 'ee210000-0000-0000-0000-0000000000a0', 'ee210000-0000-0000-0000-00000000a004', 'foreground_checkin', 'edge21-a-queued', 'h-21a3', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb);
COMMIT;
RESET ROLE;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(39);

CREATE FUNCTION pg_temp.rows(p_sql text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  v_n int;
BEGIN
  EXECUTE p_sql;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$f$;
-- Privilege probes by OID (this session has no USAGE on app/private, so names as TEXT would fail at resolution).
CREATE FUNCTION pg_temp.col_priv(p_role text, p_col text, p_priv text) RETURNS boolean LANGUAGE sql AS $f$
  SELECT has_column_privilege(p_role, c.oid, p_col, p_priv) FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device'
$f$;
CREATE FUNCTION pg_temp.fn_priv(p_role text, p_schema text, p_name text) RETURNS boolean LANGUAGE sql AS $f$
  SELECT has_function_privilege(p_role, p.oid, 'EXECUTE') FROM pg_proc p WHERE p.pronamespace = p_schema::regnamespace AND p.proname = p_name
$f$;

-- ============================================================================
-- 1. Nothing bound: the definer refuses
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a001', 'android')$$,
  '42501', 'claim_device_platform_for_actor: no actor is bound in this transaction', 'unbound: the definer refuses');
ROLLBACK;

-- ============================================================================
-- 2. Bound as UA: first wins, never changes a set platform
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee210000-0000-0000-0000-0000000000a0')$$, 'bind UA');
SELECT is((SELECT platform IS NULL FROM app.device WHERE id = 'ee210000-0000-0000-0000-00000000a001'), true, 'control: a1 starts unknown (NULL), read as UA');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a001', 'android'), 'android', 'an unknown device claimed as android: android is on record');
SELECT is((SELECT platform FROM app.device WHERE id = 'ee210000-0000-0000-0000-00000000a001'), 'android', 'and it was REALLY written (read back, not an RLS no-op)');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a001', 'ios'), 'android', 'FIRST WINS: a later ios claim returns android and changes nothing');
SELECT is((SELECT platform FROM app.device WHERE id = 'ee210000-0000-0000-0000-00000000a001'), 'android', 'read back: still android');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a001', 'android'), 'android', 'the same claim again is idempotent');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a002', 'ios'), 'ios', 'another unknown device, claimed ios: ios');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a004', 'android'), 'ios', 'a device already ios is NOT relabelled android');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a005', 'ios'), 'android', 'a device already android is NOT relabelled ios');
SELECT is((SELECT platform FROM app.device WHERE id = 'ee210000-0000-0000-0000-00000000a004') || ',' || (SELECT platform FROM app.device WHERE id = 'ee210000-0000-0000-0000-00000000a005'), 'ios,android', 'read back: a4 ios, a5 android untouched');
-- Shape and ownership.
SELECT throws_ok($$SELECT private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a003', 'windows')$$, '22023', NULL, 'a platform that is not ios/android is refused (22023)');
SELECT throws_ok($$SELECT private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a003', NULL)$$, '22023', NULL, 'a NULL platform is refused');
SELECT throws_ok($$SELECT private.claim_device_platform_for_actor(NULL, 'ios')$$, '22023', NULL, 'a NULL device is refused');
SELECT is((SELECT platform IS NULL FROM app.device WHERE id = 'ee210000-0000-0000-0000-00000000a003'), true, 'read back: a3 is still unknown after the refusals');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000b001', 'android'), NULL::text, 'UB''s device answers NULL for UA (the actor-keyed policies hide it from the definer), and raises nothing: the caller''s transaction stays usable');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000dead', 'android'), NULL::text, 'a nonexistent device is the same NULL');
-- No direct path.
SELECT throws_ok($$UPDATE app.device SET platform = 'ios' WHERE id = 'ee210000-0000-0000-0000-00000000a003'$$, '42501', NULL, 'direct: edge_actor cannot UPDATE platform (no column grant)');
SELECT throws_ok($$UPDATE app.device SET platform = 'ios' WHERE id = 'ee210000-0000-0000-0000-00000000a001'$$, '42501', NULL, 'direct: nor relabel a set one');
-- ensureOwn's INSERT still works with an unknown platform, and the CHECK still bounds the column.
SELECT lives_ok($$INSERT INTO app.device (id, user_id, platform) VALUES ('ee210000-0000-0000-0000-00000000a0f1', 'ee210000-0000-0000-0000-0000000000a0', NULL)$$, 'edge_actor can INSERT a device with an unknown (NULL) platform: what ensureOwn(id, null) does now');
SELECT throws_ok($$INSERT INTO app.device (id, user_id, platform) VALUES ('ee210000-0000-0000-0000-00000000a0f2', 'ee210000-0000-0000-0000-0000000000a0', 'windows')$$, '23514', NULL, 'the CHECK still refuses any other platform');
ROLLBACK;

-- ============================================================================
-- 3. Bound as UB: UA's devices are invisible and untouched
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee210000-0000-0000-0000-0000000000b0')$$, 'bind UB');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a001', 'android'), NULL::text, 'UB cannot claim a platform on UA''s device (NULL, nothing written)');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'ee210000-0000-0000-0000-0000000000a0'), 0, 'UA''s devices are invisible to UB');
SELECT is(private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000b001', 'ios'), 'ios', 'control: UB claims on UB''s own device');
ROLLBACK;
-- ...and UA's devices really are untouched (the ROLLBACKs held).
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee210000-0000-0000-0000-0000000000a0')$$, 'bind UA again');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'ee210000-0000-0000-0000-0000000000a0' AND platform IS NULL), 3, 'UA still has its three unknown devices (a1-a3): nothing leaked across the rollbacks');
ROLLBACK;

-- ============================================================================
-- 4. A system delegate may not claim
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('ee210000-0000-0000-0000-0000000a0e03'), 'ee210000-0000-0000-0000-0000000000a0'::uuid, 'delegate: edge_system binds the owner of a queued row');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a003', 'ios')$$,
  '42501', 'claim_device_platform_for_actor: a system delegate may not claim a platform', 'delegate: a system-delegate binding cannot claim');
ROLLBACK;

-- ============================================================================
-- 5. A binding does not outlive its transaction
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee210000-0000-0000-0000-0000000000a0')$$, 'stale: bind UA in transaction 1 ...');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.claim_device_platform_for_actor('ee210000-0000-0000-0000-00000000a003', 'ios')$$,
  '42501', 'claim_device_platform_for_actor: no actor is bound in this transaction', 'stale: ... and in transaction 2 a stale binding does not claim');
ROLLBACK;

-- ============================================================================
-- 6. Posture: nothing was broadened
-- ============================================================================
SELECT is(pg_temp.col_priv('edge_actor', 'platform', 'UPDATE'), false, 'edge_actor holds NO UPDATE on app.device.platform');
SELECT is(pg_temp.col_priv('edge_actor', 'platform', 'INSERT'), true, 'control: it keeps INSERT on platform (ensureOwn)');
SELECT is(pg_temp.col_priv('private_definer', 'platform', 'UPDATE'), true, 'private_definer holds the one column grant the definer needs');
SELECT is(pg_temp.fn_priv('edge_system', 'private', 'claim_device_platform_for_actor') OR pg_temp.fn_priv('authenticated', 'private', 'claim_device_platform_for_actor') OR pg_temp.fn_priv('anon', 'private', 'claim_device_platform_for_actor') OR pg_temp.fn_priv('service_role', 'private', 'claim_device_platform_for_actor'), false,
  'no other role can call the definer (EXECUTE: edge_actor only)');
SELECT is((SELECT count(*)::int FROM pg_policies WHERE schemaname = 'app' AND tablename = 'device' AND 'edge_actor' = ANY (roles) AND cmd = 'UPDATE'), 1, 'edge_actor still has exactly one UPDATE policy on app.device (0042 added none)');
SELECT is((SELECT c.relforcerowsecurity AND c.relrowsecurity FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device'), true, 'app.device keeps ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT NOT a.attnotnull FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device' AND a.attname = 'platform'), true, 'platform is nullable (unknown), and the ios/android CHECK remains (proved by the 23514 above)');

-- ============================================================================
-- PHASE 2: cleanup (harness role, as service_role)
-- ============================================================================
\c :"harness_db" :"harness_user"
SET ROLE service_role;
BEGIN;
SELECT count(private.delete_my_data(u)) FROM unnest(ARRAY['ee210000-0000-0000-0000-0000000000a0', 'ee210000-0000-0000-0000-0000000000b0']::uuid[]) AS u;
COMMIT;
RESET ROLE;
