-- 17_attest_key_registration_edge.sql
-- App Attest KEY REGISTRATION under the NOBYPASSRLS Edge role (0034): private.register_attest_key_for_actor, called the
-- way the Edge runtime will call it after edge-role PR2-PR4 -- as a REAL `edge_gateway` login that `SET LOCAL ROLE`s into
-- `edge_actor` and binds an actor with private.bind_actor. The service_role lane (what devices-attest-key uses today),
-- the trigger's content rule and the validation are 17_attest_key_registration.sql; this file proves the part that only
-- exists for edge_actor: it reaches the key columns ONLY through the bound-actor definer, never directly, and the
-- definer's actor-keyed policies (pd_edge_act_device_select / pd_edge_act_device_update) confine it to the bound actor's
-- own device.
--
-- Same shape as 16_edge_role.sql, and for the same reason (read its header): `SET ROLE` is judged by the SESSION user, so
-- every assertion lives in the edge_gateway session, reached by `\c`. Three phases: 0 seeds (harness role, committed),
-- 1 asserts (edge_gateway; every group is its own BEGIN ... ROLLBACK, except the stale-binding group), 2 removes the seed.
-- All ids start ee170000-; UA is the actor, UB someone else. Re-runnable on the same cluster.
--
-- ⛔ WATCH (the silent class edge_actor introduces): under RLS an UPDATE with no matching policy affects ZERO rows and
-- raises nothing. A registration that "worked" must therefore be proven by READING the row back, not by the absence of an
-- error; every group below does.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset

-- ============================================================================
-- PHASE 0: seed (harness role -> service_role; committed)
-- ============================================================================
SET ROLE service_role;
BEGIN;
INSERT INTO auth.users (id) VALUES
  ('ee170000-0000-0000-0000-0000000000a0'),
  ('ee170000-0000-0000-0000-0000000000b0')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.profile (user_id, handle) VALUES
  ('ee170000-0000-0000-0000-0000000000a0', 'edge17_ua'),
  ('ee170000-0000-0000-0000-0000000000b0', 'edge17_ub');
-- UA: a1 (first registration), a2 (Android), a3 (replacement), a4 (the committed-binding cell). UB: b1.
INSERT INTO app.device (id, user_id, platform) VALUES
  ('ee170000-0000-0000-0000-00000000a001', 'ee170000-0000-0000-0000-0000000000a0', 'ios'),
  ('ee170000-0000-0000-0000-00000000a002', 'ee170000-0000-0000-0000-0000000000a0', 'android'),
  ('ee170000-0000-0000-0000-00000000a003', 'ee170000-0000-0000-0000-0000000000a0', 'ios'),
  ('ee170000-0000-0000-0000-00000000a004', 'ee170000-0000-0000-0000-0000000000a0', 'ios'),
  ('ee170000-0000-0000-0000-00000000b001', 'ee170000-0000-0000-0000-0000000000b0', 'ios');
-- A queued_catalog evidence row of UA: the system-delegate cell binds its owner.
INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) VALUES
  ('ee170000-0000-0000-0000-0000000a0e03', 'ee170000-0000-0000-0000-0000000000a0', 'ee170000-0000-0000-0000-00000000a001', 'foreground_checkin', 'edge17-a-queued', 'h-17a3', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb);
-- UA's a3 already has a key (kid 'old'), registered through the function: the replacement cell replaces it.
SELECT app.register_attest_key('ee170000-0000-0000-0000-0000000000a0', 'ee170000-0000-0000-0000-00000000a003',
  encode(sha256(decode('04' || repeat('11', 64), 'hex')), 'base64'), decode('04' || repeat('11', 64), 'hex'));
COMMIT;
RESET ROLE;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(54);

-- Key n: 65 bytes starting 0x04, and the key id that IS its hash (the database checks the shape and that relation).
CREATE FUNCTION pg_temp.pk(n int) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT decode('04' || repeat(lpad(to_hex(n), 2, '0'), 64), 'hex') $$;
CREATE FUNCTION pg_temp.kid(n int) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT encode(sha256(pg_temp.pk(n)), 'base64') $$;
CREATE FUNCTION pg_temp.rows(p_sql text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  v_n int;
BEGIN
  EXECUTE p_sql;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$f$;

-- Privilege probes by OID: this session (edge_gateway, no role set) has no USAGE on schema app/private, so naming
-- 'app.device' or a function signature as TEXT would fail at name resolution rather than answer.
CREATE FUNCTION pg_temp.col_priv(p_role text, p_col text, p_priv text) RETURNS boolean LANGUAGE sql AS $f$
  SELECT has_column_privilege(p_role, c.oid, p_col, p_priv) FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device'
$f$;
CREATE FUNCTION pg_temp.fn_priv(p_role text, p_schema text, p_name text) RETURNS boolean LANGUAGE sql AS $f$
  SELECT has_function_privilege(p_role, p.oid, 'EXECUTE') FROM pg_proc p WHERE p.pronamespace = p_schema::regnamespace AND p.proname = p_name
$f$;

-- ============================================================================
-- 1. Nothing bound: the wrapper refuses
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(1), pg_temp.pk(1))$$,
  '42501', 'register_attest_key_for_actor: no actor is bound in this transaction', 'unbound: the wrapper refuses (and nothing is registered for anyone)');
ROLLBACK;

-- ============================================================================
-- 2. Bound as UA: first registration, then every direct path to the key columns is closed
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee170000-0000-0000-0000-0000000000a0')$$, 'bind UA');
SELECT is(private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(1), pg_temp.pk(1)), 'registered', 'edge_actor: UA registers a key on UA''s own device through the wrapper');
-- Read it back: an RLS no-op would have raised nothing at all.
SELECT is((SELECT attest_key_id FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a001'), pg_temp.kid(1), 'the key id was really written (read back as UA)');
SELECT is((SELECT attest_public_key FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a001'), pg_temp.pk(1), 'the public key was really written');
SELECT is((SELECT attest_registered_at IS NOT NULL AND attest_counter = 0 AND attest_retired_key_hashes = '{}' FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a001'), true, 'registered_at set, counter 0, nothing retired');
-- The same key again.
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(1), pg_temp.pk(1))$$, '55000', NULL, 'the same key again is refused (55000)');
-- Direct writes to the key columns: closed for edge_actor (column grants exclude them).
SELECT throws_ok($$UPDATE app.device SET attest_key_id = 'x' WHERE id = 'ee170000-0000-0000-0000-00000000a001'$$, '42501', NULL, 'direct: edge_actor cannot write attest_key_id');
SELECT throws_ok($$UPDATE app.device SET attest_public_key = NULL WHERE id = 'ee170000-0000-0000-0000-00000000a001'$$, '42501', NULL, 'direct: edge_actor cannot write attest_public_key');
SELECT throws_ok($$UPDATE app.device SET attest_registered_at = NULL WHERE id = 'ee170000-0000-0000-0000-00000000a001'$$, '42501', NULL, 'direct: edge_actor cannot write attest_registered_at');
SELECT throws_ok($$UPDATE app.device SET attest_retired_key_hashes = '{}' WHERE id = 'ee170000-0000-0000-0000-00000000a001'$$, '42501', NULL, 'direct: edge_actor cannot write attest_retired_key_hashes');
-- The counter: edge_actor may advance its own device's counter (the verifier's statement) but never lower it.
SELECT is(pg_temp.rows($$UPDATE app.device SET attest_counter = 5 WHERE id = 'ee170000-0000-0000-0000-00000000a001'$$), 1, 'control: edge_actor advances its own device''s counter (1 row)');
SELECT throws_ok($$UPDATE app.device SET attest_counter = 0 WHERE id = 'ee170000-0000-0000-0000-00000000a001'$$, '23514', NULL, 'direct: edge_actor cannot roll its counter back under the same key (the trigger)');
SELECT throws_ok($$UPDATE app.device SET attest_counter = 2 WHERE id = 'ee170000-0000-0000-0000-00000000a001'$$, '23514', NULL, 'direct: nor to any lower value');
-- A replacement through the wrapper: the one way a counter restarts.
SELECT is(private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(2), pg_temp.pk(2)), 'replaced', 'edge_actor: a reinstall''s new key replaces the old one through the wrapper');
SELECT is((SELECT attest_key_id || ':' || attest_counter FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a001'), pg_temp.kid(2) || ':0', 'the new key is current and its counter restarted at 0 (read back)');
SELECT is(cardinality((SELECT attest_retired_key_hashes FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a001')), 1, 'the old key is on the retired list (read back)');
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(1), pg_temp.pk(1))$$, '23514', NULL, 'the retired key cannot come back');
-- Ownership and shape.
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000b001', pg_temp.kid(3), pg_temp.pk(3))$$, 'P0002', NULL, 'UB''s device is P0002 for UA (the actor-keyed policies hide it from the definer)');
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000dead', pg_temp.kid(3), pg_temp.pk(3))$$, 'P0002', NULL, 'a nonexistent device is the same P0002');
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a002', pg_temp.kid(3), pg_temp.pk(3))$$, '22023', NULL, 'UA''s Android device cannot hold an App Attest key');
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(3), pg_temp.pk(4))$$, '22023', NULL, 'a key id that is not the hash of the key is refused');
-- The app function is not callable directly.
SELECT throws_ok($$SELECT app.register_attest_key('ee170000-0000-0000-0000-0000000000a0', 'ee170000-0000-0000-0000-00000000a001', pg_temp.kid(3), pg_temp.pk(3))$$,
  '42501', 'permission denied for function register_attest_key', 'edge_actor cannot call app.register_attest_key directly (it would let a caller name any user)');
SELECT is(private.actor_uid(), 'ee170000-0000-0000-0000-0000000000a0'::uuid, 'still bound as UA after the refused calls');
ROLLBACK;

-- ============================================================================
-- 3. Bound as UB: UA's devices are invisible and untouched
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee170000-0000-0000-0000-0000000000b0')$$, 'bind UB');
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(5), pg_temp.pk(5))$$, 'P0002', NULL, 'UB cannot register a key on UA''s device');
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a003', pg_temp.kid(5), pg_temp.pk(5))$$, 'P0002', NULL, 'nor replace the key on UA''s keyed device');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'ee170000-0000-0000-0000-0000000000a0'), 0, 'UA''s devices are invisible to UB (control: the probe sees rows at all when they are its own)');
SELECT is(private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000b001', pg_temp.kid(5), pg_temp.pk(5)), 'registered', 'control: UB registers on UB''s own device');
ROLLBACK;
-- ...and UA's devices really are untouched (UB's attempts were rolled back, and were refused before that).
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee170000-0000-0000-0000-0000000000a0')$$, 'bind UA again');
SELECT is((SELECT attest_key_id IS NULL FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a001'), true, 'UA''s a1 still has no key (the ROLLBACKs held)');
SELECT is((SELECT attest_key_id FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a003'), encode(sha256(decode('04' || repeat('11', 64), 'hex')), 'base64'), 'UA''s a3 still has the key the seed gave it');
ROLLBACK;

-- ============================================================================
-- 4. A system delegate may not register a key
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('ee170000-0000-0000-0000-0000000a0e03'), 'ee170000-0000-0000-0000-0000000000a0'::uuid, 'delegate: edge_system binds the owner of a queued row');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a001', pg_temp.kid(6), pg_temp.pk(6))$$,
  '42501', 'register_attest_key_for_actor: a system delegate may not register a key', 'delegate: a system-delegate binding cannot register a key');
ROLLBACK;

-- ============================================================================
-- 5. Replacement of a seeded key, and the binding does not outlive its transaction
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee170000-0000-0000-0000-0000000000a0')$$, 'bind UA');
SELECT is(private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a003', pg_temp.kid(7), pg_temp.pk(7)), 'replaced', 'a device that already had a (seeded) key gets "replaced"');
SELECT is((SELECT attest_key_id FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a003'), pg_temp.kid(7), 'and the new key is current');
ROLLBACK;
-- A binding left by a COMMITTED transaction is dead in the next one on the same connection.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee170000-0000-0000-0000-0000000000a0')$$, 'stale: bind UA in transaction 1 ...');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'stale: ... and in transaction 2 on the same connection the binding is gone');
SELECT throws_ok($$SELECT private.register_attest_key_for_actor('ee170000-0000-0000-0000-00000000a004', pg_temp.kid(8), pg_temp.pk(8))$$,
  '42501', 'register_attest_key_for_actor: no actor is bound in this transaction', 'stale: a stale binding does not register a key');
ROLLBACK;

-- ============================================================================
-- 5b. The verifier's counter advance is bound to the KEY it verified (LOW-1, privileged.ts advanceAttestCounter)
-- ============================================================================
-- The statement the Repo issues in EDGE_DB_MODE=edge, as the bound actor: `... WHERE id AND user_id AND attest_key_id = $key AND
-- attest_counter < $new`. a3 holds the seeded key 17 (0x11) at counter 0. A WHERE clause on attest_key_id needs SELECT on it, which
-- edge_actor holds (the key columns are readable, just not writable); the only column it writes is attest_counter.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee170000-0000-0000-0000-0000000000a0')$$, 'advance: bind UA');
SELECT is(pg_temp.rows($$UPDATE app.device SET attest_counter = 5, last_seen = now() WHERE id = 'ee170000-0000-0000-0000-00000000a003' AND user_id = 'ee170000-0000-0000-0000-0000000000a0' AND attest_key_id = pg_temp.kid(17) AND attest_counter < 5 RETURNING id$$), 1,
  'advance: the verified key is still the device''s key: the counter advances (1 row)');
SELECT is(pg_temp.rows($$UPDATE app.device SET attest_counter = 9, last_seen = now() WHERE id = 'ee170000-0000-0000-0000-00000000a003' AND user_id = 'ee170000-0000-0000-0000-0000000000a0' AND attest_key_id = pg_temp.kid(18) AND attest_counter < 9 RETURNING id$$), 0,
  'advance: a key that is no longer (or never was) the device''s key advances nothing (0 rows: a retired key''s assertion fails closed)');
SELECT is(pg_temp.rows($$UPDATE app.device SET attest_counter = 5, last_seen = now() WHERE id = 'ee170000-0000-0000-0000-00000000a003' AND user_id = 'ee170000-0000-0000-0000-0000000000a0' AND attest_key_id = pg_temp.kid(17) AND attest_counter < 5 RETURNING id$$), 0,
  'advance: the same counter again is a replay (0 rows)');
SELECT is((SELECT attest_counter FROM app.device WHERE id = 'ee170000-0000-0000-0000-00000000a003'), 5::bigint, 'advance: and the counter is the one the verified key wrote');
ROLLBACK;

-- ============================================================================
-- 6. Posture: nothing outside the wrapper changed for the edge roles
-- ============================================================================
-- NIT-5: pd_edge_act_device_update is the one UPDATE policy private_definer has on app.device; its expressions are pinned here
-- straight from pg_policy (not from the allow-list's copy of them), so a widened USING or WITH CHECK fails THIS file too.
SELECT is((SELECT pg_get_expr(pol.polqual, pol.polrelid) FROM pg_policy pol WHERE pol.polname = 'pd_edge_act_device_update' AND pol.polrelid = (SELECT c.oid FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device')),
  '(user_id = ( SELECT private.actor_uid() AS actor_uid))', 'pd_edge_act_device_update USING is exactly the bound actor''s own rows');
SELECT is((SELECT pg_get_expr(pol.polwithcheck, pol.polrelid) FROM pg_policy pol WHERE pol.polname = 'pd_edge_act_device_update' AND pol.polrelid = (SELECT c.oid FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device')),
  '(user_id = ( SELECT private.actor_uid() AS actor_uid))', 'pd_edge_act_device_update WITH CHECK is exactly the bound actor''s own rows');
SELECT is((SELECT pol.polcmd::text || ':' || array_to_string(pol.polroles::regrole[], ',') || ':' || pol.polpermissive::text FROM pg_policy pol WHERE pol.polname = 'pd_edge_act_device_update' AND pol.polrelid = (SELECT c.oid FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device')),
  'w:private_definer:true', 'pd_edge_act_device_update is a permissive UPDATE policy for private_definer alone');
SELECT is((SELECT count(*)::int FROM pg_policies WHERE schemaname = 'app' AND tablename = 'device' AND 'edge_actor' = ANY (roles) AND cmd = 'UPDATE'), 1,
  'edge_actor still has exactly one UPDATE policy on app.device (0034 added none for edge_actor; its new policy is private_definer''s)');
SELECT is(pg_temp.col_priv('edge_actor', 'attest_key_id', 'UPDATE') OR pg_temp.col_priv('edge_actor', 'attest_public_key', 'UPDATE')
          OR pg_temp.col_priv('edge_actor', 'attest_registered_at', 'UPDATE') OR pg_temp.col_priv('edge_actor', 'attest_retired_key_hashes', 'UPDATE'), false,
  'edge_actor holds UPDATE on none of the four key columns');
SELECT is(pg_temp.col_priv('edge_actor', 'attest_counter', 'UPDATE'), true, 'control: it still holds UPDATE on attest_counter (the verifier''s monotonic statement)');
SELECT is(pg_temp.fn_priv('edge_system', 'private', 'register_attest_key_for_actor'), false, 'edge_system cannot call the wrapper');
SELECT is(pg_temp.fn_priv('edge_actor', 'app', 'register_attest_key'), false, 'edge_actor cannot call the app function');
SELECT is((SELECT count(*)::int FROM pg_policies WHERE schemaname = 'app' AND tablename = 'device' AND 'private_definer' = ANY (roles) AND policyname = 'pd_edge_act_device_update'), 1, 'the one new private_definer policy exists (it is registered in the allow-list: check 5/6 of the inventory)');

-- ============================================================================
-- PHASE 2: cleanup (harness role, as service_role)
-- ============================================================================
\c :"harness_db" :"harness_user"
SET ROLE service_role;
BEGIN;
SELECT count(private.delete_my_data(u)) FROM unnest(ARRAY['ee170000-0000-0000-0000-0000000000a0', 'ee170000-0000-0000-0000-0000000000b0']::uuid[]) AS u;
COMMIT;
RESET ROLE;
