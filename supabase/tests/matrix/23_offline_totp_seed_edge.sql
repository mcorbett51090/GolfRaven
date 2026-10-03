-- 23_offline_totp_seed_edge.sql
-- 0045, the edge_actor lane, run as a REAL `edge_gateway` login that SET LOCAL ROLEs into `edge_actor` and binds an actor with private.bind_actor, exactly as
-- 21_device_platform_claim.sql (read its header: `SET ROLE` is judged by the SESSION user, so every assertion lives in the edge_gateway session, reached by
-- `\c`). The structure and the derivation vectors are 23_offline_totp_seed.sql.
--
--   * PROVISIONING (private.offline_seed_for_actor): the bound actor's own device only; the vector for (user, device, version); deterministic; a different
--     device, user or version is a different seed; rotation increments atomically; another account's device and a nonexistent one are the same ZERO ROWS;
--     no direct path to the version column, the replay table, the Vault or the derivation core.
--   * THE STAFF-LANE REPLAY RECORD (private.offline_code_record_step_for_actor): recorded / replayed / stale_seed_version / step_out_of_window /
--     no_such_device; staff and manager scope at the facility only (another facility's staff, a revoked member, an operator and a plain player are refused);
--     a staff member's OWN device is refused (22023); a system delegate and an unbound or stale binding are refused; the write-time prune.
--   * The rows this file COMMITS (a recorded step, a rotation, a pruned old row) are read back, exported and deleted by 23_offline_totp_seed_rows.sql, which
--     pg_prove runs next (file order): pgTAP's plan is per session, and a service_role read needs a different session from this edge_gateway one.
--
-- ⛔ WATCH (the silent class edge_actor introduces): under RLS an UPDATE or DELETE with no matching policy affects ZERO rows and raises nothing, so every
-- "it was written / it was pruned" claim is proven by READING the row back as service_role (phase 2).
-- Test vectors (computed OUTSIDE the database, see 23_offline_totp_seed.sql): the shim K, user ee230000-...-a0, device ee230000-...-a001.
-- All ids start ee230000-; PA, PB are players; the staff principals are helpers.sql's. Re-runnable on the same cluster.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset

-- ============================================================================
-- PHASE 0: seed (harness role -> service_role; committed)
-- ============================================================================
SET ROLE service_role;
BEGIN;
INSERT INTO auth.users (id) VALUES
  ('ee230000-0000-0000-0000-0000000000a0'),
  ('ee230000-0000-0000-0000-0000000000b0')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.profile (user_id, handle) VALUES
  ('ee230000-0000-0000-0000-0000000000a0', 'edge23_pa'),
  ('ee230000-0000-0000-0000-0000000000b0', 'edge23_pb');
-- PA: a001, a002. PB: b001. s001 is staff-x's OWN device (the self-attestation cell).
INSERT INTO app.device (id, user_id, platform) VALUES
  ('ee230000-0000-0000-0000-00000000a001', 'ee230000-0000-0000-0000-0000000000a0', 'android'),
  ('ee230000-0000-0000-0000-00000000a002', 'ee230000-0000-0000-0000-0000000000a0', 'ios'),
  ('ee230000-0000-0000-0000-00000000b001', 'ee230000-0000-0000-0000-0000000000b0', 'android'),
  ('ee230000-0000-0000-0000-00000000f001', '00000000-0000-0000-0000-1000000000a1', 'android');
-- a queued evidence row for PA, so edge_system can bind a system delegate (the cell: a delegate-bound transaction may not use either function).
INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) VALUES
  ('ee230000-0000-0000-0000-0000000a0e03', 'ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a002', 'foreground_checkin', 'edge23-pa-queued', 'h-23a3', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb);
COMMIT;
RESET ROLE;
-- Two OLD replay rows (a step far behind the clock, which no longer needs remembering), one on PA's device and one on PB's, written the way 0016 / 0017 / 0019
-- seed a FORCE-RLS table with no policy for the harness role: a temporary CURRENT_USER policy, dropped again.
SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint AS cur0 \gset
GRANT INSERT ON app.offline_code_step TO CURRENT_USER;
CREATE POLICY current_user_seed_offline_code_step_23 ON app.offline_code_step FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO app.offline_code_step (user_id, device_id, seed_version, step, facility_id) VALUES
  ('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1, :cur0 - 50, 'fac_x'),
  ('ee230000-0000-0000-0000-0000000000b0', 'ee230000-0000-0000-0000-00000000b001', 1, :cur0 - 50, 'fac_x');
DROP POLICY current_user_seed_offline_code_step_23 ON app.offline_code_step;
REVOKE INSERT ON app.offline_code_step FROM CURRENT_USER;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(91);
SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint AS cur \gset
CREATE FUNCTION pg_temp.cur() RETURNS bigint LANGUAGE sql AS $f$ SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint $f$;

-- ============================================================================
-- 1. Nothing bound: both definers refuse
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)$$,
  '42501', 'offline_seed_for_actor: no actor is bound in this transaction', 'unbound: the provisioning definer refuses');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, 1, 'fac_x')$$,
  '42501', 'offline_code_record_step_for_actor: no actor is bound in this transaction', 'unbound: the replay-record definer refuses');
ROLLBACK;

-- ============================================================================
-- 2. Provisioning, bound as PA
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0')$$, 'bind PA');
SELECT is((SELECT encode(o_seed, 'hex') FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)),
  'add40558091437161f58c7fad32608775b39e7f79910f980924d6f26a10ddc04', 'vector: PA''s device a001 at version 1 (computed outside the database)');
SELECT is((SELECT o_seed_version FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)), 1, 'a fresh device is at seed version 1');
SELECT is((SELECT octet_length(o_seed) FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)), 32, 'the seed is 32 bytes');
SELECT is((SELECT o_issued_at BETWEEN now() - interval '1 minute' AND clock_timestamp() + interval '1 second' FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)), true, 'issued_at is the server clock');
SELECT is((SELECT o_seed FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)),
          (SELECT o_seed FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)), 'deterministic: re-provisioning returns the SAME seed (a reinstall that lost the secure store recovers)');
SELECT is((SELECT encode(o_seed, 'hex') FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a002', false)),
  '05960b88294025ee5f4cccdc81c40999bd88a7bb915b2034f40c30ee708192fe', 'vector: PA''s OTHER device a002 is a different seed');
SELECT is((SELECT (SELECT o_seed FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)) = (SELECT o_seed FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a002', false))), false,
  'a seed leaked from one device is not the seed of the account''s other device');
-- rotation
SELECT is((SELECT o_seed_version FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', true)), 2, 'rotate: the version is incremented (1 -> 2)');
SELECT is((SELECT encode(o_seed, 'hex') FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)),
  '552d171b816981be928316aac6d6b0fe598bdc69f9d46b2974ea9ab620d96e5e', 'vector: after the rotation the device''s seed is the version-2 seed, and a plain call returns it');
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000a001'), 2, 'the rotation was REALLY written (read back as the actor, not an RLS no-op)');
SELECT is((SELECT o_seed_version FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', true)), 3, 'a second rotation: 3 (each rotation is its own version)');
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000a002'), 1, 'the other device is untouched by the rotation');
-- another account's device, and a device that does not exist: the SAME answer, nothing raised, nothing changed
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', false)), 0, 'PB''s device: ZERO rows for PA (no seed, no error, no oracle)');
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', true)), 0, 'PB''s device with rotate: still zero rows ...');
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000dead', false)), 0, 'a device that does not exist: the same zero rows');
SELECT throws_ok($$SELECT * FROM private.offline_seed_for_actor(NULL, false)$$, '22023', NULL, 'a NULL device is refused (22023)');
SELECT throws_ok($$SELECT * FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', NULL)$$, '22023', NULL, 'a NULL rotate flag is refused (22023)');
-- no direct path
SELECT throws_ok($$UPDATE app.device SET offline_seed_version = 9 WHERE id = 'ee230000-0000-0000-0000-00000000a001'$$, '42501', NULL, 'direct: edge_actor cannot UPDATE the version (no column grant)');
SELECT throws_ok($$SELECT private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1)$$, '42501', NULL, 'direct: edge_actor cannot EXECUTE the derivation core (K is never one call away)');
SELECT throws_ok($$SELECT * FROM vault.decrypted_secrets$$, '42501', NULL, 'direct: edge_actor cannot read the Vault (K)');
SELECT throws_ok($$SELECT count(*) FROM app.offline_code_step$$, '42501', NULL, 'direct: edge_actor cannot read the replay table');
SELECT throws_ok($$INSERT INTO app.offline_code_step (user_id, device_id, seed_version, step, facility_id) VALUES ('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1, 1, 'fac_x')$$, '42501', NULL, 'direct: edge_actor cannot INSERT a replay row');
SELECT throws_ok($$DELETE FROM app.offline_code_step$$, '42501', NULL, 'direct: nor DELETE one');
ROLLBACK;
-- ...the rolled-back rotations left nothing behind (read as the owner of the device in a fresh transaction)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0')$$, 'bind PA again');
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000a001'), 1, 'the ROLLBACK undid the rotations: a001 is back at version 1');
ROLLBACK;

-- ============================================================================
-- 3. Provisioning, bound as PB: PA's devices are not PB's
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000b0')$$, 'bind PB');
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)), 0, 'PA''s device: zero rows for PB');
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', true)), 0, 'PA''s device with rotate: zero rows for PB (an attacker cannot rotate a victim''s seed)');
SELECT is((SELECT encode(o_seed, 'hex') FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', false)),
  encode((SELECT o_seed FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', false)), 'hex'), 'control: PB gets a seed for PB''s own device');
SELECT isnt((SELECT encode(o_seed, 'hex') FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', false)), 'add40558091437161f58c7fad32608775b39e7f79910f980924d6f26a10ddc04', 'and it is not PA''s seed');
ROLLBACK;

-- ============================================================================
-- 3b. A settable GUC is NOT an ownership boundary (gate LOW-1). The older app.delete_my_data.target_user_id window (0016, pd_delete_device_user_id_r) and the
-- device window this migration's record function uses can both be set by ANY session, edge_actor included, and `private_definer` policies keyed on them make
-- another account's device row VISIBLE inside a definer. Provisioning must therefore be safe on its EXPLICIT filter (d.user_id = the bound uid), not on RLS:
-- planted as PA, each of them must still give PB's device ZERO rows, for the read and for the rotate path. (The mutant that removes the explicit filter fails here.)
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0')$$, 'GUC plant: bind PA');
SELECT set_config('app.offline_code.target_device_id', 'ee230000-0000-0000-0000-00000000b001', true);
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', false)), 0, 'GUC plant (the offline_code device window = PB''s device): PB''s device is still ZERO rows for PA');
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', true)), 0, 'GUC plant (offline_code device window): and the ROTATE path is zero rows too');
SELECT set_config('app.delete_my_data.target_user_id', 'ee230000-0000-0000-0000-0000000000b0', true);
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', false)), 0, 'GUC plant (BOTH windows, the delete_my_data user window = PB): still zero rows');
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', true)), 0, 'GUC plant (both windows): the rotate path is zero rows');
SELECT is((SELECT encode(o_seed, 'hex') FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)), 'add40558091437161f58c7fad32608775b39e7f79910f980924d6f26a10ddc04', 'GUC plant: control, PA still gets PA''s own seed (derived with the BOUND uid, never the planted one)');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000b001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'GUC plant: a non-staff PA planting the windows still cannot record a step (the scope check is explicit)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0')$$, 'GUC plant 2: bind PA');
SELECT set_config('app.delete_my_data.target_user_id', 'ee230000-0000-0000-0000-0000000000b0', true);
SELECT is((SELECT count(*)::int FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000b001', false)), 0, 'GUC plant (the delete_my_data user window ALONE = PB): zero rows');
ROLLBACK;

-- ============================================================================
-- 4. A system delegate may use neither function
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.bind_delegate_for_queued_evidence('ee230000-0000-0000-0000-0000000a0e03'), 'ee230000-0000-0000-0000-0000000000a0'::uuid, 'delegate: edge_system binds the owner of a queued row');
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a001', false)$$,
  '42501', 'offline_seed_for_actor: a system delegate may not read an offline seed', 'delegate: a system-delegate binding cannot read a seed');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, 1, 'fac_x')$$,
  '42501', 'offline_code_record_step_for_actor: a system delegate may not record an offline code step', 'delegate: nor record a step');
ROLLBACK;

-- ============================================================================
-- 5. The replay record, bound as STAFF-X (a staff member at fac_x)
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'bind staff-x');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_x'), 'recorded', 'a code step is RECORDED');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_x'), 'replayed', 'the SAME step again is a replay: refused');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_x'), 'replayed', '... and again');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur + 1, 'fac_x'), 'recorded', 'the NEXT step is a different code: recorded');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur - 1, 'fac_x'), 'recorded', 'the PREVIOUS step too (the core accepts +-1)');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur() + 2, 'fac_x'), 'recorded', 'two steps ahead is still inside the database''s own (wider) bound');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur + 10, 'fac_x'), 'step_out_of_window', 'ten steps ahead: out of window');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur - 10, 'fac_x'), 'step_out_of_window', 'ten steps behind: out of window');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, 0, 'fac_x'), 'step_out_of_window', 'step 0 (the epoch): out of window');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 2, :cur, 'fac_x'), 'stale_seed_version', 'a seed version that is not the device''s CURRENT one is refused (the device is at 1)');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 99, :cur, 'fac_x'), 'stale_seed_version', 'a FUTURE version is refused the same way');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000dead', 1, :cur, 'fac_x'), 'no_such_device', 'a device that does not exist');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000b001', 1, :cur, 'fac_x'), 'recorded', 'a different device''s same step is independent (the key includes the device)');
-- argument shape
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor(NULL, 1, 1, 'fac_x')$$, '22023', NULL, 'a NULL device is refused');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', NULL, 1, 'fac_x')$$, '22023', NULL, 'a NULL version is refused');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 0, 1, 'fac_x')$$, '22023', NULL, 'version 0 is refused');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, NULL, 'fac_x')$$, '22023', NULL, 'a NULL step is refused');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, -1, 'fac_x')$$, '22023', NULL, 'a negative step is refused');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, 1, NULL)$$, '22023', NULL, 'a NULL facility is refused');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, 1, '  ')$$, '22023', NULL, 'a blank facility is refused');
-- staff-x holds no scope at fac_y
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_y')$$, '42501', 'offline_code_record_step_for_actor: the caller holds no staff scope at that facility', 'staff-x has no scope at fac_y: refused');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_nope')$$, '42501', NULL, 'nor at a facility that does not exist');
-- the scope check comes BEFORE any device lookup: no oracle for an out-of-scope caller (the same refusal for a real device and for a made-up one)
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000dead', 1, pg_temp.cur(), 'fac_y')$$, '42501', NULL, 'out of scope: the refusal is the same for a device that does not exist (no existence oracle)');
-- a staff member can never attest their OWN account (A2-21)
SELECT throws_like($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000f001', 1, pg_temp.cur(), 'fac_x')$$, 'self_attestation_refused%', 'staff-x''s OWN device: refused (22023, A2-21)');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000f001', 1, pg_temp.cur(), 'fac_x')$$, '22023', NULL, '... with SQLSTATE 22023');
SELECT throws_ok($$SELECT count(*) FROM app.offline_code_step$$, '42501', NULL, 'staff-x cannot read the replay table directly either');
ROLLBACK;

-- ============================================================================
-- 6. Who holds a staff scope: staff and manager of THAT facility only
-- ============================================================================
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-2000000000b1');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_x'), 'recorded', 'manager-x (a manager at fac_x) may record');
ROLLBACK;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a3');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'staff-y (staff at fac_y) may NOT record at fac_x');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_y'), 'recorded', 'control: staff-y may record at fac_y');
ROLLBACK;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a2');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a REVOKED staff member may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-2000000000b2');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a REVOKED manager may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-3000000000c1');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'an OPERATOR (not staff or manager) may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000b001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a plain PLAYER (PA, no partner membership) may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000b0');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000b001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a player cannot record a step for their OWN device (no scope)');
ROLLBACK;

BEGIN; SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-4000000000d0');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_nope')$$, '23503', NULL, 'an ADMIN (whom the scope check passes for any facility string) naming a facility that does not exist: 23503 at the INSERT (an immediate FK), not an opaque failure at COMMIT');
ROLLBACK;

-- ============================================================================
-- 7. A binding does not outlive its transaction
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'stale: bind staff-x in transaction 1 ...');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501',
  'offline_code_record_step_for_actor: no actor is bound in this transaction', '... transaction 2 inherits NO actor (the binding is per transaction)');
ROLLBACK;

-- ============================================================================
-- 8. COMMITTED writes, for phase 2 (the prune, the facility, the owner, rotation, export, deletion)
-- ============================================================================
-- 8a. staff-x records one step on PA's a001 (this also prunes a001's OLD row, which was seeded far behind the clock) and one on PB's b001's *other* step.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'bind staff-x for the committed writes');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_x'), 'recorded', 'committed: a001 step cur recorded at fac_x');
COMMIT;
-- 8b. PA rotates a002 (committed), then staff records at the OLD version (stale) and the NEW one (recorded): a rotation invalidates the old seed's steps.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0')$$, 'bind PA for the committed rotation');
SELECT is((SELECT o_seed_version FROM private.offline_seed_for_actor('ee230000-0000-0000-0000-00000000a002', true)), 2, 'committed: a002 rotated to version 2');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'bind staff-x again');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a002', 1, :cur, 'fac_x'), 'stale_seed_version', 'after the rotation the OLD version''s step is refused ...');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a002', 2, :cur, 'fac_x'), 'recorded', '... and the NEW version''s same step is recorded (a different seed: a different code)');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a002', 2, :cur, 'fac_x'), 'replayed', '... once');
COMMIT;

SELECT * FROM finish();
