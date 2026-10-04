-- 23_offline_totp_seed_record.sql
-- 0047 (partner-auth spine, S1.1a, X9): the staff lane's atomic replay record, private.offline_code_record_step_for_actor, as an OWNER-ONLY PRIMITIVE.
--
-- WHY THIS FILE EXISTS. 0045 let `edge_actor` execute the recorder and proved it from 23_offline_totp_seed_edge.sql, as a real edge_gateway login. It is staff authority under a
-- plain user binding (partner-auth-design E21, G7): any user-lane transaction could call it, so 0047 REVOKEs EXECUTE from edge_actor (the function and these proofs STAY: the
-- money doc's replay property, 12 parallel calls give exactly one `recorded`, depends on them, and S3's verify-and-record definer supersedes the function later). An edge_gateway
-- session can no longer reach it, so the proofs run from the harness role (the migrating role: it holds SET on private_definer): BEGIN; SET LOCAL ROLE private_definer; the binding
-- is written with private.bind_actor in the SAME transaction (the owner holds EXECUTE on its own functions); then the primitive is called. Every cell below is the 0045 cell with
-- exactly that one change of caller; the cells that provision a seed or rotate a device (edge_actor's, still true) stay in 23_offline_totp_seed_edge.sql, which commits the fixtures
-- this file reads (users, devices, the rotation of a002), and 23_offline_totp_seed_rows.sql reads back what this file COMMITS (file order: edge, record, rows).
--
-- Fixtures: all ids start ee230000-; PA, PB are players; the staff principals are helpers.sql's.

\set QUIET 1
SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint AS cur \gset
CREATE FUNCTION pg_temp.cur() RETURNS bigint LANGUAGE sql AS $f$ SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint $f$;
-- (created by the harness role, whose default privileges revoke PUBLIC EXECUTE: private_definer calls it inside the throws_ok strings, so it is granted explicitly)
GRANT EXECUTE ON FUNCTION pg_temp.cur() TO PUBLIC;
SELECT plan(50);

-- ============================================================================
-- 0. Nobody but the owner can call it (the X9 revocation, PA-9c)
-- ============================================================================
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'), ('edge_signin_minter')) r(n)
           WHERE has_function_privilege(r.n, 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE')), NULL,
  'X9 / PA-9c: NO edge or client role may EXECUTE offline_code_record_step_for_actor (it is staff authority under a plain user binding): the owner only');
SELECT is((SELECT has_function_privilege('private_definer', 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE')), true, 'the owner still can: the primitive and its proofs are kept');

-- ============================================================================
-- 1. Nothing bound: the definer refuses (as the owner, so the refusal is the function's own, not a privilege error)
-- ============================================================================
BEGIN;
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, 1, 'fac_x')$$,
  '42501', 'offline_code_record_step_for_actor: no actor is bound in this transaction', 'unbound: the replay-record definer refuses');
ROLLBACK;

-- ============================================================================
-- 4. A system delegate may not record a step
-- ============================================================================
BEGIN;
SET LOCAL ROLE private_definer;
SELECT is(private.bind_delegate_for_queued_evidence('ee230000-0000-0000-0000-0000000a0e03'), 'ee230000-0000-0000-0000-0000000000a0'::uuid, 'delegate: the owner binds the owner of a queued row as a system delegate');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, 1, 'fac_x')$$,
  '42501', 'offline_code_record_step_for_actor: a system delegate may not record an offline code step', 'delegate: a system-delegate binding cannot record a step');
ROLLBACK;

-- ============================================================================
-- 4b. A settable GUC is NOT an ownership boundary (gate LOW-1): a non-staff PA planting the windows still cannot record a step (the scope check is explicit)
-- ============================================================================
BEGIN;
SET LOCAL ROLE private_definer;
SELECT lives_ok($$SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0')$$, 'GUC plant: bind PA');
SELECT set_config('app.offline_code.target_device_id', 'ee230000-0000-0000-0000-00000000b001', true);
SELECT set_config('app.delete_my_data.target_user_id', 'ee230000-0000-0000-0000-0000000000b0', true);
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000b001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'GUC plant: a non-staff PA planting the windows still cannot record a step (the scope check is explicit)');
ROLLBACK;

-- ============================================================================
-- 5. The replay record, bound as STAFF-X (a staff member at fac_x)
-- ============================================================================
BEGIN;
SET LOCAL ROLE private_definer;
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
ROLLBACK;

-- ============================================================================
-- 6. Who holds a staff scope: staff and manager of THAT facility only
-- ============================================================================
BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('00000000-0000-0000-0000-2000000000b1');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_x'), 'recorded', 'manager-x (a manager at fac_x) may record');
ROLLBACK;
BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a3');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'staff-y (staff at fac_y) may NOT record at fac_x');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_y'), 'recorded', 'control: staff-y may record at fac_y');
ROLLBACK;
BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a2');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a REVOKED staff member may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('00000000-0000-0000-0000-2000000000b2');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a REVOKED manager may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('00000000-0000-0000-0000-3000000000c1');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'an OPERATOR (not staff or manager) may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000a0');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000b001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a plain PLAYER (PA, no partner membership) may not record');
ROLLBACK;
BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('ee230000-0000-0000-0000-0000000000b0');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000b001', 1, pg_temp.cur(), 'fac_x')$$, '42501', NULL, 'a player cannot record a step for their OWN device (no scope)');
ROLLBACK;

BEGIN; SET LOCAL ROLE private_definer; SELECT private.bind_actor('00000000-0000-0000-0000-4000000000d0');
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_nope')$$, '23503', NULL, 'an ADMIN (whom the scope check passes for any facility string) naming a facility that does not exist: 23503 at the INSERT (an immediate FK), not an opaque failure at COMMIT');
ROLLBACK;

-- ============================================================================
-- 7. A binding does not outlive its transaction
-- ============================================================================
BEGIN;
SET LOCAL ROLE private_definer;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'stale: bind staff-x in transaction 1 ...');
COMMIT;
BEGIN;
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, pg_temp.cur(), 'fac_x')$$, '42501',
  'offline_code_record_step_for_actor: no actor is bound in this transaction', '... transaction 2 inherits NO actor (the binding is per transaction)');
ROLLBACK;

-- ============================================================================
-- 8. COMMITTED writes, for phase 2 (the prune, the facility, the owner, export, deletion)
-- ============================================================================
-- 8a. staff-x records one step on PA's a001 (this also prunes a001's OLD row, which was seeded far behind the clock) and one on PB's b001's *other* step.
BEGIN;
SET LOCAL ROLE private_definer;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'bind staff-x for the committed writes');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a001', 1, :cur, 'fac_x'), 'recorded', 'committed: a001 step cur recorded at fac_x');
COMMIT;
-- 8b'. (the rotation of a002 to version 2 was committed by 23_offline_totp_seed_edge.sql, as PA through edge_actor) staff records at the OLD version (stale) and the NEW one (recorded).
BEGIN;
SET LOCAL ROLE private_definer;
SELECT lives_ok($$SELECT private.bind_actor('00000000-0000-0000-0000-1000000000a1')$$, 'bind staff-x again');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a002', 1, :cur, 'fac_x'), 'stale_seed_version', 'after the rotation the OLD version''s step is refused ...');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a002', 2, :cur, 'fac_x'), 'recorded', '... and the NEW version''s same step is recorded (a different seed: a different code)');
SELECT is(private.offline_code_record_step_for_actor('ee230000-0000-0000-0000-00000000a002', 2, :cur, 'fac_x'), 'replayed', '... once');
COMMIT;



SELECT * FROM finish();
