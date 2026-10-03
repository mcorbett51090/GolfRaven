-- 22_device_first_attested_edge.sql
-- 0043, the edge_actor lane: the statements privileged.ts issues (rewards.recordDeviceVerdict writes integrity_last; rewards.hasAttestedVerdictOnDevice
-- reads first_attested_at / integrity_last) run as a REAL `edge_gateway` login that SET LOCAL ROLEs into `edge_actor` and binds an actor with
-- private.bind_actor, exactly as 21_device_platform_claim.sql (read its header: `SET ROLE` is judged by the SESSION user, so every assertion lives in
-- the edge_gateway session, reached by `\c`). The service_role lane and the trigger's content rules are 22_device_first_attested.sql.
--
-- ⛔ WATCH (the silent class edge_actor introduces): under RLS an UPDATE with no matching policy affects ZERO rows and raises nothing, so every
-- "it was stamped" claim below is proven by READING the row back.
-- All ids start ee220000-; UA is the actor, UB someone else. Re-runnable on the same cluster.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset

-- ============================================================================
-- PHASE 0: seed (harness role -> service_role; committed)
-- ============================================================================
SET ROLE service_role;
BEGIN;
INSERT INTO auth.users (id) VALUES
  ('ee220000-0000-0000-0000-0000000000a0'),
  ('ee220000-0000-0000-0000-0000000000b0')
ON CONFLICT (id) DO NOTHING;
INSERT INTO app.profile (user_id, handle) VALUES
  ('ee220000-0000-0000-0000-0000000000a0', 'edge22_ua'),
  ('ee220000-0000-0000-0000-0000000000b0', 'edge22_ub');
-- UA: a1 never attested; a2 never attested (the cells that must stay false); a3 holds an `attested` integrity_last with NO stamp (a pre-0043 row).
-- UB: b1 attested (stamped through a verdict below).
INSERT INTO app.device (id, user_id, platform) VALUES
  ('ee220000-0000-0000-0000-00000000a001', 'ee220000-0000-0000-0000-0000000000a0', 'android'),
  ('ee220000-0000-0000-0000-00000000a002', 'ee220000-0000-0000-0000-0000000000a0', 'android'),
  ('ee220000-0000-0000-0000-00000000b001', 'ee220000-0000-0000-0000-0000000000b0', 'android');
-- a3: the pre-0043 shape, which the INSERT arm of the trigger no longer produces: switch the trigger off (as the table owner) for this INSERT only.
COMMIT;
RESET ROLE;
ALTER TABLE app.device DISABLE TRIGGER device_first_attested_stamp_trg;
SET ROLE service_role;
BEGIN;
INSERT INTO app.device (id, user_id, platform, integrity_last) VALUES
  ('ee220000-0000-0000-0000-00000000a003', 'ee220000-0000-0000-0000-0000000000a0', 'android', '{"grade":"attested"}'::jsonb);
COMMIT;
RESET ROLE;
ALTER TABLE app.device ENABLE TRIGGER device_first_attested_stamp_trg;
SET ROLE service_role;
BEGIN;
UPDATE app.device SET integrity_last = '{"grade":"attested"}'::jsonb WHERE id = 'ee220000-0000-0000-0000-00000000b001';
COMMIT;
RESET ROLE;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(23);

CREATE FUNCTION pg_temp.rows(p_sql text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  v_n int;
BEGIN
  EXECUTE p_sql;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$f$;
CREATE FUNCTION pg_temp.col_priv(p_role text, p_col text, p_priv text) RETURNS boolean LANGUAGE sql AS $f$
  SELECT has_column_privilege(p_role, c.oid, p_col, p_priv) FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device'
$f$;

-- ============================================================================
-- 1. Bound as UA: the verdict write stamps, and only the verdict write
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee220000-0000-0000-0000-0000000000a0')$$, 'bind UA');
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = 'ee220000-0000-0000-0000-00000000a001'), true, 'control: a1 starts unstamped, read as UA');
-- privileged.ts#recordDeviceVerdict's statement, with a non-attested grade.
SELECT is(pg_temp.rows($$UPDATE app.device SET devicecheck_token_hash = coalesce(NULL::text, devicecheck_token_hash), integrity_last = '{"grade":"unattestable"}'::jsonb, last_seen = now() WHERE id = 'ee220000-0000-0000-0000-00000000a001' AND user_id = 'ee220000-0000-0000-0000-0000000000a0'$$), 1, 'recordDeviceVerdict(unattestable) updates the row as edge_actor (no 42501: the trigger needs no grant)');
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = 'ee220000-0000-0000-0000-00000000a001'), true, 'an `unattestable` verdict does not stamp');
SELECT is(pg_temp.rows($$UPDATE app.device SET devicecheck_token_hash = coalesce(NULL::text, devicecheck_token_hash), integrity_last = '{"grade":"attested"}'::jsonb, last_seen = now() WHERE id = 'ee220000-0000-0000-0000-00000000a001' AND user_id = 'ee220000-0000-0000-0000-0000000000a0'$$), 1, 'recordDeviceVerdict(attested) updates the row');
SELECT is((SELECT first_attested_at = now() FROM app.device WHERE id = 'ee220000-0000-0000-0000-00000000a001'), true, 'and it REALLY stamped the device (read back, not an RLS no-op)');
COMMIT;

-- ============================================================================
-- 2. A later transaction: a later verdict does not erase it (a stamp older than this transaction proves it was not re-stamped)
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee220000-0000-0000-0000-0000000000a0')$$, 'bind UA again');
SELECT is(pg_temp.rows($$UPDATE app.device SET integrity_last = '{"grade":"failed"}'::jsonb, last_seen = now() WHERE id = 'ee220000-0000-0000-0000-00000000a001' AND user_id = 'ee220000-0000-0000-0000-0000000000a0'$$), 1, 'a later `failed` verdict is written');
SELECT is((SELECT integrity_last ->> 'grade' FROM app.device WHERE id = 'ee220000-0000-0000-0000-00000000a001'), 'failed', 'integrity_last now says failed (the exported "last verdict" is unchanged in meaning)');
SELECT is((SELECT first_attested_at IS NOT NULL AND first_attested_at < now() FROM app.device WHERE id = 'ee220000-0000-0000-0000-00000000a001'), true, 'but the stamp survives and is OLDER than this transaction: not cleared, not re-stamped');
-- hasAttestedVerdictOnDevice's statement (privileged.ts), for each shape of device.
SELECT is((SELECT exists (select 1 from app.device where id = 'ee220000-0000-0000-0000-00000000a001' and user_id = 'ee220000-0000-0000-0000-0000000000a0' and (first_attested_at is not null or integrity_last ->> 'grade' = 'attested'))), true, 'hasAttestedVerdictOnDevice: a1 (stamped, last verdict failed) is true');
SELECT is((SELECT exists (select 1 from app.device where id = 'ee220000-0000-0000-0000-00000000a002' and user_id = 'ee220000-0000-0000-0000-0000000000a0' and (first_attested_at is not null or integrity_last ->> 'grade' = 'attested'))), false, 'a2 (never attested) is false');
SELECT is((SELECT exists (select 1 from app.device where id = 'ee220000-0000-0000-0000-00000000a003' and user_id = 'ee220000-0000-0000-0000-0000000000a0' and (first_attested_at is not null or integrity_last ->> 'grade' = 'attested'))), true, 'a3 (pre-0043 shape: attested integrity_last, no stamp) is true through the integrity_last arm');
SELECT is((SELECT exists (select 1 from app.device where id = 'ee220000-0000-0000-0000-00000000b001' and user_id = 'ee220000-0000-0000-0000-0000000000a0' and (first_attested_at is not null or integrity_last ->> 'grade' = 'attested'))), false, 'UB''s attested device reads false for UA (the row is invisible to the actor)');
-- No direct path.
SELECT throws_ok($$UPDATE app.device SET first_attested_at = NULL WHERE id = 'ee220000-0000-0000-0000-00000000a001'$$, '42501', NULL, 'direct: edge_actor cannot clear the stamp (no column grant)');
SELECT throws_ok($$UPDATE app.device SET first_attested_at = now() WHERE id = 'ee220000-0000-0000-0000-00000000a002'$$, '42501', NULL, 'direct: nor set it on a device that never attested');
SELECT throws_ok($$UPDATE app.device SET integrity_last = '{"grade":"attested"}'::jsonb, first_attested_at = now() WHERE id = 'ee220000-0000-0000-0000-00000000a002'$$, '42501', NULL, 'direct: not even next to a legitimate verdict write');
SELECT throws_ok($$INSERT INTO app.device (id, user_id, platform, first_attested_at) VALUES ('ee220000-0000-0000-0000-00000000a0f1', 'ee220000-0000-0000-0000-0000000000a0', 'android', now())$$, '42501', NULL, 'direct: nor INSERT a device with a stamp');
ROLLBACK;

-- ============================================================================
-- 3. Bound as UB: UA's devices are not UB's to stamp
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee220000-0000-0000-0000-0000000000b0')$$, 'bind UB');
SELECT is(pg_temp.rows($$UPDATE app.device SET integrity_last = '{"grade":"attested"}'::jsonb, last_seen = now() WHERE id = 'ee220000-0000-0000-0000-00000000a002'$$), 0, 'UB''s verdict write on UA''s device matches ZERO rows (the policy hides it)');
ROLLBACK;
-- ...and UA's a2 really is untouched.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('ee220000-0000-0000-0000-0000000000a0')$$, 'bind UA once more');
SELECT is((SELECT first_attested_at IS NULL AND integrity_last IS NULL FROM app.device WHERE id = 'ee220000-0000-0000-0000-00000000a002'), true, 'a2 is untouched: unstamped, no verdict');
ROLLBACK;

-- ============================================================================
-- 4. Posture
-- ============================================================================
SELECT is(pg_temp.col_priv('edge_actor', 'first_attested_at', 'UPDATE') OR pg_temp.col_priv('edge_actor', 'first_attested_at', 'INSERT'), false, 'edge_actor holds neither UPDATE nor INSERT on first_attested_at');

-- ============================================================================
-- PHASE 2: cleanup (harness role, as service_role)
-- ============================================================================
\c :"harness_db" :"harness_user"
SET ROLE service_role;
BEGIN;
SELECT count(private.delete_my_data(u)) FROM unnest(ARRAY['ee220000-0000-0000-0000-0000000000a0', 'ee220000-0000-0000-0000-0000000000b0']::uuid[]) AS u;
COMMIT;
RESET ROLE;
