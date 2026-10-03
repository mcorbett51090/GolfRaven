-- 0042_device_platform_unknown.sql
--
-- A device first seen WITHOUT a platform no longer gets a platform guessed for it.
--
-- THE BUG. `checkin-challenge` and `evidence` create a device row the first time they see a device id, and neither request carries a platform. The
-- Edge code (privileged.ts `device.ensureOwn(id, null)`) stored `platform ?? 'ios'`, because the column was NOT NULL. An Android device first seen
-- there was therefore labelled iOS, and `rewards-activate` (which refuses a request whose platform differs from the row's, 422 `platform_mismatch`)
-- then refused its Android activation.
--
-- THE FIX (option b: unknown until a platform-bearing request). `app.device.platform` becomes NULLABLE: NULL means "no request that carries a
-- platform has been seen for this device yet". It is set by the FIRST platform-bearing use, and the first one wins; a later request that names the
-- other platform is refused exactly as before (activation: 422 platform_mismatch; attest-key: 422 platform_mismatch). The platform-bearing uses are
-- reward activation, App Attest key registration (iOS only), a push-token registration that names a platform, and a check-in token whose attestation
-- verified (`attested`). Option (a), asking the mobile client to send a platform to the challenge and evidence endpoints, was rejected: the evidence
-- body is strict and its input hash is the idempotency key of a replay, so a new field would turn a client's own replays into 409s.
--
-- WHAT IS ADDED, and what is not:
--   1. app.device.platform DROP NOT NULL. The CHECK (platform IN ('ios','android')) is kept (a NULL passes a CHECK; nothing else may be stored).
--      Nothing else on the table changes: FORCE ROW LEVEL SECURITY and every policy are untouched.
--   2. GRANT UPDATE (platform) ON app.device TO private_definer -- the one narrow column grant the definer below needs. The row filter is the
--      existing pd_edge_act_device_update policy (the BOUND actor's own device only). edge_actor itself gains NO privilege on this column (it keeps
--      INSERT (id, user_id, platform) and no UPDATE of platform), and no policy is added or widened.
--   3. private.claim_device_platform_for_actor(device, platform): SECURITY DEFINER, EXECUTE for edge_actor only, kind = 'user' bindings only (a
--      catalog-drain delegate never claims). It sets the platform ONLY when it is NULL (UPDATE ... WHERE platform IS NULL: first wins, race-safe under
--      READ COMMITTED because the second writer re-evaluates the predicate) and returns the platform now on record (NULL for a device that is not the actor's own), so the
--      caller compares it with the one it asked for. It never changes a platform that is set. The same shape as 0034's private.register_attest_key_for_actor.
--   4. The registry row in private.function_inventory (checks 1-3 of verify-function-inventory.mjs).
--
-- NOT DONE: no data migration. A row already labelled 'ios' by the bug cannot be told from a real iOS device that has not registered an App Attest key
-- yet (both have platform 'ios' and no key), so relabelling would have to be to "unknown" rather than to 'android'. That would be safe for the data (the
-- first platform-bearing use re-claims it) but this repository's databases are pre-launch (no player rows exist) and an UPDATE inside a migration is
-- filtered by FORCE ROW LEVEL SECURITY for the table owner, so it would be unreliable. Where such rows exist, an operator may run, as service_role,
--   UPDATE app.device SET platform = NULL WHERE platform = 'ios' AND attest_key_id IS NULL;
-- (a row with a REGISTERED key is certainly iOS and is excluded).
--
-- Deploy order: apply this migration BEFORE the Edge code that inserts a NULL platform (an older schema would refuse it with 23502).

ALTER TABLE app.device ALTER COLUMN platform DROP NOT NULL;
COMMENT ON COLUMN app.device.platform IS
  'ios | android, or NULL = unknown: the device was first seen by an endpoint that carries no platform (checkin-challenge, evidence). Set once, by the first platform-bearing use (private.claim_device_platform_for_actor; first wins); never changed by any Edge role afterwards. 0042.';

GRANT UPDATE (platform) ON app.device TO private_definer;

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.claim_device_platform_for_actor(p_device_id uuid, p_platform text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_current text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'claim_device_platform_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'claim_device_platform_for_actor: a system delegate may not claim a platform' USING ERRCODE = '42501';
  END IF;
  IF p_device_id IS NULL OR p_platform IS NULL OR p_platform NOT IN ('ios', 'android') THEN
    RAISE EXCEPTION 'claim_device_platform_for_actor: a device id and a platform of ios or android are required' USING ERRCODE = '22023';
  END IF;
  -- First wins: only an UNKNOWN platform is ever written. Ownership is part of the WHERE clause (and of the policy), never a post-hoc check.
  UPDATE app.device SET platform = p_platform
  WHERE id = p_device_id AND user_id = v_uid AND platform IS NULL;
  SELECT d.platform INTO v_current FROM app.device d WHERE d.id = p_device_id AND d.user_id = v_uid;
  -- NULL (not an exception) for a device that is not the bound actor's own: the caller is inside the request's transaction, and an error raised
  -- there would abort it. A nonexistent device and another account's device are the same answer.
  RETURN v_current;
END;
$$;
REVOKE EXECUTE ON FUNCTION private.claim_device_platform_for_actor(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.claim_device_platform_for_actor(uuid, text) TO edge_actor;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('private', 'claim_device_platform_for_actor', 'p_device_id uuid, p_platform text', false, false, false, true, false,
   '0042: edge_actor only; sets app.device.platform for the BOUND kind=user actor''s own device iff it is still NULL (first platform-bearing use wins) and returns the platform on record (NULL if not the actor''s device); never changes a set platform');

DO $assert_0042$
BEGIN
  IF has_column_privilege('edge_actor', 'app.device', 'platform', 'UPDATE') THEN
    RAISE EXCEPTION '0042: edge_actor must hold no UPDATE on app.device.platform';
  END IF;
  IF NOT (SELECT relforcerowsecurity FROM pg_class WHERE oid = 'app.device'::regclass) THEN
    RAISE EXCEPTION '0042: app.device must keep FORCE ROW LEVEL SECURITY';
  END IF;
END
$assert_0042$;
