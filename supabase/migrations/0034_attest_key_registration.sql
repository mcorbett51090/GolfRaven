-- 0034_attest_key_registration.sql
--
-- App Attest KEY REGISTRATION (build plan §7.5; follow-up F2 of the P3f section of
-- docs/security/p3-money-path-requirements.md). Until now nothing wrote `app.device.attest_public_key`,
-- so every real iOS device graded `unattestable` and was held. The Edge Function
-- `devices-attest-key` (POST /v1/devices/attest-key) verifies an attestation object against Apple's
-- pinned root in TypeScript and then calls the one function below to record the key it attested.
--
-- 0033 belongs to another builder and 0035 to Sign in with Apple; 0001-0032 are immutable and are not
-- edited. No table is added (so there is nothing new to register in pii_retention_policy /
-- pii_export_policy, and no edge_actor policy to add to private.edge_policy_allowlist: edge_actor
-- reaches the key columns ONLY through the definer in section 4, never directly). What is added:
--
--   1. three columns on app.device -- the provenance of a key, and the keys a device has retired;
--   2. the one-way counter trigger (0032) redefined so the ONE legitimate decrease is allowed:
--      a key REPLACED by a never-before-used key, enforced by CONTENT (so no role can use it to roll a
--      counter back under the same key);
--   3. app.register_attest_key  (service_role, and private_definer for the wrapper), invoker-rights, the
--      same shape as app.activate_* (0027): validates, replaces, audits;
--   4. private.register_attest_key_for_actor (edge_actor), the SECURITY DEFINER wrapper over it for the
--      BOUND actor (0030's binding), exactly as 0032 did for activation;
--   5. the registries: one definer-policy row (+ the checked-in fixture), two function-inventory rows.
--
-- DESIGN DECISION -- RE-REGISTRATION (a reinstall means a new key).
-- Reinstalling the app destroys the Secure Enclave key; the install generates a new one and (if it kept
-- its device id, e.g. from the Keychain) asks to register it on the SAME device row. The old key's counter
-- (say 40) cannot carry over: a new key's assertions start at 1. But 0032's trigger forbids ANY counter
-- decrease (it is the replay window App Attest's counter exists to close). So:
--   - the trigger now allows a decrease ONLY when ALL of: the new counter is 0; the key id AND public key
--     both CHANGED (neither NULL before or after); the OLD key's hash is now in `attest_retired_key_hashes`;
--     and the NEW key's hash was NOT already retired on this row. That is "a different key that this device
--     never used before", so no assertion ever signed under a key the server has seen can be replayed
--     against a lowered counter: the lowered counter belongs to a key with no history;
--   - the retired list keeps the last 16 retired keys' SHA-256 (of the key id string), FIFO; flipping back to
--     a retired key is refused (23514) while it is still on the list;
--   - a device whose key is replaced is audited (audit_log 'device.attest_key_replaced', hash PREFIXES only);
--   - the request still needs a fresh server challenge and a valid Apple attestation, which are verified in
--     TypeScript before this function is reached. Registering the SAME key again is refused (55000): an
--     attestation of an already-attested key cannot exist, so the client's answer is "already registered".
-- Alternatives rejected: leaving the counter alone on replacement (the new key's first 40 assertions would
-- fail as replays); one counter per key in a side table (a new table, with its registry rows, for what two
-- columns and a trigger do); a role-based exemption in the trigger (every role then holds a rollback).
--
-- An attested grade requires a REGISTERED key: Repo#rewards.deviceAttestState (privileged.ts) now returns the
-- stored public key only when `attest_registered_at` is set, i.e. only for a key written by this function.
-- A key written any other way reads as "no key" and grades `unattestable`, never `attested`.

-- ============================================================================
-- 1. app.device: provenance and retired keys
-- ============================================================================
ALTER TABLE app.device ADD COLUMN attest_registered_at timestamptz;
ALTER TABLE app.device ADD COLUMN attest_retired_key_hashes text[] NOT NULL DEFAULT '{}';
ALTER TABLE app.device ADD CONSTRAINT device_attest_retired_cap
  CHECK (cardinality(attest_retired_key_hashes) <= 16);
ALTER TABLE app.device ADD CONSTRAINT device_attest_registered_needs_key
  CHECK (attest_registered_at IS NULL OR (attest_key_id IS NOT NULL AND attest_public_key IS NOT NULL));
COMMENT ON COLUMN app.device.attest_registered_at IS
  'When app.register_attest_key verified-and-recorded this device''s App Attest key. NULL = no key was registered through the verified path; the assertion verifier is then given no key (unattestable), whatever attest_public_key holds. Written ONLY by app.register_attest_key.';
COMMENT ON COLUMN app.device.attest_retired_key_hashes IS
  'SHA-256 hex of the key ids this device row has retired (a reinstall replaces the key), newest last, at most 16. A retired key cannot be registered again while it is listed, which is what lets the attest_counter trigger allow a counter reset for a NEW key only. Never exported.';

-- ============================================================================
-- 2. The counter trigger: monotonic per KEY (redefines 0032's function body; same trigger, same signature)
-- ============================================================================
CREATE OR REPLACE FUNCTION app.device_attest_counter_monotonic() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_old_hash text;
  v_new_hash text;
BEGIN
  IF NEW.attest_counter >= OLD.attest_counter THEN
    RETURN NEW;
  END IF;
  -- The ONE legitimate decrease: a key replaced by a key this row has never used. Decided by CONTENT, not by role.
  IF NEW.attest_counter = 0
     AND OLD.attest_key_id IS NOT NULL AND NEW.attest_key_id IS NOT NULL
     AND NEW.attest_key_id IS DISTINCT FROM OLD.attest_key_id
     AND OLD.attest_public_key IS NOT NULL AND NEW.attest_public_key IS NOT NULL
     AND NEW.attest_public_key IS DISTINCT FROM OLD.attest_public_key
  THEN
    v_old_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(OLD.attest_key_id, 'UTF8')), 'hex');
    v_new_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(NEW.attest_key_id, 'UTF8')), 'hex');
    IF v_old_hash = ANY (NEW.attest_retired_key_hashes)
       AND NOT (v_new_hash = ANY (OLD.attest_retired_key_hashes))
       AND NOT (v_new_hash = ANY (NEW.attest_retired_key_hashes))
    THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'device: attest_counter is monotonic per key (% -> % refused, id=%); only a replacement by a never-before-used key may start from 0', OLD.attest_counter, NEW.attest_counter, OLD.id
    USING ERRCODE = '23514';
END;
$$;

-- ============================================================================
-- 3. app.register_attest_key  (invoker-rights, the shape of app.activate_*)
-- ============================================================================
-- Returns 'registered' (the device had no key) or 'replaced'. SQLSTATEs the TypeScript maps:
--   22023  malformed argument, a key id that is not the SHA-256 of the key, or a non-iOS device
--   P0002  no such device FOR THIS USER (another user's device and a nonexistent one are the same)
--   55000  that key is already the device's key
--   23514  that key was retired on this device and may not come back
CREATE FUNCTION app.register_attest_key(p_user_id uuid, p_device_id uuid, p_key_id text, p_public_key bytea)
RETURNS text
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_dev app.device%ROWTYPE;
  v_old_hash text;
  v_new_hash text;
  v_retired text[];
  v_replaced boolean;
BEGIN
  IF p_user_id IS NULL OR p_device_id IS NULL OR p_key_id IS NULL OR p_public_key IS NULL THEN
    RAISE EXCEPTION 'register_attest_key: every argument is required' USING ERRCODE = '22023';
  END IF;
  -- An uncompressed P-256 point, and a key id that IS its hash: the database refuses to pair a key id with a key
  -- that does not hash to it, whatever the caller verified.
  IF pg_catalog.octet_length(p_public_key) <> 65 OR pg_catalog.get_byte(p_public_key, 0) <> 4 THEN
    RAISE EXCEPTION 'register_attest_key: the public key must be a 65-byte uncompressed P-256 point' USING ERRCODE = '22023';
  END IF;
  IF p_key_id !~ '^[A-Za-z0-9+/]{43}=$' OR p_key_id <> pg_catalog.encode(pg_catalog.sha256(p_public_key), 'base64') THEN
    RAISE EXCEPTION 'register_attest_key: the key id is not the base64 SHA-256 of the public key' USING ERRCODE = '22023';
  END IF;

  -- Ownership is part of the WHERE clause, never a post-hoc check; the row lock serialises two registrations.
  SELECT * INTO v_dev FROM app.device WHERE id = p_device_id AND user_id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'register_attest_key: no such device for this user' USING ERRCODE = 'P0002';
  END IF;
  IF v_dev.platform <> 'ios' THEN
    RAISE EXCEPTION 'register_attest_key: App Attest exists on iOS only' USING ERRCODE = '22023';
  END IF;
  IF v_dev.attest_key_id IS NOT DISTINCT FROM p_key_id THEN
    RAISE EXCEPTION 'register_attest_key: this key is already registered on this device' USING ERRCODE = '55000';
  END IF;

  v_new_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_key_id, 'UTF8')), 'hex');
  IF v_new_hash = ANY (v_dev.attest_retired_key_hashes) THEN
    RAISE EXCEPTION 'register_attest_key: this key was retired on this device and cannot be registered again' USING ERRCODE = '23514';
  END IF;

  v_replaced := v_dev.attest_key_id IS NOT NULL;
  IF v_replaced THEN
    v_old_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_dev.attest_key_id, 'UTF8')), 'hex');
    v_retired := v_dev.attest_retired_key_hashes || v_old_hash;
    -- Keep the newest 16 (array slices are 1-based and inclusive).
    IF pg_catalog.cardinality(v_retired) > 16 THEN
      v_retired := v_retired[pg_catalog.cardinality(v_retired) - 15 : pg_catalog.cardinality(v_retired)];
    END IF;
    UPDATE app.device SET
      attest_key_id = p_key_id,
      attest_public_key = p_public_key,
      attest_counter = 0,
      attest_registered_at = now(),
      attest_retired_key_hashes = v_retired,
      last_seen = now()
    WHERE id = p_device_id AND user_id = p_user_id;
  ELSE
    -- First registration: the counter is left exactly as it is (a keyless device's counter is 0).
    UPDATE app.device SET
      attest_key_id = p_key_id,
      attest_public_key = p_public_key,
      attest_registered_at = now(),
      last_seen = now()
    WHERE id = p_device_id AND user_id = p_user_id;
  END IF;

  -- The audit row carries hash PREFIXES only (never a key id or key) and the counter the replaced key had reached.
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (
    p_user_id,
    CASE WHEN v_replaced THEN 'device.attest_key_replaced' ELSE 'device.attest_key_registered' END,
    'device',
    p_device_id::text,
    pg_catalog.jsonb_build_object(
      'newKeySha256Prefix', pg_catalog.left(v_new_hash, 16),
      'oldKeySha256Prefix', CASE WHEN v_replaced THEN pg_catalog.left(v_old_hash, 16) ELSE NULL END,
      'counterBefore', v_dev.attest_counter
    )
  );
  RETURN CASE WHEN v_replaced THEN 'replaced' ELSE 'registered' END;
END;
$$;
REVOKE EXECUTE ON FUNCTION app.register_attest_key(uuid, uuid, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.register_attest_key(uuid, uuid, text, bytea) TO service_role, private_definer;

-- ============================================================================
-- 4. What private_definer needs to run it for ONE bound actor (actor-keyed, like 0032 section 4)
-- ============================================================================
-- SELECT on app.device is pd_edge_act_device_select (0032: the bound actor's own devices). UPDATE is new and
-- limited, by column, to what the function writes; by row, to the bound actor's own devices. The audit INSERT
-- uses 0016's pd_audit_log_insert. edge_actor itself gains NOTHING on these columns (its column grant on
-- app.device excludes attest_key_id / attest_public_key since 0031).
GRANT UPDATE (attest_key_id, attest_public_key, attest_counter, attest_registered_at, attest_retired_key_hashes, last_seen)
  ON app.device TO private_definer;
CREATE POLICY pd_edge_act_device_update ON app.device
  FOR UPDATE TO private_definer
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- The edge_actor entry point: no user argument, kind = 'user' bindings only (a catalog-drain delegate never
-- registers a key). Errors are the ones app.register_attest_key raises.
CREATE FUNCTION private.register_attest_key_for_actor(p_device_id uuid, p_key_id text, p_public_key bytea)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'register_attest_key_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'register_attest_key_for_actor: a system delegate may not register a key' USING ERRCODE = '42501';
  END IF;
  RETURN app.register_attest_key(v_uid, p_device_id, p_key_id, p_public_key);
END;
$$;
REVOKE EXECUTE ON FUNCTION private.register_attest_key_for_actor(uuid, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.register_attest_key_for_actor(uuid, text, bytea) TO edge_actor;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 5. Registries
-- ============================================================================
-- 5a. private.definer_policy_allowlist (FORCE RLS, no policy for the migrating role: the temporary,
-- self-dropped CURRENT_USER policy 0030/0032 use).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0034 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('app', 'device', 'pd_edge_act_device_update', 'UPDATE', true,
   'register_attest_key_for_actor -> app.register_attest_key: the BOUND actor''s own device only (private.actor_uid()), and only the columns granted to private_definer (attest_key_id, attest_public_key, attest_counter, attest_registered_at, attest_retired_key_hashes, last_seen); edge_actor itself holds no UPDATE on the key columns (0034)');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name = 'pd_edge_act_device_update';
DROP POLICY current_user_seed_definer_policy_allowlist_0034 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 5b. private.function_inventory (the 0017 INSERT policy is still in place).
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('app', 'register_attest_key', 'p_user_id uuid, p_device_id uuid, p_key_id text, p_public_key bytea', false, false, true, false, false,
   '0034: records the App Attest key a verified attestation attested (first registration, or a replacement after a reinstall), audits it, refuses the same or a retired key; invoker-rights, called by devices-attest-key through withOwnership as service_role and, for edge_actor, by private.register_attest_key_for_actor as private_definer. Not callable by edge_actor directly'),
  ('private', 'register_attest_key_for_actor', 'p_device_id uuid, p_key_id text, p_public_key bytea', false, false, false, true, false,
   '0034: edge_actor only; app.register_attest_key for the BOUND kind=user actor (no user argument)');
