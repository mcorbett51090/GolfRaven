-- 0045_offline_totp_seed.sql
--
-- P4.2b-3a: the SERVER side of the offline staff code (build plan §7.6 "Offline staff path (G-P1-07)", "Offline marker purchase (G2-03)", "Offline offer
-- redemption (A2-21)"; §4.5 `staff_presence`; P5 acceptance tests (12) and (13)). A 6-digit TOTP (RFC 6238, 10-minute step) is computed on the device from a
-- per-(account, device) seed the server provisions while the device is online. This migration adds what the database owns of that design; the Edge side is
-- supabase/functions/me-offline-seed (the provisioning endpoint) and supabase/functions/_shared/offline-code/ (the pure verification core P5 will call).
-- Migrations 0001-0044 are untouched.
--
-- THE DESIGN IN ONE PARAGRAPH
--   NO PER-DEVICE SEED IS STORED. The seed is DERIVED:  seed = HMAC-SHA256(K, label || user_id || device_id || seed_version)  with
--       label        = 'golfraven/offline-seed/v1' (UTF-8) followed by one 0x00 byte,
--       user_id      = the 16 raw bytes of the uuid,
--       device_id    = the 16 raw bytes of the uuid,
--       seed_version = 4 bytes, big-endian (int4send),
--   a fixed-length encoding after the label, so no two different (user, device, version) triples can produce the same message. K is a secret in Vault
--   (`offline_seed_key`, at least 32 bytes, used as raw UTF-8 bytes like the pseudonym keys). K is read ONLY inside private.offline_seed_derive, a SECURITY DEFINER
--   function owned by private_definer with search_path = '' and EXECUTE for nobody; K is never returned, logged or passed as a parameter. WHERE THE HMAC RUNS
--   (the choice the task asked to be documented): in Postgres. The alternative, handing K to the Edge runtime the way 0035 hands out the sign-in KEK, would put
--   the one key that mints EVERY player's offline code into a process that serves public requests. Here the Edge runtime receives only a derived seed, for one
--   device of the caller, and only after the database has checked that the device is the caller's. A seed leaked from one device is useless for any other
--   device, account or seed version (all three are in the HMAC input) and says nothing about K (HMAC is a PRF).
--
-- WHAT THIS ADDS
--   1. app.device.offline_seed_version (integer NOT NULL DEFAULT 1, monotonic by trigger). Rotation = increment; every code from the old version stops verifying
--      because the seed changes. edge_actor has NO UPDATE on the column; only private.offline_seed_for_actor writes it (private_definer, under the existing
--      pd_edge_act_device_update policy: the BOUND actor's own device).
--   2. app.offline_code_step: the REPLAY table. One row per code step that was accepted, primary key (device_id, seed_version, step), so the same step of the
--      same seed can never be accepted twice, by any number of concurrent staff requests (INSERT ... ON CONFLICT DO NOTHING; the loser sees 0 rows). It carries
--      user_id (the same shape as every personal table: FK to auth.users, classified in private.pii_retention_policy, deleted by delete_my_data's generic pass
--      and exported) and the facility the step was accepted at. It never holds a seed or a code.
--   3. private.offline_seed_derive(user, device, version): the internal core. EXECUTE for NO role: reachable only through the wrappers below and through the
--      staff-lane wrapper P5 adds (docs/security/p3-money-path-requirements.md, "Offline TOTP seed provisioning").
--   4. private.offline_seed_for_actor(device, rotate): edge_actor only. The BOUND actor's own device, else ZERO ROWS (never an error, so a request that is
--      about to answer 404 does not abort its own transaction). Optionally rotates, atomically, under the device row lock.
--   5. private.offline_code_record_step_for_actor(device, seed_version, step, facility): edge_actor only, the staff lane's atomic replay record. The bound actor
--      must hold a staff / manager scope on the facility (private.is_staff_or_manager_of_facility), must not be the device's owner (a staff member can never
--      attest their own player account, A2-21: 22023 `self_attestation_refused`), and the seed version must be the device's CURRENT one. Answers
--      'recorded' | 'replayed' | 'stale_seed_version' | 'step_out_of_window' | 'no_such_device'. It also prunes that device's steps too old to be accepted
--      again, so the table keeps a handful of rows per device, not a history.
--   6. private.export_my_data: the device block gains offline_seed_version and a new block exports the account's own offline_code_step rows. The SEED is
--      not stored and is never exported.
--
-- DELIBERATELY NOT HERE
--   * The staff verification endpoint and the staff-lane seed derivation for ANOTHER player (by handle): P5. Nothing in this migration returns one account's seed
--     to another account's session.
--   * The "5 failures per staff per hour" limit: P5 (the bucket constants are in _shared/offline-code/params.ts).
--   * A TTL purge job for app.offline_code_step. The write-time prune bounds growth per device; a retention-purge step is a follow-up.
--
-- DEPLOY: apply this migration, THEN create the Vault secret (`select vault.create_secret('<random, >= 32 bytes>', 'offline_seed_key')`), THEN deploy the Edge
-- code. Until the secret exists the provisioning function raises 55000 and the endpoint answers 503 `offline_seed_unavailable`; nothing else is affected.
-- ROTATING K invalidates every provisioned seed fleet-wide (every device must re-provision); it is an incident response, not routine (see the design doc).
-- [unverified] on a real Supabase project: that pgcrypto's `hmac` is reachable as public.hmac (0029 already relies on that) and that Vault accepts the name.

-- ============================================================================
-- 1. app.device.offline_seed_version
-- ============================================================================
ALTER TABLE app.device ADD COLUMN offline_seed_version integer NOT NULL DEFAULT 1 CHECK (offline_seed_version >= 1);
COMMENT ON COLUMN app.device.offline_seed_version IS
  'Version of the device''s offline-code seed (0045). The seed is DERIVED from (user, device, this version), never stored; rotation increments it, which invalidates every code from the old seed. Monotonic (never decreases); written only by private.offline_seed_for_actor.';

CREATE FUNCTION app.device_offline_seed_version_monotonic() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- A lower version would make a rotated-out seed valid again: the replay window of a rotation re-opened.
  IF NEW.offline_seed_version < OLD.offline_seed_version THEN
    RAISE EXCEPTION 'device: offline_seed_version is monotonic (% -> % refused, id=%)', OLD.offline_seed_version, NEW.offline_seed_version, OLD.id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER device_offline_seed_version_monotonic_trg
BEFORE UPDATE OF offline_seed_version ON app.device
FOR EACH ROW EXECUTE FUNCTION app.device_offline_seed_version_monotonic();

-- The one narrow column grant the rotation needs. The ROW filter is the existing pd_edge_act_device_update policy (0034): the BOUND actor's own device.
-- edge_actor itself gains no privilege on the column (its UPDATE grant on app.device is a column list that does not include it).
GRANT UPDATE (offline_seed_version) ON app.device TO private_definer;

-- ============================================================================
-- 2. app.offline_code_step (the replay table)
-- ============================================================================
CREATE TABLE app.offline_code_step (
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES app.device (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  seed_version integer NOT NULL CHECK (seed_version >= 1),
  step bigint NOT NULL CHECK (step >= 0),
  -- NOT deferred (unlike the device FK): a facility id that does not exist (only an admin passes the scope check for one) fails AT the INSERT, as a 23503 the Edge code
  -- maps to a 422, not at COMMIT as an opaque 500. delete_my_data never deletes catalog rows, so the 0014 reason for deferring app-internal FKs does not apply.
  facility_id text NOT NULL REFERENCES app.catalog_facility (id),
  used_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, seed_version, step)
);
CREATE INDEX offline_code_step_user_idx ON app.offline_code_step (user_id);
COMMENT ON TABLE app.offline_code_step IS
  '0045. Replay table of the offline staff code (build plan §7.6): one row per ACCEPTED (device, seed version, step), so a code step can never be accepted twice. Holds no seed and no code. Written only by private.offline_code_record_step_for_actor; no client role and no edge role has any privilege on it; deleted with the account (FK cascade and delete_my_data) and exported to its subject.';
ALTER TABLE app.offline_code_step ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.offline_code_step FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.offline_code_step FROM PUBLIC, anon, authenticated;
GRANT SELECT ON app.offline_code_step TO service_role;

-- private_definer: delete_my_data's generic pass (DELETE + the `_r` SELECT companion on user_id, the exact 0016 form) and the export read, and the record
-- function's own INSERT and prune, scoped to ONE device by a transaction-local GUC the definer sets and clears (compared as TEXT in the exact nullif form of
-- verify-function-inventory check 7, so a leftover '' on a reused pooled connection raises nothing and admits nothing).
GRANT SELECT, INSERT, DELETE ON app.offline_code_step TO private_definer;
CREATE POLICY pd_delete_offline_code_step_user_id ON app.offline_code_step
  FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid);
CREATE POLICY pd_delete_offline_code_step_user_id_r ON app.offline_code_step
  FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid);
CREATE POLICY pd_offline_code_step_insert ON app.offline_code_step
  FOR INSERT TO private_definer WITH CHECK (device_id::text = nullif(current_setting('app.offline_code.target_device_id', true), ''));
CREATE POLICY pd_offline_code_step_prune ON app.offline_code_step
  FOR DELETE TO private_definer USING (device_id::text = nullif(current_setting('app.offline_code.target_device_id', true), ''));
CREATE POLICY pd_offline_code_step_prune_r ON app.offline_code_step
  FOR SELECT TO private_definer USING (device_id::text = nullif(current_setting('app.offline_code.target_device_id', true), ''));

-- The staff lane reads the PLAYER's device row (owner and current seed version) for the one device the definer named in the GUC. The bound actor's own
-- devices are already visible through pd_edge_act_device_select (0032); this is the other account's, one id at a time, inside the definer only.
CREATE POLICY pd_offline_code_device_select ON app.device
  FOR SELECT TO private_definer USING (id::text = nullif(current_setting('app.offline_code.target_device_id', true), ''));

-- ============================================================================
-- 3. The definer functions (ownership bracket: 0020 / 0022 / 0030)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. THE derivation. The only place K is read. No role is granted EXECUTE (the wrappers below, owned by the same role, call it; PUBLIC is revoked below). It
-- derives for ANY (user, device, version) it is handed, so it must never be reachable from a session: it is the core, like private.signin_enqueue_internal.
-- The failure message names no key material (the Edge runtime maps 55000 to a bare 503, and the database log carries only this text).
CREATE FUNCTION private.offline_seed_derive(p_user_id uuid, p_device_id uuid, p_seed_version integer)
RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
BEGIN
  IF p_user_id IS NULL OR p_device_id IS NULL OR p_seed_version IS NULL OR p_seed_version < 1 THEN
    RAISE EXCEPTION 'offline_seed_derive: a user, a device and a seed version of at least 1 are required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'offline_seed_key';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'offline_seed_derive: the offline seed key is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  RETURN public.hmac(
    pg_catalog.convert_to('golfraven/offline-seed/v1', 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.decode(pg_catalog.replace(p_user_id::text, '-', ''), 'hex')
      || pg_catalog.decode(pg_catalog.replace(p_device_id::text, '-', ''), 'hex')
      || pg_catalog.int4send(p_seed_version),
    pg_catalog.convert_to(v_key, 'UTF8'),
    'sha256');
END;
$$;

-- 3b. Provisioning, for the BOUND kind = 'user' actor (no uid argument). ZERO ROWS for a device that is not the actor's own or does not exist (the same
-- answer for both: no oracle on device ids, and nothing raised, so the caller's transaction is not aborted). p_rotate = true increments the device's seed
-- version first (one atomic UPDATE under the row lock, so two concurrent rotations get two different versions) and derives under the new one. The seed
-- is returned to the caller as a function RESULT, never logged here; it is a secret of the device and the caller is that device's own account.
CREATE FUNCTION private.offline_seed_for_actor(p_device_id uuid, p_rotate boolean)
RETURNS TABLE (o_seed bytea, o_seed_version integer, o_issued_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_version integer;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'offline_seed_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'offline_seed_for_actor: a system delegate may not read an offline seed' USING ERRCODE = '42501';
  END IF;
  IF p_device_id IS NULL OR p_rotate IS NULL THEN
    RAISE EXCEPTION 'offline_seed_for_actor: a device id and a rotate flag are required' USING ERRCODE = '22023';
  END IF;
  IF p_rotate THEN
    UPDATE app.device d SET offline_seed_version = d.offline_seed_version + 1
    WHERE d.id = p_device_id AND d.user_id = v_uid
    RETURNING d.offline_seed_version INTO v_version;
  ELSE
    SELECT d.offline_seed_version INTO v_version FROM app.device d WHERE d.id = p_device_id AND d.user_id = v_uid;
  END IF;
  IF v_version IS NULL THEN
    RETURN;
  END IF;
  o_seed := private.offline_seed_derive(v_uid, p_device_id, v_version);
  o_seed_version := v_version;
  o_issued_at := pg_catalog.clock_timestamp();
  RETURN NEXT;
END;
$$;

-- 3c. The atomic replay record, for the BOUND kind = 'user' actor acting as STAFF. The verification itself (derive the player's seed, check the typed code) is
-- P5's, in the staff Edge function; this is the step that makes it single-use. Order of checks matters: the SCOPE check comes first, so a caller with no staff
-- scope at the facility learns nothing about whether a device exists or what version it is at.
--   42501  no actor bound / a system delegate / no staff or manager scope at p_facility_id
--   22023  bad arguments, or the device is the caller's OWN (a staff member can never attest their own player account, A2-21)
-- and otherwise a status: 'no_such_device', 'stale_seed_version' (the caller derived under a version that is no longer current: a rotation happened between
-- the derive and this call), 'step_out_of_window' (further than 2 steps from the database clock: the TypeScript core accepts +-1, this bound is deliberately
-- wider so the two clocks sitting either side of a step boundary never refuse a code the core accepted), 'replayed' (that exact (device, version, step)
-- was already recorded) or 'recorded'.
CREATE FUNCTION private.offline_code_record_step_for_actor(p_device_id uuid, p_seed_version integer, p_step bigint, p_facility_id text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_owner uuid;
  v_version integer;
  v_now_step bigint;
  v_n integer;
  v_result text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'offline_code_record_step_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'offline_code_record_step_for_actor: a system delegate may not record an offline code step' USING ERRCODE = '42501';
  END IF;
  IF p_device_id IS NULL OR p_seed_version IS NULL OR p_seed_version < 1 OR p_step IS NULL OR p_step < 0
     OR p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'offline_code_record_step_for_actor: a device, a seed version, a step and a facility are required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.is_staff_or_manager_of_facility(v_uid, p_facility_id) THEN
    RAISE EXCEPTION 'offline_code_record_step_for_actor: the caller holds no staff scope at that facility' USING ERRCODE = '42501';
  END IF;

  PERFORM pg_catalog.set_config('app.offline_code.target_device_id', p_device_id::text, true);
  SELECT d.user_id, d.offline_seed_version INTO v_owner, v_version FROM app.device d WHERE d.id = p_device_id;
  IF v_owner IS NULL THEN
    v_result := 'no_such_device';
  ELSIF v_owner = v_uid THEN
    PERFORM pg_catalog.set_config('app.offline_code.target_device_id', '', true);
    RAISE EXCEPTION 'self_attestation_refused: a staff member cannot attest their own account' USING ERRCODE = '22023';
  ELSIF p_seed_version <> v_version THEN
    v_result := 'stale_seed_version';
  ELSE
    v_now_step := pg_catalog.floor(EXTRACT(epoch FROM pg_catalog.clock_timestamp()) / 600)::bigint;
    IF pg_catalog.abs(p_step - v_now_step) > 2 THEN
      v_result := 'step_out_of_window';
    ELSE
      -- Steps further than 3 behind the clock can never be accepted again (the window above is +-2), so a row for one is dead weight; drop them.
      DELETE FROM app.offline_code_step s WHERE s.device_id = p_device_id AND s.step < v_now_step - 3;
      INSERT INTO app.offline_code_step (user_id, device_id, seed_version, step, facility_id)
      VALUES (v_owner, p_device_id, p_seed_version, p_step, p_facility_id)
      ON CONFLICT (device_id, seed_version, step) DO NOTHING;
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_result := CASE WHEN v_n = 1 THEN 'recorded' ELSE 'replayed' END;
    END IF;
  END IF;
  PERFORM pg_catalog.set_config('app.offline_code.target_device_id', '', true);
  RETURN v_result;
END;
$$;

-- 3d. EXECUTE grants. PUBLIC first (private_definer-created functions default to PUBLIC), then exactly the roles below. The derive core: nobody.
REVOKE EXECUTE ON FUNCTION private.offline_seed_derive(uuid, uuid, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.offline_seed_for_actor(uuid, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.offline_code_record_step_for_actor(uuid, integer, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.offline_seed_for_actor(uuid, boolean) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.offline_code_record_step_for_actor(uuid, integer, bigint, text) TO edge_actor;

COMMENT ON FUNCTION private.offline_seed_derive(uuid, uuid, integer) IS
  '0045. The ONLY reader of Vault secret offline_seed_key: HMAC-SHA256(K, ''golfraven/offline-seed/v1'' || 0x00 || user_id(16 bytes) || device_id(16 bytes) || int4send(seed_version)). No role has EXECUTE; reachable only through the SECURITY DEFINER wrappers. K is never returned.';
COMMENT ON FUNCTION private.offline_seed_for_actor(uuid, boolean) IS
  '0045. edge_actor only. The offline-code seed of the BOUND actor''s own device (zero rows for any other device), optionally rotating (seed_version + 1) first; the seed is a function result only.';
COMMENT ON FUNCTION private.offline_code_record_step_for_actor(uuid, integer, bigint, text) IS
  '0045. edge_actor only. Staff lane: atomically records an accepted (device, seed version, step) at a facility where the bound actor holds a staff or manager scope; refuses the actor''s own device (22023 self_attestation_refused). Returns recorded | replayed | stale_seed_version | step_out_of_window | no_such_device.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Export: private.export_my_data, rebuilt from 0044's FINAL body with exactly TWO changes (the device column list, and the offline_code_step block, both commented 0045)
-- ============================================================================
-- DECISION (the task asked for it to be made and recorded): personal data about the account is exported, the secret is not. offline_seed_version is a counter
-- about the account's own device, the same kind of fact as first_attested_at; the replay rows record that a staff member accepted a code of the account's own device
-- at a facility at a time (a presence-shaped record about the subject, like purchase_evidence), so the subject is entitled to see them. NO seed is exported:
-- there is none stored, and the derivation key is not the subject's data. Same SECURITY DEFINER / empty search_path / owner / ACL (CREATE OR REPLACE keeps them).
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.export_my_data(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_result jsonb := '{}'::jsonb;
  v_tbl record;
  v_json jsonb;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'export_my_data: user_id is required';
  END IF;

  PERFORM set_config('app.delete_my_data.target_user_id', p_user_id::text, true);

  -- ==========================================================================
  -- Fail-closed coverage check (must run FIRST, before any real export):
  -- every app. table private.pii_retention_policy classifies at all
  -- (delete_row/set_null/special) must have a private.pii_export_policy
  -- row. A personal table added later with no export decision made for
  -- it fails EVERY export call, loudly, rather than silently vanishing
  -- from the output.
  -- ==========================================================================
  FOR v_tbl IN
    SELECT DISTINCT table_name
    FROM private.pii_retention_policy
    WHERE schema_name = 'app'
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM private.pii_export_policy
      WHERE schema_name = 'app' AND table_name = v_tbl.table_name
    ) THEN
      RAISE EXCEPTION
        'export_my_data: app.% is classified in private.pii_retention_policy but has no private.pii_export_policy row -- classify it (export/exclude, with a reason) before export can run',
        v_tbl.table_name;
    END IF;
  END LOOP;

  -- ==========================================================================
  -- Explicit, hand-written exports. Every SELECT names its own columns —
  -- never `SELECT *` / `to_jsonb(t)` over a whole row.
  -- ==========================================================================
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, created_at FROM app.admin_user WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('admin_user', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id FROM app.app_review_demo_account WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('app_review_demo_account', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, provider, provider_ref, facility_id, tee_time, status
    FROM app.booking WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('booking', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, provider, external_user_id, scopes, status, created_at, revoked_at
    FROM app.connector_account WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('connector_account', v_json);

  -- 0045: offline_seed_version added to the column list (a counter about the account's own device).
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, platform, attest_key_id, attest_counter, integrity_last, first_attested_at, offline_seed_version, first_seen, last_seen
    FROM app.device WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('device', v_json);

  -- ---- P3f additions (0028): the caller's own reward-issuance ledger ----
  -- A reduced projection: which of the caller's OWN rewards were issued on which
  -- of the caller's OWN devices, and when. devicecheck_token_hash is the
  -- secret-key denylist's (a vendor-token digest, never exported, same as on
  -- app.device / offer_code / entitlement); nothing here names another account.
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, device_id, reward_kind, reward_id, at
    FROM app.device_reward_ledger WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('device_reward_ledger', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, device_id, source, source_ref, input_hash, course_id, facility_id,
           started_at, ended_at, local_date, summary, integrity, cosignal, attestation_grade,
           matcher_version, catalog_version, status, created_at,
           claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input
    FROM app.evidence WHERE user_id = p_user_id
  ) t;
  -- P3e round 2/3 (0024): the four queued_catalog columns are exported —
  -- see this migration's own header, section 4, for why queued_input is
  -- the caller's own data.
  v_result := v_result || jsonb_build_object('evidence', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, trail_id, facility_id, purchase_evidence_id, status, created_at
    FROM app.marker_credit WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('marker_credit', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, offer_id, user_id, facility_id, state, earned_at, activated_device_id,
           activated_at, expires_at, expiry_paused_at, redeemed_at, redeemed_offline
    FROM app.offer_code WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('offer_code', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, org_id, role, revoked_at, created_at
    FROM app.partner_member WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('partner_member', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, course_id, facility_id, play_date, course_disambiguated_by,
           score_badge, score_monetary, hard_signal, presence_signal, money, held_review,
           policy_version, input_digest, status
    FROM app.play WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('play', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, handle, locale, home_region, birth_year_bucket, leaderboard_opt_in, created_at
    FROM app.profile WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('profile', v_json);

  -- P3d gate round 3, S1: ref_id excluded (this file's own header —
  -- for a course-QR row it is the consumed token's own nonce hash, not
  -- the caller's own data).
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, facility_id, trail_id, method, qr_variant, offline, cosignal,
           no_cosignal_reason, ip_region_match, local_date, status, created_at
    FROM app.purchase_evidence WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('purchase_evidence', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, device_id, expo_token, updated_at
    FROM app.push_token WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('push_token', v_json);

  -- 0045: the account's own offline-code replay rows (which step of which of its OWN devices was accepted, at which facility, and when). The seed itself is
  -- DERIVED, never stored, and is never exported; the version on the device block is just a counter.
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, device_id, seed_version, step, facility_id, used_at
    FROM app.offline_code_step WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('offline_code_step', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, achievement_id, award_key, awarded_at, basis, revoked_at, revoke_reason
    FROM app.user_achievement WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('user_achievement', v_json);

  -- ---- Subject specials (four named columns) --------------------------
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, facility_id, player_user_id, player_pseudonym, kind, token_jti, cosignal_ok, created_at
    FROM app.attestation WHERE player_user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('attestation', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, kind, trail_id, roster_version, sponsorship_id, basis, state,
           activated_device_id, activated_at, redeemed_at, redeemed_facility_id,
           redemption_method, redemption_jti, redemption_cosignal_ok, voucher_facility_id, voucher_issued_at
    FROM app.entitlement WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('entitlement', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, facility_id, local_date, phash, receipt_number_ocr, created_at
    FROM app.receipt_fingerprint WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('receipt_fingerprint', v_json);

  -- P3d gate round 3, S1: subject_id excluded (this file's own header —
  -- a polymorphic reference that can itself be another account's id).
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, action, subject_table, created_at
    FROM app.audit_log WHERE actor_user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('audit_log', v_json);

  -- ---- The gate's two named, deliberately-restricted exceptions ------
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, kind, created_at FROM app.fraud_signal WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('fraud_signal', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, kind, created_at FROM app.review_item WHERE resolved_by = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('review_item', v_json);

  RETURN v_result;
END;
$$;

COMMENT ON FUNCTION private.export_my_data(uuid) IS
  'Read-only twin of private.delete_my_data — walks the SAME private.pii_retention_policy registry, cross-checked against private.pii_export_policy (fail-closed: raises if any classified table has no export decision). Every SELECT names its own explicit column list; never SELECT */to_jsonb(t) over a whole row, and never reached through a set_null ACTOR column. P3d gate round 3: also excludes audit_log.subject_id and purchase_evidence.ref_id (S1). P3e (0024): the evidence block additionally exports claimed_facility_id/claimed_course_id/claimed_catalog_version/queued_input. P3f (0028): additionally exports a reduced projection of the caller own device_reward_ledger rows (never devicecheck_token_hash); 0044: the device block additionally exports first_attested_at (0043); 0045: the device block additionally exports offline_seed_version and a new offline_code_step block exports the caller own replay rows (never a seed: none is stored); every other block is byte-identical to 0044.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 5. Registries
-- ============================================================================
-- 5a. private.definer_policy_allowlist (FORCE RLS, no policy for the migrating role: the temporary, self-dropped CURRENT_USER policy 0035 / 0039 use).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0045 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('app', 'offline_code_step', 'pd_delete_offline_code_step_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: offline_code_step.user_id = delete_row): the deleted account''s own replay rows, GUC-scoped'),
  ('app', 'offline_code_step', 'pd_delete_offline_code_step_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_offline_code_step_user_id; also the export read and delete_my_data''s post-condition count'),
  ('app', 'offline_code_step', 'pd_offline_code_step_insert', 'INSERT', true, 'offline_code_record_step_for_actor: the one row of the ONE device the definer named in app.offline_code.target_device_id, set and cleared inside the definer'),
  ('app', 'offline_code_step', 'pd_offline_code_step_prune', 'DELETE', true, 'offline_code_record_step_for_actor: that one device''s steps too old to be accepted again (more than 3 steps behind the database clock)'),
  ('app', 'offline_code_step', 'pd_offline_code_step_prune_r', 'SELECT', true, 'visibility companion to pd_offline_code_step_prune (DELETE ... WHERE needs SELECT-level visibility)'),
  ('app', 'device', 'pd_offline_code_device_select', 'SELECT', true, 'offline_code_record_step_for_actor: the owner and current offline_seed_version of the ONE device named in app.offline_code.target_device_id (the staff lane reads the player''s device row; the bound actor''s own devices are pd_edge_act_device_select)');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_delete_offline_code_step_user_id', 'pd_delete_offline_code_step_user_id_r', 'pd_offline_code_step_insert',
    'pd_offline_code_step_prune', 'pd_offline_code_step_prune_r', 'pd_offline_code_device_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0045 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 5b. PII registries. The table carries a user_id FK to auth.users, so it is a personal table: retention = delete with the account, export = yes.
GRANT INSERT ON private.pii_retention_policy TO CURRENT_USER;
CREATE POLICY current_user_seed_pii_retention_policy_0045 ON private.pii_retention_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'offline_code_step', 'user_id', 'delete_row', 'own offline-code replay row (0045): which step of the account''s own device a staff member accepted, where and when; deleted with the account by delete_my_data''s generic pass (and by FK cascade with the device and the auth user)');
DROP POLICY current_user_seed_pii_retention_policy_0045 ON private.pii_retention_policy;
REVOKE INSERT ON private.pii_retention_policy FROM CURRENT_USER;

CREATE POLICY current_user_seed_pii_export_policy_0045 ON private.pii_export_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_export_policy (schema_name, table_name, action, reason) VALUES
  ('app', 'offline_code_step', 'export', 'own offline-code replay rows (user_id, device_id, seed_version, step, facility_id, used_at): a presence-shaped record about the subject, like purchase_evidence; no seed exists to export (0045)');
DROP POLICY current_user_seed_pii_export_policy_0045 ON private.pii_export_policy;

-- 5c. private.function_inventory (the 0017 INSERT policy is still in place)
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('app', 'device_offline_seed_version_monotonic', '', false, false, false, false, false,
   '0045: trigger function (app.device_offline_seed_version_monotonic_trg, BEFORE UPDATE OF offline_seed_version) -- the seed version never decreases (a lower one would revive a rotated-out seed); never EXECUTEd directly by any role'),
  ('private', 'offline_seed_derive', 'p_user_id uuid, p_device_id uuid, p_seed_version integer', false, false, false, false, false,
   '0045: the ONLY reader of Vault secret offline_seed_key; HMAC-SHA256 derivation of the offline-code seed for ANY (user, device, version) it is handed, so NO role has EXECUTE: reachable only through the SECURITY DEFINER wrappers (and the staff-lane wrapper P5 adds)'),
  ('private', 'offline_seed_for_actor', 'p_device_id uuid, p_rotate boolean', false, false, false, true, false,
   '0045: edge_actor only; the offline-code seed of the BOUND kind=user actor''s own device (zero rows for any other), optionally rotating (seed_version + 1) first'),
  ('private', 'offline_code_record_step_for_actor', 'p_device_id uuid, p_seed_version integer, p_step bigint, p_facility_id text', false, false, false, true, false,
   '0045: edge_actor only; staff lane: atomically records an accepted offline-code step (INSERT ... ON CONFLICT DO NOTHING) at a facility where the bound actor holds a staff or manager scope; refuses the actor''s own device (22023)');

-- ============================================================================
-- 6. Proofs (the migration stops if any of them fails)
-- ============================================================================
DO $assert_0045$
BEGIN
  IF has_column_privilege('edge_actor', 'app.device', 'offline_seed_version', 'UPDATE') OR has_column_privilege('edge_actor', 'app.device', 'offline_seed_version', 'INSERT') THEN
    RAISE EXCEPTION '0045: edge_actor must hold no INSERT or UPDATE on app.device.offline_seed_version (only private.offline_seed_for_actor writes it)';
  END IF;
  IF has_table_privilege('edge_actor', 'app.offline_code_step', 'SELECT') OR has_table_privilege('edge_actor', 'app.offline_code_step', 'INSERT')
     OR has_table_privilege('edge_actor', 'app.offline_code_step', 'UPDATE') OR has_table_privilege('edge_actor', 'app.offline_code_step', 'DELETE')
     OR has_table_privilege('edge_system', 'app.offline_code_step', 'SELECT') OR has_table_privilege('authenticated', 'app.offline_code_step', 'SELECT')
     OR has_table_privilege('anon', 'app.offline_code_step', 'SELECT') THEN
    RAISE EXCEPTION '0045: no edge or client role may hold any privilege on app.offline_code_step (every path is a definer)';
  END IF;
  IF NOT (SELECT relforcerowsecurity AND relrowsecurity FROM pg_class WHERE oid = 'app.offline_code_step'::regclass) THEN
    RAISE EXCEPTION '0045: app.offline_code_step must have ENABLE and FORCE ROW LEVEL SECURITY';
  END IF;
  IF NOT (SELECT relforcerowsecurity FROM pg_class WHERE oid = 'app.device'::regclass) THEN
    RAISE EXCEPTION '0045: app.device must keep FORCE ROW LEVEL SECURITY';
  END IF;
  IF has_function_privilege('edge_actor', 'private.offline_seed_derive(uuid, uuid, integer)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.offline_seed_derive(uuid, uuid, integer)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.offline_seed_derive(uuid, uuid, integer)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.offline_seed_derive(uuid, uuid, integer)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.offline_seed_derive(uuid, uuid, integer)', 'EXECUTE') THEN
    RAISE EXCEPTION '0045: no role may EXECUTE private.offline_seed_derive (the one reader of the derivation key)';
  END IF;
  IF NOT has_function_privilege('edge_actor', 'private.offline_seed_for_actor(uuid, boolean)', 'EXECUTE')
     OR NOT has_function_privilege('edge_actor', 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0045: edge_actor must EXECUTE both offline-code wrappers';
  END IF;
  IF has_function_privilege('edge_system', 'private.offline_seed_for_actor(uuid, boolean)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.offline_seed_for_actor(uuid, boolean)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.offline_seed_for_actor(uuid, boolean)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.offline_seed_for_actor(uuid, boolean)', 'EXECUTE') THEN
    RAISE EXCEPTION '0045: only edge_actor may EXECUTE private.offline_seed_for_actor';
  END IF;
END
$assert_0045$;
