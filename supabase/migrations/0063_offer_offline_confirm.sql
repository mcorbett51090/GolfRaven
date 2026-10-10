-- 0063_offer_offline_confirm.sql
--
-- P5 follow-up to 0062 (offline_code offer redeem): PLAYER-LANE co-signal that CLEARS
-- app.offer_code.offline_confirm_by. Money doc step 5 / A2-21 / design §35.3 / §37:
-- a qualifying fix within the offline code's step window (step start −10 min … +20 min,
-- same window S3 uses for marker_purchase awaiting) confirms the offline redeem before
-- the 24 h deadline; settlement unconfirmed_count and fraud_signal offer_offline_unconfirmed
-- then stop counting that code.
--
-- WHAT THIS ADDS
--   1. app.offer_code.offline_step: the HOTP step recorded at redeem (offline_code_step rows
--      prune after ~3 steps; the 24 h confirm window needs the step on the code itself).
--   2. CREATE OR REPLACE apply_offline: also writes offline_step (signature gains p_offline_step).
--   3. private.offer_offline_confirm_for_actor (edge_actor): same co-signal proof as
--      marker_cosignal_attach_for_actor; clears offline_confirm_by on the bound player's own
--      redeemed_offline codes at the facility whose offline_step window holds the fix and
--      whose offline_confirm_by is still in the future. Statuses commit: confirmed | none_awaiting
--      | cosignal_invalid | cosignal_used | review_account.
--
-- DELIBERATELY NOT HERE: rollups-refresh writer; receipts upload; partners UI (already §36).
-- Nothing from 0001–0062 is edited except REPLACE of the 0062 apply helper (arg list change).

-- ============================================================================
-- 1. Column
-- ============================================================================
ALTER TABLE app.offer_code ADD COLUMN offline_step bigint;
COMMENT ON COLUMN app.offer_code.offline_step IS
  '0063: HOTP step accepted at offline offer redeem (0062). Used by offer_offline_confirm_for_actor to match a player fix to the redeem; NULL for staff_scan. Survives offline_code_step prune.';

-- ============================================================================
-- 2. Apply helper (DROP: arg list change) + redeem call site + confirm definer
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

DROP FUNCTION IF EXISTS private.partner_offers_redeem_apply_offline(uuid, text, uuid, uuid, uuid, text, numeric);

CREATE FUNCTION private.partner_offers_redeem_apply_offline(
  p_staff uuid, p_facility_id text, p_player uuid, p_offer_id uuid, p_offer_code_id uuid, p_jti text, p_amount numeric, p_offline_step bigint
)
RETURNS TABLE (o_status text, o_attestation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_w record;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  BEGIN
    PERFORM app.consume_offer_budget(p_offer_id, p_amount);
  EXCEPTION
    WHEN check_violation THEN
      RETURN QUERY SELECT 'budget_short'::text, NULL::uuid;
      RETURN;
  END;

  SELECT w.o_status, w.o_attestation_id INTO v_w
  FROM private.partner_attest_write(p_staff, p_facility_id, p_player, 'offer_redemption', 'ofr-off:' || p_jti, p_jti, true, false, v_now, v_now) w;
  IF v_w.o_status <> 'ok' THEN
    UPDATE app.offer
    SET budget_used = GREATEST(budget_used - p_amount, 0),
        budget_reserved = budget_reserved + p_amount
    WHERE id = p_offer_id;
    RETURN QUERY SELECT v_w.o_status, NULL::uuid;
    RETURN;
  END IF;

  INSERT INTO private.consumed_nonce (nonce_hash, source) VALUES (p_jti, 'offer_redemption');
  UPDATE app.offer_code
  SET state = 'redeemed', redeemed_at = v_now, redeemed_by_staff = p_staff, redeemed_offline = true,
      offline_confirm_by = v_now + interval '24 hours',
      offline_step = p_offline_step
  WHERE id = p_offer_code_id;
  PERFORM private.partner_audit_write('partner.offer_redeem_offline', 'app.offer_code', p_offer_code_id::text,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'offer', p_offer_id, 'method', 'offline_code', 'amount', p_amount, 'step', p_offline_step));
  RETURN QUERY SELECT 'ok'::text, v_w.o_attestation_id;
END
$$;

-- Redeclare redeem_offline so its call to apply passes the step (body otherwise identical to 0062).
CREATE OR REPLACE FUNCTION private.partner_offers_redeem_offline_for_partner(
  p_facility_id text, p_offer_code_id uuid, p_handle text, p_code text, p_name_confirmed boolean
)
RETURNS TABLE (o_status text, o_attestation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_player uuid;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_step_now bigint := pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 600)::bigint;
  v_staff_key text;
  v_hour_key text;
  v_day_key text;
  v_fails bigint;
  v_t_hour bigint;
  v_t_day bigint;
  v_cmp bytea := public.gen_random_bytes(16);
  v_dev record;
  v_off integer;
  v_seed bytea;
  v_hit_dev uuid;
  v_hit_ver integer;
  v_hit_step bigint;
  v_n integer;
  v_failed boolean := true;
  v_replayed boolean := false;
  v_code record;
  v_amount numeric;
  v_jti text;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_offer_code_id IS NULL OR p_handle IS NULL OR p_code IS NULL THEN
    RAISE EXCEPTION 'partner_offers_redeem_offline_for_partner: a facility, an offer code, a handle and a code are required' USING ERRCODE = '22023';
  END IF;
  IF p_name_confirmed IS DISTINCT FROM true THEN
    RETURN QUERY SELECT 'name_unconfirmed'::text, NULL::uuid;
    RETURN;
  END IF;

  v_staff_key := 'offline-code-fail:staff:' || v_uid::text;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_staff_key, 0));
  SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_fails FROM private.rate_limit_bucket r WHERE r.bucket_key = v_staff_key AND r.window_start > v_now - interval '1 hour';
  IF v_fails >= 5 THEN
    RETURN QUERY SELECT 'rate_limited'::text, NULL::uuid;
    RETURN;
  END IF;

  IF pg_catalog.char_length(p_handle) BETWEEN 3 AND 20 AND p_handle !~ '[^a-z0-9_]' THEN
    SELECT p.user_id INTO v_player FROM app.profile p WHERE p.handle = p_handle;
  END IF;
  IF v_player IS NOT NULL AND private.is_demo_account(v_player) THEN
    v_player := NULL;
  END IF;
  IF v_player IS NOT NULL AND v_player = v_uid THEN
    RAISE EXCEPTION 'self_redeem_refused: a staff member cannot redeem their own account' USING ERRCODE = '22023';
  END IF;

  IF v_player IS NOT NULL THEN
    v_hour_key := 'offline-code-fail:target-h:' || v_player::text;
    v_day_key := 'offline-code-fail:target-d:' || v_player::text;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_hour_key, 0));
    SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_t_hour FROM private.rate_limit_bucket r WHERE r.bucket_key = v_hour_key AND r.window_start > v_now - interval '1 hour';
    SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_t_day FROM private.rate_limit_bucket r WHERE r.bucket_key = v_day_key AND r.window_start > v_now - interval '1 day';
    IF v_t_hour >= 10 OR v_t_day >= 30 THEN
      RETURN QUERY SELECT 'rate_limited'::text, NULL::uuid;
      RETURN;
    END IF;
  END IF;

  IF v_player IS NOT NULL AND pg_catalog.char_length(p_code) = 6 AND p_code !~ '[^0-9]' THEN
    FOR v_dev IN
      SELECT d.id AS id, d.offline_seed_version AS ver
      FROM app.device d
      WHERE d.user_id = v_player AND d.last_seen > v_now - interval '90 days'
      ORDER BY d.last_seen DESC, d.id
      LIMIT 5
    LOOP
      v_seed := private.offline_seed_derive(v_player, v_dev.id, v_dev.ver);
      FOR v_off IN -1 .. 1 LOOP
        IF public.hmac(pg_catalog.convert_to(private.hotp(v_seed, v_step_now + v_off, 6, 'sha256'), 'UTF8'), v_cmp, 'sha256') = public.hmac(pg_catalog.convert_to(p_code, 'UTF8'), v_cmp, 'sha256') AND v_hit_dev IS NULL THEN
          v_hit_dev := v_dev.id;
          v_hit_ver := v_dev.ver;
          v_hit_step := v_step_now + v_off;
        END IF;
      END LOOP;
    END LOOP;
  END IF;

  IF v_hit_dev IS NOT NULL THEN
    DELETE FROM app.offline_code_step s WHERE s.device_id = v_hit_dev AND s.step < v_step_now - 3;
    INSERT INTO app.offline_code_step (user_id, device_id, seed_version, step, facility_id)
    VALUES (v_player, v_hit_dev, v_hit_ver, v_hit_step, p_facility_id)
    ON CONFLICT (device_id, seed_version, step) DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n = 1 THEN
      v_failed := false;
    ELSE
      v_replayed := true;
    END IF;
  END IF;

  IF v_failed THEN
    PERFORM private.hit_rate_limit(v_staff_key, interval '1 hour', 1000000);
    IF v_player IS NOT NULL THEN
      PERFORM private.hit_rate_limit(v_hour_key, interval '1 hour', 1000000);
      PERFORM private.hit_rate_limit(v_day_key, interval '1 day', 1000000);
    END IF;
    RETURN QUERY SELECT (CASE WHEN v_replayed THEN 'replayed' ELSE 'verification_failed' END)::text, NULL::uuid;
    RETURN;
  END IF;

  SELECT c.user_id, c.offer_id, c.facility_id, c.state, c.expires_at, c.reserved_amount INTO v_code
  FROM app.offer_code c WHERE c.id = p_offer_code_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_code.user_id <> v_player THEN
    RETURN QUERY SELECT 'wrong_player'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_code.state <> 'issued' OR private.is_demo_account(v_code.user_id) THEN
    RETURN QUERY SELECT 'not_issued'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_code.expires_at IS NOT NULL AND v_code.expires_at <= v_now THEN
    RETURN QUERY SELECT 'expired'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_code.facility_id IS DISTINCT FROM p_facility_id THEN
    RETURN QUERY SELECT 'wrong_facility'::text, NULL::uuid;
    RETURN;
  END IF;

  SELECT c.user_id, c.offer_id, c.facility_id, c.state, c.expires_at, c.reserved_amount INTO v_code
  FROM app.offer_code c WHERE c.id = p_offer_code_id FOR UPDATE;
  IF NOT FOUND OR v_code.state <> 'issued' THEN
    RETURN QUERY SELECT 'not_issued'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_code.expires_at IS NOT NULL AND v_code.expires_at <= v_now THEN
    RETURN QUERY SELECT 'expired'::text, NULL::uuid;
    RETURN;
  END IF;

  v_amount := v_code.reserved_amount;
  IF v_amount IS NULL OR v_amount < 0 THEN
    v_amount := 0;
  END IF;
  v_jti := 'offline:' || v_hit_dev::text || ':' || v_hit_ver::text || ':' || v_hit_step::text;
  IF EXISTS (SELECT 1 FROM private.consumed_nonce n WHERE n.nonce_hash = v_jti) THEN
    RETURN QUERY SELECT 'replayed'::text, NULL::uuid;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT a.o_status, a.o_attestation_id
  FROM private.partner_offers_redeem_apply_offline(v_uid, p_facility_id, v_code.user_id, v_code.offer_id, p_offer_code_id, v_jti, v_amount, v_hit_step) a;
END
$$;

-- Player-lane clear of offline_confirm_by (HARD RULE: every statement filters by the bound uid).
CREATE FUNCTION private.offer_offline_confirm_for_actor(
  p_facility_id text,
  p_at timestamptz,
  p_cosignal_grade text,
  p_cosignal_fix_id text,
  p_cosignal_evidence_id uuid
)
RETURNS TABLE (o_result text, o_cleared integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_now timestamptz := pg_catalog.now();
  v_tz text;
  v_check text;
  v_n integer := 0;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'offer_offline_confirm_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'offer_offline_confirm_for_actor: a system delegate may not confirm an offline offer' USING ERRCODE = '42501';
  END IF;
  IF private.is_demo_account(v_uid) THEN
    o_result := 'review_account';
    o_cleared := 0;
    RETURN NEXT;
    RETURN;
  END IF;
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_at IS NULL OR p_cosignal_grade IS NULL OR p_cosignal_grade NOT IN ('attested', 'unattestable')
     OR p_cosignal_fix_id IS NULL OR p_cosignal_evidence_id IS NULL OR p_at < v_now - interval '7 days' OR p_at > v_now + interval '5 minutes' THEN
    RAISE EXCEPTION 'offer_offline_confirm_for_actor: invalid arguments (a facility, a qualifying co-signal and a time within 7 days)' USING ERRCODE = '22023';
  END IF;

  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    o_result := 'none_awaiting';
    o_cleared := 0;
    RETURN NEXT;
    RETURN;
  END IF;
  v_check := private.marker_cosignal_check(v_uid, p_facility_id, (p_at AT TIME ZONE v_tz)::date, p_at, p_cosignal_grade, p_cosignal_fix_id, p_cosignal_evidence_id);
  IF v_check <> 'ok' THEN
    o_result := v_check;
    o_cleared := 0;
    RETURN NEXT;
    RETURN;
  END IF;

  -- Same step window as S3 offline marker_purchase awaiting: step start −10 min … +20 min; until = offline_confirm_by.
  UPDATE app.offer_code c
  SET offline_confirm_by = NULL
  WHERE c.user_id = v_uid
    AND c.facility_id = p_facility_id
    AND c.redeemed_offline
    AND c.offline_confirm_by IS NOT NULL
    AND c.offline_confirm_by >= v_now
    AND c.offline_step IS NOT NULL
    AND p_at >= pg_catalog.to_timestamp((c.offline_step * 600)::double precision) - interval '10 minutes'
    AND p_at <= pg_catalog.to_timestamp((c.offline_step * 600)::double precision) + interval '20 minutes';
  GET DIAGNOSTICS v_n = ROW_COUNT;

  -- No partner_audit_write here: that helper requires a partner binding and action ^partner\.. Marker attach also leaves no audit row.
  IF v_n > 0 THEN
    o_result := 'confirmed';
    o_cleared := v_n;
  ELSE
    o_result := 'none_awaiting';
    o_cleared := 0;
  END IF;
  RETURN NEXT;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_offers_redeem_apply_offline(uuid, text, uuid, uuid, uuid, text, numeric, bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.offer_offline_confirm_for_actor(text, timestamptz, text, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.offer_offline_confirm_for_actor(text, timestamptz, text, text, uuid) TO edge_actor;

COMMENT ON FUNCTION private.partner_offers_redeem_apply_offline(uuid, text, uuid, uuid, uuid, text, numeric, bigint) IS
  '0062/0063. Mutating tail of an offline offer redeem (consume, attest, nonce, code update with redeemed_offline, offline_confirm_by and offline_step). EXECUTE for nobody but the owner.';
COMMENT ON FUNCTION private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean) IS
  '0062/0063 (P5.1b offline offer redeem, money doc step 5 / A2-21). edge_partner only; class A1. Records offline_step for the player-lane confirm clear.';
COMMENT ON FUNCTION private.offer_offline_confirm_for_actor(text, timestamptz, text, text, uuid) IS
  '0063 (A2-21 co-signal clear). edge_actor only. Qualifying fix clears offline_confirm_by on the bound player''s own redeemed_offline offer codes at the facility whose offline_step window holds the fix. Statuses: confirmed | none_awaiting | cosignal_invalid | cosignal_used | review_account.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Registries
-- ============================================================================
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0063 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

-- Drop the old apply identity (7-arg) from the inventory; insert the 8-arg form + confirm.
DELETE FROM private.function_inventory
WHERE schema_name = 'private' AND function_name = 'partner_offers_redeem_apply_offline'
  AND identity_args = 'p_staff uuid, p_facility_id text, p_player uuid, p_offer_id uuid, p_offer_code_id uuid, p_jti text, p_amount numeric';

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'partner_offers_redeem_apply_offline', 'p_staff uuid, p_facility_id text, p_player uuid, p_offer_id uuid, p_offer_code_id uuid, p_jti text, p_amount numeric, p_offline_step bigint', false, false, false, false, false, false, false, '0063: owner-only apply helper for offline offer redeem (writes offline_step)'),
  ('private', 'offer_offline_confirm_for_actor', 'p_facility_id text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid', false, false, false, true, false, false, false, '0063: edge_actor only; clears offline_confirm_by on a qualifying co-signal')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_actor = EXCLUDED.expected_edge_actor,
    expected_edge_partner = EXCLUDED.expected_edge_partner,
    note = EXCLUDED.note;

UPDATE private.function_inventory
SET note = '0062/0063 (P5.1b offline offer redeem). edge_partner only; class A1; records offline_step for confirm clear'
WHERE schema_name = 'private' AND function_name = 'partner_offers_redeem_offline_for_partner';

DROP POLICY current_user_edit_function_inventory_0063 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

DO $assert_0063$
BEGIN
  IF NOT has_function_privilege('edge_actor', 'private.offer_offline_confirm_for_actor(text, timestamptz, text, text, uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0063: edge_actor must EXECUTE offer_offline_confirm_for_actor';
  END IF;
  IF has_function_privilege('edge_partner', 'private.offer_offline_confirm_for_actor(text, timestamptz, text, text, uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0063: edge_partner must not EXECUTE offer_offline_confirm_for_actor';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'offer_code' AND column_name = 'offline_step') THEN
    RAISE EXCEPTION '0063: offer_code.offline_step missing';
  END IF;
END
$assert_0063$;
