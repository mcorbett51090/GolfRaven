-- 0062_partner_offers_offline_redeem.sql
--
-- P5.1b follow-up: OFFLINE_CODE OFFER REDEEM. docs/security/partner-auth-design.md section 32.3
-- (offline_code offer redeem: PIN step-up + profile-card name check; fraud_signal / unconfirmed after 24 h)
-- and the money doc step 5 offer-redemption clause (A2-21) are the specification; its "As built" section
-- (design 35) is the reading guide for this file. Migrations 0001-0061 are untouched.
--
-- WHAT THIS ADDS
--   1. app.offer_code.offline_confirm_by: set to now() + 24 h on an offline redeem; NULL means not awaiting
--      (staff_scan) or already confirmed. Settlement unconfirmed_count uses redeemed_offline AND
--      offline_confirm_by IS NOT NULL AND offline_confirm_by < now().
--   2. private.partner_offers_redeem_offline_for_partner(facility, offer_code_id, handle, code, name_confirmed):
--      class A1. Verifies the offline code in the database (same counters and candidate rules as 0056),
--      requires name_confirmed = true (the in-app profile-card check), redeems with redeemed_offline = true,
--      writes offer_redemption attestation, sets offline_confirm_by. Statuses commit; 22023 / 42501 raise.
--   3. CREATE OR REPLACE private.partner_settlement_export_for_partner: unconfirmed_count uses the new column;
--      inserts fraud_signal kind=offer_offline_unconfirmed for newly overdue offline redemptions (once).
--   4. Binding-keyed policy widen: fraud_signal INSERT allows offer_offline_unconfirmed.
--   5. UPDATE grant on offer_code.offline_confirm_by (covered by existing column-less UPDATE grant).
--
-- DELIBERATELY NOT HERE: player-lane cosignal attach that CLEARS offline_confirm_by (a confirmed fix against
-- the recorded offline_code_step); S7 UI for the offline redeem form; rollups-refresh writer.
--
-- CHECK 14: every `_for_partner` body begins with private.partner_authorize (string-literal class), holds no
-- dollar sign, double quote, backslash or E-string, and no EXCEPTION block.

-- ============================================================================
-- 1. Column + fraud policy widen
-- ============================================================================
ALTER TABLE app.offer_code ADD COLUMN offline_confirm_by timestamptz;
COMMENT ON COLUMN app.offer_code.offline_confirm_by IS
  '0062: deadline for a co-signal that confirms an offline offer redeem. Set to redeemed_at + 24 h when redeemed_offline; cleared when a future player-lane attach confirms; NULL for staff_scan redemptions. Settlement unconfirmed_count and fraud_signal offer_offline_unconfirmed use overdue rows.';

DROP POLICY IF EXISTS pd_partner_attest_fraud_insert ON app.fraud_signal;
CREATE POLICY pd_partner_attest_fraud_insert ON app.fraud_signal FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner'
              AND kind = ANY (ARRAY['same_device_attest'::text, 'offer_offline_unconfirmed'::text]));

-- ============================================================================
-- 2. Offline redeem definer + settlement replace
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- Offline apply tail: same as 0060 apply but redeemed_offline = true and offline_confirm_by set. EXECUTE for nobody but the owner.
CREATE FUNCTION private.partner_offers_redeem_apply_offline(
  p_staff uuid, p_facility_id text, p_player uuid, p_offer_id uuid, p_offer_code_id uuid, p_jti text, p_amount numeric
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
      offline_confirm_by = v_now + interval '24 hours'
  WHERE id = p_offer_code_id;
  PERFORM private.partner_audit_write('partner.offer_redeem_offline', 'app.offer_code', p_offer_code_id::text,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'offer', p_offer_id, 'method', 'offline_code', 'amount', p_amount));
  RETURN QUERY SELECT 'ok'::text, v_w.o_attestation_id;
END
$$;

-- Class A1 offline redeem: handle + six digits + name_confirmed. Reuses the 0056 verify-and-record counters and candidate rules.
CREATE FUNCTION private.partner_offers_redeem_offline_for_partner(
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

  -- offer_code checks (same status-before-FOR UPDATE ordering as 0060)
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
  FROM private.partner_offers_redeem_apply_offline(v_uid, p_facility_id, v_code.user_id, v_code.offer_id, p_offer_code_id, v_jti, v_amount) a;
END
$$;

-- Replace settlement export: real unconfirmed_count + fraud_signal for overdue offline redemptions.
CREATE OR REPLACE FUNCTION private.partner_settlement_export_for_partner(p_trail_id text, p_month date)
RETURNS TABLE (
  o_status text,
  o_facility_id text,
  o_month date,
  o_funder text,
  o_sponsorship_id uuid,
  o_redemptions bigint,
  o_offline_count bigint,
  o_unconfirmed_count bigint,
  o_face_value_total numeric
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_month date;
  v_n bigint;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row record;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' OR p_month IS NULL THEN
    RAISE EXCEPTION 'partner_settlement_export_for_partner: a trail and a month (first of month) are required' USING ERRCODE = '22023';
  END IF;
  v_month := pg_catalog.date_trunc('month', p_month::timestamp)::date;

  -- Mark overdue offline redemptions once (fraud_signal); settlement count reads the deadline column.
  FOR v_row IN
    SELECT oc.id, oc.user_id
    FROM app.offer_code oc
    JOIN app.offer o ON o.id = oc.offer_id
    WHERE o.trail_id = p_trail_id AND oc.state = 'redeemed' AND oc.redeemed_offline
      AND oc.offline_confirm_by IS NOT NULL AND oc.offline_confirm_by < v_now
      AND NOT EXISTS (
        SELECT 1 FROM app.fraud_signal f
        WHERE f.user_id = oc.user_id AND f.kind = 'offer_offline_unconfirmed'
          AND f.detail ->> 'offer_code_id' = oc.id::text
      )
  LOOP
    INSERT INTO app.fraud_signal (user_id, kind, detail)
    VALUES (v_row.user_id, 'offer_offline_unconfirmed',
            pg_catalog.jsonb_build_object('offer_code_id', v_row.id, 'trail_id', p_trail_id));
  END LOOP;

  SELECT pg_catalog.count(*) INTO v_n
  FROM app.offer_code oc
  JOIN app.offer o ON o.id = oc.offer_id
  WHERE o.trail_id = p_trail_id AND oc.state = 'redeemed'
    AND pg_catalog.date_trunc('month', oc.redeemed_at)::date = v_month;
  IF v_n = 0 THEN
    RETURN QUERY SELECT 'empty'::text, NULL::text, NULL::date, NULL::text, NULL::uuid, NULL::bigint, NULL::bigint, NULL::bigint, NULL::numeric;
    RETURN;
  END IF;
  RETURN QUERY
  SELECT
    'ok'::text,
    o.facility_id,
    v_month,
    o.funder::text,
    o.sponsorship_id,
    pg_catalog.count(*)::bigint,
    pg_catalog.count(*) FILTER (WHERE oc.redeemed_offline)::bigint,
    pg_catalog.count(*) FILTER (
      WHERE oc.redeemed_offline AND oc.offline_confirm_by IS NOT NULL AND oc.offline_confirm_by < v_now
    )::bigint,
    CASE WHEN pg_catalog.sum(o.face_value) IS NULL THEN 0::numeric ELSE pg_catalog.sum(o.face_value) END
  FROM app.offer_code oc
  JOIN app.offer o ON o.id = oc.offer_id
  WHERE o.trail_id = p_trail_id AND oc.state = 'redeemed'
    AND pg_catalog.date_trunc('month', oc.redeemed_at)::date = v_month
  GROUP BY o.facility_id, o.funder, o.sponsorship_id
  ORDER BY o.facility_id, o.funder, o.sponsorship_id NULLS FIRST;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_offers_redeem_apply_offline(uuid, text, uuid, uuid, uuid, text, numeric) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean) TO edge_partner;

COMMENT ON FUNCTION private.partner_offers_redeem_apply_offline(uuid, text, uuid, uuid, uuid, text, numeric) IS
  '0062. Mutating tail of an offline offer redeem (consume, attest, nonce, code update with redeemed_offline and offline_confirm_by). EXECUTE for nobody but the owner.';
COMMENT ON FUNCTION private.partner_offers_redeem_offline_for_partner(text, uuid, text, text, boolean) IS
  '0062 (P5.1b offline offer redeem, money doc step 5 / A2-21). edge_partner only; class A1. handle + six digits verified in the database; name_confirmed must be true; redeems with redeemed_offline and a 24 h offline_confirm_by. Statuses: ok | not_found | not_issued | expired | wrong_facility | wrong_player | verification_failed | replayed | rate_limited | name_unconfirmed | no_facility | cold_start_cap | budget_short.';
COMMENT ON FUNCTION private.partner_settlement_export_for_partner(text, date) IS
  '0060/0062 (P5.1b, AT(17), AT(20)). edge_partner only; class A3. Settlement lines; unconfirmed_count is overdue offline_confirm_by; inserts fraud_signal offer_offline_unconfirmed once per overdue code. Statuses: ok | empty.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Registries
-- ============================================================================
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0062 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'partner_offers_redeem_offline_for_partner', 'p_facility_id text, p_offer_code_id uuid, p_handle text, p_code text, p_name_confirmed boolean', false, false, false, false, false, true, false, '0062: edge_partner only; class A1; offline_code offer redeem'),
  ('private', 'partner_offers_redeem_apply_offline', 'p_staff uuid, p_facility_id text, p_player uuid, p_offer_id uuid, p_offer_code_id uuid, p_jti text, p_amount numeric', false, false, false, false, false, false, false, '0062: owner-only apply helper for offline offer redeem')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_partner = EXCLUDED.expected_edge_partner,
    note = EXCLUDED.note;

UPDATE private.function_inventory
SET note = '0060/0062 (P5.1b, AT(17), AT(20)). edge_partner only; class A3; settlement lines; unconfirmed via offline_confirm_by'
WHERE schema_name = 'private' AND function_name = 'partner_settlement_export_for_partner';

DROP POLICY current_user_edit_function_inventory_0062 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT UPDATE ON private.policy_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_policy_inventory_0062 ON private.policy_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.policy_inventory
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid),
    note = 'S3/0062: same_device_attest and offer_offline_unconfirmed fraud_signal inserts under a partner binding'
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'app' AND c.relname = 'fraud_signal' AND pol.polname = 'pd_partner_attest_fraud_insert'
  AND private.policy_inventory.schema_name = 'app'
  AND private.policy_inventory.table_name = 'fraud_signal'
  AND private.policy_inventory.policy_name = 'pd_partner_attest_fraud_insert';

DROP POLICY current_user_edit_policy_inventory_0062 ON private.policy_inventory;
REVOKE UPDATE ON private.policy_inventory FROM CURRENT_USER;
