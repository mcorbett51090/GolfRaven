-- 0060_partner_offers_settlement.sql
--
-- P5.1b (database half): OFFERS-REDEEM AND SETTLEMENT EXPORT. docs/security/partner-auth-design.md section 12
-- (offers-redeem / settlement), 6.3 (class A1 redeem, A0 queue, A3 settlement-export), 8c (binding-keyed policies, never a GUC)
-- and the money doc's consume_offer_budget / offer_settlement path are the specification; its "As built: P5.1b" section (design 32)
-- is the reading guide for this file. Migrations 0001-0059 are untouched.
--
-- WHAT THIS ADDS (all of it partner-bound: every `_for_partner` definer begins with private.partner_authorize)
--   1. BINDING-KEYED POLICIES for partner staff redeem of offer_code (select/update issued->redeemed), offer budget consume columns,
--      play guard read via offer_code.play_id, attestation insert kind=offer_redemption, and settlement SELECT of redeemed codes.
--      Each keyed on private.partner_bound_staff_at / partner_bound_operator_at_trail / partner_bound_admin, never a GUC.
--   2. GRANT EXECUTE on app.consume_offer_budget TO private_definer; GRANT UPDATE (budget_used) on app.offer (budget_reserved already granted).
--   3. private.partner_offers_redeem_for_partner(facility, offer_code_id, method, credential): class A1 staff/manager. Status before FOR UPDATE
--      (0058 ordering). Method staff_scan (player checkin jti). offline_code refused with 22023. Statuses:
--      ok | not_found | not_issued | expired | wrong_facility | token_invalid | wrong_player | replayed | no_facility | cold_start_cap | budget_short.
--      Calls partner_attest_write with offer_redemption; consume_offer_budget; updates the code.
--   4. private.partner_offers_queue_for_partner(facility): class A0. Issued codes at the facility with player handle.
--   5. private.partner_settlement_export_for_partner(trail_id, month): class A3 operator-at-trail (or admin via has_trail_scope).
--      Rows: facility_id, month, funder, sponsorship_id, redemptions, offline_count, unconfirmed_count, face_value_total.
--      Status ok | empty.
--
-- DELIBERATELY NOT HERE: Edge handlers (partner-offers-redeem, settlement-export, exports-purge); offline_code redeem; issuance staff gate AT(10);
-- rollups-refresh writer; S7 UI.
--
-- CHECK 14: every `_for_partner` body begins with private.partner_authorize (a string-literal class), holds no dollar sign, double quote, backslash or E-string, and no EXCEPTION block; comments inside the bodies obey the same lexing (no apostrophes there). Outcomes are STATUS rows; only malformed arguments (22023) and a missing authority (42501) raise. budget_short is mapped by a non-_for_partner apply helper (the 0057 pattern).
-- OWNERSHIP BRACKET as 0056 / 0058 / 0059: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; CREATE FUNCTION ...; RESET ROLE; REVOKE CREATE.

-- ============================================================================
-- 1. Grants (consume_offer_budget + offer.budget_used)
-- ============================================================================
GRANT EXECUTE ON FUNCTION app.consume_offer_budget(uuid, numeric) TO private_definer;
GRANT UPDATE (budget_used) ON app.offer TO private_definer;
-- function_inventory is FORCE RLS; UPDATE needs the 0041 / 0057 pattern (INSERT still uses the 0017 owner policy).
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0060 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.function_inventory
SET note = 'locks + moves a reservation into budget_used; service_role and private_definer (0060 partner offers-redeem)'
WHERE schema_name = 'app' AND function_name = 'consume_offer_budget' AND identity_args = 'p_offer_id uuid, p_amount numeric';
DROP POLICY current_user_edit_function_inventory_0060 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 2. Binding-keyed policies (private_definer). Never a GUC.
-- ============================================================================
-- 2a. offer_code: issued (and redeemed, so the 0017 play guard can re-read) at a facility the bound staff works at
CREATE POLICY pd_partner_offers_offer_code_select ON app.offer_code FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND state IN ('issued', 'redeemed') AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_offers_offer_code_update ON app.offer_code FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND state = 'issued' AND private.partner_bound_staff_at(facility_id))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND state = 'redeemed' AND private.partner_bound_staff_at(facility_id)
              AND redeemed_by_staff = (SELECT private.partner_binding_user()));

-- 2b. the 0017 offer_code_play_guard re-reads the backing play; its GUC window is closed under a partner binding
CREATE POLICY pd_partner_offers_play_guard_read ON app.play FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND EXISTS (SELECT 1 FROM app.offer_code c WHERE c.play_id = play.id AND c.user_id = play.user_id));

-- 2c. offer budget columns for consume_offer_budget at a facility the bound staff works at
CREATE POLICY pd_partner_offers_offer_select ON app.offer FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_offers_offer_update ON app.offer FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));

-- 2d. attestation of an offer redemption (0056 insert policy allows presence and marker_purchase only; 0058 adds special_marker_handover)
CREATE POLICY pd_partner_offers_attest_insert ON app.attestation FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND staff_user_id = (SELECT private.partner_binding_user())
              AND kind = 'offer_redemption' AND private.partner_bound_staff_at(facility_id));

-- 2e. the check-in token a staff_scan redeem consumes (source offer_redemption; 0056 covers attestation, 0058 entitlement_redeem)
CREATE POLICY pd_partner_offers_nonce_insert ON private.consumed_nonce FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND source = 'offer_redemption');
CREATE POLICY pd_partner_offers_nonce_select ON private.consumed_nonce FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND source = 'offer_redemption');

-- 2f. settlement export: redeemed codes at a facility on a trail the bound operator runs (or admin).
-- Deliberately keyed on facility_programme, NOT a subquery of app.offer: offer's private_definer policies
-- (pd_edge_act_offer_select) EXISTS offer_code, so an offer_code policy that SELECTs offer recurses (helpers.sql COMMIT /
-- offer_code_play_guard). The settlement definer still joins offer for trail_id / funder / face_value; this policy is the
-- binding-keyed gate only.
CREATE POLICY pd_partner_offers_settlement_code_select ON app.offer_code FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND state = 'redeemed' AND (
    private.partner_bound_admin()
    OR EXISTS (
      SELECT 1 FROM app.facility_programme fp
      -- qualify the outer column: bare facility_id deparses as fp.facility_id (tautology)
      WHERE fp.facility_id = offer_code.facility_id AND private.partner_bound_operator_at_trail(fp.trail_id)
    )
  ));

-- ============================================================================
-- 3. Apply helper (may hold EXCEPTION) and the partner definers
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. The mutating tail of a redeem (may hold EXCEPTION). Consume first; on check_violation return budget_short with no attestation.
-- On a non-ok attest status after a successful consume, reverse the consume so nothing commits half-built. EXECUTE for nobody but the owner.
CREATE FUNCTION private.partner_offers_redeem_apply(
  p_staff uuid, p_facility_id text, p_player uuid, p_offer_id uuid, p_offer_code_id uuid, p_jti text, p_amount numeric, p_method text
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
  FROM private.partner_attest_write(p_staff, p_facility_id, p_player, 'offer_redemption', 'ofr:' || p_jti, p_jti, false, false, v_now, v_now) w;
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
  SET state = 'redeemed', redeemed_at = v_now, redeemed_by_staff = p_staff, redeemed_offline = false
  WHERE id = p_offer_code_id;
  PERFORM private.partner_audit_write('partner.offer_redeem', 'app.offer_code', p_offer_code_id::text,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'offer', p_offer_id, 'method', p_method, 'amount', p_amount));
  RETURN QUERY SELECT 'ok'::text, v_w.o_attestation_id;
END
$$;

-- 3b. GET queue (class A0): issued offer codes at the facility, by player handle
CREATE FUNCTION private.partner_offers_queue_for_partner(p_facility_id text)
RETURNS TABLE (
  o_offer_code_id uuid,
  o_offer_id uuid,
  o_player_handle text,
  o_expires_at timestamptz,
  o_face_value numeric
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'partner_offers_queue_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT c.id, c.offer_id, p.handle, c.expires_at, o.face_value
  FROM app.offer_code c
  JOIN app.offer o ON o.id = c.offer_id
  LEFT JOIN app.profile p ON p.user_id = c.user_id
  WHERE c.facility_id = p_facility_id AND c.state = 'issued'
  ORDER BY c.expires_at NULLS LAST, c.id;
END
$$;

-- 3c. POST redeem (class A1): staff_scan of an issued offer_code. Statuses (all commit):
-- ok | not_found | not_issued | expired | wrong_facility | token_invalid | wrong_player | replayed | no_facility | cold_start_cap | budget_short.
-- Raises: 42501, 22023 (malformed arguments; self_redeem_refused; offline_code refused).
CREATE FUNCTION private.partner_offers_redeem_for_partner(p_facility_id text, p_offer_code_id uuid, p_method text, p_credential text)
RETURNS TABLE (o_status text, o_attestation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_code record;
  v_cred text;
  v_jti uuid;
  v_tok record;
  v_amount numeric;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_method = 'offline_code' THEN
    RAISE EXCEPTION 'partner_offers_redeem_for_partner: offline_code redemption is not supported in this slice' USING ERRCODE = '22023';
  END IF;
  v_cred := pg_catalog.lower(p_credential);
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_offer_code_id IS NULL OR p_method IS NULL OR p_method <> 'staff_scan' OR v_cred IS NULL
     OR pg_catalog.char_length(v_cred) <> 36 OR v_cred !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' THEN
    RAISE EXCEPTION 'partner_offers_redeem_for_partner: a facility, an offer code, method staff_scan and a check-in token jti are required' USING ERRCODE = '22023';
  END IF;

  -- Read without FOR UPDATE first: SELECT FOR UPDATE also applies UPDATE RLS, and the UPDATE policy only opens issued rows.
  SELECT c.user_id, c.offer_id, c.facility_id, c.state, c.expires_at, c.reserved_amount INTO v_code
  FROM app.offer_code c WHERE c.id = p_offer_code_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_code.user_id = v_uid THEN
    RAISE EXCEPTION 'self_redeem_refused: a staff member cannot redeem their own account' USING ERRCODE = '22023';
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

  v_jti := v_cred::uuid;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('partner-attest:' || v_jti::text, 0));
  SELECT t.user_id, t.facility_id, t.expires_at INTO v_tok FROM app.checkin_token t WHERE t.jti = v_jti;
  IF NOT FOUND OR v_tok.expires_at <= v_now OR (v_tok.facility_id IS NOT NULL AND v_tok.facility_id <> p_facility_id) THEN
    RETURN QUERY SELECT 'token_invalid'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_tok.user_id <> v_code.user_id THEN
    RETURN QUERY SELECT 'wrong_player'::text, NULL::uuid;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM private.consumed_nonce n WHERE n.nonce_hash = v_jti::text) THEN
    RETURN QUERY SELECT 'replayed'::text, NULL::uuid;
    RETURN;
  END IF;

  -- Lock the code (UPDATE RLS allows issued) and re-check state after the credential work
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
  RETURN QUERY
  SELECT a.o_status, a.o_attestation_id
  FROM private.partner_offers_redeem_apply(v_uid, p_facility_id, v_code.user_id, v_code.offer_id, p_offer_code_id, v_jti::text, v_amount, p_method) a;
END
$$;

-- 3d. POST settlement export (class A3): operator of the trail (or admin). One row per (facility, funder, sponsorship) for the month.
-- Statuses: ok (one or more lines) | empty (no redeemed codes in the month for the trail).
CREATE FUNCTION private.partner_settlement_export_for_partner(p_trail_id text, p_month date)
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
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' OR p_month IS NULL THEN
    RAISE EXCEPTION 'partner_settlement_export_for_partner: a trail and a month (first of month) are required' USING ERRCODE = '22023';
  END IF;
  v_month := pg_catalog.date_trunc('month', p_month::timestamp)::date;
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
    pg_catalog.count(*) FILTER (WHERE oc.redeemed_by_staff IS NULL)::bigint,
    CASE WHEN pg_catalog.sum(o.face_value) IS NULL THEN 0::numeric ELSE pg_catalog.sum(o.face_value) END
  FROM app.offer_code oc
  JOIN app.offer o ON o.id = oc.offer_id
  WHERE o.trail_id = p_trail_id AND oc.state = 'redeemed'
    AND pg_catalog.date_trunc('month', oc.redeemed_at)::date = v_month
  GROUP BY o.facility_id, o.funder, o.sponsorship_id
  ORDER BY o.facility_id, o.funder, o.sponsorship_id NULLS FIRST;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_offers_redeem_apply(uuid, text, uuid, uuid, uuid, text, numeric, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offers_queue_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offers_redeem_for_partner(text, uuid, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_settlement_export_for_partner(text, date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_offers_queue_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_offers_redeem_for_partner(text, uuid, text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_settlement_export_for_partner(text, date) TO edge_partner;

COMMENT ON FUNCTION private.partner_offers_redeem_apply(uuid, text, uuid, uuid, uuid, text, numeric, text) IS
  '0060 (P5.1b). The mutating tail of an offer redeem (consume, attest, nonce, code update). Maps check_violation to budget_short. EXECUTE for nobody but the owner.';
COMMENT ON FUNCTION private.partner_offers_queue_for_partner(text) IS
  '0060 (P5.1b). edge_partner only; class A0 (staff or manager at the facility). Issued offer codes at the facility, by player handle.';
COMMENT ON FUNCTION private.partner_offers_redeem_for_partner(text, uuid, text, text) IS
  '0060 (P5.1b). edge_partner only; class A1. staff_scan redeem of an issued offer_code: consume_offer_budget, one offer_redemption attestation. offline_code is 22023. Statuses: ok | not_found | not_issued | expired | wrong_facility | token_invalid | wrong_player | replayed | no_facility | cold_start_cap | budget_short.';
COMMENT ON FUNCTION private.partner_settlement_export_for_partner(text, date) IS
  '0060 (P5.1b, AT(17), AT(20)). edge_partner only; class A3 (operator of the trail or admin). Settlement lines for a month with sponsorship attribution and face_value_total. Statuses: ok | empty.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Registries
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_offers_redeem_apply', 'p_staff uuid, p_facility_id text, p_player uuid, p_offer_id uuid, p_offer_code_id uuid, p_jti text, p_amount numeric, p_method text', false, false, false, false, false, false, false, '0060 (P5.1b): mutating redeem tail; EXECUTE for nobody but the owner'),
  ('private', 'partner_offers_queue_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0060 (P5.1b): edge_partner only; class A0; issued offer_code queue at a facility'),
  ('private', 'partner_offers_redeem_for_partner', 'p_facility_id text, p_offer_code_id uuid, p_method text, p_credential text', false, false, false, false, false, true, false, '0060 (P5.1b): edge_partner only; class A1; offer_code staff_scan redeem'),
  ('private', 'partner_settlement_export_for_partner', 'p_trail_id text, p_month date', false, false, false, false, false, true, false, '0060 (P5.1b): edge_partner only; class A3; settlement lines for a trail month');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0060 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'offer_code', 'pd_partner_offers_offer_code_select', 'SELECT', true, 'P5.1b: issued and redeemed offer codes at a facility the bound partner staff works at (design 8c: the 0017 guard window is closed under a partner binding)', 'private_definer'),
  ('app', 'offer_code', 'pd_partner_offers_offer_code_update', 'UPDATE', true, 'P5.1b: issued -> redeemed by the bound staff member at a facility they work at', 'private_definer'),
  ('app', 'play', 'pd_partner_offers_play_guard_read', 'SELECT', true, 'P5.1b: the 0017 offer_code_play_guard re-reads the backing play of an offer_code the redeem policy shows; the GUC window pd_play_guard_read is closed under a partner binding', 'private_definer'),
  ('app', 'offer', 'pd_partner_offers_offer_select', 'SELECT', true, 'P5.1b: offer rows at a facility the bound staff works at (consume_offer_budget FOR UPDATE)', 'private_definer'),
  ('app', 'offer', 'pd_partner_offers_offer_update', 'UPDATE', true, 'P5.1b: offer budget_reserved/budget_used at a facility the bound staff works at (consume_offer_budget)', 'private_definer'),
  ('app', 'attestation', 'pd_partner_offers_attest_insert', 'INSERT', true, 'P5.1b: an offer_redemption attestation by the BOUND partner member at a facility they work at', 'private_definer'),
  ('private', 'consumed_nonce', 'pd_partner_offers_nonce_insert', 'INSERT', true, 'P5.1b: the check-in token a staff_scan offer redeem consumes, source offer_redemption', 'private_definer'),
  ('private', 'consumed_nonce', 'pd_partner_offers_nonce_select', 'SELECT', true, 'P5.1b: the replay check of a staff_scan offer redeem, source offer_redemption only', 'private_definer'),
  ('app', 'offer_code', 'pd_partner_offers_settlement_code_select', 'SELECT', true, 'P5.1b: redeemed offer codes at a facility on a trail the bound operator runs (or admin), via facility_programme (not offer: offer policies EXISTS offer_code and would recurse); settlement export', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_partner_offers_offer_code_select', 'pd_partner_offers_offer_code_update', 'pd_partner_offers_play_guard_read',
    'pd_partner_offers_offer_select', 'pd_partner_offers_offer_update', 'pd_partner_offers_attest_insert',
    'pd_partner_offers_nonce_insert', 'pd_partner_offers_nonce_select', 'pd_partner_offers_settlement_code_select');
DO $assert_0060_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN (
    'pd_partner_offers_offer_code_select', 'pd_partner_offers_offer_code_update', 'pd_partner_offers_play_guard_read',
    'pd_partner_offers_offer_select', 'pd_partner_offers_offer_update', 'pd_partner_offers_attest_insert',
    'pd_partner_offers_nonce_insert', 'pd_partner_offers_nonce_select', 'pd_partner_offers_settlement_code_select')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 9 THEN
    RAISE EXCEPTION '0060: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0060_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0060 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;
