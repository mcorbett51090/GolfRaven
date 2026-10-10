-- 0061_at10_issuance_staff_gate.sql
--
-- P5.1b follow-up: AT(10) ISSUANCE STAFF GATE. docs/security/partner-auth-design.md section 12.1
-- (AT(10): offer not issued at a facility with no active staff) and design §32.3 (deferred on 0060).
-- Migrations 0001-0060 are untouched.
--
-- WHAT THIS ADDS
--   1. private.facility_has_active_staff(facility): STABLE SECURITY DEFINER; true when a non-revoked
--      staff or manager has partner_scope.facility_id = the argument.
--   2. CREATE OR REPLACE app.activate_offer_code (0027 body + gate): when decision=activate and state=earned
--      and the facility has no active staff, hold_review with hold_detail.heldFor = no_active_staff.
--      Already-issued re-activate is NOT gated.
--   3. CREATE OR REPLACE app.resolve_held_offer_code (0027 body + gate): when approve would issue and the
--      facility has no active staff, refuse with check_violation (23514), same shape as a short budget.
--   4. CREATE OR REPLACE private.partner_resolve_held_offer_code_apply so that refusal maps to status
--      no_active_staff (budget short stays budget_short).
--
-- DELIBERATELY NOT HERE: Edge handler changes; offline_code redeem; rollups-refresh; S7 UI.

-- ============================================================================
-- 1. private.facility_has_active_staff
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.facility_has_active_staff(p_facility_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM app.partner_member pm
    JOIN app.partner_scope ps ON ps.org_id = pm.org_id
    WHERE pm.revoked_at IS NULL
      AND pm.role IN ('staff', 'manager')
      AND ps.facility_id = p_facility_id
  );
$$;

REVOKE EXECUTE ON FUNCTION private.facility_has_active_staff(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.facility_has_active_staff(text) TO private_definer;
GRANT EXECUTE ON FUNCTION private.facility_has_active_staff(text) TO service_role;

COMMENT ON FUNCTION private.facility_has_active_staff(text) IS
  '0061 (AT(10)). True when a non-revoked staff or manager is scoped to the facility. Used by activate_offer_code and resolve_held_offer_code; EXECUTE for private_definer and service_role only.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. app.activate_offer_code — 0027 body with the AT(10) earned-issuance gate
-- ============================================================================
CREATE OR REPLACE FUNCTION app.activate_offer_code(
  p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text,
  p_hold_detail jsonb DEFAULT NULL
) RETURNS app.offer_code_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_code app.offer_code%ROWTYPE;
  v_reserve numeric := 0;
BEGIN
  IF private.is_demo_account(p_user_id) THEN
    RAISE EXCEPTION 'activate_offer_code: the review account may not activate a reward' USING ERRCODE = '42501';
  END IF;
  IF p_decision IS NULL OR p_decision NOT IN ('activate', 'held_review') THEN
    RAISE EXCEPTION 'activate_offer_code: p_decision must be ''activate'' or ''held_review'' (got %)', p_decision
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_code FROM app.offer_code WHERE id = p_code_id AND user_id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'activate_offer_code: no offer_code % for this user', p_code_id USING ERRCODE = 'P0002';
  END IF;

  PERFORM 1 FROM app.device WHERE id = p_device_id AND user_id = p_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'activate_offer_code: device % is not owned by this user', p_device_id USING ERRCODE = '42501';
  END IF;

  -- A held code is awaiting a human (§9.2 SLA). Activation never releases it
  -- and never re-runs the table over it: idempotent no-op.
  IF v_code.state = 'held_review' THEN
    RETURN v_code.state;
  END IF;
  IF v_code.state NOT IN ('earned', 'issued') THEN
    RAISE EXCEPTION 'activate_offer_code: offer_code % is % and cannot be activated', p_code_id, v_code.state
      USING ERRCODE = '55000';
  END IF;
  IF v_code.expires_at IS NOT NULL AND v_code.expires_at <= now() AND v_code.expiry_paused_at IS NULL THEN
    RAISE EXCEPTION 'activate_offer_code: offer_code % has expired', p_code_id USING ERRCODE = '55000';
  END IF;

  IF p_decision = 'activate' THEN
    -- Table rows 2 and 3, enforced by the database independently of the caller.
    IF v_code.rests_on_unattestable AND v_code.review_cleared_at IS NULL THEN
      RAISE EXCEPTION 'activate_offer_code: offer_code % rests on an unattestable co-signal (§7.5 row 3) and cannot be activated', p_code_id
        USING ERRCODE = '23514';
    END IF;
    IF v_code.play_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM app.play WHERE id = v_code.play_id AND user_id = p_user_id AND held_review
    ) THEN
      RAISE EXCEPTION 'activate_offer_code: offer_code % is backed by a held_review play (§7.5 row 3) and cannot be activated', p_code_id
        USING ERRCODE = '23514';
    END IF;
    -- Row 2 is an ACCOUNT-level condition: only the signal being cleared
    -- (cleared_at) releases it. review_cleared_at deliberately plays no part
    -- here (N3): a reviewer approving ONE reward must not waive a signal about
    -- the account's attestation.
    IF EXISTS (
      SELECT 1 FROM app.fraud_signal
      WHERE user_id = p_user_id AND kind = 'attestation_failed' AND cleared_at IS NULL
    ) THEN
      RAISE EXCEPTION 'activate_offer_code: the account has an open attestation_failed fraud_signal (§7.5 row 2); activations are held'
        USING ERRCODE = '23514';
    END IF;

    -- AT(10): do not first-issue an earned code at a facility with no active staff/manager.
    -- Already-issued re-activate (state = issued) is deliberately not gated.
    IF v_code.state = 'earned' AND NOT private.facility_has_active_staff(v_code.facility_id) THEN
      UPDATE app.offer_code SET
        state = 'held_review',
        hold_detail = coalesce(p_hold_detail, '{}'::jsonb) || jsonb_build_object('heldFor', 'no_active_staff'),
        activated_device_id = coalesce(activated_device_id, p_device_id),
        devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
        activated_at = coalesce(activated_at, now())
      WHERE id = p_code_id;
      RETURN 'held_review';
    END IF;

    -- Issuing a code that holds no reservation takes one (header: model, step 2).
    -- If the cap cannot cover it the code is HELD, never issued unreserved (N1):
    -- an issued code is payable.
    IF v_code.state = 'earned' AND v_code.reserved_amount = 0 THEN
      v_reserve := app.reserve_offer_for_code(v_code.offer_id, v_code.id, 'held_offer_budget_unreserved');
      IF v_reserve IS NULL THEN
        UPDATE app.offer_code SET
          state = 'held_review',
          hold_detail = coalesce(p_hold_detail, '{}'::jsonb) || jsonb_build_object('heldFor', 'offer_budget'),
          activated_device_id = coalesce(activated_device_id, p_device_id),
          devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
          activated_at = coalesce(activated_at, now())
        WHERE id = p_code_id;
        RETURN 'held_review';
      END IF;
    END IF;

    UPDATE app.offer_code SET
      state = 'issued',
      reserved_amount = reserved_amount + v_reserve,
      activated_device_id = coalesce(activated_device_id, p_device_id),
      devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
      activated_at = coalesce(activated_at, now())
    WHERE id = p_code_id;

    INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
    VALUES (p_device_id, p_token_hash, p_user_id, 'offer', p_code_id)
    ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    RETURN 'issued';
  END IF;

  -- held_review. app.offer_code_reservation_sync reserves the budget and pauses
  -- the expiry clock on the state change — the same path the play-hold cascade
  -- takes, so there is exactly one implementation.
  UPDATE app.offer_code SET
    state = 'held_review',
    hold_detail = coalesce(p_hold_detail, hold_detail),
    activated_device_id = coalesce(activated_device_id, p_device_id),
    devicecheck_token_hash = coalesce(devicecheck_token_hash, p_token_hash),
    activated_at = coalesce(activated_at, now())
  WHERE id = p_code_id;
  RETURN 'held_review';
END;
$$;

COMMENT ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text, jsonb) IS
  'P3f / 0061 (AT(10)): offer_code activation. earned/issued -> issued | held_review. An earned activate at a facility with no active staff/manager is held (heldFor=no_active_staff); already-issued re-activate is not gated. Reservation (a clean activation the cap cannot cover is HELD), ledger row, rows 2/3 backstop.';

-- ============================================================================
-- 3. app.resolve_held_offer_code — 0027 body with the AT(10) issue-on-approve gate
-- ============================================================================
CREATE OR REPLACE FUNCTION app.resolve_held_offer_code(p_code_id uuid, p_approve boolean, p_resolved_by uuid)
RETURNS app.offer_code_state
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_code app.offer_code%ROWTYPE;
  v_expires timestamptz;
  v_new app.offer_code_state;
  v_reserve numeric;
BEGIN
  IF p_approve IS NULL THEN
    RAISE EXCEPTION 'resolve_held_offer_code: p_approve must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF p_resolved_by IS NULL OR NOT private.is_admin(p_resolved_by) THEN
    RAISE EXCEPTION 'resolve_held_offer_code: p_resolved_by is not an admin' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_code FROM app.offer_code WHERE id = p_code_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'resolve_held_offer_code: no offer_code %', p_code_id USING ERRCODE = 'P0002';
  END IF;
  IF private.is_demo_account(v_code.user_id) THEN
    RAISE EXCEPTION 'resolve_held_offer_code: the review account may not receive a reward' USING ERRCODE = '42501';
  END IF;
  IF v_code.state <> 'held_review' THEN
    RAISE EXCEPTION 'resolve_held_offer_code: offer_code % is % (not held_review)', p_code_id, v_code.state
      USING ERRCODE = '55000';
  END IF;

  IF p_approve THEN
    -- An approved code is payable. If it holds no reservation (it was held
    -- because the cap could not cover it, N1), take one now — and if the cap STILL
    -- cannot cover it, refuse the approval (23514) rather than issue a code the
    -- offer cannot pay: raise the cap, or reject the code.
    IF v_code.reserved_amount = 0 THEN
      v_reserve := app.reserve_offer_for_code(v_code.offer_id, v_code.id, 'held_offer_budget_unreserved');
      IF v_reserve IS NULL THEN
        RAISE EXCEPTION 'resolve_held_offer_code: offer % cannot cover this code''s face value; raise its budget_cap or reject the code', v_code.offer_id
          USING ERRCODE = '23514';
      END IF;
      v_code.reserved_amount := v_reserve;
    END IF;
    v_expires := CASE
      WHEN v_code.issued_before_hold AND v_code.expiry_remaining IS NOT NULL THEN now() + v_code.expiry_remaining
      WHEN v_code.expires_at IS NOT NULL AND v_code.expires_at > v_code.earned_at THEN now() + (v_code.expires_at - v_code.earned_at)
      ELSE v_code.expires_at END;
    v_new := CASE WHEN v_code.activated_device_id IS NULL THEN 'earned'::app.offer_code_state ELSE 'issued'::app.offer_code_state END;
    -- AT(10): approving into issued needs active staff at the code's facility (return-to-earned is not an issuance).
    IF v_new = 'issued' AND NOT private.facility_has_active_staff(v_code.facility_id) THEN
      RAISE EXCEPTION 'resolve_held_offer_code: facility % has no active staff; cannot issue (AT(10) no_active_staff)', v_code.facility_id
        USING ERRCODE = '23514';
    END IF;
    UPDATE app.offer_code SET
      state = v_new,
      expires_at = v_expires,
      expiry_paused_at = NULL,
      issued_before_hold = false,
      expiry_remaining = NULL,
      reserved_amount = v_code.reserved_amount,
      review_cleared_at = CASE WHEN v_new = 'earned' THEN now() ELSE review_cleared_at END
    WHERE id = p_code_id;
    IF v_new = 'issued' THEN
      INSERT INTO app.device_reward_ledger (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id)
      VALUES (v_code.activated_device_id, v_code.devicecheck_token_hash, v_code.user_id, 'offer', p_code_id)
      ON CONFLICT (device_id, reward_kind, reward_id) DO NOTHING;
    END IF;
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (p_resolved_by, 'held_reward_approved', 'offer_code', p_code_id::text,
            jsonb_build_object('reserved_amount', v_code.reserved_amount, 'resulting_state', v_new));
    RETURN v_new;
  END IF;

  UPDATE app.offer_code SET state = 'void' WHERE id = p_code_id; -- the trigger releases the reservation
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (p_resolved_by, 'held_reward_rejected', 'offer_code', p_code_id::text,
          jsonb_build_object('released_amount', v_code.reserved_amount));
  RETURN 'void';
END;
$$;

COMMENT ON FUNCTION app.resolve_held_offer_code(uuid, boolean, uuid) IS
  'P3f / 0061 (AT(10)): §9.2 review decision on a held offer_code. Approve that would issue refuses with 23514 when the facility has no active staff/manager (no_active_staff); return-to-earned is not gated.';

-- ============================================================================
-- 4. partner apply helper: map no_active_staff separately from budget_short
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_resolve_held_offer_code_apply(p_code_id uuid, p_approve boolean, p_resolved_by uuid)
RETURNS TABLE (o_status text, o_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_state app.offer_code_state;
BEGIN
  BEGIN
    v_state := app.resolve_held_offer_code(p_code_id, p_approve, p_resolved_by);
    RETURN QUERY SELECT 'ok'::text, v_state::text;
  EXCEPTION
    WHEN SQLSTATE 'P0002' THEN RETURN QUERY SELECT 'not_found'::text, NULL::text;
    WHEN SQLSTATE '55000' THEN RETURN QUERY SELECT 'not_held'::text, NULL::text;
    WHEN check_violation THEN
      IF position('no_active_staff' in SQLERRM) > 0 THEN
        RETURN QUERY SELECT 'no_active_staff'::text, NULL::text;
      ELSE
        RETURN QUERY SELECT 'budget_short'::text, NULL::text;
      END IF;
  END;
END
$$;

COMMENT ON FUNCTION private.partner_resolve_held_offer_code_apply(uuid, boolean, uuid) IS
  '0057 / 0061. Translates app.resolve_held_offer_code SQLSTATEs into statuses (ok | not_found | not_held | budget_short | no_active_staff). Reads no binding; EXECUTE for nobody but the owner.';

COMMENT ON FUNCTION private.partner_resolve_held_offer_code_for_partner(uuid, boolean) IS
  '0057 (S4, E20) / 0061. edge_partner only; class A3; ADMIN only. Wraps app.resolve_held_offer_code so the Edge never reaches it. Statuses: ok | not_found | not_held | budget_short | no_active_staff.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 5. function_inventory
-- ============================================================================
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0061 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'facility_has_active_staff', 'p_facility_id text', false, false, true, false, false, false, false, '0061 (AT(10)): STABLE SECURITY DEFINER; true when a non-revoked staff or manager is scoped to the facility; EXECUTE for private_definer and service_role');

UPDATE private.function_inventory
SET note = 'P3f / 0061 (AT(10)): the offer_code activation state machine; earned/issued -> issued | held_review; earned activate with no active staff is held (heldFor=no_active_staff); reservation (a clean activation the cap cannot cover is HELD), ledger row, rows 2/3 backstop. Called by rewards-activate through withOwnership as service_role / activate_offer_code_for_actor; plain invoker function, not SECURITY DEFINER'
WHERE schema_name = 'app' AND function_name = 'activate_offer_code'
  AND identity_args = 'p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb';

UPDATE private.function_inventory
SET note = 'P3f / 0061 (AT(10)): §9.2 review decision on a held offer_code; approve that would issue refuses when the facility has no active staff (no_active_staff). service_role and private_definer (0057 partner review apply)'
WHERE schema_name = 'app' AND function_name = 'resolve_held_offer_code'
  AND identity_args = 'p_code_id uuid, p_approve boolean, p_resolved_by uuid';

UPDATE private.function_inventory
SET note = '0057 / 0061: status translation of app.resolve_held_offer_code (ok | not_found | not_held | budget_short | no_active_staff); EXECUTE for nobody but the owner'
WHERE schema_name = 'private' AND function_name = 'partner_resolve_held_offer_code_apply'
  AND identity_args = 'p_code_id uuid, p_approve boolean, p_resolved_by uuid';

UPDATE private.function_inventory
SET note = '0057 (S4, E20) / 0061: edge_partner only; class A3; ADMIN only; wraps resolve_held_offer_code; statuses include no_active_staff'
WHERE schema_name = 'private' AND function_name = 'partner_resolve_held_offer_code_for_partner'
  AND identity_args = 'p_code_id uuid, p_approve boolean';

DROP POLICY current_user_edit_function_inventory_0061 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

-- Assert EXECUTE surface of the new helper (no edge role).
DO $assert_0061_grants$
BEGIN
  IF has_function_privilege('edge_partner', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_actor', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('anon', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0061: facility_has_active_staff must not be EXECUTEable by edge/client roles';
  END IF;
  IF NOT has_function_privilege('private_definer', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('service_role', 'private.facility_has_active_staff(text)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0061: private_definer and service_role must EXECUTE facility_has_active_staff';
  END IF;
END
$assert_0061_grants$;
