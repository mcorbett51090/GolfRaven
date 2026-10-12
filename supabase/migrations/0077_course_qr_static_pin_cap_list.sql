-- 0077_course_qr_static_pin_cap_list.sql
--
-- P5 §63: partner read of open course_qr_static_pin_cap fraud_signal rows
-- left open by 0076 / partner-auth-design §62.3. Operator-facing portal
-- list on the Course QR surface (same A0 manager/operator gate as §59
-- course_pin_alarm_list).
--
-- WHAT THIS ADDS
--   1. private.course_qr_static_pin_cap_list_for_partner(facility)
--      class A0, manager or operator at the facility (admin via authorize);
--      returns id / facility / local_date / count / raised_at (= created_at)
--      for OPEN signals only (cleared_at IS NULL), newest first, at most 100.
--   2. SELECT policy pd_course_qr_cap_partner_select on app.fraud_signal
--      keyed on partner_bound_manager_at(detail->>'facilityId') plus
--      kind = course_qr_static_pin_cap and cleared_at IS NULL.
--
-- DELIBERATELY NOT HERE: pepper-rotation tooling, OCR / aHash / UI flag
-- flips / CAMERA. Nothing from 0001–0076 is edited.

-- ============================================================================
-- 1. Partner SELECT policy
-- ============================================================================
CREATE POLICY pd_course_qr_cap_partner_select ON app.fraud_signal FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND kind = 'course_qr_static_pin_cap'
         AND cleared_at IS NULL
         AND private.partner_bound_manager_at(detail ->> 'facilityId'));

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.course_qr_static_pin_cap_list_for_partner(p_facility_id text)
RETURNS TABLE (
  o_id uuid,
  o_facility_id text,
  o_local_date date,
  o_count integer,
  o_raised_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'course_qr_static_pin_cap_list_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT f.id,
         f.detail ->> 'facilityId',
         (f.detail ->> 'localDate')::date,
         (f.detail ->> 'count')::integer,
         f.created_at
  FROM app.fraud_signal f
  WHERE f.kind = 'course_qr_static_pin_cap'
    AND f.cleared_at IS NULL
    AND f.detail ->> 'facilityId' = p_facility_id
  ORDER BY f.created_at DESC, f.id
  LIMIT 100;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.course_qr_static_pin_cap_list_for_partner(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.course_qr_static_pin_cap_list_for_partner(text) TO edge_partner;

COMMENT ON FUNCTION private.course_qr_static_pin_cap_list_for_partner(text) IS
  '0077 (§63). edge_partner only; class A0 (manager or operator at the facility). Open course_qr_static_pin_cap fraud_signal rows for that facility (newest first, 100): plan §8.3 static-PIN daily cap alert. No user id.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Inventories
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'course_qr_static_pin_cap_list_for_partner', 'p_facility_id text', false, false, false, false, false, true, false,
   '0077 (§63): edge_partner only; class A0 (manager / operator); open course_qr_static_pin_cap fraud_signal list for a facility');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0077 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'fraud_signal', 'pd_course_qr_cap_partner_select', 'SELECT', true,
   '0077 (§63): partner-bound manager / operator (or admin) reads open course_qr_static_pin_cap fraud_signal rows of a facility in their reach', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname = 'pd_course_qr_cap_partner_select';
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name = 'pd_course_qr_cap_partner_select') <> 1 THEN
    RAISE EXCEPTION '0077: expected 1 definer_policy_allowlist row for pd_course_qr_cap_partner_select';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0077 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $$
DECLARE
  v_n int;
BEGIN
  SELECT count(*)::int INTO v_n FROM pg_policy pol
  JOIN pg_class c ON c.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'fraud_signal'
    AND pol.polname = 'pd_course_qr_cap_partner_select';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0077: expected one pd_course_qr_cap_partner_select policy, found %', v_n;
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.course_qr_static_pin_cap_list_for_partner(text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0077: edge_partner must EXECUTE course_qr_static_pin_cap_list_for_partner';
  END IF;
  IF has_function_privilege('edge_actor', 'private.course_qr_static_pin_cap_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.course_qr_static_pin_cap_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.course_qr_static_pin_cap_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.course_qr_static_pin_cap_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.course_qr_static_pin_cap_list_for_partner(text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0077: course_qr_static_pin_cap_list_for_partner must not be EXECUTEable by client / actor / system / service_role';
  END IF;
END
$$;
