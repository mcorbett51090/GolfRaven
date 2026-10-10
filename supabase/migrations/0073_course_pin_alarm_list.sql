-- 0073_course_pin_alarm_list.sql
--
-- P5 §59: partner read of app.course_pin_alarm left open by 0046 /
-- partner-auth-design §58.3 / §25.3. Operator-facing portal list of
-- automatic wrong-PIN rotations (30 failures → pin_epoch + 1).
--
-- WHAT THIS ADDS
--   1. private.course_pin_alarm_list_for_partner(facility)
--      class A0, manager or operator at the facility (admin via authorize);
--      returns the row columns only (no user id, no PIN), newest first,
--      at most 100.
--   2. SELECT policy pd_course_pin_alarm_partner_select keyed on
--      partner_bound_manager_at (InitPlan form). 0046's actor_uid policy
--      stays for the player-lane writer; purge companions stay closed
--      under a partner binding.
--
-- DELIBERATELY NOT HERE: pepper-rotation tooling, OCR / aHash / UI flag
-- flips / CAMERA, plan §8.3 cap alert.
-- Nothing from 0001–0072 is edited.

-- ============================================================================
-- 1. Partner SELECT policy
-- ============================================================================
CREATE POLICY pd_course_pin_alarm_partner_select ON app.course_pin_alarm FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND private.partner_bound_manager_at(facility_id));

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.course_pin_alarm_list_for_partner(p_facility_id text)
RETURNS TABLE (
  o_id uuid,
  o_facility_id text,
  o_local_date date,
  o_pin_epoch_before integer,
  o_pin_epoch_after integer,
  o_failures integer,
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
    RAISE EXCEPTION 'course_pin_alarm_list_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT a.id, a.facility_id, a.local_date, a.pin_epoch_before, a.pin_epoch_after, a.failures, a.raised_at
  FROM app.course_pin_alarm a
  WHERE a.facility_id = p_facility_id
  ORDER BY a.raised_at DESC, a.id
  LIMIT 100;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.course_pin_alarm_list_for_partner(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.course_pin_alarm_list_for_partner(text) TO edge_partner;

COMMENT ON FUNCTION private.course_pin_alarm_list_for_partner(text) IS
  '0073 (§59). edge_partner only; class A0 (manager or operator at the facility). The course_pin_alarm rows of that facility (newest first, 100): when the 30-wrong-PIN gate rotated the PIN. No user id and no PIN.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.course_pin_alarm IS
  '0046/0071/0073. One row each time the facility-wide wrong-PIN alarm (30 failures at one facility on one facility-local date, plan §9.2) rotated that facility''s PIN (pin_epoch + 1). Operator-facing: private.course_pin_alarm_list_for_partner (portal). Holds no user id and no PIN, so it is not a personal table. Written only by private.course_pin_attempt_for_actor. Retention: private.purge_course_pin_alarms (raised_at older than 90 days).';

-- ============================================================================
-- 3. Inventories
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'course_pin_alarm_list_for_partner', 'p_facility_id text', false, false, false, false, false, true, false,
   '0073 (§59): edge_partner only; class A0 (manager / operator); course_pin_alarm list for a facility');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0073 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'course_pin_alarm', 'pd_course_pin_alarm_partner_select', 'SELECT', true,
   '0073 (§59): partner-bound manager / operator (or admin) reads alarm rows of a facility in their reach', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname = 'pd_course_pin_alarm_partner_select';
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name = 'pd_course_pin_alarm_partner_select') <> 1 THEN
    RAISE EXCEPTION '0073: expected 1 definer_policy_allowlist row for pd_course_pin_alarm_partner_select';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0073 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $$
DECLARE
  v_n int;
BEGIN
  SELECT count(*)::int INTO v_n FROM pg_policy pol
  JOIN pg_class c ON c.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'course_pin_alarm'
    AND pol.polname = 'pd_course_pin_alarm_partner_select';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0073: expected one pd_course_pin_alarm_partner_select policy, found %', v_n;
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.course_pin_alarm_list_for_partner(text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0073: edge_partner must EXECUTE course_pin_alarm_list_for_partner';
  END IF;
  IF has_function_privilege('edge_actor', 'private.course_pin_alarm_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.course_pin_alarm_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.course_pin_alarm_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.course_pin_alarm_list_for_partner(text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.course_pin_alarm_list_for_partner(text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0073: course_pin_alarm_list_for_partner must not be EXECUTEable by client / actor / system / service_role';
  END IF;
END
$$;
