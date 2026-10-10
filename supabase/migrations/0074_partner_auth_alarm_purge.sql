-- 0074_partner_auth_alarm_purge.sql
--
-- P5 §60: retention for app.partner_auth_alarm left open by 0048 /
-- partner-auth-design §9 / §59.3. Bounded edge_system purge on the
-- existing retention-purge schedule (0040 / 0054 / 0071 / 0072 shape).
--
-- WHAT THIS ADDS
--   private.purge_partner_auth_alarms()
--     raised_at < now() - 90 days; LIMIT 5000.
--
-- POLICIES: floor repeated in private_definer DELETE + SELECT companion;
-- closed under a partner binding (0050 InitPlan form).
--
-- GRANTS: DELETE + SELECT (id, raised_at) on partner_auth_alarm (0048
-- granted INSERT + SELECT on the arbiter columns only). EXECUTE for
-- edge_system only.
--
-- DELIBERATELY NOT HERE: pepper-rotation tooling, plan §8.3 cap alert,
-- OCR / aHash / UI flag flips / CAMERA.
-- Nothing from 0001–0073 is edited.

-- ============================================================================
-- 1. Grants and policies (private_definer)
-- ============================================================================
GRANT DELETE, SELECT (id, raised_at) ON app.partner_auth_alarm TO private_definer;

CREATE POLICY pd_purge_partner_auth_alarm ON app.partner_auth_alarm FOR DELETE TO private_definer
  USING (raised_at < now() - interval '90 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_auth_alarm_r ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (raised_at < now() - interval '90 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.purge_partner_auth_alarms()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_auth_alarm a
  WHERE a.id = ANY (ARRAY(
    SELECT s.id FROM app.partner_auth_alarm s
    WHERE s.raised_at < pg_catalog.now() - interval '90 days'
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

REVOKE EXECUTE ON FUNCTION private.purge_partner_auth_alarms() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.purge_partner_auth_alarms() TO edge_system;

COMMENT ON FUNCTION private.purge_partner_auth_alarms() IS
  '0074 (§60). edge_system. Deletes partner_auth_alarm rows whose raised_at is more than 90 days past, at most 5000 per call; returns the count. Floor repeated in pd_purge_partner_auth_alarm[_r].';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074. One row per (kind, credential, minute) when private.partner_session_mint refused a sign-in the Edge had already passed: signature_invalid or counter_regression. Operator-facing. Holds no user id and no assertion bytes. Written only by private.partner_mint_alarm_write. Retention: private.purge_partner_auth_alarms (raised_at older than 90 days).';

-- ============================================================================
-- 3. Registries
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'purge_partner_auth_alarms', '', false, false, false, false, true, false, false,
   '0074 (§60): edge_system; partner_auth_alarm rows older than 90 days, 5000 per call');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0074 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_purge_partner_auth_alarm', 'DELETE', true,
   '0074 purge: alarms raised more than 90 days ago; closed under a partner binding', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_purge_partner_auth_alarm_r', 'SELECT', true,
   'row-visibility companion to pd_purge_partner_auth_alarm', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_purge_partner_auth_alarm', 'pd_purge_partner_auth_alarm_r');
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN ('pd_purge_partner_auth_alarm', 'pd_purge_partner_auth_alarm_r')) <> 2 THEN
    RAISE EXCEPTION '0074: expected 2 definer_policy_allowlist rows for the new purge policies';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0074 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $$
BEGIN
  IF NOT has_function_privilege('edge_system', 'private.purge_partner_auth_alarms()', 'EXECUTE') THEN
    RAISE EXCEPTION '0074: edge_system must EXECUTE purge_partner_auth_alarms';
  END IF;
  IF has_function_privilege('edge_actor', 'private.purge_partner_auth_alarms()', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.purge_partner_auth_alarms()', 'EXECUTE')
     OR has_function_privilege('anon', 'private.purge_partner_auth_alarms()', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.purge_partner_auth_alarms()', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.purge_partner_auth_alarms()', 'EXECUTE') THEN
    RAISE EXCEPTION '0074: purge_partner_auth_alarms must not be EXECUTEable by client / partner / service_role';
  END IF;
END
$$;
