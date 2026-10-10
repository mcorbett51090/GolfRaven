-- 0075_partner_auth_alarm_list.sql
--
-- P5 §61: partner (admin) read of app.partner_auth_alarm left open by
-- 0048 / 0074 / partner-auth-design §60.3. Operator-facing portal list of
-- sign-in alarms the database raised after the Edge had already passed
-- the assertion (signature_invalid / counter_regression).
--
-- WHAT THIS ADDS
--   1. private.partner_auth_alarm_list_for_partner()
--      class A0, ADMIN only (same gate as partner_held_queue_for_partner);
--      returns the row columns, newest first, at most 100.
--   2. SELECT policy pd_partner_auth_alarm_partner_select keyed on
--      partner_bound_admin (InitPlan form). 0048's unbound mint-writer
--      policies and 0074's purge companions stay closed under a partner
--      binding (or open only without one).
--   3. GRANT SELECT (detail) — id/kind/credential_id/minute_bucket/
--      raised_at already granted by 0048 / 0074.
--
-- DELIBERATELY NOT HERE: pepper-rotation tooling, OCR / aHash / UI flag
-- flips / CAMERA, plan §8.3 cap alert.
-- Nothing from 0001–0074 is edited.

-- ============================================================================
-- 1. Partner SELECT policy + column grant
-- ============================================================================
GRANT SELECT (detail) ON app.partner_auth_alarm TO private_definer;

CREATE POLICY pd_partner_auth_alarm_partner_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND private.partner_bound_admin());

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_auth_alarm_list_for_partner()
RETURNS TABLE (
  o_id uuid,
  o_kind text,
  o_credential_id uuid,
  o_minute_bucket bigint,
  o_detail jsonb,
  o_raised_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_auth_alarm_list_for_partner: only an admin may read partner auth alarms' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT a.id, a.kind, a.credential_id, a.minute_bucket, a.detail, a.raised_at
  FROM app.partner_auth_alarm a
  ORDER BY a.raised_at DESC, a.id
  LIMIT 100;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.partner_auth_alarm_list_for_partner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_auth_alarm_list_for_partner() TO edge_partner;

COMMENT ON FUNCTION private.partner_auth_alarm_list_for_partner() IS
  '0075 (§61). edge_partner only; class A0; ADMIN only. The partner_auth_alarm rows (newest first, 100): signature_invalid / counter_regression after the Edge passed. No user id and no assertion bytes.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075. One row per (kind, credential, minute) when private.partner_session_mint refused a sign-in the Edge had already passed: signature_invalid or counter_regression. Operator-facing: private.partner_auth_alarm_list_for_partner (portal). Holds no user id and no assertion bytes. Written only by private.partner_mint_alarm_write. Retention: private.purge_partner_auth_alarms (raised_at older than 90 days).';

-- ============================================================================
-- 3. Inventories
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_auth_alarm_list_for_partner', '', false, false, false, false, false, true, false,
   '0075 (§61): edge_partner only; class A0; ADMIN only; partner_auth_alarm list');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0075 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_auth_alarm_partner_select', 'SELECT', true,
   '0075 (§61): partner-bound admin reads partner_auth_alarm rows', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname = 'pd_partner_auth_alarm_partner_select';
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name = 'pd_partner_auth_alarm_partner_select') <> 1 THEN
    RAISE EXCEPTION '0075: expected 1 definer_policy_allowlist row for pd_partner_auth_alarm_partner_select';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0075 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $$
DECLARE
  v_n int;
BEGIN
  SELECT count(*)::int INTO v_n FROM pg_policy pol
  JOIN pg_class c ON c.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'partner_auth_alarm'
    AND pol.polname = 'pd_partner_auth_alarm_partner_select';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0075: expected one pd_partner_auth_alarm_partner_select policy, found %', v_n;
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.partner_auth_alarm_list_for_partner()', 'EXECUTE') THEN
    RAISE EXCEPTION '0075: edge_partner must EXECUTE partner_auth_alarm_list_for_partner';
  END IF;
  IF has_function_privilege('edge_actor', 'private.partner_auth_alarm_list_for_partner()', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_auth_alarm_list_for_partner()', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_auth_alarm_list_for_partner()', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_auth_alarm_list_for_partner()', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_auth_alarm_list_for_partner()', 'EXECUTE') THEN
    RAISE EXCEPTION '0075: partner_auth_alarm_list_for_partner must not be EXECUTEable by client / actor / system / service_role';
  END IF;
  IF NOT has_column_privilege('private_definer', 'app.partner_auth_alarm', 'detail', 'SELECT') THEN
    RAISE EXCEPTION '0075: private_definer must SELECT partner_auth_alarm.detail';
  END IF;
END
$$;
