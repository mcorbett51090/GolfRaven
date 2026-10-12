-- 0090_partner_member_list.sql
--
-- P5 §80: GET org member roster for managers / operators (class A0), so
-- the partners PWA can pick a userId for credential list / note / revoke
-- under reach (§79). Closes the §79.3 leftover "org member roster GET".
--
-- WHAT THIS ADDS
--   private.partner_member_list_for_partner(p_org_id uuid)
--     A0; manager | operator (admin passes). Active memberships only
--     (revoked_at IS NULL). Scoped like invite list: admin, or
--     has_facility_scope(manager|operator) on the org's facility.
--     Outside scope / unknown org → empty. Never email or token material.
--
-- SELECT policy: unchanged (pd_read_partner_member USING(true); body is
-- the real scope — same rationale as 0016 for scope helpers).
--
-- DELIBERATELY NOT HERE: partners PWA for others' credentials; OCR /
-- aHash / UI flag flips / CAMERA.
-- Nothing from 0001–0089 is edited.

-- ============================================================================
-- 1. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_member_list_for_partner(p_org_id uuid)
RETURNS TABLE (
  o_user_id uuid,
  o_org_id uuid,
  o_role app.partner_role,
  o_facility_id text,
  o_invited_by uuid,
  o_created_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A0');
  RETURN QUERY
  SELECT m.user_id, m.org_id, m.role, s.facility_id, m.invited_by, m.created_at
  FROM app.partner_member m
  LEFT JOIN app.partner_scope s ON s.org_id = m.org_id
  WHERE m.revoked_at IS NULL
    AND (p_org_id IS NULL OR m.org_id = p_org_id)
    AND (
      private.is_admin(v_uid)
      OR (s.facility_id IS NOT NULL
          AND private.has_facility_scope(v_uid, s.facility_id, ARRAY['manager', 'operator']::app.partner_role[]))
    )
  ORDER BY m.created_at DESC, m.user_id
  LIMIT 200;
END
$$;

COMMENT ON FUNCTION private.partner_member_list_for_partner(uuid) IS
  '0090 (§80). edge_partner only; class A0. Lists active memberships in orgs the actor''s manager/operator facility scope covers (or all for an admin). p_org_id NULL = every in-scope org. Never email or token material. Outside scope → empty.';

REVOKE ALL ON FUNCTION private.partner_member_list_for_partner(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_member_list_for_partner(uuid) TO edge_partner;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0090 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_member_list_for_partner', 'p_org_id uuid', false, false, false, false, false, true, false,
   '0090 (§80): edge_partner only; class A0; list active members in manager/operator facility scope (empty outside)')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_anon = EXCLUDED.expected_anon,
    expected_authenticated = EXCLUDED.expected_authenticated,
    expected_service_role = EXCLUDED.expected_service_role,
    expected_edge_actor = EXCLUDED.expected_edge_actor,
    expected_edge_system = EXCLUDED.expected_edge_system,
    expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter,
    note = EXCLUDED.note;

DO $assert_0090_inventory$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM private.function_inventory
    WHERE schema_name = 'private' AND function_name = 'partner_member_list_for_partner'
      AND identity_args = 'p_org_id uuid' AND expected_edge_partner AND note LIKE '%A0%'
  ) THEN
    RAISE EXCEPTION '0090: function_inventory must list partner_member_list_for_partner (edge_partner, A0)';
  END IF;
END
$assert_0090_inventory$;

DROP POLICY current_user_edit_function_inventory_0090 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 3. Assert
-- ============================================================================
DO $assert_0090$
DECLARE
  v_n int;
  v_src text;
BEGIN
  SELECT count(*)::int, max(p.prosrc)
  INTO v_n, v_src
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_member_list_for_partner'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole
    AND pg_get_function_identity_arguments(p.oid) = 'p_org_id uuid';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0090: expected one partner_member_list_for_partner(p_org_id uuid) SECURITY DEFINER owned by private_definer';
  END IF;
  IF v_src IS NULL
     OR v_src NOT LIKE '%partner_authorize%'
     OR v_src NOT LIKE '%has_facility_scope%'
     OR v_src NOT LIKE '%manager%' THEN
    RAISE EXCEPTION '0090: partner_member_list_for_partner body must authorize A0 and call has_facility_scope';
  END IF;
  IF pg_get_function_result('private.partner_member_list_for_partner(uuid)'::regprocedure) ~* 'email|token' THEN
    RAISE EXCEPTION '0090: member list must not return email or token columns';
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.partner_member_list_for_partner(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0090: edge_partner must EXECUTE partner_member_list_for_partner';
  END IF;
  IF has_function_privilege('edge_actor', 'private.partner_member_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_member_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.partner_member_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_member_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_member_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_member_list_for_partner(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0090: partner_member_list_for_partner must not be EXECUTEable by client / actor / system / minter / service_role';
  END IF;
END
$assert_0090$;
