-- 0089_partner_credential_list_reach.sql
--
-- P5 §79: widen GET credentials so a manager (or higher) under the 6.5
-- reach rule may list another person's credentials (never the key, the
-- credential id bytes, or the sign counter). Closes the §76.2 / §78.3
-- leftover that kept list own-only while PATCH/DELETE already did reach.
-- Class stays A0. Outside reach / unknown target → empty set (same
-- non-oracle as "no credentials visible").
--
-- WHAT THIS CHANGES
--   1. DROP + CREATE private.partner_credential_list_for_partner(p_user_id uuid DEFAULT NULL)
--      (NULL or self → own rows; else only when partner_reach_covers)
--   2. function_inventory identity_args '' → p_user_id uuid; COMMENT
--
-- SELECT policy pd_read_partner_credential_bound already allows own OR
-- reach (0054); no policy change.
--
-- DELIBERATELY NOT HERE: partners PWA for others' credentials; org
-- member roster GET; OCR / aHash / UI flag flips / CAMERA.
-- Nothing from 0001–0088 is edited.

-- ============================================================================
-- 1. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

DROP FUNCTION private.partner_credential_list_for_partner();

CREATE FUNCTION private.partner_credential_list_for_partner(p_user_id uuid DEFAULT NULL)
RETURNS TABLE (o_id uuid, o_label text, o_note text, o_created_at timestamptz, o_last_used_at timestamptz, o_revoked_at timestamptz, o_backup_eligible boolean, o_backup_state boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_target uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  v_target := COALESCE(p_user_id, v_uid);
  -- own, or a person the 6.5 reach rule covers; otherwise empty (no not_found status on a list)
  IF v_target <> v_uid AND NOT private.partner_reach_covers(v_uid, v_target) THEN
    RETURN;
  END IF;
  RETURN QUERY
  SELECT c.id, c.label, c.note, c.created_at, c.last_used_at, c.revoked_at, c.backup_eligible, c.backup_state
  FROM app.partner_credential c
  WHERE c.user_id = v_target
  ORDER BY c.created_at DESC, c.id;
END
$$;

COMMENT ON FUNCTION private.partner_credential_list_for_partner(uuid) IS
  '0054/0089 (§79). edge_partner only; class A0. Lists credentials of the signed-in person (p_user_id NULL or self), or of a person the 6.5 reach rule covers. Never the public key, credential id bytes, or sign counter. Outside reach → empty.';

REVOKE ALL ON FUNCTION private.partner_credential_list_for_partner(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_credential_list_for_partner(uuid) TO edge_partner;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Inventories
-- ============================================================================
GRANT INSERT, UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0089 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

DELETE FROM private.function_inventory
WHERE schema_name = 'private' AND function_name = 'partner_credential_list_for_partner' AND identity_args = '';

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_credential_list_for_partner', 'p_user_id uuid', false, false, false, false, false, true, false,
   '0054/0089 (§79): edge_partner only; class A0; list own or reach-covered person''s credentials (empty outside reach)')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_anon = EXCLUDED.expected_anon,
    expected_authenticated = EXCLUDED.expected_authenticated,
    expected_service_role = EXCLUDED.expected_service_role,
    expected_edge_actor = EXCLUDED.expected_edge_actor,
    expected_edge_system = EXCLUDED.expected_edge_system,
    expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter,
    note = EXCLUDED.note;

-- Inventory asserts while the CURRENT_USER edit policy is still open (FORCE RLS).
DO $assert_0089_inventory$
BEGIN
  IF (SELECT count(*)::int FROM private.function_inventory
      WHERE schema_name = 'private' AND function_name = 'partner_credential_list_for_partner') <> 1 THEN
    RAISE EXCEPTION '0089: expected exactly one function_inventory row for partner_credential_list_for_partner';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM private.function_inventory
    WHERE schema_name = 'private' AND function_name = 'partner_credential_list_for_partner'
      AND identity_args = 'p_user_id uuid' AND note LIKE '%reach%'
  ) THEN
    RAISE EXCEPTION '0089: function_inventory must list p_user_id uuid with a reach note';
  END IF;
END
$assert_0089_inventory$;

DROP POLICY current_user_edit_function_inventory_0089 ON private.function_inventory;
REVOKE INSERT, UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 3. Assert (catalog / ACL; no inventory SELECT after FORCE RLS policy drop)
-- ============================================================================
DO $assert_0089$
DECLARE
  v_n int;
  v_src text;
BEGIN
  SELECT count(*)::int, max(p.prosrc)
  INTO v_n, v_src
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_credential_list_for_partner'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole
    AND pg_get_function_identity_arguments(p.oid) = 'p_user_id uuid';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0089: expected one partner_credential_list_for_partner(p_user_id uuid) SECURITY DEFINER owned by private_definer';
  END IF;
  IF v_src IS NULL OR v_src NOT LIKE '%partner_reach_covers%' THEN
    RAISE EXCEPTION '0089: partner_credential_list_for_partner body must call partner_reach_covers';
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.partner_credential_list_for_partner(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0089: edge_partner must EXECUTE partner_credential_list_for_partner(uuid)';
  END IF;
  IF has_function_privilege('edge_actor', 'private.partner_credential_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_credential_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.partner_credential_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_credential_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_credential_list_for_partner(uuid)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_credential_list_for_partner(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0089: partner_credential_list_for_partner must not be EXECUTEable by client / actor / system / minter / service_role';
  END IF;
  -- zero-arg overload must be gone (DEFAULT keeps bare calls working)
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'private' AND p.proname = 'partner_credential_list_for_partner'
      AND pg_get_function_identity_arguments(p.oid) = ''
  ) THEN
    RAISE EXCEPTION '0089: zero-arg partner_credential_list_for_partner must be dropped';
  END IF;
END
$assert_0089$;
