-- 0084_course_pin_pepper_previous_purge.sql
--
-- P5 §71: automatic 7-day purge of Vault course_pin_pepper_previous left
-- open by 0082 / partner-auth-design §69.3 / §70.3. Thin edge_system
-- wrapper on the existing retention-purge schedule; the 7-day floor and
-- DELETE live in private.course_pin_pepper_rotate('retire_previous').
--
-- WHAT THIS ADDS
--   private.purge_course_pin_pepper_previous()
--     calls course_pin_pepper_rotate('retire_previous'); maps ok → 1,
--     too_early / previous_absent → 0; raises only on unexpected SQL
--     errors (unexpected status is a programming error).
--
-- GRANTS: EXECUTE for edge_system only. Never GRANT edge_* EXECUTE on
-- course_pin_pepper_rotate (owner / SQL-editor only, 0082).
--
-- AUDIT: keep operator.course_pin_pepper.rotate from retire_previous —
-- no separate system.* audit on this seam.
--
-- DELIBERATELY NOT HERE: OCR / aHash / UI flag flips / CAMERA;
-- credential revoke/add UI; reach-rule note edits.
-- Nothing from 0001–0083 is edited.

-- ============================================================================
-- 1. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.purge_course_pin_pepper_previous()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_status text;
BEGIN
  v_status := private.course_pin_pepper_rotate('retire_previous');
  IF v_status = 'ok' THEN
    RETURN 1;
  END IF;
  IF v_status IN ('too_early', 'previous_absent') THEN
    RETURN 0;
  END IF;
  RAISE EXCEPTION 'purge_course_pin_pepper_previous: unexpected status %', v_status
    USING ERRCODE = 'XX000';
END
$$;

REVOKE EXECUTE ON FUNCTION private.purge_course_pin_pepper_previous() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.purge_course_pin_pepper_previous() TO edge_system;

COMMENT ON FUNCTION private.purge_course_pin_pepper_previous() IS
  '0084 (§71). edge_system. Wrapper: private.course_pin_pepper_rotate(''retire_previous''); returns 1 on ok, 0 on too_early / previous_absent. Audit stays operator.course_pin_pepper.rotate from the rotate definer. Never GRANT edge EXECUTE on course_pin_pepper_rotate.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0084 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'purge_course_pin_pepper_previous', '', false, false, false, false, true, false, false,
   '0084 (§71): edge_system; wraps course_pin_pepper_rotate(retire_previous); ok→1, too_early/previous_absent→0')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_anon = EXCLUDED.expected_anon,
    expected_authenticated = EXCLUDED.expected_authenticated,
    expected_service_role = EXCLUDED.expected_service_role,
    expected_edge_actor = EXCLUDED.expected_edge_actor,
    expected_edge_system = EXCLUDED.expected_edge_system,
    expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter,
    note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0084 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 3. DO asserts
-- ============================================================================
DO $assert_0084$
DECLARE
  v_n int;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'purge_course_pin_pepper_previous'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0084: purge_course_pin_pepper_previous must be SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
  IF NOT has_function_privilege('edge_system', 'private.purge_course_pin_pepper_previous()', 'EXECUTE') THEN
    RAISE EXCEPTION '0084: edge_system must EXECUTE purge_course_pin_pepper_previous';
  END IF;
  IF has_function_privilege('edge_actor', 'private.purge_course_pin_pepper_previous()', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.purge_course_pin_pepper_previous()', 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.purge_course_pin_pepper_previous()', 'EXECUTE')
     OR has_function_privilege('anon', 'private.purge_course_pin_pepper_previous()', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.purge_course_pin_pepper_previous()', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.purge_course_pin_pepper_previous()', 'EXECUTE') THEN
    RAISE EXCEPTION '0084: purge_course_pin_pepper_previous must not be EXECUTEable by client / partner / service_role';
  END IF;
  -- Wrapper only: rotate stays owner-only (no edge EXECUTE).
  IF has_function_privilege('edge_system', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_actor', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.course_pin_pepper_rotate(text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0084: course_pin_pepper_rotate must still have NO edge/client/service_role EXECUTE';
  END IF;
END
$assert_0084$;
