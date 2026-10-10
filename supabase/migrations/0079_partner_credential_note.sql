-- 0079_partner_credential_note.sql
--
-- P5 §65: PATCH credentials/{id} display note left open by 0054 /
-- partner-auth-design §23.3 / §64.3. Class A0; own credential only;
-- display metadata never used by a security decision.
--
-- WHAT THIS ADDS
--   1. GRANT UPDATE (note) on app.partner_credential to private_definer
--   2. UPDATE policy pd_update_partner_credential_note (partner-bound, own)
--   3. private.partner_credential_note_for_partner(id, note)
--      statuses: ok | not_found; blank/NULL clears; length > 40 → 22023
--
-- DELIBERATELY NOT HERE: admin keep=2, IP/global alert buckets,
-- pepper-rotation, OCR / aHash / UI flag flips / CAMERA, partners PWA.
-- Nothing from 0001–0078 is edited.

-- ============================================================================
-- 1. Column grant + UPDATE policy
-- ============================================================================
GRANT UPDATE (note) ON app.partner_credential TO private_definer;

CREATE POLICY pd_update_partner_credential_note ON app.partner_credential FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND user_id = (SELECT private.partner_binding_user()))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner'
              AND user_id = (SELECT private.partner_binding_user()));

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_credential_note_for_partner(p_credential_id uuid, p_note text)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_owner uuid;
  v_note text;
  v_n integer;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  IF p_credential_id IS NULL THEN
    RAISE EXCEPTION 'partner_credential_note_for_partner: a credential is required' USING ERRCODE = '22023';
  END IF;
  -- blank / whitespace clears; over 40 characters is malformed (CHECK is the second line)
  v_note := CASE WHEN p_note IS NULL THEN NULL ELSE NULLIF(pg_catalog.btrim(p_note), '') END;
  IF v_note IS NOT NULL AND pg_catalog.char_length(v_note) > 40 THEN
    RAISE EXCEPTION 'partner_credential_note_for_partner: note is at most 40 characters' USING ERRCODE = '22023';
  END IF;
  SELECT c.user_id INTO v_owner FROM app.partner_credential c WHERE c.id = p_credential_id;
  IF NOT FOUND OR v_owner <> v_uid THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  UPDATE app.partner_credential c SET note = v_note WHERE c.id = p_credential_id;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n <> 1 THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'ok'::text;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.partner_credential_note_for_partner(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_credential_note_for_partner(uuid, text) TO edge_partner;

COMMENT ON FUNCTION private.partner_credential_note_for_partner(uuid, text) IS
  '0079 (§65). edge_partner only; class A0. Sets the display-only note on the signed-in person''s OWN credential (ok | not_found). Blank or NULL clears; at most 40 characters. Never used by a security decision.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Inventories
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_credential_note_for_partner', 'p_credential_id uuid, p_note text', false, false, false, false, false, true, false,
   '0079 (§65): edge_partner only; class A0; set display note on own credential (ok | not_found)');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0079 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_credential', 'pd_update_partner_credential_note', 'UPDATE', true,
   '0079 (§65): partner-bound person updates note on their OWN credential only', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname = 'pd_update_partner_credential_note';
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name = 'pd_update_partner_credential_note') <> 1 THEN
    RAISE EXCEPTION '0079: expected 1 definer_policy_allowlist row for pd_update_partner_credential_note';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0079 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $$
DECLARE
  v_n int;
BEGIN
  SELECT count(*)::int INTO v_n FROM pg_policy pol
  JOIN pg_class c ON c.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'partner_credential'
    AND pol.polname = 'pd_update_partner_credential_note';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0079: expected one pd_update_partner_credential_note policy, found %', v_n;
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0079: edge_partner must EXECUTE partner_credential_note_for_partner';
  END IF;
  IF has_function_privilege('edge_actor', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0079: partner_credential_note_for_partner must not be EXECUTEable by client / actor / system / service_role';
  END IF;
END
$$;
