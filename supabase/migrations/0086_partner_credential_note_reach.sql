-- 0086_partner_credential_note_reach.sql
--
-- P5 §76: widen credential display-note PATCH so a manager (or higher)
-- under the 6.5 reach rule may set the note on another person's
-- credential. Closes the §65.2 / §75.3 leftover "reach-rule note edits".
-- Class stays A0 (display metadata; never a security decision). Own
-- writes unchanged. List stays own-only (no PWA surface for others yet).
--
-- WHAT THIS CHANGES
--   1. DROP + CREATE policy pd_update_partner_credential_note
--      (own OR partner_reach_covers)
--   2. CREATE OR REPLACE private.partner_credential_note_for_partner
--      (same reach check as revoke: unknown / outside reach → not_found)
--   3. function_inventory note / COMMENT / allowlist exprs
--
-- DELIBERATELY NOT HERE: partner_pin pepper_kid; OCR / aHash / UI flag
-- flips / CAMERA; partners PWA for others' credentials.
-- Nothing from 0001–0085 is edited.

-- ============================================================================
-- 1. UPDATE policy: own OR reach
-- ============================================================================
DROP POLICY pd_update_partner_credential_note ON app.partner_credential;

CREATE POLICY pd_update_partner_credential_note ON app.partner_credential FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND (user_id = (SELECT private.partner_binding_user())
              OR private.partner_reach_covers((SELECT private.partner_binding_user()), user_id)))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner'
              AND (user_id = (SELECT private.partner_binding_user())
                   OR private.partner_reach_covers((SELECT private.partner_binding_user()), user_id)));

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_credential_note_for_partner(p_credential_id uuid, p_note text)
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
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  -- own, or a person the 6.5 reach rule covers (same not_found for outside reach)
  IF v_owner <> v_uid AND NOT private.partner_reach_covers(v_uid, v_owner) THEN
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

COMMENT ON FUNCTION private.partner_credential_note_for_partner(uuid, text) IS
  '0079/0086 (§65/§76). edge_partner only; class A0. Sets the display-only note on the signed-in person''s OWN credential, or on a credential of a person the 6.5 reach rule covers (ok | not_found). Blank or NULL clears; at most 40 characters. Never used by a security decision.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0086 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_credential_note_for_partner', 'p_credential_id uuid, p_note text', false, false, false, false, false, true, false,
   '0079/0086 (§65/§76): edge_partner only; class A0; set display note on own or reach-covered credential (ok | not_found)')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_anon = EXCLUDED.expected_anon,
    expected_authenticated = EXCLUDED.expected_authenticated,
    expected_service_role = EXCLUDED.expected_service_role,
    expected_edge_actor = EXCLUDED.expected_edge_actor,
    expected_edge_system = EXCLUDED.expected_edge_system,
    expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter,
    note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0086 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0086 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.definer_policy_allowlist
SET note = '0086 (§76): partner-bound person updates note on OWN credential or one the 6.5 reach rule covers'
WHERE schema_name = 'app' AND table_name = 'partner_credential' AND policy_name = 'pd_update_partner_credential_note';

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
    RAISE EXCEPTION '0086: expected 1 definer_policy_allowlist row for pd_update_partner_credential_note';
  END IF;
END
$$;

DROP POLICY current_user_seed_definer_policy_allowlist_0086 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 4. DO asserts
-- ============================================================================
DO $assert_0086$
DECLARE
  v_n int;
  v_src text;
  v_using text;
BEGIN
  SELECT count(*)::int, max(p.prosrc) INTO v_n, v_src
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_credential_note_for_partner'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole
    AND pg_get_function_identity_arguments(p.oid) = 'p_credential_id uuid, p_note text';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0086: partner_credential_note_for_partner must be SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
  IF v_src IS NULL
     OR v_src NOT LIKE '%partner_authorize%'
     OR v_src NOT LIKE '%A0%'
     OR v_src NOT LIKE '%partner_reach_covers%' THEN
    RAISE EXCEPTION '0086: partner_credential_note_for_partner body must authorize A0 and call partner_reach_covers';
  END IF;
  SELECT count(*)::int, max(pg_get_expr(pol.polqual, pol.polrelid)) INTO v_n, v_using
  FROM pg_policy pol
  JOIN pg_class c ON c.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'partner_credential'
    AND pol.polname = 'pd_update_partner_credential_note';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0086: expected one pd_update_partner_credential_note policy, found %', v_n;
  END IF;
  IF v_using IS NULL OR v_using NOT LIKE '%partner_reach_covers%' THEN
    RAISE EXCEPTION '0086: pd_update_partner_credential_note USING must call partner_reach_covers';
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0086: edge_partner must EXECUTE partner_credential_note_for_partner';
  END IF;
  IF has_function_privilege('edge_actor', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_credential_note_for_partner(uuid, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0086: partner_credential_note_for_partner must not be EXECUTEable by client / actor / system / service_role';
  END IF;
END
$assert_0086$;
