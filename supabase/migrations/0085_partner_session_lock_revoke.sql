-- 0085_partner_session_lock_revoke.sql
--
-- P5 §72: make private.partner_session_lock_for_partner revoke with
-- revoke_reason = 'lock' (closes design 20.4 / 20.12 server follow-up).
-- Body mirrors partner_session_revoke_for_partner; no grant/mfa clears
-- (redundant once the row is dead). Function kept; PWA still uses POST
-- sign-out for Lock UI (no apps/partners change this slice).
--
-- WHAT THIS CHANGES
--   CREATE OR REPLACE private.partner_session_lock_for_partner()
--     authorize SESSION → bind sid → UPDATE revoked_at + revoke_reason='lock'
--     WHERE revoked_at IS NULL
--   function_inventory note / COMMENT
--
-- DELIBERATELY NOT HERE: PWA Lock UI route change; OCR / aHash / UI flag
-- flips / CAMERA; credential revoke/add UI.
-- Nothing from 0001–0084 is edited.

-- ============================================================================
-- 1. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_session_lock_for_partner()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, NULL, 'SESSION');
  v_sid := private.partner_binding_session();
  UPDATE app.partner_session s
     SET revoked_at = pg_catalog.clock_timestamp(),
         revoke_reason = 'lock'
   WHERE s.id = v_sid AND s.revoked_at IS NULL;
END
$$;

COMMENT ON FUNCTION private.partner_session_lock_for_partner() IS
  '0049/0085 (§72). edge_partner only; lock: class SESSION; revokes the bound session with revoke_reason = ''lock'' (mirrors partner_session_revoke_for_partner / sign_out). PWA Lock UI still sends POST sign-out (20.4); this route stays callable.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0085 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_session_lock_for_partner', '', false, false, false, false, false, true, false,
   '0085 (§72): edge_partner only; lock: class SESSION; revokes the bound session with revoke_reason = lock')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_anon = EXCLUDED.expected_anon,
    expected_authenticated = EXCLUDED.expected_authenticated,
    expected_service_role = EXCLUDED.expected_service_role,
    expected_edge_actor = EXCLUDED.expected_edge_actor,
    expected_edge_system = EXCLUDED.expected_edge_system,
    expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter,
    note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0085 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 3. DO asserts
-- ============================================================================
DO $assert_0085$
DECLARE
  v_n int;
  v_src text;
BEGIN
  SELECT count(*)::int, max(p.prosrc) INTO v_n, v_src
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_session_lock_for_partner'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole
    AND pg_get_function_identity_arguments(p.oid) = '';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0085: partner_session_lock_for_partner must be SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
  IF v_src IS NULL
     OR v_src NOT LIKE '%partner_authorize%'
     OR v_src NOT LIKE '%SESSION%'
     OR v_src NOT LIKE '%revoke_reason%'
     OR v_src NOT LIKE '%''lock''%'
     OR v_src LIKE '%partner_pin_grant_consume%'
     OR v_src LIKE '%partner_reauth_clear%'
     OR v_src LIKE '%partner_totp_mfa_clear%' THEN
    RAISE EXCEPTION '0085: partner_session_lock_for_partner body must authorize SESSION and revoke with reason lock (no grant/mfa clears)';
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.partner_session_lock_for_partner()', 'EXECUTE') THEN
    RAISE EXCEPTION '0085: edge_partner must EXECUTE partner_session_lock_for_partner';
  END IF;
  IF has_function_privilege('edge_actor', 'private.partner_session_lock_for_partner()', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_session_lock_for_partner()', 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.partner_session_lock_for_partner()', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_session_lock_for_partner()', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_session_lock_for_partner()', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_session_lock_for_partner()', 'EXECUTE') THEN
    RAISE EXCEPTION '0085: partner_session_lock_for_partner must not be EXECUTEable by client / other edge / service_role';
  END IF;
END
$assert_0085$;
