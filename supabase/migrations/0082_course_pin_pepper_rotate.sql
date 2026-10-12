-- 0082_course_pin_pepper_rotate.sql
--
-- P5 §69: operator course-PIN pepper rotation (design M1 / 0046 header /
-- leftover from §68.3). One SECURITY DEFINER, private.course_pin_pepper_rotate,
-- is the source of truth; tools/db/rotate-course-pin-pepper.mjs only prints
-- SQL that calls it (stdout → pipe to psql; never holds pepper bytes).
--
-- MODES (p_mode text; hyphen aliases accepted):
--   non_compromise — refuse if course_pin_pepper_previous already exists;
--     copy current → previous (in-DB from vault.decrypted_secrets); replace
--     current via vault.update_secret with encode(gen_random_bytes(32),'hex');
--     INSERT app.course_pin_pepper_epoch (effective_from) VALUES (now()).
--   compromise — do NOT copy old; write NO epoch row; replace current;
--     DELETE previous in the same txn when present.
--   retire_previous — DELETE Vault previous only when latest effective_from
--     ≤ now() − 7 days; otherwise too_early (no-op). Operator-only in this
--     seam (no retention-purge hook).
--
-- EXECUTE: owner / SQL-editor only (REVOKE PUBLIC; no edge_* / client /
-- service_role grant). Pepper never leaves the database.
--
-- DELIBERATELY NOT HERE: retention-purge of previous, OCR / aHash / UI flag
-- flips / CAMERA. Nothing from 0001–0081 is edited.

-- ============================================================================
-- 1. Privileges the definer needs (Vault writers + pepper-epoch INSERT)
-- ============================================================================
-- Hosted Vault shape [unverified]: create_secret / update_secret as documented;
-- delete is DELETE FROM vault.secrets (no vault.delete_secret). Fail closed if
-- the Vault API functions are absent (DO assert below).
GRANT EXECUTE ON FUNCTION vault.create_secret(text, text, text, uuid) TO private_definer;
GRANT EXECUTE ON FUNCTION vault.update_secret(uuid, text, text, text, uuid) TO private_definer;
-- SELECT/INSERT/UPDATE/DELETE: harness Vault stand-ins are INVOKER (plaintext);
-- create_secret uses INSERT … RETURNING (needs SELECT). Hosted supabase_vault
-- create_secret/update_secret are SECURITY DEFINER and do not need table DML,
-- but the grants are required for the shim and only widen private_definer
-- (which already SELECTs decrypted_secrets).
GRANT SELECT, INSERT, UPDATE, DELETE ON vault.secrets TO private_definer;

GRANT INSERT ON app.course_pin_pepper_epoch TO private_definer;
CREATE POLICY pd_course_pin_pepper_epoch_insert ON app.course_pin_pepper_epoch
  FOR INSERT TO private_definer
  WITH CHECK (true);

COMMENT ON TABLE app.course_pin_pepper_epoch IS
  '0046/0082. One row per pepper rotation that keeps the old pepper as Vault secret course_pin_pepper_previous: the instant the NEW pepper took effect. Written by private.course_pin_pepper_rotate (non_compromise) in the same transaction as the Vault update; service_role may still SELECT/INSERT for diagnostics. Read by private.course_pin_matches (and the rotate definer for retire_previous). A COMPROMISE rotation writes no row and keeps no previous pepper. Holds no user id and no secret.';

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.course_pin_pepper_rotate(p_mode text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_mode text;
  v_cur_id uuid;
  v_cur text;
  v_prev_id uuid;
  v_prev text;
  v_new text;
  v_since timestamptz;
  v_effective_from timestamptz;
BEGIN
  IF p_mode IS NULL OR pg_catalog.btrim(p_mode) = '' THEN
    RAISE EXCEPTION 'course_pin_pepper_rotate: mode is required (non_compromise | compromise | retire_previous)' USING ERRCODE = '22023';
  END IF;
  v_mode := pg_catalog.lower(pg_catalog.replace(pg_catalog.btrim(p_mode), '-', '_'));
  IF v_mode NOT IN ('non_compromise', 'compromise', 'retire_previous') THEN
    RAISE EXCEPTION 'course_pin_pepper_rotate: bad mode % (non_compromise | compromise | retire_previous)', p_mode USING ERRCODE = '22023';
  END IF;

  SELECT s.id, s.decrypted_secret INTO v_cur_id, v_cur
  FROM vault.decrypted_secrets s
  WHERE s.name = 'course_pin_pepper';
  SELECT s.id, s.decrypted_secret INTO v_prev_id, v_prev
  FROM vault.decrypted_secrets s
  WHERE s.name = 'course_pin_pepper_previous';

  IF v_mode = 'retire_previous' THEN
    IF v_prev_id IS NULL THEN
      RETURN 'previous_absent';
    END IF;
    SELECT pg_catalog.max(e.effective_from) INTO v_since FROM app.course_pin_pepper_epoch e;
    IF v_since IS NULL OR v_since > pg_catalog.now() - interval '7 days' THEN
      RETURN 'too_early';
    END IF;
    DELETE FROM vault.secrets s WHERE s.id = v_prev_id AND s.name = 'course_pin_pepper_previous';
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (
      NULL,
      'operator.course_pin_pepper.rotate',
      'vault.secrets',
      'course_pin_pepper_previous',
      pg_catalog.jsonb_build_object('mode', v_mode, 'effective_from', v_since)
    );
    RETURN 'ok';
  END IF;

  IF v_cur_id IS NULL
     OR v_cur IS NULL
     OR pg_catalog.octet_length(pg_catalog.convert_to(v_cur, 'UTF8')) < 32 THEN
    RETURN 'no_pepper';
  END IF;

  IF v_mode = 'non_compromise' THEN
    IF v_prev_id IS NOT NULL THEN
      RETURN 'previous_exists';
    END IF;
    PERFORM vault.create_secret(
      v_cur,
      'course_pin_pepper_previous',
      'Previous course PIN pepper; delete via private.course_pin_pepper_rotate(retire_previous) after 7 days'
    );
    v_new := pg_catalog.encode(public.gen_random_bytes(32), 'hex');
    PERFORM vault.update_secret(v_cur_id, v_new);
    v_effective_from := pg_catalog.now();
    INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (v_effective_from);
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (
      NULL,
      'operator.course_pin_pepper.rotate',
      'app.course_pin_pepper_epoch',
      v_effective_from::text,
      pg_catalog.jsonb_build_object('mode', v_mode, 'effective_from', v_effective_from)
    );
    RETURN 'ok';
  END IF;

  -- compromise: replace current; drop previous if present; no epoch row
  v_new := pg_catalog.encode(public.gen_random_bytes(32), 'hex');
  PERFORM vault.update_secret(v_cur_id, v_new);
  IF v_prev_id IS NOT NULL THEN
    DELETE FROM vault.secrets s WHERE s.id = v_prev_id AND s.name = 'course_pin_pepper_previous';
  END IF;
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (
    NULL,
    'operator.course_pin_pepper.rotate',
    'vault.secrets',
    'course_pin_pepper',
    pg_catalog.jsonb_build_object('mode', v_mode, 'effective_from', NULL)
  );
  RETURN 'ok';
END
$$;

REVOKE EXECUTE ON FUNCTION private.course_pin_pepper_rotate(text) FROM PUBLIC;

COMMENT ON FUNCTION private.course_pin_pepper_rotate(text) IS
  '0082 (§69). Operator-only course PIN pepper rotation (non_compromise | compromise | retire_previous). SECURITY DEFINER search_path='''' owned by private_definer; REVOKE PUBLIC; no edge/client/service_role EXECUTE. Statuses: ok | previous_exists | no_pepper | previous_absent | too_early; raise 22023 for bad_mode. Pepper bytes never leave the database. Audit: operator.course_pin_pepper.rotate with mode + effective_from only.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0082 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'course_pin_pepper_rotate', 'p_mode text', false, false, false, false, false, false, false,
   '0082 (§69): owner/SQL-editor only; course PIN pepper rotation; no edge/client EXECUTE; statuses ok|previous_exists|no_pepper|previous_absent|too_early')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_anon = EXCLUDED.expected_anon,
    expected_authenticated = EXCLUDED.expected_authenticated,
    expected_service_role = EXCLUDED.expected_service_role,
    expected_edge_actor = EXCLUDED.expected_edge_actor,
    expected_edge_system = EXCLUDED.expected_edge_system,
    expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter,
    note = EXCLUDED.note;

UPDATE private.function_inventory
SET note = '0046/0082: reads Vault secret course_pin_pepper (with course_pin_matches); derives the daily PIN; NO role has EXECUTE. Pepper rotation is private.course_pin_pepper_rotate (operator-only).'
WHERE schema_name = 'private' AND function_name = 'course_pin_derive'
  AND identity_args = 'p_facility_id text, p_local_date date, p_pin_epoch integer';

UPDATE private.function_inventory
SET note = '0046/0082: is this PIN the one displayed at the instant p_at (current pepper, or previous before app.course_pin_pepper_epoch); reads the Vault peppers; no role has EXECUTE. Operator rotation: private.course_pin_pepper_rotate.'
WHERE schema_name = 'private' AND function_name = 'course_pin_matches'
  AND identity_args = 'p_facility_id text, p_local_date date, p_pin_epoch integer, p_pin text, p_at timestamp with time zone';

DROP POLICY current_user_edit_function_inventory_0082 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0082 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'course_pin_pepper_epoch', 'pd_course_pin_pepper_epoch_insert', 'INSERT', true,
   '0082: private.course_pin_pepper_rotate (non_compromise) writes effective_from = now(); no personal data; WITH CHECK (true)',
   'private_definer')
ON CONFLICT (schema_name, table_name, policy_name) DO UPDATE
SET note = EXCLUDED.note, command = EXCLUDED.command, scoped = EXCLUDED.scoped, role_name = EXCLUDED.role_name;
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND al.policy_name IN ('pd_course_pin_pepper_epoch_insert', 'pd_marker_scan_pepper_epoch_select');
UPDATE private.definer_policy_allowlist
SET note = 'private.course_pin_matches / course_pin_pepper_rotate: WHEN the current pepper took effect; no personal data and no secret, so USING (true)'
WHERE policy_name = 'pd_marker_scan_pepper_epoch_select';
DROP POLICY current_user_seed_definer_policy_allowlist_0082 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 4. DO asserts
-- ============================================================================
DO $assert_0082$
DECLARE
  v_n int;
BEGIN
  IF to_regprocedure('vault.create_secret(text, text, text, uuid)') IS NULL
     OR to_regprocedure('vault.update_secret(uuid, text, text, text, uuid)') IS NULL THEN
    RAISE EXCEPTION '0082: vault.create_secret / vault.update_secret are required (fail closed)';
  END IF;
  IF NOT has_function_privilege('private_definer', 'vault.create_secret(text, text, text, uuid)', 'EXECUTE')
     OR NOT has_function_privilege('private_definer', 'vault.update_secret(uuid, text, text, text, uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0082: private_definer must EXECUTE vault.create_secret / vault.update_secret';
  END IF;
  IF NOT has_table_privilege('private_definer', 'vault.secrets', 'SELECT')
     OR NOT has_table_privilege('private_definer', 'vault.secrets', 'INSERT')
     OR NOT has_table_privilege('private_definer', 'vault.secrets', 'UPDATE')
     OR NOT has_table_privilege('private_definer', 'vault.secrets', 'DELETE') THEN
    RAISE EXCEPTION '0082: private_definer must SELECT/INSERT/UPDATE/DELETE vault.secrets (shim INVOKER writers + RETURNING + retire/compromise delete; body filters previous by name)';
  END IF;
  IF NOT has_table_privilege('private_definer', 'app.course_pin_pepper_epoch', 'INSERT') THEN
    RAISE EXCEPTION '0082: private_definer must INSERT app.course_pin_pepper_epoch';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'course_pin_pepper_rotate'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0082: course_pin_pepper_rotate must be SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
  IF has_function_privilege('anon', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_actor', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.course_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.course_pin_pepper_rotate(text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0082: course_pin_pepper_rotate must not be EXECUTEable by client / edge / service_role';
  END IF;
  -- function_inventory is FORCE RLS; matrix 60 proves the inventory row as service_role.
END
$assert_0082$;
