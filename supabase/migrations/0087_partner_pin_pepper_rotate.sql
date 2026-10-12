-- 0087_partner_pin_pepper_rotate.sql
--
-- P5 §77: operator partner-PIN pepper rotation + dual-verify / lazy rewrap
-- (design D4 / 0052 header / leftover from §76.3). Mirrors §69 course-PIN
-- rotate, with one difference: stored verifiers cannot be rehashed without
-- the member's derived key, so private.partner_pin_core accepts the previous
-- Vault pepper while app.partner_pin_pepper_epoch exists, and
-- private.partner_pin_attempt rewrites verifier + pepper_kid under the
-- current pepper on a previous match.
--
-- MODES (p_mode text; hyphen aliases accepted):
--   non_compromise — refuse if partner_pin_pepper_previous already exists;
--     copy current → previous (in-DB); replace current; INSERT epoch with a
--     fresh pepper_kid.
--   compromise — no copy, no epoch row; replace current; DELETE previous.
--   retire_previous — DELETE previous only when latest effective_from
--     ≤ now() − 7 days; else too_early. Operator-only in this seam.
--
-- EXECUTE: owner / SQL-editor only (REVOKE PUBLIC; no edge/client/
-- service_role). Pepper never leaves the database.
--
-- DELIBERATELY NOT HERE: retention-purge of previous, OCR / aHash / UI flag
-- flips / CAMERA; partners PWA for others' credentials.
-- Nothing from 0001–0086 is edited.

-- ============================================================================
-- 1. app.partner_pin_pepper_epoch
-- ============================================================================
CREATE TABLE app.partner_pin_pepper_epoch (
  effective_from timestamptz PRIMARY KEY,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  pepper_kid text NOT NULL CHECK (pepper_kid ~ '^[a-z0-9_-]{1,32}$'),
  CONSTRAINT partner_pin_pepper_epoch_effective_not_future CHECK (effective_from <= recorded_at),
  CONSTRAINT partner_pin_pepper_epoch_kid_unique UNIQUE (pepper_kid)
);
COMMENT ON TABLE app.partner_pin_pepper_epoch IS
  '0087 (§77). One row per non-compromise partner PIN pepper rotation: when the NEW pepper took effect and its pepper_kid. Written by private.partner_pin_pepper_rotate in the same transaction as the Vault update. Read by private.partner_pin_core (current kid + whether previous may be tried). A COMPROMISE rotation writes no row. Holds no user id and no secret.';
ALTER TABLE app.partner_pin_pepper_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_pin_pepper_epoch FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.partner_pin_pepper_epoch FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON app.partner_pin_pepper_epoch TO service_role;
GRANT SELECT ON app.partner_pin_pepper_epoch TO private_definer;
CREATE POLICY pd_partner_pin_pepper_epoch_select ON app.partner_pin_pepper_epoch
  FOR SELECT TO private_definer USING (true);

-- Vault writers already granted to private_definer in 0082; epoch INSERT for rotate.
GRANT INSERT ON app.partner_pin_pepper_epoch TO private_definer;
CREATE POLICY pd_partner_pin_pepper_epoch_insert ON app.partner_pin_pepper_epoch
  FOR INSERT TO private_definer
  WITH CHECK (true);

-- ============================================================================
-- 2. Dual-verify core (DROP + CREATE: third OUT column o_pepper_kid)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

DROP FUNCTION private.partner_pin_core(uuid, bytea, bytea);

CREATE FUNCTION private.partner_pin_core(p_uid uuid, p_derived bytea, p_stored bytea)
RETURNS TABLE (o_verifier bytea, o_match boolean, o_pepper_kid text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
  v_prev text;
  v_k bytea;
  v_k_prev bytea;
  v_msg bytea;
  v_ver bytea;
  v_ver_prev bytea;
  v_kid text;
  v_prev_ok boolean;
BEGIN
  IF p_uid IS NULL OR p_derived IS NULL OR pg_catalog.octet_length(p_derived) <> 32 THEN
    RAISE EXCEPTION 'partner_pin_core: a user and a 32-byte derived key are required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'partner_pin_pepper';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'partner_pin_core: the partner PIN pepper is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  SELECT e.pepper_kid INTO v_kid
  FROM app.partner_pin_pepper_epoch e
  ORDER BY e.effective_from DESC
  LIMIT 1;
  IF v_kid IS NULL THEN
    v_kid := 'v1';
  END IF;
  v_k := pg_catalog.convert_to(v_key, 'UTF8');
  v_msg := pg_catalog.convert_to('golfraven/partner-pin/v1', 'UTF8')
        || pg_catalog.decode('00', 'hex')
        || pg_catalog.decode(pg_catalog.replace(p_uid::text, '-', ''), 'hex')
        || p_derived;
  v_ver := public.hmac(v_msg, v_k, 'sha256');
  o_verifier := v_ver;
  o_pepper_kid := v_kid;
  o_match := false;
  IF p_stored IS NOT NULL THEN
    IF public.hmac(p_stored, v_k, 'sha256') = public.hmac(v_ver, v_k, 'sha256') THEN
      o_match := true;
    ELSE
      -- previous pepper only while an epoch row exists (non_compromise window)
      SELECT s.decrypted_secret INTO v_prev
      FROM vault.decrypted_secrets s
      WHERE s.name = 'partner_pin_pepper_previous';
      v_prev_ok := v_prev IS NOT NULL
                   AND pg_catalog.octet_length(pg_catalog.convert_to(v_prev, 'UTF8')) >= 32
                   AND EXISTS (SELECT 1 FROM app.partner_pin_pepper_epoch);
      IF v_prev_ok THEN
        v_k_prev := pg_catalog.convert_to(v_prev, 'UTF8');
        v_ver_prev := public.hmac(v_msg, v_k_prev, 'sha256');
        IF public.hmac(p_stored, v_k_prev, 'sha256') = public.hmac(v_ver_prev, v_k_prev, 'sha256') THEN
          o_match := true;
          -- o_verifier stays under CURRENT so the caller can lazy-rewrap
        END IF;
      END IF;
    END IF;
  END IF;
  RETURN NEXT;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_pin_core(uuid, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_pin_core(uuid, bytea, bytea) TO partner_pin_verifier;

COMMENT ON FUNCTION private.partner_pin_core(uuid, bytea, bytea) IS
  '0052/0087 (§77). ONLY reader of Vault partner_pin_pepper (+ partner_pin_pepper_previous while an epoch row exists). Returns HMAC under the CURRENT pepper as o_verifier, current pepper_kid, and o_match (current or previous). On a previous-only match o_verifier is the rewrap target. EXECUTE for partner_pin_verifier + owner private_definer; pepper never returned.';

-- ============================================================================
-- 3. Operator rotate definer
-- ============================================================================
CREATE FUNCTION private.partner_pin_pepper_rotate(p_mode text)
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
  v_kid text;
  v_since timestamptz;
  v_effective_from timestamptz;
BEGIN
  IF p_mode IS NULL OR pg_catalog.btrim(p_mode) = '' THEN
    RAISE EXCEPTION 'partner_pin_pepper_rotate: mode is required (non_compromise | compromise | retire_previous)' USING ERRCODE = '22023';
  END IF;
  v_mode := pg_catalog.lower(pg_catalog.replace(pg_catalog.btrim(p_mode), '-', '_'));
  IF v_mode NOT IN ('non_compromise', 'compromise', 'retire_previous') THEN
    RAISE EXCEPTION 'partner_pin_pepper_rotate: bad mode % (non_compromise | compromise | retire_previous)', p_mode USING ERRCODE = '22023';
  END IF;

  SELECT s.id, s.decrypted_secret INTO v_cur_id, v_cur
  FROM vault.decrypted_secrets s
  WHERE s.name = 'partner_pin_pepper';
  SELECT s.id, s.decrypted_secret INTO v_prev_id, v_prev
  FROM vault.decrypted_secrets s
  WHERE s.name = 'partner_pin_pepper_previous';

  IF v_mode = 'retire_previous' THEN
    IF v_prev_id IS NULL THEN
      RETURN 'previous_absent';
    END IF;
    SELECT pg_catalog.max(e.effective_from) INTO v_since FROM app.partner_pin_pepper_epoch e;
    IF v_since IS NULL OR v_since > pg_catalog.now() - interval '7 days' THEN
      RETURN 'too_early';
    END IF;
    DELETE FROM vault.secrets s WHERE s.id = v_prev_id AND s.name = 'partner_pin_pepper_previous';
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (
      NULL,
      'operator.partner_pin_pepper.rotate',
      'vault.secrets',
      'partner_pin_pepper_previous',
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
      'partner_pin_pepper_previous',
      'Previous partner PIN pepper; delete via private.partner_pin_pepper_rotate(retire_previous) after 7 days'
    );
    v_new := pg_catalog.encode(public.gen_random_bytes(32), 'hex');
    v_kid := pg_catalog.encode(public.gen_random_bytes(8), 'hex');
    PERFORM vault.update_secret(v_cur_id, v_new);
    v_effective_from := pg_catalog.now();
    INSERT INTO app.partner_pin_pepper_epoch (effective_from, pepper_kid)
    VALUES (v_effective_from, v_kid);
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (
      NULL,
      'operator.partner_pin_pepper.rotate',
      'app.partner_pin_pepper_epoch',
      v_effective_from::text,
      pg_catalog.jsonb_build_object('mode', v_mode, 'effective_from', v_effective_from, 'pepper_kid', v_kid)
    );
    RETURN 'ok';
  END IF;

  -- compromise: replace current; drop previous if present; no epoch row
  v_new := pg_catalog.encode(public.gen_random_bytes(32), 'hex');
  PERFORM vault.update_secret(v_cur_id, v_new);
  IF v_prev_id IS NOT NULL THEN
    DELETE FROM vault.secrets s WHERE s.id = v_prev_id AND s.name = 'partner_pin_pepper_previous';
  END IF;
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (
    NULL,
    'operator.partner_pin_pepper.rotate',
    'vault.secrets',
    'partner_pin_pepper',
    pg_catalog.jsonb_build_object('mode', v_mode, 'effective_from', NULL)
  );
  RETURN 'ok';
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_pin_pepper_rotate(text) FROM PUBLIC;

COMMENT ON FUNCTION private.partner_pin_pepper_rotate(text) IS
  '0087 (§77). Operator-only partner PIN pepper rotation (non_compromise | compromise | retire_previous). SECURITY DEFINER search_path='''' owned by private_definer; REVOKE PUBLIC; no edge/client/service_role EXECUTE. Statuses: ok | previous_exists | no_pepper | previous_absent | too_early; raise 22023 for bad_mode. Pepper bytes never leave the database. Audit: operator.partner_pin_pepper.rotate with mode + effective_from (+ pepper_kid on non_compromise) only.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Lazy rewrap on attempt + current kid on set/change
-- ============================================================================
GRANT partner_pin_verifier TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
GRANT CREATE ON SCHEMA private TO partner_pin_verifier;
SET ROLE partner_pin_verifier;

CREATE OR REPLACE FUNCTION private.partner_pin_attempt(p_uid uuid, p_derived bytea)
RETURNS TABLE (o_status text, o_retry_after integer, o_newly_locked boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_p record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_day date := (pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')::date;
  v_match boolean;
  v_ver bytea;
  v_kid text;
  v_fc integer;
  v_ft integer;
  v_next timestamptz;
BEGIN
  IF p_uid IS NULL OR p_derived IS NULL OR pg_catalog.octet_length(p_derived) <> 32 THEN
    RAISE EXCEPTION 'partner_pin_attempt: a user and a 32-byte derived key are required' USING ERRCODE = '22023';
  END IF;
  SELECT p.verifier, p.failed_count, p.failed_today, p.failed_day, p.next_attempt_at, p.locked_at, p.must_change INTO v_p
  FROM app.partner_pin p WHERE p.user_id = p_uid FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unset'::text, 0, false;
    RETURN;
  END IF;
  IF v_p.locked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'locked'::text, 0, false;
    RETURN;
  END IF;
  IF v_p.must_change THEN
    RETURN QUERY SELECT 'must_change'::text, 0, false;
    RETURN;
  END IF;
  IF v_p.next_attempt_at IS NOT NULL AND v_p.next_attempt_at > v_now THEN
    RETURN QUERY SELECT 'retry_after'::text, pg_catalog.ceil(pg_catalog.date_part('epoch', v_p.next_attempt_at - v_now))::integer, false;
    RETURN;
  END IF;
  SELECT c.o_match, c.o_verifier, c.o_pepper_kid INTO v_match, v_ver, v_kid
  FROM private.partner_pin_core(p_uid, p_derived, v_p.verifier) c;
  IF v_match THEN
    -- success: clear consecutive failures; lazy-rewrap when the match was under previous
    UPDATE app.partner_pin p
    SET failed_count = 0,
        next_attempt_at = NULL,
        last_ok_at = v_now,
        verifier = CASE WHEN p.verifier IS DISTINCT FROM v_ver THEN v_ver ELSE p.verifier END,
        pepper_kid = CASE WHEN p.verifier IS DISTINCT FROM v_ver THEN v_kid ELSE p.pepper_kid END
    WHERE p.user_id = p_uid;
    RETURN QUERY SELECT 'ok'::text, 0, false;
    RETURN;
  END IF;
  v_fc := v_p.failed_count + 1;
  v_ft := CASE WHEN v_p.failed_day IS DISTINCT FROM v_day THEN 0 ELSE v_p.failed_today END + 1;
  IF v_fc >= 5 OR v_ft >= 20 THEN
    UPDATE app.partner_pin p
    SET failed_count = LEAST(v_fc, 5), failed_today = LEAST(v_ft, 20), failed_day = v_day, last_failed_at = v_now, next_attempt_at = NULL, locked_at = v_now
    WHERE p.user_id = p_uid;
    RETURN QUERY SELECT 'locked'::text, 0, true;
    RETURN;
  END IF;
  v_next := CASE v_fc WHEN 3 THEN v_now + interval '30 seconds' WHEN 4 THEN v_now + interval '5 minutes' ELSE NULL END;
  UPDATE app.partner_pin p
  SET failed_count = v_fc, failed_today = v_ft, failed_day = v_day, last_failed_at = v_now, next_attempt_at = v_next
  WHERE p.user_id = p_uid;
  RETURN QUERY SELECT 'wrong'::text, CASE v_fc WHEN 3 THEN 30 WHEN 4 THEN 300 ELSE 0 END, false;
END
$$;

CREATE OR REPLACE FUNCTION private.partner_pin_set_apply(p_mode text, p_derived bytea, p_salt bytea, p_iterations integer, p_current bytea)
RETURNS TABLE (o_status text, o_retry_after integer, o_newly_locked boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_sid uuid := private.partner_binding_session();
  v_s record;
  v_p record;
  v_a record;
  v_ver bytea;
  v_kid text;
  v_n integer;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_pin_set_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  SELECT s.enrolment_until, s.otp_proof_until INTO v_s FROM app.partner_session s WHERE s.id = v_sid;
  IF NOT FOUND OR NOT ((v_s.enrolment_until IS NOT NULL AND v_s.enrolment_until > v_now) OR (v_s.otp_proof_until IS NOT NULL AND v_s.otp_proof_until > v_now)) THEN
    RAISE EXCEPTION 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof' USING ERRCODE = '42501';
  END IF;
  IF p_mode IS NULL OR p_mode NOT IN ('set', 'change')
     OR p_derived IS NULL OR pg_catalog.octet_length(p_derived) <> 32
     OR p_salt IS NULL OR pg_catalog.octet_length(p_salt) <> 16
     OR p_iterations IS NULL OR p_iterations NOT BETWEEN 210000 AND 1000000
     OR (p_mode = 'change' AND (p_current IS NULL OR pg_catalog.octet_length(p_current) <> 32)) THEN
    RAISE EXCEPTION 'partner_pin_set_apply: a mode (set or change), a 32-byte derived key, a 16-byte salt, 210000 to 1000000 iterations (and, for a change, the 32-byte current key) are required' USING ERRCODE = '22023';
  END IF;
  SELECT c.o_verifier, c.o_pepper_kid INTO v_ver, v_kid FROM private.partner_pin_core(v_uid, p_derived, NULL) c;

  IF p_mode = 'set' THEN
    INSERT INTO app.partner_pin (user_id, salt, iterations, pepper_kid, verifier, set_at, created_at)
    VALUES (v_uid, p_salt, p_iterations, v_kid, v_ver, v_now, v_now)
    ON CONFLICT (user_id) DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n = 1 THEN
      RETURN QUERY SELECT 'ok'::text, 0, false;
      RETURN;
    END IF;
    SELECT p.locked_at, p.must_change INTO v_p FROM app.partner_pin p WHERE p.user_id = v_uid FOR UPDATE;
    IF v_p.locked_at IS NOT NULL THEN
      RETURN QUERY SELECT 'locked'::text, 0, false;
      RETURN;
    END IF;
    IF NOT v_p.must_change THEN
      RETURN QUERY SELECT 'already_set'::text, 0, false;
      RETURN;
    END IF;
  ELSE
    PERFORM 1 FROM app.partner_pin p WHERE p.user_id = v_uid;
    IF NOT FOUND THEN
      RETURN QUERY SELECT 'no_pin'::text, 0, false;
      RETURN;
    END IF;
    SELECT a.o_status, a.o_retry_after, a.o_newly_locked INTO v_a FROM private.partner_pin_attempt(v_uid, p_current) a;
    IF v_a.o_status IS DISTINCT FROM 'ok' THEN
      RETURN QUERY SELECT v_a.o_status, v_a.o_retry_after, v_a.o_newly_locked;
      RETURN;
    END IF;
  END IF;
  UPDATE app.partner_pin p
  SET salt = p_salt, iterations = p_iterations, pepper_kid = v_kid, verifier = v_ver, must_change = false, failed_count = 0, next_attempt_at = NULL,
      failed_today = CASE WHEN p_mode = 'set' THEN 0 ELSE p.failed_today END, set_at = v_now
  WHERE p.user_id = v_uid;
  RETURN QUERY SELECT 'ok'::text, 0, false;
END
$$;

COMMENT ON FUNCTION private.partner_pin_attempt(uuid, bytea) IS
  '0052/0087 (§77). Owned by partner_pin_verifier; ONE attempt: lock, backoff, dual-pepper compare via partner_pin_core, counters; on previous-pepper match rewrites verifier + pepper_kid under current. Every outcome a returned status. EXECUTE for nobody (same-owner verify/change call it).';
COMMENT ON FUNCTION private.partner_pin_set_apply(text, bytea, bytea, integer, bytea) IS
  '0052/0087 (§77). Owned by partner_pin_verifier. Sets or changes the bound person''s PIN only inside an enrolment window or after an email proof; stores pepper_kid of the current Vault pepper. EXECUTE for private_definer only.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_pin_verifier;
REVOKE partner_pin_verifier FROM CURRENT_USER;

COMMENT ON TABLE app.partner_pin IS
  '0052/0087 (design 5.1, 6.3, §77). One row per person: PBKDF2 inputs, HMAC(Vault pepper, label || user || derived) verifier, pepper_kid of the pepper that produced it, and failure / lockout state. After a non-compromise pepper rotate, a successful attempt under the previous pepper lazy-rewraps verifier + pepper_kid. FORCE RLS; no client, edge or service_role privilege.';

COMMENT ON COLUMN app.partner_pin.pepper_kid IS
  '0052/0087. Which partner_pin pepper generation produced verifier: ''v1'' before the first non-compromise rotate, else app.partner_pin_pepper_epoch.pepper_kid. Updated on set/change and on lazy rewrap.';

-- ============================================================================
-- 5. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0087 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_pin_pepper_rotate', 'p_mode text', false, false, false, false, false, false, false,
   '0087 (§77): owner/SQL-editor only; partner PIN pepper rotation; no edge/client EXECUTE; statuses ok|previous_exists|no_pepper|previous_absent|too_early')
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
SET note = '0052/0087 (§77): ONLY reader of Vault partner_pin_pepper (+ previous while epoch exists); HMAC under current as o_verifier + o_pepper_kid + o_match (current|previous); EXECUTE for partner_pin_verifier and owner private_definer; pepper never returned'
WHERE schema_name = 'private' AND function_name = 'partner_pin_core'
  AND identity_args = 'p_uid uuid, p_derived bytea, p_stored bytea';

UPDATE private.function_inventory
SET note = '0052/0087 (§77): owned by partner_pin_verifier; ONE attempt: locks row, dual-pepper compare, counters; lazy-rewrap on previous match; EXECUTE for nobody'
WHERE schema_name = 'private' AND function_name = 'partner_pin_attempt'
  AND identity_args = 'p_uid uuid, p_derived bytea';

UPDATE private.function_inventory
SET note = '0052/0087 (§77): owned by partner_pin_verifier; set/change under enrolment or email proof; stores current pepper_kid; EXECUTE for private_definer only'
WHERE schema_name = 'private' AND function_name = 'partner_pin_set_apply'
  AND identity_args = 'p_mode text, p_derived bytea, p_salt bytea, p_iterations integer, p_current bytea';

DROP POLICY current_user_edit_function_inventory_0087 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0087 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_pin_pepper_epoch', 'pd_partner_pin_pepper_epoch_select', 'SELECT', true,
   '0087: private.partner_pin_core / partner_pin_pepper_rotate read WHEN the current pepper took effect and its kid; no personal data; USING (true)',
   'private_definer'),
  ('app', 'partner_pin_pepper_epoch', 'pd_partner_pin_pepper_epoch_insert', 'INSERT', true,
   '0087: private.partner_pin_pepper_rotate (non_compromise) writes effective_from + pepper_kid; no personal data; WITH CHECK (true)',
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
  AND al.policy_name IN ('pd_partner_pin_pepper_epoch_select', 'pd_partner_pin_pepper_epoch_insert');
DROP POLICY current_user_seed_definer_policy_allowlist_0087 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 6. DO asserts
-- ============================================================================
DO $assert_0087$
DECLARE
  v_n int;
BEGIN
  IF to_regprocedure('vault.create_secret(text, text, text, uuid)') IS NULL
     OR to_regprocedure('vault.update_secret(uuid, text, text, text, uuid)') IS NULL THEN
    RAISE EXCEPTION '0087: vault.create_secret / vault.update_secret are required (fail closed)';
  END IF;
  IF NOT has_function_privilege('private_definer', 'vault.create_secret(text, text, text, uuid)', 'EXECUTE')
     OR NOT has_function_privilege('private_definer', 'vault.update_secret(uuid, text, text, text, uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0087: private_definer must EXECUTE vault.create_secret / vault.update_secret';
  END IF;
  IF NOT has_table_privilege('private_definer', 'app.partner_pin_pepper_epoch', 'SELECT')
     OR NOT has_table_privilege('private_definer', 'app.partner_pin_pepper_epoch', 'INSERT') THEN
    RAISE EXCEPTION '0087: private_definer must SELECT/INSERT app.partner_pin_pepper_epoch';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_pin_pepper_rotate'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0087: partner_pin_pepper_rotate must be SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
  IF has_function_privilege('anon', 'private.partner_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_actor', 'private.partner_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.partner_pin_pepper_rotate(text)', 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'private.partner_pin_pepper_rotate(text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0087: partner_pin_pepper_rotate must not be EXECUTEable by client / edge / service_role';
  END IF;
  -- core still exactly pin-verifier + owner ACL; OUT columns include o_pepper_kid
  IF (SELECT p.pronargs FROM pg_proc p WHERE p.oid = 'private.partner_pin_core(uuid, bytea, bytea)'::regprocedure) <> 3 THEN
    RAISE EXCEPTION '0087: partner_pin_core must keep three IN args (uuid, bytea, bytea)';
  END IF;
  IF NOT has_function_privilege('partner_pin_verifier', 'private.partner_pin_core(uuid, bytea, bytea)', 'EXECUTE') THEN
    RAISE EXCEPTION '0087: partner_pin_verifier must EXECUTE partner_pin_core after DROP/CREATE';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_pin_core'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0087: partner_pin_core must remain SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
END
$assert_0087$;
