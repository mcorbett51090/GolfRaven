-- 0092_partner_totp_reset_alarm.sql
--
-- P5 §95: operator alert on TOTP reset (design §1911 / §21.4 / §6.4).
-- Until now partner_totp_reset_for_partner wrote audit_log only; admins
-- listing partner_auth_alarm never saw a reset. Closes that leftover:
-- kind totp_reset on app.partner_auth_alarm, raised from the reset
-- wrapper (one row per target uid per minute).
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with totp_reset.
--   2. Row CHECK: totp_reset → credential_id IS NULL AND bucket_key is
--      target uid text (same shape as rate_member).
--   3. INSERT + SELECT policies so a PARTNER-bound private_definer can
--      write/read totp_reset rows (bucket_key is the TARGET, not the
--      actor — unlike rate_member).
--   4. CREATE OR REPLACE partner_totp_reset_for_partner: after audit,
--      INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"target":"<uuid>","status":"ok"|"unset"} only (no actor email).
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); OCR / aHash / UI
-- flag flips / CAMERA. Nothing from 0001–0091 is edited.

-- ============================================================================
-- 1. Kind + row CHECKs
-- ============================================================================
ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_kind_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_kind_check CHECK (kind IN (
    'signature_invalid',
    'counter_regression',
    'rate_options_ip',
    'rate_options_global',
    'rate_verify_ip',
    'rate_member',
    'credential_add',
    'totp_reset'
  ));

ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_bucket_shape_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_bucket_shape_check CHECK (
    (
      kind IN ('signature_invalid', 'counter_regression', 'credential_add')
      AND credential_id IS NOT NULL
      AND bucket_key = credential_id::text
    )
    OR (
      kind IN ('rate_options_ip', 'rate_options_global', 'rate_verify_ip')
      AND credential_id IS NULL
      AND length(bucket_key) BETWEEN 1 AND 128
    )
    OR (
      kind IN ('rate_member', 'totp_reset')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092. Arbiter key with (kind, minute_bucket): mint/credential_add = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member = binding uid; totp_reset = target uid. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for totp_reset
-- ============================================================================
CREATE POLICY pd_partner_totp_reset_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'totp_reset'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_totp_reset_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'totp_reset'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Reset wrapper raises the alarm (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_totp_reset_for_partner(p_target_uid uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_status text;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_target_uid IS NULL OR p_target_uid = v_uid THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: a different target user is required' USING ERRCODE = '22023';
  END IF;
  IF NOT (private.is_admin(p_target_uid)
          OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_target_uid AND m.revoked_at IS NULL AND m.role = 'operator')) THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: the target must be an operator or an admin' USING ERRCODE = '42501';
  END IF;
  IF NOT private.partner_reach_covers(v_uid, p_target_uid) THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: the reach rule does not cover this person' USING ERRCODE = '42501';
  END IF;
  v_status := private.partner_totp_reset_apply(p_target_uid);
  PERFORM private.partner_sessions_revoke('user', p_target_uid, 'totp_reset');
  PERFORM private.partner_audit_write('partner.totp.reset', 'app.partner_totp', p_target_uid::text,
    pg_catalog.jsonb_build_object('status', v_status));
  v_detail := pg_catalog.jsonb_build_object('target', p_target_uid::text, 'status', v_status);
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'totp_reset',
    NULL,
    p_target_uid::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN QUERY SELECT v_status;
END
$$;

COMMENT ON FUNCTION private.partner_totp_reset_for_partner(uuid) IS
  '0053/0054/0092 (§95). edge_partner only; POST members/totp-reset: class A3; reach rule; revokes target sessions; audit partner.totp.reset; raises partner_auth_alarm kind totp_reset (one per target uid per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), and TOTP-reset operator signal (totp_reset). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0092 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0053/0054/0092 (§95): edge_partner only; POST members/totp-reset: class A3; reach rule; revokes target sessions; raises totp_reset alarm'
WHERE schema_name = 'private'
  AND function_name = 'partner_totp_reset_for_partner'
  AND identity_args = 'p_target_uid uuid';

DROP POLICY current_user_edit_function_inventory_0092 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0092 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_totp_reset_alarm_insert', 'INSERT', true,
   '0092 (§95): partner-bound private_definer inserts totp_reset for target uid', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_totp_reset_alarm_select', 'SELECT', true,
   '0092 (§95): partner-bound private_definer reads totp_reset rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_totp_reset_alarm_insert', 'pd_partner_totp_reset_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0092 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0092$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_totp_reset_alarm_insert', 'pd_partner_totp_reset_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0092: expected partner-bound totp_reset INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%totp_reset%' THEN
    RAISE EXCEPTION '0092: partner_auth_alarm kind CHECK must include totp_reset';
  END IF;
  SELECT pg_get_functiondef('private.partner_totp_reset_for_partner(uuid)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%totp_reset%' THEN
    RAISE EXCEPTION '0092: partner_totp_reset_for_partner must raise totp_reset alarm';
  END IF;
END
$assert_0092$;
