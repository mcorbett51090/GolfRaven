-- 0100_partner_enrolment_issue_alarm.sql
--
-- P5 §106: operator alert on admin enrolment-token issue (design §105.3 /
-- §21.4 admin-bootstrap trail). Until now
-- partner_admin_enrolment_issue_for_partner wrote audit_log only; admins
-- listing partner_auth_alarm never saw an enrolment issue. Closes that
-- leftover: kind enrolment_issue on app.partner_auth_alarm, raised from
-- the wrapper on status ok only (one row per target uid per minute).
-- Exception paths (42501 / 22023) stay quiet (no row).
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with enrolment_issue.
--   2. Row CHECK: enrolment_issue → credential_id IS NULL AND bucket_key
--      is target uid text (same uuid shape as member_recover).
--   3. INSERT + SELECT policies for partner-bound private_definer.
--   4. CREATE OR REPLACE partner_admin_enrolment_issue_for_partner: after
--      audit on ok, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"subject":"<target>","status":"ok"} only (no token hash).
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- OCR / aHash / UI flag flips / CAMERA. Nothing from 0001–0099 is edited.

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
    'totp_reset',
    'pin_locked',
    'pin_reset',
    'member_recover',
    'org_revoke_all',
    'member_revoke',
    'credential_revoke',
    'invite_revoke',
    'enrolment_issue'
  ));

ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_bucket_shape_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_bucket_shape_check CHECK (
    (
      kind IN ('signature_invalid', 'counter_regression', 'credential_add', 'credential_revoke')
      AND credential_id IS NOT NULL
      AND bucket_key = credential_id::text
    )
    OR (
      kind IN ('rate_options_ip', 'rate_options_global', 'rate_verify_ip')
      AND credential_id IS NULL
      AND length(bucket_key) BETWEEN 1 AND 128
    )
    OR (
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke', 'enrolment_issue')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke / enrolment_issue = subject uid; org_revoke_all = org id; invite_revoke = invite id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for enrolment_issue
-- ============================================================================
CREATE POLICY pd_partner_enrolment_issue_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'enrolment_issue'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_enrolment_issue_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'enrolment_issue'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Admin enrolment-issue wrapper raises the alarm on ok (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_admin_enrolment_issue_for_partner(p_user_id uuid, p_token_hash text)
RETURNS TABLE (o_status text, o_token_id uuid, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_id uuid;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_exp timestamptz;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_admin_enrolment_issue_for_partner: only an admin may issue an admin enrolment token' USING ERRCODE = '42501';
  END IF;
  IF p_user_id IS NULL OR p_user_id = v_uid OR p_token_hash IS NULL
     OR pg_catalog.char_length(p_token_hash) <> 64
     OR p_token_hash !~ '^[0-9a-f]{64}' THEN
    RAISE EXCEPTION 'partner_admin_enrolment_issue_for_partner: a different target user and a 64-hex token hash are required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.is_admin(p_user_id) THEN
    RAISE EXCEPTION 'partner_admin_enrolment_issue_for_partner: the target must be in app.admin_user' USING ERRCODE = '42501';
  END IF;
  v_exp := v_now + interval '24 hours';
  INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at)
  VALUES (p_user_id, 'admin', v_uid, p_token_hash, v_now, v_exp)
  RETURNING id INTO v_id;
  PERFORM private.partner_audit_write('partner.admin.enrolment_issue', 'app.partner_enrolment_token', v_id::text,
    pg_catalog.jsonb_build_object('target', p_user_id));
  v_detail := pg_catalog.jsonb_build_object('subject', p_user_id::text, 'status', 'ok');
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'enrolment_issue',
    NULL,
    p_user_id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN QUERY SELECT 'ok'::text, v_id, v_exp;
END
$$;

COMMENT ON FUNCTION private.partner_admin_enrolment_issue_for_partner(uuid, text) IS
  '0053/0054/0100 (§106). edge_partner only; POST admin/enrolments: class A3; admin issues an admin enrolment token for a different admin; audit partner.admin.enrolment_issue; raises partner_auth_alarm kind enrolment_issue on ok (one per target uid per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), invite-revoke (invite_revoke), and admin enrolment-issue operator signal (enrolment_issue). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0100 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0053/0054/0100 (§106): edge_partner only; POST admin/enrolments: class A3; raises enrolment_issue alarm on ok'
WHERE schema_name = 'private'
  AND function_name = 'partner_admin_enrolment_issue_for_partner'
  AND identity_args = 'p_user_id uuid, p_token_hash text';

DROP POLICY current_user_edit_function_inventory_0100 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0100 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_enrolment_issue_alarm_insert', 'INSERT', true,
   '0100 (§106): partner-bound private_definer inserts enrolment_issue for target uid', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_enrolment_issue_alarm_select', 'SELECT', true,
   '0100 (§106): partner-bound private_definer reads enrolment_issue rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_enrolment_issue_alarm_insert', 'pd_partner_enrolment_issue_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0100 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0100$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_enrolment_issue_alarm_insert', 'pd_partner_enrolment_issue_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0100: expected partner-bound enrolment_issue INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%enrolment_issue%' THEN
    RAISE EXCEPTION '0100: partner_auth_alarm kind CHECK must include enrolment_issue';
  END IF;
  SELECT pg_get_functiondef('private.partner_admin_enrolment_issue_for_partner(uuid, text)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%enrolment_issue%' THEN
    RAISE EXCEPTION '0100: partner_admin_enrolment_issue_for_partner must raise enrolment_issue alarm';
  END IF;
END
$assert_0100$;
