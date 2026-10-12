-- 0098_partner_credential_revoke_alarm.sql
--
-- P5 §104: operator alert on partner credential revoke (design §103.3 /
-- §21.4 credential-event trail after credential_add). Until now
-- partner_credential_revoke_for_partner wrote audit_log only; admins
-- listing partner_auth_alarm never saw a credential revoke. Closes that
-- leftover: kind credential_revoke on app.partner_auth_alarm, raised from
-- the wrapper on status ok only (one row per credential id per minute).
-- not_found / already_revoked stay quiet.
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with credential_revoke.
--   2. Row CHECK: credential_revoke → credential_id IS NOT NULL AND
--      bucket_key = credential_id::text (same shape as credential_add).
--   3. INSERT + SELECT policies for partner-bound private_definer.
--   4. CREATE OR REPLACE partner_credential_revoke_for_partner: after audit
--      on ok, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"subject":"<owner>","own":bool,"status":"ok"} only.
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- OCR / aHash / UI flag flips / CAMERA. Nothing from 0001–0097 is edited.

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
    'credential_revoke'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke = subject uid; org_revoke_all = org id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for credential_revoke
-- ============================================================================
CREATE POLICY pd_partner_credential_revoke_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'credential_revoke'
    AND credential_id IS NOT NULL
    AND bucket_key = credential_id::text
  );

CREATE POLICY pd_partner_credential_revoke_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'credential_revoke'
    AND credential_id IS NOT NULL
    AND bucket_key = credential_id::text
  );

-- ============================================================================
-- 3. Revoke wrapper raises the alarm on ok (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_credential_revoke_for_partner(p_credential_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_c record;
  v_status text;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A2');
  IF p_credential_id IS NULL THEN
    RAISE EXCEPTION 'partner_credential_revoke_for_partner: a credential id is required' USING ERRCODE = '22023';
  END IF;
  SELECT c.user_id, c.revoked_at INTO v_c FROM app.partner_credential c WHERE c.id = p_credential_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_c.user_id <> v_uid AND NOT private.partner_reach_covers(v_uid, v_c.user_id) THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_c.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_revoked'::text;
    RETURN;
  END IF;
  v_status := private.partner_credential_revoke_apply(p_credential_id, v_uid, 'revoked');
  IF v_status = 'ok' THEN
    PERFORM private.partner_sessions_revoke('credential', p_credential_id, 'credential_revoked');
    PERFORM private.partner_audit_write('partner.credential.revoke', 'app.partner_credential', p_credential_id::text,
      pg_catalog.jsonb_build_object('owner', v_c.user_id, 'own', v_c.user_id = v_uid));
    v_detail := pg_catalog.jsonb_build_object('subject', v_c.user_id::text, 'own', v_c.user_id = v_uid, 'status', 'ok');
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'credential_revoke',
      p_credential_id,
      p_credential_id::text,
      pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
      v_detail
    )
    ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  END IF;
  RETURN QUERY SELECT v_status;
END
$$;

COMMENT ON FUNCTION private.partner_credential_revoke_for_partner(uuid) IS
  '0054/0098 (§104). edge_partner only; DELETE credentials/{id}: class A2; own or reach; audit partner.credential.revoke; raises partner_auth_alarm kind credential_revoke on ok (one per credential id per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), and credential-revoke operator signal (credential_revoke). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0098 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0054/0098 (§104): edge_partner only; DELETE credentials/{id}: class A2; own or reach; raises credential_revoke alarm on ok'
WHERE schema_name = 'private'
  AND function_name = 'partner_credential_revoke_for_partner'
  AND identity_args = 'p_credential_id uuid';

DROP POLICY current_user_edit_function_inventory_0098 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0098 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_credential_revoke_alarm_insert', 'INSERT', true,
   '0098 (§104): partner-bound private_definer inserts credential_revoke for credential id', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_credential_revoke_alarm_select', 'SELECT', true,
   '0098 (§104): partner-bound private_definer reads credential_revoke rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_credential_revoke_alarm_insert', 'pd_partner_credential_revoke_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0098 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0098$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_credential_revoke_alarm_insert', 'pd_partner_credential_revoke_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0098: expected partner-bound credential_revoke INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%credential_revoke%' THEN
    RAISE EXCEPTION '0098: partner_auth_alarm kind CHECK must include credential_revoke';
  END IF;
  SELECT pg_get_functiondef('private.partner_credential_revoke_for_partner(uuid)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%credential_revoke%' THEN
    RAISE EXCEPTION '0098: partner_credential_revoke_for_partner must raise credential_revoke alarm';
  END IF;
END
$assert_0098$;
