-- 0096_partner_org_revoke_all_alarm.sql
--
-- P5 §101: operator alert on partner org revoke-all (design §21.4 /
-- §100.3 "related membership events"; the stolen-iPad button). Until
-- now partner_org_sessions_revoke_for_partner wrote audit_log only;
-- admins listing partner_auth_alarm never saw a panic revoke. Closes
-- that leftover: kind org_revoke_all on app.partner_auth_alarm, raised
-- from the wrapper on status ok only (one row per org id per minute).
-- not_found stays quiet.
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with org_revoke_all.
--   2. Row CHECK: org_revoke_all → credential_id IS NULL AND bucket_key
--      is org id text (uuid shape, same as member_recover / pin_reset).
--   3. INSERT + SELECT policies for partner-bound private_definer.
--   4. CREATE OR REPLACE partner_org_sessions_revoke_for_partner: after
--      audit on ok, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"org":"<uuid>","status":"ok"} only (no token / session dump).
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); member-revoke
-- alarm; OCR / aHash / UI flag flips / CAMERA. Nothing from 0001–0095
-- is edited.

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
    'org_revoke_all'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096. Arbiter key with (kind, minute_bucket): mint/credential_add = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover = subject uid; org_revoke_all = org id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for org_revoke_all
-- ============================================================================
CREATE POLICY pd_partner_org_revoke_all_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'org_revoke_all'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_org_revoke_all_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'org_revoke_all'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Revoke-all wrapper raises the alarm on ok (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_org_sessions_revoke_for_partner(p_org_id uuid, p_created_after timestamptz)
RETURNS TABLE (o_status text, o_sessions integer, o_credentials integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind app.partner_org_kind;
  v_fac text;
  v_sessions integer;
  v_creds integer := 0;
  v_m record;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_org_id IS NULL OR (p_created_after IS NOT NULL AND p_created_after > pg_catalog.clock_timestamp() + interval '1 minute') THEN
    RAISE EXCEPTION 'partner_org_sessions_revoke_for_partner: an org (and, when given, a time that is not in the future) is required' USING ERRCODE = '22023';
  END IF;
  SELECT o.kind INTO v_kind FROM app.partner_org o WHERE o.id = p_org_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, 0, 0;
    RETURN;
  END IF;
  IF NOT private.is_admin(v_uid) THEN
    IF v_kind <> 'facility' THEN
      RAISE EXCEPTION 'partner_org_sessions_revoke_for_partner: no scope' USING ERRCODE = '42501';
    END IF;
    SELECT s.facility_id INTO v_fac FROM app.partner_scope s WHERE s.org_id = p_org_id AND s.facility_id IS NOT NULL LIMIT 1;
    IF v_fac IS NULL OR NOT private.has_facility_scope(v_uid, v_fac, ARRAY['manager', 'operator']::app.partner_role[]) THEN
      RAISE EXCEPTION 'partner_org_sessions_revoke_for_partner: no scope' USING ERRCODE = '42501';
    END IF;
  END IF;
  IF p_created_after IS NOT NULL THEN
    FOR v_m IN SELECT m.user_id FROM app.partner_member m WHERE m.org_id = p_org_id AND m.revoked_at IS NULL AND m.user_id <> v_uid LOOP
      IF private.partner_reach_covers(v_uid, v_m.user_id) THEN
        v_creds := v_creds + private.partner_credentials_revoke_user(v_m.user_id, v_uid, 'panic_revoke', p_created_after);
      END IF;
    END LOOP;
  END IF;
  v_sessions := private.partner_sessions_revoke('org', p_org_id, 'panic_revoke_all');
  PERFORM private.partner_audit_write('partner.org.revoke_all', 'app.partner_org', p_org_id::text,
    pg_catalog.jsonb_build_object('sessions', v_sessions, 'credentials', v_creds));
  v_detail := pg_catalog.jsonb_build_object('org', p_org_id::text, 'status', 'ok');
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'org_revoke_all',
    NULL,
    p_org_id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN QUERY SELECT 'ok'::text, v_sessions, v_creds;
END
$$;

COMMENT ON FUNCTION private.partner_org_sessions_revoke_for_partner(uuid, timestamptz) IS
  '0054/0096 (§101). edge_partner only; POST orgs/sessions/revoke-all: class A2; stolen-iPad button; audit partner.org.revoke_all; raises partner_auth_alarm kind org_revoke_all on ok (one per org id per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), and org revoke-all operator signal (org_revoke_all). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0096 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0054/0096 (§101): edge_partner only; POST orgs/sessions/revoke-all: class A2; raises org_revoke_all alarm on ok'
WHERE schema_name = 'private'
  AND function_name = 'partner_org_sessions_revoke_for_partner'
  AND identity_args = 'p_org_id uuid, p_created_after timestamp with time zone';

DROP POLICY current_user_edit_function_inventory_0096 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0096 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_org_revoke_all_alarm_insert', 'INSERT', true,
   '0096 (§101): partner-bound private_definer inserts org_revoke_all for org id', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_org_revoke_all_alarm_select', 'SELECT', true,
   '0096 (§101): partner-bound private_definer reads org_revoke_all rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_org_revoke_all_alarm_insert', 'pd_partner_org_revoke_all_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0096 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0096$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_org_revoke_all_alarm_insert', 'pd_partner_org_revoke_all_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0096: expected partner-bound org_revoke_all INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%org_revoke_all%' THEN
    RAISE EXCEPTION '0096: partner_auth_alarm kind CHECK must include org_revoke_all';
  END IF;
  SELECT pg_get_functiondef('private.partner_org_sessions_revoke_for_partner(uuid, timestamptz)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%org_revoke_all%' THEN
    RAISE EXCEPTION '0096: partner_org_sessions_revoke_for_partner must raise org_revoke_all alarm';
  END IF;
END
$assert_0096$;
