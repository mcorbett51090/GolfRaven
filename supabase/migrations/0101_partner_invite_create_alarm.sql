-- 0101_partner_invite_create_alarm.sql
--
-- P5 §107: operator alert on partner invite create (design §106.3 /
-- §21.4 invite-event trail after invite_revoke). Until now
-- partner_invite_create_for_partner wrote audit_log only; admins
-- listing partner_auth_alarm never saw an invite create. Closes that
-- leftover: kind invite_create on app.partner_auth_alarm, raised from
-- the wrapper on status ok only (one row per invite id per minute).
-- already_member stays quiet; exception paths stay quiet.
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with invite_create.
--   2. Row CHECK: invite_create → credential_id IS NULL AND bucket_key
--      is invite id text (same uuid shape as invite_revoke).
--   3. INSERT + SELECT policies for partner-bound private_definer.
--   4. CREATE OR REPLACE partner_invite_create_for_partner: after audit
--      on ok, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"invite":"<id>","org":"<org>","role":"<role>","status":"ok"} only
--      (never the token hash or invitee email).
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- OCR / aHash / UI flag flips / CAMERA. Nothing from 0001–0100 is edited.

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
    'enrolment_issue',
    'invite_create'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke', 'enrolment_issue', 'invite_create')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke / enrolment_issue = subject uid; org_revoke_all = org id; invite_revoke / invite_create = invite id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for invite_create
-- ============================================================================
CREATE POLICY pd_partner_invite_create_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'invite_create'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_invite_create_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'invite_create'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Invite-create wrapper raises the alarm on ok (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_invite_create_for_partner(p_org_id uuid, p_role app.partner_role, p_invitee_email text, p_token_hash text)
RETURNS TABLE (o_status text, o_invite_id uuid, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_email text;
  v_kind app.partner_org_kind;
  v_fac text;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_exp timestamptz;
  v_id uuid;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_role IS NULL OR p_role NOT IN ('staff', 'manager', 'operator') THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: a staff, manager or operator role is required (sponsor invites are disabled)' USING ERRCODE = '22023';
  END IF;
  IF p_org_id IS NULL OR p_invitee_email IS NULL OR p_token_hash IS NULL OR pg_catalog.char_length(p_token_hash) <> 64 OR p_token_hash !~ '^[0-9a-f]{64}' THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: an org, an invitee email and a 64-hex token hash are required' USING ERRCODE = '22023';
  END IF;
  v_email := pg_catalog.lower(pg_catalog.btrim(p_invitee_email));
  IF pg_catalog.char_length(v_email) NOT BETWEEN 3 AND 254 OR v_email ~ '[[:space:]]' OR v_email !~ '^[^@]+@[^@]+' THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: the invitee email is malformed' USING ERRCODE = '22023';
  END IF;
  SELECT o.kind INTO v_kind FROM app.partner_org o WHERE o.id = p_org_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: no scope' USING ERRCODE = '42501';
  END IF;
  IF p_role = 'operator' THEN
    IF v_kind <> 'operator' OR NOT private.is_admin(v_uid) THEN
      RAISE EXCEPTION 'partner_invite_create_for_partner: only an admin invites an operator, into an operator org' USING ERRCODE = '42501';
    END IF;
  ELSE
    IF v_kind <> 'facility' THEN
      RAISE EXCEPTION 'partner_invite_create_for_partner: no scope' USING ERRCODE = '42501';
    END IF;
    SELECT s.facility_id INTO v_fac FROM app.partner_scope s WHERE s.org_id = p_org_id AND s.facility_id IS NOT NULL LIMIT 1;
    IF v_fac IS NULL
       OR NOT private.has_facility_scope(v_uid, v_fac,
            CASE WHEN p_role = 'staff' THEN ARRAY['manager', 'operator'] ELSE ARRAY['operator'] END::app.partner_role[]) THEN
      RAISE EXCEPTION 'partner_invite_create_for_partner: the grant is not a subset of the inviter reach' USING ERRCODE = '42501';
    END IF;
  END IF;
  IF EXISTS (SELECT 1 FROM app.partner_member m JOIN auth.users u ON u.id = m.user_id
             WHERE m.org_id = p_org_id AND m.revoked_at IS NULL AND pg_catalog.lower(pg_catalog.btrim(u.email)) = v_email) THEN
    RETURN QUERY SELECT 'already_member'::text, NULL::uuid, NULL::timestamptz;
    RETURN;
  END IF;
  v_exp := v_now + interval '72 hours';
  INSERT INTO app.partner_invite (org_id, role, facility_id, trail_id, invited_by, invitee_email, token_hash, expires_at, created_at)
  VALUES (p_org_id, p_role, v_fac, NULL, v_uid, v_email, p_token_hash, v_exp, v_now)
  RETURNING id INTO v_id;
  PERFORM private.partner_audit_write('partner.invite.create', 'app.partner_invite', v_id::text,
    pg_catalog.jsonb_build_object('org', p_org_id, 'role', p_role));
  v_detail := pg_catalog.jsonb_build_object('invite', v_id::text, 'org', p_org_id::text, 'role', p_role::text, 'status', 'ok');
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'invite_create',
    NULL,
    v_id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN QUERY SELECT 'ok'::text, v_id, v_exp;
END
$$;

COMMENT ON FUNCTION private.partner_invite_create_for_partner(uuid, app.partner_role, text, text) IS
  '0054/0101 (§107). edge_partner only; POST invites: class A2; manager/operator in scope; audit partner.invite.create; raises partner_auth_alarm kind invite_create on ok (one per invite id per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), invite-revoke (invite_revoke), admin enrolment-issue (enrolment_issue), and invite-create operator signal (invite_create). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0101 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0054/0101 (§107): edge_partner only; POST invites: class A2; raises invite_create alarm on ok'
WHERE schema_name = 'private'
  AND function_name = 'partner_invite_create_for_partner'
  AND identity_args = 'p_org_id uuid, p_role app.partner_role, p_invitee_email text, p_token_hash text';

DROP POLICY current_user_edit_function_inventory_0101 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0101 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_invite_create_alarm_insert', 'INSERT', true,
   '0101 (§107): partner-bound private_definer inserts invite_create for invite id', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_invite_create_alarm_select', 'SELECT', true,
   '0101 (§107): partner-bound private_definer reads invite_create rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_invite_create_alarm_insert', 'pd_partner_invite_create_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0101 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0101$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_invite_create_alarm_insert', 'pd_partner_invite_create_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0101: expected partner-bound invite_create INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%invite_create%' THEN
    RAISE EXCEPTION '0101: partner_auth_alarm kind CHECK must include invite_create';
  END IF;
  SELECT pg_get_functiondef('private.partner_invite_create_for_partner(uuid, app.partner_role, text, text)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%invite_create%' THEN
    RAISE EXCEPTION '0101: partner_invite_create_for_partner must raise invite_create alarm';
  END IF;
END
$assert_0101$;
