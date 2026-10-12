-- 0099_partner_invite_revoke_alarm.sql
--
-- P5 §105: operator alert on partner invite revoke (design §104.3 /
-- §21.4 invite-event trail). Until now partner_invite_revoke_for_partner
-- wrote audit_log only; admins listing partner_auth_alarm never saw an
-- invite revoke. Closes that leftover: kind invite_revoke on
-- app.partner_auth_alarm, raised from the wrapper on status ok only
-- (one row per invite id per minute). not_found / already_accepted /
-- already_revoked stay quiet.
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with invite_revoke.
--   2. Row CHECK: invite_revoke → credential_id IS NULL AND bucket_key
--      is invite id text (uuid shape, same as org_revoke_all).
--   3. INSERT + SELECT policies for partner-bound private_definer.
--   4. CREATE OR REPLACE partner_invite_revoke_for_partner: after audit
--      on ok, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"invite":"<id>","org":"<org>","status":"ok"} only.
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- OCR / aHash / UI flag flips / CAMERA. Nothing from 0001–0098 is edited.

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
    'invite_revoke'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke = subject uid; org_revoke_all = org id; invite_revoke = invite id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for invite_revoke
-- ============================================================================
CREATE POLICY pd_partner_invite_revoke_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'invite_revoke'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_invite_revoke_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'invite_revoke'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Invite-revoke wrapper raises the alarm on ok (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_invite_revoke_for_partner(p_invite_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_i record;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_invite_id IS NULL THEN
    RAISE EXCEPTION 'partner_invite_revoke_for_partner: an invite id is required' USING ERRCODE = '22023';
  END IF;
  SELECT i.accepted_at, i.revoked_at, i.org_id INTO v_i FROM app.partner_invite i WHERE i.id = p_invite_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_i.accepted_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_accepted'::text;
    RETURN;
  END IF;
  IF v_i.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_revoked'::text;
    RETURN;
  END IF;
  UPDATE app.partner_invite i SET revoked_at = pg_catalog.clock_timestamp(), revoked_by = v_uid WHERE i.id = p_invite_id AND i.accepted_at IS NULL AND i.revoked_at IS NULL;
  PERFORM private.partner_audit_write('partner.invite.revoke', 'app.partner_invite', p_invite_id::text, '{}'::jsonb);
  v_detail := pg_catalog.jsonb_build_object('invite', p_invite_id::text, 'org', v_i.org_id::text, 'status', 'ok');
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'invite_revoke',
    NULL,
    p_invite_id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN QUERY SELECT 'ok'::text;
END
$$;

COMMENT ON FUNCTION private.partner_invite_revoke_for_partner(uuid) IS
  '0054/0099 (§105). edge_partner only; DELETE invites/{id}: class A2; manager/operator in scope; audit partner.invite.revoke; raises partner_auth_alarm kind invite_revoke on ok (one per invite id per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), and invite-revoke operator signal (invite_revoke). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0099 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0054/0099 (§105): edge_partner only; DELETE invites/{id}: class A2; raises invite_revoke alarm on ok'
WHERE schema_name = 'private'
  AND function_name = 'partner_invite_revoke_for_partner'
  AND identity_args = 'p_invite_id uuid';

DROP POLICY current_user_edit_function_inventory_0099 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0099 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_invite_revoke_alarm_insert', 'INSERT', true,
   '0099 (§105): partner-bound private_definer inserts invite_revoke for invite id', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_invite_revoke_alarm_select', 'SELECT', true,
   '0099 (§105): partner-bound private_definer reads invite_revoke rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_invite_revoke_alarm_insert', 'pd_partner_invite_revoke_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0099 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0099$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_invite_revoke_alarm_insert', 'pd_partner_invite_revoke_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0099: expected partner-bound invite_revoke INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%invite_revoke%' THEN
    RAISE EXCEPTION '0099: partner_auth_alarm kind CHECK must include invite_revoke';
  END IF;
  SELECT pg_get_functiondef('private.partner_invite_revoke_for_partner(uuid)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%invite_revoke%' THEN
    RAISE EXCEPTION '0099: partner_invite_revoke_for_partner must raise invite_revoke alarm';
  END IF;
END
$assert_0099$;
