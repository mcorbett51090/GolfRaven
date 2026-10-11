-- 0107_partner_totp_enrol_alarm.sql
--
-- P5 §113: operator alert on partner TOTP enrol (design §112.3 leftover
-- after pin_set; operator/admin enrolment ceremony step after
-- register_first). Until now partner_totp_enrol_for_partner wrote
-- audit_log partner.totp.enrol only; admins listing partner_auth_alarm
-- never saw a TOTP enrolment. Closes that leftover: kind totp_enrol on
-- app.partner_auth_alarm, raised from the enrol wrapper on ok only (one
-- row per subject uid per minute). already_confirmed stays quiet.
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with totp_enrol.
--   2. Row CHECK: totp_enrol → credential_id IS NULL AND bucket_key is
--      subject uid text (same shape as totp_reset / totp_locked).
--   3. INSERT + SELECT policies so a PARTNER-bound private_definer can
--      write/read totp_enrol rows.
--   4. CREATE OR REPLACE partner_totp_enrol_for_partner: after audit on
--      ok, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"subject","status","seed_version"} only (never the seed).
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- totp_confirm success alarm; OCR / aHash / UI flag flips / CAMERA.
-- Nothing from 0001–0106 is edited.

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
    'invite_create',
    'invite_accept',
    'enrolment_accept',
    'totp_locked',
    'credential_register',
    'pin_set',
    'totp_enrol'
  ));

ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_bucket_shape_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_bucket_shape_check CHECK (
    (
      kind IN ('signature_invalid', 'counter_regression', 'credential_add', 'credential_revoke', 'credential_register')
      AND credential_id IS NOT NULL
      AND bucket_key = credential_id::text
    )
    OR (
      kind IN ('rate_options_ip', 'rate_options_global', 'rate_verify_ip')
      AND credential_id IS NULL
      AND length(bucket_key) BETWEEN 1 AND 128
    )
    OR (
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke', 'enrolment_issue', 'invite_create', 'invite_accept', 'enrolment_accept', 'totp_locked', 'pin_set', 'totp_enrol')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105/0106/0107. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke/credential_register = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke / enrolment_issue / totp_locked / pin_set / totp_enrol = subject uid; org_revoke_all = org id; invite_revoke / invite_create / invite_accept = invite id; enrolment_accept = enrolment token id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for totp_enrol
-- ============================================================================
CREATE POLICY pd_partner_totp_enrol_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'totp_enrol'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_totp_enrol_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'totp_enrol'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Enrol wrapper raises the alarm on ok
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_totp_enrol_for_partner()
RETURNS TABLE (o_status text, o_seed bytea, o_seed_version integer, o_issuer text, o_period integer, o_digits integer, o_algo text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0_ENROL');
  SELECT a.o_status, a.o_seed, a.o_seed_version, a.o_issuer, a.o_period, a.o_digits, a.o_algo INTO v_r
  FROM private.partner_totp_enrol_apply() a;
  IF v_r.o_status = 'ok' THEN
    UPDATE app.partner_session s SET otp_proof_until = NULL
    WHERE s.id = private.partner_binding_session() AND s.otp_proof_until IS NOT NULL;
    PERFORM private.partner_audit_write('partner.totp.enrol', 'app.partner_totp', v_uid::text,
      pg_catalog.jsonb_build_object('seed_version', v_r.o_seed_version));
    v_detail := pg_catalog.jsonb_build_object(
      'subject', v_uid::text,
      'status', 'ok',
      'seed_version', v_r.o_seed_version
    );
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'totp_enrol',
      NULL,
      v_uid::text,
      pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
      v_detail
    )
    ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_seed, v_r.o_seed_version, v_r.o_issuer, v_r.o_period, v_r.o_digits, v_r.o_algo;
END
$$;

COMMENT ON FUNCTION private.partner_totp_enrol_for_partner() IS
  '0053/0107 (§113). edge_partner only; POST totp/enrol: class A0_ENROL; returns otpauth params on ok; raises partner_auth_alarm kind totp_enrol on ok (one per subject uid per minute; never the seed in detail).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105/0106/0107. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), invite-revoke (invite_revoke), admin enrolment-issue (enrolment_issue), invite-create (invite_create), invite-accept (invite_accept), enrolment-accept (enrolment_accept), TOTP-lock (totp_locked), first-credential register (credential_register), PIN-set (pin_set), and TOTP-enrol operator signal (totp_enrol). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0107 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0053/0107 (§113): edge_partner only; POST totp/enrol: class A0_ENROL; raises totp_enrol alarm on ok'
WHERE schema_name = 'private'
  AND function_name = 'partner_totp_enrol_for_partner'
  AND identity_args = '';

DROP POLICY current_user_edit_function_inventory_0107 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0107 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_totp_enrol_alarm_insert', 'INSERT', true,
   '0107 (§113): partner-bound private_definer inserts totp_enrol for subject uid', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_totp_enrol_alarm_select', 'SELECT', true,
   '0107 (§113): partner-bound private_definer reads totp_enrol rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_totp_enrol_alarm_insert', 'pd_partner_totp_enrol_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0107 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0107$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_totp_enrol_alarm_insert', 'pd_partner_totp_enrol_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0107: expected partner-bound totp_enrol INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%totp_enrol%' THEN
    RAISE EXCEPTION '0107: partner_auth_alarm kind CHECK must include totp_enrol';
  END IF;
  SELECT pg_get_functiondef('private.partner_totp_enrol_for_partner()'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%totp_enrol%' THEN
    RAISE EXCEPTION '0107: partner_totp_enrol_for_partner must raise totp_enrol alarm';
  END IF;
END
$assert_0107$;
