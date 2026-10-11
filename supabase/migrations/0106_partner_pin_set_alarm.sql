-- 0106_partner_pin_set_alarm.sql
--
-- P5 §112: operator alert on partner PIN set (design §111.3 leftover
-- after credential_register; next staff enrolment ceremony step after
-- register_first). Until now partner_pin_set_for_partner wrote audit_log
-- partner.pin.set only; admins listing partner_auth_alarm never saw a
-- first PIN. Closes that leftover: kind pin_set on app.partner_auth_alarm,
-- raised from the set wrapper on ok only (one row per subject uid per
-- minute). already_set / locked stay quiet. pin_change is deliberately
-- not covered (routine self-service).
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with pin_set.
--   2. Row CHECK: pin_set → credential_id IS NULL AND bucket_key is
--      subject uid text (same shape as pin_reset / pin_locked).
--   3. INSERT + SELECT policies so a PARTNER-bound private_definer can
--      write/read pin_set rows.
--   4. CREATE OR REPLACE partner_pin_set_for_partner: after audit on ok,
--      INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"subject":"<uuid>","status":"ok"} only.
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- pin_change alarm; OCR / aHash / UI flag flips / CAMERA. Nothing from
-- 0001–0105 is edited.

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
    'pin_set'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke', 'enrolment_issue', 'invite_create', 'invite_accept', 'enrolment_accept', 'totp_locked', 'pin_set')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105/0106. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke/credential_register = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke / enrolment_issue / totp_locked / pin_set = subject uid; org_revoke_all = org id; invite_revoke / invite_create / invite_accept = invite id; enrolment_accept = enrolment token id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for pin_set
-- ============================================================================
CREATE POLICY pd_partner_pin_set_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'pin_set'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_pin_set_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'pin_set'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Set wrapper raises the alarm on ok
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_pin_set_for_partner(p_derived bytea, p_salt bytea, p_iterations integer)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0_WRITE');
  -- the PIN is a staff / manager factor: an admin passes the anywhere branch of partner_authorize with no membership at all, and an admin or operator has NO PIN (6.3; the A3 substitution is S1.4's)
  IF NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL AND m.role IN ('staff', 'manager')) THEN
    RAISE EXCEPTION 'partner_pin_set_for_partner: only an active staff or manager member holds a PIN' USING ERRCODE = '42501';
  END IF;
  SELECT a.o_status, a.o_retry_after INTO v_r FROM private.partner_pin_set_apply('set', p_derived, p_salt, p_iterations, NULL) a;
  IF v_r.o_status = 'ok' THEN
    -- the email proof is SINGLE USE for a PIN set or change (S1.3 gate MEDIUM-1): spent in the SAME transaction as the write, on `ok` only. A refusal (`locked`, `already_set`) writes no PIN and keeps the proof.
    -- private_definer holds UPDATE on this one column (0049: lock clears it) and the guard always allows a clear. The GoTrue session id stays, so one GoTrue session still proves one proof.
    UPDATE app.partner_session s SET otp_proof_until = NULL WHERE s.id = private.partner_binding_session() AND s.otp_proof_until IS NOT NULL;
    PERFORM private.partner_audit_write('partner.pin.set', 'app.partner_pin', v_uid::text, '{}'::jsonb);
    v_detail := pg_catalog.jsonb_build_object('subject', v_uid::text, 'status', 'ok');
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'pin_set',
      NULL,
      v_uid::text,
      pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
      v_detail
    )
    ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after;
END
$$;

COMMENT ON FUNCTION private.partner_pin_set_for_partner(bytea, bytea, integer) IS
  '0052/0106 (§112). edge_partner only; POST pin/set: class A0_WRITE; first PIN or replacement after reset inside enrolment window or email proof; raises partner_auth_alarm kind pin_set on ok (one per subject uid per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105/0106. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), invite-revoke (invite_revoke), admin enrolment-issue (enrolment_issue), invite-create (invite_create), invite-accept (invite_accept), enrolment-accept (enrolment_accept), TOTP-lock (totp_locked), first-credential register (credential_register), and PIN-set operator signal (pin_set). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0106 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0052/0106 (§112): edge_partner only; POST pin/set: class A0_WRITE; raises pin_set alarm on ok'
WHERE schema_name = 'private'
  AND function_name = 'partner_pin_set_for_partner'
  AND identity_args = 'p_derived bytea, p_salt bytea, p_iterations integer';

DROP POLICY current_user_edit_function_inventory_0106 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0106 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_pin_set_alarm_insert', 'INSERT', true,
   '0106 (§112): partner-bound private_definer inserts pin_set for subject uid', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_pin_set_alarm_select', 'SELECT', true,
   '0106 (§112): partner-bound private_definer reads pin_set rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_pin_set_alarm_insert', 'pd_partner_pin_set_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0106 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0106$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_pin_set_alarm_insert', 'pd_partner_pin_set_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0106: expected partner-bound pin_set INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%pin_set%' THEN
    RAISE EXCEPTION '0106: partner_auth_alarm kind CHECK must include pin_set';
  END IF;
  SELECT pg_get_functiondef('private.partner_pin_set_for_partner(bytea, bytea, integer)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%pin_set%' THEN
    RAISE EXCEPTION '0106: partner_pin_set_for_partner must raise pin_set alarm';
  END IF;
END
$assert_0106$;
