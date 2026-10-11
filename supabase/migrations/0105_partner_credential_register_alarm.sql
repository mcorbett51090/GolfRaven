-- 0105_partner_credential_register_alarm.sql
--
-- P5 §111: operator alert on first-credential registration (design
-- §110.3 leftover after totp_locked; completes issue→accept→register).
-- Until now partner_credential_register_first wrote the credential and
-- recorded registered_credential_id on the invite or enrolment token
-- with no partner_auth_alarm row; admins listing alarms never saw a
-- first passkey. Closes that leftover: kind credential_register on
-- app.partner_auth_alarm, raised from AFTER UPDATE triggers when
-- registered_credential_id first becomes non-NULL. Quiet paths that
-- never set the column stay quiet. register_first stays owned by
-- partner_session_issuer (no REPLACE of that huge function).
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with credential_register.
--   2. Row CHECK: credential_register → mint-shaped (credential_id NOT
--      NULL AND bucket_key = credential_id::text), same as
--      credential_add / credential_revoke.
--   3. No new partner-bound policies: register_first is minter-lane only
--      (unbound); the existing 0048 binding-IS-NULL INSERT/SELECT cover
--      the writer.
--   4. Triggers on partner_invite and partner_enrolment_token
--      (AFTER UPDATE OF registered_credential_id): first set → INSERT
--      alarm ON CONFLICT DO NOTHING; detail carries credential, subject,
--      source, invite|token, and status only (never token hash or email).
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- OCR / aHash / UI flag flips / CAMERA. Nothing from 0001–0104 is edited.

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
    'credential_register'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke', 'enrolment_issue', 'invite_create', 'invite_accept', 'enrolment_accept', 'totp_locked')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke/credential_register = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke / enrolment_issue / totp_locked = subject uid; org_revoke_all = org id; invite_revoke / invite_create / invite_accept = invite id; enrolment_accept = enrolment token id. Never a raw IP.';

-- ============================================================================
-- 2. Trigger functions (private_definer) — minter-lane register only (unbound)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_invite_credential_register_alarm_on_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_detail jsonb;
BEGIN
  IF OLD.registered_credential_id IS NOT NULL
     OR NEW.registered_credential_id IS NULL
     OR NEW.accepted_by IS NULL THEN
    RETURN NEW;
  END IF;
  v_detail := pg_catalog.jsonb_build_object(
    'credential', NEW.registered_credential_id::text,
    'subject', NEW.accepted_by::text,
    'source', 'invite',
    'invite', NEW.id::text,
    'org', NEW.org_id::text,
    'role', NEW.role::text,
    'status', 'ok'
  );
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'credential_register',
    NEW.registered_credential_id,
    NEW.registered_credential_id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN NEW;
END
$$;

COMMENT ON FUNCTION private.partner_invite_credential_register_alarm_on_update() IS
  '0105 (§111). Trigger function (AFTER UPDATE OF registered_credential_id on app.partner_invite): first registration → credential_register alarm; never EXECUTEd directly by any role.';

CREATE FUNCTION private.partner_enrolment_credential_register_alarm_on_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_detail jsonb;
BEGIN
  IF OLD.registered_credential_id IS NOT NULL
     OR NEW.registered_credential_id IS NULL
     OR NEW.user_id IS NULL THEN
    RETURN NEW;
  END IF;
  v_detail := pg_catalog.jsonb_build_object(
    'credential', NEW.registered_credential_id::text,
    'subject', NEW.user_id::text,
    'source', 'enrolment',
    'token', NEW.id::text,
    'purpose', NEW.purpose,
    'status', 'ok'
  );
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'credential_register',
    NEW.registered_credential_id,
    NEW.registered_credential_id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN NEW;
END
$$;

COMMENT ON FUNCTION private.partner_enrolment_credential_register_alarm_on_update() IS
  '0105 (§111). Trigger function (AFTER UPDATE OF registered_credential_id on app.partner_enrolment_token): first registration → credential_register alarm; never EXECUTEd directly by any role.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

CREATE TRIGGER partner_invite_credential_register_alarm_trg
  AFTER UPDATE OF registered_credential_id ON app.partner_invite
  FOR EACH ROW EXECUTE FUNCTION private.partner_invite_credential_register_alarm_on_update();
CREATE TRIGGER partner_enrolment_credential_register_alarm_trg
  AFTER UPDATE OF registered_credential_id ON app.partner_enrolment_token
  FOR EACH ROW EXECUTE FUNCTION private.partner_enrolment_credential_register_alarm_on_update();
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.partner_invite_credential_register_alarm_on_update() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_enrolment_credential_register_alarm_on_update() FROM PUBLIC;
RESET ROLE;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102/0103/0104/0105. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), invite-revoke (invite_revoke), admin enrolment-issue (enrolment_issue), invite-create (invite_create), invite-accept (invite_accept), enrolment-accept (enrolment_accept), TOTP-lock (totp_locked), and first-credential register operator signal (credential_register). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 3. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0105 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_invite_credential_register_alarm_on_update', '', false, false, false, false, false, false, false,
   '0105 (§111): trigger function AFTER UPDATE OF registered_credential_id on partner_invite; never EXECUTEd directly'),
  ('private', 'partner_enrolment_credential_register_alarm_on_update', '', false, false, false, false, false, false, false,
   '0105 (§111): trigger function AFTER UPDATE OF registered_credential_id on partner_enrolment_token; never EXECUTEd directly')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0105 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 4. DO asserts
-- ============================================================================
DO $assert_0105$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%credential_register%' THEN
    RAISE EXCEPTION '0105: partner_auth_alarm kind CHECK must include credential_register';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname LIKE 'pd_partner_credential_register_alarm_%';
  IF v_n <> 0 THEN
    RAISE EXCEPTION '0105: credential_register must not add partner-bound policies (minter unbound)';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_trigger t
  JOIN pg_class c ON c.oid = t.tgrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'partner_invite'
    AND t.tgname = 'partner_invite_credential_register_alarm_trg' AND NOT t.tgisinternal;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0105: expected partner_invite_credential_register_alarm_trg on app.partner_invite';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_trigger t
  JOIN pg_class c ON c.oid = t.tgrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'partner_enrolment_token'
    AND t.tgname = 'partner_enrolment_credential_register_alarm_trg' AND NOT t.tgisinternal;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0105: expected partner_enrolment_credential_register_alarm_trg on app.partner_enrolment_token';
  END IF;
  SELECT pg_get_functiondef('private.partner_invite_credential_register_alarm_on_update()'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%credential_register%' THEN
    RAISE EXCEPTION '0105: partner_invite_credential_register_alarm_on_update must raise credential_register alarm';
  END IF;
  SELECT pg_get_functiondef('private.partner_enrolment_credential_register_alarm_on_update()'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%credential_register%' THEN
    RAISE EXCEPTION '0105: partner_enrolment_credential_register_alarm_on_update must raise credential_register alarm';
  END IF;
END
$assert_0105$;
