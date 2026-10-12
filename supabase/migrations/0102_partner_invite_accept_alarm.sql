-- 0102_partner_invite_accept_alarm.sql
--
-- P5 §108: operator alert on partner invite accept (design §107.3 /
-- §21.4 invite-event trail after invite_create). Until now both accept
-- wrappers wrote audit_log partner.invite.accept only; admins listing
-- partner_auth_alarm never saw an acceptance. Closes that leftover:
-- kind invite_accept on app.partner_auth_alarm, raised from an AFTER
-- UPDATE trigger when accepted_at first becomes non-NULL (covers branch N
-- minter accept and branch E partner accept). Quiet statuses that never
-- set accepted_at stay quiet.
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with invite_accept.
--   2. Row CHECK: invite_accept → credential_id IS NULL AND bucket_key
--      is invite id text (same uuid shape as invite_create / invite_revoke).
--   3. Partner-bound INSERT + SELECT policies (branch E). Unbound mint
--      path uses the existing 0048 binding-IS-NULL policies.
--   4. Trigger private.partner_invite_accept_alarm_on_update: on first
--      accept, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"invite","org","role","subject","status"} only (subject =
--      accepted_by; never the token hash or invitee email).
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); staging path probe;
-- OCR / aHash / UI flag flips / CAMERA. Nothing from 0001–0101 is edited.

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
    'invite_accept'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked', 'pin_reset', 'member_recover', 'org_revoke_all', 'member_revoke', 'invite_revoke', 'enrolment_issue', 'invite_create', 'invite_accept')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102. Arbiter key with (kind, minute_bucket): mint/credential_add/credential_revoke = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked / pin_reset / member_recover / member_revoke / enrolment_issue = subject uid; org_revoke_all = org id; invite_revoke / invite_create / invite_accept = invite id. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for invite_accept
-- ============================================================================
CREATE POLICY pd_partner_invite_accept_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'invite_accept'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_invite_accept_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'invite_accept'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Trigger function (private_definer) — fires for branch N and branch E
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_invite_accept_alarm_on_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_detail jsonb;
BEGIN
  IF OLD.accepted_at IS NOT NULL OR NEW.accepted_at IS NULL OR NEW.accepted_by IS NULL THEN
    RETURN NEW;
  END IF;
  v_detail := pg_catalog.jsonb_build_object(
    'invite', NEW.id::text,
    'org', NEW.org_id::text,
    'role', NEW.role::text,
    'subject', NEW.accepted_by::text,
    'status', 'ok'
  );
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'invite_accept',
    NULL,
    NEW.id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN NEW;
END
$$;

COMMENT ON FUNCTION private.partner_invite_accept_alarm_on_update() IS
  '0102 (§108). Trigger function (AFTER UPDATE OF accepted_at on app.partner_invite): first accept → invite_accept alarm; never EXECUTEd directly by any role.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- Create the trigger as the migrating role (table owner), then strip EXECUTE.
CREATE TRIGGER partner_invite_accept_alarm_trg
  AFTER UPDATE OF accepted_at ON app.partner_invite
  FOR EACH ROW EXECUTE FUNCTION private.partner_invite_accept_alarm_on_update();
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.partner_invite_accept_alarm_on_update() FROM PUBLIC;
RESET ROLE;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093/0094/0095/0096/0097/0098/0099/0100/0101/0102. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), PIN-lock (pin_locked), PIN-reset (pin_reset), member-recover (member_recover), org revoke-all (org_revoke_all), member-revoke (member_revoke), credential-revoke (credential_revoke), invite-revoke (invite_revoke), admin enrolment-issue (enrolment_issue), invite-create (invite_create), and invite-accept operator signal (invite_accept). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0102 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_invite_accept_alarm_on_update', '', false, false, false, false, false, false, false,
   '0102 (§108): trigger function AFTER UPDATE OF accepted_at on partner_invite; never EXECUTEd directly')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0102 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0102 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_invite_accept_alarm_insert', 'INSERT', true,
   '0102 (§108): partner-bound private_definer inserts invite_accept for invite id', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_invite_accept_alarm_select', 'SELECT', true,
   '0102 (§108): partner-bound private_definer reads invite_accept rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_invite_accept_alarm_insert', 'pd_partner_invite_accept_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0102 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0102$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_invite_accept_alarm_insert', 'pd_partner_invite_accept_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0102: expected partner-bound invite_accept INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%invite_accept%' THEN
    RAISE EXCEPTION '0102: partner_auth_alarm kind CHECK must include invite_accept';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_trigger t
  JOIN pg_class c ON c.oid = t.tgrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relname = 'partner_invite'
    AND t.tgname = 'partner_invite_accept_alarm_trg' AND NOT t.tgisinternal;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0102: expected partner_invite_accept_alarm_trg on app.partner_invite';
  END IF;
  SELECT pg_get_functiondef('private.partner_invite_accept_alarm_on_update()'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%invite_accept%' THEN
    RAISE EXCEPTION '0102: partner_invite_accept_alarm_on_update must raise invite_accept alarm';
  END IF;
END
$assert_0102$;
