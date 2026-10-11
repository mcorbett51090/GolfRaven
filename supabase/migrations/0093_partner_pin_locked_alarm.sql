-- 0093_partner_pin_locked_alarm.sql
--
-- P5 §97: operator alert on partner PIN lock (design §19.5 / LOW-3 /
-- §96.3). Until now partner_pin_verify_for_partner and
-- partner_pin_change_for_partner wrote audit_log partner.pin.locked only;
-- admins listing partner_auth_alarm never saw a lock. Closes that leftover:
-- kind pin_locked on app.partner_auth_alarm, raised only when
-- o_newly_locked (one row per subject uid per minute).
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with pin_locked.
--   2. Row CHECK: pin_locked → credential_id IS NULL AND bucket_key is
--      subject uid text (same shape as rate_member / totp_reset).
--   3. INSERT + SELECT policies so a PARTNER-bound private_definer can
--      write/read pin_locked rows (bucket_key is the locked member).
--   4. CREATE OR REPLACE partner_pin_verify_for_partner and
--      partner_pin_change_for_partner: after the existing audit, when
--      o_newly_locked, INSERT alarm ON CONFLICT DO NOTHING; detail
--      {"subject":"<uuid>","stage":"verify"|"change"} only.
--
-- DELIBERATELY NOT HERE: Q7 email (U1 condition 3); member/manager
-- notice beyond the operator alarm list; pin_reset alarm; OCR / aHash /
-- UI flag flips / CAMERA. Nothing from 0001–0092 is edited.

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
    'pin_locked'
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
      kind IN ('rate_member', 'totp_reset', 'pin_locked')
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083/0091/0092/0093. Arbiter key with (kind, minute_bucket): mint/credential_add = credential_id::text; IP/global rate = 64-hex IP hash or global; rate_member / totp_reset / pin_locked = subject uid. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for pin_locked
-- ============================================================================
CREATE POLICY pd_partner_pin_locked_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'pin_locked'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

CREATE POLICY pd_partner_pin_locked_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'pin_locked'
    AND credential_id IS NULL
    AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  );

-- ============================================================================
-- 3. Verify + change wrappers raise the alarm on o_newly_locked
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_pin_verify_for_partner(p_derived bytea)
RETURNS TABLE (o_status text, o_retry_after integer, o_grant_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
  v_detail jsonb;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0_WRITE');
  SELECT a.o_status, a.o_retry_after, a.o_newly_locked, a.o_grant_until INTO v_r FROM private.partner_pin_verify_apply(p_derived) a;
  IF v_r.o_status = 'wrong' OR v_r.o_newly_locked THEN
    PERFORM private.partner_audit_write(CASE WHEN v_r.o_newly_locked THEN 'partner.pin.locked' ELSE 'partner.pin.wrong' END, 'app.partner_pin', v_uid::text, pg_catalog.jsonb_build_object('stage', 'verify'));
  END IF;
  IF v_r.o_newly_locked THEN
    v_detail := pg_catalog.jsonb_build_object('subject', v_uid::text, 'stage', 'verify');
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'pin_locked',
      NULL,
      v_uid::text,
      pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
      v_detail
    )
    ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after, v_r.o_grant_until;
END
$$;

COMMENT ON FUNCTION private.partner_pin_verify_for_partner(bytea) IS
  '0052/0093 (§97). edge_partner only; POST step-up/pin: class A0_WRITE; verifies the derived key and, on ok, sets the single-use PIN grant; audit for wrong/lock; raises partner_auth_alarm kind pin_locked when o_newly_locked (one per subject uid per minute).';

CREATE OR REPLACE FUNCTION private.partner_pin_change_for_partner(p_current bytea, p_derived bytea, p_salt bytea, p_iterations integer)
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
  IF NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL AND m.role IN ('staff', 'manager')) THEN
    RAISE EXCEPTION 'partner_pin_change_for_partner: only an active staff or manager member holds a PIN' USING ERRCODE = '42501';
  END IF;
  SELECT a.o_status, a.o_retry_after, a.o_newly_locked INTO v_r FROM private.partner_pin_set_apply('change', p_derived, p_salt, p_iterations, p_current) a;
  IF v_r.o_status = 'ok' THEN
    UPDATE app.partner_session s SET otp_proof_until = NULL WHERE s.id = private.partner_binding_session() AND s.otp_proof_until IS NOT NULL;
    PERFORM private.partner_audit_write('partner.pin.change', 'app.partner_pin', v_uid::text, '{}'::jsonb);
  ELSIF v_r.o_status = 'wrong' OR v_r.o_newly_locked THEN
    PERFORM private.partner_audit_write(CASE WHEN v_r.o_newly_locked THEN 'partner.pin.locked' ELSE 'partner.pin.wrong' END, 'app.partner_pin', v_uid::text, pg_catalog.jsonb_build_object('stage', 'change'));
  END IF;
  IF v_r.o_newly_locked THEN
    v_detail := pg_catalog.jsonb_build_object('subject', v_uid::text, 'stage', 'change');
    INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
    VALUES (
      'pin_locked',
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

COMMENT ON FUNCTION private.partner_pin_change_for_partner(bytea, bytea, bytea, integer) IS
  '0052/0093 (§97). edge_partner only; POST pin/change: class A0_WRITE; replaces a live PIN under the current key; audit for wrong/lock/change; raises partner_auth_alarm kind pin_locked when o_newly_locked (one per subject uid per minute).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091/0092/0093. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), credential-add (credential_add), TOTP-reset (totp_reset), and PIN-lock operator signal (pin_locked). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0093 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0052/0093 (§97): edge_partner only; POST step-up/pin: class A0_WRITE; raises pin_locked alarm on o_newly_locked'
WHERE schema_name = 'private'
  AND function_name = 'partner_pin_verify_for_partner'
  AND identity_args = 'p_derived bytea';

UPDATE private.function_inventory
SET note = '0052/0093 (§97): edge_partner only; POST pin/change: class A0_WRITE; raises pin_locked alarm on o_newly_locked'
WHERE schema_name = 'private'
  AND function_name = 'partner_pin_change_for_partner'
  AND identity_args = 'p_current bytea, p_derived bytea, p_salt bytea, p_iterations integer';

DROP POLICY current_user_edit_function_inventory_0093 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0093 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_pin_locked_alarm_insert', 'INSERT', true,
   '0093 (§97): partner-bound private_definer inserts pin_locked for subject uid', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_pin_locked_alarm_select', 'SELECT', true,
   '0093 (§97): partner-bound private_definer reads pin_locked rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_pin_locked_alarm_insert', 'pd_partner_pin_locked_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0093 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0093$
DECLARE
  v_n int;
  v_def text;
BEGIN
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_pin_locked_alarm_insert', 'pd_partner_pin_locked_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0093: expected partner-bound pin_locked INSERT + SELECT policies';
  END IF;
  SELECT pg_get_constraintdef(oid) INTO v_def
  FROM pg_constraint
  WHERE conname = 'partner_auth_alarm_kind_check'
    AND conrelid = 'app.partner_auth_alarm'::regclass;
  IF v_def IS NULL OR v_def NOT LIKE '%pin_locked%' THEN
    RAISE EXCEPTION '0093: partner_auth_alarm kind CHECK must include pin_locked';
  END IF;
  SELECT pg_get_functiondef('private.partner_pin_verify_for_partner(bytea)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%pin_locked%' THEN
    RAISE EXCEPTION '0093: partner_pin_verify_for_partner must raise pin_locked alarm';
  END IF;
  SELECT pg_get_functiondef('private.partner_pin_change_for_partner(bytea, bytea, bytea, integer)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT ILIKE '%pin_locked%' THEN
    RAISE EXCEPTION '0093: partner_pin_change_for_partner must raise pin_locked alarm';
  END IF;
END
$assert_0093$;
