-- 0083_partner_member_rate_alarm.sql
--
-- P5 §70: member-keyed 1,200/h alert-only "any partner call" bucket
-- (design §8). Soft-cap only: never refuse a request; raise
-- app.partner_auth_alarm kind rate_member keyed on the bound member's
-- uid (never caller-chosen). Does not replace hard per-route caps.
--
-- WHAT THIS CHANGES
--   1. kind CHECK widens with rate_member.
--   2. Row CHECK: rate_member → credential_id IS NULL AND bucket_key is
--      uuid text.
--   3. INSERT + SELECT policies so a PARTNER-bound private_definer can
--      write/read rate_member rows for the bound uid (0048's insert/
--      select policies require NO binding — they stay for mint/minter
--      writers).
--   4. private.partner_member_rate_alarm_raise(p_detail jsonb) —
--      edge_partner only; REQUIRES partner binding; bucket_key =
--      partner_binding_user()::text; INSERT ON CONFLICT DO NOTHING;
--      audit_log partner.rate.rate_member only when new.
--
-- DELIBERATELY NOT HERE: retire-previous purge, credential revoke/add UI,
-- reach-rule note edits, partner_pin pepper_kid, OCR / aHash / UI flag
-- flips / CAMERA. partner_rate_alarm_raise (minter-only) is untouched.
-- Nothing from 0001–0082 is edited.

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
    'rate_member'
  ));

ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_bucket_shape_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_bucket_shape_check CHECK (
    (
      kind IN ('signature_invalid', 'counter_regression')
      AND credential_id IS NOT NULL
      AND bucket_key = credential_id::text
    )
    OR (
      kind IN ('rate_options_ip', 'rate_options_global', 'rate_verify_ip')
      AND credential_id IS NULL
      AND length(bucket_key) BETWEEN 1 AND 128
    )
    OR (
      kind = 'rate_member'
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081/0083. Arbiter key with (kind, minute_bucket): mint kinds = credential_id::text; IP/global rate kinds = 64-hex IP hash or global; rate_member = partner_binding_user()::text. Never a raw IP.';

-- ============================================================================
-- 2. Partner-bound INSERT + SELECT (ON CONFLICT) for rate_member
-- ============================================================================
CREATE POLICY pd_partner_member_rate_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'rate_member'
    AND credential_id IS NULL
    AND bucket_key = (SELECT private.partner_binding_user()::text)
  );

CREATE POLICY pd_partner_member_rate_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'rate_member'
    AND bucket_key = (SELECT private.partner_binding_user()::text)
  );

-- ============================================================================
-- 3. Writer (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_member_rate_alarm_raise(p_detail jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_n integer;
  v_bucket text;
BEGIN
  IF private.partner_binding_kind() IS DISTINCT FROM 'partner' THEN
    RAISE EXCEPTION 'partner_member_rate_alarm_raise: partner binding required' USING ERRCODE = '42501';
  END IF;
  v_uid := private.partner_binding_user();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'partner_member_rate_alarm_raise: partner binding required' USING ERRCODE = '42501';
  END IF;
  v_bucket := v_uid::text;
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'rate_member',
    NULL,
    v_bucket,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    coalesce(p_detail, '{}'::jsonb)
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 1 THEN
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (NULL, 'partner.rate.rate_member', 'app.partner_auth_alarm', v_bucket, coalesce(p_detail, '{}'::jsonb));
  END IF;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_member_rate_alarm_raise(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_member_rate_alarm_raise(jsonb) TO edge_partner;

COMMENT ON FUNCTION private.partner_member_rate_alarm_raise(jsonb) IS
  '0083 (§70). edge_partner only. Alert-only member any-call rate signal: one partner_auth_alarm row per (rate_member, binding uid, minute); audit_log partner.rate.rate_member only when new. REQUIRES a partner binding; bucket_key is never caller-chosen. Never a hard limit.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083. Mint refusals (signature_invalid / counter_regression), alert-only IP/global rate buckets (rate_options_ip / rate_options_global / rate_verify_ip), and member-keyed any-call soft-cap (rate_member). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Holds no assertion bytes, no raw IP. Writers: partner_mint_alarm_write (issuer), partner_rate_alarm_raise (minter), partner_member_rate_alarm_raise (edge_partner). Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0083 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_member_rate_alarm_raise', 'p_detail jsonb', false, false, false, false, false, true, false,
   '0083 (§70): edge_partner only; alert-only member rate alarm; requires partner binding; bucket_key = binding uid')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter,
    note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0083 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0083 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_member_rate_alarm_insert', 'INSERT', true,
   '0083 (§70): partner-bound private_definer inserts rate_member for binding uid only', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_member_rate_alarm_select', 'SELECT', true,
   '0083 (§70): partner-bound private_definer reads own rate_member rows for ON CONFLICT', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_partner_member_rate_alarm_insert', 'pd_partner_member_rate_alarm_select');
DROP POLICY current_user_seed_definer_policy_allowlist_0083 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0083$
DECLARE
  v_n int;
BEGIN
  IF NOT has_function_privilege('edge_partner', 'private.partner_member_rate_alarm_raise(jsonb)', 'EXECUTE') THEN
    RAISE EXCEPTION '0083: edge_partner must EXECUTE partner_member_rate_alarm_raise';
  END IF;
  IF has_function_privilege('edge_partner_minter', 'private.partner_member_rate_alarm_raise(jsonb)', 'EXECUTE')
     OR has_function_privilege('edge_actor', 'private.partner_member_rate_alarm_raise(jsonb)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_member_rate_alarm_raise(jsonb)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_member_rate_alarm_raise(jsonb)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_member_rate_alarm_raise(jsonb)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_member_rate_alarm_raise(jsonb)', 'EXECUTE') THEN
    RAISE EXCEPTION '0083: partner_member_rate_alarm_raise must not be EXECUTEable by minter / client / actor / system / service_role';
  END IF;
  -- minter-only rate raiser must stay closed to edge_partner
  IF has_function_privilege('edge_partner', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE') THEN
    RAISE EXCEPTION '0083: partner_rate_alarm_raise must remain edge_partner_minter only';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_member_rate_alarm_raise'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0083: partner_member_rate_alarm_raise must be SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_member_rate_alarm_insert', 'pd_partner_member_rate_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0083: expected partner-bound rate_member INSERT + SELECT policies';
  END IF;
END
$assert_0083$;
