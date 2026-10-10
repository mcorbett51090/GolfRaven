-- 0081_partner_rate_alarm_buckets.sql
--
-- P5 §68: IP / global alert-only rate buckets for partner-session
-- options + verify failures (design §8 / leftover from §67.3 / 18.5).
-- Never refuse a request on these buckets (a NAT-shared office must not
-- be a DoS lever); they only raise app.partner_auth_alarm rows.
--
-- WHAT THIS CHANGES
--   1. app.partner_auth_alarm.bucket_key (text NOT NULL) — arbiter with
--      kind + minute_bucket. Mint kinds keep credential_id; rate kinds
--      leave credential_id NULL and key on sha256(IP) hex or 'global'.
--   2. kind CHECK widens: signature_invalid | counter_regression |
--      rate_options_ip | rate_options_global | rate_verify_ip.
--   3. Row CHECK: mint kinds require credential_id + bucket_key =
--      credential_id::text; rate kinds require credential_id IS NULL and
--      length(bucket_key) BETWEEN 1 AND 128.
--   4. CREATE OR REPLACE private.partner_mint_alarm_write — sets
--      bucket_key; ON CONFLICT (kind, bucket_key, minute_bucket).
--   5. private.partner_rate_alarm_raise(kind, bucket_key, detail) —
--      edge_partner_minter only; refuses any binding; INSERT ON CONFLICT
--      DO NOTHING; audit_log partner.rate.<kind> only when new.
--
-- DELIBERATELY NOT HERE: pepper-rotation tooling, OCR / aHash / UI flag
-- flips / CAMERA, invite hard-limit behaviour of hitSystemRateLimit.
-- Nothing from 0001–0080 is edited.

-- ============================================================================
-- 1. Column + backfill + nullability
-- ============================================================================
ALTER TABLE app.partner_auth_alarm ADD COLUMN bucket_key text;

UPDATE app.partner_auth_alarm
SET bucket_key = credential_id::text
WHERE bucket_key IS NULL;

ALTER TABLE app.partner_auth_alarm ALTER COLUMN bucket_key SET NOT NULL;
ALTER TABLE app.partner_auth_alarm ALTER COLUMN credential_id DROP NOT NULL;

COMMENT ON COLUMN app.partner_auth_alarm.bucket_key IS
  '0081 (§68). Arbiter key with (kind, minute_bucket): for mint kinds equals credential_id::text; for rate kinds a 64-hex IP hash or the literal global. Never a raw IP.';

-- ============================================================================
-- 2. UNIQUE + CHECKs
-- ============================================================================
ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_kind_credential_id_minute_bucket_key;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_kind_bucket_key_minute_bucket_key
  UNIQUE (kind, bucket_key, minute_bucket);

ALTER TABLE app.partner_auth_alarm
  DROP CONSTRAINT partner_auth_alarm_kind_check;

ALTER TABLE app.partner_auth_alarm
  ADD CONSTRAINT partner_auth_alarm_kind_check CHECK (kind IN (
    'signature_invalid',
    'counter_regression',
    'rate_options_ip',
    'rate_options_global',
    'rate_verify_ip'
  ));

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
  );

GRANT SELECT (bucket_key) ON app.partner_auth_alarm TO private_definer;

-- ============================================================================
-- 3. Mint writer + rate raiser (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_mint_alarm_write(p_kind text, p_credential_id uuid, p_detail jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_kind IS NULL OR p_kind NOT IN ('signature_invalid', 'counter_regression') OR p_credential_id IS NULL THEN
    RAISE EXCEPTION 'partner_mint_alarm_write: a kind (signature_invalid or counter_regression) and a credential are required' USING ERRCODE = '22023';
  END IF;
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    p_kind,
    p_credential_id,
    p_credential_id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    coalesce(p_detail, '{}'::jsonb)
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 1 THEN
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (NULL, 'partner.mint.' || p_kind, 'app.partner_credential', p_credential_id::text, coalesce(p_detail, '{}'::jsonb));
  END IF;
END
$$;

COMMENT ON FUNCTION private.partner_mint_alarm_write(text, uuid, jsonb) IS
  '0048/0081. One app.partner_auth_alarm row per (kind, bucket_key=credential_id::text, minute) and, when new, one audit_log row; EXECUTE for partner_session_issuer only.';

CREATE FUNCTION private.partner_rate_alarm_raise(p_kind text, p_bucket_key text, p_detail jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_rate_alarm_raise: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  IF p_kind IS NULL OR p_kind NOT IN ('rate_options_ip', 'rate_options_global', 'rate_verify_ip') THEN
    RAISE EXCEPTION 'partner_rate_alarm_raise: kind must be rate_options_ip, rate_options_global or rate_verify_ip' USING ERRCODE = '22023';
  END IF;
  IF p_bucket_key IS NULL
     OR NOT (p_bucket_key = 'global' OR p_bucket_key ~ '^[0-9a-f]{64}$') THEN
    RAISE EXCEPTION 'partner_rate_alarm_raise: bucket_key must be global or 64 lowercase hex' USING ERRCODE = '22023';
  END IF;
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    p_kind,
    NULL,
    p_bucket_key,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    coalesce(p_detail, '{}'::jsonb)
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 1 THEN
    INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
    VALUES (NULL, 'partner.rate.' || p_kind, 'app.partner_auth_alarm', p_bucket_key, coalesce(p_detail, '{}'::jsonb));
  END IF;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_rate_alarm_raise(text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_rate_alarm_raise(text, text, jsonb) TO edge_partner_minter;

COMMENT ON FUNCTION private.partner_rate_alarm_raise(text, text, jsonb) IS
  '0081 (§68). edge_partner_minter only. Alert-only IP/global rate signal: one partner_auth_alarm row per (kind, bucket_key, minute); audit_log partner.rate.<kind> only when new. Refuses any bound transaction. Never a hard limit.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081. Mint refusals after the Edge passed (signature_invalid / counter_regression) and alert-only rate buckets (rate_options_ip / rate_options_global / rate_verify_ip). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Holds no user id, no assertion bytes, no raw IP. Writers: partner_mint_alarm_write (issuer) and partner_rate_alarm_raise (minter). Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0081 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_rate_alarm_raise', 'p_kind text, p_bucket_key text, p_detail jsonb', false, false, false, false, false, false, true,
   '0081 (§68): edge_partner_minter only; alert-only rate alarm; refuses any binding')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_partner_minter = EXCLUDED.expected_edge_partner_minter, note = EXCLUDED.note;

UPDATE private.function_inventory
SET note = '0048/0081: one app.partner_auth_alarm row per (kind, bucket_key=credential_id::text, minute) and, when new, one audit_log row; EXECUTE for partner_session_issuer only (private.partner_owner_privilege)'
WHERE schema_name = 'private' AND function_name = 'partner_mint_alarm_write'
  AND identity_args = 'p_kind text, p_credential_id uuid, p_detail jsonb';

DROP POLICY current_user_edit_function_inventory_0081 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0081 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.definer_policy_allowlist
SET note = 'private.partner_mint_alarm_write / partner_rate_alarm_raise: INSERT ... ON CONFLICT reads the arbiter columns (kind, bucket_key, minute_bucket; column-level grant); no binding at all'
WHERE policy_name = 'pd_partner_auth_alarm_select';
DROP POLICY current_user_seed_definer_policy_allowlist_0081 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0081$
DECLARE
  v_n int;
BEGIN
  IF NOT has_column_privilege('private_definer', 'app.partner_auth_alarm', 'bucket_key', 'SELECT') THEN
    RAISE EXCEPTION '0081: private_definer must SELECT partner_auth_alarm.bucket_key';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_constraint k
  WHERE k.conrelid = 'app.partner_auth_alarm'::regclass
    AND k.conname = 'partner_auth_alarm_kind_bucket_key_minute_bucket_key'
    AND k.contype = 'u';
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0081: expected UNIQUE (kind, bucket_key, minute_bucket)';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_constraint k
  WHERE k.conrelid = 'app.partner_auth_alarm'::regclass
    AND k.conname = 'partner_auth_alarm_kind_credential_id_minute_bucket_key';
  IF v_n <> 0 THEN
    RAISE EXCEPTION '0081: old UNIQUE (kind, credential_id, minute_bucket) must be gone';
  END IF;
  IF NOT has_function_privilege('edge_partner_minter', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE') THEN
    RAISE EXCEPTION '0081: edge_partner_minter must EXECUTE partner_rate_alarm_raise';
  END IF;
  IF has_function_privilege('edge_partner', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE')
     OR has_function_privilege('edge_actor', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.partner_rate_alarm_raise(text, text, jsonb)', 'EXECUTE') THEN
    RAISE EXCEPTION '0081: partner_rate_alarm_raise must not be EXECUTEable by client / partner / actor / system / service_role';
  END IF;
  -- function_inventory is FORCE RLS; matrix 59 proves the inventory row as service_role.
  SELECT count(*)::int INTO v_n
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = 'partner_rate_alarm_raise'
    AND p.prosecdef AND p.proconfig = ARRAY['search_path=""']
    AND p.proowner = 'private_definer'::regrole;
  IF v_n <> 1 THEN
    RAISE EXCEPTION '0081: partner_rate_alarm_raise must be SECURITY DEFINER search_path='''' owned by private_definer';
  END IF;
END
$assert_0081$;
