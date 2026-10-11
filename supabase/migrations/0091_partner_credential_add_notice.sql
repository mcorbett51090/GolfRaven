-- 0091_partner_credential_add_notice.sql
--
-- P5 §92: U1 credential-add notice (server half). Notice table + operator
-- alarm kind credential_add + member list/ack + manager reach list + purge
-- + Edge routes on partner-members. PWA interstitial is NOT this slice.
--
-- WHAT THIS ADDS
--   1. app.partner_credential_add_notice + FORCE RLS (no edge table grant)
--   2. AFTER INSERT trigger on app.partner_credential when
--      created_via_credential_id IS NOT NULL (second credential)
--   3. partner_auth_alarm kind credential_add (mint-shaped bucket_key)
--   4. private.partner_credential_add_notice_* definers + purge
--
-- DELIBERATELY NOT HERE: partners PWA interstitial; OCR / aHash / UI flag
-- flips / CAMERA. partner_credential_register_for_partner is untouched.
-- Nothing from 0001–0090 is edited.

-- ============================================================================
-- 1. Notice table
-- ============================================================================
CREATE TABLE app.partner_credential_add_notice (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  credential_id uuid NOT NULL REFERENCES app.partner_credential (id) UNIQUE,
  subject_user_id uuid NOT NULL REFERENCES auth.users (id),
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 120),
  created_at timestamptz NOT NULL DEFAULT now(),
  subject_acked_at timestamptz
);

COMMENT ON TABLE app.partner_credential_add_notice IS
  '0091 (§92). One row per second (or later) credential add: pending until the subject acks (U1 interstitial). Manager reach list reads unacked rows. Retention: purge_partner_credential_add_notices.';

ALTER TABLE app.partner_credential_add_notice ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_credential_add_notice FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.partner_credential_add_notice FROM PUBLIC, anon, authenticated, service_role;

GRANT INSERT, SELECT, UPDATE, DELETE ON app.partner_credential_add_notice TO private_definer;

CREATE POLICY pd_insert_partner_credential_add_notice ON app.partner_credential_add_notice FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND subject_user_id IS NOT NULL
    AND credential_id IS NOT NULL
  );

CREATE POLICY pd_read_partner_credential_add_notice_subject ON app.partner_credential_add_notice FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND subject_user_id = (SELECT private.partner_binding_user())
  );

CREATE POLICY pd_read_partner_credential_add_notice_reach ON app.partner_credential_add_notice FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND subject_user_id IS DISTINCT FROM (SELECT private.partner_binding_user())
    AND private.partner_reach_covers((SELECT private.partner_binding_user()), subject_user_id)
  );

CREATE POLICY pd_update_partner_credential_add_notice_ack ON app.partner_credential_add_notice FOR UPDATE TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND subject_user_id = (SELECT private.partner_binding_user())
  )
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND subject_user_id = (SELECT private.partner_binding_user())
  );

-- Qualify notice.credential_id: bare `credential_id` inside FROM partner_credential
-- resolves to the bytea WebAuthn id column (uuid = bytea).
CREATE POLICY pd_purge_partner_credential_add_notice ON app.partner_credential_add_notice FOR DELETE TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND (
      subject_acked_at < now() - interval '30 days'
      OR EXISTS (
        SELECT 1 FROM app.partner_credential c
        WHERE c.id = partner_credential_add_notice.credential_id
          AND c.revoked_at < now() - interval '180 days'
      )
    )
  );

CREATE POLICY pd_purge_partner_credential_add_notice_r ON app.partner_credential_add_notice FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND (
      subject_acked_at < now() - interval '30 days'
      OR EXISTS (
        SELECT 1 FROM app.partner_credential c
        WHERE c.id = partner_credential_add_notice.credential_id
          AND c.revoked_at < now() - interval '180 days'
      )
    )
  );

-- ============================================================================
-- 2. Alarm kind credential_add
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
    'credential_add'
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
      kind = 'rate_member'
      AND credential_id IS NULL
      AND bucket_key ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )
  );

CREATE POLICY pd_partner_credential_add_alarm_insert ON app.partner_auth_alarm FOR INSERT TO private_definer
  WITH CHECK (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'credential_add'
    AND credential_id IS NOT NULL
    AND bucket_key = credential_id::text
  );

CREATE POLICY pd_partner_credential_add_alarm_select ON app.partner_auth_alarm FOR SELECT TO private_definer
  USING (
    (SELECT private.partner_binding_kind()) = 'partner'
    AND kind = 'credential_add'
    AND credential_id IS NOT NULL
    AND bucket_key = credential_id::text
  );

-- ============================================================================
-- 3. Trigger + definers (private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_credential_add_notice_on_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_detail jsonb;
BEGIN
  IF NEW.created_via_credential_id IS NULL THEN
    RETURN NEW;
  END IF;
  INSERT INTO app.partner_credential_add_notice (credential_id, subject_user_id, label)
  VALUES (NEW.id, NEW.user_id, NEW.label);
  v_detail := pg_catalog.jsonb_build_object('subject', NEW.user_id::text);
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'credential_add',
    NEW.id,
    NEW.id::text,
    pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 60)::bigint,
    v_detail
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  RETURN NEW;
END
$$;

-- Trigger is created as the migrating role after RESET ROLE (CREATE TRIGGER
-- needs table ownership; 0054 partner_member_last_membership shape). PUBLIC
-- still holds EXECUTE here so creation can resolve the function.

CREATE FUNCTION private.partner_credential_add_notice_list_mine_for_partner()
RETURNS TABLE (
  o_notice_id uuid,
  o_credential_id uuid,
  o_label text,
  o_created_at timestamptz,
  o_credential_revoked_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  RETURN QUERY
  SELECT n.id, n.credential_id, n.label, n.created_at, c.revoked_at
  FROM app.partner_credential_add_notice n
  JOIN app.partner_credential c ON c.id = n.credential_id
  WHERE n.subject_user_id = v_uid
    AND n.subject_acked_at IS NULL
  ORDER BY n.created_at DESC, n.id
  LIMIT 50;
END
$$;

CREATE FUNCTION private.partner_credential_add_notice_ack_for_partner(p_notice_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_n integer;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  IF p_notice_id IS NULL THEN
    RAISE EXCEPTION 'partner_credential_add_notice_ack_for_partner: a notice id is required' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM app.partner_credential_add_notice n
    WHERE n.id = p_notice_id AND n.subject_user_id = v_uid AND n.subject_acked_at IS NOT NULL
  ) THEN
    RETURN QUERY SELECT 'already_acked'::text;
    RETURN;
  END IF;
  UPDATE app.partner_credential_add_notice n
  SET subject_acked_at = pg_catalog.clock_timestamp()
  WHERE n.id = p_notice_id AND n.subject_user_id = v_uid AND n.subject_acked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 1 THEN
    RETURN QUERY SELECT 'ok'::text;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'not_found'::text;
END
$$;

CREATE FUNCTION private.partner_credential_add_notice_list_reach_for_partner()
RETURNS TABLE (
  o_notice_id uuid,
  o_subject_user_id uuid,
  o_credential_id uuid,
  o_label text,
  o_created_at timestamptz,
  o_credential_revoked_at timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A0');
  RETURN QUERY
  SELECT n.id, n.subject_user_id, n.credential_id, n.label, n.created_at, c.revoked_at
  FROM app.partner_credential_add_notice n
  JOIN app.partner_credential c ON c.id = n.credential_id
  WHERE n.subject_acked_at IS NULL
    AND n.subject_user_id IS DISTINCT FROM v_uid
    AND private.partner_reach_covers(v_uid, n.subject_user_id)
  ORDER BY n.created_at DESC, n.id
  LIMIT 100;
END
$$;

CREATE FUNCTION private.purge_partner_credential_add_notices()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_credential_add_notice d
  WHERE d.id = ANY (ARRAY(
    SELECT s.id
    FROM app.partner_credential_add_notice s
    LEFT JOIN app.partner_credential c ON c.id = s.credential_id
    WHERE s.subject_acked_at < pg_catalog.now() - interval '30 days'
       OR (c.revoked_at IS NOT NULL AND c.revoked_at < pg_catalog.now() - interval '180 days')
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

REVOKE EXECUTE ON FUNCTION
  private.partner_credential_add_notice_list_mine_for_partner(),
  private.partner_credential_add_notice_ack_for_partner(uuid),
  private.partner_credential_add_notice_list_reach_for_partner(),
  private.purge_partner_credential_add_notices()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  private.partner_credential_add_notice_list_mine_for_partner(),
  private.partner_credential_add_notice_ack_for_partner(uuid),
  private.partner_credential_add_notice_list_reach_for_partner()
TO edge_partner;
GRANT EXECUTE ON FUNCTION private.purge_partner_credential_add_notices() TO edge_system;

COMMENT ON FUNCTION private.partner_credential_add_notice_list_mine_for_partner() IS
  '0091 (§92). edge_partner only; class A0. Unacked credential-add notices for the signed-in subject; newest first; at most 50.';
COMMENT ON FUNCTION private.partner_credential_add_notice_ack_for_partner(uuid) IS
  '0091 (§92). edge_partner only; class A0. Subject acks own notice (ok | not_found | already_acked).';
COMMENT ON FUNCTION private.partner_credential_add_notice_list_reach_for_partner() IS
  '0091 (§92). edge_partner only; class A0. Unacked notices for reach-covered members (never own); manager|operator; at most 100.';
COMMENT ON FUNCTION private.purge_partner_credential_add_notices() IS
  '0091 (§92). edge_system. Deletes notices acked more than 30 days ago or tied to a credential revoked more than 180 days ago; at most 5000 per call.';
COMMENT ON FUNCTION private.partner_credential_add_notice_on_insert() IS
  '0091 (§92). Trigger function (AFTER INSERT on app.partner_credential): second credential → notice + credential_add alarm; never EXECUTEd directly by any role.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- Create the trigger as the migrating role (table owner), then strip EXECUTE.
CREATE TRIGGER partner_credential_add_notice_trg
  AFTER INSERT ON app.partner_credential
  FOR EACH ROW EXECUTE FUNCTION private.partner_credential_add_notice_on_insert();
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.partner_credential_add_notice_on_insert() FROM PUBLIC;
RESET ROLE;

COMMENT ON TABLE app.partner_auth_alarm IS
  '0048/0074/0075/0081/0083/0091. Mint refusals, alert-only rate buckets, member any-call soft-cap (rate_member), and credential-add operator signal (credential_add). UNIQUE (kind, bucket_key, minute_bucket). Operator-facing via partner_auth_alarm_list_for_partner. Retention: purge_partner_auth_alarms (90 days).';

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0091 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_credential_add_notice_on_insert', '', false, false, false, false, false, false, false,
   '0091 (§92): trigger function AFTER INSERT on partner_credential; never EXECUTEd directly'),
  ('private', 'partner_credential_add_notice_list_mine_for_partner', '', false, false, false, false, false, true, false,
   '0091 (§92): edge_partner only; class A0; subject unacked credential-add notices'),
  ('private', 'partner_credential_add_notice_ack_for_partner', 'p_notice_id uuid', false, false, false, false, false, true, false,
   '0091 (§92): edge_partner only; class A0; subject ack own notice'),
  ('private', 'partner_credential_add_notice_list_reach_for_partner', '', false, false, false, false, false, true, false,
   '0091 (§92): edge_partner only; class A0; manager reach unacked credential-add notices'),
  ('private', 'purge_partner_credential_add_notices', '', false, false, false, false, true, false, false,
   '0091 (§92): edge_system; credential-add notice retention purge')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_partner = EXCLUDED.expected_edge_partner,
    expected_edge_system = EXCLUDED.expected_edge_system,
    expected_edge_actor = EXCLUDED.expected_edge_actor,
    note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0091 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0091 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_alarm', 'pd_partner_credential_add_alarm_insert', 'INSERT', true,
   '0091 (§92): partner-bound private_definer inserts credential_add for new credential id', 'private_definer'),
  ('app', 'partner_auth_alarm', 'pd_partner_credential_add_alarm_select', 'SELECT', true,
   '0091 (§92): partner-bound private_definer reads credential_add rows for ON CONFLICT', 'private_definer'),
  ('app', 'partner_credential_add_notice', 'pd_insert_partner_credential_add_notice', 'INSERT', true,
   '0091 (§92): second-credential trigger insert under partner binding', 'private_definer'),
  ('app', 'partner_credential_add_notice', 'pd_read_partner_credential_add_notice_subject', 'SELECT', true,
   '0091 (§92): subject reads own notices', 'private_definer'),
  ('app', 'partner_credential_add_notice', 'pd_read_partner_credential_add_notice_reach', 'SELECT', true,
   '0091 (§92): manager reach reads covered subjects'' notices', 'private_definer'),
  ('app', 'partner_credential_add_notice', 'pd_update_partner_credential_add_notice_ack', 'UPDATE', true,
   '0091 (§92): subject acks own notice', 'private_definer'),
  ('app', 'partner_credential_add_notice', 'pd_purge_partner_credential_add_notice', 'DELETE', true,
   '0091 (§92): retention purge; closed under partner binding', 'private_definer'),
  ('app', 'partner_credential_add_notice', 'pd_purge_partner_credential_add_notice_r', 'SELECT', true,
   '0091 (§92): row-visibility companion to pd_purge_partner_credential_add_notice', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN (
    'pd_partner_credential_add_alarm_insert', 'pd_partner_credential_add_alarm_select',
    'pd_insert_partner_credential_add_notice', 'pd_read_partner_credential_add_notice_subject',
    'pd_read_partner_credential_add_notice_reach', 'pd_update_partner_credential_add_notice_ack',
    'pd_purge_partner_credential_add_notice', 'pd_purge_partner_credential_add_notice_r'
  );
DROP POLICY current_user_seed_definer_policy_allowlist_0091 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 5. DO asserts
-- ============================================================================
DO $assert_0091$
DECLARE
  v_n int;
BEGIN
  IF NOT has_function_privilege('edge_partner', 'private.partner_credential_add_notice_list_mine_for_partner()', 'EXECUTE') THEN
    RAISE EXCEPTION '0091: edge_partner must EXECUTE partner_credential_add_notice_list_mine_for_partner';
  END IF;
  IF NOT has_function_privilege('edge_system', 'private.purge_partner_credential_add_notices()', 'EXECUTE') THEN
    RAISE EXCEPTION '0091: edge_system must EXECUTE purge_partner_credential_add_notices';
  END IF;
  IF has_table_privilege('edge_partner', 'app.partner_credential_add_notice', 'SELECT')
     OR has_table_privilege('edge_partner', 'app.partner_credential_add_notice', 'INSERT') THEN
    RAISE EXCEPTION '0091: edge_partner must have no table privilege on partner_credential_add_notice';
  END IF;
  SELECT count(*)::int INTO v_n
  FROM pg_policy pol
  WHERE pol.polname IN ('pd_partner_credential_add_alarm_insert', 'pd_partner_credential_add_alarm_select');
  IF v_n <> 2 THEN
    RAISE EXCEPTION '0091: expected partner-bound credential_add INSERT + SELECT policies';
  END IF;
END
$assert_0091$;
