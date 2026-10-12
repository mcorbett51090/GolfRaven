-- 0064_player_receipts_upload.sql
--
-- P5 player-lane receipt upload (partner-auth-design §27.3 seam / §40): EXIF-stripped image already in Storage,
-- perceptual hash (or HEIC sha256) and purchase_evidence intake per eligible trail, with app.dedupe_receipt_fingerprint
-- on the first purchase of the upload.
--
-- WHAT THIS ADDS
--   1. private.receipt_intake_for_actor (edge_actor): validates facility/programme, writes receipt purchases + credits,
--      calls app.dedupe_receipt_fingerprint once on the first purchase id. Statuses commit: ok | duplicate | review |
--      no_facility | no_programme | review_account | bad_args. o_dedupe: clean | same_user | cross_user.
--   2. Binding-keyed private_definer policies + column grants for dedupe (fraud_signal, review_item, receipt_fingerprint,
--      cross-user purchase demotion, void_reason, marker_credit detach).
--   3. GRANT EXECUTE on app.dedupe_receipt_fingerprint TO private_definer (not edge_actor).
--
-- DELIBERATELY NOT HERE: OCR pipeline, 90-day image purge, HEIC perceptual hash decoder, mobile UI.
-- Nothing from 0001–0063 is edited.

-- ============================================================================
-- 1. Grants and policies (FORCE RLS; actor_uid() must be set)
-- ============================================================================
GRANT EXECUTE ON FUNCTION app.dedupe_receipt_fingerprint(uuid, uuid, text, text, date, text) TO private_definer;

GRANT UPDATE (void_reason) ON app.purchase_evidence TO private_definer;
GRANT UPDATE (purchase_evidence_id) ON app.marker_credit TO private_definer;
GRANT INSERT (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date) ON app.receipt_fingerprint TO private_definer;

CREATE POLICY pd_receipt_fp_select ON app.receipt_fingerprint FOR SELECT TO private_definer
  USING (private.actor_uid() IS NOT NULL);

CREATE POLICY pd_receipt_fp_insert ON app.receipt_fingerprint FOR INSERT TO private_definer
  WITH CHECK (user_id = private.actor_uid());

CREATE POLICY pd_receipt_fraud_insert ON app.fraud_signal FOR INSERT TO private_definer
  WITH CHECK (
    private.actor_uid() IS NOT NULL
    AND user_id = private.actor_uid()
    AND kind IN ('receipt_phash_duplicate', 'receipt_ocr_duplicate', 'receipt_cross_user_match')
  );

CREATE POLICY pd_receipt_review_insert ON app.review_item FOR INSERT TO private_definer
  WITH CHECK (
    private.actor_uid() IS NOT NULL
    AND kind = 'receipt_cross_user_match'
    AND subject_table = 'purchase_evidence'
    AND EXISTS (
      SELECT 1 FROM app.purchase_evidence pe
      WHERE pe.id = subject_id AND pe.user_id = private.actor_uid()
    )
  );

-- Cross-user demotion matches app.dedupe_receipt_fingerprint: never touch void/valid
-- (a later collision must not un-accept an already-valid purchase). Own rows still update
-- for same-user void (status → void + void_reason).
CREATE POLICY pd_receipt_pe_cross_user_update ON app.purchase_evidence FOR UPDATE TO private_definer
  USING (
    private.actor_uid() IS NOT NULL
    AND (
      user_id = private.actor_uid()
      OR (user_id IS DISTINCT FROM private.actor_uid() AND status NOT IN ('void', 'valid'))
    )
  )
  WITH CHECK (
    user_id = private.actor_uid()
    OR (user_id IS DISTINCT FROM private.actor_uid() AND status = 'pending')
  );

CREATE POLICY pd_receipt_credit_detach ON app.marker_credit FOR UPDATE TO private_definer
  USING (user_id = private.actor_uid())
  WITH CHECK (user_id = private.actor_uid());

-- ============================================================================
-- 2. Definer
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.receipt_intake_for_actor(
  p_facility_id text,
  p_phash text,
  p_storage_object text,
  p_local_date date DEFAULT NULL,
  p_receipt_number_ocr text DEFAULT NULL
)
RETURNS TABLE (
  o_status text,
  o_local_date date,
  o_purchase_id uuid,
  o_trail_id text,
  o_purchase_status text,
  o_credit_id uuid,
  o_credit_status text,
  o_dedupe text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_tz text;
  v_local date;
  v_trails text[];
  v_trail text;
  v_cosignal jsonb;
  v_win_from timestamptz;
  v_win_to timestamptz;
  v_top_status text := 'ok';
  v_dedupe text := 'clean';
  v_dedupe_called boolean := false;
  v_purchase uuid;
  v_credit uuid;
  v_pstatus text;
  v_cstatus text;
  v_void_reason text;
  v_purchase_ids uuid[] := '{}';
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'receipt_intake_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'receipt_intake_for_actor: a system delegate may not upload a receipt purchase' USING ERRCODE = '42501';
  END IF;
  IF private.is_demo_account(v_uid) THEN
    o_status := 'review_account';
    o_dedupe := NULL;
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = ''
     OR p_phash IS NULL OR pg_catalog.btrim(p_phash) = ''
     OR p_storage_object IS NULL OR pg_catalog.btrim(p_storage_object) = '' THEN
    o_status := 'bad_args';
    o_dedupe := NULL;
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    o_status := 'no_facility';
    o_dedupe := NULL;
    RETURN NEXT;
    RETURN;
  END IF;

  v_local := coalesce(p_local_date, (v_now AT TIME ZONE v_tz)::date);

  SELECT pg_catalog.array_agg(fp.trail_id ORDER BY fp.trail_id) INTO v_trails
  FROM app.facility_programme fp
  JOIN app.trail_programme tp ON tp.trail_id = fp.trail_id
  WHERE fp.facility_id = p_facility_id
    AND fp.participation = 'accepted'
    AND tp.status IN ('pilot', 'live')
    AND tp.marker_source = 'any_purchase';
  IF v_trails IS NULL THEN
    o_status := 'no_programme';
    o_dedupe := NULL;
    RETURN NEXT;
    RETURN;
  END IF;

  v_win_from := (v_local::timestamp) AT TIME ZONE v_tz;
  v_win_to := ((v_local + 1)::timestamp AT TIME ZONE v_tz) - interval '1 millisecond';
  v_cosignal := pg_catalog.jsonb_build_object('awaiting', pg_catalog.jsonb_build_object(
    'from', pg_catalog.to_char(v_win_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'to', pg_catalog.to_char(v_win_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'until', pg_catalog.to_char((v_now + interval '7 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')));

  FOREACH v_trail IN ARRAY v_trails LOOP
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('marker-credit:' || v_uid::text || ':' || v_trail || ':' || p_facility_id, 0));

    INSERT INTO app.purchase_evidence (user_id, facility_id, trail_id, method, ref_id, offline, cosignal, local_date, status)
    VALUES (v_uid, p_facility_id, v_trail, 'receipt', p_storage_object, false, v_cosignal, v_local, 'pending')
    RETURNING id INTO v_purchase;
    v_purchase_ids := v_purchase_ids || v_purchase;

    INSERT INTO app.marker_credit (user_id, trail_id, facility_id, purchase_evidence_id, status)
    VALUES (v_uid, v_trail, p_facility_id, v_purchase, 'pending')
    RETURNING id INTO v_credit;

    IF NOT v_dedupe_called THEN
      v_dedupe_called := true;
      IF app.dedupe_receipt_fingerprint(v_purchase, v_uid, p_phash, p_facility_id, v_local, p_receipt_number_ocr) THEN
        v_top_status := 'ok';
        v_dedupe := 'clean';
      ELSE
        SELECT pe.status::text, pe.void_reason::text INTO v_pstatus, v_void_reason
        FROM app.purchase_evidence pe WHERE pe.id = v_purchase;
        IF v_pstatus = 'void' AND v_void_reason = 'duplicate' THEN
          v_top_status := 'duplicate';
          v_dedupe := 'same_user';
          UPDATE app.purchase_evidence pe
          SET status = 'void', void_reason = 'duplicate'
          WHERE pe.id = ANY (v_purchase_ids) AND pe.id <> v_purchase AND pe.status = 'pending';
          UPDATE app.marker_credit mc
          SET purchase_evidence_id = NULL
          WHERE mc.purchase_evidence_id = ANY (v_purchase_ids) AND mc.status <> 'credited';
        ELSE
          v_top_status := 'review';
          v_dedupe := 'cross_user';
        END IF;
      END IF;
    ELSIF v_top_status = 'duplicate' THEN
      UPDATE app.purchase_evidence pe SET status = 'void', void_reason = 'duplicate' WHERE pe.id = v_purchase;
      UPDATE app.marker_credit mc SET purchase_evidence_id = NULL WHERE mc.purchase_evidence_id = v_purchase AND mc.status <> 'credited';
    END IF;

    SELECT pe.status::text INTO v_pstatus FROM app.purchase_evidence pe WHERE pe.id = v_purchase;
    SELECT mc.status::text INTO v_cstatus FROM app.marker_credit mc WHERE mc.id = v_credit;

    o_status := v_top_status;
    o_local_date := v_local;
    o_purchase_id := v_purchase;
    o_trail_id := v_trail;
    o_purchase_status := v_pstatus;
    o_credit_id := v_credit;
    o_credit_status := v_cstatus;
    o_dedupe := v_dedupe;
    RETURN NEXT;
  END LOOP;
END
$$;

REVOKE EXECUTE ON FUNCTION private.receipt_intake_for_actor(text, text, text, date, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.receipt_intake_for_actor(text, text, text, date, text) TO edge_actor;

COMMENT ON FUNCTION private.receipt_intake_for_actor(text, text, text, date, text) IS
  '0064 (player-lane receipt upload). edge_actor only. Storage object path + phash; one pending purchase per eligible trail; dedupe on first purchase. Statuses: ok | duplicate | review | no_facility | no_programme | review_account | bad_args. o_dedupe: clean | same_user | cross_user.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Registries
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0064 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'receipt_intake_for_actor', 'p_facility_id text, p_phash text, p_storage_object text, p_local_date date, p_receipt_number_ocr text', false, false, false, true, false, false, false, '0064: edge_actor only; player receipt upload intake + dedupe')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_actor = EXCLUDED.expected_edge_actor, note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0064 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_edit_definer_policy_allowlist_0064 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'receipt_fingerprint', 'pd_receipt_fp_select', 'SELECT', true, '0064: dedupe phash/OCR lookup under a bound actor', 'private_definer'),
  ('app', 'receipt_fingerprint', 'pd_receipt_fp_insert', 'INSERT', true, '0064: record fingerprint for the bound actor''s purchase', 'private_definer'),
  ('app', 'fraud_signal', 'pd_receipt_fraud_insert', 'INSERT', true, '0064: receipt dedupe fraud signals for the bound actor', 'private_definer'),
  ('app', 'review_item', 'pd_receipt_review_insert', 'INSERT', true, '0064: cross-user receipt match review item on the actor''s purchase', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_receipt_pe_cross_user_update', 'UPDATE', true, '0064: void own or demote other user''s purchase to pending on cross-user dedupe', 'private_definer'),
  ('app', 'marker_credit', 'pd_receipt_credit_detach', 'UPDATE', true, '0064: detach marker_credit on duplicate void', 'private_definer')
ON CONFLICT (schema_name, table_name, policy_name) DO UPDATE
SET note = EXCLUDED.note, command = EXCLUDED.command, scoped = EXCLUDED.scoped, role_name = EXCLUDED.role_name;

UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = al.schema_name AND c.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_receipt_fp_select', 'pd_receipt_fp_insert', 'pd_receipt_fraud_insert', 'pd_receipt_review_insert',
    'pd_receipt_pe_cross_user_update', 'pd_receipt_credit_detach'
  );

DROP POLICY current_user_edit_definer_policy_allowlist_0064 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $assert_0064$
BEGIN
  IF NOT has_function_privilege('edge_actor', 'private.receipt_intake_for_actor(text, text, text, date, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0064: edge_actor must EXECUTE receipt_intake_for_actor';
  END IF;
  IF has_function_privilege('edge_partner', 'private.receipt_intake_for_actor(text, text, text, date, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0064: edge_partner must not EXECUTE receipt_intake_for_actor';
  END IF;
  IF has_function_privilege('edge_actor', 'app.dedupe_receipt_fingerprint(uuid, uuid, text, text, date, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0064: edge_actor must not EXECUTE app.dedupe_receipt_fingerprint directly';
  END IF;
  IF NOT has_function_privilege('private_definer', 'app.dedupe_receipt_fingerprint(uuid, uuid, text, text, date, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0064: private_definer must EXECUTE app.dedupe_receipt_fingerprint';
  END IF;
END
$assert_0064$;
