-- 0069_partner_resolve_receipt_cross_user.sql
--
-- P5 partner resolve of receipt_cross_user_match (partner-auth-design §48):
-- an admin with A3 closes an open cross-user receipt review item. Approve
-- keeps both money paths (inserts the subject's missing fingerprint so §47
-- promote can run); reject voids the subject's upload set with
-- void_reason='reviewer' (money-path §5 — never 'duplicate').
--
-- WHAT THIS ADDS
--   1. Binding-keyed private_definer policies for resolve side effects under
--      partner_bound_admin() (review_item UPDATE, purchase/credit/evidence/
--      fingerprint/fraud_signal).
--   2. private.partner_resolve_receipt_cross_user_match_apply +
--      _for_partner (class A3, admin only; status rows).
--
-- DELIBERATELY NOT HERE: OCR pipeline, perceptual aHash, picker UI, partners
-- PWA resolve button (queue already lists the items).
-- Nothing from 0001–0068 is edited.

-- ============================================================================
-- 1. Policies (admin partner binding; never a GUC)
-- ============================================================================
CREATE POLICY pd_partner_receipt_review_item_update ON app.review_item FOR UPDATE TO private_definer
  USING (
    private.partner_bound_admin()
    AND kind = 'receipt_cross_user_match'
    AND subject_table = 'purchase_evidence'
    AND resolved_at IS NULL
    AND status = 'open'
  )
  WITH CHECK (
    private.partner_bound_admin()
    AND kind = 'receipt_cross_user_match'
    AND subject_table = 'purchase_evidence'
    AND resolved_at IS NOT NULL
    AND resolved_by = private.partner_binding_user()
    AND status IN ('approved', 'rejected')
  );

CREATE POLICY pd_partner_receipt_pe_select ON app.purchase_evidence FOR SELECT TO private_definer
  USING (private.partner_bound_admin() AND method = 'receipt');

CREATE POLICY pd_partner_receipt_pe_update ON app.purchase_evidence FOR UPDATE TO private_definer
  USING (private.partner_bound_admin() AND method = 'receipt')
  WITH CHECK (private.partner_bound_admin() AND method = 'receipt');

CREATE POLICY pd_partner_receipt_credit_select ON app.marker_credit FOR SELECT TO private_definer
  USING (private.partner_bound_admin());

CREATE POLICY pd_partner_receipt_credit_update ON app.marker_credit FOR UPDATE TO private_definer
  USING (private.partner_bound_admin())
  WITH CHECK (private.partner_bound_admin());

CREATE POLICY pd_partner_receipt_fp_insert ON app.receipt_fingerprint FOR INSERT TO private_definer
  WITH CHECK (private.partner_bound_admin());

CREATE POLICY pd_partner_receipt_fp_select ON app.receipt_fingerprint FOR SELECT TO private_definer
  USING (private.partner_bound_admin());

CREATE POLICY pd_partner_receipt_evidence_select ON app.evidence FOR SELECT TO private_definer
  USING (private.partner_bound_admin() AND source = 'receipt_green_fee');

CREATE POLICY pd_partner_receipt_evidence_update ON app.evidence FOR UPDATE TO private_definer
  USING (
    private.partner_bound_admin()
    AND source = 'receipt_green_fee'
    AND status = 'accepted'
  )
  WITH CHECK (
    private.partner_bound_admin()
    AND source = 'receipt_green_fee'
    AND status = 'accepted'
  );

CREATE POLICY pd_partner_receipt_fraud_select ON app.fraud_signal FOR SELECT TO private_definer
  USING (private.partner_bound_admin() AND kind = 'receipt_cross_user_match');

CREATE POLICY pd_partner_receipt_fraud_update ON app.fraud_signal FOR UPDATE TO private_definer
  USING (
    private.partner_bound_admin()
    AND kind = 'receipt_cross_user_match'
    AND cleared_at IS NULL
  )
  WITH CHECK (
    private.partner_bound_admin()
    AND kind = 'receipt_cross_user_match'
    AND cleared_at IS NOT NULL
    AND cleared_by = private.partner_binding_user()
  );

-- ============================================================================
-- 2. Definers
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- Apply: status translation only (EXCEPTION block; EXECUTE for nobody but owner).
CREATE FUNCTION private.partner_resolve_receipt_cross_user_match_apply(
  p_review_id uuid,
  p_approve boolean,
  p_resolved_by uuid
)
RETURNS TABLE (o_status text, o_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_kind text;
  v_subject uuid;
  v_detail jsonb;
  v_uid uuid;
  v_facility text;
  v_phash text;
  v_local date;
  v_ref text;
  v_pstatus text;
  v_cosignal jsonb;
  v_ev uuid;
  v_fix jsonb;
  v_now timestamptz := pg_catalog.now();
BEGIN
  SELECT r.kind, r.subject_id, r.detail
    INTO v_kind, v_subject, v_detail
  FROM app.review_item r
  WHERE r.id = p_review_id
    AND r.resolved_at IS NULL
    AND r.status = 'open'
  FOR UPDATE;
  IF NOT FOUND THEN
    IF EXISTS (SELECT 1 FROM app.review_item r WHERE r.id = p_review_id) THEN
      RETURN QUERY SELECT 'not_open'::text, NULL::text;
    ELSE
      RETURN QUERY SELECT 'not_found'::text, NULL::text;
    END IF;
    RETURN;
  END IF;
  IF v_kind IS DISTINCT FROM 'receipt_cross_user_match' THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::text;
    RETURN;
  END IF;

  SELECT pe.user_id, pe.facility_id, pe.ref_id, pe.status::text, pe.cosignal, pe.local_date
    INTO v_uid, v_facility, v_ref, v_pstatus, v_cosignal, v_local
  FROM app.purchase_evidence pe
  WHERE pe.id = v_subject AND pe.method = 'receipt'
  FOR UPDATE;
  IF v_uid IS NULL THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::text;
    RETURN;
  END IF;

  v_phash := coalesce(v_detail ->> 'phash', NULL);
  IF v_phash IS NULL OR pg_catalog.btrim(v_phash) = '' THEN
    -- OCR-only match: recover phash from the subject's pending evidence summary.
    SELECT e.summary ->> 'fingerprint' INTO v_phash
    FROM app.evidence e
    WHERE e.user_id = v_uid
      AND e.source = 'receipt_green_fee'
      AND e.source_ref LIKE 'receipt:' || v_facility || ':%'
      AND (e.summary ->> 'status') = 'pending'
    ORDER BY e.created_at DESC
    LIMIT 1;
  END IF;
  IF v_local IS NULL AND v_detail ? 'local_date' THEN
    v_local := (v_detail ->> 'local_date')::date;
  END IF;

  IF p_approve THEN
    UPDATE app.review_item r
    SET status = 'approved', resolved_at = v_now, resolved_by = p_resolved_by
    WHERE r.id = p_review_id;

    IF v_phash IS NOT NULL AND pg_catalog.btrim(v_phash) <> '' THEN
      INSERT INTO app.receipt_fingerprint
        (purchase_evidence_id, user_id, phash, receipt_number_ocr, facility_id, local_date)
      VALUES
        (v_subject, v_uid, v_phash, NULL, v_facility, v_local)
      ON CONFLICT (purchase_evidence_id) WHERE purchase_evidence_id IS NOT NULL DO NOTHING;
    END IF;

    -- Clear the open cross-user fraud signal for this subject purchase.
    UPDATE app.fraud_signal fs
    SET cleared_at = v_now, cleared_by = p_resolved_by
    WHERE fs.kind = 'receipt_cross_user_match'
      AND fs.cleared_at IS NULL
      AND fs.user_id = v_uid
      AND (fs.detail ->> 'purchase_evidence_id') = v_subject::text;

    -- If the purchase is already valid (cosignal ran while the item was open), promote now.
    IF v_pstatus = 'valid' AND v_phash IS NOT NULL AND v_cosignal ? 'evidenceId' THEN
      BEGIN
        v_ev := (v_cosignal ->> 'evidenceId')::uuid;
      EXCEPTION WHEN invalid_text_representation THEN
        v_ev := NULL;
      END;
      IF v_ev IS NOT NULL THEN
        SELECT e.summary -> 'fix' INTO v_fix
        FROM app.evidence e
        WHERE e.id = v_ev AND e.user_id = v_uid;
        IF v_fix IS NOT NULL AND pg_catalog.jsonb_typeof(v_fix) = 'object' THEN
          UPDATE app.evidence e
          SET summary = pg_catalog.jsonb_build_object(
            'localDate', e.summary ->> 'localDate',
            'status', 'approved',
            'fingerprint', e.summary ->> 'fingerprint',
            'coSignalFix', v_fix
          )
          WHERE e.user_id = v_uid
            AND e.source = 'receipt_green_fee'
            AND e.source_ref = 'receipt:' || v_facility || ':' || v_phash
            AND e.status = 'accepted'
            AND (e.summary ->> 'status') = 'pending';
        END IF;
      END IF;
    END IF;

    RETURN QUERY SELECT 'ok'::text, 'approved'::text;
  ELSE
    UPDATE app.review_item r
    SET status = 'rejected', resolved_at = v_now, resolved_by = p_resolved_by
    WHERE r.id = p_review_id;

    -- Void the subject's upload set (same ref_id siblings); matched earlier purchase untouched.
    UPDATE app.purchase_evidence pe
    SET status = 'void', void_reason = 'reviewer'
    WHERE pe.user_id = v_uid
      AND pe.facility_id = v_facility
      AND pe.method = 'receipt'
      AND pe.ref_id IS NOT DISTINCT FROM v_ref
      AND pe.status <> 'void';

    UPDATE app.marker_credit mc
    SET purchase_evidence_id = NULL
    WHERE mc.user_id = v_uid
      AND mc.purchase_evidence_id IN (
        SELECT pe.id FROM app.purchase_evidence pe
        WHERE pe.user_id = v_uid
          AND pe.facility_id = v_facility
          AND pe.method = 'receipt'
          AND pe.ref_id IS NOT DISTINCT FROM v_ref
      )
      AND mc.status <> 'credited';

    IF v_phash IS NOT NULL AND pg_catalog.btrim(v_phash) <> '' THEN
      UPDATE app.evidence e
      SET summary = pg_catalog.jsonb_build_object(
        'localDate', e.summary ->> 'localDate',
        'status', 'void',
        'fingerprint', e.summary ->> 'fingerprint',
        'voidReason', 'reviewer'
      )
      WHERE e.user_id = v_uid
        AND e.source = 'receipt_green_fee'
        AND e.source_ref = 'receipt:' || v_facility || ':' || v_phash
        AND e.status = 'accepted'
        AND (e.summary ->> 'status') = 'pending';
    END IF;

    UPDATE app.fraud_signal fs
    SET cleared_at = v_now, cleared_by = p_resolved_by
    WHERE fs.kind = 'receipt_cross_user_match'
      AND fs.cleared_at IS NULL
      AND fs.user_id = v_uid
      AND (fs.detail ->> 'purchase_evidence_id') = v_subject::text;

    RETURN QUERY SELECT 'ok'::text, 'rejected'::text;
  END IF;
END;
$$;

CREATE FUNCTION private.partner_resolve_receipt_cross_user_match_for_partner(
  p_review_id uuid,
  p_approve boolean
)
RETURNS TABLE (o_status text, o_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_resolve_receipt_cross_user_match_for_partner: only an admin may resolve a receipt cross-user match' USING ERRCODE = '42501';
  END IF;
  IF p_review_id IS NULL OR p_approve IS NULL THEN
    RAISE EXCEPTION 'partner_resolve_receipt_cross_user_match_for_partner: a review id and an approve flag are required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
    SELECT a.o_status, a.o_state
    FROM private.partner_resolve_receipt_cross_user_match_apply(p_review_id, p_approve, v_uid) a;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.partner_resolve_receipt_cross_user_match_apply(uuid, boolean, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_resolve_receipt_cross_user_match_for_partner(uuid, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_resolve_receipt_cross_user_match_for_partner(uuid, boolean) TO edge_partner;

COMMENT ON FUNCTION private.partner_resolve_receipt_cross_user_match_apply(uuid, boolean, uuid) IS
  '0069. Resolves an open receipt_cross_user_match review_item. EXECUTE for nobody but the owner.';
COMMENT ON FUNCTION private.partner_resolve_receipt_cross_user_match_for_partner(uuid, boolean) IS
  '0069. edge_partner only; class A3; ADMIN only. Approve keeps money path + fingerprint; reject voids subject upload with void_reason=reviewer.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Registries
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0069 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'partner_resolve_receipt_cross_user_match_apply', 'p_review_id uuid, p_approve boolean, p_resolved_by uuid', false, false, false, false, false, false, false, '0069: apply helper; EXECUTE for nobody but owner'),
  ('private', 'partner_resolve_receipt_cross_user_match_for_partner', 'p_review_id uuid, p_approve boolean', false, false, false, false, false, true, false, '0069: edge_partner only; class A3; admin resolve of receipt_cross_user_match')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_partner = EXCLUDED.expected_edge_partner, note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0069 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_edit_definer_policy_allowlist_0069 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'review_item', 'pd_partner_receipt_review_item_update', 'UPDATE', true, '0069: admin closes open receipt_cross_user_match', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_partner_receipt_pe_select', 'SELECT', true, '0069: admin reads receipt purchases for resolve', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_partner_receipt_pe_update', 'UPDATE', true, '0069: admin voids rejected receipt purchases', 'private_definer'),
  ('app', 'marker_credit', 'pd_partner_receipt_credit_select', 'SELECT', true, '0069: admin reads credits to detach on reject', 'private_definer'),
  ('app', 'marker_credit', 'pd_partner_receipt_credit_update', 'UPDATE', true, '0069: admin detaches credits on reject', 'private_definer'),
  ('app', 'receipt_fingerprint', 'pd_partner_receipt_fp_insert', 'INSERT', true, '0069: admin inserts subject fingerprint on approve', 'private_definer'),
  ('app', 'receipt_fingerprint', 'pd_partner_receipt_fp_select', 'SELECT', true, '0069: INSERT ON CONFLICT needs fingerprint visible', 'private_definer'),
  ('app', 'evidence', 'pd_partner_receipt_evidence_select', 'SELECT', true, '0069: admin reads receipt_green_fee for promote/void', 'private_definer'),
  ('app', 'evidence', 'pd_partner_receipt_evidence_update', 'UPDATE', true, '0069: admin promotes or voids receipt_green_fee summary', 'private_definer'),
  ('app', 'fraud_signal', 'pd_partner_receipt_fraud_select', 'SELECT', true, '0069: admin reads open cross-user fraud signals', 'private_definer'),
  ('app', 'fraud_signal', 'pd_partner_receipt_fraud_update', 'UPDATE', true, '0069: admin clears cross-user fraud signals on resolve', 'private_definer')
ON CONFLICT (schema_name, table_name, policy_name) DO UPDATE
SET note = EXCLUDED.note, command = EXCLUDED.command, scoped = EXCLUDED.scoped, role_name = EXCLUDED.role_name;

UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = al.schema_name AND c.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name LIKE 'pd_partner_receipt_%';

DROP POLICY current_user_edit_definer_policy_allowlist_0069 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $assert_0069$
BEGIN
  IF NOT has_function_privilege('edge_partner', 'private.partner_resolve_receipt_cross_user_match_for_partner(uuid, boolean)', 'EXECUTE') THEN
    RAISE EXCEPTION '0069: edge_partner must EXECUTE partner_resolve_receipt_cross_user_match_for_partner';
  END IF;
  IF has_function_privilege('edge_partner', 'private.partner_resolve_receipt_cross_user_match_apply(uuid, boolean, uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0069: edge_partner must not EXECUTE the apply helper';
  END IF;
END
$assert_0069$;
