-- 0070_partner_receipt_preview.sql
--
-- P5 partner review image preview (partner-auth-design §51):
-- an admin with A0 reads storage ref_ids for an open
-- receipt_cross_user_match so the Edge can mint short-lived signed URLs.
-- Paths never leave the Edge as storage paths (uid leak); the wire uses
-- opaque labels (subject / matched) only.
--
-- WHAT THIS ADDS
--   1. private.partner_receipt_cross_user_preview_for_partner(review_id)
--      (class A0, admin only; status rows: ok | not_found | not_open | no_image).
--
-- POLICIES: reuses 0057 pd_partner_review_item_select and 0069
-- pd_partner_receipt_pe_select (partner_bound_admin()). No new policies.
--
-- DELIBERATELY NOT HERE: OCR, aHash, signed URL mint (Edge + Storage).
-- Nothing from 0001–0069 is edited.

-- ============================================================================
-- 1. Definer
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.partner_receipt_cross_user_preview_for_partner(p_review_id uuid)
RETURNS TABLE (o_status text, o_subject_ref text, o_matched_ref text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_subject uuid;
  v_detail jsonb;
  v_resolved timestamptz;
  v_status text;
  v_subject_ref text;
  v_matched_id uuid;
  v_matched_ref text;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_receipt_cross_user_preview_for_partner: only an admin may preview a receipt cross-user match' USING ERRCODE = '42501';
  END IF;
  IF p_review_id IS NULL THEN
    RAISE EXCEPTION 'partner_receipt_cross_user_preview_for_partner: a review id is required' USING ERRCODE = '22023';
  END IF;

  SELECT r.kind, r.subject_id, r.detail, r.resolved_at, r.status
    INTO v_kind, v_subject, v_detail, v_resolved, v_status
  FROM app.review_item r
  WHERE r.id = p_review_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text;
    RETURN;
  END IF;
  IF v_kind IS DISTINCT FROM 'receipt_cross_user_match'
     OR v_subject IS NULL THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text;
    RETURN;
  END IF;
  IF v_resolved IS NOT NULL OR v_status IS DISTINCT FROM 'open' THEN
    RETURN QUERY SELECT 'not_open'::text, NULL::text, NULL::text;
    RETURN;
  END IF;

  SELECT pe.ref_id INTO v_subject_ref
  FROM app.purchase_evidence pe
  WHERE pe.id = v_subject AND pe.method = 'receipt';
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text;
    RETURN;
  END IF;

  v_matched_ref := NULL;
  BEGIN
    v_matched_id := NULLIF(pg_catalog.btrim(coalesce(v_detail ->> 'matched_purchase_evidence_id', '')), '')::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    v_matched_id := NULL;
  END;
  IF v_matched_id IS NOT NULL THEN
    SELECT pe.ref_id INTO v_matched_ref
    FROM app.purchase_evidence pe
    WHERE pe.id = v_matched_id AND pe.method = 'receipt';
    IF v_matched_ref IS NOT NULL AND pg_catalog.btrim(v_matched_ref) = '' THEN
      v_matched_ref := NULL;
    END IF;
  END IF;

  IF v_subject_ref IS NOT NULL AND pg_catalog.btrim(v_subject_ref) = '' THEN
    v_subject_ref := NULL;
  END IF;

  IF v_subject_ref IS NULL AND v_matched_ref IS NULL THEN
    RETURN QUERY SELECT 'no_image'::text, NULL::text, NULL::text;
    RETURN;
  END IF;

  RETURN QUERY SELECT 'ok'::text, v_subject_ref, v_matched_ref;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.partner_receipt_cross_user_preview_for_partner(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_receipt_cross_user_preview_for_partner(uuid) TO edge_partner;

COMMENT ON FUNCTION private.partner_receipt_cross_user_preview_for_partner(uuid) IS
  '0070. edge_partner only; class A0; ADMIN only. Returns storage ref_ids for an open receipt_cross_user_match (Edge signs; paths stay off the wire).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Registries
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0070 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'partner_receipt_cross_user_preview_for_partner', 'p_review_id uuid', false, false, false, false, false, true, false, '0070: edge_partner only; class A0; admin preview refs for receipt_cross_user_match')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_partner = EXCLUDED.expected_edge_partner, note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0070 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

DO $assert_0070$
BEGIN
  IF NOT has_function_privilege('edge_partner', 'private.partner_receipt_cross_user_preview_for_partner(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0070: edge_partner must EXECUTE partner_receipt_cross_user_preview_for_partner';
  END IF;
END
$assert_0070$;
