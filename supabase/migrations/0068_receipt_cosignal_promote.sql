-- 0068_receipt_cosignal_promote.sql
--
-- P5 receipt_green_fee promotion on cosignal (partner-auth-design §47): when
-- marker_cosignal_attach_for_actor completes a method=receipt purchase to valid,
-- promote the matching facility-level receipt_green_fee evidence row to
-- summary.status=approved with coSignalFix copied from the cosignal fix evidence.
-- Open receipt_cross_user_match review items block promotion (money-path §5).
--
-- WHAT THIS ADDS
--   1. GRANT UPDATE (summary) on app.evidence + pd_receipt_evidence_update
--      (own receipt_green_fee, pending → approved only).
--   2. pd_receipt_review_select so the attach definer can see open cross-user
--      review items on the actor's own purchases.
--   3. CREATE OR REPLACE marker_cosignal_attach_for_actor: after a successful
--      attested attach of a receipt purchase, promote the evidence row.
--
-- DELIBERATELY NOT HERE: partner resolve of receipt_cross_user_match, OCR, aHash, picker UI.
-- Nothing from 0001–0067 is edited (function body replaced in place; signature unchanged).

-- ============================================================================
-- 1. Grants and policies
-- ============================================================================
GRANT UPDATE (summary) ON app.evidence TO private_definer;

CREATE POLICY pd_receipt_evidence_update ON app.evidence FOR UPDATE TO private_definer
  USING (
    private.actor_uid() IS NOT NULL
    AND user_id = private.actor_uid()
    AND source = 'receipt_green_fee'
    AND status = 'accepted'
    AND (summary ->> 'status') = 'pending'
  )
  WITH CHECK (
    user_id = private.actor_uid()
    AND source = 'receipt_green_fee'
    AND status = 'accepted'
    AND (summary ->> 'status') = 'approved'
    AND summary ? 'coSignalFix'
    AND summary ? 'fingerprint'
  );

CREATE POLICY pd_receipt_review_select ON app.review_item FOR SELECT TO private_definer
  USING (
    private.actor_uid() IS NOT NULL
    AND kind = 'receipt_cross_user_match'
    AND subject_table = 'purchase_evidence'
    AND EXISTS (
      SELECT 1 FROM app.purchase_evidence pe
      WHERE pe.id = subject_id AND pe.user_id = private.actor_uid()
    )
  );

-- ============================================================================
-- 2. Definer (REPLACE 0051 body + receipt promote)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.marker_cosignal_attach_for_actor(
  p_facility_id text,
  p_at timestamptz,
  p_cosignal_grade text,
  p_cosignal_fix_id text,
  p_cosignal_evidence_id uuid
)
RETURNS TABLE (o_result text, o_purchase_id uuid, o_trail_id text, o_purchase_status text, o_credit_id uuid, o_credit_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_now timestamptz := pg_catalog.now();
  v_ref text;
  v_method app.purchase_method;
  v_row record;
  v_pstatus text;
  v_cstatus text;
  v_cosignal jsonb;
  v_credit uuid;
  v_credit_status text;
  v_existing_credit uuid;
  v_any boolean := false;
  v_tz text;
  v_check text;
  v_phash text;
  v_fix jsonb;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'marker_cosignal_attach_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'marker_cosignal_attach_for_actor: a system delegate may not attach a co-signal' USING ERRCODE = '42501';
  END IF;
  -- 0051: the app-review account can record no marker purchase and earn no credit (plan line 1871: "can receive no offer or special marker"). A returned status, this function's own
  -- refusal style: nothing has been written yet, and the Edge answers 403.
  IF private.is_demo_account(v_uid) THEN
    o_result := 'review_account';
    RETURN NEXT;
    RETURN;
  END IF;
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_at IS NULL OR p_cosignal_grade IS NULL OR p_cosignal_grade NOT IN ('attested', 'unattestable')
     OR p_cosignal_fix_id IS NULL OR p_cosignal_evidence_id IS NULL OR p_at < v_now - interval '7 days' OR p_at > v_now + interval '5 minutes' THEN
    RAISE EXCEPTION 'marker_cosignal_attach_for_actor: invalid arguments (a facility, a qualifying co-signal and a time within 7 days)' USING ERRCODE = '22023';
  END IF;

  -- The co-signal must be real: the bound actor's own evidence row for this fix, at this facility, with this grade and this captured time, used by no scan (private.marker_cosignal_check).
  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    o_result := 'no_pending_purchase';
    RETURN NEXT;
    RETURN;
  END IF;
  v_check := private.marker_cosignal_check(v_uid, p_facility_id, (p_at AT TIME ZONE v_tz)::date, p_at, p_cosignal_grade, p_cosignal_fix_id, p_cosignal_evidence_id);
  IF v_check <> 'ok' THEN
    o_result := v_check;
    RETURN NEXT;
    RETURN;
  END IF;

  -- The earliest awaiting scan of THIS player at THIS facility whose window holds the fix. Explicit filters on the bound uid (the HARD RULE), and the row lock.
  SELECT p.ref_id, p.method INTO v_ref, v_method
  FROM app.purchase_evidence p
  WHERE p.user_id = v_uid AND p.facility_id = p_facility_id AND p.status = 'pending'
    AND p.cosignal ? 'awaiting'
    AND (p.cosignal -> 'awaiting' ->> 'from')::timestamptz <= p_at
    AND p_at <= (p.cosignal -> 'awaiting' ->> 'to')::timestamptz
    AND v_now <= (p.cosignal -> 'awaiting' ->> 'until')::timestamptz
  ORDER BY p.created_at, p.id
  LIMIT 1;
  IF NOT FOUND THEN
    o_result := 'no_pending_purchase';
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_cosignal_grade = 'attested' THEN
    v_pstatus := 'valid';
    v_cstatus := 'credited';
  ELSE
    v_pstatus := 'held_review';
    v_cstatus := 'held_review';
  END IF;
  v_cosignal := pg_catalog.jsonb_build_object('fixId', p_cosignal_fix_id, 'grade', p_cosignal_grade, 'capturedAt', pg_catalog.to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'evidenceId', p_cosignal_evidence_id);

  FOR v_row IN
    SELECT p.id, p.trail_id
    FROM app.purchase_evidence p
    WHERE p.user_id = v_uid AND p.facility_id = p_facility_id AND p.status = 'pending' AND p.method = v_method AND p.ref_id IS NOT DISTINCT FROM v_ref
      AND p.cosignal ? 'awaiting'
    ORDER BY p.trail_id, p.id
    FOR UPDATE
  LOOP
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('marker-credit:' || v_uid::text || ':' || v_row.trail_id || ':' || p_facility_id, 0));
    UPDATE app.purchase_evidence p SET status = v_pstatus::app.purchase_status, cosignal = v_cosignal WHERE p.id = v_row.id AND p.user_id = v_uid;

    -- The credit of this purchase: a pending one linked to it (the scan wrote it, or the staff lane did), else the player's existing credited credit for this shop (the scan found
    -- the player already credited), else a NEW credit (the staff lane inserted the purchase row alone). Every statement filters by the bound uid.
    v_credit := NULL;
    v_credit_status := v_cstatus;
    v_existing_credit := NULL;
    IF v_cstatus = 'credited' THEN
      SELECT c.id INTO v_existing_credit FROM app.marker_credit c WHERE c.user_id = v_uid AND c.trail_id = v_row.trail_id AND c.facility_id = p_facility_id AND c.status = 'credited';
    END IF;
    SELECT c.id INTO v_credit FROM app.marker_credit c WHERE c.purchase_evidence_id = v_row.id AND c.user_id = v_uid AND c.status = 'pending';
    IF v_credit IS NOT NULL THEN
      IF v_existing_credit IS NOT NULL THEN
        -- the player became credited for this shop through another scan while this one waited: this pending credit is redundant
        UPDATE app.marker_credit c SET status = 'void' WHERE c.id = v_credit AND c.user_id = v_uid;
        v_credit := v_existing_credit;
        v_credit_status := 'credited';
      ELSE
        UPDATE app.marker_credit c SET status = v_cstatus::app.credit_status WHERE c.id = v_credit AND c.user_id = v_uid;
      END IF;
    ELSIF v_existing_credit IS NOT NULL THEN
      v_credit := v_existing_credit;
      v_credit_status := 'credited';
    ELSIF NOT EXISTS (SELECT 1 FROM app.marker_credit c WHERE c.purchase_evidence_id = v_row.id AND c.user_id = v_uid) THEN
      INSERT INTO app.marker_credit (user_id, trail_id, facility_id, purchase_evidence_id, status)
      VALUES (v_uid, v_row.trail_id, p_facility_id, v_row.id, v_cstatus::app.credit_status)
      RETURNING id INTO v_credit;
    END IF;

    v_any := true;
    o_result := 'attached';
    o_purchase_id := v_row.id;
    o_trail_id := v_row.trail_id;
    o_purchase_status := v_pstatus;
    o_credit_id := v_credit;
    o_credit_status := v_credit_status;
    RETURN NEXT;
  END LOOP;
  IF NOT v_any THEN
    o_result := 'no_pending_purchase';
    o_purchase_id := NULL;
    o_trail_id := NULL;
    o_purchase_status := NULL;
    o_credit_id := NULL;
    o_credit_status := NULL;
    RETURN NEXT;
  END IF;

  -- 0068: promote receipt_green_fee evidence when a receipt purchase becomes valid.
  IF v_any AND v_method = 'receipt' AND v_pstatus = 'valid' THEN
    SELECT rf.phash INTO v_phash
    FROM app.receipt_fingerprint rf
    JOIN app.purchase_evidence pe ON pe.id = rf.purchase_evidence_id
    WHERE pe.user_id = v_uid
      AND pe.facility_id = p_facility_id
      AND pe.method = 'receipt'
      AND pe.ref_id IS NOT DISTINCT FROM v_ref
    LIMIT 1;

    IF v_phash IS NOT NULL
       AND NOT EXISTS (
         SELECT 1
         FROM app.review_item ri
         JOIN app.purchase_evidence pe ON pe.id = ri.subject_id
         WHERE ri.kind = 'receipt_cross_user_match'
           AND ri.subject_table = 'purchase_evidence'
           AND ri.resolved_at IS NULL
           AND pe.user_id = v_uid
           AND pe.facility_id = p_facility_id
           AND pe.method = 'receipt'
           AND pe.ref_id IS NOT DISTINCT FROM v_ref
       )
    THEN
      SELECT e.summary -> 'fix' INTO v_fix
      FROM app.evidence e
      WHERE e.id = p_cosignal_evidence_id AND e.user_id = v_uid;

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
          AND e.source_ref = 'receipt:' || p_facility_id || ':' || v_phash
          AND e.status = 'accepted'
          AND (e.summary ->> 'status') = 'pending';
      END IF;
    END IF;
  END IF;
END;
$$;

COMMENT ON FUNCTION private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid) IS
  'Ownership: private_definer. 0046/0051 attach + 0068 receipt_green_fee promote on valid receipt. edge_actor only.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Registries
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0068 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0046+0051+0068: edge_actor only; cosignal attach + receipt_green_fee promote on valid receipt'
WHERE schema_name = 'private'
  AND function_name = 'marker_cosignal_attach_for_actor'
  AND identity_args = 'p_facility_id text, p_at timestamptz, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid';

DROP POLICY current_user_edit_function_inventory_0068 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_edit_definer_policy_allowlist_0068 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'evidence', 'pd_receipt_evidence_update', 'UPDATE', true, '0068: promote pending receipt_green_fee summary to approved with coSignalFix', 'private_definer'),
  ('app', 'review_item', 'pd_receipt_review_select', 'SELECT', true, '0068: attach reads open receipt_cross_user_match items on the actor''s purchases', 'private_definer')
ON CONFLICT (schema_name, table_name, policy_name) DO UPDATE
SET note = EXCLUDED.note, command = EXCLUDED.command, scoped = EXCLUDED.scoped, role_name = EXCLUDED.role_name;

UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = al.schema_name AND c.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN ('pd_receipt_evidence_update', 'pd_receipt_review_select');

DROP POLICY current_user_edit_definer_policy_allowlist_0068 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $assert_0068$
BEGIN
  IF NOT has_function_privilege('edge_actor', 'private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0068: edge_actor must still EXECUTE marker_cosignal_attach_for_actor';
  END IF;
  IF NOT has_column_privilege('private_definer', 'app.evidence', 'summary', 'UPDATE') THEN
    RAISE EXCEPTION '0068: private_definer must UPDATE app.evidence.summary';
  END IF;
END
$assert_0068$;
