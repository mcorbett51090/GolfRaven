-- 0067_receipt_green_fee_evidence.sql
--
-- P5 receipt_green_fee writer (partner-auth-design §46 / money-path §2 + §5): extend
-- private.receipt_intake_for_actor so a successful player-lane receipt upload also writes
-- ONE facility-level app.evidence row (source=receipt_green_fee). POST /v1/evidence keeps
-- receipt_green_fee in REJECTED_SOURCES — forge surface stays closed.
--
-- WHAT THIS ADDS
--   1. private_definer INSERT grant + policy on app.evidence for receipt_green_fee only
--      (own user, accepted, course_id NULL, device_id NULL).
--   2. CREATE OR REPLACE receipt_intake_for_actor: after the purchase/credit loop, INSERT
--      one evidence row keyed by source_ref = 'receipt:' || facility || ':' || phash
--      (ON CONFLICT DO NOTHING). summary.status = pending for ok/review; void +
--      voidReason=duplicate for same-user re-upload when no prior evidence row exists.
--
-- DELIBERATELY NOT HERE: OCR, perceptual aHash, picker UI, coSignalFix→approved, review resolve.
-- Nothing from 0001–0066 is edited (function body replaced in place; signature unchanged).

-- ============================================================================
-- 1. Grants and policy
-- ============================================================================
GRANT INSERT (
  user_id, device_id, source, source_ref, input_hash,
  course_id, facility_id, local_date, summary, integrity, cosignal,
  attestation_grade, status
) ON app.evidence TO private_definer;

CREATE POLICY pd_receipt_evidence_insert ON app.evidence FOR INSERT TO private_definer
  WITH CHECK (
    private.actor_uid() IS NOT NULL
    AND user_id = private.actor_uid()
    AND source = 'receipt_green_fee'
    AND status = 'accepted'
    AND course_id IS NULL
    AND device_id IS NULL
  );

-- ============================================================================
-- 2. Definer (REPLACE 0064 body + evidence write)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.receipt_intake_for_actor(
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
  v_source_ref text;
  v_summary jsonb;
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

  -- 0067: one facility-level receipt_green_fee evidence row (idempotent on facility+phash).
  IF v_dedupe_called THEN
    v_source_ref := 'receipt:' || p_facility_id || ':' || p_phash;
    IF v_top_status = 'duplicate' THEN
      v_summary := pg_catalog.jsonb_build_object(
        'localDate', v_local::text,
        'status', 'void',
        'fingerprint', p_phash,
        'voidReason', 'duplicate'
      );
    ELSE
      v_summary := pg_catalog.jsonb_build_object(
        'localDate', v_local::text,
        'status', 'pending',
        'fingerprint', p_phash
      );
    END IF;
    INSERT INTO app.evidence (
      user_id, device_id, source, source_ref, input_hash,
      course_id, facility_id, local_date, summary, integrity, cosignal,
      attestation_grade, status
    ) VALUES (
      v_uid,
      NULL,
      'receipt_green_fee',
      v_source_ref,
      p_phash,
      NULL,
      p_facility_id,
      v_local,
      v_summary,
      '{}'::jsonb,
      '{}'::jsonb,
      'unattestable',
      'accepted'
    )
    ON CONFLICT (user_id, source, source_ref) DO NOTHING;
  END IF;
END
$$;

COMMENT ON FUNCTION private.receipt_intake_for_actor(text, text, text, date, text) IS
  'Ownership: private_definer. 0064 intake + 0067 receipt_green_fee evidence write. edge_actor only. Storage path + phash; one pending purchase per eligible trail; dedupe on first purchase; one facility-level evidence row (pending or void/duplicate). Statuses: ok | duplicate | review | no_facility | no_programme | review_account | bad_args. o_dedupe: clean | same_user | cross_user.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Registries
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0067 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0064+0067: edge_actor only; player receipt upload intake + dedupe + receipt_green_fee evidence'
WHERE schema_name = 'private'
  AND function_name = 'receipt_intake_for_actor'
  AND identity_args = 'p_facility_id text, p_phash text, p_storage_object text, p_local_date date, p_receipt_number_ocr text';

DROP POLICY current_user_edit_function_inventory_0067 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_edit_definer_policy_allowlist_0067 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'evidence', 'pd_receipt_evidence_insert', 'INSERT', true, '0067: receipt_intake writes receipt_green_fee evidence for the bound actor', 'private_definer')
ON CONFLICT (schema_name, table_name, policy_name) DO UPDATE
SET note = EXCLUDED.note, command = EXCLUDED.command, scoped = EXCLUDED.scoped, role_name = EXCLUDED.role_name;

UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = al.schema_name AND c.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name = 'pd_receipt_evidence_insert';

DROP POLICY current_user_edit_definer_policy_allowlist_0067 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $assert_0067$
BEGIN
  IF NOT has_function_privilege('edge_actor', 'private.receipt_intake_for_actor(text, text, text, date, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0067: edge_actor must still EXECUTE receipt_intake_for_actor';
  END IF;
  IF has_table_privilege('edge_actor', 'app.purchase_evidence', 'SELECT') THEN
    RAISE EXCEPTION '0067: edge_actor must still have no SELECT on app.purchase_evidence';
  END IF;
  IF NOT has_column_privilege('private_definer', 'app.evidence', 'source', 'INSERT') THEN
    RAISE EXCEPTION '0067: private_definer must have column INSERT on app.evidence.source';
  END IF;
END
$assert_0067$;
