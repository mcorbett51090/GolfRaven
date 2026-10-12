-- 0076_course_qr_static_pin_cap_alert.sql
--
-- P5 §62: plan §8.3 course-QR static-PIN daily cap **alert** (signal, not
-- block). A facility's 26th printed-QR credit of a local date still credits;
-- at or above 25 the Edge writes one fraud_signal (kind course_qr_static_pin_cap)
-- after counting through a new _for_actor read (≥ so a multi-trail jump that
-- skips exactly 25 still alerts; open unique index dedupes). See
-- partner-auth-design §62 and p3-money-path-requirements.md (~L3974).
--
-- WHAT THIS ADDS
--   1. private.course_qr_static_pin_credit_count_for_actor(facility, local_date)
--      → integer: credited static_pin course_qr marker_credits for that
--      facility+local_date. edge_actor only; SECURITY DEFINER private_definer;
--      search_path=''; requires a user (or system_delegate) binding.
--   2. SELECT policies so the count can see facility-wide credited rows under
--      an actor binding (not only the bound actor's own):
--        pd_course_qr_cap_credit_select / pd_course_qr_cap_purchase_select.
--      Named outside pd_marker_scan_* so matrix 24's exact 22-policy pin stays.
--   3. Partial unique index on open fraud_signal rows of kind
--      course_qr_static_pin_cap keyed by (facilityId, localDate) — Repo#
--      fraudSignal.insert ON CONFLICT DO NOTHING for concurrency / retry.
--
-- DELIBERATELY NOT HERE: pepper-rotation tooling, OCR / aHash / UI flag flips /
-- CAMERA, partners PWA surface for this signal (fraud_signal is enough for
-- closable; portal one-liner not built).
-- Nothing from 0001–0075 is edited.

-- ============================================================================
-- 1. Dedup index (open signal per facility+localDate)
-- ============================================================================
CREATE UNIQUE INDEX fraud_signal_course_qr_static_pin_cap_open_idx
  ON app.fraud_signal ((detail ->> 'facilityId'), (detail ->> 'localDate'))
  WHERE kind = 'course_qr_static_pin_cap' AND cleared_at IS NULL;

COMMENT ON INDEX app.fraud_signal_course_qr_static_pin_cap_open_idx IS
  '0076 (§62): at most one open course_qr_static_pin_cap fraud_signal per (facilityId, localDate). Repo#fraudSignal.insert ON CONFLICT DO NOTHING against this index.';

-- ============================================================================
-- 2. SELECT policies (private_definer under actor binding)
-- ============================================================================
-- Narrow: only credited credits, and only course_qr/static_pin purchases.
-- OR'd with existing own-row policies; other definers still filter by uid in SQL.
CREATE POLICY pd_course_qr_cap_credit_select ON app.marker_credit FOR SELECT TO private_definer
  USING (
    private.actor_uid() IS NOT NULL
    AND status = 'credited'
  );

CREATE POLICY pd_course_qr_cap_purchase_select ON app.purchase_evidence FOR SELECT TO private_definer
  USING (
    private.actor_uid() IS NOT NULL
    AND method = 'course_qr'
    AND qr_variant = 'static_pin'
  );

-- ============================================================================
-- 3. Definer
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.course_qr_static_pin_credit_count_for_actor(
  p_facility_id text,
  p_local_date date
)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_n integer;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'course_qr_static_pin_credit_count_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind IS DISTINCT FROM 'user' AND v_kind IS DISTINCT FROM 'system_delegate' THEN
    RAISE EXCEPTION 'course_qr_static_pin_credit_count_for_actor: only a user or system_delegate binding may count credits' USING ERRCODE = '42501';
  END IF;
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_local_date IS NULL THEN
    RAISE EXCEPTION 'course_qr_static_pin_credit_count_for_actor: facility_id and local_date are required' USING ERRCODE = '22023';
  END IF;

  SELECT count(*)::integer INTO v_n
  FROM app.marker_credit mc
  JOIN app.purchase_evidence pe ON pe.id = mc.purchase_evidence_id
  WHERE mc.facility_id = p_facility_id
    AND mc.status = 'credited'
    AND pe.facility_id = p_facility_id
    AND pe.local_date = p_local_date
    AND pe.method = 'course_qr'
    AND pe.qr_variant = 'static_pin';

  RETURN v_n;
END;
$$;

REVOKE ALL ON FUNCTION private.course_qr_static_pin_credit_count_for_actor(text, date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.course_qr_static_pin_credit_count_for_actor(text, date) TO edge_actor;

COMMENT ON FUNCTION private.course_qr_static_pin_credit_count_for_actor(text, date) IS
  '0076 (§62, plan §8.3). edge_actor only. Count of credited static_pin course_qr marker_credits at facility+local_date (facility-wide). Allows user and system_delegate bindings; refuses unbound / partner. No edge_actor table SELECT.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Inventories
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0076 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'course_qr_static_pin_credit_count_for_actor', 'p_facility_id text, p_local_date date', false, false, false, true, false, false, false,
   '0076 (§62): edge_actor only; plan §8.3 static-PIN daily cap count (signal, not block)')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_actor = EXCLUDED.expected_edge_actor, note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0076 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0076 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'marker_credit', 'pd_course_qr_cap_credit_select', 'SELECT', true,
   '0076 (§62): bound actor may read credited marker_credit rows for facility-wide static-PIN cap count', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_course_qr_cap_purchase_select', 'SELECT', true,
   '0076 (§62): bound actor may read course_qr/static_pin purchase_evidence for facility-wide static-PIN cap count', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_course_qr_cap_credit_select', 'pd_course_qr_cap_purchase_select');
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN ('pd_course_qr_cap_credit_select', 'pd_course_qr_cap_purchase_select')) <> 2 THEN
    RAISE EXCEPTION '0076: expected 2 definer_policy_allowlist rows for pd_course_qr_cap_*';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0076 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $assert_0076$
BEGIN
  IF NOT has_function_privilege('edge_actor', 'private.course_qr_static_pin_credit_count_for_actor(text, date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0076: edge_actor must EXECUTE course_qr_static_pin_credit_count_for_actor';
  END IF;
  IF has_function_privilege('edge_system', 'private.course_qr_static_pin_credit_count_for_actor(text, date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0076: edge_system must not EXECUTE course_qr_static_pin_credit_count_for_actor';
  END IF;
  IF has_function_privilege('edge_partner', 'private.course_qr_static_pin_credit_count_for_actor(text, date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0076: edge_partner must not EXECUTE course_qr_static_pin_credit_count_for_actor';
  END IF;
  IF has_table_privilege('edge_actor', 'app.marker_credit', 'SELECT') THEN
    RAISE EXCEPTION '0076: edge_actor must still have no SELECT on app.marker_credit';
  END IF;
  IF has_table_privilege('edge_actor', 'app.purchase_evidence', 'SELECT') THEN
    RAISE EXCEPTION '0076: edge_actor must still have no SELECT on app.purchase_evidence';
  END IF;
  IF (SELECT count(*)::int FROM pg_indexes
      WHERE schemaname = 'app' AND indexname = 'fraud_signal_course_qr_static_pin_cap_open_idx') <> 1 THEN
    RAISE EXCEPTION '0076: expected fraud_signal_course_qr_static_pin_cap_open_idx';
  END IF;
END
$assert_0076$;
