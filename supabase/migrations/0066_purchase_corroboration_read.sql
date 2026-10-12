-- 0066_purchase_corroboration_read.sql
--
-- P5 purchase corroboration into scorePlay (partner-auth-design §44): edge_actor (and its
-- system_delegate drains) must load the bound actor's valid purchase_evidence rows into
-- scorePlay ctx WITHOUT a table GRANT on app.purchase_evidence (matrix 16 / 24 keep that
-- closed — writes stay behind marker-scan / receipt / attest definers).
--
-- WHAT THIS ADDS
--   1. private.list_valid_purchases_around_for_actor(facility, around_local_date): SECURITY DEFINER
--      under private_definer; RETURNS distinct (facility_id, local_date) of status='valid' rows for
--      the bound actor within ±7 days (CORROBORATION_WINDOW_DAYS). Allows kind user and
--      system_delegate (live intake + catalog drain / rescore); refuses unbound and partner.
--   2. GRANT EXECUTE TO edge_actor only. Reuses existing pd_marker_scan_purchase_select (no new
--      table policy / no edge_actor table privilege).
--
-- DELIBERATELY NOT HERE: receipt_green_fee writer, OCR, aHash, HEIC strip, picker UI.
-- Nothing from 0001–0065 is edited.

-- ============================================================================
-- 1. Definer
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.list_valid_purchases_around_for_actor(
  p_facility_id text,
  p_around_local_date date
)
RETURNS TABLE (
  o_facility_id text,
  o_local_date date
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
  v_window integer := 7; -- packages/rules CORROBORATION_WINDOW_DAYS; not caller-controlled
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'list_valid_purchases_around_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind IS DISTINCT FROM 'user' AND v_kind IS DISTINCT FROM 'system_delegate' THEN
    RAISE EXCEPTION 'list_valid_purchases_around_for_actor: only a user or system_delegate binding may read purchases' USING ERRCODE = '42501';
  END IF;
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_around_local_date IS NULL THEN
    RAISE EXCEPTION 'list_valid_purchases_around_for_actor: facility_id and around_local_date are required' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT DISTINCT pe.facility_id, pe.local_date
  FROM app.purchase_evidence pe
  WHERE pe.user_id = v_uid
    AND pe.facility_id = p_facility_id
    AND pe.status = 'valid'
    AND pe.local_date BETWEEN (p_around_local_date - v_window)
                          AND (p_around_local_date + v_window)
  ORDER BY pe.local_date ASC
  LIMIT 64;
END;
$$;

REVOKE ALL ON FUNCTION private.list_valid_purchases_around_for_actor(text, date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.list_valid_purchases_around_for_actor(text, date) TO edge_actor;

COMMENT ON FUNCTION private.list_valid_purchases_around_for_actor(text, date) IS
  '0066 (purchase corroboration). edge_actor only. Distinct (facility_id, local_date) of the bound actor''s own valid purchase_evidence within ±7 days. Allows user and system_delegate bindings (live scorePlay + catalog drain/rescore); no table GRANT for edge_actor.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Registries
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0066 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'list_valid_purchases_around_for_actor', 'p_facility_id text, p_around_local_date date', false, false, false, true, false, false, false,
   '0066: edge_actor only; scorePlay purchase corroboration read (±7d valid rows); user + system_delegate')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_actor = EXCLUDED.expected_edge_actor, note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0066 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

DO $assert_0066$
BEGIN
  IF NOT has_function_privilege('edge_actor', 'private.list_valid_purchases_around_for_actor(text, date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0066: edge_actor must EXECUTE list_valid_purchases_around_for_actor';
  END IF;
  IF has_function_privilege('edge_system', 'private.list_valid_purchases_around_for_actor(text, date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0066: edge_system must not EXECUTE list_valid_purchases_around_for_actor (binds via edge_actor delegate)';
  END IF;
  IF has_function_privilege('edge_partner', 'private.list_valid_purchases_around_for_actor(text, date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0066: edge_partner must not EXECUTE list_valid_purchases_around_for_actor';
  END IF;
  IF has_table_privilege('edge_actor', 'app.purchase_evidence', 'SELECT') THEN
    RAISE EXCEPTION '0066: edge_actor must still have no SELECT on app.purchase_evidence';
  END IF;
END
$assert_0066$;
