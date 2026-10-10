-- 0072_course_pin_epoch_log_purge.sql
--
-- P5 §58: retention for app.course_pin_epoch_log left open by 0046 /
-- partner-auth-design §57.3. Bounded edge_system purge on the existing
-- retention-purge schedule (0040 / 0054 / 0071 shape).
--
-- WHAT THIS ADDS
--   private.purge_course_pin_epoch_log()
--     effective_from < now() - 90 days AND not the latest epoch for
--     that facility (pin_epoch < max(pin_epoch) per facility_id);
--     LIMIT 5000. The latest row is always kept so course_pin_epoch_at
--     still has a predecessor for pre-rotation instants.
--
-- POLICIES: floor repeated in private_definer DELETE + SELECT companion;
-- closed under a partner binding (0050 InitPlan form).
--
-- GRANTS: DELETE on course_pin_epoch_log (0046 granted INSERT+SELECT only).
-- EXECUTE for edge_system only.
--
-- DELIBERATELY NOT HERE: PIN alarm UI, pepper-rotation tooling, OCR /
-- aHash / UI flag flips / CAMERA.
-- Nothing from 0001–0071 is edited.

-- ============================================================================
-- 1. Grants and policies (private_definer)
-- ============================================================================
GRANT DELETE ON app.course_pin_epoch_log TO private_definer;

-- Floor only in the policies: a keep-latest subquery on the SAME table
-- recurses under FORCE RLS. The body keeps the latest epoch per facility;
-- pd_marker_scan_epoch_log_select (USING true) already lets the definer
-- read every row for that check.
CREATE POLICY pd_purge_course_pin_epoch_log ON app.course_pin_epoch_log FOR DELETE TO private_definer
  USING (effective_from < now() - interval '90 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_course_pin_epoch_log_r ON app.course_pin_epoch_log FOR SELECT TO private_definer
  USING (effective_from < now() - interval '90 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- ============================================================================
-- 2. Definer (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.purge_course_pin_epoch_log()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_deleted integer := 0;
  v_k integer;
  v_row record;
BEGIN
  -- Composite PK (facility_id, pin_epoch): batch once, delete by primary key (0050).
  FOR v_row IN
    SELECT s.facility_id, s.pin_epoch
    FROM app.course_pin_epoch_log s
    WHERE s.effective_from < pg_catalog.now() - interval '90 days'
      AND s.pin_epoch < (
        SELECT max(l.pin_epoch) FROM app.course_pin_epoch_log l WHERE l.facility_id = s.facility_id
      )
    LIMIT v_limit
  LOOP
    DELETE FROM app.course_pin_epoch_log e
    WHERE e.facility_id = v_row.facility_id AND e.pin_epoch = v_row.pin_epoch;
    GET DIAGNOSTICS v_k = ROW_COUNT;
    v_deleted := v_deleted + v_k;
  END LOOP;
  RETURN v_deleted;
END
$$;

-- Grants and comments inside the bracket (the owner makes them) — same as 0040 / 0071.
REVOKE EXECUTE ON FUNCTION private.purge_course_pin_epoch_log() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.purge_course_pin_epoch_log() TO edge_system;

COMMENT ON FUNCTION private.purge_course_pin_epoch_log() IS
  '0072 (§58). edge_system. Deletes course_pin_epoch_log rows whose effective_from is more than 90 days past and that are not the latest epoch for their facility, at most 5000 per call; returns the count. Floor repeated in pd_purge_course_pin_epoch_log[_r].';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

COMMENT ON TABLE app.course_pin_epoch_log IS
  '0046/0072. One row per PIN rotation of a facility: the new epoch, the one it replaced and the instant it took effect. Holds no user id and no PIN. Written only by the trigger on app.facility_programme.pin_epoch (private.course_pin_epoch_log_write); read by private.course_pin_epoch_at. Retention: private.purge_course_pin_epoch_log (effective_from older than 90 days; latest epoch per facility always kept).';

-- ============================================================================
-- 3. Registries
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'purge_course_pin_epoch_log', '', false, false, false, false, true, false, false, '0072 (§58): edge_system; course_pin_epoch_log rows older than 90 days except the latest epoch per facility, 5000 per call');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0072 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'course_pin_epoch_log', 'pd_purge_course_pin_epoch_log', 'DELETE', true, '0072 purge: epoch log rows older than 90 days; closed under a partner binding (keep-latest is body-only: same-table subquery recurses under FORCE RLS)', 'private_definer'),
  ('app', 'course_pin_epoch_log', 'pd_purge_course_pin_epoch_log_r', 'SELECT', true, 'row-visibility companion to pd_purge_course_pin_epoch_log', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN ('pd_purge_course_pin_epoch_log', 'pd_purge_course_pin_epoch_log_r');
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN ('pd_purge_course_pin_epoch_log', 'pd_purge_course_pin_epoch_log_r')) <> 2 THEN
    RAISE EXCEPTION '0072: expected 2 definer_policy_allowlist rows for the new purge policies';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0072 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $$
BEGIN
  IF NOT has_function_privilege('edge_system', 'private.purge_course_pin_epoch_log()', 'EXECUTE') THEN
    RAISE EXCEPTION '0072: edge_system must EXECUTE purge_course_pin_epoch_log';
  END IF;
  IF has_function_privilege('edge_actor', 'private.purge_course_pin_epoch_log()', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.purge_course_pin_epoch_log()', 'EXECUTE')
     OR has_function_privilege('anon', 'private.purge_course_pin_epoch_log()', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.purge_course_pin_epoch_log()', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.purge_course_pin_epoch_log()', 'EXECUTE') THEN
    RAISE EXCEPTION '0072: purge_course_pin_epoch_log must not be EXECUTEable by client / partner / service_role';
  END IF;
END
$$;
