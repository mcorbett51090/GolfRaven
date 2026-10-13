-- 0110_partner_facility_programme_roster_gate.sql
--
-- P5 section 139: a programme row for a facility that is not on the trail's roster can no longer be written.
--
-- WHAT WAS WRONG (design section 138, observed on the real database): private.has_facility_scope lets an OPERATOR reach a facility through any app.facility_programme row of a
-- trail it is scoped to (0007, E6), and private.partner_facility_programme_upsert_for_partner (0059) lets that operator write such a row for ANY facility id (the only check was the
-- table's foreign key). So an operator could write a row for a facility that is on no trail and from then on invite managers and staff there, with the reach rule behind PIN resets,
-- passkey revokes and recovery, and the printed QR of that facility as well.
--
-- WHAT THIS CHANGES
--   1. private_definer may read, under a partner binding only, the few catalog columns that say which facilities a trail's current roster names: catalog_roster_version(trail_id,
--      version), catalog_roster_member(trail_id, roster_version, course_id, any_of_course_ids, facility_id, hole_id, removed_on), catalog_course(id, facility_id) and catalog_hole(id,
--      course_id), each with one SELECT policy keyed on the partner binding kind (public catalog data, so that is the whole predicate), each registered in
--      private.definer_policy_allowlist with its derived expression (and in supabase/tests/fixtures/definer_policy_exprs.txt).
--   2. partner_facility_programme_upsert_for_partner (CREATE OR REPLACE; owner, ACL, search_path, volatility untouched): when no row exists yet for (trail, facility), the facility must
--      be on the trail's current roster, else 22023 (the Edge's 422 invalid_request). The check applies to an admin too. An EXISTING row stays editable, so that an operator can
--      still set participation to 'left' or 'declined'. The statuses are unchanged, so the Edge needs no change and there is no deploy-order hazard.
--
-- DELIBERATELY NOT HERE: rows written BEFORE this migration are not repaired (nothing is deployed, so none are expected); the G3 participation filter on has_facility_scope (declined and
-- left still give reach until it lands, next); a facility-side consent step (design 138.3 option D). Nothing from 0001-0109 is edited. Migration 0108 is left to the open draft that claims it (PR 162).

-- ============================================================================
-- 1. The catalog reads the gate needs
-- ============================================================================
GRANT SELECT (trail_id, version) ON app.catalog_roster_version TO private_definer;
CREATE POLICY pd_partner_roster_gate_roster_version_read ON app.catalog_roster_version FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');
GRANT SELECT (trail_id, roster_version, course_id, any_of_course_ids, facility_id, hole_id, removed_on) ON app.catalog_roster_member TO private_definer;
CREATE POLICY pd_partner_roster_gate_roster_member_read ON app.catalog_roster_member FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');
GRANT SELECT (id, facility_id) ON app.catalog_course TO private_definer;
CREATE POLICY pd_partner_roster_gate_course_read ON app.catalog_course FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');
GRANT SELECT (id, course_id) ON app.catalog_hole TO private_definer;
CREATE POLICY pd_partner_roster_gate_hole_read ON app.catalog_hole FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');

-- ============================================================================
-- 2. The upsert, with the gate
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_facility_programme_upsert_for_partner(
  p_trail_id text,
  p_facility_id text,
  p_participation text,
  p_stocks_markers boolean,
  p_holds_special_marker boolean,
  p_connectivity text,
  p_staff_network boolean,
  p_wifi_note text,
  p_qr_mode text
)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' OR p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = ''
     OR p_participation IS NULL OR p_participation NOT IN ('invited', 'accepted', 'declined', 'left')
     OR (p_connectivity IS NOT NULL AND p_connectivity NOT IN ('ok', 'weak', 'none'))
     OR p_qr_mode IS NULL OR p_qr_mode NOT IN ('rotating', 'static_pin', 'both')
     OR (p_wifi_note IS NOT NULL AND pg_catalog.char_length(p_wifi_note) > 500) THEN
    RAISE EXCEPTION 'partner_facility_programme_upsert_for_partner: a trail, a facility, participation and qr_mode are required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.trail_programme t WHERE t.trail_id = p_trail_id) THEN
    RETURN QUERY SELECT 'no_trail'::text;
    RETURN;
  END IF;
  -- 0110: a NEW (trail, facility) row needs the facility to be on the trail's current roster. A programme row is also what makes the facility reachable by an operator of the trail
  -- (private.has_facility_scope, E6), so writing one for a facility that is not the trail's is writing oneself a grant. An EXISTING row stays editable, so that an operator can still
  -- set participation to 'left' or 'declined' on a facility that has since left the roster. The current roster is the same test the player-side progress RPC uses (0011): the latest
  -- roster_version of the trail, members not removed; a member names the facility directly, through a course (course_id or any_of_course_ids) or through a hole.
  IF NOT EXISTS (SELECT 1 FROM app.facility_programme fp WHERE fp.trail_id = p_trail_id AND fp.facility_id = p_facility_id)
     AND NOT EXISTS (
       SELECT 1
       FROM app.catalog_roster_member rm
       WHERE rm.trail_id = p_trail_id
         AND rm.removed_on IS NULL
         AND rm.roster_version = (SELECT max(v.version) FROM app.catalog_roster_version v WHERE v.trail_id = p_trail_id)
         AND (
           rm.facility_id = p_facility_id
           OR EXISTS (SELECT 1 FROM app.catalog_course c
                      WHERE c.facility_id = p_facility_id AND (c.id = rm.course_id OR c.id = ANY (rm.any_of_course_ids)))
           OR EXISTS (SELECT 1 FROM app.catalog_hole h JOIN app.catalog_course c ON c.id = h.course_id
                      WHERE h.id = rm.hole_id AND c.facility_id = p_facility_id)
         )
     ) THEN
    RAISE EXCEPTION 'partner_facility_programme_upsert_for_partner: the facility is not on this trail''s roster' USING ERRCODE = '22023';
  END IF;
  INSERT INTO app.facility_programme (
    trail_id, facility_id, participation, stocks_markers, holds_special_marker,
    connectivity, staff_network, wifi_note, qr_mode
  ) VALUES (
    p_trail_id, p_facility_id, p_participation::app.programme_participation, p_stocks_markers, p_holds_special_marker,
    p_connectivity::app.connectivity, p_staff_network, p_wifi_note, p_qr_mode::app.qr_mode
  )
  ON CONFLICT (trail_id, facility_id) DO UPDATE SET
    participation = EXCLUDED.participation,
    stocks_markers = EXCLUDED.stocks_markers,
    holds_special_marker = EXCLUDED.holds_special_marker,
    connectivity = EXCLUDED.connectivity,
    staff_network = EXCLUDED.staff_network,
    wifi_note = EXCLUDED.wifi_note,
    qr_mode = EXCLUDED.qr_mode;
  PERFORM private.partner_audit_write('partner.facility_programme_upsert', 'app.facility_programme', p_trail_id || ':' || p_facility_id,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'participation', p_participation));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

COMMENT ON FUNCTION private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text) IS
  '0059/0110 (S6, section 139). edge_partner only; class A3 (operator of the trail). Upsert facility_programme (not pin_epoch); a NEW row needs the facility on the trail''s current roster (else 22023). Statuses: ok | no_trail.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Inventories
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0110 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0059/0110 (S6, section 139): edge_partner only; class A3; facility_programme upsert; a new row needs the facility on the trail''s current roster (22023)'
WHERE schema_name = 'private'
  AND function_name = 'partner_facility_programme_upsert_for_partner';

DROP POLICY current_user_edit_function_inventory_0110 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0110 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'catalog_roster_version', 'pd_partner_roster_gate_roster_version_read', 'SELECT', true, '0110 (section 139): public catalog data, readable under a partner binding by the facility programme upsert''s roster gate: the version numbers of a trail''s roster, to find the latest', 'private_definer'),
  ('app', 'catalog_roster_member', 'pd_partner_roster_gate_roster_member_read', 'SELECT', true, '0110 (section 139): public catalog data, readable under a partner binding by the facility programme upsert''s roster gate: a trail''s current roster members and what each names', 'private_definer'),
  ('app', 'catalog_course', 'pd_partner_roster_gate_course_read', 'SELECT', true, '0110 (section 139): public catalog data, readable under a partner binding by the facility programme upsert''s roster gate: the facility of a course', 'private_definer'),
  ('app', 'catalog_hole', 'pd_partner_roster_gate_hole_read', 'SELECT', true, '0110 (section 139): public catalog data, readable under a partner binding by the facility programme upsert''s roster gate: the course of a hole', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND pol.polname IN ('pd_partner_roster_gate_roster_version_read', 'pd_partner_roster_gate_roster_member_read', 'pd_partner_roster_gate_course_read', 'pd_partner_roster_gate_hole_read');
DO $assert_0110_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd\_partner\_roster\_gate\_%' AND using_expr IS NOT NULL) <> 4 THEN
    RAISE EXCEPTION '0110: an allowlist row names no live policy (its expression was not derived)';
  END IF;
END
$assert_0110_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0110 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 4. DO asserts
-- ============================================================================
DO $assert_0110$
DECLARE
  v_def text;
BEGIN
  SELECT pg_get_functiondef('private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT LIKE '%catalog_roster_member%' THEN
    RAISE EXCEPTION '0110: partner_facility_programme_upsert_for_partner must check the trail''s roster';
  END IF;
  IF NOT has_function_privilege('edge_partner', 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0110: the EXECUTE set of the facility programme upsert changed';
  END IF;
END
$assert_0110$;
