-- 0111_partner_facility_scope_participation.sql
--
-- P5 section 142: a programme row that says declined or left gives an OPERATOR no reach to the facility (the G3 filter of design sections 6.1, 141.4).
--
-- WHAT WAS WRONG. private.has_facility_scope (0007, E6) lets an operator reach a facility through ANY app.facility_programme row of a trail it is scoped to, whatever the row's
-- participation says (design G3). Two consequences, both recorded: an operator could invite staff into a facility that had left the programme (6.1), and, since 0110 lets an operator
-- demote an existing row to left or declined (the only per-facility off-switch it has), a demoted row switched off the PLAYER lane at the facility but not the operator's reach
-- to it (141.1, matrix 88 F31, pinned there as a known limit that "flips when the reach is fixed").
--
-- WHAT THIS CHANGES (one function, CREATE OR REPLACE; owner, ACL, search_path, volatility, signature and default untouched; the 0007 body verbatim plus one predicate)
--   The operator leg of private.has_facility_scope counts a programme row only when its participation is invited or accepted. invited keeps the reach on purpose: it is the state in which
--   an operator brings a facility in (it invites the facility's staff). The direct leg (a partner_scope row on the facility itself) and the admin leg are untouched, so a facility's own
--   staff and managers keep their scope whatever the programme says. Every wrapper (is_operator_of_facility, is_manager_or_operator_of_facility), the facility_programme read policy
--   and the API views reach the operator leg through this function, so none of them is edited.
--
-- DELIBERATELY NOT HERE: rows are not deleted or repaired; the roster side (0110) is untouched; the player-lane participation gates (accepted only) are untouched.
-- Nothing from 0001-0110 is edited.

-- ============================================================================
-- 1. Before any change: the live function is the 0007 function (drift aborts here, with nothing changed)
-- ============================================================================
DO $pre_0111$
DECLARE
  v_p pg_proc%ROWTYPE;
BEGIN
  SELECT * INTO v_p FROM pg_proc WHERE oid = 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure;
  IF pg_catalog.md5(v_p.prosrc) <> '7f59ffd3e54275daf6f1aeadc554c60d' THEN
    RAISE EXCEPTION '0111: has_facility_scope is not the 0007 definition (its source hashes to %)', pg_catalog.md5(v_p.prosrc);
  END IF;
  IF pg_get_userbyid(v_p.proowner) <> 'private_definer' OR NOT v_p.prosecdef OR v_p.provolatile <> 's' OR v_p.proconfig IS DISTINCT FROM ARRAY['search_path=""'] THEN
    RAISE EXCEPTION '0111: has_facility_scope owner / security / volatility / search_path drifted';
  END IF;
  IF has_function_privilege('anon', 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('authenticated', 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('service_role', 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0111: has_facility_scope EXECUTE set drifted';
  END IF;
END
$pre_0111$;
CREATE TEMP TABLE m0111_before AS
  SELECT proacl::text AS acl, pg_get_function_arguments(oid) AS args, pg_get_userbyid(proowner) AS owner
  FROM pg_proc WHERE oid = 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure;

-- ============================================================================
-- 2. The function
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.has_facility_scope(
  p_uid uuid, p_facility_id text, p_roles app.partner_role[] DEFAULT ARRAY['staff', 'manager', 'operator']::app.partner_role[]
)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT
    private.is_admin(p_uid)
    OR EXISTS (
      SELECT 1
      FROM app.partner_member pm
      JOIN app.partner_scope ps ON ps.org_id = pm.org_id
      WHERE pm.user_id = p_uid
        AND pm.revoked_at IS NULL
        AND pm.role = ANY (p_roles)
        AND (
          ps.facility_id = p_facility_id
          OR (
            pm.role = 'operator'
            AND ps.trail_id IS NOT NULL
            AND EXISTS (
              SELECT 1 FROM app.facility_programme fp
              WHERE fp.facility_id = p_facility_id AND fp.trail_id = ps.trail_id
                AND fp.participation IN ('invited', 'accepted')
            )
          )
        )
    );
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Inventory
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0111 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = 'scope helper (0007); 0111 (section 142): the operator leg ignores programme rows that say declined or left'
WHERE schema_name = 'private'
  AND function_name = 'has_facility_scope';

DROP POLICY current_user_edit_function_inventory_0111 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 4. After: the new predicate is there, and nothing else about the function moved
-- ============================================================================
DO $assert_0111$
DECLARE
  v_b m0111_before%ROWTYPE;
  v_p pg_proc%ROWTYPE;
BEGIN
  SELECT * INTO v_b FROM m0111_before;
  SELECT * INTO v_p FROM pg_proc WHERE oid = 'private.has_facility_scope(uuid, text, app.partner_role[])'::regprocedure;
  IF v_p.prosrc NOT LIKE '%fp.participation IN (''invited'', ''accepted'')%' THEN
    RAISE EXCEPTION '0111: has_facility_scope must count only invited and accepted programme rows';
  END IF;
  IF v_p.proacl::text IS DISTINCT FROM v_b.acl OR pg_get_function_arguments(v_p.oid) IS DISTINCT FROM v_b.args OR pg_get_userbyid(v_p.proowner) IS DISTINCT FROM v_b.owner
     OR NOT v_p.prosecdef OR v_p.provolatile <> 's' OR v_p.proconfig IS DISTINCT FROM ARRAY['search_path=""'] THEN
    RAISE EXCEPTION '0111: the ACL, signature, owner, security, volatility or search_path of has_facility_scope changed';
  END IF;
END
$assert_0111$;
DROP TABLE m0111_before;
