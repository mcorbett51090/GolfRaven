-- 0110_partner_facility_programme_roster.sql
--
-- P5 section 140 (the owner's decision A on the finding of section 138): the programme editor refuses a facility that is not on the trail's CURRENT roster.
--
-- WHAT WAS WRONG (observed on the real database, section 138.1). private.has_facility_scope (0007, E6) lets an OPERATOR reach a facility when app.facility_programme holds ANY row
-- (trail, facility) for a trail the operator is scoped to. private.partner_facility_programme_upsert_for_partner (0059, class A3) writes those rows for ANY p_facility_id: its only
-- checks were the argument shapes, that the trail has a trail_programme row, and the table's foreign key to catalog_facility. So an operator could write itself reach to a facility
-- that has nothing to do with its trail and then invite managers there, reset PINs, revoke passkeys and rotate that facility's PIN. The intended boundary is the opposite (PA-15 and
-- 6.1: "operator at a facility not on its trail: 403"; the S2a as-built item 10: keeping the programme and the roster in step is the programme editor's job).
--
-- WHAT THIS CHANGES (one function, CREATE OR REPLACE; owner, ACL, search_path, SECURITY DEFINER and volatility untouched; has_facility_scope is NOT touched)
--   1. partner_facility_programme_upsert_for_partner: after the existing checks (authorise, argument shapes, no_trail) and BEFORE the write, the facility must be on the roster of
--      THIS trail, or the call raises 22023 (the Edge maps it to 422 invalid_request, as for every other malformed argument; the same code the section 137 refusal uses). The roster
--      test is the one 138.3 names: a member of the trail's LATEST roster version (the greatest catalog_roster_version.version, as api.my_progress reads it) with removed_on IS NULL
--      that names the facility (facility_id), or names a course of it (course_id), a hole of it (hole_id) or a course of it inside any_of_course_ids. "A facility that does not exist"
--      is the same refusal as "a facility that is not on the roster" (before this a nonexistent facility id was a raw foreign-key error, 23503, which the Edge does not translate).
--      The rule holds for EVERY caller the definer authorises (an operator of the trail, and an admin); nobody is exempt.
--   2. private_definer gains the narrowest read the check needs. The definer runs as private_definer under FORCE ROW LEVEL SECURITY and, until now, could read none of the four catalog
--      tables the roster is made of. Column-level SELECT (not table-level) on exactly the columns the check reads, and four SELECT policies keyed on the partner BINDING (never a GUC):
--      the roster rows (catalog_roster_member, catalog_roster_version) only for a trail the bound member operates (or an admin), and the course / hole -> facility mapping
--      (catalog_course, catalog_hole; public catalogue data that the authenticated role already reads in full) only under a partner binding. No other role gains anything.
--   3. Registries: the four policies in private.definer_policy_allowlist (the checked-in fixture supabase/tests/fixtures/definer_policy_exprs.txt is regenerated from a live catalogue);
--      the function_inventory note and the function comment.
--
-- THE SELF-CHECK (the 0051 / 0108 shape, with the drift detection moved BEFORE the DDL). The live source of the function is captured first. Before ANY statement that changes the
-- database: its source must hash to the pinned md5 of the 0059 definition, its owner / SECURITY DEFINER / search_path / volatility / return shape / EXECUTE set / comment must be what 0059
-- left, and the one intended edit must apply to it exactly once. Only then do the grants, the policies and the function change. After the redefinition the migration asserts again that the
-- live source IS that edited source, that every attribute is unchanged, and that the new reads are exactly the intended ones. (A post-check alone leaves the redefinition applied when
-- a runner does not wrap the file in a transaction; the pin does not.)
--
-- DELIBERATELY NOT HERE (section 140): the G3 participation filter (a declined / left facility giving no reach) is a separate decision the owner has not made; rows written BEFORE
-- this migration are not touched, listed or repaired by it (the query in tools/db/facility-programme-off-roster.sql lists them for the first deploy); any other consumer of
-- has_facility_scope. Nothing from 0001-0109 is edited and this migration changes no data.

-- ============================================================================
-- 1. The pre-flight: what the function is NOW, proved BEFORE anything changes
-- ============================================================================
CREATE TEMP TABLE r110_fn (
  fn_oid oid NOT NULL,
  attr text NOT NULL,
  cmt text,
  old_src text NOT NULL,
  exp_src text
);
CREATE FUNCTION pg_temp.r110_edit(p_src text, p_old text, p_new text) RETURNS text LANGUAGE plpgsql AS $f$
BEGIN
  IF p_src IS NULL OR p_old IS NULL OR p_new IS NULL OR p_old = '' OR p_old = p_new
     OR (length(p_src) - length(replace(p_src, p_old, ''))) <> length(p_old) THEN
    RAISE EXCEPTION '0110: the live definition does not contain the expected fragment exactly once (it drifted from 0059): %', left(p_old, 70);
  END IF;
  RETURN replace(p_src, p_old, p_new);
END
$f$;
INSERT INTO r110_fn (fn_oid, attr, cmt, old_src)
SELECT p.oid,
       md5(ROW(pg_get_userbyid(p.proowner), p.proacl, p.proconfig, p.prosecdef, p.prolang, p.prorettype, p.proretset, pg_get_function_result(p.oid), pg_get_function_arguments(p.oid),
               p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults, p.prokind, p.procost, p.prorows, p.proargmodes, p.proargnames)::text),
       obj_description(p.oid, 'pg_proc'), p.prosrc
FROM pg_proc p
WHERE p.oid = 'private.partner_facility_programme_upsert_for_partner(text, text, text, boolean, boolean, text, boolean, text, text)'::regprocedure;

-- The one intended edit: the old fragment must occur exactly once in the live source (pg_temp.r110_edit raises otherwise, BEFORE anything is redefined).
UPDATE r110_fn SET exp_src = pg_temp.r110_edit(old_src,
    $o1$    RETURN QUERY SELECT 'no_trail'::text;
    RETURN;
  END IF;
  INSERT INTO app.facility_programme ($o1$,
    $n1$    RETURN QUERY SELECT 'no_trail'::text;
    RETURN;
  END IF;
  -- 0110 (section 140): the facility is on THIS trail's CURRENT roster: a member of the trail's latest roster version, not removed, that names the facility, a course of it, a hole of it, or a
  -- course of it inside any_of_course_ids. An unknown facility is the same refusal. The check precedes the write, so a refused call writes (and audits) nothing, and the roster is read in
  -- THIS statement's snapshot (partner_authorize has already required READ COMMITTED), so a roster version that commits later is seen by the next call and not by this one.
  IF NOT EXISTS (
    SELECT 1
    FROM app.catalog_roster_member rm
    WHERE rm.trail_id = p_trail_id
      AND rm.removed_on IS NULL
      AND rm.roster_version = (SELECT pg_catalog.max(v.version) FROM app.catalog_roster_version v WHERE v.trail_id = p_trail_id)
      AND (
        rm.facility_id = p_facility_id
        OR rm.course_id IN (SELECT c.id FROM app.catalog_course c WHERE c.facility_id = p_facility_id)
        OR rm.hole_id IN (SELECT h.id FROM app.catalog_hole h JOIN app.catalog_course c ON c.id = h.course_id WHERE c.facility_id = p_facility_id)
        OR rm.any_of_course_ids && ARRAY(SELECT c.id FROM app.catalog_course c WHERE c.facility_id = p_facility_id)
      )
  ) THEN
    RAISE EXCEPTION 'partner_facility_programme_upsert_for_partner: the facility must be on the current roster of this trail' USING ERRCODE = '22023';
  END IF;
  INSERT INTO app.facility_programme ($n1$);

-- THE PRE-DDL CHECK. Nothing below this DO block runs if it raises (the harness applies a migration with ON_ERROR_STOP; a transactional runner rolls the file back as well).
DO $r110_pre$
DECLARE
  r record;
  v_acl text;
BEGIN
  SELECT * INTO r FROM r110_fn;
  IF r.fn_oid IS NULL OR r.exp_src IS NULL OR r.exp_src = r.old_src THEN
    RAISE EXCEPTION '0110: expected to capture partner_facility_programme_upsert_for_partner and derive an edited source for it';
  END IF;
  -- (a) the pinned pre-image: the md5 of the function source exactly as 0059 wrote it. Drift OUTSIDE the edited fragment (a comment, a changed check, another migration's redefinition) is caught
  --     here, before any DDL; the fragment match above only proves the fragment.
  IF md5(r.old_src) <> '36e5276bb565830e893071d9e8d795c0' THEN
    RAISE EXCEPTION '0110: the live partner_facility_programme_upsert_for_partner is not the 0059 definition (its source hashes to %, expected 36e5276bb565830e893071d9e8d795c0); another migration redefined it, or it was edited by hand. Nothing was changed.', md5(r.old_src);
  END IF;
  -- (b) the attributes this migration promises not to move, as they stand NOW
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p
    WHERE p.oid = r.fn_oid AND pg_get_userbyid(p.proowner) = 'private_definer' AND p.prosecdef AND p.prokind = 'f' AND p.provolatile = 'v'
      AND p.proconfig = ARRAY['search_path=""'] AND p.proretset AND pg_get_function_result(p.oid) = 'TABLE(o_status text)'
  ) THEN
    RAISE EXCEPTION '0110: the live partner_facility_programme_upsert_for_partner has attributes other than 0059 gave it (owner, SECURITY DEFINER, search_path, volatility, return shape). Nothing was changed.';
  END IF;
  SELECT string_agg(a.grantee::regrole::text || ':' || a.privilege_type, ',' ORDER BY a.grantee::regrole::text)
    INTO v_acl
  FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
  WHERE p.oid = r.fn_oid;
  IF v_acl IS DISTINCT FROM 'edge_partner:EXECUTE,private_definer:EXECUTE' THEN
    RAISE EXCEPTION '0110: the EXECUTE set of partner_facility_programme_upsert_for_partner is not edge_partner + the owner alone (it is: %). Nothing was changed.', v_acl;
  END IF;
  IF r.cmt IS DISTINCT FROM '0059 (S6). edge_partner only; class A3 (operator of the trail). Upsert facility_programme (not pin_epoch). Statuses: ok | no_trail.' THEN
    RAISE EXCEPTION '0110: the comment of partner_facility_programme_upsert_for_partner is not the 0059 comment. Nothing was changed.';
  END IF;
  -- (c) the catalogue columns the check reads exist, and none of the four policies this migration creates exists yet
  IF (SELECT count(*) FROM pg_attribute a
      WHERE NOT a.attisdropped AND a.attnum > 0 AND (
        (a.attrelid = 'app.catalog_roster_member'::regclass AND a.attname IN ('trail_id', 'roster_version', 'removed_on', 'course_id', 'any_of_course_ids', 'facility_id', 'hole_id'))
        OR (a.attrelid = 'app.catalog_roster_version'::regclass AND a.attname IN ('trail_id', 'version'))
        OR (a.attrelid = 'app.catalog_course'::regclass AND a.attname IN ('id', 'facility_id'))
        OR (a.attrelid = 'app.catalog_hole'::regclass AND a.attname IN ('id', 'course_id')))) <> 13 THEN
    RAISE EXCEPTION '0110: the roster / course / hole columns the facility check reads are not all there. Nothing was changed.';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_policy pol WHERE pol.polname IN ('pd_partner_roster_read_member', 'pd_partner_roster_read_version', 'pd_partner_roster_read_course', 'pd_partner_roster_read_hole')) THEN
    RAISE EXCEPTION '0110: one of the roster read policies already exists. Nothing was changed.';
  END IF;
END
$r110_pre$;

-- ============================================================================
-- 2. private_definer: the narrowest read the check needs (column-level, binding-keyed policies; no other role gains anything)
-- ============================================================================
GRANT SELECT (trail_id, roster_version, removed_on, course_id, any_of_course_ids, facility_id, hole_id) ON app.catalog_roster_member TO private_definer;
GRANT SELECT (trail_id, version) ON app.catalog_roster_version TO private_definer;
GRANT SELECT (id, facility_id) ON app.catalog_course TO private_definer;
GRANT SELECT (id, course_id) ON app.catalog_hole TO private_definer;

-- The roster rows of a trail: only for a trail the bound partner member operates (or an admin), the shape of the 0059 programme policies.
CREATE POLICY pd_partner_roster_read_member ON app.catalog_roster_member FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
CREATE POLICY pd_partner_roster_read_version ON app.catalog_roster_version FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND (private.partner_bound_admin() OR private.partner_bound_operator_at_trail(trail_id)));
-- The course / hole -> facility mapping is public catalogue data (authenticated reads it all); under a partner binding only, like pd_course_qr_staff_facility_read (0055).
CREATE POLICY pd_partner_roster_read_course ON app.catalog_course FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');
CREATE POLICY pd_partner_roster_read_hole ON app.catalog_hole FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner');

-- ============================================================================
-- 3. The function (the body of 0059 verbatim plus the one check; owner / ACL / search_path / volatility are kept by CREATE OR REPLACE and asserted below)
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
  -- 0110 (section 140): the facility is on THIS trail's CURRENT roster: a member of the trail's latest roster version, not removed, that names the facility, a course of it, a hole of it, or a
  -- course of it inside any_of_course_ids. An unknown facility is the same refusal. The check precedes the write, so a refused call writes (and audits) nothing, and the roster is read in
  -- THIS statement's snapshot (partner_authorize has already required READ COMMITTED), so a roster version that commits later is seen by the next call and not by this one.
  IF NOT EXISTS (
    SELECT 1
    FROM app.catalog_roster_member rm
    WHERE rm.trail_id = p_trail_id
      AND rm.removed_on IS NULL
      AND rm.roster_version = (SELECT pg_catalog.max(v.version) FROM app.catalog_roster_version v WHERE v.trail_id = p_trail_id)
      AND (
        rm.facility_id = p_facility_id
        OR rm.course_id IN (SELECT c.id FROM app.catalog_course c WHERE c.facility_id = p_facility_id)
        OR rm.hole_id IN (SELECT h.id FROM app.catalog_hole h JOIN app.catalog_course c ON c.id = h.course_id WHERE c.facility_id = p_facility_id)
        OR rm.any_of_course_ids && ARRAY(SELECT c.id FROM app.catalog_course c WHERE c.facility_id = p_facility_id)
      )
  ) THEN
    RAISE EXCEPTION 'partner_facility_programme_upsert_for_partner: the facility must be on the current roster of this trail' USING ERRCODE = '22023';
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
  '0059/0110 (S6, section 140). edge_partner only; class A3 (operator of the trail, or an admin). Upsert facility_programme (not pin_epoch). The facility must be on the trail''s current roster (the latest roster version, a member not removed that names the facility or a course / hole / any_of course of it), else 22023; no one is exempt. Statuses: ok | no_trail.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. The self-check, second half
-- ============================================================================
DO $r110_post$
DECLARE
  r record;
  v_attr text;
  v_src text;
  v_cmt text;
  v_acl text;
BEGIN
  SELECT * INTO r FROM r110_fn;
  SELECT md5(ROW(pg_get_userbyid(p.proowner), p.proacl, p.proconfig, p.prosecdef, p.prolang, p.prorettype, p.proretset, pg_get_function_result(p.oid), pg_get_function_arguments(p.oid),
                 p.provolatile, p.proparallel, p.proisstrict, p.proleakproof, p.pronargdefaults, p.prokind, p.procost, p.prorows, p.proargmodes, p.proargnames)::text),
         p.prosrc, obj_description(p.oid, 'pg_proc')
    INTO v_attr, v_src, v_cmt
  FROM pg_proc p WHERE p.oid = r.fn_oid;
  IF v_attr IS DISTINCT FROM r.attr THEN
    RAISE EXCEPTION '0110: partner_facility_programme_upsert_for_partner changed an attribute (owner, ACL, search_path, SECURITY DEFINER, volatility, return shape, ...) when it was redefined';
  END IF;
  IF v_src IS DISTINCT FROM r.exp_src OR v_src = r.old_src THEN
    RAISE EXCEPTION '0110: partner_facility_programme_upsert_for_partner differs from its previous definition by more than the intended roster check';
  END IF;
  IF v_cmt IS NULL OR v_cmt NOT LIKE '0059/0110 (S6, section 140)%' THEN
    RAISE EXCEPTION '0110: the comment of partner_facility_programme_upsert_for_partner was not updated';
  END IF;
  -- the leading authorisation call is still there and still first (check 14), and the roster check precedes the write
  IF position('v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY[''operator'']::app.partner_role[], ''A3'');' IN v_src) = 0
     OR position('catalog_roster_member' IN v_src) = 0
     OR position('catalog_roster_member' IN v_src) > position('INSERT INTO app.facility_programme' IN v_src) THEN
    RAISE EXCEPTION '0110: the roster check must sit after the authorisation call and before the write';
  END IF;
  -- the EXECUTE set did not move
  SELECT string_agg(a.grantee::regrole::text || ':' || a.privilege_type, ',' ORDER BY a.grantee::regrole::text)
    INTO v_acl
  FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
  WHERE p.oid = r.fn_oid;
  IF v_acl IS DISTINCT FROM 'edge_partner:EXECUTE,private_definer:EXECUTE' THEN
    RAISE EXCEPTION '0110: the EXECUTE set of partner_facility_programme_upsert_for_partner moved (now: %)', v_acl;
  END IF;
  -- the new reads are exactly the intended ones: no table-level privilege of any kind (SELECT included), and column-level SELECT on exactly the 13 columns the check reads and nothing else
  IF EXISTS (SELECT 1 FROM unnest(ARRAY['app.catalog_roster_member', 'app.catalog_roster_version', 'app.catalog_course', 'app.catalog_hole']) t(n)
             WHERE has_table_privilege('private_definer', t.n, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) THEN
    RAISE EXCEPTION '0110: private_definer holds a table-level privilege on a roster table (only column-level SELECT was intended)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_attribute a
             WHERE a.attrelid IN ('app.catalog_roster_member'::regclass, 'app.catalog_roster_version'::regclass, 'app.catalog_course'::regclass, 'app.catalog_hole'::regclass)
               AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'INSERT,UPDATE,REFERENCES')) THEN
    RAISE EXCEPTION '0110: private_definer holds a column privilege other than SELECT on a roster table';
  END IF;
  IF (SELECT count(*) FROM pg_attribute a
      WHERE a.attrelid IN ('app.catalog_roster_member'::regclass, 'app.catalog_roster_version'::regclass, 'app.catalog_course'::regclass, 'app.catalog_hole'::regclass)
        AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'SELECT')) <> 13
     OR (SELECT count(*) FROM pg_attribute a
         WHERE NOT a.attisdropped AND a.attnum > 0 AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'SELECT') AND (
           (a.attrelid = 'app.catalog_roster_member'::regclass AND a.attname IN ('trail_id', 'roster_version', 'removed_on', 'course_id', 'any_of_course_ids', 'facility_id', 'hole_id'))
           OR (a.attrelid = 'app.catalog_roster_version'::regclass AND a.attname IN ('trail_id', 'version'))
           OR (a.attrelid = 'app.catalog_course'::regclass AND a.attname IN ('id', 'facility_id'))
           OR (a.attrelid = 'app.catalog_hole'::regclass AND a.attname IN ('id', 'course_id')))) <> 13 THEN
    RAISE EXCEPTION '0110: private_definer does not hold column-level SELECT on exactly the 13 intended roster columns';
  END IF;
  IF (SELECT count(*) FROM pg_policy pol WHERE pol.polname IN ('pd_partner_roster_read_member', 'pd_partner_roster_read_version', 'pd_partner_roster_read_course', 'pd_partner_roster_read_hole')
        AND pol.polcmd = 'r' AND pol.polpermissive AND pol.polroles = ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'private_definer')]
        AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%partner_binding_kind%' AND pg_get_expr(pol.polqual, pol.polrelid) NOT LIKE '%current\_setting%') <> 4 THEN
    RAISE EXCEPTION '0110: expected four SELECT policies for private_definer, each keyed on the partner binding (none on a setting)';
  END IF;
END
$r110_post$;
DROP TABLE r110_fn;
DROP FUNCTION pg_temp.r110_edit(text, text, text);

-- ============================================================================
-- 5. Registries
-- ============================================================================
GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0110 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0059/0110 (S6, section 140): edge_partner only; class A3; facility_programme upsert; the facility must be on the trail''s current roster (22023)'
WHERE schema_name = 'private'
  AND function_name = 'partner_facility_programme_upsert_for_partner';

DROP POLICY current_user_edit_function_inventory_0110 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0110 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'catalog_roster_member', 'pd_partner_roster_read_member', 'SELECT', true, '0110 (section 140): roster members of a trail the bound partner member operates (or an admin); the programme editor''s roster check', 'private_definer'),
  ('app', 'catalog_roster_version', 'pd_partner_roster_read_version', 'SELECT', true, '0110 (section 140): roster versions of a trail the bound partner member operates (or an admin); the latest version for the roster check', 'private_definer'),
  ('app', 'catalog_course', 'pd_partner_roster_read_course', 'SELECT', true, '0110 (section 140): course -> facility mapping (public catalogue data) under a partner binding; the roster check', 'private_definer'),
  ('app', 'catalog_hole', 'pd_partner_roster_read_hole', 'SELECT', true, '0110 (section 140): hole -> course mapping (public catalogue data) under a partner binding; the roster check', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN ('pd_partner_roster_read_member', 'pd_partner_roster_read_version', 'pd_partner_roster_read_course', 'pd_partner_roster_read_hole');
DO $assert_0110_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN ('pd_partner_roster_read_member', 'pd_partner_roster_read_version', 'pd_partner_roster_read_course', 'pd_partner_roster_read_hole')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 4 THEN
    RAISE EXCEPTION '0110: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0110_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0110 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;
