-- 0065_rollups_refresh.sql
--
-- P5 rollups-refresh writer (partner-auth-design §30.3 / §40.3 seam; this file's as-built is §41): a scheduled
-- edge_system job recomputes operator_rollup.completions and sponsor_rollup.markers_earned for a calendar month
-- from live awards / entitlements, with k-anonymity (no row when cohort_n < 10; existing sub-threshold rows removed).
-- Migrations 0001-0064 are untouched.
--
-- WHAT THIS ADDS
--   1. app.entitlement.earned_at timestamptz NOT NULL DEFAULT now() (month bucket for markers_earned; backfilled from
--      play.play_date, then activated_at / redeemed_at / voucher_issued_at, then now()).
--   2. GUC-windowed private_definer policies (app.edge.rollups_refresh = on) for cross-user SELECT of source tables and
--      INSERT/UPDATE/DELETE of the two rollup tables (cohort_n >= 10 repeated in WITH CHECK). Partner SELECT policies stay.
--   3. private.refresh_rollups(p_month date): edge_system only. NULL month = current UTC month. Returns written/removed counts.
--      Metric names are closed: operator completions (user_achievement with award_key matching completion family vN on a
--      trail-scoped catalog_achievement_def); sponsor markers_earned (non-void entitlement with sponsorship_id).
--
-- DELIBERATELY NOT HERE: additional metrics, partner-triggered refresh, sponsor portal (P6), scheduling (deploy step).
-- The Edge function rollups-refresh is the caller; nothing in this repository schedules it.

-- ============================================================================
-- 1. entitlement.earned_at (month source for markers_earned)
-- ============================================================================
ALTER TABLE app.entitlement ADD COLUMN IF NOT EXISTS earned_at timestamptz;

UPDATE app.entitlement e
SET earned_at = coalesce(
  (SELECT (p.play_date::timestamp AT TIME ZONE 'UTC') FROM app.play p WHERE p.id = e.play_id AND p.user_id = e.user_id),
  e.activated_at,
  e.redeemed_at,
  e.voucher_issued_at,
  now()
)
WHERE e.earned_at IS NULL;

ALTER TABLE app.entitlement ALTER COLUMN earned_at SET DEFAULT now();
ALTER TABLE app.entitlement ALTER COLUMN earned_at SET NOT NULL;

COMMENT ON COLUMN app.entitlement.earned_at IS
  '0065 (rollups-refresh). Instant the special-marker entitlement was earned; month bucket for sponsor_rollup.markers_earned. Backfilled on add.';

-- ============================================================================
-- 2. Grants and GUC-windowed policies (private_definer)
-- ============================================================================
GRANT SELECT ON app.catalog_achievement_def TO private_definer;
-- user_achievement SELECT already granted (0016); entitlement SELECT already granted (0016).
GRANT INSERT, UPDATE, DELETE ON app.operator_rollup TO private_definer;
GRANT INSERT, UPDATE, DELETE ON app.sponsor_rollup TO private_definer;

-- Source reads open only while the refresh definer holds the GUC (same shape as pd_fix_coords_read),
-- and never under a partner binding (design 8c: partner windows are binding-keyed, not GUC).
CREATE POLICY pd_rollups_refresh_achievement_select ON app.user_achievement FOR SELECT TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
  );
CREATE POLICY pd_rollups_refresh_achievement_def_select ON app.catalog_achievement_def FOR SELECT TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
  );
CREATE POLICY pd_rollups_refresh_entitlement_select ON app.entitlement FOR SELECT TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
  );

-- Rollup writes: GUC window + k-anonymity floor repeated in WITH CHECK (CHECK constraint is the last line of defence).
CREATE POLICY pd_rollups_refresh_operator_select ON app.operator_rollup FOR SELECT TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
  );
CREATE POLICY pd_rollups_refresh_operator_insert ON app.operator_rollup FOR INSERT TO private_definer
  WITH CHECK (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND cohort_n >= 10
    AND metric = 'completions'
  );
CREATE POLICY pd_rollups_refresh_operator_update ON app.operator_rollup FOR UPDATE TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND metric = 'completions'
  )
  WITH CHECK (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND cohort_n >= 10
    AND metric = 'completions'
  );
CREATE POLICY pd_rollups_refresh_operator_delete ON app.operator_rollup FOR DELETE TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND metric = 'completions'
  );

CREATE POLICY pd_rollups_refresh_sponsor_select ON app.sponsor_rollup FOR SELECT TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
  );
CREATE POLICY pd_rollups_refresh_sponsor_insert ON app.sponsor_rollup FOR INSERT TO private_definer
  WITH CHECK (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND cohort_n >= 10
    AND metric = 'markers_earned'
  );
CREATE POLICY pd_rollups_refresh_sponsor_update ON app.sponsor_rollup FOR UPDATE TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND metric = 'markers_earned'
  )
  WITH CHECK (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND cohort_n >= 10
    AND metric = 'markers_earned'
  );
CREATE POLICY pd_rollups_refresh_sponsor_delete ON app.sponsor_rollup FOR DELETE TO private_definer
  USING (
    nullif(current_setting('app.edge.rollups_refresh', true), '') = 'on'
    AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner'
    AND metric = 'markers_earned'
  );
-- ============================================================================
-- 3. The refresh definer (edge_system)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.refresh_rollups(p_month date DEFAULT NULL)
RETURNS TABLE (
  o_month date,
  o_operator_written integer,
  o_operator_removed integer,
  o_sponsor_written integer,
  o_sponsor_removed integer
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_month date;
  v_op_w integer := 0;
  v_op_r integer := 0;
  v_sp_w integer := 0;
  v_sp_r integer := 0;
BEGIN
  v_month := date_trunc('month', coalesce(p_month, (pg_catalog.timezone('UTC', pg_catalog.now()))::date))::date;

  PERFORM set_config('app.edge.rollups_refresh', 'on', true);

  -- Operator completions: completion-family awards (award_key vN) on a trail-scoped achievement, not revoked.
  WITH src AS (
    SELECT d.trail_id AS trail_id,
           count(*)::numeric AS value,
           count(DISTINCT a.user_id)::integer AS cohort_n
    FROM app.user_achievement a
    JOIN app.catalog_achievement_def d ON d.id = a.achievement_id
    WHERE a.revoked_at IS NULL
      AND d.trail_id IS NOT NULL
      AND a.award_key ~ '^v[0-9]+$'
      AND date_trunc('month', a.awarded_at AT TIME ZONE 'UTC')::date = v_month
    GROUP BY d.trail_id
  ),
  upserted AS (
    INSERT INTO app.operator_rollup (trail_id, month, metric, value, cohort_n)
    SELECT s.trail_id, v_month, 'completions', s.value, s.cohort_n
    FROM src s
    WHERE s.cohort_n >= 10
    ON CONFLICT (trail_id, month, metric) DO UPDATE
      SET value = EXCLUDED.value, cohort_n = EXCLUDED.cohort_n
    RETURNING 1
  )
  SELECT count(*)::integer INTO v_op_w FROM upserted;

  WITH doomed AS (
    SELECT r.trail_id
    FROM app.operator_rollup r
    WHERE r.month = v_month AND r.metric = 'completions'
      AND NOT EXISTS (
        SELECT 1
        FROM app.user_achievement a
        JOIN app.catalog_achievement_def d ON d.id = a.achievement_id
        WHERE a.revoked_at IS NULL
          AND d.trail_id = r.trail_id
          AND a.award_key ~ '^v[0-9]+$'
          AND date_trunc('month', a.awarded_at AT TIME ZONE 'UTC')::date = v_month
        GROUP BY d.trail_id
        HAVING count(DISTINCT a.user_id) >= 10
      )
  ),
  deleted AS (
    DELETE FROM app.operator_rollup r
    USING doomed d
    WHERE r.trail_id = d.trail_id AND r.month = v_month AND r.metric = 'completions'
    RETURNING 1
  )
  SELECT count(*)::integer INTO v_op_r FROM deleted;

  -- Sponsor markers_earned: non-void entitlements tied to a sponsorship, bucketed by earned_at.
  WITH src AS (
    SELECT e.sponsorship_id AS sponsorship_id,
           count(*)::numeric AS value,
           count(DISTINCT e.user_id)::integer AS cohort_n
    FROM app.entitlement e
    WHERE e.sponsorship_id IS NOT NULL
      AND e.state <> 'void'
      AND date_trunc('month', e.earned_at AT TIME ZONE 'UTC')::date = v_month
    GROUP BY e.sponsorship_id
  ),
  upserted AS (
    INSERT INTO app.sponsor_rollup (sponsorship_id, month, metric, value, cohort_n)
    SELECT s.sponsorship_id, v_month, 'markers_earned', s.value, s.cohort_n
    FROM src s
    WHERE s.cohort_n >= 10
    ON CONFLICT (sponsorship_id, month, metric) DO UPDATE
      SET value = EXCLUDED.value, cohort_n = EXCLUDED.cohort_n
    RETURNING 1
  )
  SELECT count(*)::integer INTO v_sp_w FROM upserted;

  WITH doomed AS (
    SELECT r.sponsorship_id
    FROM app.sponsor_rollup r
    WHERE r.month = v_month AND r.metric = 'markers_earned'
      AND NOT EXISTS (
        SELECT 1
        FROM app.entitlement e
        WHERE e.sponsorship_id = r.sponsorship_id
          AND e.state <> 'void'
          AND date_trunc('month', e.earned_at AT TIME ZONE 'UTC')::date = v_month
        GROUP BY e.sponsorship_id
        HAVING count(DISTINCT e.user_id) >= 10
      )
  ),
  deleted AS (
    DELETE FROM app.sponsor_rollup r
    USING doomed d
    WHERE r.sponsorship_id = d.sponsorship_id AND r.month = v_month AND r.metric = 'markers_earned'
    RETURNING 1
  )
  SELECT count(*)::integer INTO v_sp_r FROM deleted;

  PERFORM set_config('app.edge.rollups_refresh', '', true);

  o_month := v_month;
  o_operator_written := v_op_w;
  o_operator_removed := v_op_r;
  o_sponsor_written := v_sp_w;
  o_sponsor_removed := v_sp_r;
  RETURN NEXT;
END
$$;

REVOKE EXECUTE ON FUNCTION private.refresh_rollups(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.refresh_rollups(date) TO edge_system;

COMMENT ON FUNCTION private.refresh_rollups(date) IS
  '0065 (rollups-refresh). edge_system only. Recomputes operator_rollup.completions and sponsor_rollup.markers_earned for the UTC month (NULL = current). k-anonymity: no row when cohort_n < 10; stale rows for those metrics and month are removed.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Registries
-- ============================================================================
GRANT UPDATE, DELETE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0065 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.function_inventory (
  schema_name, function_name, identity_args,
  expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note
) VALUES
  ('private', 'refresh_rollups', 'p_month date', false, false, false, false, true, false, false, '0065: edge_system only; recompute operator/sponsor rollups for a UTC month with k-anonymity')
ON CONFLICT (schema_name, function_name, identity_args) DO UPDATE
SET expected_edge_system = EXCLUDED.expected_edge_system, note = EXCLUDED.note;

DROP POLICY current_user_edit_function_inventory_0065 ON private.function_inventory;
REVOKE UPDATE, DELETE ON private.function_inventory FROM CURRENT_USER;

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_edit_definer_policy_allowlist_0065 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'user_achievement', 'pd_rollups_refresh_achievement_select', 'SELECT', true, '0065: rollups-refresh GUC window over completion awards', 'private_definer'),
  ('app', 'catalog_achievement_def', 'pd_rollups_refresh_achievement_def_select', 'SELECT', true, '0065: rollups-refresh GUC window over achievement defs', 'private_definer'),
  ('app', 'entitlement', 'pd_rollups_refresh_entitlement_select', 'SELECT', true, '0065: rollups-refresh GUC window over entitlements', 'private_definer'),
  ('app', 'operator_rollup', 'pd_rollups_refresh_operator_select', 'SELECT', true, '0065: rollups-refresh GUC window read of operator_rollup', 'private_definer'),
  ('app', 'operator_rollup', 'pd_rollups_refresh_operator_insert', 'INSERT', true, '0065: rollups-refresh write completions (cohort_n >= 10)', 'private_definer'),
  ('app', 'operator_rollup', 'pd_rollups_refresh_operator_update', 'UPDATE', true, '0065: rollups-refresh update completions (cohort_n >= 10)', 'private_definer'),
  ('app', 'operator_rollup', 'pd_rollups_refresh_operator_delete', 'DELETE', true, '0065: rollups-refresh remove sub-threshold completions', 'private_definer'),
  ('app', 'sponsor_rollup', 'pd_rollups_refresh_sponsor_select', 'SELECT', true, '0065: rollups-refresh GUC window read of sponsor_rollup', 'private_definer'),
  ('app', 'sponsor_rollup', 'pd_rollups_refresh_sponsor_insert', 'INSERT', true, '0065: rollups-refresh write markers_earned (cohort_n >= 10)', 'private_definer'),
  ('app', 'sponsor_rollup', 'pd_rollups_refresh_sponsor_update', 'UPDATE', true, '0065: rollups-refresh update markers_earned (cohort_n >= 10)', 'private_definer'),
  ('app', 'sponsor_rollup', 'pd_rollups_refresh_sponsor_delete', 'DELETE', true, '0065: rollups-refresh remove sub-threshold markers_earned', 'private_definer')
ON CONFLICT (schema_name, table_name, policy_name) DO UPDATE
SET note = EXCLUDED.note, command = EXCLUDED.command, scoped = EXCLUDED.scoped, role_name = EXCLUDED.role_name;

UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = al.schema_name AND c.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_rollups_refresh_achievement_select', 'pd_rollups_refresh_achievement_def_select', 'pd_rollups_refresh_entitlement_select',
    'pd_rollups_refresh_operator_select', 'pd_rollups_refresh_operator_insert', 'pd_rollups_refresh_operator_update', 'pd_rollups_refresh_operator_delete',
    'pd_rollups_refresh_sponsor_select', 'pd_rollups_refresh_sponsor_insert', 'pd_rollups_refresh_sponsor_update', 'pd_rollups_refresh_sponsor_delete'
  );

DROP POLICY current_user_edit_definer_policy_allowlist_0065 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

DO $assert_0065$
BEGIN
  IF NOT has_function_privilege('edge_system', 'private.refresh_rollups(date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0065: edge_system must EXECUTE refresh_rollups';
  END IF;
  IF has_function_privilege('edge_actor', 'private.refresh_rollups(date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0065: edge_actor must not EXECUTE refresh_rollups';
  END IF;
  IF has_function_privilege('edge_partner', 'private.refresh_rollups(date)', 'EXECUTE') THEN
    RAISE EXCEPTION '0065: edge_partner must not EXECUTE refresh_rollups';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'app' AND table_name = 'entitlement' AND column_name = 'earned_at'
  ) THEN
    RAISE EXCEPTION '0065: app.entitlement.earned_at must exist';
  END IF;
END
$assert_0065$;
