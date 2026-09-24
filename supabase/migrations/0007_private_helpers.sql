-- 0007_private_helpers.sql
-- build plan §4.7 item 4 (docs/golf-trails/02-build-plan.md:1288-1296):
-- "Partner scopes are checked in the DB, not in claims." Also item 3's
-- `private.has_trail_scope` / `has_facility_scope` (line 1257, 1284-1285),
-- and the admin/demo-account principals used throughout §4.7.7's matrix
-- (line 1315-1391) that the plan names but never gives a storage
-- mechanism for.
--
-- AMBIGUITY (see handback report): the plan's principal table (§3.6, line
-- 439-449) and the §4.7.7 matrix both name `admin` and an "app-review demo
-- account" as principals, but never says where that status is recorded.
-- Taking the most literal/secure reading per this task's instructions
-- ("anything security-relevant defaults to deny"): status is a dedicated,
-- service_role-only-writable table, read by a SECURITY DEFINER helper —
-- never a JWT claim, for the same reason §4.7 item 4 forbids reading roles
-- from `user_metadata` ("which the user can write via auth.updateUser").

CREATE TABLE app.admin_user (
  user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.app_review_demo_account (
  user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE
);

-- Both tables: RLS enabled+forced, no client policies at all (§4.7 item 2 +
-- the "default deny" instruction) — only service_role (which bypasses RLS)
-- and the SECURITY DEFINER helpers below can read them.
ALTER TABLE app.admin_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.admin_user FORCE ROW LEVEL SECURITY;
ALTER TABLE app.app_review_demo_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.app_review_demo_account FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION private.is_admin(p_uid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (SELECT 1 FROM app.admin_user WHERE user_id = p_uid);
$$;

CREATE OR REPLACE FUNCTION private.is_demo_account(p_uid uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (SELECT 1 FROM app.app_review_demo_account WHERE user_id = p_uid);
$$;

-- has_facility_scope — build plan line 1292-1294: "SECURITY DEFINER, STABLE,
-- runs with SET search_path = '', and reads partner_member/partner_scope
-- where revoked_at is null." True for: direct staff/manager scope on that
-- facility; OR an operator/admin scoped to a trail the facility currently
-- participates in (facility_programme); OR a platform admin.
CREATE OR REPLACE FUNCTION private.has_facility_scope(p_uid uuid, p_facility_id text)
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
        AND (
          ps.facility_id = p_facility_id
          OR (
            ps.trail_id IS NOT NULL
            AND EXISTS (
              SELECT 1 FROM app.facility_programme fp
              WHERE fp.facility_id = p_facility_id AND fp.trail_id = ps.trail_id
            )
          )
        )
    );
$$;

-- has_trail_scope — build plan line 1257: read by the operator rollup view
-- WHERE clause, and generally by any operator-scoped read.
CREATE OR REPLACE FUNCTION private.has_trail_scope(p_uid uuid, p_trail_id text)
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
        AND ps.trail_id = p_trail_id
    );
$$;

-- has_sponsorship_scope — build plan line 1262 (sponsor rollups, P6).
CREATE OR REPLACE FUNCTION private.has_sponsorship_scope(p_uid uuid, p_sponsorship_id uuid)
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
        AND ps.sponsorship_id = p_sponsorship_id
    )
    -- an operator whose trail scope covers the sponsorship's trail also
    -- has scope over it (build plan line 1252: "operator of that trail").
    OR EXISTS (
      SELECT 1 FROM app.sponsorship s
      WHERE s.id = p_sponsorship_id AND private.has_trail_scope(p_uid, s.trail_id)
    );
$$;

-- has_org_role — helper used by the manager-invite / operator-invite
-- must-fail cells (§4.7.7: "grant ⊆ the grantor's own scope AND a role
-- strictly below the grantor's", line 839).
CREATE OR REPLACE FUNCTION private.partner_role_rank(p_role app.partner_role)
RETURNS int
LANGUAGE sql IMMUTABLE
AS $$
  SELECT CASE p_role
    WHEN 'staff' THEN 1
    WHEN 'manager' THEN 2
    WHEN 'operator' THEN 3
    WHEN 'sponsor' THEN 3
  END;
$$;

-- private.hit_rate_limit — build plan §4.7 item 8 (line 1397-1398).
CREATE OR REPLACE FUNCTION private.hit_rate_limit(p_bucket_key text, p_window interval, p_max int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_window_start timestamptz;
  v_count int;
BEGIN
  -- Bucket the current time into fixed windows of width p_window.
  v_window_start := to_timestamp(floor(extract(epoch FROM now()) / extract(epoch FROM p_window)) * extract(epoch FROM p_window));

  INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count)
  VALUES (p_bucket_key, v_window_start, 1)
  ON CONFLICT (bucket_key, window_start)
  DO UPDATE SET count = private.rate_limit_bucket.count + 1
  RETURNING count INTO v_count;

  IF v_count > p_max THEN
    RAISE EXCEPTION 'rate_limit_exceeded: % over % in %', p_bucket_key, p_max, p_window
      USING ERRCODE = 'P0429';
  END IF;

  RETURN v_count;
END;
$$;

-- Nightly purge (build plan line 1418: "purges windows older than 2 days,
-- G-P2-05"). Exposed as a plain function; the actual pg_cron / scheduled
-- Edge Function wiring is out of this stage's scope (no deploy/network).
CREATE OR REPLACE FUNCTION private.purge_rate_limit_buckets() RETURNS void
LANGUAGE sql SECURITY DEFINER
SET search_path = ''
AS $$
  DELETE FROM private.rate_limit_bucket WHERE window_start < now() - interval '2 days';
$$;

GRANT EXECUTE ON FUNCTION private.is_admin(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.is_demo_account(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.has_facility_scope(uuid, text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.has_trail_scope(uuid, text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.has_sponsorship_scope(uuid, uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.partner_role_rank(app.partner_role) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION private.hit_rate_limit(text, interval, int) TO service_role;
GRANT EXECUTE ON FUNCTION private.purge_rate_limit_buckets() TO service_role;
-- anon explicitly gets nothing here (§4.7 item 5: EXECUTE default-revoked
-- from PUBLIC in 0001; nothing above grants it to anon).
