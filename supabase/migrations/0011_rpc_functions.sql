-- 0011_rpc_functions.sql
-- build plan §4.7 item 5 (docs/golf-trails/02-build-plan.md:1298-1306):
-- "GRANT EXECUTE goes only to the named api.* functions. v3 allowlist:
-- api.my_progress(trail_id) and api.my_offers(). v2's
-- api.request_checkin_token() is removed."
--
-- Both functions run as SECURITY INVOKER (the default — no SECURITY
-- DEFINER keyword below), so they inherit the caller's own RLS exactly
-- like a security_invoker view (§4.7 item 5's CI query fails on any
-- SECURITY DEFINER function in an exposed schema, line 1305). They read
-- `app` tables directly, relying on the 0008 RLS policies + 0009 SELECT
-- grants — the same access an api.my_* view would have.
--
-- TODO(build plan §8.2, packages/rules — out of this stage's scope, task
-- instruction "packages/rules (the scorer)" is being built in parallel):
-- `api.my_progress` below is a literal, minimal "which roster members have
-- a play at all" projection. It does NOT run the real completion
-- evaluator (n-of-m rules, ledger-merge resolution, version parity,
-- money-mode gating for the marker/entitlement legs) — that logic lives
-- in @golfraven/rules per §8.2/§4.6, which this stage does not touch.

CREATE OR REPLACE FUNCTION api.my_progress(trail_id text)
RETURNS TABLE (
  member_unit app.roster_unit,
  course_id text,
  facility_id text,
  hole_id text,
  has_play boolean
)
LANGUAGE sql STABLE
AS $$
  SELECT
    rm.unit,
    rm.course_id,
    rm.facility_id,
    rm.hole_id,
    EXISTS (
      SELECT 1 FROM app.play p
      WHERE p.user_id = auth.uid()
        AND p.status = 'confirmed'
        AND (
          (rm.course_id IS NOT NULL AND p.course_id = rm.course_id)
          OR (rm.facility_id IS NOT NULL AND p.facility_id = rm.facility_id)
        )
    ) AS has_play
  FROM app.catalog_roster_member rm
  WHERE rm.trail_id = my_progress.trail_id
    AND rm.removed_on IS NULL
    AND rm.roster_version = (
      SELECT max(crv.version) FROM app.catalog_roster_version crv
      WHERE crv.trail_id = my_progress.trail_id
    );
$$;

-- S3 (gate round 2): mirrors `api.offer`'s column masking exactly — a
-- player must not read budget/eligibility through this RPC either. Returns
-- the same shape as `api.offer` (not `SETOF app.offer`, which would have
-- carried every raw column unmasked).
CREATE OR REPLACE FUNCTION api.my_offers()
RETURNS TABLE (
  id uuid, terms_id text, trail_id text, facility_id text, funder app.offer_funder,
  sponsorship_id uuid, valid_from date, valid_to date, status app.offer_status,
  eligibility jsonb, budget_cap numeric, budget_used numeric, budget_reserved numeric,
  max_redemptions int
)
LANGUAGE sql STABLE
AS $$
  -- Live, currently-valid offers. `app.offer` itself carries no
  -- eligibility evaluation (RuleExpr evaluation is packages/rules, out of
  -- scope here) — this is the reference-data list a client filters/
  -- evaluates against.
  SELECT
    o.id, o.terms_id, o.trail_id, o.facility_id, o.funder, o.sponsorship_id,
    o.valid_from, o.valid_to, o.status,
    CASE WHEN private.has_facility_scope(auth.uid(), o.facility_id) OR private.has_trail_scope(auth.uid(), o.trail_id, ARRAY['operator']::app.partner_role[])
      THEN o.eligibility ELSE NULL END,
    CASE WHEN private.has_facility_scope(auth.uid(), o.facility_id) OR private.has_trail_scope(auth.uid(), o.trail_id, ARRAY['operator']::app.partner_role[])
      THEN o.budget_cap ELSE NULL END,
    CASE WHEN private.has_facility_scope(auth.uid(), o.facility_id) OR private.has_trail_scope(auth.uid(), o.trail_id, ARRAY['operator']::app.partner_role[])
      THEN o.budget_used ELSE NULL END,
    CASE WHEN private.has_facility_scope(auth.uid(), o.facility_id) OR private.has_trail_scope(auth.uid(), o.trail_id, ARRAY['operator']::app.partner_role[])
      THEN o.budget_reserved ELSE NULL END,
    CASE WHEN private.has_facility_scope(auth.uid(), o.facility_id) OR private.has_trail_scope(auth.uid(), o.trail_id, ARRAY['operator']::app.partner_role[])
      THEN o.max_redemptions ELSE NULL END
  FROM app.offer o
  WHERE o.status = 'live'
    AND (o.valid_from IS NULL OR o.valid_from <= current_date)
    AND (o.valid_to IS NULL OR o.valid_to >= current_date);
$$;

REVOKE EXECUTE ON FUNCTION api.my_progress(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION api.my_offers() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api.my_progress(text) TO authenticated;
GRANT EXECUTE ON FUNCTION api.my_offers() TO authenticated;
-- Deliberately NOT granted to anon (§4.7 item 5's must-fail: only the
-- named allowlist, and even that is authenticated-only — no client
-- function in this plan is meant for anon, since anon reaches only the
-- static site, §4.4/§4.7 intro).

-- api.request_checkin_token() is REMOVED (v2 → v3, line 1303-1304): it is
-- deliberately never created. The §4.7.7 must-fail cell "authenticated
-- calls api.request_checkin_token() (removed) → permission denied / not
-- found" (line 1363) holds by construction — pgTAP asserts the function
-- does not exist (supabase/tests/matrix/05_rpc.sql).
