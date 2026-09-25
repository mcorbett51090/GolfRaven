-- 0010_api_views.sql
-- build plan §4.7 item 3 (docs/golf-trails/02-build-plan.md:1241-1286):
-- "Every api. view is created WITH (security_invoker = true) ... Every
-- player-facing view filters user_id = auth.uid() in its own WHERE, not by
-- RLS alone." `api` is the only schema PostgREST exposes (§4.4 intro,
-- line 816); `app` itself is never reached directly by a client.
--
-- [unverified — training knowledge; the P3 spike confirms it, line 1243]
-- `security_invoker = true` is the PG15+ view option that makes a view run
-- with the querying role's own privileges (and therefore its own RLS),
-- rather than the view owner's.

-- ---------------------------------------------------------------------------
-- Catalog — reference data, all authenticated (§4.4 lines 821-823). No
-- user_id filter: this is not player-facing personal data.
-- ---------------------------------------------------------------------------
CREATE VIEW api.catalog_version WITH (security_invoker = true) AS SELECT * FROM app.catalog_version;
CREATE VIEW api.catalog_id_ledger WITH (security_invoker = true) AS SELECT * FROM app.catalog_id_ledger;
CREATE VIEW api.catalog_designer WITH (security_invoker = true) AS SELECT * FROM app.catalog_designer;
CREATE VIEW api.catalog_trail WITH (security_invoker = true) AS SELECT * FROM app.catalog_trail;
CREATE VIEW api.catalog_facility WITH (security_invoker = true) AS SELECT * FROM app.catalog_facility;
CREATE VIEW api.catalog_course WITH (security_invoker = true) AS SELECT * FROM app.catalog_course;
CREATE VIEW api.catalog_hole WITH (security_invoker = true) AS SELECT * FROM app.catalog_hole;
CREATE VIEW api.catalog_roster_version WITH (security_invoker = true) AS SELECT * FROM app.catalog_roster_version;
CREATE VIEW api.catalog_roster_member WITH (security_invoker = true) AS SELECT * FROM app.catalog_roster_member;
CREATE VIEW api.catalog_achievement_def WITH (security_invoker = true) AS SELECT * FROM app.catalog_achievement_def;
CREATE VIEW api.trail_programme WITH (security_invoker = true) AS SELECT * FROM app.trail_programme;
CREATE VIEW api.special_marker_availability WITH (security_invoker = true) AS SELECT * FROM app.special_marker_availability;

-- ⛔ SECURITY FIX (S3, gate round 2): `api.offer` was `SELECT *` gated only
-- by a `USING (true)` table policy — every player could read every
-- offer's row (drafts included) and every column (budget_cap, budget_used,
-- budget_reserved, and the eligibility RuleExpr included). "Players must
-- not read drafts, budgets or eligibility" is now enforced twice:
--   - ROW: the base table's own RLS policy (0008) now requires
--     `status = 'live'` for a non-staff reader — a draft/approved-but-not-
--     live offer is invisible to a player at the table level, not only
--     hidden by this view's WHERE.
--   - COLUMN: this view masks `eligibility`/`budget_cap`/`budget_used`/
--     `budget_reserved`/`max_redemptions` to NULL for anyone who is not
--     staff/manager/operator of the offer's facility/trail (or admin) —
--     even reading a live offer, a player never sees the operator's
--     budget or the raw RuleExpr.
CREATE VIEW api.offer WITH (security_invoker = true, security_barrier = true) AS
  SELECT
    id, terms_id, trail_id, facility_id, funder, sponsorship_id, valid_from, valid_to, status,
    CASE WHEN private.has_facility_scope(auth.uid(), facility_id) OR private.has_trail_scope(auth.uid(), trail_id, ARRAY['operator']::app.partner_role[])
      THEN eligibility ELSE NULL END AS eligibility,
    CASE WHEN private.has_facility_scope(auth.uid(), facility_id) OR private.has_trail_scope(auth.uid(), trail_id, ARRAY['operator']::app.partner_role[])
      THEN budget_cap ELSE NULL END AS budget_cap,
    CASE WHEN private.has_facility_scope(auth.uid(), facility_id) OR private.has_trail_scope(auth.uid(), trail_id, ARRAY['operator']::app.partner_role[])
      THEN budget_used ELSE NULL END AS budget_used,
    CASE WHEN private.has_facility_scope(auth.uid(), facility_id) OR private.has_trail_scope(auth.uid(), trail_id, ARRAY['operator']::app.partner_role[])
      THEN budget_reserved ELSE NULL END AS budget_reserved,
    CASE WHEN private.has_facility_scope(auth.uid(), facility_id) OR private.has_trail_scope(auth.uid(), trail_id, ARRAY['operator']::app.partner_role[])
      THEN max_redemptions ELSE NULL END AS max_redemptions
  FROM app.offer;

-- ---------------------------------------------------------------------------
-- Player-facing "own row" views — every WHERE repeats user_id = auth.uid()
-- explicitly (§4.7 item 3, second bullet), even though RLS on the base
-- table already enforces it, so a later, looser policy can never widen
-- what these views return.
-- ---------------------------------------------------------------------------
CREATE VIEW api.my_profile WITH (security_invoker = true) AS
  SELECT * FROM app.profile WHERE user_id = auth.uid();

CREATE VIEW api.my_device WITH (security_invoker = true) AS
  SELECT * FROM app.device WHERE user_id = auth.uid();

CREATE VIEW api.my_push_token WITH (security_invoker = true) AS
  SELECT * FROM app.push_token WHERE user_id = auth.uid();

CREATE VIEW api.my_evidence WITH (security_invoker = true) AS
  SELECT * FROM app.evidence WHERE user_id = auth.uid();

CREATE VIEW api.my_purchase_evidence WITH (security_invoker = true) AS
  SELECT * FROM app.purchase_evidence WHERE user_id = auth.uid();

CREATE VIEW api.my_play WITH (security_invoker = true) AS
  SELECT * FROM app.play WHERE user_id = auth.uid();

CREATE VIEW api.my_play_evidence WITH (security_invoker = true) AS
  SELECT pe.* FROM app.play_evidence pe
  JOIN app.play p ON p.id = pe.play_id
  WHERE p.user_id = auth.uid();

CREATE VIEW api.my_achievement WITH (security_invoker = true) AS
  SELECT * FROM app.user_achievement WHERE user_id = auth.uid();

CREATE VIEW api.my_marker_credit WITH (security_invoker = true) AS
  SELECT * FROM app.marker_credit WHERE user_id = auth.uid();

CREATE VIEW api.my_entitlement WITH (security_invoker = true) AS
  SELECT * FROM app.entitlement WHERE user_id = auth.uid();

CREATE VIEW api.my_offer_code WITH (security_invoker = true) AS
  SELECT * FROM app.offer_code WHERE user_id = auth.uid();

CREATE VIEW api.my_booking WITH (security_invoker = true) AS
  SELECT * FROM app.booking WHERE user_id = auth.uid();

-- connector_account — "own via a view without token columns" (line 856):
-- the column list below deliberately omits refresh_token_ciphertext,
-- dek_wrapped, kek_id.
CREATE VIEW api.my_connector_account WITH (security_invoker = true) AS
  SELECT id, user_id, provider, external_user_id, scopes, status, created_at, revoked_at
  FROM app.connector_account
  WHERE user_id = auth.uid();

-- attestation — "the player sees own rows only" (line 841).
CREATE VIEW api.my_attestation WITH (security_invoker = true) AS
  SELECT * FROM app.attestation WHERE player_user_id = auth.uid();

-- ---------------------------------------------------------------------------
-- Public / cross-user projections — build plan §4.7 item 3's named
-- exceptions (lines 1263-1281).
-- ---------------------------------------------------------------------------
CREATE VIEW api.public_profile WITH (security_invoker = true) AS
  SELECT handle, public_achievements, updated_at FROM app.public_profile_projection;

-- staff_shift_log — "staff and managers of that facility" (line 842,
-- G3-06). B7 fix: this projection is player-identifying (handles), so it
-- uses the NARROW staff/manager-only helper, not the broad
-- has_facility_scope (which also matches operator — the exact leak the
-- matrix's "operator@T reads any player-level row -> 0 rows" forbids,
-- line 1357). `security_barrier=true` (S3) so the WHERE clause's scope
-- check cannot be defeated by a cost-based reordering of a
-- caller-supplied predicate against this view.
CREATE VIEW api.staff_shift_log WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.attestation_shift_log
  WHERE private.is_staff_or_manager_of_facility(auth.uid(), facility_id);

-- staff_activity — "the one listed exception ... manager and operator"
-- (line 843). B7 fix: staff must NOT read this (plan's reader column
-- never lists staff for this row).
CREATE VIEW api.staff_activity WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.staff_activity
  WHERE private.is_manager_or_operator_of_facility(auth.uid(), facility_id);

-- operator_rollup_<metric> — "api.operator_*... WHERE has_trail_scope(...)
-- AND cohort_n >= 10 in the view itself" (line 1257-1258). S3: the scope
-- check now ALSO lives in the base table's own RLS policy (0008), not
-- only here — this view's WHERE is a second, redundant layer, and
-- `security_barrier=true` stops the two layers from being reordered
-- around each other.
CREATE VIEW api.operator_rollup WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.operator_rollup
  WHERE private.has_trail_scope(auth.uid(), trail_id) AND cohort_n >= 10;

-- sponsor_rollup_<metric> (O11; read from P6) — "api.sponsor_*... WHERE
-- has_sponsorship_scope(...)" (line 1260-1262).
CREATE VIEW api.sponsor_rollup WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.sponsor_rollup
  WHERE private.has_sponsorship_scope(auth.uid(), sponsorship_id) AND cohort_n >= 10;

-- ---------------------------------------------------------------------------
-- Partner scope views — "self (members)" (line 839), scoped defensively.
-- ---------------------------------------------------------------------------
CREATE VIEW api.my_partner_org WITH (security_invoker = true) AS
  SELECT * FROM app.partner_org WHERE private.is_org_member(auth.uid(), id);

CREATE VIEW api.my_partner_member WITH (security_invoker = true) AS
  SELECT * FROM app.partner_member WHERE private.is_org_member(auth.uid(), org_id);

CREATE VIEW api.my_partner_scope WITH (security_invoker = true) AS
  SELECT * FROM app.partner_scope WHERE private.is_org_member(auth.uid(), org_id);

CREATE VIEW api.my_partner_invite WITH (security_invoker = true) AS
  SELECT * FROM app.partner_invite WHERE private.is_org_member(auth.uid(), org_id);

-- B7 fix: reader is "admin / operator" (line 840) — no staff/manager.
CREATE VIEW api.facility_programme WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.facility_programme
  WHERE private.has_trail_scope(auth.uid(), trail_id) OR private.is_operator_of_facility(auth.uid(), facility_id);

-- B7 fix (nit): "admin and operator only" — no staff/manager.
CREATE VIEW api.facility_qr WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.facility_qr WHERE private.is_operator_of_facility(auth.uid(), facility_id);

-- B7 fix (nit): "admin and operator only" — no staff/manager.
CREATE VIEW api.marker_code_batch WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.marker_code_batch
  WHERE private.has_trail_scope(auth.uid(), trail_id) OR private.is_operator_of_facility(auth.uid(), facility_id);

CREATE VIEW api.special_marker_stock WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.special_marker_stock
  WHERE private.has_trail_scope(auth.uid(), trail_id) OR private.has_facility_scope(auth.uid(), facility_id);

CREATE VIEW api.special_marker_stock_movement WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.special_marker_stock_movement
  WHERE private.has_trail_scope(auth.uid(), trail_id) OR private.has_facility_scope(auth.uid(), facility_id);

CREATE VIEW api.sponsorship WITH (security_invoker = true, security_barrier = true) AS
  SELECT * FROM app.sponsorship
  WHERE private.has_trail_scope(auth.uid(), trail_id) OR private.has_sponsorship_scope(auth.uid(), id);

-- ---------------------------------------------------------------------------
-- Grants — SELECT on every view above to authenticated (security_invoker
-- means the underlying table's own RLS/grant still applies; the view grant
-- is what makes PostgREST able to route the request at all).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  v record;
BEGIN
  FOR v IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'api' AND c.relkind = 'v'
  LOOP
    EXECUTE format('GRANT SELECT ON api.%I TO authenticated', v.relname);
  END LOOP;
END
$$;

-- api.public_profile and api.special_marker_availability and
-- api.catalog_* / api.trail_programme / api.offer hold no per-user secret
-- and no PII beyond an opted-in handle — still authenticated-only, never
-- anon (build plan: "no grants to anon on anything personal"; catalog data
-- is public in the SEPARATE static site artifact, not through this live
-- API — see the AMBIGUITIES note in the handback report).

-- CI query (build plan §4.7 item 3, line 1245): "fail if any view in
-- api/public lacks security_invoker=true in pg_class.reloptions." —
-- implemented as a pgTAP test (supabase/tests/matrix/03_views.sql), not a
-- migration-time assertion, since it is a repo-health check.
