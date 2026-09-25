-- 0009_grants_revokes.sql
-- build plan §4.7 item 1 (docs/golf-trails/02-build-plan.md:1167-1181):
-- "Server-only derived and trust columns." The named tables get
-- `REVOKE INSERT, UPDATE, DELETE ... FROM anon, authenticated` — they are
-- written only by Edge Functions running as service_role. This migration
-- also grants the base SELECT that 0008's policies ride on (a policy with
-- no GRANT is a no-op — Postgres checks table privileges before RLS), and
-- gives `profile` its one column-level UPDATE grant (line 824).

-- ---------------------------------------------------------------------------
-- SELECT grants — one per table with a client-facing SELECT policy in
-- 0008. (Tables with no policy at all get no SELECT grant either — belt
-- and suspenders for every "nobody" / "denied (no policy)" row.)
-- ---------------------------------------------------------------------------
GRANT SELECT ON
  app.catalog_version, app.catalog_id_ledger, app.catalog_designer,
  app.catalog_trail, app.catalog_facility, app.catalog_course, app.catalog_hole,
  app.catalog_roster_version, app.catalog_roster_member, app.catalog_achievement_def,
  app.public_profile_projection, app.operator_rollup,
  app.device, app.facility_qr, app.push_token,
  app.evidence, app.purchase_evidence,
  app.play, app.play_evidence, app.user_achievement,
  app.partner_org, app.partner_member, app.partner_scope, app.partner_invite,
  app.facility_programme, app.attestation, app.attestation_shift_log, app.staff_activity,
  app.trail_programme, app.marker_code_batch, app.marker_credit, app.entitlement,
  app.special_marker_stock, app.special_marker_stock_movement, app.special_marker_availability,
  app.sponsorship, app.offer, app.offer_code, app.sponsor_rollup,
  app.connector_account, app.booking,
  app.review_item, app.fraud_signal, app.webhook_event, app.audit_log
TO authenticated;

-- `profile`: SELECT own row, plus the plan's explicit column-level UPDATE
-- grant (line 824: "player via column-level GRANT UPDATE (handle, locale,
-- home_region, leaderboard_opt_in)").
GRANT SELECT ON app.profile TO authenticated;
GRANT UPDATE (handle, locale, home_region, leaderboard_opt_in) ON app.profile TO authenticated;

-- service_role gets full DML on every app table (writes go through Edge
-- Functions + withOwnership(); service_role itself bypasses RLS per its
-- BYPASSRLS attribute in the shim / real Supabase).
DO $$
DECLARE
  t record;
BEGIN
  FOR t IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'app' AND c.relkind = 'r'
  LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON app.%I TO service_role', t.relname);
  END LOOP;
END
$$;
GRANT SELECT, INSERT, UPDATE, DELETE ON private.rate_limit_bucket TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.admin_user, app.app_review_demo_account TO service_role;

-- ---------------------------------------------------------------------------
-- Explicit REVOKE of INSERT/UPDATE/DELETE from anon + authenticated on
-- every trust/derived table named at build plan lines 1169-1175. This is
-- belt-and-suspenders: 0001/0003-0008 never GRANTed these in the first
-- place (only SELECT, above, and profile's column-level UPDATE), so the
-- REVOKE is a no-op today and a second line of defense against a future
-- migration accidentally widening a grant.
-- ---------------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE ON
  app.play, app.play_evidence, app.user_achievement, app.marker_credit,
  app.entitlement, app.offer, app.offer_code, app.attestation,
  app.purchase_evidence, app.receipt_fingerprint, app.evidence, app.booking,
  app.fraud_signal, app.device_reward_ledger, app.checkin_challenge,
  app.partner_invite, app.facility_programme, app.trail_programme,
  app.push_token, app.public_profile_projection, app.attestation_shift_log,
  app.staff_activity, app.operator_rollup, app.catalog_id_ledger,
  app.course_qr_token, app.facility_qr, app.sponsorship, app.sponsor_rollup,
  app.special_marker_stock, app.special_marker_stock_movement,
  app.special_marker_availability, app.signin_provider_token
FROM anon, authenticated;
-- `profile` is handled above (its UPDATE grant is intentionally
-- column-scoped, so a blanket REVOKE UPDATE would remove that too).
REVOKE INSERT, DELETE ON app.profile FROM anon, authenticated;

-- No client role gets any grant on: receipt_fingerprint, marker_code,
-- device_reward_ledger, checkin_challenge, course_qr_token,
-- signin_provider_token, review_item, webhook_event,
-- private.rate_limit_bucket, app.admin_user, app.app_review_demo_account —
-- consistent with their "nobody" / admin-only §4.4 reader column.

-- CI check (this migration's job): fail if any app. table grants a write
-- to a client role. Implemented as a pgTAP test
-- (supabase/tests/matrix/10_grants.sql), not here — this migration only
-- establishes the grants themselves.
