-- 0008_rls_policies.sql
-- build plan §4.7 item 2 (docs/golf-trails/02-build-plan.md:1239): "RLS
-- enabled and forced on every app. table, with select policies only for
-- client roles." Every table gets ENABLE + FORCE. A table with NO policy
-- below is default-deny for anon/authenticated by construction (only
-- service_role, which bypasses RLS, can touch it) — this is deliberate for
-- every "nobody" / "denied (no policy)" row in §4.4/§4.7.7.
--
-- Ordering follows §4.4's table list. Each policy's comment cites the exact
-- "Client read" cell it implements.

CREATE OR REPLACE FUNCTION private.is_org_member(p_uid uuid, p_org_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1 FROM app.partner_member
    WHERE user_id = p_uid AND org_id = p_org_id AND revoked_at IS NULL
  ) OR private.is_admin(p_uid);
$$;
GRANT EXECUTE ON FUNCTION private.is_org_member(uuid, uuid) TO authenticated, service_role;

-- ============================================================================
-- Catalog tables — "all authenticated" (build plan line 821-823).
-- ============================================================================
ALTER TABLE app.catalog_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_version FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_version_read ON app.catalog_version FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_id_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_id_ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_id_ledger_read ON app.catalog_id_ledger FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_designer ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_designer FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_designer_read ON app.catalog_designer FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_trail ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_trail FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_trail_read ON app.catalog_trail FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_facility ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_facility FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_facility_read ON app.catalog_facility FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_course ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_course FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_course_read ON app.catalog_course FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_hole ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_hole FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_hole_read ON app.catalog_hole FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_roster_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_roster_version FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_roster_version_read ON app.catalog_roster_version FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_roster_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_roster_member FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_roster_member_read ON app.catalog_roster_member FOR SELECT TO authenticated USING (true);

ALTER TABLE app.catalog_achievement_def ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_achievement_def FORCE ROW LEVEL SECURITY;
CREATE POLICY catalog_achievement_def_read ON app.catalog_achievement_def FOR SELECT TO authenticated USING (true);

-- ============================================================================
-- profile — "own row only; never granted to another user" (line 824, A2-11).
-- ============================================================================
ALTER TABLE app.profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.profile FORCE ROW LEVEL SECURITY;
CREATE POLICY profile_select_own ON app.profile FOR SELECT TO authenticated USING (user_id = auth.uid());
-- Column-level UPDATE grant (handle, locale, home_region, leaderboard_opt_in)
-- lives in 0009_grants_revokes.sql; this USING clause bounds it to own row.
CREATE POLICY profile_update_own ON app.profile FOR UPDATE TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- public_profile_projection — "opted-in users only ... via api.public_profile
-- (all authenticated)" (line 825). Holds no user id, so broad read is safe.
ALTER TABLE app.public_profile_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.public_profile_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY public_profile_projection_read ON app.public_profile_projection
  FOR SELECT TO authenticated USING (true);

-- operator_rollup_<metric> — "api.operator_*, scoped by has_trail_scope in
-- the view's own WHERE" (line 826). No user id in the table; the view does
-- the trail-scoping, so table-level RLS only needs to keep it authenticated
-- and non-PII.
ALTER TABLE app.operator_rollup ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.operator_rollup FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_rollup_read ON app.operator_rollup FOR SELECT TO authenticated USING (true);

-- ============================================================================
-- device — "own" (line 827).
-- ============================================================================
ALTER TABLE app.device ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.device FORCE ROW LEVEL SECURITY;
CREATE POLICY device_select_own ON app.device FOR SELECT TO authenticated USING (user_id = auth.uid());

-- device_reward_ledger — "nobody (admin)" (line 828): admin reads through a
-- dedicated tool outside this stage's scope; no client-role policy here.
ALTER TABLE app.device_reward_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.device_reward_ledger FORCE ROW LEVEL SECURITY;

-- checkin_challenge — "nobody" (line 829).
ALTER TABLE app.checkin_challenge ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.checkin_challenge FORCE ROW LEVEL SECURITY;

-- course_qr_token (O5) — "nobody" (line 830).
ALTER TABLE app.course_qr_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.course_qr_token FORCE ROW LEVEL SECURITY;

-- facility_qr (O5) — "admin / operator" (line 831).
ALTER TABLE app.facility_qr ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.facility_qr FORCE ROW LEVEL SECURITY;
CREATE POLICY facility_qr_read ON app.facility_qr FOR SELECT TO authenticated
  USING (private.has_facility_scope(auth.uid(), facility_id));

-- push_token — "own" (line 832).
ALTER TABLE app.push_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.push_token FORCE ROW LEVEL SECURITY;
CREATE POLICY push_token_select_own ON app.push_token FOR SELECT TO authenticated USING (user_id = auth.uid());

-- ============================================================================
-- evidence — "own" (line 833).
-- ============================================================================
ALTER TABLE app.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_select_own ON app.evidence FOR SELECT TO authenticated USING (user_id = auth.uid());

-- purchase_evidence — "own" (line 834).
ALTER TABLE app.purchase_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.purchase_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY purchase_evidence_select_own ON app.purchase_evidence FOR SELECT TO authenticated USING (user_id = auth.uid());

-- receipt_fingerprint — "nobody" (line 835).
ALTER TABLE app.receipt_fingerprint ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.receipt_fingerprint FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- play / play_evidence — "own" (lines 836-837).
-- ============================================================================
ALTER TABLE app.play ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.play FORCE ROW LEVEL SECURITY;
CREATE POLICY play_select_own ON app.play FOR SELECT TO authenticated USING (user_id = auth.uid());

ALTER TABLE app.play_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.play_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY play_evidence_select_own ON app.play_evidence FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM app.play p WHERE p.id = play_id AND p.user_id = auth.uid()));

-- user_achievement — "own; opted-in public view" (line 838).
ALTER TABLE app.user_achievement ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.user_achievement FORCE ROW LEVEL SECURITY;
CREATE POLICY user_achievement_select_own ON app.user_achievement FOR SELECT TO authenticated USING (user_id = auth.uid());

-- ============================================================================
-- partner_org / partner_member / partner_scope / partner_invite — "self
-- (members)" (line 839): any non-revoked member of the org.
-- ============================================================================
ALTER TABLE app.partner_org ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_org FORCE ROW LEVEL SECURITY;
CREATE POLICY partner_org_select_member ON app.partner_org FOR SELECT TO authenticated
  USING (private.is_org_member(auth.uid(), id));

ALTER TABLE app.partner_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_member FORCE ROW LEVEL SECURITY;
CREATE POLICY partner_member_select_member ON app.partner_member FOR SELECT TO authenticated
  USING (private.is_org_member(auth.uid(), org_id));

ALTER TABLE app.partner_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY partner_scope_select_member ON app.partner_scope FOR SELECT TO authenticated
  USING (private.is_org_member(auth.uid(), org_id));

ALTER TABLE app.partner_invite ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_invite FORCE ROW LEVEL SECURITY;
CREATE POLICY partner_invite_select_member ON app.partner_invite FOR SELECT TO authenticated
  USING (private.is_org_member(auth.uid(), org_id));

-- ============================================================================
-- facility_programme — "admin / operator" (line 840).
-- ============================================================================
ALTER TABLE app.facility_programme ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.facility_programme FORCE ROW LEVEL SECURITY;
CREATE POLICY facility_programme_read ON app.facility_programme FOR SELECT TO authenticated
  USING (private.has_trail_scope(auth.uid(), trail_id) OR private.has_facility_scope(auth.uid(), facility_id));

-- ============================================================================
-- attestation — "the player sees own rows only; no client role reads
-- another player's row" (line 841, G3-06). Staff/manager do NOT get a
-- policy here at all — they read the attestation_shift_log projection
-- instead (§4.7.7 must-fail: "staff@X reads attestation rows ... → 0 rows").
-- ============================================================================
ALTER TABLE app.attestation ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.attestation FORCE ROW LEVEL SECURITY;
CREATE POLICY attestation_select_own_player ON app.attestation FOR SELECT TO authenticated
  USING (player_user_id = auth.uid());

-- attestation_shift_log (projection, G3-06) — "api.staff_shift_log: staff
-- and managers of that facility, scoped by has_facility_scope in the
-- view's own WHERE" (line 842).
ALTER TABLE app.attestation_shift_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.attestation_shift_log FORCE ROW LEVEL SECURITY;
CREATE POLICY attestation_shift_log_read ON app.attestation_shift_log FOR SELECT TO authenticated
  USING (private.has_facility_scope(auth.uid(), facility_id));

-- staff_activity — "the one listed exception" (line 843, G3-06): manager
-- and operator of that facility/trail; admin.
ALTER TABLE app.staff_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.staff_activity FORCE ROW LEVEL SECURITY;
CREATE POLICY staff_activity_read ON app.staff_activity FOR SELECT TO authenticated
  USING (private.has_facility_scope(auth.uid(), facility_id));

-- ============================================================================
-- trail_programme — "public copy via the catalog" (line 844). Read here at
-- the DB level is authenticated-only (non-personal reference data); the
-- literal "public" (anon) copy is the separately-built static catalog
-- artifact on the website, not this live table — see AMBIGUITIES in the
-- handback report.
-- ============================================================================
ALTER TABLE app.trail_programme ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.trail_programme FORCE ROW LEVEL SECURITY;
CREATE POLICY trail_programme_read ON app.trail_programme FOR SELECT TO authenticated USING (true);

-- ============================================================================
-- marker_code_batch — "admin / operator" (line 845).
-- ============================================================================
ALTER TABLE app.marker_code_batch ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.marker_code_batch FORCE ROW LEVEL SECURITY;
CREATE POLICY marker_code_batch_read ON app.marker_code_batch FOR SELECT TO authenticated
  USING (private.has_trail_scope(auth.uid(), trail_id) OR private.has_facility_scope(auth.uid(), facility_id));

-- marker_code — "nobody" (line 846).
ALTER TABLE app.marker_code ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.marker_code FORCE ROW LEVEL SECURITY;

-- marker_credit — "own" (line 847).
ALTER TABLE app.marker_credit ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.marker_credit FORCE ROW LEVEL SECURITY;
CREATE POLICY marker_credit_select_own ON app.marker_credit FOR SELECT TO authenticated USING (user_id = auth.uid());

-- entitlement — "own" (line 848).
ALTER TABLE app.entitlement ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.entitlement FORCE ROW LEVEL SECURITY;
CREATE POLICY entitlement_select_own ON app.entitlement FOR SELECT TO authenticated USING (user_id = auth.uid());

-- ============================================================================
-- special_marker_stock / _stock_movement — "manager and staff of that
-- facility; operator of that trail; admin. Holds no player data" (849-850).
-- ============================================================================
ALTER TABLE app.special_marker_stock ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.special_marker_stock FORCE ROW LEVEL SECURITY;
CREATE POLICY special_marker_stock_read ON app.special_marker_stock FOR SELECT TO authenticated
  USING (private.has_trail_scope(auth.uid(), trail_id) OR private.has_facility_scope(auth.uid(), facility_id));

ALTER TABLE app.special_marker_stock_movement ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.special_marker_stock_movement FORCE ROW LEVEL SECURITY;
CREATE POLICY special_marker_stock_movement_read ON app.special_marker_stock_movement FOR SELECT TO authenticated
  USING (private.has_trail_scope(auth.uid(), trail_id) OR private.has_facility_scope(auth.uid(), facility_id));

-- special_marker_availability (projection, O9/O10) — "api.
-- special_marker_availability (all authenticated): the app's 'in stock at'
-- list ... holds no player data" (line 851).
ALTER TABLE app.special_marker_availability ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.special_marker_availability FORCE ROW LEVEL SECURITY;
CREATE POLICY special_marker_availability_read ON app.special_marker_availability
  FOR SELECT TO authenticated USING (true);

-- sponsorship (O11) — "admin / operator of that trail; the sponsor itself
-- from P6" (line 852).
ALTER TABLE app.sponsorship ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.sponsorship FORCE ROW LEVEL SECURITY;
CREATE POLICY sponsorship_read ON app.sponsorship FOR SELECT TO authenticated
  USING (private.has_trail_scope(auth.uid(), trail_id) OR private.has_sponsorship_scope(auth.uid(), id));

-- offer / offer_code — offer itself is reference data an authenticated
-- player must be able to browse for api.my_offers() (§4.7 item 5, line
-- 1302); offer_code is "own (no plaintext in portal-verify mode, G-P2-04)"
-- (line 853).
ALTER TABLE app.offer ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.offer FORCE ROW LEVEL SECURITY;
CREATE POLICY offer_read ON app.offer FOR SELECT TO authenticated USING (true);

ALTER TABLE app.offer_code ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.offer_code FORCE ROW LEVEL SECURITY;
CREATE POLICY offer_code_select_own ON app.offer_code FOR SELECT TO authenticated USING (user_id = auth.uid());

-- sponsor_rollup_<metric> (O11) — "api.sponsor_* ... scoped by
-- has_sponsorship_scope ... admin / operator" (line 855).
ALTER TABLE app.sponsor_rollup ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.sponsor_rollup FORCE ROW LEVEL SECURITY;
CREATE POLICY sponsor_rollup_read ON app.sponsor_rollup FOR SELECT TO authenticated
  USING (private.has_sponsorship_scope(auth.uid(), sponsorship_id));

-- ============================================================================
-- connector_account — "own via a view without token columns" (line 856).
-- RLS restricts ROWS to own; the api view restricts COLUMNS (0010).
-- ============================================================================
ALTER TABLE app.connector_account ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.connector_account FORCE ROW LEVEL SECURITY;
CREATE POLICY connector_account_select_own ON app.connector_account FOR SELECT TO authenticated
  USING (user_id = auth.uid());

-- signin_provider_token (O12) — "nobody" / "denied (no policy)" (line 857
-- and the explicit §4.7.7 must-fail cell, line 1393). No policy at all,
-- not even own-row.
ALTER TABLE app.signin_provider_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.signin_provider_token FORCE ROW LEVEL SECURITY;

-- booking — "own" (line 858).
ALTER TABLE app.booking ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.booking FORCE ROW LEVEL SECURITY;
CREATE POLICY booking_select_own ON app.booking FOR SELECT TO authenticated USING (user_id = auth.uid());

-- ============================================================================
-- review_item, fraud_signal, webhook_event, audit_log — "admin" (line 859).
-- ============================================================================
ALTER TABLE app.review_item ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.review_item FORCE ROW LEVEL SECURITY;
CREATE POLICY review_item_read ON app.review_item FOR SELECT TO authenticated USING (private.is_admin(auth.uid()));

ALTER TABLE app.fraud_signal ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.fraud_signal FORCE ROW LEVEL SECURITY;
CREATE POLICY fraud_signal_read ON app.fraud_signal FOR SELECT TO authenticated USING (private.is_admin(auth.uid()));

ALTER TABLE app.webhook_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.webhook_event FORCE ROW LEVEL SECURITY;
CREATE POLICY webhook_event_read ON app.webhook_event FOR SELECT TO authenticated USING (private.is_admin(auth.uid()));

ALTER TABLE app.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_log_read ON app.audit_log FOR SELECT TO authenticated USING (private.is_admin(auth.uid()));

-- ============================================================================
-- private.rate_limit_bucket — "nobody" (line 860). Defense in depth even
-- though `private` is never exposed to PostgREST.
-- ============================================================================
ALTER TABLE private.rate_limit_bucket ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.rate_limit_bucket FORCE ROW LEVEL SECURITY;
