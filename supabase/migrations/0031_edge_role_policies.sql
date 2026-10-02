-- 0031_edge_role_policies.sql
-- PR1 of the NOBYPASSRLS edge-role work (follow-up 6), part 2 of 2: every GRANT and every RLS policy
-- for edge_actor and edge_system, the nonce-tombstone trigger-function redefinition, and the policy
-- registry. 0030 created the roles, the actor binding and the definer functions; read its header and
-- docs/security/edge-role-design.md first. Nothing here touches anon, authenticated or service_role.
--
-- DEPENDS ON the final (P3f round 3, merged) 0027: app.install_link_account, app.record_install_link and
-- private.account_pseudonyms exist only there.
--
-- GENERATED: the policies in section 3 and the registry rows in section 5 come from one spec so they
-- cannot disagree while being written; the checked-in text below is the source of truth afterwards.
-- Every table keeps ENABLE + FORCE ROW LEVEL SECURITY (none is touched here).
--
-- ============================================================================
-- THE RULES THIS FILE FOLLOWS
-- ============================================================================
--   * edge_actor policies are keyed on `user_id = (select private.actor_uid())` and nothing else:
--     never current_setting(), never auth.uid(). The `(select ...)` form makes it an initplan, one
--     evaluation per statement. An unbound transaction has actor_uid() = NULL, so every one of these
--     comparisons is NULL and the policy admits nothing (fail closed).
--   * Column-level grants wherever a table has columns the Edge code must not write (key material,
--     admin columns, the scorer's decision inputs set elsewhere). INSERT/UPDATE column lists below
--     are the union of what the P3c-P3f Repo statements write today.
--   * edge_actor reads public catalog data with USING (true) policies of its own (0008's policies
--     name `authenticated` and are untouched).
--   * edge_system has NO policy and NO grant on any table that holds personal data (checked by
--     tools/db/verify-function-inventory.mjs check 12). It imports the catalog and reaches users only
--     through 0030's definers / delegate binders.
--
-- THE HELD-REVIEW CASCADE IS NOT REDEFINED (the decision, and why it is safe).
--   app.play_held_review_cascade (0017) is an invoker-rights trigger on app.play: it UPDATEs the play's
--   own offer_code / entitlement rows. Under edge_actor that works unchanged, because (1) the play, the
--   codes and the entitlements all belong to ONE user (the composite FKs offer_code_play_user_fk and
--   entitlement_play_user_fk force play.user_id = code.user_id), (2) this file grants edge_actor UPDATE
--   on exactly the columns the cascade writes (`state`) and the P3f activation writes, under the same
--   own-row policy, and (3) the P3f reservation trigger (app.offer_code_reservation_sync, fired by
--   that state change) runs as the same role and is covered by the offer / review_item policies below.
--   P3f's round 3 (merged) redefined the cascade only to take its locks in one global order (the play's
--   codes, then their offers, then entitlements, each ORDER BY id ... FOR UPDATE). That still needs nothing
--   new from this file: SELECT ... FOR UPDATE needs UPDATE privilege and the UPDATE policy to pass, which
--   the own-row / own-code policies and column grants below give. So nothing about the cascade is
--   rewritten, and any later change to its body lands without a conflict here. Proven under edge_actor in
--   supabase/tests/matrix/16_edge_role.sql (rows move, budget reserved, expiry paused).
--   The one trigger function that DOES have to change is the nonce tombstone, in section 8 (it read
--   and wrote private.consumed_nonce directly, which edge_actor cannot reach).
--
-- KNOWN, ACCEPTED RESIDUAL RISKS (details and the PR5 plan in docs/security/edge-role-design.md):
--   R1  edge_actor can UPDATE offer.budget_reserved (and only that column) on an offer on which it
--       holds a code. The reservation trigger and the P3f functions are invoker-rights and write that
--       column as the writing role; wrapping them in definers would mean redefining P3f's functions.
--   R2  edge_actor can UPDATE its own offer_code / entitlement `state` and friends directly, bypassing
--       the activation functions' backstops. Same trust boundary as binding any uid. PR5 moves
--       activation behind a definer.
--   R3  private.account_pseudonyms(uuid) takes any uid, so edge_actor can compute any account's
--       vault-keyed pseudonym (the install-link tombstone policy and app.record_install_link call it as
--       the writing role). No worse than bind_actor(any uid); it reveals only an HMAC.
--
-- ============================================================================
-- 1. Table grants (column lists are deliberate; see the rules above)
-- ============================================================================
-- ---- edge_actor ----
GRANT SELECT ON app.device TO edge_actor;
GRANT INSERT (id, user_id, platform) ON app.device TO edge_actor;
GRANT UPDATE (attest_counter, devicecheck_token_hash, integrity_last, last_seen, install_link_hash) ON app.device TO edge_actor;

GRANT SELECT ON app.evidence TO edge_actor;
GRANT INSERT (user_id, device_id, source, source_ref, input_hash, course_id, facility_id, started_at, ended_at, local_date,
              summary, integrity, cosignal, attestation_grade, matcher_version, catalog_version, status,
              claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) ON app.evidence TO edge_actor;
GRANT UPDATE (course_id, facility_id, summary, integrity, attestation_grade, catalog_version, status,
              claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) ON app.evidence TO edge_actor;

GRANT SELECT ON app.play TO edge_actor;
GRANT INSERT (user_id, course_id, facility_id, play_date, course_disambiguated_by, score_badge, score_monetary, hard_signal,
              presence_signal, money, held_review, policy_version, input_digest, status) ON app.play TO edge_actor;
GRANT UPDATE (course_id, course_disambiguated_by, score_badge, score_monetary, hard_signal, presence_signal, money,
              held_review, policy_version, input_digest, status) ON app.play TO edge_actor;

GRANT SELECT ON app.play_evidence TO edge_actor;
GRANT INSERT (play_id, evidence_id, user_id) ON app.play_evidence TO edge_actor;

GRANT SELECT (id, user_id, kind, detail, created_at, cleared_at) ON app.fraud_signal TO edge_actor;
GRANT INSERT (user_id, kind, detail) ON app.fraud_signal TO edge_actor;

GRANT SELECT ON app.checkin_challenge TO edge_actor;
GRANT INSERT (user_id, staff_user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) ON app.checkin_challenge TO edge_actor;
GRANT UPDATE (used_at) ON app.checkin_challenge TO edge_actor;

GRANT SELECT ON app.checkin_token TO edge_actor;
GRANT INSERT (challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) ON app.checkin_token TO edge_actor;
GRANT UPDATE (consumed_at) ON app.checkin_token TO edge_actor;

GRANT SELECT ON app.push_token TO edge_actor;
GRANT INSERT (user_id, device_id, expo_token, updated_at) ON app.push_token TO edge_actor;
GRANT UPDATE (expo_token, updated_at) ON app.push_token TO edge_actor;

GRANT SELECT (user_id, provider) ON app.signin_provider_token TO edge_actor;
GRANT SELECT (user_id, provider) ON app.connector_account TO edge_actor;
GRANT SELECT ON app.app_review_demo_account TO edge_actor;

GRANT SELECT ON app.device_reward_ledger TO edge_actor;
GRANT INSERT (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id) ON app.device_reward_ledger TO edge_actor;

GRANT SELECT ON app.offer_code TO edge_actor;
GRANT UPDATE (state, reserved_amount, activated_device_id, devicecheck_token_hash, activated_at, hold_detail) ON app.offer_code TO edge_actor;
GRANT SELECT ON app.entitlement TO edge_actor;
GRANT UPDATE (state, activated_device_id, devicecheck_token_hash, activated_at, hold_detail) ON app.entitlement TO edge_actor;

GRANT SELECT ON app.offer TO edge_actor;
GRANT UPDATE (budget_reserved) ON app.offer TO edge_actor;
GRANT SELECT (kind, subject_table, subject_id, resolved_at) ON app.review_item TO edge_actor;
GRANT INSERT (kind, subject_table, subject_id, detail) ON app.review_item TO edge_actor;
-- P3f round 3: the install-link tombstone (no user column; policies are keyed on the actor's account pseudonym).
GRANT SELECT (install_link_hash, account_pseudonym) ON app.install_link_account TO edge_actor;
GRANT INSERT (install_link_hash, account_pseudonym, account_pseudonym_hmac_id) ON app.install_link_account TO edge_actor;
GRANT SELECT (actor_user_id, action, subject_table, subject_id) ON app.audit_log TO edge_actor;
GRANT INSERT (actor_user_id, action, subject_table, subject_id, detail) ON app.audit_log TO edge_actor;

GRANT SELECT ON app.catalog_version, app.catalog_id_ledger, app.catalog_facility, app.catalog_course, app.catalog_hole TO edge_actor;
GRANT SELECT (kid, public_key_b64url, revoked_at) ON app.catalog_signing_key TO edge_actor;
GRANT SELECT (kid, recorded_at) ON app.catalog_kid_revocation TO edge_actor;
GRANT SELECT (course_id, done_at) ON app.catalog_rescore_backlog TO edge_actor;

-- ---- edge_system ----
GRANT SELECT, INSERT ON app.catalog_version TO edge_system;
GRANT SELECT (kid, public_key_b64url, revoked_at) ON app.catalog_signing_key TO edge_system;
GRANT SELECT, INSERT ON app.catalog_kid_revocation TO edge_system;
GRANT SELECT, INSERT ON app.catalog_id_ledger TO edge_system;
GRANT UPDATE (status, verified_in_version, tombstoned_at, merged_into, split_from) ON app.catalog_id_ledger TO edge_system;
GRANT SELECT, INSERT ON app.catalog_trail, app.catalog_designer, app.catalog_facility, app.catalog_hole TO edge_system;
GRANT UPDATE (slug, name, catalog_version) ON app.catalog_trail TO edge_system;
GRANT UPDATE (name, catalog_version) ON app.catalog_designer TO edge_system;
GRANT UPDATE (slug, region, tz, name, catalog_version) ON app.catalog_facility TO edge_system;
GRANT UPDATE (course_id, number, catalog_version) ON app.catalog_hole TO edge_system;
-- The importer never writes geometry (no geometry pipeline yet): INSERT excludes boundary / radius_* / geometry_kind.
GRANT SELECT ON app.catalog_course TO edge_system;
GRANT INSERT (id, facility_id, designer_id, name, holes, verification_status, closed, catalog_version) ON app.catalog_course TO edge_system;
GRANT UPDATE (facility_id, designer_id, name, holes, verification_status, closed, catalog_version) ON app.catalog_course TO edge_system;
GRANT SELECT, INSERT ON app.catalog_roster_version, app.catalog_roster_member TO edge_system;
GRANT SELECT ON app.catalog_rescore_backlog TO edge_system;
GRANT INSERT (course_id, reason, catalog_version) ON app.catalog_rescore_backlog TO edge_system;
GRANT UPDATE (cursor_play_id, cursor_created_at, done_at, finished_at, swept) ON app.catalog_rescore_backlog TO edge_system;

-- ============================================================================
-- 2. EXECUTE on the app.* functions the actor's writes run (invoker-rights, so the writing role needs
--    EXECUTE). NOT granted: resolve_held_*, mark_account_devices_fraud_voided (admin paths),
--    reserve/consume_offer_budget, dedupe_receipt_fingerprint, device_link_signals (its cross-account
--    read would silently undercount under edge_actor's policies: private.device_link_signals_for_actor
--    replaces it).
-- ============================================================================
GRANT EXECUTE ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text, jsonb) TO edge_actor;
GRANT EXECUTE ON FUNCTION app.activate_entitlement(uuid, uuid, uuid, text, text, jsonb) TO edge_actor;
GRANT EXECUTE ON FUNCTION app.reserve_offer_for_code(uuid, uuid, text) TO edge_actor;
GRANT EXECUTE ON FUNCTION app.release_offer_budget(uuid, numeric) TO edge_actor;
GRANT EXECUTE ON FUNCTION app.release_account_reservations(uuid) TO edge_actor;
GRANT EXECUTE ON FUNCTION app.record_install_link(uuid, uuid, text) TO edge_actor;
-- Two private.* functions the tombstone path runs as the WRITING role (the policy and app.record_install_link
-- call private.account_pseudonyms; the install_link_account BEFORE INSERT trigger calls the registrar). They are
-- owned by private_definer, so only the owner can grant EXECUTE: bracketed SET ROLE, no schema CREATE needed.
-- Residual R3: account_pseudonyms(uuid) takes any uid, so edge_actor can compute any account's vault-keyed
-- pseudonym; no worse than bind_actor(any uid) (it can already act as that account), and it reveals only an HMAC.
SET ROLE private_definer;
GRANT EXECUTE ON FUNCTION private.account_pseudonyms(uuid) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.validate_and_register_pseudonym_hmac_id(uuid) TO edge_actor;
RESET ROLE;

-- 2b. The registry table. Created and filled here, THEN row-secured (a table's owner can insert into
-- its own table before RLS is switched on, which saves a temporary self-granting policy).
CREATE TABLE private.edge_policy_allowlist (
  schema_name text NOT NULL,
  table_name text NOT NULL,
  policy_name text NOT NULL,
  role_name text NOT NULL CHECK (role_name IN ('edge_actor', 'edge_system')),
  command text NOT NULL,
  scope text NOT NULL CHECK (scope IN ('actor', 'open_read', 'system_write')),
  note text NOT NULL,
  using_expr text,
  with_check_expr text,
  PRIMARY KEY (schema_name, table_name, policy_name)
);
COMMENT ON TABLE private.edge_policy_allowlist IS
  'Every RLS policy that applies to edge_actor or edge_system, by name, with its role and deparsed USING / WITH CHECK text (0031). Compared with the live pg_policy rows in BOTH directions by tools/db/verify-function-inventory.mjs (checks 10-12) and supabase/tests/matrix/10_function_inventory.sql; mirrored by supabase/tests/fixtures/edge_policy_exprs.txt so a self-consistent policy+row edit still shows up as a diff in review. scope: actor = user-scoped (must contain private.actor_uid()); open_read = SELECT USING (true) on public catalog data; system_write = edge_system catalog access.';


-- ============================================================================
-- 3. Policies (generated from one spec together with the allowlist rows in section 5)
-- ============================================================================

-- ---- edge_actor ----
CREATE POLICY edge_actor_device_select ON app.device
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_device_insert ON app.device
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_device_update ON app.device
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_evidence_select ON app.evidence
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_evidence_insert ON app.evidence
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_evidence_update ON app.evidence
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_play_select ON app.play
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_play_insert ON app.play
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_play_update ON app.play
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_play_evidence_select ON app.play_evidence
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_play_evidence_insert ON app.play_evidence
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()) AND EXISTS (SELECT 1 FROM app.play p WHERE p.id = play_id AND p.user_id = (SELECT private.actor_uid())) AND EXISTS (SELECT 1 FROM app.evidence e WHERE e.id = evidence_id AND e.user_id = (SELECT private.actor_uid())));
CREATE POLICY edge_actor_fraud_signal_select ON app.fraud_signal
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_fraud_signal_insert ON app.fraud_signal
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_checkin_challenge_select ON app.checkin_challenge
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_checkin_challenge_insert ON app.checkin_challenge
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()) AND staff_user_id IS NULL);
CREATE POLICY edge_actor_checkin_challenge_update ON app.checkin_challenge
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_checkin_token_select ON app.checkin_token
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_checkin_token_insert ON app.checkin_token
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_checkin_token_update ON app.checkin_token
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_push_token_select ON app.push_token
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_push_token_insert ON app.push_token
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_push_token_update ON app.push_token
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_signin_provider_token_select ON app.signin_provider_token
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_connector_account_select ON app.connector_account
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_app_review_demo_account_select ON app.app_review_demo_account
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_device_reward_ledger_select ON app.device_reward_ledger
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_device_reward_ledger_insert ON app.device_reward_ledger
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()) AND EXISTS (SELECT 1 FROM app.device d WHERE d.id = device_id AND d.user_id = (SELECT private.actor_uid())));
CREATE POLICY edge_actor_offer_code_select ON app.offer_code
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_offer_code_update ON app.offer_code
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_entitlement_select ON app.entitlement
  FOR SELECT TO edge_actor
  USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_entitlement_update ON app.entitlement
  FOR UPDATE TO edge_actor
  USING (user_id = (SELECT private.actor_uid()))
  WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY edge_actor_offer_select ON app.offer
  FOR SELECT TO edge_actor
  USING (EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.offer_id = offer.id AND oc.user_id = (SELECT private.actor_uid())));
CREATE POLICY edge_actor_offer_update ON app.offer
  FOR UPDATE TO edge_actor
  USING (EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.offer_id = offer.id AND oc.user_id = (SELECT private.actor_uid())))
  WITH CHECK (EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.offer_id = offer.id AND oc.user_id = (SELECT private.actor_uid())));
CREATE POLICY edge_actor_review_item_insert ON app.review_item
  FOR INSERT TO edge_actor
  WITH CHECK (subject_table = 'offer_code' AND kind IN ('held_offer_budget_unreserved', 'issued_offer_budget_unreserved') AND EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.id = subject_id AND oc.user_id = (SELECT private.actor_uid())));
CREATE POLICY edge_actor_review_item_select ON app.review_item
  FOR SELECT TO edge_actor
  USING (subject_table = 'offer_code' AND EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.id = review_item.subject_id AND oc.user_id = (SELECT private.actor_uid())));
CREATE POLICY edge_actor_install_link_account_select ON app.install_link_account
  FOR SELECT TO edge_actor
  USING (CASE WHEN (SELECT private.actor_uid()) IS NULL THEN false ELSE account_pseudonym IN (SELECT a.pseudonym FROM private.account_pseudonyms((SELECT private.actor_uid())) a) END);
CREATE POLICY edge_actor_install_link_account_insert ON app.install_link_account
  FOR INSERT TO edge_actor
  WITH CHECK (CASE WHEN (SELECT private.actor_uid()) IS NULL THEN false ELSE account_pseudonym IN (SELECT a.pseudonym FROM private.account_pseudonyms((SELECT private.actor_uid())) a) END);
CREATE POLICY edge_actor_audit_log_select ON app.audit_log
  FOR SELECT TO edge_actor
  USING (actor_user_id = (SELECT private.actor_uid()) AND action = 'play.repick');
CREATE POLICY edge_actor_audit_log_insert ON app.audit_log
  FOR INSERT TO edge_actor
  WITH CHECK (actor_user_id = (SELECT private.actor_uid()) AND action = 'play.repick' AND subject_table = 'play');
CREATE POLICY edge_actor_catalog_version_read ON app.catalog_version
  FOR SELECT TO edge_actor
  USING (true);
CREATE POLICY edge_actor_catalog_id_ledger_read ON app.catalog_id_ledger
  FOR SELECT TO edge_actor
  USING (true);
CREATE POLICY edge_actor_catalog_facility_read ON app.catalog_facility
  FOR SELECT TO edge_actor
  USING (true);
CREATE POLICY edge_actor_catalog_course_read ON app.catalog_course
  FOR SELECT TO edge_actor
  USING (true);
CREATE POLICY edge_actor_catalog_hole_read ON app.catalog_hole
  FOR SELECT TO edge_actor
  USING (true);
CREATE POLICY edge_actor_catalog_signing_key_read ON app.catalog_signing_key
  FOR SELECT TO edge_actor
  USING (true);
CREATE POLICY edge_actor_catalog_kid_revocation_read ON app.catalog_kid_revocation
  FOR SELECT TO edge_actor
  USING (true);
CREATE POLICY edge_actor_catalog_rescore_backlog_read ON app.catalog_rescore_backlog
  FOR SELECT TO edge_actor
  USING (true);

-- ---- edge_system ----
CREATE POLICY edge_system_catalog_version_select ON app.catalog_version
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_version_insert ON app.catalog_version
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_signing_key_select ON app.catalog_signing_key
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_kid_revocation_select ON app.catalog_kid_revocation
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_kid_revocation_insert ON app.catalog_kid_revocation
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_id_ledger_select ON app.catalog_id_ledger
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_id_ledger_insert ON app.catalog_id_ledger
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_id_ledger_update ON app.catalog_id_ledger
  FOR UPDATE TO edge_system
  USING (true)
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_trail_select ON app.catalog_trail
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_trail_insert ON app.catalog_trail
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_trail_update ON app.catalog_trail
  FOR UPDATE TO edge_system
  USING (true)
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_designer_select ON app.catalog_designer
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_designer_insert ON app.catalog_designer
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_designer_update ON app.catalog_designer
  FOR UPDATE TO edge_system
  USING (true)
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_facility_select ON app.catalog_facility
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_facility_insert ON app.catalog_facility
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_facility_update ON app.catalog_facility
  FOR UPDATE TO edge_system
  USING (true)
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_hole_select ON app.catalog_hole
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_hole_insert ON app.catalog_hole
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_hole_update ON app.catalog_hole
  FOR UPDATE TO edge_system
  USING (true)
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_course_select ON app.catalog_course
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_course_insert ON app.catalog_course
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_course_update ON app.catalog_course
  FOR UPDATE TO edge_system
  USING (true)
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_roster_version_select ON app.catalog_roster_version
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_roster_version_insert ON app.catalog_roster_version
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_roster_member_select ON app.catalog_roster_member
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_roster_member_insert ON app.catalog_roster_member
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_rescore_backlog_select ON app.catalog_rescore_backlog
  FOR SELECT TO edge_system
  USING (true);
CREATE POLICY edge_system_catalog_rescore_backlog_insert ON app.catalog_rescore_backlog
  FOR INSERT TO edge_system
  WITH CHECK (true);
CREATE POLICY edge_system_catalog_rescore_backlog_update ON app.catalog_rescore_backlog
  FOR UPDATE TO edge_system
  USING (true)
  WITH CHECK (true);

-- ============================================================================
-- 5. private.edge_policy_allowlist: every policy above, by name, with its deparsed text
-- ============================================================================
INSERT INTO private.edge_policy_allowlist (schema_name, table_name, policy_name, role_name, command, scope, note) VALUES
  ('app', 'device', 'edge_actor_device_select', 'edge_actor', 'SELECT', 'actor', 'own devices'),
  ('app', 'device', 'edge_actor_device_insert', 'edge_actor', 'INSERT', 'actor', 'Repo#device.ensureOwn registers the actor''s own device'),
  ('app', 'device', 'edge_actor_device_update', 'edge_actor', 'UPDATE', 'actor', 'attestation counter / verdict / install link of the actor''s own device (column grant excludes attest_key_id, attest_public_key, fraud_voided_at)'),
  ('app', 'evidence', 'edge_actor_evidence_select', 'edge_actor', 'SELECT', 'actor', 'own evidence'),
  ('app', 'evidence', 'edge_actor_evidence_insert', 'edge_actor', 'INSERT', 'actor', 'intake inserts the actor''s own evidence'),
  ('app', 'evidence', 'edge_actor_evidence_update', 'edge_actor', 'UPDATE', 'actor', 're-score / queued-row resolution / re-pick of the actor''s own evidence (column grant: summary, integrity, status, ids, grade, queued_*)'),
  ('app', 'play', 'edge_actor_play_select', 'edge_actor', 'SELECT', 'actor', 'own plays'),
  ('app', 'play', 'edge_actor_play_insert', 'edge_actor', 'INSERT', 'actor', 'upsertFromScore inserts the actor''s own play'),
  ('app', 'play', 'edge_actor_play_update', 'edge_actor', 'UPDATE', 'actor', 'score columns, the user-pick label, the re-pick course move, held_review -- the 0017 held-review cascade trigger fires from this UPDATE as the writing role'),
  ('app', 'play_evidence', 'edge_actor_play_evidence_select', 'edge_actor', 'SELECT', 'actor', 'own links (ON CONFLICT inference reads them)'),
  ('app', 'play_evidence', 'edge_actor_play_evidence_insert', 'edge_actor', 'INSERT', 'actor', 'a link row only between the actor''s own play and the actor''s own evidence'),
  ('app', 'fraud_signal', 'edge_actor_fraud_signal_select', 'edge_actor', 'SELECT', 'actor', 'own signals: the once-only / open-attestation_failed checks read them (columns exclude cleared_by)'),
  ('app', 'fraud_signal', 'edge_actor_fraud_signal_insert', 'edge_actor', 'INSERT', 'actor', 'intake and activation raise signals about the actor only'),
  ('app', 'checkin_challenge', 'edge_actor_checkin_challenge_select', 'edge_actor', 'SELECT', 'actor', 'own challenges'),
  ('app', 'checkin_challenge', 'edge_actor_checkin_challenge_insert', 'edge_actor', 'INSERT', 'actor', 'a player-issued challenge for the actor; a staff-issued one is not an edge_actor path'),
  ('app', 'checkin_challenge', 'edge_actor_checkin_challenge_update', 'edge_actor', 'UPDATE', 'actor', 'consume: used_at (column grant: used_at only); the used_at_once trigger still makes it one-way'),
  ('app', 'checkin_token', 'edge_actor_checkin_token_select', 'edge_actor', 'SELECT', 'actor', 'own tokens'),
  ('app', 'checkin_token', 'edge_actor_checkin_token_insert', 'edge_actor', 'INSERT', 'actor', 'token issuance for the actor'),
  ('app', 'checkin_token', 'edge_actor_checkin_token_update', 'edge_actor', 'UPDATE', 'actor', 'consumeForFix: consumed_at only (column grant)'),
  ('app', 'push_token', 'edge_actor_push_token_select', 'edge_actor', 'SELECT', 'actor', 'own tokens'),
  ('app', 'push_token', 'edge_actor_push_token_insert', 'edge_actor', 'INSERT', 'actor', 'registration'),
  ('app', 'push_token', 'edge_actor_push_token_update', 'edge_actor', 'UPDATE', 'actor', 'ON CONFLICT DO UPDATE: expo_token, updated_at'),
  ('app', 'signin_provider_token', 'edge_actor_signin_provider_token_select', 'edge_actor', 'SELECT', 'actor', 'own grants; column grant is user_id, provider only (never the ciphertext)'),
  ('app', 'connector_account', 'edge_actor_connector_account_select', 'edge_actor', 'SELECT', 'actor', 'own connectors; column grant is user_id, provider only (never the ciphertext)'),
  ('app', 'app_review_demo_account', 'edge_actor_app_review_demo_account_select', 'edge_actor', 'SELECT', 'actor', 'is the actor the app-review demo account (§4.7.7 answer)'),
  ('app', 'device_reward_ledger', 'edge_actor_device_reward_ledger_select', 'edge_actor', 'SELECT', 'actor', 'own ledger: hasPriorReward'),
  ('app', 'device_reward_ledger', 'edge_actor_device_reward_ledger_insert', 'edge_actor', 'INSERT', 'actor', 'the activation functions record the actor''s own reward on the actor''s own device'),
  ('app', 'offer_code', 'edge_actor_offer_code_select', 'edge_actor', 'SELECT', 'actor', 'own codes (activate_offer_code SELECT * ... FOR UPDATE)'),
  ('app', 'offer_code', 'edge_actor_offer_code_update', 'edge_actor', 'UPDATE', 'actor', 'activation + the play-hold cascade: state, reserved_amount, activated_device_id, devicecheck_token_hash, activated_at, hold_detail (column grant)'),
  ('app', 'entitlement', 'edge_actor_entitlement_select', 'edge_actor', 'SELECT', 'actor', 'own entitlements'),
  ('app', 'entitlement', 'edge_actor_entitlement_update', 'edge_actor', 'UPDATE', 'actor', 'activation + the play-hold cascade: state, activated_device_id, devicecheck_token_hash, activated_at, hold_detail (column grant)'),
  ('app', 'offer', 'edge_actor_offer_select', 'edge_actor', 'SELECT', 'actor', 'an offer the actor holds a code on (reserve_offer_for_code reads it)'),
  ('app', 'offer', 'edge_actor_offer_update', 'edge_actor', 'UPDATE', 'actor', 'budget_reserved only (column grant), only on an offer the actor holds a code on: the reservation trigger and the P3f functions are invoker-rights. Residual risk R1 in docs/security/edge-role-design.md'),
  ('app', 'review_item', 'edge_actor_review_item_insert', 'edge_actor', 'INSERT', 'actor', 'the ''budget could not be reserved'' review item for one of the actor''s own codes (reserve_offer_for_code)'),
  ('app', 'review_item', 'edge_actor_review_item_select', 'edge_actor', 'SELECT', 'actor', 'the once-per-code check inside reserve_offer_for_code (P3f round 3: NOT EXISTS an open review item) reads the actor''s own budget-unreserved items'),
  ('app', 'install_link_account', 'edge_actor_install_link_account_select', 'edge_actor', 'SELECT', 'actor', 'the actor''s own install-link tombstone rows (matched by the actor''s account pseudonym under any active vault key)'),
  ('app', 'install_link_account', 'edge_actor_install_link_account_insert', 'edge_actor', 'INSERT', 'actor', 'app.record_install_link writes the tombstone row for the actor''s own pseudonym only'),
  ('app', 'audit_log', 'edge_actor_audit_log_select', 'edge_actor', 'SELECT', 'actor', 'the one-re-pick-per-play record'),
  ('app', 'audit_log', 'edge_actor_audit_log_insert', 'edge_actor', 'INSERT', 'actor', 'the re-pick audit row'),
  ('app', 'catalog_version', 'edge_actor_catalog_version_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: catalog versions'),
  ('app', 'catalog_id_ledger', 'edge_actor_catalog_id_ledger_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: the id ledger'),
  ('app', 'catalog_facility', 'edge_actor_catalog_facility_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: facilities'),
  ('app', 'catalog_course', 'edge_actor_catalog_course_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: courses (incl. the geometry the matcher reads)'),
  ('app', 'catalog_hole', 'edge_actor_catalog_hole_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: holes'),
  ('app', 'catalog_signing_key', 'edge_actor_catalog_signing_key_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: public signing keys (column grant: kid, public_key_b64url, revoked_at)'),
  ('app', 'catalog_kid_revocation', 'edge_actor_catalog_kid_revocation_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: revoked kids (column grant: kid, recorded_at)'),
  ('app', 'catalog_rescore_backlog', 'edge_actor_catalog_rescore_backlog_read', 'edge_actor', 'SELECT', 'open_read', 'public catalog data: open-backlog existence (column grant: course_id, done_at)'),
  ('app', 'catalog_version', 'edge_system_catalog_version_select', 'edge_system', 'SELECT', 'system_write', 'append-only version table: read'),
  ('app', 'catalog_version', 'edge_system_catalog_version_insert', 'edge_system', 'INSERT', 'system_write', 'append-only version table: import'),
  ('app', 'catalog_signing_key', 'edge_system_catalog_signing_key_select', 'edge_system', 'SELECT', 'system_write', 'public keys (column grant)'),
  ('app', 'catalog_kid_revocation', 'edge_system_catalog_kid_revocation_select', 'edge_system', 'SELECT', 'system_write', 'append-only revocation record: read'),
  ('app', 'catalog_kid_revocation', 'edge_system_catalog_kid_revocation_insert', 'edge_system', 'INSERT', 'system_write', 'append-only revocation record: import'),
  ('app', 'catalog_id_ledger', 'edge_system_catalog_id_ledger_select', 'edge_system', 'SELECT', 'system_write', 'id ledger: read'),
  ('app', 'catalog_id_ledger', 'edge_system_catalog_id_ledger_insert', 'edge_system', 'INSERT', 'system_write', 'id ledger: import'),
  ('app', 'catalog_id_ledger', 'edge_system_catalog_id_ledger_update', 'edge_system', 'UPDATE', 'system_write', 'id ledger: upsert / ledger state (column grant)'),
  ('app', 'catalog_trail', 'edge_system_catalog_trail_select', 'edge_system', 'SELECT', 'system_write', 'catalog trail: read'),
  ('app', 'catalog_trail', 'edge_system_catalog_trail_insert', 'edge_system', 'INSERT', 'system_write', 'catalog trail: import'),
  ('app', 'catalog_trail', 'edge_system_catalog_trail_update', 'edge_system', 'UPDATE', 'system_write', 'catalog trail: upsert / ledger state (column grant)'),
  ('app', 'catalog_designer', 'edge_system_catalog_designer_select', 'edge_system', 'SELECT', 'system_write', 'catalog designer: read'),
  ('app', 'catalog_designer', 'edge_system_catalog_designer_insert', 'edge_system', 'INSERT', 'system_write', 'catalog designer: import'),
  ('app', 'catalog_designer', 'edge_system_catalog_designer_update', 'edge_system', 'UPDATE', 'system_write', 'catalog designer: upsert / ledger state (column grant)'),
  ('app', 'catalog_facility', 'edge_system_catalog_facility_select', 'edge_system', 'SELECT', 'system_write', 'catalog facility: read'),
  ('app', 'catalog_facility', 'edge_system_catalog_facility_insert', 'edge_system', 'INSERT', 'system_write', 'catalog facility: import'),
  ('app', 'catalog_facility', 'edge_system_catalog_facility_update', 'edge_system', 'UPDATE', 'system_write', 'catalog facility: upsert / ledger state (column grant)'),
  ('app', 'catalog_hole', 'edge_system_catalog_hole_select', 'edge_system', 'SELECT', 'system_write', 'catalog hole: read'),
  ('app', 'catalog_hole', 'edge_system_catalog_hole_insert', 'edge_system', 'INSERT', 'system_write', 'catalog hole: import'),
  ('app', 'catalog_hole', 'edge_system_catalog_hole_update', 'edge_system', 'UPDATE', 'system_write', 'catalog hole: upsert / ledger state (column grant)'),
  ('app', 'catalog_course', 'edge_system_catalog_course_select', 'edge_system', 'SELECT', 'system_write', 'catalog course: read'),
  ('app', 'catalog_course', 'edge_system_catalog_course_insert', 'edge_system', 'INSERT', 'system_write', 'catalog course: import'),
  ('app', 'catalog_course', 'edge_system_catalog_course_update', 'edge_system', 'UPDATE', 'system_write', 'catalog course: upsert / ledger state (column grant)'),
  ('app', 'catalog_roster_version', 'edge_system_catalog_roster_version_select', 'edge_system', 'SELECT', 'system_write', 'roster versions (ON CONFLICT DO NOTHING): read'),
  ('app', 'catalog_roster_version', 'edge_system_catalog_roster_version_insert', 'edge_system', 'INSERT', 'system_write', 'roster versions (ON CONFLICT DO NOTHING): import'),
  ('app', 'catalog_roster_member', 'edge_system_catalog_roster_member_select', 'edge_system', 'SELECT', 'system_write', 'roster members: read'),
  ('app', 'catalog_roster_member', 'edge_system_catalog_roster_member_insert', 'edge_system', 'INSERT', 'system_write', 'roster members: import'),
  ('app', 'catalog_rescore_backlog', 'edge_system_catalog_rescore_backlog_select', 'edge_system', 'SELECT', 'system_write', 'AT 18 backlog: read'),
  ('app', 'catalog_rescore_backlog', 'edge_system_catalog_rescore_backlog_insert', 'edge_system', 'INSERT', 'system_write', 'AT 18 backlog: import'),
  ('app', 'catalog_rescore_backlog', 'edge_system_catalog_rescore_backlog_update', 'edge_system', 'UPDATE', 'system_write', 'AT 18 backlog: upsert / ledger state (column grant)');

-- ============================================================================
-- 6. Capture the live expression text, then row-secure the registry
-- ============================================================================
-- Copied off the pg_policy rows just created (never hand-typed), the same way 0016 does it for
-- private.definer_policy_allowlist.
UPDATE private.edge_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name;
ALTER TABLE private.edge_policy_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.edge_policy_allowlist FORCE ROW LEVEL SECURITY;
GRANT SELECT ON private.edge_policy_allowlist TO service_role;

-- ============================================================================
-- 7. function_inventory: the edge EXECUTE flags of the pre-existing app.* functions granted above
-- ============================================================================
-- function_inventory has only the 0017 owner INSERT policy; UPDATE needs the temporary, self-revoked
-- CURRENT_USER policy (FOR ALL: an UPDATE ... WHERE also needs SELECT-level visibility, see 0016).
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0031 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.function_inventory SET expected_edge_actor = true
WHERE (schema_name, function_name, identity_args) IN (
  ('app', 'activate_offer_code', 'p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb'),
  ('app', 'activate_entitlement', 'p_entitlement_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb'),
  ('app', 'reserve_offer_for_code', 'p_offer_id uuid, p_code_id uuid, p_review_kind text'),
  ('app', 'release_offer_budget', 'p_offer_id uuid, p_amount numeric'),
  ('app', 'release_account_reservations', 'p_user_id uuid'),
  ('app', 'record_install_link', 'p_user_id uuid, p_device_id uuid, p_link_hash text'),
  ('private', 'account_pseudonyms', 'p_user_id uuid'),
  ('private', 'validate_and_register_pseudonym_hmac_id', 'p_key_id uuid')
);
DROP POLICY current_user_edit_function_inventory_0031 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

-- ============================================================================
-- 8. The nonce tombstone trigger function (the ONE trigger function this migration redefines)
-- ============================================================================
-- Same trigger (checkin_challenge_tombstone_nonce_trg, BEFORE INSERT), same contract and error as
-- 0017: a nonce hash that was ever inserted can never be inserted again. The only change is WHO writes
-- the ledger: it used to read and INSERT private.consumed_nonce as the writing role, which edge_actor
-- cannot reach by design; it now calls private.record_consumed_nonce (0030, SECURITY DEFINER). The
-- app.attestation twin (attestation_tombstone_nonce) is a partner path, not an Edge path: untouched.
CREATE OR REPLACE FUNCTION app.checkin_challenge_tombstone_nonce() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  PERFORM private.record_consumed_nonce(NEW.nonce_hash, NEW.expires_at);
  RETURN NEW;
END;
$$;

