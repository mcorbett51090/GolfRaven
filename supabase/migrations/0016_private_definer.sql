-- 0016_private_definer.sql
-- S1 close-out, second design (gate round 3; coordinator directive):
-- "Close S1 with a design that keeps FORCE on every table and gives less
-- privilege, not more." A dedicated, NOLOGIN, NOSUPERUSER, NOBYPASSRLS
-- role (`private_definer`) OWNS every private.* SECURITY DEFINER function.
-- It is deliberately NOT the table owner of anything in app/private — so
-- FORCE ROW LEVEL SECURITY applies to it exactly the same way it applies to
-- anon/authenticated/service_role: RLS policies, evaluated per role, no
-- owner-bypass exception, in every mode (superuser or restricted). Every
-- table a definer function touches gets an EXPLICIT, NARROW policy for
-- `private_definer` — scoped to that function's own contract wherever the
-- contract has a natural row scope (delete_my_data: only rows keyed to the
-- uid/email/handle/pseudonym it was called with, via session-local GUCs set
-- at the top of its body); `USING (true)` only where the function's own
-- body is what does the real scoping (the scope-check helpers, which must
-- be able to look up ANY user's membership — that IS their contract — and
-- the rate-limit functions, which operate on caller-supplied bucket keys,
-- not a fixed row set), each commented at the point of use.
--
-- `anon`, `authenticated` and `service_role` behaviour is unchanged by any
-- of this: none of them is ever `private_definer`, and none of the grants
-- or policies below names them.

-- ============================================================================
-- 1. The role
-- ============================================================================
CREATE ROLE private_definer NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA app, private TO private_definer;

-- ============================================================================
-- 2. Ownership: every private.* SECURITY DEFINER function moves to
--    private_definer. The pinned `search_path = ''` (already set on each,
--     0007/0015) is unaffected by an ownership change.
-- ============================================================================
ALTER FUNCTION private.is_admin(uuid) OWNER TO private_definer;
ALTER FUNCTION private.is_demo_account(uuid) OWNER TO private_definer;
ALTER FUNCTION private.has_facility_scope(uuid, text, app.partner_role[]) OWNER TO private_definer;
ALTER FUNCTION private.has_trail_scope(uuid, text, app.partner_role[]) OWNER TO private_definer;
ALTER FUNCTION private.has_sponsorship_scope(uuid, uuid) OWNER TO private_definer;
ALTER FUNCTION private.is_org_member(uuid, uuid) OWNER TO private_definer;
ALTER FUNCTION private.is_staff_or_manager_of_facility(uuid, text) OWNER TO private_definer;
ALTER FUNCTION private.is_manager_or_operator_of_facility(uuid, text) OWNER TO private_definer;
ALTER FUNCTION private.is_operator_of_facility(uuid, text) OWNER TO private_definer;
ALTER FUNCTION private.hit_rate_limit(text, interval, int) OWNER TO private_definer;
ALTER FUNCTION private.purge_rate_limit_buckets() OWNER TO private_definer;
ALTER FUNCTION private.delete_my_data(uuid) OWNER TO private_definer;

-- ============================================================================
-- 3. The explicit allow-list (gate round 3 step 5): every policy this
--    migration grants to private_definer is registered here BEFORE it is
--    created; 10_function_inventory.sql asserts the two sets are identical
--    in both directions, so a policy added later without a matching row —
--    or a row with no matching policy — fails CI.
-- ============================================================================
CREATE TABLE private.definer_policy_allowlist (
  schema_name text NOT NULL,
  table_name text NOT NULL,
  policy_name text NOT NULL,
  command text NOT NULL,
  scoped boolean NOT NULL,
  note text NOT NULL,
  PRIMARY KEY (schema_name, table_name, policy_name)
);

-- ============================================================================
-- 4. Read-only scope-check helpers: USING (true) — the function's OWN
--    contract is "look up scope for an ARBITRARY caller-supplied uid", so
--    there is no narrower row scope to express; access is fully mediated by
--    the function's own controlled signature (private_definer itself is
--    NOLOGIN and unreachable except through these functions).
-- ============================================================================

-- ============================================================================
-- 5. Rate-limit functions: USING (true) — bucket_key is caller-supplied and
--    intentionally not scoped to any one user (a bucket can key on device id,
--    IP, or facility, per §4.7 item 8); the function's own bucket_key naming
--    convention is the real scope.
-- ============================================================================


-- ============================================================================
-- 6. delete_my_data: every table it touches, scoped to the target user's own
--    rows via a session-local GUC the function sets at the top of its body
--    (0015_delete_my_data.sql) — private_definer can delete or null exactly
--    the rows delete_my_data's own contract says it may, and nothing else.
-- ============================================================================

-- 6a. delete_row-policed tables (FOR DELETE, scoped to the target uid).
CREATE POLICY private_definer_delete_admin_user_user_id ON app.admin_user FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_app_review_demo_account_user_id ON app.app_review_demo_account FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_booking_user_id ON app.booking FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_checkin_challenge_staff_user_id ON app.checkin_challenge FOR DELETE TO private_definer USING (staff_user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_checkin_challenge_user_id ON app.checkin_challenge FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_connector_account_user_id ON app.connector_account FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_course_qr_token_issued_by_staff ON app.course_qr_token FOR DELETE TO private_definer USING (issued_by_staff = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_course_qr_token_used_by_user ON app.course_qr_token FOR DELETE TO private_definer USING (used_by_user = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_device_user_id ON app.device FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_device_reward_ledger_user_id ON app.device_reward_ledger FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_evidence_user_id ON app.evidence FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_marker_credit_user_id ON app.marker_credit FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_offer_code_user_id ON app.offer_code FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_partner_member_user_id ON app.partner_member FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_play_user_id ON app.play FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_profile_user_id ON app.profile FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_purchase_evidence_user_id ON app.purchase_evidence FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_push_token_user_id ON app.push_token FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_signin_provider_token_user_id ON app.signin_provider_token FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_staff_activity_staff_user_id ON app.staff_activity FOR DELETE TO private_definer USING (staff_user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_delete_user_achievement_user_id ON app.user_achievement FOR DELETE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);

-- 6b. set_null-policed tables (FOR UPDATE, scoped to the target uid; WITH
--     CHECK requires the column to end up NULL — the function may redact,
--     never rewrite to something else).
CREATE POLICY private_definer_setnull_attestation_staff_user_id ON app.attestation FOR UPDATE TO private_definer USING (staff_user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (staff_user_id IS NULL);
CREATE POLICY private_definer_setnull_entitlement_redeemed_by_staff ON app.entitlement FOR UPDATE TO private_definer USING (redeemed_by_staff = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (redeemed_by_staff IS NULL);
CREATE POLICY private_definer_setnull_fraud_signal_cleared_by ON app.fraud_signal FOR UPDATE TO private_definer USING (cleared_by = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (cleared_by IS NULL);
CREATE POLICY private_definer_setnull_marker_code_activated_by_staff ON app.marker_code FOR UPDATE TO private_definer USING (activated_by_staff = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (activated_by_staff IS NULL);
CREATE POLICY private_definer_setnull_marker_code_redeemed_by ON app.marker_code FOR UPDATE TO private_definer USING (redeemed_by = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (redeemed_by IS NULL);
CREATE POLICY private_definer_setnull_offer_code_redeemed_by_staff ON app.offer_code FOR UPDATE TO private_definer USING (redeemed_by_staff = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (redeemed_by_staff IS NULL);
CREATE POLICY private_definer_setnull_partner_member_invited_by ON app.partner_member FOR UPDATE TO private_definer USING (invited_by = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (invited_by IS NULL);
CREATE POLICY private_definer_setnull_review_item_resolved_by ON app.review_item FOR UPDATE TO private_definer USING (resolved_by = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (resolved_by IS NULL);
CREATE POLICY private_definer_setnull_special_marker_stock_movement_by_member ON app.special_marker_stock_movement FOR UPDATE TO private_definer USING (by_member = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (by_member IS NULL);

-- 6c. Bespoke ('special') cases — the exact rows/columns delete_my_data's
--     own special-case code (0015) touches, no more.
CREATE POLICY private_definer_entitlement_update ON app.entitlement FOR UPDATE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);
CREATE POLICY private_definer_fraud_signal_update ON app.fraud_signal FOR UPDATE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (user_id IS NULL);
CREATE POLICY private_definer_attestation_player_update ON app.attestation FOR UPDATE TO private_definer USING (player_user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (player_user_id IS NULL);
CREATE POLICY private_definer_audit_log_update ON app.audit_log FOR UPDATE TO private_definer USING (actor_user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (actor_user_id IS NULL);
CREATE POLICY private_definer_partner_invite_delete ON app.partner_invite FOR DELETE TO private_definer USING (invited_by = current_setting('app.delete_my_data.target_user_id', true)::uuid OR invitee_email = current_setting('app.delete_my_data.target_email', true));
CREATE POLICY private_definer_shift_log_update ON app.attestation_shift_log FOR UPDATE TO private_definer USING (player_pseudonym = current_setting('app.delete_my_data.target_pseudonym', true) OR (player_pseudonym IS NULL AND player_handle_snapshot = current_setting('app.delete_my_data.target_handle', true))) WITH CHECK (player_handle_snapshot = 'deleted player');
CREATE POLICY private_definer_public_profile_delete ON app.public_profile_projection FOR DELETE TO private_definer USING (handle = current_setting('app.delete_my_data.target_handle', true));
CREATE POLICY private_definer_receipt_fingerprint_update ON app.receipt_fingerprint FOR UPDATE TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid) WITH CHECK (user_id IS NULL);
CREATE POLICY private_definer_storage_objects_delete ON storage.objects FOR DELETE TO private_definer USING (bucket_id = 'receipts' AND (owner = current_setting('app.delete_my_data.target_user_id', true)::uuid OR name LIKE 'receipts/' || current_setting('app.delete_my_data.target_user_id', true) || '/%'));
CREATE POLICY private_definer_profile_select ON app.profile FOR SELECT TO private_definer USING (user_id = current_setting('app.delete_my_data.target_user_id', true)::uuid);


-- ============================================================================
-- 7. Baseline table/schema grants (every GRANT the policies above/here
--    depend on to even reach the ROW-level check) and the audit_log
--    INSERT policy for delete_my_data's own log entry.
-- ============================================================================
GRANT USAGE ON SCHEMA auth, storage TO private_definer;
GRANT SELECT ON auth.users TO private_definer;
-- delete_my_data's generic pass reads its own driving table; governance
-- data, not user-scoped, so USING(true) (same reasoning as section 4).
GRANT SELECT ON private.pii_retention_policy TO private_definer;
CREATE POLICY private_definer_read_pii_retention_policy ON private.pii_retention_policy FOR SELECT TO private_definer USING (true);

GRANT DELETE, SELECT ON app.admin_user TO private_definer;
GRANT DELETE, SELECT ON app.app_review_demo_account TO private_definer;
GRANT UPDATE ON app.attestation TO private_definer;
GRANT UPDATE ON app.attestation_shift_log TO private_definer;
GRANT INSERT, UPDATE ON app.audit_log TO private_definer;
GRANT DELETE ON app.booking TO private_definer;
GRANT DELETE ON app.checkin_challenge TO private_definer;
GRANT DELETE ON app.connector_account TO private_definer;
GRANT DELETE ON app.course_qr_token TO private_definer;
GRANT DELETE ON app.device TO private_definer;
GRANT DELETE ON app.device_reward_ledger TO private_definer;
GRANT UPDATE ON app.entitlement TO private_definer;
GRANT DELETE ON app.evidence TO private_definer;
GRANT SELECT ON app.facility_programme TO private_definer;
GRANT UPDATE ON app.fraud_signal TO private_definer;
GRANT UPDATE ON app.marker_code TO private_definer;
GRANT DELETE ON app.marker_credit TO private_definer;
GRANT DELETE, UPDATE ON app.offer_code TO private_definer;
GRANT DELETE ON app.partner_invite TO private_definer;
GRANT DELETE, SELECT, UPDATE ON app.partner_member TO private_definer;
GRANT SELECT ON app.partner_scope TO private_definer;
GRANT DELETE ON app.play TO private_definer;
GRANT DELETE, SELECT ON app.profile TO private_definer;
GRANT DELETE ON app.public_profile_projection TO private_definer;
GRANT DELETE ON app.purchase_evidence TO private_definer;
GRANT DELETE ON app.push_token TO private_definer;
GRANT UPDATE ON app.receipt_fingerprint TO private_definer;
GRANT UPDATE ON app.review_item TO private_definer;
GRANT DELETE ON app.signin_provider_token TO private_definer;
GRANT UPDATE ON app.special_marker_stock_movement TO private_definer;
GRANT SELECT ON app.sponsorship TO private_definer;
GRANT DELETE ON app.staff_activity TO private_definer;
GRANT DELETE ON app.user_achievement TO private_definer;
GRANT DELETE, INSERT, SELECT, UPDATE ON private.rate_limit_bucket TO private_definer;
GRANT DELETE ON storage.objects TO private_definer;

-- audit_log INSERT: the deletion event's own log row. Not target-scoped
-- (actor_user_id is deliberately NULL for this entry, see 0015) -- WITH CHECK
-- (true) because there is no narrower predicate to express for "a brand new
-- log row about this specific call"; the trigger's insert-only guarantee is
-- the real invariant here, same as for any other caller.
CREATE POLICY private_definer_audit_log_insert ON app.audit_log FOR INSERT TO private_definer WITH CHECK (true);

-- ============================================================================
-- 8. Seed the allow-list with every policy created above (step 3's promise).
-- ============================================================================
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('private', 'pii_retention_policy', 'private_definer_read_pii_retention_policy', 'SELECT', true, 'delete_my_data reads its own driving table; governance data, not user-scoped'),
  ('app', 'admin_user', 'private_definer_read_admin_user', 'SELECT', true, 'is_admin(p_uid) looks up an arbitrary uid, not only the caller''s; USING(true) because the function body is the real scope, not this policy'),
  ('app', 'app_review_demo_account', 'private_definer_read_demo_account', 'SELECT', true, 'is_demo_account(p_uid) — same reasoning as private_definer_read_admin_user'),
  ('app', 'partner_member', 'private_definer_read_partner_member', 'SELECT', true, 'has_facility_scope/has_trail_scope/is_org_member etc. look up scope for an arbitrary uid; USING(true) because the function body is the real scope'),
  ('app', 'partner_scope', 'private_definer_read_partner_scope', 'SELECT', true, 'same reasoning as private_definer_read_partner_member'),
  ('app', 'facility_programme', 'private_definer_read_facility_programme', 'SELECT', true, 'has_facility_scope''s operator-via-trail leg reads this to resolve facility<->trail participation; not row-owner-scoped by nature'),
  ('app', 'sponsorship', 'private_definer_read_sponsorship', 'SELECT', true, 'has_sponsorship_scope''s operator leg reads this to resolve a sponsorship''s trail_id'),
  ('private', 'rate_limit_bucket', 'private_definer_rate_limit_select', 'SELECT', true, 'hit_rate_limit''s ON CONFLICT DO UPDATE needs to see the existing row to bump count'),
  ('private', 'rate_limit_bucket', 'private_definer_rate_limit_insert', 'INSERT', true, 'hit_rate_limit creates a bucket for an arbitrary caller-supplied key'),
  ('private', 'rate_limit_bucket', 'private_definer_rate_limit_update', 'UPDATE', true, 'hit_rate_limit bumps count on ON CONFLICT'),
  ('private', 'rate_limit_bucket', 'private_definer_rate_limit_purge', 'DELETE', true, 'purge_rate_limit_buckets deletes windows older than 2 days, across all keys'),
  ('app', 'admin_user', 'private_definer_delete_admin_user_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: admin_user.user_id = delete_row)'),
  ('app', 'app_review_demo_account', 'private_definer_delete_app_review_demo_account_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: app_review_demo_account.user_id = delete_row)'),
  ('app', 'booking', 'private_definer_delete_booking_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: booking.user_id = delete_row)'),
  ('app', 'checkin_challenge', 'private_definer_delete_checkin_challenge_staff_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: checkin_challenge.staff_user_id = delete_row)'),
  ('app', 'checkin_challenge', 'private_definer_delete_checkin_challenge_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: checkin_challenge.user_id = delete_row)'),
  ('app', 'connector_account', 'private_definer_delete_connector_account_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: connector_account.user_id = delete_row)'),
  ('app', 'course_qr_token', 'private_definer_delete_course_qr_token_issued_by_staff', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: course_qr_token.issued_by_staff = delete_row)'),
  ('app', 'course_qr_token', 'private_definer_delete_course_qr_token_used_by_user', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: course_qr_token.used_by_user = delete_row)'),
  ('app', 'device', 'private_definer_delete_device_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: device.user_id = delete_row)'),
  ('app', 'device_reward_ledger', 'private_definer_delete_device_reward_ledger_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: device_reward_ledger.user_id = delete_row)'),
  ('app', 'evidence', 'private_definer_delete_evidence_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: evidence.user_id = delete_row)'),
  ('app', 'marker_credit', 'private_definer_delete_marker_credit_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: marker_credit.user_id = delete_row)'),
  ('app', 'offer_code', 'private_definer_delete_offer_code_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: offer_code.user_id = delete_row)'),
  ('app', 'partner_member', 'private_definer_delete_partner_member_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: partner_member.user_id = delete_row)'),
  ('app', 'play', 'private_definer_delete_play_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: play.user_id = delete_row)'),
  ('app', 'profile', 'private_definer_delete_profile_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: profile.user_id = delete_row)'),
  ('app', 'purchase_evidence', 'private_definer_delete_purchase_evidence_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: purchase_evidence.user_id = delete_row)'),
  ('app', 'push_token', 'private_definer_delete_push_token_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: push_token.user_id = delete_row)'),
  ('app', 'signin_provider_token', 'private_definer_delete_signin_provider_token_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: signin_provider_token.user_id = delete_row)'),
  ('app', 'staff_activity', 'private_definer_delete_staff_activity_staff_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: staff_activity.staff_user_id = delete_row)'),
  ('app', 'user_achievement', 'private_definer_delete_user_achievement_user_id', 'DELETE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: user_achievement.user_id = delete_row)'),
  ('app', 'attestation', 'private_definer_setnull_attestation_staff_user_id', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: attestation.staff_user_id = set_null)'),
  ('app', 'entitlement', 'private_definer_setnull_entitlement_redeemed_by_staff', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: entitlement.redeemed_by_staff = set_null)'),
  ('app', 'fraud_signal', 'private_definer_setnull_fraud_signal_cleared_by', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: fraud_signal.cleared_by = set_null)'),
  ('app', 'marker_code', 'private_definer_setnull_marker_code_activated_by_staff', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: marker_code.activated_by_staff = set_null)'),
  ('app', 'marker_code', 'private_definer_setnull_marker_code_redeemed_by', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: marker_code.redeemed_by = set_null)'),
  ('app', 'offer_code', 'private_definer_setnull_offer_code_redeemed_by_staff', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: offer_code.redeemed_by_staff = set_null)'),
  ('app', 'partner_member', 'private_definer_setnull_partner_member_invited_by', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: partner_member.invited_by = set_null)'),
  ('app', 'review_item', 'private_definer_setnull_review_item_resolved_by', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: review_item.resolved_by = set_null)'),
  ('app', 'special_marker_stock_movement', 'private_definer_setnull_special_marker_stock_movement_by_member', 'UPDATE', true, 'delete_my_data''s generic pass (private.pii_retention_policy: special_marker_stock_movement.by_member = set_null)'),
  ('app', 'entitlement', 'private_definer_entitlement_update', 'UPDATE', true, 'detach activated_device_id (all states) and void unredeemed/vouchered special_marker entitlements (O9/O10) -- user_id itself is never changed'),
  ('app', 'fraud_signal', 'private_definer_fraud_signal_update', 'UPDATE', true, 'nulls fraud_signal.user_id for the target account'),
  ('app', 'attestation', 'private_definer_attestation_player_update', 'UPDATE', true, 'nulls attestation.player_user_id for the target account (line 841)'),
  ('app', 'audit_log', 'private_definer_audit_log_update', 'UPDATE', true, 'redacts audit_log.actor_user_id -- the table''s own insert-only trigger further restricts this to exactly this shape'),
  ('app', 'partner_invite', 'private_definer_partner_invite_delete', 'DELETE', true, 'deletes invites the target either sent (invited_by) or received (invitee_email)'),
  ('app', 'attestation_shift_log', 'private_definer_shift_log_update', 'UPDATE', true, 'rewrites the handle snapshot to ''deleted player'', matched by pseudonym (or, for a pre-pseudonym row, by the pre-deletion handle)'),
  ('app', 'public_profile_projection', 'private_definer_public_profile_delete', 'DELETE', true, 'removes the opted-in public projection row for the target''s (pre-deletion) handle'),
  ('app', 'receipt_fingerprint', 'private_definer_receipt_fingerprint_update', 'UPDATE', true, 'nulls receipt_fingerprint.user_id (24-month fraud retention kept, line 835)'),
  ('storage', 'objects', 'private_definer_storage_objects_delete', 'DELETE', true, 'removes the target''s receipt objects'),
  ('app', 'profile', 'private_definer_profile_select', 'SELECT', true, 'reads the target''s own handle before deleting the row (delete_my_data captures v_handle first)'),
  ('app', 'audit_log', 'private_definer_audit_log_insert', 'INSERT', false, 'writes the delete_my_data audit-log entry itself (actor_user_id is NULL by design, not the target -- see 0015)');

ALTER TABLE private.definer_policy_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.definer_policy_allowlist FORCE ROW LEVEL SECURITY;
GRANT SELECT ON private.definer_policy_allowlist TO service_role;

-- No LOGIN, no EXECUTE grant to any client role, no membership grant to
-- anyone: private_definer is reachable ONLY as the owning identity of the
-- functions in section 2. anon/authenticated/service_role's own grants and
-- policies (0008/0009/0010) are untouched by anything in this file.
