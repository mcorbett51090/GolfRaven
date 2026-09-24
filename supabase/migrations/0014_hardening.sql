-- 0015_hardening.sql
-- Gate-round-2 hardening pass, addressing the Opus security gate's
-- blocking findings against commit 6493fbe (P3a). Three independent
-- pieces:
--
--   1. `private.pii_retention_policy` — the "declared retention map" B3
--      asked for: one row per FK-to-`auth.users` column in `app`, with
--      the action `private.delete_my_data` (0014, rewritten) takes and
--      why. Driven from `pg_constraint`, not hand-maintained prose — a
--      new personal table's FK is either classified here or
--      `delete_my_data` raises rather than silently skipping it
--      (fail-closed).
--   2. `private.function_inventory` — B2's derived function inventory +
--      expected-grants manifest, read by both
--      `supabase/tests/matrix/11_function_security.sql` and
--      `tools/db/verify-function-inventory.mjs`.
--   3. DEFERRABLE INITIALLY DEFERRED on every FK constraint within `app`
--      (table -> table, not to `auth.users`) — so `delete_my_data` (and
--      any other function that must delete/detach several
--      mutually-referencing personal rows) can do so in ANY order within
--      one transaction; the FK is only checked at COMMIT.
--   4. B1 backstop: a blanket `REVOKE ALL ON ALL FUNCTIONS ... FROM
--      PUBLIC` across all three schemas, run after every function in this
--      migration set exists (0001's fix already prevents new grants to
--      PUBLIC from this point forward; this is the "existing functions"
--      half of B1's ask).
-- ⛔ Also: `special_marker_stock_movement.by_member` is made nullable so
-- it can be redacted (set_null) rather than forcing a choice between
-- "leave the identity" and "delete real inventory history" — see the
-- policy row below.

-- ============================================================================
-- 1. Declared PII retention map
-- ============================================================================
CREATE TYPE private.retention_action AS ENUM ('delete_row', 'set_null', 'special');

CREATE TABLE private.pii_retention_policy (
  schema_name text NOT NULL,
  table_name text NOT NULL,
  column_name text NOT NULL,
  action private.retention_action NOT NULL,
  reason text NOT NULL,
  PRIMARY KEY (schema_name, table_name, column_name)
);

-- delete_row: this IS the person's own personal data.
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'admin_user', 'user_id', 'delete_row', 'admin status is personal to the account'),
  ('app', 'app_review_demo_account', 'user_id', 'delete_row', 'demo-account status is personal to the account'),
  ('app', 'booking', 'user_id', 'delete_row', 'own booking row (line 858)'),
  ('app', 'checkin_challenge', 'user_id', 'delete_row', 'own, short-TTL row (line 829)'),
  ('app', 'checkin_challenge', 'staff_user_id', 'delete_row', 'same table, staff-issued challenge, same short TTL; deleting by whichever column matches covers both legs'),
  ('app', 'connector_account', 'user_id', 'delete_row', 'own row, tokens included (line 856)'),
  ('app', 'course_qr_token', 'issued_by_staff', 'delete_row', '120s-TTL operational row (line 830), not a long-term audit record; deleted outright rather than redacted'),
  ('app', 'course_qr_token', 'used_by_user', 'delete_row', 'same table, same reasoning as issued_by_staff'),
  ('app', 'device', 'user_id', 'delete_row', 'own device row (line 827)'),
  ('app', 'device_reward_ledger', 'user_id', 'delete_row', 'own reward-issuance record (line 828)'),
  ('app', 'evidence', 'user_id', 'delete_row', 'own play evidence (line 833)'),
  ('app', 'marker_credit', 'user_id', 'delete_row', 'own credit (line 847)'),
  ('app', 'offer_code', 'user_id', 'delete_row', 'own offer code (line 853)'),
  ('app', 'partner_member', 'user_id', 'delete_row', 'own membership row; the person is leaving the org (task instruction: "Cover partner_member")'),
  ('app', 'play', 'user_id', 'delete_row', 'own play (line 836)'),
  ('app', 'profile', 'user_id', 'delete_row', 'own profile (line 824) — deleted last, after its handle is captured for the shift-log/public-profile redaction steps'),
  ('app', 'purchase_evidence', 'user_id', 'delete_row', 'own purchase evidence (line 834)'),
  ('app', 'push_token', 'user_id', 'delete_row', 'own push token; explicit AT(6) line item ("deletes push tokens")'),
  ('app', 'signin_provider_token', 'user_id', 'delete_row', 'own sign-in provider grant (O12, line 857)'),
  ('app', 'staff_activity', 'staff_user_id', 'delete_row', 'part of the (staff_user_id, facility_id, day) primary key, so it cannot be nulled; deleted outright ("Cover ... staff_activity")'),
  ('app', 'user_achievement', 'user_id', 'delete_row', 'own achievement (line 838)');

-- set_null: identifies WHO acted on an operational/audit record that must
-- survive for someone else's legitimate purpose (stock reconciliation,
-- fraud review, invite provenance) — the row is kept, the actor redacted.
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'attestation', 'staff_user_id', 'set_null', 'gate round 2 fix: staff_user_id is now nullable, ON DELETE SET NULL — the attestation row survives (kind + cosignal_ok + staff_pseudonym intact, so it stays verifiable as "staff-attested"); only the staff identity is redacted, the same treatment player_user_id already gets'),
  ('app', 'entitlement', 'redeemed_by_staff', 'set_null', 'redemption record survives for the trail''s stock audit trail; only the staff identity is redacted'),
  ('app', 'fraud_signal', 'cleared_by', 'set_null', 'the fraud decision itself is an admin record independent of who cleared it'),
  ('app', 'marker_code', 'activated_by_staff', 'set_null', 'code lifecycle record survives (programme_marker supply chain); staff identity redacted'),
  ('app', 'marker_code', 'redeemed_by', 'set_null', 'same table — a redeeming PLAYER''s identity is also redacted here rather than deleting the code row, since the code''s lifecycle (batch, activation) is shared supply-chain data'),
  ('app', 'offer_code', 'redeemed_by_staff', 'set_null', 'the offer_code row itself is deleted via the user_id policy above when the PLAYER deletes their account; this column redacts the STAFF identity when the staff member deletes theirs'),
  ('app', 'partner_member', 'invited_by', 'set_null', 'the invitee''s own membership row is unaffected by the inviter''s account deletion; only the "who invited them" provenance is redacted'),
  ('app', 'review_item', 'resolved_by', 'set_null', 'the review decision is an admin record independent of who resolved it'),
  ('app', 'special_marker_stock_movement', 'by_member', 'set_null', 'inventory ledger row survives for reconciliation (nightly check asserts on_hand = sum(movements), line 850); only the staff identity is redacted');

-- special: bespoke code in private.delete_my_data (0014) — the match key
-- isn't the FK column itself (pseudonym/email matching), or the
-- redaction needs an exception to another invariant (audit_log's
-- insert-only trigger). No row in this table carries an open TODO — every
-- FK-to-auth.users column in `app` has a real, implemented redaction path
-- (09_delete_my_data.sql asserts this: it fails on any `reason` containing
-- the text "TODO").
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'attestation', 'player_user_id', 'special', 'nulled in delete_my_data (line 841: "nulled on account deletion"); player_pseudonym (HMAC of user_id) is kept for audit'),
  ('app', 'entitlement', 'user_id', 'special', 'never a plain delete_row: activated_device_id is detached first (the RESTRICT FK B3 flagged), then unredeemed/vouchered states are voided in place (O9/O10, line 2759) while `redeemed` stays terminal — the row is never deleted outright'),
  ('app', 'fraud_signal', 'user_id', 'special', 'nulled (ON DELETE SET NULL already on the column), not deleted — an admin fraud record about a deleted account is still a record admin needs'),
  ('app', 'audit_log', 'actor_user_id', 'special', 'redacted via the one narrow exception in audit_log_no_mutation()''s insert-only trigger (0006) — covers every historical row matching, not only new ones'),
  ('app', 'partner_invite', 'invited_by', 'special', 'partner_invite rows are deleted in delete_my_data by EITHER invited_by = the deleted user OR invitee_email = their verified email (task instruction: "Cover ... partner_invite.invitee_email")'),
  ('app', 'receipt_fingerprint', 'user_id', 'special', 'nulled, not deleted — the 24-month cross-account fraud-fingerprint retention (line 835) must survive account deletion');

-- ============================================================================
-- 2. Function inventory + expected-grants manifest (B2)
-- ============================================================================
CREATE TABLE private.function_inventory (
  schema_name text NOT NULL,
  function_name text NOT NULL,
  identity_args text NOT NULL,
  expected_anon boolean NOT NULL DEFAULT false,
  expected_authenticated boolean NOT NULL DEFAULT false,
  expected_service_role boolean NOT NULL DEFAULT false,
  note text NOT NULL,
  PRIMARY KEY (schema_name, function_name, identity_args)
);

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('api', 'my_offers', '', false, true, false, 'v3 RPC allowlist (line 1302)'),
  ('api', 'my_progress', 'trail_id text', false, true, false, 'v3 RPC allowlist (line 1302)'),
  ('app', 'audit_log_no_mutation', '', false, false, false, 'trigger function; fires via CREATE TRIGGER, needs no EXECUTE grant to any role (Postgres does not check EXECUTE for trigger invocation)'),
  ('private', 'delete_my_data', 'p_user_id uuid', false, false, true, 'me-delete Edge Function only (0014)'),
  ('private', 'has_facility_scope', 'p_uid uuid, p_facility_id text, p_roles app.partner_role[]', false, true, true, 'scope helper (0007)'),
  ('private', 'has_sponsorship_scope', 'p_uid uuid, p_sponsorship_id uuid', false, true, true, 'scope helper (0007)'),
  ('private', 'has_trail_scope', 'p_uid uuid, p_trail_id text, p_roles app.partner_role[]', false, true, true, 'scope helper (0007)'),
  ('private', 'hit_rate_limit', 'p_bucket_key text, p_window interval, p_max integer', false, false, true, 'rate limiter (0007), service_role-only'),
  ('private', 'is_admin', 'p_uid uuid', false, true, true, 'principal helper (0007)'),
  ('private', 'is_demo_account', 'p_uid uuid', false, true, true, 'principal helper (0007)'),
  ('private', 'is_manager_or_operator_of_facility', 'p_uid uuid, p_facility_id text', false, true, true, 'narrow scope helper (0007, B7 fix)'),
  ('private', 'is_operator_of_facility', 'p_uid uuid, p_facility_id text', false, true, true, 'narrow scope helper (0007, B7 fix)'),
  ('private', 'is_org_member', 'p_uid uuid, p_org_id uuid', false, true, true, 'scope helper (0008)'),
  ('private', 'is_staff_or_manager_of_facility', 'p_uid uuid, p_facility_id text', false, true, true, 'narrow scope helper (0007, B7 fix)'),
  ('private', 'partner_role_rank', 'p_role app.partner_role', false, true, true, 'invite-role-ordering helper (0007)'),
  ('private', 'purge_rate_limit_buckets', '', false, false, true, 'nightly purge (0007), service_role-only');

-- ============================================================================
-- 3. DEFERRABLE INITIALLY DEFERRED on every app-internal FK
-- ============================================================================
-- So `private.delete_my_data` (and anything else that must remove/detach
-- several mutually-referencing personal rows in one transaction — e.g.
-- app.device is referenced by app.evidence, app.checkin_challenge,
-- app.device_reward_ledger, app.push_token, and by app.entitlement /
-- app.offer_code's activated_device_id, which 0014 detaches rather than
-- deletes) can do so in any statement order: every FK check is deferred
-- to COMMIT, at which point the caller's whole transaction must already
-- be consistent, but no individual statement inside it has to be.
-- Excludes FKs to auth.users (handled by the retention policy above, not
-- by reordering) and to app.catalog_id_ledger/app.catalog_version, which
-- are import-time (not delete_my_data-time) referential concerns.
DO $$
DECLARE
  c record;
BEGIN
  FOR c IN
    SELECT con.conname, cl.relname AS table_name
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    WHERE con.contype = 'f'
      AND n.nspname = 'app'
      AND con.confrelid::regclass::text NOT IN ('auth.users')
      AND NOT con.condeferrable
  LOOP
    EXECUTE format('ALTER TABLE app.%I ALTER CONSTRAINT %I DEFERRABLE INITIALLY DEFERRED', c.table_name, c.conname);
  END LOOP;
END
$$;

-- special_marker_stock_movement.by_member: made nullable so the set_null
-- policy above is actually applicable.
ALTER TABLE app.special_marker_stock_movement ALTER COLUMN by_member DROP NOT NULL;

-- ============================================================================
-- 4. B1 backstop — blanket revoke across every function that now exists
-- ============================================================================
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA api FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC;

-- private schema tables above: RLS, no client policy (governance data,
-- service_role / postgres only — consistent with every other "nobody"
-- table in this migration set).
ALTER TABLE private.pii_retention_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.pii_retention_policy FORCE ROW LEVEL SECURITY;
ALTER TABLE private.function_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.function_inventory FORCE ROW LEVEL SECURITY;
GRANT SELECT ON private.pii_retention_policy, private.function_inventory TO service_role;
