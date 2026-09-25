-- 0022_export_and_delete_hardening.sql
-- (renamed from 0022_delete_my_data_post_condition.sql — round 3, see
-- "WHY THIS FILE REPLACES 0021's BODY" below for why the export rewrite
-- moved here too)
--
-- P3d gate round 3, blocking B1: "0021 was edited in place after #13
-- merged it to main (34d00dc)." `supabase/migrations/0021_export_my_data.sql`
-- is restored byte-for-byte to its merged (34d00dc) content in this same
-- commit (`git checkout 34d00dc -- supabase/migrations/0021_export_my_data.sql`)
-- — a merged migration is never edited in place, full stop, regardless of
-- how good the reason. Everything gate round 2 changed inside 0021 (the
-- new `private.pii_export_policy` registry, and the rewritten
-- `export_my_data` body that fixed the round-2 blocking-HIGH export leak)
-- moves HERE instead, as this file's own additions on top of the
-- restored original — `private.pii_export_policy` is a brand-new table
-- (plain `CREATE TABLE`, nothing to replace), and `export_my_data` is
-- redefined via `CREATE OR REPLACE FUNCTION` under 0020's own ownership
-- bracket (see below), the exact same pattern `delete_my_data`'s own
-- redefinition already uses further down in this file. The net, EFFECTIVE
-- final state — which rows exist, which columns export, what
-- `delete_my_data` does — is UNCHANGED from what gate round 2 built;
-- only WHICH migration file states it changed, so 0021 can stay
-- byte-identical to what #13 actually merged.
--
-- A new CI check (`scripts/check-migrations-immutable.sh`, wired into
-- `.github/workflows/ci.yml`) now makes this class of mistake fail the
-- build instead of relying on a human/gate catching it after the fact:
-- any file under `supabase/migrations/` that already exists on
-- `origin/main` must be byte-identical in the PR.
--
-- ⛔ WHY THIS FILE REPLACES 0021's BODY, NOT JUST ADDS TO IT (round 2's
-- own header, restated here since it now lives in THIS file instead):
-- the original `export_my_data` drove itself off
-- `private.pii_retention_policy` generically — looping over every
-- FK-to-`auth.users` column classified `delete_row` **or `set_null`**,
-- exporting the WHOLE matched row via `to_jsonb(t)`. That leaked another
-- account's rows through a `set_null` ACTOR column (`redeemed_by_staff`,
-- `invited_by`, `staff_user_id`, `cleared_by`, `resolved_by`,
-- `by_member`), exported encrypted token material verbatim
-- (`connector_account`'s ciphertext/dek/kek columns, and all of
-- `signin_provider_token`), and exported `fraud_signal`/`review_item`'s
-- full `detail` jsonb (server-side diagnostic data, security doc §3).
-- THIS version below never does a blind `SELECT *`/`to_jsonb(t)` over an
-- FK-matched row. Every exported table gets an EXPLICIT, HAND-WRITTEN
-- column list, and the function reads ONLY through columns naming the
-- CALLER as the row's own data subject (the `delete_row` user columns,
-- plus the four "subject special" columns — `attestation.player_user_id`,
-- `entitlement.user_id`, `receipt_fingerprint.user_id`,
-- `audit_log.actor_user_id`) — never through a `set_null` actor column.
-- `fraud_signal`/`review_item` are exported but restricted to
-- `id`/`kind`/`created_at` only. Fail-closed coverage: before exporting
-- anything, `export_my_data` walks `pii_retention_policy` and RAISES if
-- any `app.` table it names has no `pii_export_policy` row.
--
-- ⛔ P3d gate round 3, should-fix 1 (S1) — two further narrowings found
-- THIS round, on top of round 2's fix:
--   - `audit_log.subject_id` is no longer exported at all (was: id,
--     action, subject_table, subject_id, created_at). `subject_id` is a
--     polymorphic reference to WHATEVER row the audit action concerned —
--     for an action the caller took on another account's row (a staff
--     member resolving another user's review, an admin's action), that
--     id can itself be another account's own identifier. The gate
--     offered two options ("stop exporting it, or restrict to rows
--     where it equals the caller's own id"); the SAFER one is chosen:
--     drop the column entirely, rather than adding a per-row conditional
--     that still exports it SOMETIMES (a conditional is one more place a
--     future edit could get the condition wrong; omitting it outright
--     cannot leak, full stop — the same "keep it simple; omitting is
--     acceptable" allowance round 2's own fix already used for the
--     actor-only tables).
--   - `purchase_evidence.ref_id` is no longer exported. Per
--     `checkin/token-handler.ts`'s own schema, `ref_id` for a
--     `qr_variant = 'course'` row is the CONSUMED course-QR token's own
--     nonce hash (`app.course_qr_token.nonce_hash`) — an internal
--     matching/audit key for a SHARED, facility-issued token, not data
--     that belongs to the caller (the same reasoning `course_qr_token`
--     itself is excluded from export entirely for). Excluded via the
--     same "narrow the column list" mechanism as every other secret/
--     internal-key column already excluded from this function.
--
-- ⛔ P3d gate round 3, should-fix 4 (S4) — corrects a comment in
-- `delete_my_data`'s own post-condition (below) that OVERCLAIMED what
-- the "_r companion" check guarantees; see that comment, and
-- `tools/db/verify-function-inventory.mjs` check 8 / `supabase/tests/
-- matrix/10_function_inventory.sql` check 11/12 (now COLUMN-level, not
-- table-level) for the fix itself.

CREATE TYPE private.export_action AS ENUM ('export', 'exclude');

CREATE TABLE private.pii_export_policy (
  schema_name text NOT NULL,
  table_name text NOT NULL,
  action private.export_action NOT NULL,
  reason text NOT NULL,
  PRIMARY KEY (schema_name, table_name)
);

INSERT INTO private.pii_export_policy (schema_name, table_name, action, reason) VALUES
  -- ---- Exported: the caller's own `delete_row` rows -------------------
  ('app', 'admin_user', 'export', 'own admin-status row (user_id, created_at only)'),
  ('app', 'app_review_demo_account', 'export', 'own demo-account-status row (user_id only)'),
  ('app', 'booking', 'export', 'own booking row, mirrors api.my_booking'),
  ('app', 'connector_account', 'export', 'own connector grant, mirrors api.my_connector_account exactly (no token columns)'),
  ('app', 'device', 'export', 'own device row, mirrors api.my_device minus devicecheck_token_hash (secret-key denylist)'),
  ('app', 'evidence', 'export', 'own play evidence, mirrors api.my_evidence'),
  ('app', 'marker_credit', 'export', 'own marker credit, mirrors the columns api.my_marker_credit would'),
  ('app', 'offer_code', 'export', 'own offer code, mirrors api.my_offer_code minus code_hmac/pepper_kid/devicecheck_token_hash (secret-key denylist) and redeemed_by_staff (another account''s id)'),
  ('app', 'partner_member', 'export', 'own membership row, minus invited_by (another account''s id)'),
  ('app', 'play', 'export', 'own play, mirrors api.my_play'),
  ('app', 'profile', 'export', 'own profile, mirrors api.my_profile'),
  ('app', 'purchase_evidence', 'export', 'own purchase evidence, mirrors api.my_purchase_evidence minus ref_id (P3d gate round 3, S1: for a course-QR row this is the consumed token''s own nonce hash, app.course_qr_token.nonce_hash -- an internal matching key, not the caller''s own data)'),
  ('app', 'push_token', 'export', 'own push token, mirrors api.my_push_token'),
  ('app', 'user_achievement', 'export', 'own achievement, mirrors api.my_achievement'),
  -- ---- Excluded (delete_row, but not the subject's own exportable data) ----
  ('app', 'checkin_challenge', 'exclude', 'ephemeral short-TTL operational row; carries BOTH a subject (user_id) and an actor (staff_user_id) column with no api.my_* view precedent to mirror — omitted per the gate''s "keep it simple" allowance'),
  ('app', 'checkin_token', 'exclude', 'ephemeral short-TTL (15 min, checkin/token-handler.ts TOKEN_TTL_SECONDS) session token; single-use; same reasoning as checkin_challenge/course_qr_token — no api.my_* view precedent'),
  ('app', 'course_qr_token', 'exclude', 'ephemeral 120s-TTL operational row; carries BOTH an actor (issued_by_staff) and a subject (used_by_user) column with no view precedent'),
  ('app', 'device_reward_ledger', 'exclude', 'build plan line 828: client read is "nobody (admin)" — per-reward eligibility bookkeeping, not player-facing data'),
  ('app', 'signin_provider_token', 'exclude', 'build plan line 857: visible to NOBODY, not even its owner — holds only encrypted OAuth refresh-token material (refresh_token_ciphertext/dek_wrapped/kek_id); excluded entirely, no partial export'),
  ('app', 'staff_activity', 'exclude', 'operational attest/activation counters for a facility-day, no self-service export precedent (api.staff_activity is manager/operator-scoped, not "own row"); "actions you took" list omitted per the gate''s "keep it simple" allowance'),
  -- ---- Excluded (set_null / special, actor-only or not a named subject) ----
  ('app', 'marker_code', 'exclude', 'actor-only columns (activated_by_staff, redeemed_by); no direct subject column at all; supply-chain/operational table'),
  ('app', 'special_marker_stock_movement', 'exclude', 'actor-only column (by_member, NOT NULL); inventory ledger row, no direct subject column'),
  ('app', 'partner_invite', 'exclude', 'classified special (not delete_row); matched by inviter (an actor, invited_by) or by invitee_email (text, not a uuid-scoped subject column) in delete_my_data -- not among the gate''s four named subject-specials; omitted per "keep it simple"'),
  -- ---- Exported: the four named "subject special" columns ------------
  ('app', 'attestation', 'export', 'subject special (player_user_id) -- mirrors api.my_attestation minus staff_user_id/staff_pseudonym (another account''s identity)'),
  ('app', 'entitlement', 'export', 'subject special (user_id) -- mirrors api.my_entitlement minus redeemed_by_staff (another account''s id) and devicecheck_token_hash (secret-key denylist)'),
  ('app', 'receipt_fingerprint', 'export', 'subject special (user_id) -- id/facility_id/local_date/phash/receipt_number_ocr/created_at, no secret material'),
  ('app', 'audit_log', 'export', 'subject special (actor_user_id) -- id/action/subject_table/created_at only; never detail (may name another row/account) and, P3d gate round 3 S1, never subject_id either (a polymorphic reference that can itself BE another account''s own identifier, e.g. a staff member''s audit row for an action taken on another user''s data)'),
  -- ---- Exported, deliberately restricted (the gate's own two named exceptions) ----
  ('app', 'fraud_signal', 'export', 'subject (user_id) but restricted to id/kind/created_at only -- never detail (security doc S3: server-side diagnostic only) or cleared_by (another account''s id)'),
  ('app', 'review_item', 'export', 'NOT a subject column -- an explicit "actions you took" exception for resolved_by (an admin''s own past review decisions), restricted to id/kind/created_at only -- never detail, subject_table/subject_id (another row''s identity) or resolved_by itself');

ALTER TABLE private.pii_export_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.pii_export_policy FORCE ROW LEVEL SECURITY;
GRANT SELECT ON private.pii_export_policy TO service_role;
-- private_definer needs to read this INSIDE export_my_data (below) for
-- its own fail-closed coverage check.
CREATE POLICY pd_read_pii_export_policy ON private.pii_export_policy FOR SELECT TO private_definer USING (true);
GRANT SELECT ON private.pii_export_policy TO private_definer;

-- Allow-listed the same way 0016_private_definer.sql allow-lists every
-- OTHER private_definer policy (its own §3/§8) — this is a NEW policy,
-- so it needs its own row + captured expression text, same mechanism.
-- Same self-granting CURRENT_USER-scoped temporary-policy dance 0017/
-- 0019/0021(original)/0022(original) already use for this EXACT table —
-- `definer_policy_allowlist` already has FORCE ROW LEVEL SECURITY on
-- with no policy for any non-service_role role by the time THIS
-- migration runs.
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0022 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('private', 'pii_export_policy', 'pd_read_pii_export_policy', 'SELECT', true, 'export_my_data''s own fail-closed coverage check reads this table; governance data, not user-scoped');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.schema_name = 'private' AND al.table_name = 'pii_export_policy' AND al.policy_name = 'pd_read_pii_export_policy';
DROP POLICY current_user_seed_definer_policy_allowlist_0022 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ⛔ Ownership bracket for BOTH redefinitions below — 0020_rate_limit_no_raise.sql's
-- own pattern (see that file's header for the full reasoning): `CREATE OR
-- REPLACE FUNCTION` on a function ALREADY owned by `private_definer`
-- (both `export_my_data`, 0021, and `delete_my_data`, 0015/0016, are, by
-- the time this migration runs) requires the caller to both OWN the
-- function being replaced and hold CREATE on its schema — `private_definer`
-- deliberately holds neither the rest of the time. One shared bracket
-- covers both functions; opened once, closed once.
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- ============================================================================
-- private.export_my_data — redefined (was: created fresh by 0021, which
-- this file leaves untouched/restored). Same signature, same OID, same
-- EXECUTE grants (0021's own REVOKE/GRANT already apply and are
-- unaffected by CREATE OR REPLACE) — nothing to re-grant here.
-- ============================================================================
CREATE OR REPLACE FUNCTION private.export_my_data(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_result jsonb := '{}'::jsonb;
  v_tbl record;
  v_json jsonb;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'export_my_data: user_id is required';
  END IF;

  PERFORM set_config('app.delete_my_data.target_user_id', p_user_id::text, true);

  -- ==========================================================================
  -- Fail-closed coverage check (must run FIRST, before any real export):
  -- every app. table private.pii_retention_policy classifies at all
  -- (delete_row/set_null/special) must have a private.pii_export_policy
  -- row. A personal table added later with no export decision made for
  -- it fails EVERY export call, loudly, rather than silently vanishing
  -- from the output.
  -- ==========================================================================
  FOR v_tbl IN
    SELECT DISTINCT table_name
    FROM private.pii_retention_policy
    WHERE schema_name = 'app'
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM private.pii_export_policy
      WHERE schema_name = 'app' AND table_name = v_tbl.table_name
    ) THEN
      RAISE EXCEPTION
        'export_my_data: app.% is classified in private.pii_retention_policy but has no private.pii_export_policy row -- classify it (export/exclude, with a reason) before export can run',
        v_tbl.table_name;
    END IF;
  END LOOP;

  -- ==========================================================================
  -- Explicit, hand-written exports. Every SELECT names its own columns —
  -- never `SELECT *` / `to_jsonb(t)` over a whole row.
  -- ==========================================================================
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, created_at FROM app.admin_user WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('admin_user', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id FROM app.app_review_demo_account WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('app_review_demo_account', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, provider, provider_ref, facility_id, tee_time, status
    FROM app.booking WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('booking', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, provider, external_user_id, scopes, status, created_at, revoked_at
    FROM app.connector_account WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('connector_account', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, platform, attest_key_id, attest_counter, integrity_last, first_seen, last_seen
    FROM app.device WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('device', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, device_id, source, source_ref, input_hash, course_id, facility_id,
           started_at, ended_at, local_date, summary, integrity, cosignal, attestation_grade,
           matcher_version, catalog_version, status, created_at
    FROM app.evidence WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('evidence', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, trail_id, facility_id, purchase_evidence_id, status, created_at
    FROM app.marker_credit WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('marker_credit', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, offer_id, user_id, facility_id, state, earned_at, activated_device_id,
           activated_at, expires_at, expiry_paused_at, redeemed_at, redeemed_offline
    FROM app.offer_code WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('offer_code', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, org_id, role, revoked_at, created_at
    FROM app.partner_member WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('partner_member', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, course_id, facility_id, play_date, course_disambiguated_by,
           score_badge, score_monetary, hard_signal, presence_signal, money, held_review,
           policy_version, input_digest, status
    FROM app.play WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('play', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, handle, locale, home_region, birth_year_bucket, leaderboard_opt_in, created_at
    FROM app.profile WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('profile', v_json);

  -- P3d gate round 3, S1: ref_id excluded (this file's own header —
  -- for a course-QR row it is the consumed token's own nonce hash, not
  -- the caller's own data).
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, facility_id, trail_id, method, qr_variant, offline, cosignal,
           no_cosignal_reason, ip_region_match, local_date, status, created_at
    FROM app.purchase_evidence WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('purchase_evidence', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, device_id, expo_token, updated_at
    FROM app.push_token WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('push_token', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, achievement_id, award_key, awarded_at, basis, revoked_at, revoke_reason
    FROM app.user_achievement WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('user_achievement', v_json);

  -- ---- Subject specials (four named columns) --------------------------
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, facility_id, player_user_id, player_pseudonym, kind, token_jti, cosignal_ok, created_at
    FROM app.attestation WHERE player_user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('attestation', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, kind, trail_id, roster_version, sponsorship_id, basis, state,
           activated_device_id, activated_at, redeemed_at, redeemed_facility_id,
           redemption_method, redemption_jti, redemption_cosignal_ok, voucher_facility_id, voucher_issued_at
    FROM app.entitlement WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('entitlement', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, facility_id, local_date, phash, receipt_number_ocr, created_at
    FROM app.receipt_fingerprint WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('receipt_fingerprint', v_json);

  -- P3d gate round 3, S1: subject_id excluded (this file's own header —
  -- a polymorphic reference that can itself be another account's id).
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, action, subject_table, created_at
    FROM app.audit_log WHERE actor_user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('audit_log', v_json);

  -- ---- The gate's two named, deliberately-restricted exceptions ------
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, kind, created_at FROM app.fraud_signal WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('fraud_signal', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, kind, created_at FROM app.review_item WHERE resolved_by = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('review_item', v_json);

  RETURN v_result;
END;
$$;

COMMENT ON FUNCTION private.export_my_data(uuid) IS
  'Read-only twin of private.delete_my_data — walks the SAME private.pii_retention_policy registry, cross-checked against private.pii_export_policy (fail-closed: raises if any classified table has no export decision). Every SELECT names its own explicit column list; never SELECT */to_jsonb(t) over a whole row, and never reached through a set_null ACTOR column. P3d gate round 3: also excludes audit_log.subject_id and purchase_evidence.ref_id (S1).';

-- ============================================================================
-- private.delete_my_data — redefined (was: created by 0015, ownership
-- transferred to private_definer by 0016; the round-2 post-condition +
-- rate-limit-purge redefinition that used to live in the OLD
-- 0022_delete_my_data_post_condition.sql is unchanged in substance,
-- just relocated into this renamed file — same signature/OID, nothing
-- to re-grant).
-- ============================================================================
CREATE OR REPLACE FUNCTION private.delete_my_data(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_handle text;
  v_email text;
  v_result jsonb := '{}'::jsonb;
  v_pol record;
  v_row_count int;
  v_key_id uuid;
  v_key_secret text;
  v_pseudonym_candidate text;
  v_post_pol record;
  v_remaining int;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'delete_my_data: user_id is required';
  END IF;

  -- S1 close-out (gate round 3): this function is owned by `private_definer`
  -- (0016_private_definer.sql), a NOLOGIN NOSUPERUSER NOBYPASSRLS role that
  -- is NOT the table owner — every table below stays ENABLE + FORCE ROW
  -- LEVEL SECURITY, and private_definer reaches rows only through the
  -- explicit, narrow policies 0016 defines, each scoped to this session-
  -- local GUC. Set it FIRST, before the very first table read below, since
  -- even `app.profile`'s own SELECT now goes through a policy keyed on it.
  PERFORM set_config('app.delete_my_data.target_user_id', p_user_id::text, true);

  SELECT handle INTO v_handle FROM app.profile WHERE user_id = p_user_id;
  SELECT email INTO v_email FROM auth.users WHERE id = p_user_id;
  -- Fully qualified: this function runs with search_path = '' (below),
  -- and pgcrypto is installed into `public` (confirmed this session via
  -- `pg_extension.extnamespace`), so an unqualified hmac()/digest() would
  -- 42883 ("function ... does not exist") here even though the extension
  -- is present.
  --
  -- ⛔ FIX (M1, post-P3a re-gate): the pseudonym key is NEVER read from a
  -- GUC any more (0015/0016's prior `current_setting('app.pseudonym_hmac')`
  -- design had four confirmed problems: readable by anon/authenticated,
  -- overridable by any caller's own `SET LOCAL`, silently accepted an
  -- empty value with no error, and production never sets an `app.*` GUC
  -- at all — see supabase/tests/shim.sql's own note on this, where the
  -- fix is explained in full). The key now comes from Supabase Vault
  -- (`vault.decrypted_secrets`, real in production, shimmed locally) —
  -- read INSIDE this SECURITY DEFINER function body, which no other role
  -- can do (private_definer's own narrow, column-level grant on that
  -- view, 0018_pseudonym_vault.sql — anon/authenticated get none).
  --
  -- Rotation: EVERY row named `pseudonym_hmac%` in the vault is an
  -- "active" key (0018's own deploy-check note explains the naming
  -- convention). A pseudonym was computed, at WRITE time, with WHATEVER
  -- key was active then — so finding it again means trying every
  -- currently-active key, not just the newest one, or a row written
  -- under an older key becomes permanently unfindable the moment a new
  -- key is added. The loop below (right before the one place this
  -- function actually MATCHES rows by pseudonym, attestation_shift_log)
  -- does exactly that: for each active key, validate it, compute this
  -- user's pseudonym under it, and run the shift-log UPDATE once per
  -- key — safe to repeat (idempotent: a row already updated on an
  -- earlier key's pass no longer matches ANY later key's WHERE clause,
  -- since its own player_pseudonym column never changes).
  -- The two derived GUCs the "special" policies (partner_invite,
  -- public_profile_projection) match on — set once either value is
  -- known; empty string (not NULL) when there is nothing to match, so
  -- `current_setting(..., true)` never returns NULL into a `column =
  -- NULL` comparison (which would be neither true nor false and so
  -- would never permit a row — the intended, fail-closed behaviour when
  -- e.g. the account has no email on file). `target_pseudonym` is set
  -- per-key, in the loop right above the attestation_shift_log UPDATE
  -- below — see that block for why.
  PERFORM set_config('app.delete_my_data.target_email', COALESCE(v_email, ''), true);
  PERFORM set_config('app.delete_my_data.target_handle', COALESCE(v_handle, ''), true);

  -- ==========================================================================
  -- Generic pass: every FK-to-auth.users column in `app`, driven by
  -- private.pii_retention_policy. Fails closed on anything unclassified.
  -- ==========================================================================
  FOR v_pol IN
    SELECT
      cl.relname AS table_name,
      a.attname AS column_name,
      pol.action,
      pol.reason
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
    LEFT JOIN private.pii_retention_policy pol
      ON pol.schema_name = 'app' AND pol.table_name = cl.relname AND pol.column_name = a.attname
    WHERE con.contype = 'f'
      AND n.nspname = 'app'
      AND con.confrelid = 'auth.users'::regclass
  LOOP
    IF v_pol.action IS NULL THEN
      RAISE EXCEPTION
        'delete_my_data: app.%.% references auth.users but has no private.pii_retention_policy row — classify it (delete_row / set_null / special) before this function can run',
        v_pol.table_name, v_pol.column_name;
    ELSIF v_pol.action = 'delete_row' THEN
      EXECUTE format('DELETE FROM app.%I WHERE %I = $1', v_pol.table_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'set_null' THEN
      EXECUTE format('UPDATE app.%I SET %I = NULL WHERE %I = $1', v_pol.table_name, v_pol.column_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'special' THEN
      CONTINUE; -- handled below, by name, not generically
    END IF;
  END LOOP;

  -- ==========================================================================
  -- Special cases (each cross-referenced to its private.pii_retention_policy
  -- row and reason).
  -- ==========================================================================

  -- entitlement: detach activated_device_id UNCONDITIONALLY, for every
  -- state (including `redeemed`, which is terminal and never voided) — the
  -- device row is about to be deleted by the generic pass above (device.
  -- user_id is a delete_row policy) and RESTRICT (the default) on
  -- entitlement.activated_device_id would otherwise block that delete.
  -- This is not a pii_retention_policy row because activated_device_id
  -- does not reference auth.users — it references app.device — so it is
  -- outside the auth.users-driven loop above by construction; called out
  -- here because it was exactly B3's "handle the RESTRICT FK on
  -- activated_device_id" finding.
  UPDATE app.entitlement SET activated_device_id = NULL, devicecheck_token_hash = NULL
    WHERE user_id = p_user_id;
  -- entitlement.play_id / offer_code.play_id (H1, post-P3a gate): also
  -- references app.play, which the generic pass below deletes (play.user_id
  -- = delete_row) — the FK itself is now ON DELETE SET NULL DEFERRABLE
  -- INITIALLY DEFERRED (0017), so this is belt-and-suspenders, not load-
  -- bearing, but detaching explicitly here matches activated_device_id's
  -- own pattern immediately above and keeps the intent visible at the
  -- call site rather than only in the FK definition.
  UPDATE app.entitlement SET play_id = NULL WHERE user_id = p_user_id;
  UPDATE app.offer_code SET play_id = NULL WHERE user_id = p_user_id;
  -- Then, per line 2759 / O9-O10: void any UNREDEEMED entitlement or stock
  -- voucher (redeemed stays redeemed — terminal, kept for the stock ledger).
  UPDATE app.entitlement
  SET state = 'void'
  WHERE user_id = p_user_id
    AND kind = 'special_marker'
    AND state IN ('earned', 'held_review', 'redeemable', 'vouchered');
  -- offer_code.activated_device_id has the same RESTRICT shape; offer_code
  -- rows for this user are deleted by the generic pass (offer_code.user_id
  -- = delete_row), so no separate detach is needed there — but another
  -- user's already-activated offer_code could in principle point at a
  -- device this user owns only if devices were ever shared, which they are
  -- not (app.device.user_id is 1:1 with the owning account) — no action
  -- needed.

  -- attestation.player_user_id (special): nulled, not deleted (line 841).
  UPDATE app.attestation SET player_user_id = NULL WHERE player_user_id = p_user_id;
  -- attestation.staff_user_id is handled by the generic pass above (it is
  -- now a plain `set_null` policy row, gate round 2 fix) — no bespoke code
  -- needed here; staff_pseudonym (populated at attest time, out of this
  -- stage's scope) survives so the row stays verifiable as "staff-attested".

  -- audit_log.actor_user_id (special): redacted via the trigger's one
  -- narrow exception (0006) — covers every historical row matching, "older
  -- audit_log rows" included, since the WHERE has no date bound.
  UPDATE app.audit_log SET actor_user_id = NULL WHERE actor_user_id = p_user_id;

  -- receipt_fingerprint.user_id (special): nulled, row kept (24-month
  -- fraud retention, line 835).
  UPDATE app.receipt_fingerprint SET user_id = NULL WHERE user_id = p_user_id;

  -- fraud_signal.user_id (special): nulled, row kept — an admin fraud
  -- record survives its subject's account deletion.
  UPDATE app.fraud_signal SET user_id = NULL WHERE user_id = p_user_id;

  -- partner_invite (special): deleted on EITHER match — the inviter
  -- deleting their account (invited_by), or the invite naming the deleted
  -- user's own verified email (invitee_email) — task instruction: "Cover
  -- ... partner_invite.invitee_email".
  DELETE FROM app.partner_invite
  WHERE invited_by = p_user_id
     OR (v_email IS NOT NULL AND invitee_email = v_email);

  -- attestation_shift_log: match by the durable player_pseudonym (HMAC of
  -- user_id), NOT by the current handle (B3 fix — a handle can change or
  -- be reused after being freed; the projection never stores a user id at
  -- all, line 842). A row logged before this stage's pseudonym column
  -- existed falls back to matching the pre-deletion handle.
  --
  -- ⛔ FIX (should-fix, post-P3a re-gate: "key rotation ... match on each
  -- row's recorded hmac id and raise if that key is missing"): the PRIOR
  -- version tried every vault row whose NAME matched 'pseudonym_hmac%' —
  -- renaming a retired key out of that naming convention (e.g.
  -- 'pseudonym_hmac_v1' -> 'retired_v1') silently dropped it from this
  -- loop even though rows still carry its id in their OWN
  -- player_pseudonym_hmac_id column, "succeeding" while leaving that
  -- key's rows unredacted. This version drives the loop from the DATA
  -- instead of the vault's naming convention: every id ever recorded
  -- against a player_pseudonym/staff_pseudonym pair is resolved BY ID
  -- (name-independent, so a rename never matters), and a recorded id that
  -- no longer resolves in vault.decrypted_secrets at all (deleted, not
  -- merely renamed — should-fix "FK into vault.secrets", 0018, dropped
  -- the FK specifically so this can be validated here instead of relying
  -- on referential integrity to prevent it) RAISES rather than silently
  -- skipping that key's rows.
  --
  -- ⛔ FIX (should-fix 2, post-P3a re-gate): "replace the broad
  -- pd_shift_log_discover_hmac_id policy (USING(true)) with a small
  -- registry of key ids ever used ... deletion iterates the registry."
  -- The SOURCE of this loop's key ids is now private.
  -- pseudonym_key_registry (0018), populated at WRITE time by the
  -- app.attestation/app.attestation_shift_log validation triggers (also
  -- 0018) — NOT a live, row-unscoped SELECT over the wide
  -- attestation_shift_log table any more, which is what let the broad
  -- discovery policy this replaces be narrowed away entirely.
  FOR v_key_id IN
    SELECT key_id FROM private.pseudonym_key_registry
  LOOP
    SELECT decrypted_secret INTO v_key_secret FROM vault.decrypted_secrets WHERE id = v_key_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'delete_my_data: attestation_shift_log references pseudonym key id % that no longer resolves in vault.decrypted_secrets (deleted or otherwise gone) — cannot safely determine whether it matches this user', v_key_id;
    END IF;
    IF v_key_secret IS NULL OR length(v_key_secret) < 32 THEN
      RAISE EXCEPTION 'delete_my_data: pseudonym key % in vault.decrypted_secrets is NULL or shorter than 32 bytes', v_key_id;
    END IF;
    v_pseudonym_candidate := encode(public.hmac(p_user_id::text, v_key_secret, 'sha256'), 'hex');
    -- `app.delete_my_data.target_pseudonym` is re-set per key so
    -- 0016_private_definer.sql's RLS policy (which independently checks
    -- the same GUC, since private_definer reaches this table only
    -- through that policy) agrees with this statement's own WHERE clause
    -- on each pass.
    PERFORM set_config('app.delete_my_data.target_pseudonym', v_pseudonym_candidate, true);
    UPDATE app.attestation_shift_log
    SET player_handle_snapshot = 'deleted player'
    WHERE player_pseudonym_hmac_id = v_key_id AND player_pseudonym = v_pseudonym_candidate;
  END LOOP;
  -- Legacy fallback: a row logged before player_pseudonym/
  -- player_pseudonym_hmac_id existed at all has neither set — matched by
  -- the pre-deletion handle instead, same as always (0016's own RLS
  -- policy already has a SEPARATE branch for exactly this shape, keyed
  -- on target_handle, not target_pseudonym).
  UPDATE app.attestation_shift_log
  SET player_handle_snapshot = 'deleted player'
  WHERE player_pseudonym IS NULL AND player_pseudonym_hmac_id IS NULL
    AND v_handle IS NOT NULL AND player_handle_snapshot = v_handle;

  -- receipt objects in storage.objects (task instruction: "receipt objects
  -- in storage.objects"). Matched by `owner` (set at upload time by the
  -- out-of-scope receipts Edge Function) and, defensively, by the
  -- `receipts/<user_id>/...` path convention (line 868) in case `owner`
  -- was never populated for an older object.
  DELETE FROM storage.objects
  WHERE bucket_id = 'receipts'
    AND (owner = p_user_id OR name LIKE 'receipts/' || p_user_id::text || '/%');

  -- public_profile_projection + profile: profile is deleted by the
  -- generic pass (delete_row); its projection has no FK (holds no user
  -- id, line 825) so it is removed here by the handle captured above,
  -- before profile's row (and therefore v_handle's source) is gone.
  IF v_handle IS NOT NULL THEN
    DELETE FROM app.public_profile_projection WHERE handle = v_handle;
  END IF;

  -- ==========================================================================
  -- P3d gate round 2, should-fix 3: "Rate-limit keys. During deletion,
  -- remove the user's own rate_limit_bucket keys, i.e. those prefixed with
  -- their uid, inside delete_my_data or me-delete. It's fine to keep the
  -- in-flight me-delete bucket so retries stay limited, if you document
  -- it. Or wire the purge. Say which you chose."
  --
  -- CHOSEN: inside delete_my_data (here), not me-delete's own handler —
  -- this is the same transaction as the deletion itself, so it is
  -- automatically atomic with (and rolls back together with) everything
  -- else in this function, and it fires for EVERY caller of this
  -- function, not only the me-delete Edge Function specifically.
  --
  -- Scope: every bucket_key `hitRateLimitForActor` (privileged.ts) ever
  -- writes for THIS user is prefixed `<uid>:...` (that function's own
  -- `scopedBucketKey = \`${actor.uid}:${bucketKey}\``) — so a LIKE-prefix
  -- match on `p_user_id::text || ':%'` covers every bucket this user has
  -- ever hit, across every endpoint, with no separate registry needed.
  --
  -- EXCLUDED, deliberately: the in-flight `me-delete:user` bucket itself
  -- (me-delete/index.ts's own `hitRateLimitForActor(actor, "me-delete:
  -- user", ...)`, scoped key `<uid>:me-delete:user`) — kept so a RETRY of
  -- THIS SAME deletion call (delete-handler.ts's own doc: the one
  -- legitimate reason to call this endpoint again in a short window,
  -- e.g. after a partial failure) stays rate-limited exactly the way a
  -- first attempt already is, rather than becoming unbounded the moment
  -- one successful run has purged its own counter. Every OTHER bucket —
  -- evidence submission, redemption, check-in, etc. — is purged: those
  -- limits exist to bound abuse by a live account, and this account no
  -- longer has personal data to abuse anything with.
  --
  -- No new RLS policy needed: private_definer already holds an unscoped
  -- DELETE policy on this table (`pd_rate_limit_purge`, 0016), the SAME
  -- one `private.purge_rate_limit_buckets`'s own nightly sweep already
  -- uses — its own `_r` companion (`pd_rate_limit_purge_r`) already
  -- exists too.
  DELETE FROM private.rate_limit_bucket
  WHERE bucket_key LIKE p_user_id::text || ':%'
    AND bucket_key <> p_user_id::text || ':me-delete:user';

  -- ==========================================================================
  -- P3d should-fix 2: fail-closed POST-CONDITION. Re-reads every table this
  -- function's own registry (private.pii_retention_policy) names, through
  -- private_definer's own SELECT visibility, and RAISES if ANY subject row
  -- still remains. See this file's own header for why `entitlement.user_id`
  -- is the one deliberate exclusion (redeemed/terminal rows are
  -- intentionally retained, O9/O10).
  --
  -- ⛔ CORRECTED COMMENT (P3d gate round 3, S4 — the PRIOR wording here
  -- overclaimed what this post-condition is trustworthy against). The
  -- prior comment said the "_r companion" check (tools/db/verify-
  -- function-inventory.mjs check 8 / 10_function_inventory.sql check 11)
  -- guarantees this post-condition can see every row it re-counts. That
  -- was TRUE only up to the granularity that check actually verified,
  -- which round 2's version did NOT match: it was TABLE-level ("does
  -- SOME SELECT policy exist for private_definer on this table at all"),
  -- while this post-condition re-counts PER COLUMN, under RLS, using the
  -- SAME session GUC every DELETE/UPDATE policy is scoped to. A table
  -- with TWO classified columns — one with a real, correctly-scoped
  -- SELECT companion, one with none — passed the OLD table-level check
  -- (the table has *a* SELECT policy), while this post-condition's
  -- re-count for the SECOND column would ALSO see zero rows for the
  -- SAME reason RLS hid the evidence from the ORIGINAL delete/update —
  -- reporting success while a row for that column genuinely survives,
  -- table-level check notwithstanding. The check below THIS comment was
  -- fixed for this round: check 8/11/12 are now COLUMN-level (every
  -- `pii_retention_policy` (table, column) pair requires its OWN SELECT
  -- policy whose USING clause matches the exact `nullif(current_setting
  -- (...))` form on THAT column, not merely "some policy on this
  -- table") — proven against a planted must-fail fixture
  -- (`app.zz_two`, two columns, a SELECT companion on only one) this
  -- round. THAT is what makes the post-condition below trustworthy now.
  -- ==========================================================================
  FOR v_post_pol IN
    SELECT table_name, column_name
    FROM private.pii_retention_policy
    WHERE schema_name = 'app'
      AND NOT (table_name = 'entitlement' AND column_name = 'user_id')
  LOOP
    EXECUTE format('SELECT count(*) FROM app.%I WHERE %I = $1', v_post_pol.table_name, v_post_pol.column_name)
      INTO v_remaining USING p_user_id;
    IF v_remaining > 0 THEN
      RAISE EXCEPTION
        'delete_my_data: post-condition failed — % row(s) still remain in app.%.% for user % after deletion (fail-closed; a missing/misscoped RLS policy can let a DELETE/UPDATE silently affect 0 rows while reporting success — see private.pii_retention_policy and the column-level "_r companion" check in tools/db/verify-function-inventory.mjs)',
        v_remaining, v_post_pol.table_name, v_post_pol.column_name, p_user_id;
    END IF;
  END LOOP;

  v_result := jsonb_build_object('user_id', p_user_id, 'deleted_at', now());
  -- Logged via a plain INSERT — this is a NEW audit row about the
  -- deletion event itself, not a mutation of an old one, so the
  -- insert-only trigger does not apply to it.
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (NULL, 'delete_my_data', 'app.profile', p_user_id::text, v_result);

  RETURN v_result;
END;
$$;

COMMENT ON FUNCTION private.delete_my_data(uuid) IS
  'Deletes/redacts all personal data for a user, driven by private.pii_retention_policy (0014), and RAISES (fail-closed) if a post-deletion re-check (private_definer''s own RLS SELECT visibility, guaranteed column-level by check 8/11/12 -- P3d gate round 3, S4) still finds a subject row for any registry table/column other than the one documented exception (entitlement.user_id, which intentionally retains redeemed/terminal rows) — P3d gate round 2 should-fix 2, corrected round 3.';

RESET ROLE;
-- Restore 0016's exact hardened end-state — private_definer keeps only
-- USAGE on schema private, never CREATE, once this migration finishes.
REVOKE CREATE ON SCHEMA private FROM private_definer;
