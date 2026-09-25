-- 0021_export_my_data.sql
-- build plan §4.7.1a inventory ("me-export") — task instruction: "Return
-- all of the caller's personal data as JSON: the same row set
-- delete_my_data treats as personal, discovered from the same
-- pii_retention_policy registry or catalog where possible, so the two
-- can't drift."
--
-- ⛔ REWRITE (P3d gate, BLOCKING HIGH): the FIRST version of this
-- function drove itself off `private.pii_retention_policy` generically —
-- looping over every FK-to-`auth.users` column classified `delete_row`
-- **or `set_null`**, and exporting the WHOLE matched row via
-- `to_jsonb(t)`. That was wrong in three ways, all reproduced over HTTP
-- by the gate:
--   (a) a `set_null` column names the ACTOR who touched a row that
--       belongs to someone else, never the row's data subject —
--       `offer_code.redeemed_by_staff`, `partner_member.invited_by`,
--       `attestation.staff_user_id`, `marker_code.*`,
--       `fraud_signal.cleared_by`, `review_item.resolved_by`,
--       `special_marker_stock_movement.by_member` all leaked another
--       real account's row (and, for `review_item`, its `detail`) into
--       the CALLER's own export the moment the caller happened to be the
--       actor on someone else's row (a staff member, a manager, an
--       admin).
--   (b) `to_jsonb(t)` is a blind `SELECT *` in jsonb form — it exported
--       encrypted token material verbatim: `connector_account`'s
--       `refresh_token_ciphertext`/`dek_wrapped`/`kek_id`, and all of
--       `signin_provider_token` (which §4.4 line 857 says is visible to
--       NOBODY, not even its own owner, for exactly this reason).
--   (c) `fraud_signal.detail` (which can carry `excludedRows[].reasons` —
--       security doc §3: "SERVER-SIDE DIAGNOSTIC DATA ONLY... never echo
--       them into a player-facing UI") and `cleared_by` reached the
--       subject.
--
-- THIS version never does a blind `SELECT *`/`to_jsonb(t)` over an
-- FK-matched row again. Every exported table gets an EXPLICIT,
-- HAND-WRITTEN column list (never assembled from data), and the function
-- reads ONLY through columns naming the CALLER as the row's own data
-- subject — the `delete_row` user columns, plus four "subject special"
-- columns (`attestation.player_user_id`, `entitlement.user_id`,
-- `receipt_fingerprint.user_id`, `audit_log.actor_user_id`) — never
-- through a `set_null` actor column. `fraud_signal` (subject: `user_id`)
-- and `review_item` (actor: `resolved_by`, an explicit, narrow "actions
-- you took" exception per the gate's own allowance) are exported too, but
-- restricted to `id`/`kind`/`created_at` only — never `detail`, never
-- `cleared_by`/`resolved_by`. Every other `set_null`/actor-only table
-- (`offer_code.redeemed_by_staff`, `partner_member.invited_by`,
-- `attestation.staff_user_id`, `marker_code`,
-- `special_marker_stock_movement`) is simply NOT exported at all — the
-- gate's own words: "At most include an 'actions you took' list... Keep
-- it simple; omitting them is acceptable." A handful of ephemeral/
-- operational `delete_row` tables (`checkin_challenge`, `course_qr_token`,
-- `device_reward_ledger`, `staff_activity`) and one classified-but-not-
-- named table (`partner_invite`, classified `special`, not among the
-- gate's four named subject-specials) are excluded the same way, each
-- with its own documented reason.
--
-- ⛔ FAIL-CLOSED COVERAGE, NOT MERELY A TEST (the gate offered either;
-- this uses both). `private.pii_export_policy` is a NEW, small registry —
-- one row per `app.` table this function's own SQL body knows about
-- (`action = 'export'` with a `reason`, or `action = 'exclude'` with a
-- `reason` — never merely a placeholder), covering the UNION of every
-- table `private.pii_retention_policy` classifies at all (delete_row,
-- set_null AND special — a strict superset of "every delete_row table",
-- so `review_item`/`fraud_signal`/`marker_code`/etc., which carry only a
-- `set_null`/`special` row and no `delete_row` row, are covered too).
-- Before exporting anything, this function itself walks
-- `pii_retention_policy` the SAME way `delete_my_data` does and RAISES if
-- any `app.` table it names has no `pii_export_policy` row at all — a
-- table added to the retention registry later, with no export decision
-- made for it, makes EVERY export call fail loudly (not silently omit
-- the new table) until someone classifies it. `10_function_inventory.sql`
-- / `verify-function-inventory.mjs` independently assert the two
-- registries stay in lockstep (every `pii_retention_policy` table has a
-- `pii_export_policy` row, and vice versa) as a schema-level check, so a
-- gap is caught at CI time too, not only the first time the function is
-- actually called.
--
-- Same `SECURITY DEFINER` / `private_definer` defense-in-depth as
-- `delete_my_data` (S1 close-out, 0016) — reusing the EXISTING `..._r`
-- SELECT policies 0016 already created as every DELETE/UPDATE policy's
-- mandatory read-visibility companion, under the SAME
-- `app.delete_my_data.target_user_id`/`target_email` GUCs. Zero new RLS
-- policies (see the original version's own note, unchanged by this
-- rewrite — every table this version reads already has a matching `_r`
-- policy from 0016, since every export path goes through a column 0016
-- already scoped one to).

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
  ('app', 'purchase_evidence', 'export', 'own purchase evidence, mirrors api.my_purchase_evidence'),
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
  ('app', 'audit_log', 'export', 'subject special (actor_user_id) -- id/action/subject_table/subject_id/created_at, never detail (may name another row/account)'),
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
--
-- ⛔ FIX (found this round, H2 approximation mode): `definer_policy_
-- allowlist` already has FORCE ROW LEVEL SECURITY on with no policy for
-- ANY role (0016's own final state) by the time THIS migration runs —
-- a plain INSERT here fails "permission denied for table
-- definer_policy_allowlist" under a NON-superuser connecting role
-- (superuser bypasses RLS regardless, which is why this was invisible
-- under HARNESS_MODE=superuser). Same self-granting CURRENT_USER
-- -scoped temporary-policy dance 0017/0019 already use for this EXACT
-- table (0019's own comment: "definer_policy_allowlist already has
-- FORCE RLS on by the time this migration runs").
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0021 ON private.definer_policy_allowlist
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
DROP POLICY current_user_seed_definer_policy_allowlist_0021 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

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

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, facility_id, trail_id, method, qr_variant, ref_id, offline, cosignal,
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

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, action, subject_table, subject_id, created_at
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

-- Not on the api.* RPC allowlist (§4.7 item 5) — this is called only from
-- the me-export Edge Function as service_role, never directly by a
-- client. No GRANT to anon/authenticated — same posture as
-- private.delete_my_data (0015).
--
-- ⛔ ORDERING (found this round, H2 approximation mode, still true after
-- the rewrite): REVOKE/GRANT run BEFORE the OWNER TO transfer below —
-- mirrors 0015/0016's own ordering exactly. See the original version's
-- comment (unchanged reasoning) for why running them AFTER the transfer
-- fails with "permission denied for function export_my_data".
REVOKE EXECUTE ON FUNCTION private.export_my_data(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.export_my_data(uuid) TO service_role;

-- ⛔ Same GRANT/REVOKE bracketing 0016_private_definer.sql itself needed
-- around its own OWNER TO transfers (its §2 comment: "ALTER FUNCTION...
-- OWNER TO private_definer fails with 'permission denied for schema
-- private' without [CREATE]... Postgres checks the NEW owner has CREATE
-- privilege in the object's schema for an ownership transfer"). 0016
-- deliberately REVOKED that CREATE grant from private_definer again once
-- its OWN transfers were done ("nothing in its actual job... ever
-- needs it") — so a LATER migration transferring a NEW function's
-- ownership to private_definer (this one) needs the same temporary
-- grant, bracketed the same way, rather than assuming 0016's own grant
-- is still standing (it isn't).
GRANT CREATE ON SCHEMA private TO private_definer;
ALTER FUNCTION private.export_my_data(uuid) OWNER TO private_definer;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- Derived function inventory (§4.7.1a, A2-09) — 0014_hardening.sql's
-- private.function_inventory table; verify-function-inventory.mjs /
-- 10_function_inventory.sql fail CI if this row is missing.
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('private', 'export_my_data', 'p_user_id uuid', false, false, true, 'me-export Edge Function only (0021) — read-only twin of private.delete_my_data (0015); explicit per-table column allow-lists, never SELECT *');
