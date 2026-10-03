-- 0044_export_first_attested.sql
--
-- GET /v1/me/export now carries app.device.first_attested_at (added by 0043).
--
-- WHY. 0043 deliberately left the column out of the export. It is a timestamp about the account's OWN device (the first time an `attested`
-- verdict was recorded on it), the same kind of fact as `integrity_last` (grade + time of the last verdict) and `first_seen` / `last_seen`, which
-- the export already carries, and the no-attestation rule ACTS on it (a device that has shown it can attest cannot later claim it cannot). A
-- data-subject export that withholds a record the service acts on is the weaker position (the same reasoning as 0028 for the reward ledger), so
-- the privacy default is to include it.
--
-- WHAT. private.export_my_data is rebuilt from 0028's FINAL body (nothing after 0028 redefines it: 0030 adds only export_my_data_for_actor, which
-- calls it) with exactly ONE change: `first_attested_at` is added to the explicit column list of the device block, after `integrity_last`. It is
-- a timestamptz, so it serialises exactly as first_seen / last_seen do (an ISO-8601 string, or JSON null for a device that never attested).
-- Same SECURITY DEFINER / empty search_path / owner / ACL (CREATE OR REPLACE keeps them), so private.function_inventory is unchanged; the
-- ownership bracket is 0020/0022/0024/0028's. No table, grant, policy or RLS setting is touched; FORCE RLS is not involved.

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

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
    SELECT id, user_id, platform, attest_key_id, attest_counter, integrity_last, first_attested_at, first_seen, last_seen
    FROM app.device WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('device', v_json);

  -- ---- P3f additions (0028): the caller's own reward-issuance ledger ----
  -- A reduced projection: which of the caller's OWN rewards were issued on which
  -- of the caller's OWN devices, and when. devicecheck_token_hash is the
  -- secret-key denylist's (a vendor-token digest, never exported, same as on
  -- app.device / offer_code / entitlement); nothing here names another account.
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, device_id, reward_kind, reward_id, at
    FROM app.device_reward_ledger WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('device_reward_ledger', v_json);

  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, device_id, source, source_ref, input_hash, course_id, facility_id,
           started_at, ended_at, local_date, summary, integrity, cosignal, attestation_grade,
           matcher_version, catalog_version, status, created_at,
           claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input
    FROM app.evidence WHERE user_id = p_user_id
  ) t;
  -- P3e round 2/3 (0024): the four queued_catalog columns are exported —
  -- see this migration's own header, section 4, for why queued_input is
  -- the caller's own data.
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
  'Read-only twin of private.delete_my_data — walks the SAME private.pii_retention_policy registry, cross-checked against private.pii_export_policy (fail-closed: raises if any classified table has no export decision). Every SELECT names its own explicit column list; never SELECT */to_jsonb(t) over a whole row, and never reached through a set_null ACTOR column. P3d gate round 3: also excludes audit_log.subject_id and purchase_evidence.ref_id (S1). P3e (0024): the evidence block additionally exports claimed_facility_id/claimed_course_id/claimed_catalog_version/queued_input. P3f (0028): additionally exports a reduced projection of the caller own device_reward_ledger rows (never devicecheck_token_hash); 0044: the device block additionally exports first_attested_at (0043); every other block is byte-identical to 0028.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;
