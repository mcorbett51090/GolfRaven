-- 0024_evidence_queued_claims.sql
-- P3e round 2 gate, BLOCKER B3: "the evidence FKs block every queued
-- row." `app.evidence.facility_id`/`course_id`/`catalog_version` (all
-- three — 0003_player_core.sql:95,96,105) are real, DEFERRABLE INITIALLY
-- DEFERRED foreign keys (`app.catalog_facility`/`app.catalog_course`/
-- `app.catalog_version`), so the violation surfaces at COMMIT, as a raw
-- 500 — confirmed this round directly against a real Postgres 17 cluster:
-- a `queued_catalog` insert for a facility id genuinely absent from
-- `app.catalog_facility` (the literal, intended trigger case for AT 8/
-- G3-10) always fails with `evidence_facility_id_fkey`.
--
-- Fix: a `queued_catalog` row NEVER writes `facility_id`/`course_id`/
-- `catalog_version` at all (they stay NULL, satisfying every existing FK
-- trivially) — the CLIENT's raw claim goes into three new, UNCONSTRAINED
-- `claimed_*` columns instead, plus the row's own validated submission
-- (needed for real re-derivation at drain time — P3e round 2 gate, B2)
-- in `queued_input`. A CHECK constraint makes the two states mutually
-- exclusive and machine-verifiable, not merely a convention.
--
-- Per the coordinator's round-2 correction: 0021/0022 are merged and
-- must never be edited again. The export-coverage change this table
-- change needs goes here, as a `CREATE OR REPLACE FUNCTION` under the
-- SAME temporary `private_definer` ownership bracket 0020's own
-- `hit_rate_limit` replacement uses (0021 already transferred this
-- function's ownership to `private_definer` — this migration does not
-- repeat that transfer, only the replace).

-- ============================================================================
-- 1. app.evidence: claimed_* + queued_input, and the CHECK that makes a
--    queued_catalog row's "no resolved ids yet" state structural.
-- ============================================================================
ALTER TABLE app.evidence ADD COLUMN claimed_facility_id text;
ALTER TABLE app.evidence ADD COLUMN claimed_course_id text;
-- The site version STRING (yyyymmdd-gitsha7 — P3e round 2 gate, H1), not
-- the internal int: the whole point of a claim is that the server has
-- not yet imported it, so there is no internal `catalog_version.version`
-- row to reference at all, deliberately no FK.
ALTER TABLE app.evidence ADD COLUMN claimed_catalog_version text;
COMMENT ON COLUMN app.evidence.claimed_facility_id IS
  'The client''s raw, UNRESOLVED facilityId claim for a queued_catalog row (P3e round 2 gate B3) — never FK-constrained, because the whole reason the row is queued is that this id is not yet in app.catalog_facility. NULL once the row is drained to accepted/needs_attention/unknown_id (the resolved facility_id column takes over).';
COMMENT ON COLUMN app.evidence.claimed_course_id IS
  'Same as claimed_facility_id, for courseId (nullable — a facility-level submission carries none).';
COMMENT ON COLUMN app.evidence.claimed_catalog_version IS
  'The client''s claimed site catalogVersion string (yyyymmdd-gitsha7) for a queued_catalog row — used at drain time (M1) to tell "not yet imported, still legitimately queued" apart from "the import that should have covered this already ran, and the id still doesn''t exist" (terminal unknown_id).';

ALTER TABLE app.evidence ADD COLUMN queued_input jsonb;
COMMENT ON COLUMN app.evidence.queued_input IS
  'The FULL validated (request-shape.ts-parsed) submission for a queued_catalog row, server-only (P3e round 2 gate B3: "never exposed through api.* views" — see api.my_evidence and private.export_my_data below, both updated in this migration to exclude it explicitly). Read back at drain time (B2) to re-run the REAL intake derivation (tombstone rewrite, facility/course pairing, localDate, matcher, scorePlay) — never merely a status flip. NULL once the row is drained.';

ALTER TABLE app.evidence ADD CONSTRAINT evidence_queued_claim_shape CHECK (
  status <> 'queued_catalog'
  OR (facility_id IS NULL AND course_id IS NULL AND catalog_version IS NULL AND claimed_facility_id IS NOT NULL)
);
COMMENT ON CONSTRAINT evidence_queued_claim_shape ON app.evidence IS
  'P3e round 2 gate, B3: a queued_catalog row NEVER carries a resolved facility_id/course_id/catalog_version (those three FKs would reject an unknown claimed id at COMMIT) — it carries claimed_facility_id instead. Machine-enforced, not merely a convention the intake code is trusted to follow.';

-- ============================================================================
-- 2. M1: a terminal outcome for "the import that should have covered this
--    claim already ran, and the id still doesn't exist" — distinct from
--    `needs_attention` (which stays reachable purely by AGE, independent
--    of whether an import ran at all) and distinct from the live-request
--    `422 unknown_id` (a client-facing HTTP error code, not a stored
--    status). `ALTER TYPE ... ADD VALUE` cannot run in the same
--    transaction as a DML statement that USES the new value (a hard
--    Postgres restriction — 0019's own note on `attestation_grade` makes
--    the same point) — this migration only adds the value; nothing in
--    THIS file ever writes an `unknown_id` row.
-- ============================================================================
ALTER TYPE app.evidence_status ADD VALUE 'unknown_id';

-- ============================================================================
-- 3. api.my_evidence: `SELECT * FROM app.evidence` in 0010 was expanded at
--    view-creation time, so the view is FROZEN at the original 17 columns —
--    it does NOT pick up queued_input (nor the 0019 additions), and
--    CREATE OR REPLACE VIEW may only APPEND columns, never reorder or
--    drop. So this replace keeps the existing 17 in their existing order
--    and appends ONLY the three claimed_* columns (exactly what the
--    player themselves submitted while queued — a player legitimately
--    benefits from seeing why their own row is still pending, §7.6).
--    queued_input stays absent (B3: "never exposed through api.* views");
--    the matrix proves it.
-- ============================================================================
CREATE OR REPLACE VIEW api.my_evidence WITH (security_invoker = true) AS
  SELECT id, user_id, device_id, source, source_ref, source_bundle, course_id, facility_id,
         started_at, ended_at, summary, integrity, cosignal, matcher_version, catalog_version,
         status, created_at,
         claimed_facility_id, claimed_course_id, claimed_catalog_version
  FROM app.evidence WHERE user_id = auth.uid();

-- ============================================================================
-- 4. private.export_my_data (GET /v1/me/export) — rebuilt from 0022's FINAL
--    body (P3e round 3, R1). 0024 runs AFTER 0022, so a replacement taken
--    from any earlier body would silently UNDO P3d rounds 3-4 (S1 dropped
--    audit_log.subject_id and purchase_evidence.ref_id; the export's keys
--    must equal the `export`-classified private.pii_export_policy tables,
--    pgTAP 14_me_export.sql). The ONLY difference from 0022's function is
--    the `evidence` block's column list: it additionally exports
--    claimed_facility_id, claimed_course_id, claimed_catalog_version and
--    queued_input (verifiable: extract both bodies and diff — one hunk).
--
--    DECISION — queued_input IS exported (it is NOT excluded):
--      * It is the caller's OWN raw submission (the validated body they
--        POSTed, held until the covering catalog import lets the server
--        score it). It holds their own location fixes and ids — exactly
--        the data a data-subject export exists to return. Omitting it
--        would make the export incomplete for any row still queued.
--      * It cannot contain another account's data or a secret: the value
--        is the output of request-shape.ts's STRICT, allow-listed parser
--        (unknown keys are rejected), so it only ever holds the
--        player-submittable fields (source, deviceId, facilityId,
--        courseId, localDate, catalogVersion, fix/dwell fixes incl. the
--        player's own checkinTokenJti, and manifestSig — a PUBLIC
--        signature copied from the catalog, not a secret).
--      * It is still NEVER exposed through api.my_evidence (B3: "never
--        exposed through api.* views") — that is the always-on,
--        client-facing PostgREST/realtime surface; the export is a
--        one-shot, caller-authenticated, size-bounded access path.
--    The value is NULL once a row is drained (resolveQueuedRow clears it).
--
--    delete_my_data needs no change for the new columns: all four live on
--    the SAME app.evidence row, which is already deleted by its `user_id`
--    delete_row classification, and the post-condition / column-level
--    `_r` companion check (check 8/11/12) are about the (table, subject
--    column) pairs in pii_retention_policy — evidence.user_id — not about
--    non-subject data columns. Proven by a matrix cell (15_catalog_import
--    .sql) that deletes a user holding a queued row.
--
--    Same ownership bracket as 0022 (0020's pattern): the function is
--    already owned by private_definer; replacing it needs the temporary
--    CREATE on schema private.
-- ============================================================================
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
    SELECT id, user_id, platform, attest_key_id, attest_counter, integrity_last, first_seen, last_seen
    FROM app.device WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('device', v_json);

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
  'Read-only twin of private.delete_my_data — walks the SAME private.pii_retention_policy registry, cross-checked against private.pii_export_policy (fail-closed: raises if any classified table has no export decision). Every SELECT names its own explicit column list; never SELECT */to_jsonb(t) over a whole row, and never reached through a set_null ACTOR column. P3d gate round 3: also excludes audit_log.subject_id and purchase_evidence.ref_id (S1). P3e (0024): the evidence block additionally exports claimed_facility_id/claimed_course_id/claimed_catalog_version/queued_input (the caller own queued submission); every other block is byte-identical to 0022.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;
