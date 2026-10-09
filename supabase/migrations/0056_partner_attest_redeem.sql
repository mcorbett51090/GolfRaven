-- 0056_partner_attest_redeem.sql
--
-- P5.1a, slice S3 (database half): ATTEST. docs/security/partner-auth-design.md section 12 (S3), 12.1 (AT(1) attestation half, AT(2), AT(12), AT(13), AT(15), AT(16) part one), 6.5 (self-attest, per
-- account), 6.7 / X9 (the verify-and-record definer supersedes the 0045 recorder), and docs/security/p3-money-path-requirements.md "What P5 must do (the staff verification endpoint), in order"
-- are the specification; its "As built: S3" section (design 26) is the reading guide for this file. Migrations 0001-0054 are untouched (0055 belongs to the parallel S2b slice and is not created here).
--
-- WHAT THIS ADDS (all of it partner-bound: every function is a `_for_partner` definer that begins with private.partner_authorize, class A1 for an action and A0 for a read)
--   1. private.partner_attest_for_partner(facility, kind, token): the ONLINE path. The token is the player's own `checkin_token.jti` (issued by the existing checkin-token endpoint: server-graded, single use per
--      attestation, 15 minutes). The player is DERIVED from the token, never named by the caller. Self-attest is 22023 `self_attestation_refused` (per ACCOUNT, 6.5). One attestation per token (a replay is
--      a status). The same-device rule (plan A2-21: an account on the staff member's own device) writes the attestation but sends the purchase to held_review and opens a fraud_signal.
--   2. private.partner_offline_attest_for_partner(facility, kind, handle, code): the OFFLINE code, VERIFIED AND RECORDED IN THE DATABASE (money doc step 3, X9). Takes the handle and the six typed digits;
--      derives each candidate device's seed with private.offline_seed_derive (no EXECUTE for anyone: only a definer can), computes the HMAC-SHA-256 / 600 s HOTP in SQL (private.hotp), compares with a
--      per-call keyed double HMAC, records the matched (device, version, step) with the 0045 atomic INSERT ... ON CONFLICT DO NOTHING, and returns ONLY a status, the attestation id and a held flag. It
--      never returns, logs or stores a seed or an expected code. The failure counters (5 per staff an hour, 10 per target an hour and 30 a day across all staff, money doc step 2) are written BEFORE the
--      verdict can leak and COMMIT (statuses, never a RAISE). Candidates: the player's 5 most recently seen devices of the last 90 days (15 codes a guess).
--   3. private.partner_shift_log_for_partner(facility) and private.partner_staff_activity_for_partner(facility, days): the Edge reads that replace api.staff_shift_log (staff, manager) and
--      api.staff_activity (manager, operator) now that D12 (0047) has revoked the PostgREST path. The shift log returns the old view's rows (the facility's, newest first) and a SUBSET of its columns.
--   4. The shared writer private.partner_attest_write: attestation + attestation_shift_log + staff_activity, and for a marker purchase a purchase_evidence (method staff_scan) + marker_credit per eligible
--      trail, PENDING with `cosignal.awaiting` exactly as the S2a seam paragraph states (the player's fix completes it through the existing marker_cosignal_attach_for_actor), or held_review on the
--      same-device rule. No role has EXECUTE on it but its owner.
--   5. COLD-START CAP (design 10, plan 8.3 as read by this slice): a member whose earliest active membership is under 7 days old is held to 30 attestations in any rolling 24 hours (a status).
--   6. BINDING-KEYED POLICIES (S1.1a LOW-3). 0047 section 8c closed every GUC window (pd_offline_code_step_insert / _prune among them) under a partner binding, and 0017's guard reads. This file adds the
--      policies the new definers need, each keyed on the transaction's partner BINDING and on a facility-scope predicate (private.partner_bound_staff_at / _any), never on a settable GUC (the HARD
--      RULE of the money doc). They are the only way the partner lane writes the tables below; each is registered in definer_policy_allowlist and in its checked-in fixture.
--   7. X9 re-asserted: private.offline_code_record_step_for_actor is executable by NO edge role (0047 revoked it from edge_actor; a DO block here proves it, so a later GRANT cannot slip by).
--
-- DELIBERATELY NOT HERE (see design 26 "Not built, honestly"): offers-redeem (the budget settlement it needs, offer.budget_reserved to budget_used, is P5.1b's); an `app.evidence` staff_presence projection
-- (the scoring union is not wired to attestations); the co-signal that sets attestation.cosignal_ok (a player fix, arriving later through the existing intake).
--
-- CHECK 14 (verify-function-inventory): every `_for_partner` body below begins with private.partner_authorize (a string-literal class), holds no dollar sign, double quote, backslash or E-string, and no
-- EXCEPTION block; comments inside the bodies obey the same lexing. Counter and verification outcomes are STATUS rows; only malformed arguments and a self-attest (22023) and missing authority (42501) raise.
-- OWNERSHIP BRACKET as 0054: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; CREATE FUNCTION ...; RESET ROLE; REVOKE CREATE.

-- ============================================================================
-- 1. Binding-keyed predicates (EXECUTE for nobody: policies and sibling definers owned by private_definer evaluate them)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- true iff THIS transaction carries a partner binding whose member is staff or manager (an admin passes has_facility_scope too, E6) at p_facility_id. Not a GUC, not a user binding.
CREATE FUNCTION private.partner_bound_staff_at(p_facility_id text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM private.actor_binding b
    WHERE b.backend_pid = pg_catalog.pg_backend_pid()
      AND b.xact = pg_catalog.pg_current_xact_id_if_assigned()
      AND b.kind = 'partner'
      AND private.is_staff_or_manager_of_facility(b.actor_uid, p_facility_id)
  );
$$;

-- the same, for a manager or operator (the staff_activity reader of design 5.5)
CREATE FUNCTION private.partner_bound_manager_at(p_facility_id text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM private.actor_binding b
    WHERE b.backend_pid = pg_catalog.pg_backend_pid()
      AND b.xact = pg_catalog.pg_current_xact_id_if_assigned()
      AND b.kind = 'partner'
      AND private.is_manager_or_operator_of_facility(b.actor_uid, p_facility_id)
  );
$$;

-- true iff THIS transaction carries a partner binding whose member holds a staff or manager scope somewhere (or is an admin): the partner twin of 0045's offline_code_bound_staff(). NOT a per-device or
-- per-facility boundary: it lets a definer SEE a player's device, handle or token row; WHICH row and WHICH facility are the definer's explicit filters (the HARD RULE).
CREATE FUNCTION private.partner_bound_staff_any()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM private.actor_binding b
    WHERE b.backend_pid = pg_catalog.pg_backend_pid()
      AND b.xact = pg_catalog.pg_current_xact_id_if_assigned()
      AND b.kind = 'partner'
      AND (
        private.is_admin(b.actor_uid)
        OR EXISTS (
          SELECT 1
          FROM app.partner_member pm
          JOIN app.partner_scope ps ON ps.org_id = pm.org_id AND ps.facility_id IS NOT NULL
          WHERE pm.user_id = b.actor_uid AND pm.revoked_at IS NULL AND pm.role IN ('staff', 'manager')
        )
      )
  );
$$;

REVOKE EXECUTE ON FUNCTION private.partner_bound_staff_at(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_bound_manager_at(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_bound_staff_any() FROM PUBLIC;
COMMENT ON FUNCTION private.partner_bound_staff_at(text) IS
  '0056. Policy predicate: a partner binding is bound in THIS transaction and its member is staff / manager (or admin) at the facility. Keyed on the binding, not a GUC. No role holds EXECUTE but the owner (private_definer, the only role whose policies call it).';
COMMENT ON FUNCTION private.partner_bound_manager_at(text) IS
  '0056. Policy predicate: a partner binding is bound in THIS transaction and its member is manager / operator (or admin) at the facility. No role holds EXECUTE but the owner.';
COMMENT ON FUNCTION private.partner_bound_staff_any() IS
  '0056. Policy predicate: a partner binding is bound in THIS transaction and its member holds a staff / manager scope at some facility (or is admin). The partner twin of offline_code_bound_staff() (0045). Not a per-row boundary: the definers filter explicitly.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Grants and policies (private_definer). Column-level wherever a whole-row grant would reach more than the definers use. Every policy is keyed on the binding and a facility predicate.
-- ============================================================================
-- 2a. attestation: INSERT (the token's jti is the nonce the 0017 tombstone trigger records), SELECT of the staff member's OWN rows (the cold-start count and the returned id).
GRANT INSERT (facility_id, staff_user_id, staff_pseudonym, staff_pseudonym_hmac_id, player_user_id, player_pseudonym, player_pseudonym_hmac_id, kind, token_jti, cosignal_ok) ON app.attestation TO private_definer;
CREATE POLICY pd_partner_attest_insert ON app.attestation FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND staff_user_id = (SELECT private.partner_binding_user())
              AND kind IN ('presence', 'marker_purchase') AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_attest_select ON app.attestation FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND staff_user_id = (SELECT private.partner_binding_user()));

-- 2b. the nonce tombstone the 0017 trigger writes for every attestation (source 'attestation'): written and read under a partner binding, for this source only.
CREATE POLICY pd_partner_attest_nonce_insert ON private.consumed_nonce FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND source = 'attestation');
CREATE POLICY pd_partner_attest_nonce_select ON private.consumed_nonce FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND source = 'attestation');

-- 2c. the pseudonym registry the 0018 validate trigger writes through private.validate_and_register_pseudonym_hmac_id (a definer owned by private_definer; its policy is its own) needs nothing here.

-- 2d. attestation_shift_log: INSERT and the facility read (the old api.staff_shift_log: staff and managers of that facility).
GRANT INSERT (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle) ON app.attestation_shift_log TO private_definer;
CREATE POLICY pd_partner_shift_log_insert ON app.attestation_shift_log FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_shift_log_select ON app.attestation_shift_log FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));

-- 2e. staff_activity: the member's own day row (insert, increment); managers and operators read the facility's.
GRANT INSERT (staff_user_id, facility_id, day, attests, anomalies), UPDATE (attests, anomalies) ON app.staff_activity TO private_definer;
CREATE POLICY pd_partner_staff_activity_insert ON app.staff_activity FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND staff_user_id = (SELECT private.partner_binding_user()) AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_staff_activity_update ON app.staff_activity FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND staff_user_id = (SELECT private.partner_binding_user()) AND private.partner_bound_staff_at(facility_id))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND staff_user_id = (SELECT private.partner_binding_user()) AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_staff_activity_select ON app.staff_activity FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND ((staff_user_id = (SELECT private.partner_binding_user()) AND private.partner_bound_staff_at(facility_id)) OR private.partner_bound_manager_at(facility_id)));

-- 2f. the player's rows the definers read to resolve a token or a handle and to derive a candidate: profile (handle), checkin_token (the jti), device (the 5 most recent). Visible only under a partner binding
-- of a staff / manager anywhere; the definers filter explicitly by token, handle or user.
CREATE POLICY pd_partner_attest_profile_select ON app.profile FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_any());
CREATE POLICY pd_partner_attest_token_select ON app.checkin_token FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_any());
CREATE POLICY pd_partner_attest_device_select ON app.device FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_any());

-- 2f2. the facility's time zone and the trail's programme state (both read by the writer): 0046's policies on them are keyed on the USER binding (actor_uid() IS NOT NULL) and are closed to a partner.
CREATE POLICY pd_partner_attest_facility_read ON app.catalog_facility FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_any());
CREATE POLICY pd_partner_attest_trail_programme_read ON app.trail_programme FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_any());

-- 2g. the replay table of the offline code (0045): INSERT one accepted step at a facility the bound member works at; the prune removes only steps the 2-step database window can never accept again (dead
-- rows, data-derived: no GUC). The step table's SELECT is the prune's row-visibility companion.
CREATE POLICY pd_partner_offline_step_insert ON app.offline_code_step FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
-- INSERT ... ON CONFLICT is checked against the SELECT policies too (the new row must be one the role may see): the step rows of the facilities the bound member works at.
CREATE POLICY pd_partner_offline_step_select ON app.offline_code_step FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_offline_step_prune ON app.offline_code_step FOR DELETE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND step < (pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.now()) / 600)::bigint - 3));
CREATE POLICY pd_partner_offline_step_prune_r ON app.offline_code_step FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND step < (pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.now()) / 600)::bigint - 3));

-- 2h. the marker purchase a staff scan writes: pending (cosignal.awaiting) or held_review, for the player, at a facility the bound member works at. UPDATE stays the player's (the intake), not ours.
CREATE POLICY pd_partner_attest_purchase_insert ON app.purchase_evidence FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND method = 'staff_scan' AND status IN ('pending', 'held_review') AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_attest_purchase_select ON app.purchase_evidence FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND method = 'staff_scan' AND private.partner_bound_staff_at(facility_id));
CREATE POLICY pd_partner_attest_credit_insert ON app.marker_credit FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND status IN ('pending', 'held_review') AND private.partner_bound_staff_at(facility_id));

-- 2i. the fraud signal of the same-device rule (plain INSERT, no RETURNING, so no SELECT policy is needed)
GRANT INSERT (user_id, kind, detail) ON app.fraud_signal TO private_definer;
CREATE POLICY pd_partner_attest_fraud_insert ON app.fraud_signal FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND kind = 'same_device_attest');

-- ============================================================================
-- 3. The writer and the two definers of the attest lane, then the two reads.
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. THE WRITER. Called by the two attest definers AFTER partner_authorize and every check of theirs; reads no binding (the policies are the guard rail and the callers' explicit checks are the rule).
-- Returns: ok | no_facility | no_programme | cold_start_cap. p_held is the same-device verdict computed by the caller.
--   p_window_from / p_window_to: the co-signal window of a marker purchase (the S2a seam: a fix in [from, to], received before now + 7 days completes it).
CREATE FUNCTION private.partner_attest_write(
  p_staff uuid, p_facility_id text, p_player uuid, p_kind text, p_jti text, p_ref text, p_offline boolean, p_held boolean,
  p_window_from timestamptz, p_window_to timestamptz
)
RETURNS TABLE (o_status text, o_attestation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_tz text;
  v_day date;
  v_since timestamptz;
  v_recent bigint;
  v_trails text[];
  v_trail text;
  v_staff_ps text;
  v_staff_key uuid;
  v_player_ps text;
  v_player_key uuid;
  v_player_handle text;
  v_staff_handle text;
  v_att uuid;
  v_purchase uuid;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_cosignal jsonb;
BEGIN
  SELECT f.tz INTO v_tz FROM app.catalog_facility f WHERE f.id = p_facility_id;
  IF v_tz IS NULL THEN
    RETURN QUERY SELECT 'no_facility'::text, NULL::uuid;
    RETURN;
  END IF;
  v_day := (v_now AT TIME ZONE v_tz)::date;

  -- the cold-start cap: a member whose earliest active membership is under 7 days old may attest 30 times in any rolling 24 hours
  SELECT pg_catalog.min(m.created_at) INTO v_since FROM app.partner_member m WHERE m.user_id = p_staff AND m.revoked_at IS NULL;
  IF v_since IS NOT NULL AND v_since > v_now - interval '7 days' THEN
    SELECT pg_catalog.count(*) INTO v_recent FROM app.attestation a WHERE a.staff_user_id = p_staff AND a.created_at > v_now - interval '24 hours';
    IF v_recent >= 30 THEN
      RETURN QUERY SELECT 'cold_start_cap'::text, NULL::uuid;
      RETURN;
    END IF;
  END IF;

  IF p_kind = 'marker_purchase' THEN
    SELECT pg_catalog.array_agg(fp.trail_id ORDER BY fp.trail_id) INTO v_trails
    FROM app.facility_programme fp JOIN app.trail_programme tp ON tp.trail_id = fp.trail_id
    WHERE fp.facility_id = p_facility_id AND fp.participation = 'accepted' AND tp.status IN ('pilot', 'live') AND tp.marker_source = 'any_purchase';
    IF v_trails IS NULL THEN
      RETURN QUERY SELECT 'no_programme'::text, NULL::uuid;
      RETURN;
    END IF;
  END IF;

  SELECT a.pseudonym, a.key_id INTO v_staff_ps, v_staff_key FROM private.account_pseudonyms(p_staff) a WHERE a.preferred LIMIT 1;
  SELECT a.pseudonym, a.key_id INTO v_player_ps, v_player_key FROM private.account_pseudonyms(p_player) a WHERE a.preferred LIMIT 1;
  SELECT p.handle INTO v_player_handle FROM app.profile p WHERE p.user_id = p_player;
  SELECT p.handle INTO v_staff_handle FROM app.profile p WHERE p.user_id = p_staff;
  IF v_player_handle IS NULL THEN
    v_player_handle := 'player';
  END IF;
  IF v_staff_handle IS NULL THEN
    v_staff_handle := 'staff-' || pg_catalog.substr(pg_catalog.replace(p_staff::text, '-', ''), 1, 8);
  END IF;

  INSERT INTO app.attestation (facility_id, staff_user_id, staff_pseudonym, staff_pseudonym_hmac_id, player_user_id, player_pseudonym, player_pseudonym_hmac_id, kind, token_jti, cosignal_ok)
  VALUES (p_facility_id, p_staff, v_staff_ps, v_staff_key, p_player, v_player_ps, v_player_key, p_kind::app.attestation_kind, p_jti, false)
  RETURNING id INTO v_att;

  INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle)
  VALUES (p_facility_id, p_kind::app.attestation_kind, v_player_handle, v_player_ps, v_player_key, v_staff_handle);

  INSERT INTO app.staff_activity (staff_user_id, facility_id, day, attests, anomalies)
  VALUES (p_staff, p_facility_id, v_day, 1, CASE WHEN p_held THEN pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('kind', 'same_device_attest', 'attestation', v_att)) ELSE '[]'::jsonb END)
  ON CONFLICT (staff_user_id, facility_id, day) DO UPDATE
    SET attests = app.staff_activity.attests + 1,
        anomalies = CASE WHEN p_held THEN app.staff_activity.anomalies || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('kind', 'same_device_attest', 'attestation', v_att)) ELSE app.staff_activity.anomalies END;

  IF p_kind = 'marker_purchase' THEN
    v_cosignal := CASE WHEN p_held THEN NULL ELSE pg_catalog.jsonb_build_object('awaiting', pg_catalog.jsonb_build_object(
        'from', pg_catalog.to_char(p_window_from AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'to', pg_catalog.to_char(p_window_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'until', pg_catalog.to_char((v_now + interval '7 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))) END;
    FOREACH v_trail IN ARRAY v_trails LOOP
      INSERT INTO app.purchase_evidence (user_id, facility_id, trail_id, method, ref_id, offline, cosignal, local_date, status)
      VALUES (p_player, p_facility_id, v_trail, 'staff_scan', p_ref, p_offline, v_cosignal, v_day, CASE WHEN p_held THEN 'held_review' ELSE 'pending' END::app.purchase_status)
      RETURNING id INTO v_purchase;
      INSERT INTO app.marker_credit (user_id, trail_id, facility_id, purchase_evidence_id, status)
      VALUES (p_player, v_trail, p_facility_id, v_purchase, CASE WHEN p_held THEN 'held_review' ELSE 'pending' END::app.credit_status);
    END LOOP;
  END IF;

  IF p_held THEN
    INSERT INTO app.fraud_signal (user_id, kind, detail)
    VALUES (p_player, 'same_device_attest', pg_catalog.jsonb_build_object('facilityId', p_facility_id, 'kind', p_kind, 'attestation', v_att));
  END IF;
  PERFORM private.partner_audit_write('partner.attest', 'app.attestation', v_att::text,
    pg_catalog.jsonb_build_object('facility', p_facility_id, 'kind', p_kind, 'offline', p_offline, 'held', p_held));
  RETURN QUERY SELECT 'ok'::text, v_att;
END
$$;

-- 3b. The same-device rule (plan A2-21): does any device of the staff member share an install, an App Attest key or a DeviceCheck token with the player's device? Reads NO binding (the caller passes the uids).
CREATE FUNCTION private.partner_attest_same_device(p_staff uuid, p_player_device uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM app.device pd
    JOIN app.device sd ON sd.user_id = p_staff
    WHERE pd.id = p_player_device
      AND ((pd.install_link_hash IS NOT NULL AND sd.install_link_hash = pd.install_link_hash)
        OR (pd.attest_key_id IS NOT NULL AND sd.attest_key_id = pd.attest_key_id)
        OR (pd.devicecheck_token_hash IS NOT NULL AND sd.devicecheck_token_hash = pd.devicecheck_token_hash))
  );
$$;

-- 3c. ONLINE attest (class A1: staff or manager at the facility, one PIN per action). The player comes from the token. Statuses (all commit): ok | token_invalid | replayed | no_facility | no_programme | cold_start_cap.
-- Raises: 42501 (no scope, no PIN grant), 22023 (malformed arguments; self_attestation_refused).
CREATE FUNCTION private.partner_attest_for_partner(p_facility_id text, p_kind text, p_token uuid)
RETURNS TABLE (o_status text, o_attestation_id uuid, o_held boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_tok record;
  v_held boolean;
  v_w record;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_kind IS NULL OR p_kind NOT IN ('presence', 'marker_purchase') OR p_token IS NULL THEN
    RAISE EXCEPTION 'partner_attest_for_partner: a facility, a kind (presence or marker_purchase) and a token are required' USING ERRCODE = '22023';
  END IF;
  -- one attestation per token, serialised: the lock is held to the end of the transaction
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('partner-attest:' || p_token::text, 0));
  SELECT t.user_id, t.device_id, t.facility_id, t.expires_at INTO v_tok FROM app.checkin_token t WHERE t.jti = p_token;
  IF NOT FOUND OR v_tok.expires_at <= v_now OR (v_tok.facility_id IS NOT NULL AND v_tok.facility_id <> p_facility_id) THEN
    RETURN QUERY SELECT 'token_invalid'::text, NULL::uuid, false;
    RETURN;
  END IF;
  IF v_tok.user_id = v_uid THEN
    RAISE EXCEPTION 'self_attestation_refused: a staff member cannot attest their own account' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (SELECT 1 FROM private.consumed_nonce n WHERE n.nonce_hash = p_token::text AND n.source = 'attestation') THEN
    RETURN QUERY SELECT 'replayed'::text, NULL::uuid, false;
    RETURN;
  END IF;
  v_held := private.partner_attest_same_device(v_uid, v_tok.device_id);
  SELECT w.o_status, w.o_attestation_id INTO v_w
  FROM private.partner_attest_write(v_uid, p_facility_id, v_tok.user_id, p_kind, p_token::text, 'token:' || p_token::text, false, v_held,
                                     v_now - interval '10 minutes', v_now + interval '20 minutes') w;
  RETURN QUERY SELECT v_w.o_status, v_w.o_attestation_id, (v_w.o_status = 'ok' AND v_held);
END
$$;

-- 3d. OFFLINE attest: VERIFY AND RECORD (class A1). Statuses (all commit, so the failure counters survive): ok | replayed | verification_failed | rate_limited | no_facility | no_programme | cold_start_cap.
-- verification_failed is ONE answer for a malformed code, an unknown handle, a player with no recent device and a wrong code. replayed (the 409 of AT(13)) is told apart because the step was valid. A refusal NEVER
-- carries a seed, an expected code, a device or a per-candidate result. The staff counter is checked and (on failure) written under an advisory lock, so parallel guesses are counted, not raced.
CREATE FUNCTION private.partner_offline_attest_for_partner(p_facility_id text, p_kind text, p_handle text, p_code text)
RETURNS TABLE (o_status text, o_attestation_id uuid, o_held boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_player uuid;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_step_now bigint := pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) / 600)::bigint;
  v_staff_key text;
  v_hour_key text;
  v_day_key text;
  v_fails bigint;
  v_t_hour bigint;
  v_t_day bigint;
  v_cmp bytea := public.gen_random_bytes(16);
  v_dev record;
  v_off integer;
  v_seed bytea;
  v_hit_dev uuid;
  v_hit_ver integer;
  v_hit_step bigint;
  v_n integer;
  v_held boolean;
  v_w record;
  v_failed boolean := true;
  v_replayed boolean := false;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_kind IS NULL OR p_kind NOT IN ('presence', 'marker_purchase') OR p_handle IS NULL OR p_code IS NULL THEN
    RAISE EXCEPTION 'partner_offline_attest_for_partner: a facility, a kind, a handle and a code are required' USING ERRCODE = '22023';
  END IF;
  v_staff_key := 'offline-code-fail:staff:' || v_uid::text;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_staff_key, 0));
  SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_fails FROM private.rate_limit_bucket r WHERE r.bucket_key = v_staff_key AND r.window_start > v_now - interval '1 hour';
  IF v_fails >= 5 THEN
    RETURN QUERY SELECT 'rate_limited'::text, NULL::uuid, false;
    RETURN;
  END IF;

  -- resolve the handle (no handle oracle: an unknown one is a counted failure like a wrong code)
  IF pg_catalog.char_length(p_handle) BETWEEN 3 AND 20 AND p_handle !~ '[^a-z0-9_]' THEN
    SELECT p.user_id INTO v_player FROM app.profile p WHERE p.handle = p_handle;
  END IF;
  IF v_player IS NOT NULL AND v_player = v_uid THEN
    RAISE EXCEPTION 'self_attestation_refused: a staff member cannot attest their own account' USING ERRCODE = '22023';
  END IF;

  IF v_player IS NOT NULL THEN
    v_hour_key := 'offline-code-fail:target-h:' || v_player::text;
    v_day_key := 'offline-code-fail:target-d:' || v_player::text;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_hour_key, 0));
    SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_t_hour FROM private.rate_limit_bucket r WHERE r.bucket_key = v_hour_key AND r.window_start > v_now - interval '1 hour';
    SELECT coalesce(pg_catalog.sum(r.count), 0) INTO v_t_day FROM private.rate_limit_bucket r WHERE r.bucket_key = v_day_key AND r.window_start > v_now - interval '1 day';
    IF v_t_hour >= 10 OR v_t_day >= 30 THEN
      RETURN QUERY SELECT 'rate_limited'::text, NULL::uuid, false;
      RETURN;
    END IF;
  END IF;

  -- the verification: every candidate x every step is evaluated, with no early exit, so the time does not say which device matched
  IF v_player IS NOT NULL AND pg_catalog.char_length(p_code) = 6 AND p_code !~ '[^0-9]' THEN
    FOR v_dev IN
      SELECT d.id AS id, d.offline_seed_version AS ver
      FROM app.device d
      WHERE d.user_id = v_player AND d.last_seen > v_now - interval '90 days'
      ORDER BY d.last_seen DESC, d.id
      LIMIT 5
    LOOP
      v_seed := private.offline_seed_derive(v_player, v_dev.id, v_dev.ver);
      FOR v_off IN -1 .. 1 LOOP
        IF public.hmac(pg_catalog.convert_to(private.hotp(v_seed, v_step_now + v_off, 6, 'sha256'), 'UTF8'), v_cmp, 'sha256') = public.hmac(pg_catalog.convert_to(p_code, 'UTF8'), v_cmp, 'sha256') AND v_hit_dev IS NULL THEN
          v_hit_dev := v_dev.id;
          v_hit_ver := v_dev.ver;
          v_hit_step := v_step_now + v_off;
        END IF;
      END LOOP;
    END LOOP;
  END IF;

  IF v_hit_dev IS NOT NULL THEN
    DELETE FROM app.offline_code_step s WHERE s.device_id = v_hit_dev AND s.step < v_step_now - 3;
    INSERT INTO app.offline_code_step (user_id, device_id, seed_version, step, facility_id)
    VALUES (v_player, v_hit_dev, v_hit_ver, v_hit_step, p_facility_id)
    ON CONFLICT (device_id, seed_version, step) DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n = 1 THEN
      v_failed := false;
    ELSE
      v_replayed := true;
    END IF;
  END IF;

  IF v_failed THEN
    PERFORM private.hit_rate_limit(v_staff_key, interval '1 hour', 1000000);
    IF v_player IS NOT NULL THEN
      PERFORM private.hit_rate_limit(v_hour_key, interval '1 hour', 1000000);
      PERFORM private.hit_rate_limit(v_day_key, interval '1 day', 1000000);
    END IF;
    RETURN QUERY SELECT (CASE WHEN v_replayed THEN 'replayed' ELSE 'verification_failed' END)::text, NULL::uuid, false;
    RETURN;
  END IF;

  v_held := private.partner_attest_same_device(v_uid, v_hit_dev);
  SELECT w.o_status, w.o_attestation_id INTO v_w
  FROM private.partner_attest_write(v_uid, p_facility_id, v_player, p_kind,
         'offline:' || v_hit_dev::text || ':' || v_hit_ver::text || ':' || v_hit_step::text,
         'offline:' || v_hit_dev::text || ':' || v_hit_ver::text || ':' || v_hit_step::text, true, v_held,
         pg_catalog.to_timestamp((v_hit_step * 600)::double precision) - interval '10 minutes',
         pg_catalog.to_timestamp((v_hit_step * 600)::double precision) + interval '20 minutes') w;
  RETURN QUERY SELECT v_w.o_status, v_w.o_attestation_id, (v_w.o_status = 'ok' AND v_held);
END
$$;

-- 3e. GET shift-log (class A0: staff or manager of the facility): the old api.staff_shift_log's rows, the facility's, newest first, last 90 days (the retention of the projection), and a SUBSET of its columns:
-- id, facility_id, created_at, kind, player_handle_snapshot, staff_handle. The player's keyed pseudonym the old view's SELECT * carried is NOT returned (nothing a screen needs).
CREATE FUNCTION private.partner_shift_log_for_partner(p_facility_id text)
RETURNS TABLE (o_id uuid, o_facility_id text, o_created_at timestamptz, o_kind app.attestation_kind, o_player_handle text, o_staff_handle text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' THEN
    RAISE EXCEPTION 'partner_shift_log_for_partner: a facility is required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT l.id, l.facility_id, l.created_at, l.kind, l.player_handle_snapshot, l.staff_handle
  FROM app.attestation_shift_log l
  WHERE l.facility_id = p_facility_id AND l.created_at > pg_catalog.now() - interval '90 days'
  ORDER BY l.created_at DESC, l.id
  LIMIT 200;
END
$$;

-- 3f. GET staff-activity (class A0: manager or operator of the facility; staff must NOT read it, plan line 843): counts and anomaly markers per staff member per day, never a player id or handle. The staff
-- member is returned as an id the portal maps through its own member list.
CREATE FUNCTION private.partner_staff_activity_for_partner(p_facility_id text, p_days integer)
RETURNS TABLE (o_staff_user_id uuid, o_facility_id text, o_day date, o_attests integer, o_activations integer, o_anomalies jsonb)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(p_facility_id, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A0');
  IF p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = '' OR p_days IS NULL OR p_days < 1 OR p_days > 90 THEN
    RAISE EXCEPTION 'partner_staff_activity_for_partner: a facility and a window of 1 to 90 days are required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT a.staff_user_id, a.facility_id, a.day, a.attests, a.activations, a.anomalies
  FROM app.staff_activity a
  WHERE a.facility_id = p_facility_id AND a.day > pg_catalog.now()::date - p_days
  ORDER BY a.day DESC, a.staff_user_id
  LIMIT 500;
END
$$;

-- 3g. EXECUTE grants (PUBLIC revoked first). The writer and the same-device helper: nobody but their owner. The four partner definers: edge_partner.
REVOKE EXECUTE ON FUNCTION private.partner_attest_write(uuid, text, uuid, text, text, text, boolean, boolean, timestamptz, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_attest_same_device(uuid, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_attest_for_partner(text, text, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_offline_attest_for_partner(text, text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_shift_log_for_partner(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_staff_activity_for_partner(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_attest_for_partner(text, text, uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_offline_attest_for_partner(text, text, text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_shift_log_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_staff_activity_for_partner(text, integer) TO edge_partner;
COMMENT ON FUNCTION private.partner_attest_write(uuid, text, uuid, text, text, text, boolean, boolean, timestamptz, timestamptz) IS
  '0056. The shared writer of the attest lane: attestation, attestation_shift_log, staff_activity, and for a marker purchase a staff_scan purchase_evidence + marker_credit per eligible trail (pending with cosignal.awaiting, or held_review on the same-device rule). Applies the cold-start cap. Reads no binding; EXECUTE for nobody but its owner.';
COMMENT ON FUNCTION private.partner_attest_same_device(uuid, uuid) IS
  '0056. The same-device rule (A2-21): a device of the staff member shares an install link, an App Attest key or a DeviceCheck token with the player''s device. Reads no binding; EXECUTE for nobody but its owner.';
COMMENT ON FUNCTION private.partner_attest_for_partner(text, text, uuid) IS
  '0056 (S3). edge_partner only; class A1 (staff or manager at the facility). The ONLINE attest: the player is the owner of the checkin_token jti (never named by the caller); self-attest is 22023; one attestation per token; the same-device rule holds the purchase. Statuses: ok | token_invalid | replayed | no_facility | no_programme | cold_start_cap.';
COMMENT ON FUNCTION private.partner_offline_attest_for_partner(text, text, text, text) IS
  '0056 (S3, X9, money doc step 3). edge_partner only; class A1. Verify-and-record of the offline code in the database: handle + six digits + facility in; a status, the attestation id and a held flag out; never a seed, an expected code or a device. Failure counters (5 per staff an hour, 10 per target an hour, 30 a day) commit. Supersedes private.offline_code_record_step_for_actor, which no edge role can call.';
COMMENT ON FUNCTION private.partner_shift_log_for_partner(text) IS
  '0056 (S3). edge_partner only; class A0 (staff or manager at the facility). The api.staff_shift_log rows of the facility (90 days, newest first, 200) and a subset of its columns.';
COMMENT ON FUNCTION private.partner_staff_activity_for_partner(text, integer) IS
  '0056 (S3). edge_partner only; class A0 (manager or operator at the facility; staff cannot). The api.staff_activity rows of the facility: counts and anomaly markers, never a player id or handle.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. X9, asserted: no edge role can record an offline code step without presenting the code the database checked.
-- ============================================================================
DO $assert_0056_x9$
BEGIN
  IF has_function_privilege('edge_actor', 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE')
     OR has_function_privilege('edge_system', 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE') THEN
    RAISE EXCEPTION '0056: an edge role can EXECUTE private.offline_code_record_step_for_actor (X9: only the verify-and-record definer records a step)';
  END IF;
END
$assert_0056_x9$;

-- ============================================================================
-- 5. Registries
-- ============================================================================
-- 5a. private.function_inventory
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_attest_for_partner', 'p_facility_id text, p_kind text, p_token uuid', false, false, false, false, false, true, false, '0056 (S3): edge_partner only; class A1; the online attest, the player derived from the checkin_token'),
  ('private', 'partner_attest_same_device', 'p_staff uuid, p_player_device uuid', false, false, false, false, false, false, false, '0056 (S3): the same-device rule; reads no binding; EXECUTE for nobody but the owner'),
  ('private', 'partner_attest_write', 'p_staff uuid, p_facility_id text, p_player uuid, p_kind text, p_jti text, p_ref text, p_offline boolean, p_held boolean, p_window_from timestamp with time zone, p_window_to timestamp with time zone', false, false, false, false, false, false, false, '0056 (S3): the shared writer (attestation, shift log, staff_activity, staff_scan purchase and credit); reads no binding; EXECUTE for nobody but the owner'),
  ('private', 'partner_bound_manager_at', 'p_facility_id text', false, false, false, false, false, false, false, '0056 (S3): policy predicate, a partner binding of a manager / operator at the facility; EXECUTE for nobody but the owner'),
  ('private', 'partner_bound_staff_any', '', false, false, false, false, false, false, false, '0056 (S3): policy predicate, a partner binding of a staff / manager anywhere; the partner twin of offline_code_bound_staff(); EXECUTE for nobody but the owner'),
  ('private', 'partner_bound_staff_at', 'p_facility_id text', false, false, false, false, false, false, false, '0056 (S3): policy predicate, a partner binding of a staff / manager at the facility; EXECUTE for nobody but the owner'),
  ('private', 'partner_offline_attest_for_partner', 'p_facility_id text, p_kind text, p_handle text, p_code text', false, false, false, false, false, true, false, '0056 (S3, X9): edge_partner only; class A1; verify-and-record of the offline code in the database'),
  ('private', 'partner_shift_log_for_partner', 'p_facility_id text', false, false, false, false, false, true, false, '0056 (S3): edge_partner only; class A0; the shift-log read'),
  ('private', 'partner_staff_activity_for_partner', 'p_facility_id text, p_days integer', false, false, false, false, false, true, false, '0056 (S3): edge_partner only; class A0 (manager / operator); the staff-activity read');

-- 5b. private.definer_policy_allowlist: every private_definer policy this file adds, expressions derived from the live policies (supabase/tests/fixtures/definer_policy_exprs.txt is the checked-in twin).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0056 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'attestation', 'pd_partner_attest_insert', 'INSERT', true, 'S3: an attestation by the BOUND partner member (staff_user_id = the binding), kind presence or marker_purchase, at a facility the member works at', 'private_definer'),
  ('app', 'attestation', 'pd_partner_attest_select', 'SELECT', true, 'S3: the bound member''s own attestations (the cold-start count and INSERT RETURNING)', 'private_definer'),
  ('private', 'consumed_nonce', 'pd_partner_attest_nonce_insert', 'INSERT', true, 'S3: the 0017 attestation tombstone trigger writes source attestation under a partner binding', 'private_definer'),
  ('private', 'consumed_nonce', 'pd_partner_attest_nonce_select', 'SELECT', true, 'S3: the tombstone read (replay check) under a partner binding, source attestation only', 'private_definer'),
  ('app', 'attestation_shift_log', 'pd_partner_shift_log_insert', 'INSERT', true, 'S3: a shift-log row at a facility the bound member is staff or manager of', 'private_definer'),
  ('app', 'attestation_shift_log', 'pd_partner_shift_log_select', 'SELECT', true, 'S3: the shift-log read of the old api.staff_shift_log: staff and managers of the facility', 'private_definer'),
  ('app', 'staff_activity', 'pd_partner_staff_activity_insert', 'INSERT', true, 'S3: the bound member''s own day row at a facility they work at', 'private_definer'),
  ('app', 'staff_activity', 'pd_partner_staff_activity_update', 'UPDATE', true, 'S3: increments of the bound member''s own day row (UPDATE (attests, anomalies) only)', 'private_definer'),
  ('app', 'staff_activity', 'pd_partner_staff_activity_select', 'SELECT', true, 'S3: the member''s own day rows, or every row of a facility the bound member manages or operates (the old api.staff_activity)', 'private_definer'),
  ('app', 'profile', 'pd_partner_attest_profile_select', 'SELECT', true, 'S3: handle lookup under a partner binding of a staff / manager anywhere; the definers filter by handle or user explicitly', 'private_definer'),
  ('app', 'checkin_token', 'pd_partner_attest_token_select', 'SELECT', true, 'S3: the online attest resolves a token jti under a partner binding of a staff / manager anywhere; the definer filters by jti', 'private_definer'),
  ('app', 'catalog_facility', 'pd_partner_attest_facility_read', 'SELECT', true, 'S3: the facility time zone the writer reads under a partner binding of a staff / manager anywhere (0046''s policy is keyed on the user binding)', 'private_definer'),
  ('app', 'trail_programme', 'pd_partner_attest_trail_programme_read', 'SELECT', true, 'S3: the trail programme state (status, marker_source) the writer reads for a marker purchase, under a partner binding', 'private_definer'),
  ('app', 'device', 'pd_partner_attest_device_select', 'SELECT', true, 'S3: the partner twin of pd_offline_code_device_select (0045); the verify-and-record definer reads the player''s 5 most recent devices and the same-device rule reads two; both filter explicitly', 'private_definer'),
  ('app', 'offline_code_step', 'pd_partner_offline_step_insert', 'INSERT', true, 'S3: the verify-and-record definer records one accepted step at a facility the bound member works at; the primary key is the replay refusal', 'private_definer'),
  ('app', 'offline_code_step', 'pd_partner_offline_step_select', 'SELECT', true, 'S3: INSERT ... ON CONFLICT needs the new step row visible; steps recorded at a facility the bound member works at', 'private_definer'),
  ('app', 'offline_code_step', 'pd_partner_offline_step_prune', 'DELETE', true, 'S3: prune of steps the database window can never accept again (data-derived, no GUC)', 'private_definer'),
  ('app', 'offline_code_step', 'pd_partner_offline_step_prune_r', 'SELECT', true, 'row-visibility companion to pd_partner_offline_step_prune', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_partner_attest_purchase_insert', 'INSERT', true, 'S3: a staff_scan purchase, pending or held_review, at a facility the bound member works at', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_partner_attest_purchase_select', 'SELECT', true, 'S3: INSERT RETURNING of the staff_scan purchase just written', 'private_definer'),
  ('app', 'marker_credit', 'pd_partner_attest_credit_insert', 'INSERT', true, 'S3: the pending or held_review credit of a staff_scan purchase', 'private_definer'),
  ('app', 'fraud_signal', 'pd_partner_attest_fraud_insert', 'INSERT', true, 'S3: the same_device_attest signal of the same-device rule', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_partner_attest_insert', 'pd_partner_attest_select', 'pd_partner_attest_nonce_insert', 'pd_partner_attest_nonce_select', 'pd_partner_shift_log_insert', 'pd_partner_shift_log_select',
    'pd_partner_staff_activity_insert', 'pd_partner_staff_activity_update', 'pd_partner_staff_activity_select', 'pd_partner_attest_profile_select', 'pd_partner_attest_token_select',
    'pd_partner_attest_device_select', 'pd_partner_offline_step_insert', 'pd_partner_offline_step_select', 'pd_partner_offline_step_prune', 'pd_partner_offline_step_prune_r', 'pd_partner_attest_purchase_insert',
    'pd_partner_attest_purchase_select', 'pd_partner_attest_credit_insert', 'pd_partner_attest_fraud_insert', 'pd_partner_attest_facility_read', 'pd_partner_attest_trail_programme_read');
DO $assert_0056_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN (
    'pd_partner_attest_insert', 'pd_partner_attest_select', 'pd_partner_attest_nonce_insert', 'pd_partner_attest_nonce_select', 'pd_partner_shift_log_insert', 'pd_partner_shift_log_select',
    'pd_partner_staff_activity_insert', 'pd_partner_staff_activity_update', 'pd_partner_staff_activity_select', 'pd_partner_attest_profile_select', 'pd_partner_attest_token_select',
    'pd_partner_attest_device_select', 'pd_partner_offline_step_insert', 'pd_partner_offline_step_select', 'pd_partner_offline_step_prune', 'pd_partner_offline_step_prune_r', 'pd_partner_attest_purchase_insert',
    'pd_partner_attest_purchase_select', 'pd_partner_attest_credit_insert', 'pd_partner_attest_fraud_insert', 'pd_partner_attest_facility_read', 'pd_partner_attest_trail_programme_read')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 22 THEN
    RAISE EXCEPTION '0056: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0056_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0056 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;
