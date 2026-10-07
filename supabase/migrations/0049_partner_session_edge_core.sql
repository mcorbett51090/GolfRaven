-- 0049_partner_session_edge_core.sql
--
-- P5.1a, slice S1.2: the DATABASE SIDE OF THE PARTNER (STAFF) EDGE CORE. docs/security/partner-auth-design.md (revision 5, the S0 gate ruling, 16.5 and 17.8 above all) is the specification: section 4.2 (the request
-- path), 4.4 (the minter), 4.5 (the routes of `partner-session`), 5.3 (the functions), 6.2 (sign-in), 8 (rate limits: "5 failed verifications per credential per hour, then a cooldown", the ONLY bound on failed
-- verifications), 12.1 (PA-10 .. PA-13b, PA-27) and 17.8 (the seams 0048 left for this file, followed exactly). Migrations 0001-0048 are untouched; everything below is CREATE.
--
-- WHAT THIS ADDS
--   1. THE SIGN-IN FAILURE COUNTER (section 8). app.partner_sign_in_failure, one row per credential (no user id, no foreign key: the alarm-table shape of 0048), written by private.partner_sign_in_failure_record
--      (partner_session_issuer, EXECUTE for edge_partner_minter only). Five failed verifications of one credential inside an hour start a 15-minute cooldown; during the cooldown private.partner_credential_lookup
--      answers `cooldown` and nothing is counted (so the cooldown cannot be stretched). Every answer is a STATUS, never a RAISE: the refusal's transaction COMMITS and the counter with it (the 0020 lesson, 17.8).
--   2. THE MINT LANE'S OTHER THREE DEFINERS (all partner_session_issuer, all EXECUTE for edge_partner_minter): private.partner_rp_config_read() (the relying party the Edge builds the WebAuthn options and the
--      wrapper's checks from), private.partner_credential_lookup(credential_id) (the key, the counter and the user the wrapper verifies against; one uniform `unknown` for an unknown or revoked credential) and
--      private.partner_sign_in_failure_record(credential_id).
--   3. THE PARTNER LANE'S FIRST DEFINERS (the `_for_partner` family, EXECUTE for edge_partner only; each begins with private.partner_authorize, check 14):
--        partner_whoami_for_partner()                  GET session. Class PEEK: no scope, no aal gate, and it NEVER advances last_seen_at (4.2).
--        partner_session_revoke_for_partner()          sign-out. Class SESSION.
--        partner_session_lock_for_partner()            lock: clears every step-up grant NOW (4.5): the PIN grant, the reauth window, the OTP proof. Class SESSION. (mfa_until is S1.4's: nothing sets it yet.)
--        partner_session_reauth_options_for_partner()  the reauth challenge ISSUER: it takes the session from partner_binding_session(), never from an argument (17.8). Class A0.
--        partner_session_reauth_credential_for_partner(credential_id)   the key the Edge verifies the reauth assertion against, ONLY for a credential of the SESSION'S OWN user (PA-27). Class A0.
--        partner_session_reauth_for_partner(...)       the reauth verification and the write of reauth_until. Class A0.
--      and private.hit_partner_rate_limit(key, window, max), the hit_actor_rate_limit twin keyed on the partner binding's user (5.3).
--   4. REAUTH, as R5-L1 specifies it: reauth_until is a column only partner_reauth_verifier can write, and the definer that writes it is OWNED by that role and performs the verification itself
--      (private.partner_reauth_apply: it calls private.partner_reauth_check and updates only on `ok`), so a definer that skips the verification cannot write the column. partner_reauth_check is owned by
--      partner_session_issuer (it already holds every privilege the checks need: the credential, the relying party, the used-nonce table, the SQL verifier) and is executable by partner_reauth_verifier only.
--      private.partner_reauth_clear() (also partner_reauth_verifier) is what lock calls to empty the window. The reauth challenge is bound (HMAC purpose 3) to the SESSION id, so a challenge for one session
--      cannot be used for another, and the credential must belong to that session's user (PA-27).
--
-- WHAT THIS DOES NOT BUILD (the seams stay intact): PIN (S1.3), TOTP and mfa_until clearing in lock (S1.4), register_first, the register challenge issuer, invites, enrolment, members, session eviction, the
-- purge definers (S1.5), alert-only IP and global buckets (no sink exists beyond partner_auth_alarm, whose kinds 0048 fixed; see the design doc, 18.5).

-- ============================================================================
-- 1. The owner roles this file writes functions for: the migrating role holds SET on them for the length of this file only (the 0047 / 0048 bracket, R5-L3)
-- ============================================================================
GRANT partner_session_issuer, partner_reauth_verifier TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;

-- ============================================================================
-- 2. app.partner_sign_in_failure: the per-credential failure counter of section 8
-- ============================================================================
CREATE TABLE app.partner_sign_in_failure (
  -- the credential's row id. NO foreign key and NO user id (the alarm table of 0048 is the precedent): a counter is not a personal table. Rows exist only for credentials that exist (the writer looks the
  -- credential up first), so the table is bounded by the number of credentials and an attacker who presents unknown ids creates nothing.
  credential_id uuid PRIMARY KEY,
  -- the start of the current counting window: failures older than an hour are forgotten
  window_start timestamptz NOT NULL,
  -- failures inside the window; reset to 0 when the 5th starts the cooldown
  failed_count smallint NOT NULL DEFAULT 0 CHECK (failed_count BETWEEN 0 AND 4),
  -- while in the future, every verification of this credential is refused without being looked at and without being counted
  cooldown_until timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE app.partner_sign_in_failure IS
  '0049 (design 8). The per-credential counter of FAILED sign-in verifications: 5 inside an hour start a 15 minute cooldown (a status, never a RAISE, so it commits with the refusal). One row per existing credential; no user id, no foreign key. Written only by private.partner_sign_in_failure_record, read by private.partner_credential_lookup, both owned by partner_session_issuer; no client role, no edge role and not service_role has any privilege on it. Retention is a purge step (follow-up, as app.partner_auth_alarm).';
ALTER TABLE app.partner_sign_in_failure ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_sign_in_failure FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.partner_sign_in_failure FROM PUBLIC, anon, authenticated, service_role;

-- ============================================================================
-- 3. Grants and policies the new definers rely on
-- ============================================================================
-- 3a. partner_session_issuer (the owner of the minter lane's definers): the failure table, whole-table (it is the table's only reader and writer), behind three registered `psi_*` policies keyed on nothing
-- settable (USING (true)); the role is a member of nothing and nobody can become it (checks 9 and 12). Everything else the new issuer-owned definers touch it already holds (0047, 0048).
GRANT SELECT, INSERT, UPDATE ON app.partner_sign_in_failure TO partner_session_issuer;
CREATE POLICY psi_read_partner_sign_in_failure ON app.partner_sign_in_failure FOR SELECT TO partner_session_issuer USING (true);
CREATE POLICY psi_insert_partner_sign_in_failure ON app.partner_sign_in_failure FOR INSERT TO partner_session_issuer WITH CHECK (true);
CREATE POLICY psi_update_partner_sign_in_failure ON app.partner_sign_in_failure FOR UPDATE TO partner_session_issuer USING (true) WITH CHECK (true);

-- ============================================================================
-- 4. The issuer-owned definers (the minter lane's three, and the two reauth helpers)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_session_issuer;
SET ROLE partner_session_issuer;

-- 4a. The relying party (RP ID and exact origin) the Edge builds the options and the wrapper's checks from. A missing row is a deploy fault (55000), not a client refusal.
CREATE FUNCTION private.partner_rp_config_read()
RETURNS TABLE (o_rp_id text, o_origin text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RETURN QUERY SELECT r.rp_id, r.origin FROM app.partner_rp_config r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_rp_config_read: app.partner_rp_config holds no relying party (a deploy step)' USING ERRCODE = '55000';
  END IF;
END
$$;

-- 4b. THE credential lookup of the sign-in path (4.4): the key, the counter and the user the Edge's wrapper verifies the assertion against, BEFORE the mint. Statuses: `ok` | `unknown` (an unknown credential and a
-- revoked one are ONE answer) | `cooldown` (the credential has failed five verifications in the last hour: nothing is returned and nothing is looked at). Refused inside any bound transaction (a minter binds nothing).
CREATE FUNCTION private.partner_credential_lookup(p_credential_id bytea)
RETURNS TABLE (o_status text, o_credential_id uuid, o_user_id uuid, o_alg smallint, o_public_key bytea, o_sign_count bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_c record;
BEGIN
  IF p_credential_id IS NULL OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 16 AND 1023 THEN
    RAISE EXCEPTION 'partner_credential_lookup: a credential id of 16 to 1023 bytes is required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_credential_lookup: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  SELECT c.id, c.user_id, c.alg, c.public_key, c.sign_count INTO v_c FROM app.partner_credential c WHERE c.credential_id = p_credential_id AND c.revoked_at IS NULL;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM app.partner_sign_in_failure f WHERE f.credential_id = v_c.id AND f.cooldown_until > pg_catalog.clock_timestamp()) THEN
    RETURN QUERY SELECT 'cooldown'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'ok'::text, v_c.id, v_c.user_id, v_c.alg, v_c.public_key, v_c.sign_count;
END
$$;

-- 4c. THE failure counter (design 8): "5 failed verifications per credential per hour, then a 15 minute cooldown (a status, not a RAISE)". The Edge calls it when ITS verification of a presented assertion refused
-- (a wrong signature, origin, RP ID, challenge, user handle ...: the attacks); it does not call it for a refusal the database makes AFTER a valid signature (a replay, a counter regression, a limit): those are
-- not guesses. Statuses: `counted` | `cooldown` (this failure started the cooldown, or one is already running: a failure during the cooldown is not counted, so the cooldown is a fixed 15 minutes) |
-- `unknown` (an unknown or revoked credential: NOTHING is written, so a caller that presents ids it made up grows no table). The row lock serialises concurrent failures of one credential, so N parallel
-- failures count N (and the 5th starts the cooldown exactly once).
CREATE FUNCTION private.partner_sign_in_failure_record(p_credential_id bytea)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_id uuid;
  v_f record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_count integer;
BEGIN
  IF p_credential_id IS NULL OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 16 AND 1023 THEN
    RAISE EXCEPTION 'partner_sign_in_failure_record: a credential id of 16 to 1023 bytes is required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_sign_in_failure_record: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  SELECT c.id INTO v_id FROM app.partner_credential c WHERE c.credential_id = p_credential_id AND c.revoked_at IS NULL;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown'::text;
    RETURN;
  END IF;
  INSERT INTO app.partner_sign_in_failure (credential_id, window_start, failed_count, cooldown_until, updated_at)
  VALUES (v_id, v_now, 0, NULL, v_now)
  ON CONFLICT (credential_id) DO NOTHING;
  SELECT f.window_start, f.failed_count, f.cooldown_until INTO v_f FROM app.partner_sign_in_failure f WHERE f.credential_id = v_id FOR UPDATE;
  IF v_f.cooldown_until IS NOT NULL AND v_f.cooldown_until > v_now THEN
    RETURN QUERY SELECT 'cooldown'::text;
    RETURN;
  END IF;
  IF v_f.window_start <= v_now - interval '1 hour' THEN
    v_count := 1;
  ELSE
    v_count := v_f.failed_count + 1;
  END IF;
  IF v_count >= 5 THEN
    UPDATE app.partner_sign_in_failure f SET window_start = v_now, failed_count = 0, cooldown_until = v_now + interval '15 minutes', updated_at = v_now WHERE f.credential_id = v_id;
    RETURN QUERY SELECT 'cooldown'::text;
    RETURN;
  END IF;
  UPDATE app.partner_sign_in_failure f
  SET window_start = CASE WHEN v_f.window_start <= v_now - interval '1 hour' THEN v_now ELSE v_f.window_start END, failed_count = v_count, cooldown_until = NULL, updated_at = v_now
  WHERE f.credential_id = v_id;
  RETURN QUERY SELECT 'counted'::text;
END
$$;

-- 4d. The credential the Edge verifies a REAUTH assertion against: ONLY a live credential of the SESSION'S OWN user (PA-27: a coworker's own passkey is not this session's, so it is not found), with the
-- relying party it is checked against. Zero rows for anything else. EXECUTE for private_definer only (the partner_session_reauth_credential_for_partner wrapper calls it, after partner_authorize).
CREATE FUNCTION private.partner_reauth_credential_read(p_session_id uuid, p_credential_id bytea)
RETURNS TABLE (o_credential_id uuid, o_user_id uuid, o_alg smallint, o_public_key bytea, o_sign_count bigint, o_rp_id text, o_origin text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_rp record;
BEGIN
  IF p_session_id IS NULL OR p_credential_id IS NULL OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 16 AND 1023 THEN
    RAISE EXCEPTION 'partner_reauth_credential_read: a session id and a credential id of 16 to 1023 bytes are required' USING ERRCODE = '22023';
  END IF;
  SELECT r.rp_id, r.origin INTO v_rp FROM app.partner_rp_config r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_reauth_credential_read: app.partner_rp_config holds no relying party (a deploy step)' USING ERRCODE = '55000';
  END IF;
  RETURN QUERY
  SELECT c.id, c.user_id, c.alg, c.public_key, c.sign_count, v_rp.rp_id, v_rp.origin
  FROM app.partner_session s JOIN app.partner_credential c ON c.user_id = s.user_id
  WHERE s.id = p_session_id AND s.revoked_at IS NULL AND c.credential_id = p_credential_id AND c.revoked_at IS NULL;
END
$$;

-- 4e. THE reauth check: the mint's steps, for purpose 3, bound to a SESSION and to that session's USER. Same order and the same statuses as partner_session_mint (0048) wherever the step is the same:
--   (1) the HMAC (purpose 3, binding = the session id: a challenge for another session fails it) and the expiry;
--   (2) the session's user, from the session row (a live session);
--   (3) the credential: THIS user's, live. Someone else's credential, an unknown one and a revoked one are one answer, `unknown_credential` (PA-27);
--   (4) the structural checks against partner_rp_config (type webauthn.get, no crossOrigin / topOrigin, the exact origin, the challenge; rpIdHash, UP, UV);
--   (5) the SQL signature check, LAST of the checks;
--   (6) the used nonce (the primary key is the single use);
--   (7) the counter by compare-and-set (a regression is a status).
-- Every refusal is a STATUS (so the caller's transaction commits the nonce and the counter): `bad_challenge | expired | unknown_session | unknown_credential | bad_client_data | bad_client_type |
-- cross_origin | bad_origin | challenge_mismatch | bad_authenticator_data | bad_rp_id_hash | user_not_present | user_not_verified | signature_invalid | replayed | counter_regression | ok`. Only malformed
-- arguments (22023) and a missing relying party (55000) raise, and neither has written anything. It writes NO audit row and NO alarm: the caller is partner-bound and app.partner_auth_alarm admits no binding
-- (0048), so the caller (partner_session_reauth_for_partner) writes the audit row for the two alarm-worthy statuses. EXECUTE for partner_reauth_verifier only.
CREATE FUNCTION private.partner_reauth_check(
  p_session_id uuid, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea,
  p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user uuid;
  v_cred record;
  v_rp record;
  v_cd jsonb;
  v_counter bigint;
  v_n integer;
BEGIN
  IF p_session_id IS NULL OR p_credential_id IS NULL OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 16 AND 1023
     OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_exp IS NULL OR p_mac IS NULL OR pg_catalog.octet_length(p_mac) > 128
     OR p_authenticator_data IS NULL OR p_client_data_json IS NULL OR p_signature IS NULL THEN
    RAISE EXCEPTION 'partner_reauth_check: a session, a credential id, a 32-byte nonce, an expiry, a MAC, the authenticator data, the client data and a signature are required' USING ERRCODE = '22023';
  END IF;

  -- 1. the HMAC (purpose reauth = 3, bound to THIS session) and the expiry
  IF NOT private.partner_challenge_verify(3::smallint, p_exp, p_nonce, p_session_id, p_mac) THEN
    RETURN QUERY SELECT 'bad_challenge'::text;
    RETURN;
  END IF;
  IF p_exp <= pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint THEN
    RETURN QUERY SELECT 'expired'::text;
    RETURN;
  END IF;

  -- 2. the session's user
  SELECT s.user_id INTO v_user FROM app.partner_session s WHERE s.id = p_session_id AND s.revoked_at IS NULL;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown_session'::text;
    RETURN;
  END IF;

  -- 3. the credential, FROM THE TABLE, and only a live one of THIS user (PA-27). The row lock serialises two assertions of one credential (the counter's compare-and-set below).
  SELECT c.id, c.public_key, c.alg INTO v_cred
  FROM app.partner_credential c WHERE c.credential_id = p_credential_id AND c.user_id = v_user AND c.revoked_at IS NULL FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown_credential'::text;
    RETURN;
  END IF;

  -- 4. structural checks, against the relying party configured at deploy (the same checks, in the same order, as the mint)
  SELECT r.rp_id, r.origin INTO v_rp FROM app.partner_rp_config r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_reauth_check: app.partner_rp_config holds no relying party (a deploy step)' USING ERRCODE = '55000';
  END IF;
  IF pg_catalog.octet_length(p_client_data_json) NOT BETWEEN 2 AND 4096 THEN
    RETURN QUERY SELECT 'bad_client_data'::text;
    RETURN;
  END IF;
  BEGIN
    v_cd := pg_catalog.convert_from(p_client_data_json, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    v_cd := NULL;
  END;
  IF v_cd IS NULL OR pg_catalog.jsonb_typeof(v_cd) <> 'object' THEN
    RETURN QUERY SELECT 'bad_client_data'::text;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'type') IS DISTINCT FROM 'string' OR (v_cd ->> 'type') <> 'webauthn.get' THEN
    RETURN QUERY SELECT 'bad_client_type'::text;
    RETURN;
  END IF;
  IF (v_cd ? 'crossOrigin' AND (v_cd -> 'crossOrigin') <> 'false'::jsonb) OR v_cd ? 'topOrigin' THEN
    RETURN QUERY SELECT 'cross_origin'::text;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'origin') IS DISTINCT FROM 'string' OR (v_cd ->> 'origin') <> v_rp.origin THEN
    RETURN QUERY SELECT 'bad_origin'::text;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'challenge') IS DISTINCT FROM 'string'
     OR (v_cd ->> 'challenge') <> pg_catalog.rtrim(pg_catalog.translate(pg_catalog.encode(p_nonce, 'base64'), '+/', '-_'), '=') THEN
    RETURN QUERY SELECT 'challenge_mismatch'::text;
    RETURN;
  END IF;
  IF pg_catalog.octet_length(p_authenticator_data) NOT BETWEEN 37 AND 4096 THEN
    RETURN QUERY SELECT 'bad_authenticator_data'::text;
    RETURN;
  END IF;
  IF pg_catalog.substring(p_authenticator_data, 1, 32) <> pg_catalog.sha256(pg_catalog.convert_to(v_rp.rp_id, 'UTF8')) THEN
    RETURN QUERY SELECT 'bad_rp_id_hash'::text;
    RETURN;
  END IF;
  IF pg_catalog.get_byte(p_authenticator_data, 32) & 1 = 0 THEN
    RETURN QUERY SELECT 'user_not_present'::text;
    RETURN;
  END IF;
  IF pg_catalog.get_byte(p_authenticator_data, 32) & 4 = 0 THEN
    RETURN QUERY SELECT 'user_not_verified'::text;
    RETURN;
  END IF;
  v_counter := pg_catalog.get_byte(p_authenticator_data, 33)::bigint * 16777216 + pg_catalog.get_byte(p_authenticator_data, 34) * 65536
             + pg_catalog.get_byte(p_authenticator_data, 35) * 256 + pg_catalog.get_byte(p_authenticator_data, 36);

  -- 5. the signature, in SQL, LAST of the checks
  IF NOT private.partner_sig_verify(v_cred.alg, v_cred.public_key, p_authenticator_data || pg_catalog.sha256(p_client_data_json), p_signature) THEN
    RETURN QUERY SELECT 'signature_invalid'::text;
    RETURN;
  END IF;

  -- 6. the used nonce: the primary key is the single use
  INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id, session_id)
  VALUES (pg_catalog.sha256(p_nonce), 'reauth', v_user, p_session_id)
  ON CONFLICT (nonce_hash) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    RETURN QUERY SELECT 'replayed'::text;
    RETURN;
  END IF;

  -- 7. the counter, by compare-and-set (PA-9): a reauth assertion is an assertion like any other, so it advances the stored counter (or a later sign-in would see a counter the authenticator had already passed)
  UPDATE app.partner_credential c SET sign_count = v_counter, last_used_at = pg_catalog.clock_timestamp()
  WHERE c.id = v_cred.id AND c.revoked_at IS NULL AND (c.sign_count < v_counter OR (c.sign_count = 0 AND v_counter = 0));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    RETURN QUERY SELECT 'counter_regression'::text;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'ok'::text;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_session_issuer;

-- ============================================================================
-- 5. The reauth verifier's two definers (R5-L1: the ROLE that owns the column writer is the verification fact)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_reauth_verifier;
SET ROLE partner_reauth_verifier;

-- 5a. THE writer of reauth_until. It takes the session from the transaction's own binding (never an argument), runs the whole verification (partner_reauth_check) and sets reauth_until = now + 5 minutes
-- ONLY on `ok`. It is executable by private_definer only: partner_session_reauth_for_partner calls it, after partner_authorize. The UPDATE passes partner_session_guard (at most now + 5 minutes) and its own
-- bound-session policy (prv_update_partner_session).
CREATE FUNCTION private.partner_reauth_apply(
  p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea,
  p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)
RETURNS TABLE (o_status text, o_reauth_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_sid uuid := private.partner_binding_session();
  v_status text;
  v_until timestamptz;
BEGIN
  IF v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_reauth_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  SELECT c.o_status INTO v_status
  FROM private.partner_reauth_check(v_sid, p_credential_id, p_nonce, p_exp, p_mac, p_authenticator_data, p_client_data_json, p_signature) c;
  IF v_status IS DISTINCT FROM 'ok' THEN
    RETURN QUERY SELECT coalesce(v_status, 'refused')::text, NULL::timestamptz;
    RETURN;
  END IF;
  -- the role holds SELECT on (id, reauth_until) only, so the filter is the bound session's id; partner_authorize has already locked the row and refused a revoked one in this transaction
  UPDATE app.partner_session s SET reauth_until = pg_catalog.clock_timestamp() + interval '5 minutes'
  WHERE s.id = v_sid
  RETURNING s.reauth_until INTO v_until;
  IF v_until IS NULL THEN
    RETURN QUERY SELECT 'unknown_session'::text, NULL::timestamptz;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'ok'::text, v_until;
END
$$;

-- 5b. Empties the bound session's reauth window (lock). The column can be written only by this role, so this is also where the window is CLEARED. Clearing is always allowed by the guard.
CREATE FUNCTION private.partner_reauth_clear()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  UPDATE app.partner_session s SET reauth_until = NULL WHERE s.id = private.partner_binding_session() AND s.reauth_until IS NOT NULL;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_reauth_verifier;

-- ============================================================================
-- 6. The private_definer functions: the rate-limit twin and the `_for_partner` family (ownership bracket as 0045 / 0047)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 6a. hit_partner_rate_limit: the hit_actor_rate_limit body, keyed on the PARTNER binding's user (5.3). The bucket key is built here as `<uid>:<key>` (the format private.delete_my_data's purge matches), so
-- the Edge can reach neither another member's bucket nor a global one. Never raises over the cap (0020): the caller decides from the returned count. It reads the binding only to take the bound
-- partner user and REFUSE any other kind (it is on supabase/tests/fixtures/partner_kind_readers.txt). Not a `_for_partner` function: it authorises nothing, it counts.
CREATE FUNCTION private.hit_partner_rate_limit(p_bucket_key text, p_window interval, p_max int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  SELECT b.actor_uid INTO v_uid
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned() AND b.kind = 'partner';
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'hit_partner_rate_limit: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF p_bucket_key IS NULL OR p_bucket_key = '' OR length(p_bucket_key) > 128
     OR p_window IS NULL OR p_window < interval '1 second' OR p_window > interval '1 day'
     OR p_max IS NULL OR p_max < 1 OR p_max > 1000000 THEN
    RAISE EXCEPTION 'hit_partner_rate_limit: invalid bucket key, window or max' USING ERRCODE = '22023';
  END IF;
  RETURN private.hit_rate_limit(v_uid::text || ':' || p_bucket_key, p_window, p_max);
END
$$;

-- 6b. GET session (class PEEK: no scope, no aal gate, never advances last_seen_at). Everything is RE-READ now: the roles and scopes, the required assurance, the step-up state. A sponsor-only membership is not
-- reported (the binder refuses a member whose only active role is sponsor). Timestamps are the database's.
CREATE FUNCTION private.partner_whoami_for_partner()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
  v_s record;
  v_pol record;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, NULL, 'PEEK');
  v_sid := private.partner_binding_session();
  SELECT s.aal, s.created_at, s.last_seen_at, s.expires_at, s.pin_grant_until, s.reauth_until, s.mfa_until, s.otp_proof_until, s.enrolment_until INTO v_s
  FROM app.partner_session s WHERE s.id = v_sid;
  SELECT p.* INTO v_pol FROM private.partner_session_policy(v_uid) p;
  RETURN pg_catalog.jsonb_build_object(
    'userId', v_uid,
    'sessionId', v_sid,
    'aal', v_s.aal,
    'requiredAal', v_pol.required_aal,
    'createdAt', v_s.created_at,
    'lastSeenAt', v_s.last_seen_at,
    'idleExpiresAt', v_s.last_seen_at + v_pol.idle,
    'expiresAt', v_s.expires_at,
    'isAdmin', private.is_admin(v_uid),
    'stepUp', pg_catalog.jsonb_build_object(
      'pinGrantActive', coalesce(v_s.pin_grant_until > v_now, false),
      'reauthUntil', CASE WHEN v_s.reauth_until > v_now THEN v_s.reauth_until END,
      'mfaUntil', CASE WHEN v_s.mfa_until > v_now THEN v_s.mfa_until END,
      'otpProofUntil', CASE WHEN v_s.otp_proof_until > v_now THEN v_s.otp_proof_until END,
      'enrolmentUntil', CASE WHEN v_s.enrolment_until > v_now THEN v_s.enrolment_until END),
    'memberships', coalesce((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'orgId', m.org_id,
        'role', m.role,
        'facilityIds', coalesce((SELECT pg_catalog.jsonb_agg(sc.facility_id ORDER BY sc.facility_id) FROM app.partner_scope sc WHERE sc.org_id = m.org_id AND sc.facility_id IS NOT NULL), '[]'::jsonb),
        'trailIds', coalesce((SELECT pg_catalog.jsonb_agg(sc.trail_id ORDER BY sc.trail_id) FROM app.partner_scope sc WHERE sc.org_id = m.org_id AND sc.trail_id IS NOT NULL), '[]'::jsonb))
        ORDER BY m.org_id, m.role::text)
      FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL AND m.role <> 'sponsor'), '[]'::jsonb));
END
$$;

-- 6c. Sign-out (class SESSION: a live session, no scope, no aal gate: an aal 1 operator can still sign out, 4.1). Revokes the BOUND session only (the policy pd_partner_session_action is keyed on the binding).
CREATE FUNCTION private.partner_session_revoke_for_partner()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, NULL, 'SESSION');
  v_sid := private.partner_binding_session();
  UPDATE app.partner_session s SET revoked_at = pg_catalog.clock_timestamp(), revoke_reason = 'sign_out' WHERE s.id = v_sid AND s.revoked_at IS NULL;
END
$$;

-- 6d. Lock (class SESSION, 4.5): clears every step-up grant NOW. The session stays live (a locked till still reads); the next A1 / A2 action needs a fresh PIN grant, a fresh passkey assertion. Each grant is
-- cleared by the only code that may write its column: the PIN grant by private.partner_pin_grant_consume() (owned by partner_pin_verifier, S1.1a), the reauth window by private.partner_reauth_clear() (owned by
-- partner_reauth_verifier, here), the OTP proof by this role's own column grant (clearing is always allowed by the guard; the GoTrue session id stays, so one GoTrue session still proves one proof). mfa_until is
-- written by S1.4's TOTP definer and nothing sets it yet: S1.4 adds its clearer here.
CREATE FUNCTION private.partner_session_lock_for_partner()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, NULL, 'SESSION');
  v_sid := private.partner_binding_session();
  PERFORM private.partner_pin_grant_consume();
  PERFORM private.partner_reauth_clear();
  UPDATE app.partner_session s SET otp_proof_until = NULL WHERE s.id = v_sid AND s.otp_proof_until IS NOT NULL;
END
$$;

-- 6e. The reauth challenge ISSUER (4.4, 17.8): a `_for_partner` definer that takes the session from partner_binding_session(), so there is no binding argument to choose and a challenge can be issued only for
-- the caller's own session. Class A0 anywhere (a call that acts on no object: both facility and trail NULL, an explicit role list, never sponsor). Stateless (nothing is written): 32 random bytes, an expiry 120 s
-- ahead and the MAC (purpose 3, binding = the session id) from the one Vault reader. It also returns the relying party the options are built from.
CREATE FUNCTION private.partner_session_reauth_options_for_partner()
RETURNS TABLE (o_nonce bytea, o_exp bigint, o_mac bytea, o_rp_id text, o_origin text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  v_sid := private.partner_binding_session();
  o_nonce := public.gen_random_bytes(32);
  o_exp := pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint + 120;
  SELECT c.o_mac INTO o_mac FROM private.partner_challenge_core(3::smallint, o_exp, o_nonce, v_sid, NULL) c;
  SELECT r.o_rp_id, r.o_origin INTO o_rp_id, o_origin FROM private.partner_rp_config_read() r;
  RETURN NEXT;
END
$$;

-- 6f. The key the Edge verifies a reauth assertion against (PA-27): a live credential of THIS SESSION'S user, or zero rows. Class A0.
CREATE FUNCTION private.partner_session_reauth_credential_for_partner(p_credential_id bytea)
RETURNS TABLE (o_credential_id uuid, o_user_id uuid, o_alg smallint, o_public_key bytea, o_sign_count bigint, o_rp_id text, o_origin text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  RETURN QUERY SELECT r.* FROM private.partner_reauth_credential_read(private.partner_binding_session(), p_credential_id) r;
END
$$;

-- 6g. The reauth verification (class A0): the verifier-owned partner_reauth_apply does the whole check and writes reauth_until only on `ok`. The two alarm-worthy statuses (a signature the Edge passed and the
-- database refuses; a counter that did not advance) write an audit_log row (actor = the bound member) and RETURN the status: this function raises nothing over a refusal, so the nonce, the counter and the
-- audit row COMMIT with it. Bounded by the Edge's 10 reauth attempts per member per hour (design 8).
CREATE FUNCTION private.partner_session_reauth_for_partner(
  p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea,
  p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)
RETURNS TABLE (o_status text, o_reauth_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
  v_status text;
  v_until timestamptz;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  v_sid := private.partner_binding_session();
  SELECT a.o_status, a.o_reauth_until INTO v_status, v_until
  FROM private.partner_reauth_apply(p_credential_id, p_nonce, p_exp, p_mac, p_authenticator_data, p_client_data_json, p_signature) a;
  IF v_status IN ('signature_invalid', 'counter_regression') THEN
    PERFORM private.partner_audit_write('partner.reauth.' || v_status, 'app.partner_session', v_sid::text, pg_catalog.jsonb_build_object('stage', 'reauth'));
  END IF;
  RETURN QUERY SELECT v_status, v_until;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 7. EXECUTE grants (PUBLIC revoked first: a function created by a role other than the migrating role defaults to PUBLIC EXECUTE). Each as its OWNER.
-- ============================================================================
SET ROLE partner_session_issuer;
REVOKE EXECUTE ON FUNCTION
  private.partner_rp_config_read(),
  private.partner_credential_lookup(bytea),
  private.partner_sign_in_failure_record(bytea),
  private.partner_reauth_credential_read(uuid, bytea),
  private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)
FROM PUBLIC;
-- the minter lane: edge_partner_minter, and nobody else (the relying party is also read by the reauth wrapper, which runs as private_definer)
GRANT EXECUTE ON FUNCTION private.partner_rp_config_read() TO edge_partner_minter, private_definer;
GRANT EXECUTE ON FUNCTION private.partner_credential_lookup(bytea) TO edge_partner_minter;
GRANT EXECUTE ON FUNCTION private.partner_sign_in_failure_record(bytea) TO edge_partner_minter;
-- the reauth helpers: only the code that calls them
GRANT EXECUTE ON FUNCTION private.partner_reauth_credential_read(uuid, bytea) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea) TO partner_reauth_verifier;
COMMENT ON FUNCTION private.partner_credential_lookup(bytea) IS
  '0049. edge_partner_minter only; owned by partner_session_issuer. The key, counter and user the Edge verifies a sign-in assertion against, before the mint. Statuses ok | unknown (unknown and revoked are one answer) | cooldown (five failed verifications in the last hour). Refused inside a bound transaction.';
COMMENT ON FUNCTION private.partner_sign_in_failure_record(bytea) IS
  '0049. edge_partner_minter only; owned by partner_session_issuer. Design 8: five failed verifications per credential per hour start a 15 minute cooldown. A status, never a RAISE: it commits with the refusal. Writes nothing for an unknown credential.';
RESET ROLE;

SET ROLE partner_reauth_verifier;
REVOKE EXECUTE ON FUNCTION
  private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea),
  private.partner_reauth_clear()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_reauth_clear() TO private_definer;
COMMENT ON FUNCTION private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea) IS
  '0049 (R5-L1). Owned by partner_reauth_verifier, the only role that can write app.partner_session.reauth_until. Takes the session from the transaction''s binding, runs the whole verification (partner_reauth_check) and sets reauth_until = now + 5 minutes only on ok. EXECUTE for private_definer only.';
RESET ROLE;

SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION
  private.hit_partner_rate_limit(text, interval, int),
  private.partner_whoami_for_partner(),
  private.partner_session_revoke_for_partner(),
  private.partner_session_lock_for_partner(),
  private.partner_session_reauth_options_for_partner(),
  private.partner_session_reauth_credential_for_partner(bytea),
  private.partner_session_reauth_for_partner(bytea, bytea, bigint, bytea, bytea, bytea, bytea)
FROM PUBLIC;
-- the partner lane: edge_partner, and nobody else (check 14 (d) and (e))
GRANT EXECUTE ON FUNCTION private.hit_partner_rate_limit(text, interval, int) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_whoami_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_session_revoke_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_session_lock_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_session_reauth_options_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_session_reauth_credential_for_partner(bytea) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_session_reauth_for_partner(bytea, bytea, bigint, bytea, bytea, bytea, bytea) TO edge_partner;
RESET ROLE;

-- R5-L3: the migrating role keeps NO way to become either owner (a PG16+ CREATEROLE creator keeps ADMIN on the roles it creates, which is all that may remain)
REVOKE partner_session_issuer, partner_reauth_verifier FROM CURRENT_USER;

-- ============================================================================
-- 8. Registries
-- ============================================================================
-- 8a. private.function_inventory: every function above. expected_edge_partner true for the seven edge_partner functions, expected_edge_partner_minter true for the three minter-lane definers.
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_rp_config_read', '', false, false, false, false, false, false, true, '0049: owned by partner_session_issuer; the relying party (RP ID, exact origin) the Edge builds the WebAuthn options and the wrapper''s checks from; 55000 when the deploy step has not written the row; EXECUTE for edge_partner_minter and private_definer (the reauth wrappers)'),
  ('private', 'partner_credential_lookup', 'p_credential_id bytea', false, false, false, false, false, false, true, '0049: edge_partner_minter only; owned by partner_session_issuer; the key, counter and user a sign-in assertion is verified against before the mint; ok | unknown (unknown and revoked are one answer) | cooldown; refuses inside a bound transaction'),
  ('private', 'partner_sign_in_failure_record', 'p_credential_id bytea', false, false, false, false, false, false, true, '0049: edge_partner_minter only; owned by partner_session_issuer; design 8: five failed verifications per credential per hour start a 15 minute cooldown; a status, never a RAISE (it commits with the refusal); writes nothing for an unknown credential'),
  ('private', 'partner_reauth_credential_read', 'p_session_id uuid, p_credential_id bytea', false, false, false, false, false, false, false, '0049: owned by partner_session_issuer; a live credential of the SESSION''S OWN user (PA-27) and the relying party, or zero rows; EXECUTE for private_definer only (the reauth credential wrapper calls it after partner_authorize)'),
  ('private', 'partner_reauth_check', 'p_session_id uuid, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea', false, false, false, false, false, false, false, '0049: owned by partner_session_issuer; the reauth verification (HMAC purpose 3 bound to the session, the session''s own credential, the structural checks, the SQL signature, the used nonce, the counter); a status for every refusal; EXECUTE for partner_reauth_verifier only (partner_reauth_apply calls it)'),
  ('private', 'partner_reauth_apply', 'p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea', false, false, false, false, false, false, false, '0049 (R5-L1): owned by partner_reauth_verifier, the only role that can write partner_session.reauth_until; takes the session from the binding, runs partner_reauth_check and sets reauth_until = now + 5 minutes only on ok; EXECUTE for private_definer only'),
  ('private', 'partner_reauth_clear', '', false, false, false, false, false, false, false, '0049: owned by partner_reauth_verifier; empties the bound session''s reauth window (lock); EXECUTE for private_definer only'),
  ('private', 'hit_partner_rate_limit', 'p_bucket_key text, p_window interval, p_max integer', false, false, false, false, false, true, false, '0049: edge_partner rate limit: the hit_actor_rate_limit body keyed on the partner binding''s user (bucket <uid>:<key>); never raises over the cap (0020); refuses any other binding kind'),
  ('private', 'partner_whoami_for_partner', '', false, false, false, false, false, true, false, '0049: edge_partner only; GET session: class PEEK (no scope, no aal gate, never advances last_seen_at); the roles, scopes, required assurance and step-up state, all re-read'),
  ('private', 'partner_session_revoke_for_partner', '', false, false, false, false, false, true, false, '0049: edge_partner only; sign-out: class SESSION; revokes the bound session only'),
  ('private', 'partner_session_lock_for_partner', '', false, false, false, false, false, true, false, '0049: edge_partner only; lock: class SESSION; clears the PIN grant, the reauth window and the OTP proof of the bound session now'),
  ('private', 'partner_session_reauth_options_for_partner', '', false, false, false, false, false, true, false, '0049: edge_partner only; the reauth challenge issuer: class A0; the session comes from partner_binding_session(), never an argument; stateless; HMAC purpose 3 bound to the session; returns the relying party'),
  ('private', 'partner_session_reauth_credential_for_partner', 'p_credential_id bytea', false, false, false, false, false, true, false, '0049: edge_partner only; class A0; the key the Edge verifies a reauth assertion against: a live credential of the SESSION''S user, or zero rows (PA-27)'),
  ('private', 'partner_session_reauth_for_partner', 'p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea', false, false, false, false, false, true, false, '0049: edge_partner only; class A0; the reauth verification through partner_reauth_apply; a status for every refusal (it commits); an audit_log row for signature_invalid and counter_regression');

-- 8b. private.definer_policy_allowlist: the three new issuer policies, their expressions derived from the live policies (checks 5 / 6 compare the two, and the checked-in fixture is the third copy)
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0049 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_sign_in_failure', 'psi_read_partner_sign_in_failure', 'SELECT', true, 'S1.2 partner_credential_lookup / partner_sign_in_failure_record: the per-credential failure counter (design 8); the role is a member of nothing and nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_sign_in_failure', 'psi_insert_partner_sign_in_failure', 'INSERT', false, 'S1.2 partner_sign_in_failure_record: the one row per EXISTING credential (the writer looks the credential up first); no user id; nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_sign_in_failure', 'psi_update_partner_sign_in_failure', 'UPDATE', true, 'S1.2 partner_sign_in_failure_record: count, window and cooldown of an existing row under FOR UPDATE; nobody can become partner_session_issuer', 'partner_session_issuer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND pol.polname IN ('psi_read_partner_sign_in_failure', 'psi_insert_partner_sign_in_failure', 'psi_update_partner_sign_in_failure');
DO $assert_0049_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN ('psi_read_partner_sign_in_failure', 'psi_insert_partner_sign_in_failure', 'psi_update_partner_sign_in_failure')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 3 THEN
    RAISE EXCEPTION '0049: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0049_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0049 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 8c. private.partner_owner_privilege: what the two owners hold now, beyond 0047 / 0048 (checks 9 / 12 re-derive the real set from the catalog and compare both ways; the fixture is its checked-in twin)
CREATE POLICY current_user_seed_partner_owner_privilege_0049 ON private.partner_owner_privilege
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.partner_owner_privilege (role_name, object_kind, object_name, privilege, column_name) VALUES
  ('partner_session_issuer', 'relation', 'app.partner_sign_in_failure', 'SELECT', NULL),
  ('partner_session_issuer', 'relation', 'app.partner_sign_in_failure', 'INSERT', NULL),
  ('partner_session_issuer', 'relation', 'app.partner_sign_in_failure', 'UPDATE', NULL),
  ('partner_reauth_verifier', 'function', 'private.partner_reauth_check(uuid,bytea,bytea,bigint,bytea,bytea,bytea,bytea)', 'EXECUTE', NULL);
DROP POLICY current_user_seed_partner_owner_privilege_0049 ON private.partner_owner_privilege;

-- ============================================================================
-- 9. Prove the grants (a refused or misapplied GRANT only warns, so the migration fails HERE rather than on the first request)
-- ============================================================================
DO $assert_0049_grants$
DECLARE
  v_role text;
  v_fn regprocedure;
  v_bad text;
  v_minter regprocedure[] := ARRAY[
    'private.partner_rp_config_read()'::regprocedure,
    'private.partner_credential_lookup(bytea)'::regprocedure,
    'private.partner_sign_in_failure_record(bytea)'::regprocedure];
  v_lane regprocedure[] := ARRAY[
    'private.hit_partner_rate_limit(text, interval, int)'::regprocedure,
    'private.partner_whoami_for_partner()'::regprocedure,
    'private.partner_session_revoke_for_partner()'::regprocedure,
    'private.partner_session_lock_for_partner()'::regprocedure,
    'private.partner_session_reauth_options_for_partner()'::regprocedure,
    'private.partner_session_reauth_credential_for_partner(bytea)'::regprocedure,
    'private.partner_session_reauth_for_partner(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure];
  v_helpers regprocedure[] := ARRAY[
    'private.partner_reauth_credential_read(uuid, bytea)'::regprocedure,
    'private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure,
    'private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure,
    'private.partner_reauth_clear()'::regprocedure];
BEGIN
  -- the owners, SECURITY DEFINER, search_path empty
  IF EXISTS (SELECT 1 FROM unnest(v_minter || v_lane || v_helpers) f(oid) JOIN pg_proc p ON p.oid = f.oid WHERE NOT p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=""']) THEN
    RAISE EXCEPTION '0049: a new function is not SECURITY DEFINER with search_path=''''';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(ARRAY['private.partner_rp_config_read()', 'private.partner_credential_lookup(bytea)', 'private.partner_sign_in_failure_record(bytea)',
                                        'private.partner_reauth_credential_read(uuid, bytea)', 'private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'partner_session_issuer'::regrole) THEN
    RAISE EXCEPTION '0049: an issuer-owned function is not owned by partner_session_issuer';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(ARRAY['private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea)', 'private.partner_reauth_clear()']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'partner_reauth_verifier'::regrole) THEN
    RAISE EXCEPTION '0049: a verifier-owned function is not owned by partner_reauth_verifier';
  END IF;
  -- the minter lane: edge_partner_minter, and no other client or edge role
  FOREACH v_fn IN ARRAY v_minter LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0049: % can execute %; only edge_partner_minter may', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_partner_minter', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0049: edge_partner_minter cannot execute %', v_fn;
    END IF;
  END LOOP;
  -- the partner lane: edge_partner, and no other client or edge role (and not the minter)
  FOREACH v_fn IN ARRAY v_lane LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0049: % can execute %; only edge_partner may', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_partner', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0049: edge_partner cannot execute %', v_fn;
    END IF;
  END LOOP;
  -- the helpers: no edge or client role at all
  FOREACH v_fn IN ARRAY v_helpers LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0049: % can execute the helper %', v_role, v_fn;
      END IF;
    END LOOP;
  END LOOP;
  -- the internal callers: the reauth wrappers (private_definer) and the verifier
  IF NOT (has_function_privilege('private_definer', 'private.partner_rp_config_read()'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_reauth_credential_read(uuid, bytea)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_reauth_apply(bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_reauth_clear()'::regprocedure, 'EXECUTE')
          AND has_function_privilege('partner_reauth_verifier', 'private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'EXECUTE')) THEN
    RAISE EXCEPTION '0049: an internal EXECUTE grant did not take effect';
  END IF;
  IF has_function_privilege('private_definer', 'private.partner_reauth_check(uuid, bytea, bytea, bigint, bytea, bytea, bytea, bytea)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0049: private_definer can execute partner_reauth_check: only partner_reauth_verifier may (a definer that skips the verification must not reach it)';
  END IF;
  -- the minter still holds no privilege on any relation
  SELECT string_agg(c.relname, ', ') INTO v_bad FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND (has_any_column_privilege('edge_partner_minter', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_partner_minter', c.oid, 'DELETE,TRUNCATE,TRIGGER'));
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0049: edge_partner_minter holds a relation privilege: %', v_bad;
  END IF;
  -- the new table: nothing for any client or edge role
  FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated', 'service_role', 'edge_actor', 'edge_system', 'edge_partner', 'edge_partner_minter', 'edge_gateway'] LOOP
    IF has_any_column_privilege(v_role, 'app.partner_sign_in_failure', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(v_role, 'app.partner_sign_in_failure', 'DELETE,TRUNCATE,TRIGGER') THEN
      RAISE EXCEPTION '0049: % holds a privilege on app.partner_sign_in_failure', v_role;
    END IF;
  END LOOP;
  IF NOT (has_table_privilege('partner_session_issuer', 'app.partner_sign_in_failure', 'SELECT') AND has_table_privilege('partner_session_issuer', 'app.partner_sign_in_failure', 'INSERT')
          AND has_table_privilege('partner_session_issuer', 'app.partner_sign_in_failure', 'UPDATE')) THEN
    RAISE EXCEPTION '0049: a grant the failure counter needs did not take effect';
  END IF;
END
$assert_0049_grants$;
