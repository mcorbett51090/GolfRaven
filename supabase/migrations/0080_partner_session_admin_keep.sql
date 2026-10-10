-- 0080_partner_session_admin_keep.sql
--
-- P5 §66: close the §4.1 / §64.2 / §65.3 leftover — Admin concurrent
-- sessions = 2 (staff / manager / operator stay 3). Extends
-- private.partner_session_policy with concurrent; mint and
-- register_first both evict with v_pol.concurrent.
--
-- WHAT THIS CHANGES
--   1. DROP + CREATE private.partner_session_policy (adds concurrent)
--   2. CREATE OR REPLACE partner_session_mint (keep = v_pol.concurrent)
--   3. CREATE OR REPLACE partner_credential_register_first (same)
--   4. Inventory notes
--
-- DELIBERATELY NOT HERE: IP/global alert-only rate buckets,
-- pepper-rotation, OCR / aHash / UI flag flips / CAMERA, partners
-- credential settings UI.
-- Nothing from 0001–0079 is edited.

-- ============================================================================
-- 1. partner_session_policy gains concurrent (4.1 table)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

DROP FUNCTION private.partner_session_policy(uuid);

CREATE FUNCTION private.partner_session_policy(p_uid uuid)
RETURNS TABLE (required_aal smallint, idle interval, absolute interval, concurrent integer)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT (CASE WHEN a.is_admin OR a.is_op THEN 2 ELSE 1 END)::smallint,
         CASE WHEN a.is_admin THEN interval '10 minutes' WHEN a.is_op THEN interval '15 minutes' ELSE interval '30 minutes' END,
         CASE WHEN a.is_admin THEN interval '1 hour' WHEN a.is_op THEN interval '4 hours' ELSE interval '8 hours' END,
         CASE WHEN a.is_admin THEN 2 ELSE 3 END
  FROM (
    SELECT private.is_admin(p_uid) AS is_admin,
           EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_uid AND m.revoked_at IS NULL AND m.role = 'operator') AS is_op
  ) a
$$;

REVOKE EXECUTE ON FUNCTION private.partner_session_policy(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_session_policy(uuid) TO partner_session_issuer;

COMMENT ON FUNCTION private.partner_session_policy(uuid) IS
  '0047/0080 (4.1). Required aal, idle, absolute ceiling, and concurrent live-session keep of a person (highest role wins: admin keep=2, others 3). EXECUTE for partner_session_issuer; bind_partner_session / partner_authorize (same owner) call it without a grant.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Mint: evict with role keep (issuer bracket)
-- ============================================================================
GRANT partner_session_issuer TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
GRANT CREATE ON SCHEMA private TO partner_session_issuer;
SET ROLE partner_session_issuer;

CREATE OR REPLACE FUNCTION private.partner_session_mint(
  p_token_hash text, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea,
  p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)
RETURNS TABLE (o_status text, o_session_id uuid, o_aal smallint, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_cred record;
  v_rp record;
  v_pol record;
  v_cd jsonb;
  v_sid uuid := gen_random_uuid();
  v_nonce_hash bytea;
  v_counter bigint;
  v_n integer;
  v_expires timestamptz;
  v_zero constant uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
  -- 0. malformed arguments raise (nothing has been written); a minter binds nothing (the 0041 rule)
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' OR p_credential_id IS NULL OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 16 AND 1023
     OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_exp IS NULL OR p_mac IS NULL OR pg_catalog.octet_length(p_mac) > 128
     OR p_authenticator_data IS NULL OR p_client_data_json IS NULL OR p_signature IS NULL THEN
    RAISE EXCEPTION 'partner_session_mint: a token hash, a credential id, a 32-byte nonce, an expiry, a MAC, the authenticator data, the client data and a signature are required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_session_mint: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;

  -- 1. the HMAC, the purpose (sign_in: the one purpose this function mints) and the expiry. A tampered MAC, a tampered expiry and a challenge of any other purpose all fail the HMAC.
  IF NOT private.partner_challenge_verify(1::smallint, p_exp, p_nonce, v_zero, p_mac) THEN
    RETURN QUERY SELECT 'bad_challenge'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF p_exp <= pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint THEN
    RETURN QUERY SELECT 'expired'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 2. the credential, FROM THE TABLE. Unknown and revoked are one answer.
  SELECT c.id, c.user_id, c.public_key, c.alg, c.sign_count INTO v_cred
  FROM app.partner_credential c WHERE c.credential_id = p_credential_id AND c.revoked_at IS NULL;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unknown_credential'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 3. S0-L5: at most 60 successful sign-ins per credential per hour, enforced BEFORE any verification (a refusal here costs the database nothing but this count)
  -- The count and the later insert must be one critical section PER CREDENTIAL, or N concurrent mints at 58 all read 58 and all succeed (the gate's M-1: 8 concurrent mints made 66). Taking the credential's row lock
  -- here serialises mints of one credential from this point on (the lock is held to the end of the transaction, past the session insert), so each count sees every earlier mint's session. FOR NO KEY UPDATE:
  -- the same lock the counter's compare-and-set takes, and it does not block the foreign-key checks of the session insert.
  PERFORM 1 FROM app.partner_credential c WHERE c.id = v_cred.id FOR NO KEY UPDATE;
  SELECT pg_catalog.count(*) INTO v_n FROM app.partner_session s
  WHERE s.credential_id = v_cred.id AND s.mint_kind = 'sign_in' AND s.created_at > pg_catalog.clock_timestamp() - interval '1 hour';
  IF v_n >= 60 THEN
    RETURN QUERY SELECT 'rate_limited'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 4. structural checks, against the relying party configured at deploy. No row = a deploy fault (the mint refuses).
  SELECT r.rp_id, r.origin INTO v_rp FROM app.partner_rp_config r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_session_mint: app.partner_rp_config holds no relying party (a deploy step)' USING ERRCODE = '55000';
  END IF;
  -- clientDataJSON: valid UTF-8 JSON, an object, type webauthn.get, no crossOrigin (absent or false) and no topOrigin, the exact origin, and the challenge the token carries
  IF pg_catalog.octet_length(p_client_data_json) NOT BETWEEN 2 AND 4096 THEN
    RETURN QUERY SELECT 'bad_client_data'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  BEGIN
    v_cd := pg_catalog.convert_from(p_client_data_json, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    v_cd := NULL;
  END;
  IF v_cd IS NULL OR pg_catalog.jsonb_typeof(v_cd) <> 'object' THEN
    RETURN QUERY SELECT 'bad_client_data'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'type') IS DISTINCT FROM 'string' OR (v_cd ->> 'type') <> 'webauthn.get' THEN
    RETURN QUERY SELECT 'bad_client_type'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF (v_cd ? 'crossOrigin' AND (v_cd -> 'crossOrigin') <> 'false'::jsonb) OR v_cd ? 'topOrigin' THEN
    RETURN QUERY SELECT 'cross_origin'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'origin') IS DISTINCT FROM 'string' OR (v_cd ->> 'origin') <> v_rp.origin THEN
    RETURN QUERY SELECT 'bad_origin'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'challenge') IS DISTINCT FROM 'string'
     OR (v_cd ->> 'challenge') <> pg_catalog.rtrim(pg_catalog.translate(pg_catalog.encode(p_nonce, 'base64'), '+/', '-_'), '=') THEN
    RETURN QUERY SELECT 'challenge_mismatch'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  -- authenticatorData: rpIdHash (32) | flags (1) | counter (4, big-endian) | ...; the hash of the configured RP ID, user presence (0x01) and user verification (0x04)
  IF pg_catalog.octet_length(p_authenticator_data) NOT BETWEEN 37 AND 4096 THEN
    RETURN QUERY SELECT 'bad_authenticator_data'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.substring(p_authenticator_data, 1, 32) <> pg_catalog.sha256(pg_catalog.convert_to(v_rp.rp_id, 'UTF8')) THEN
    RETURN QUERY SELECT 'bad_rp_id_hash'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.get_byte(p_authenticator_data, 32) & 1 = 0 THEN
    RETURN QUERY SELECT 'user_not_present'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  IF pg_catalog.get_byte(p_authenticator_data, 32) & 4 = 0 THEN
    RETURN QUERY SELECT 'user_not_verified'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;
  v_counter := pg_catalog.get_byte(p_authenticator_data, 33)::bigint * 16777216 + pg_catalog.get_byte(p_authenticator_data, 34) * 65536
             + pg_catalog.get_byte(p_authenticator_data, 35) * 256 + pg_catalog.get_byte(p_authenticator_data, 36);

  -- 5. the signature, in SQL, LAST of the checks. The Edge verified it first, so a failure here is an ALARM (a compromised runtime, a library gap, a corrupt stored key): a distinct status, and the audit_log and
  -- app.partner_auth_alarm rows commit with it. A failed verification does NOT burn the challenge (5.1): it may be presented again within its 120 s, and each try needs a real signature.
  IF NOT private.partner_sig_verify(v_cred.alg, v_cred.public_key, p_authenticator_data || pg_catalog.sha256(p_client_data_json), p_signature) THEN
    PERFORM private.partner_mint_alarm_write('signature_invalid', v_cred.id, pg_catalog.jsonb_build_object('stage', 'mint', 'alg', v_cred.alg));
    RETURN QUERY SELECT 'signature_invalid'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 6. the used nonce: the primary key is the single use. A concurrent mint of the SAME challenge waits here for the first to finish and then finds the row.
  v_nonce_hash := pg_catalog.sha256(p_nonce);
  INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id, minted_session_id)
  VALUES (v_nonce_hash, 'sign_in', v_cred.user_id, v_sid)
  ON CONFLICT (nonce_hash) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    RETURN QUERY SELECT 'replayed'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 7. the counter, by compare-and-set (PA-9): it advances only if the stored value is still below the presented one (or both are 0: a synced passkey never counts). Two assertions racing for one credential
  -- cannot both win and neither can lower it; the loser sees the winner's value (READ COMMITTED re-evaluates the WHERE after the row lock). A regression is the clone indicator of 6.2 step 4.
  UPDATE app.partner_credential c SET sign_count = v_counter, last_used_at = pg_catalog.clock_timestamp()
  WHERE c.id = v_cred.id AND c.revoked_at IS NULL AND (c.sign_count < v_counter OR (c.sign_count = 0 AND v_counter = 0));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    IF NOT EXISTS (SELECT 1 FROM app.partner_credential c WHERE c.id = v_cred.id AND c.revoked_at IS NULL) THEN
      RETURN QUERY SELECT 'unknown_credential'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
      RETURN;
    END IF;
    PERFORM private.partner_mint_alarm_write('counter_regression', v_cred.id, pg_catalog.jsonb_build_object('stage', 'mint', 'presented', v_counter));
    RETURN QUERY SELECT 'counter_regression'::text, NULL::uuid, NULL::smallint, NULL::timestamptz;
    RETURN;
  END IF;

  -- 8. the session, with the evidence of what was verified (mint_*). Born at aal 1 with nothing verified; its absolute life is the person's role ceiling (partner_session_insert_guard re-checks it).
  SELECT p.* INTO v_pol FROM private.partner_session_policy(v_cred.user_id) p;
  v_expires := pg_catalog.clock_timestamp() + v_pol.absolute;
  INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (v_sid, p_token_hash, v_cred.user_id, v_cred.id, 1, pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), v_expires,
          'sign_in', v_nonce_hash, p_authenticator_data, p_client_data_json, p_signature);
  -- 9. 4.1: keep at most concurrent live sessions of this person (admin 2 / others 3; REVOKE oldest beyond that; never DELETE — the 60/h count is from partner_session rows)
  PERFORM private.partner_sessions_evict_oldest(v_cred.user_id, v_pol.concurrent);
  RETURN QUERY SELECT 'ok'::text, v_sid, 1::smallint, v_expires;
END
$$;


COMMENT ON FUNCTION private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea) IS
  '0048/0078/0080. edge_partner_minter only; owned by partner_session_issuer. Mints a sign-in session from a WebAuthn assertion. Order: HMAC / purpose / expiry (the nonce is the challenge in clientDataJSON), the credential FROM app.partner_credential, at most 60 sign-ins per credential per hour (before any verification), the structural checks against app.partner_rp_config, the SQL signature check, the used nonce (primary key = single use), the counter compare-and-set, the session with its mint_* evidence, then eviction beyond the person''s concurrent keep from partner_session_policy (admin 2 / others 3; REVOKE, never DELETE). Returns a status row; never raises over a refusal. A signature that fails here and a counter regression write audit_log and app.partner_auth_alarm rows that commit with the refusal.';

CREATE OR REPLACE FUNCTION private.partner_credential_register_first(
  p_token_hash text, p_user_id uuid, p_ref_kind smallint, p_ref_id uuid,
  p_nonce bytea, p_exp bigint, p_mac bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[])
RETURNS TABLE (o_status text, o_credential_id uuid, o_session_id uuid, o_aal smallint, o_expires_at timestamptz, o_enrolment_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_acc timestamptz;
  v_reg uuid;
  v_org uuid;
  v_found boolean;
  v_us bigint;
  v_c record;
  v_pol record;
  v_sid uuid := gen_random_uuid();
  v_expires timestamptz;
  v_enrol timestamptz;
  v_n integer;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' OR p_user_id IS NULL OR p_ref_kind IS NULL OR p_ref_kind NOT IN (1, 2) OR p_ref_id IS NULL
     OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_exp IS NULL OR p_mac IS NULL OR pg_catalog.octet_length(p_mac) > 128
     OR p_attestation_object IS NULL OR p_client_data_json IS NULL OR p_credential_id IS NULL OR p_public_key IS NULL THEN
    RAISE EXCEPTION 'partner_credential_register_first: a token hash, a user, a reference, the challenge, the attestation object, the client data, a credential id and a key are required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_credential_register_first: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  -- 1. the acceptance this registration follows (locked: two concurrent registrations of one acceptance serialise here)
  IF p_ref_kind = 1 THEN
    SELECT i.accepted_at, i.registered_credential_id, i.org_id, true INTO v_acc, v_reg, v_org, v_found
    FROM app.partner_invite i
    WHERE i.id = p_ref_id AND i.accepted_by = p_user_id AND i.accepted_at IS NOT NULL AND i.revoked_at IS NULL;
  ELSE
    SELECT t.consumed_at, t.registered_credential_id, NULL::uuid, true INTO v_acc, v_reg, v_org, v_found
    FROM app.partner_enrolment_token t
    WHERE t.id = p_ref_id AND t.user_id = p_user_id AND t.consumed_at IS NOT NULL AND t.revoked_at IS NULL;
  END IF;
  IF NOT coalesce(v_found, false) THEN
    RETURN QUERY SELECT 'not_accepted'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF v_reg IS NOT NULL THEN
    RETURN QUERY SELECT 'already_registered'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF p_ref_kind = 1 THEN
    PERFORM 1 FROM app.partner_invite i WHERE i.id = p_ref_id AND i.registered_credential_id IS NULL FOR UPDATE;
  ELSE
    PERFORM 1 FROM app.partner_enrolment_token t WHERE t.id = p_ref_id AND t.registered_credential_id IS NULL FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'already_registered'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF v_acc < pg_catalog.clock_timestamp() - interval '15 minutes' THEN
    RETURN QUERY SELECT 'accept_expired'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  -- 2. the challenge: bound to this uid, this invite or token and this acceptance time
  v_us := (EXTRACT(EPOCH FROM v_acc) * 1000000)::bigint;
  IF NOT private.partner_challenge_verify(2::smallint, p_exp, p_nonce, p_user_id, p_mac, p_ref_kind, p_ref_id, v_us) THEN
    RETURN QUERY SELECT 'bad_challenge'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF p_exp <= pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint THEN
    RETURN QUERY SELECT 'expired'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  -- 3. the person's state at the point of creation (6.1 step 4)
  IF EXISTS (SELECT 1 FROM app.partner_credential c WHERE c.user_id = p_user_id AND c.revoked_at IS NULL) THEN
    RETURN QUERY SELECT 'credential_exists'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  IF p_ref_kind = 1 AND (EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_user_id AND m.revoked_at IS NULL AND m.org_id <> v_org)
                         OR NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_user_id AND m.revoked_at IS NULL AND m.org_id = v_org)) THEN
    RETURN QUERY SELECT 'other_membership'::text, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  -- 4. the ceremony checks, the nonce and the credential
  SELECT k.o_status, k.o_credential_id, k.o_auth_data INTO v_c
  FROM private.partner_credential_create_core(p_user_id, p_nonce, p_attestation_object, p_client_data_json, p_credential_id, p_public_key, p_transports, NULL, NULL, v_sid) k;
  IF v_c.o_status IS DISTINCT FROM 'ok' THEN
    RETURN QUERY SELECT v_c.o_status, NULL::uuid, NULL::uuid, NULL::smallint, NULL::timestamptz, NULL::timestamptz;
    RETURN;
  END IF;
  -- 5. one registration per acceptance
  IF p_ref_kind = 1 THEN
    UPDATE app.partner_invite i SET registered_credential_id = v_c.o_credential_id WHERE i.id = p_ref_id AND i.registered_credential_id IS NULL;
  ELSE
    UPDATE app.partner_enrolment_token t SET registered_credential_id = v_c.o_credential_id WHERE t.id = p_ref_id AND t.registered_credential_id IS NULL;
  END IF;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n <> 1 THEN
    RAISE EXCEPTION 'partner_credential_register_first: the acceptance could not be marked registered' USING ERRCODE = '55000';
  END IF;
  -- 6. the first session, in this transaction: no signature exists for an attestation-none create ceremony
  SELECT p.* INTO v_pol FROM private.partner_session_policy(p_user_id) p;
  v_expires := pg_catalog.clock_timestamp() + v_pol.absolute;
  v_enrol := pg_catalog.clock_timestamp() + interval '15 minutes';
  INSERT INTO app.partner_session (id, token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, enrolment_until,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (v_sid, p_token_hash, p_user_id, v_c.o_credential_id, 1, pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp(), v_expires, v_enrol,
          'register', pg_catalog.sha256(p_nonce), v_c.o_auth_data, p_client_data_json, NULL);
  PERFORM private.partner_sessions_evict_oldest(p_user_id, v_pol.concurrent);
  PERFORM private.partner_audit_write('partner.credential.register_first', 'app.partner_credential', v_c.o_credential_id::text,
    pg_catalog.jsonb_build_object('user', p_user_id, 'ref_kind', p_ref_kind, 'ref_id', p_ref_id));
  RETURN QUERY SELECT 'ok'::text, v_c.o_credential_id, v_sid, 1::smallint, v_expires, v_enrol;
END
$$;


COMMENT ON FUNCTION private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[]) IS
  '0054/0080 (6.1, PA-7b, PA-7c). edge_partner_minter only; owned by partner_session_issuer. First credential + first session in one transaction; one registration per acceptance; then eviction beyond the person''s concurrent keep from partner_session_policy (admin 2 / others 3; REVOKE, never DELETE).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_session_issuer;
REVOKE partner_session_issuer FROM CURRENT_USER;

-- ============================================================================
-- 3. Inventory notes
-- ============================================================================
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0080 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0047/0080: required aal, idle, absolute ceiling, and concurrent keep (admin 2 / others 3); EXECUTE for partner_session_issuer; bind / authorize call as owner'
WHERE schema_name = 'private' AND function_name = 'partner_session_policy'
  AND identity_args = 'p_uid uuid';

UPDATE private.function_inventory
SET note = '0048/0078/0080: edge_partner_minter only; owned by partner_session_issuer; mints a sign-in session from a WebAuthn assertion: HMAC / purpose / expiry, the credential from the table, 60 per hour per credential, structural checks against partner_rp_config, the SQL signature check, the used nonce, the counter compare-and-set, the session with its mint_* evidence, then eviction beyond partner_session_policy.concurrent (admin 2 / others 3; REVOKE not DELETE); every refusal is a status, never a RAISE'
WHERE schema_name = 'private' AND function_name = 'partner_session_mint'
  AND identity_args = 'p_token_hash text, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea';

UPDATE private.function_inventory
SET note = '0054/0080 (6.1, PA-7b, PA-7c): edge_partner_minter only; owned by partner_session_issuer; first credential + first session in one transaction; one registration per acceptance; eviction via partner_session_policy.concurrent (admin 2 / others 3)'
WHERE schema_name = 'private' AND function_name = 'partner_credential_register_first'
  AND identity_args = 'p_token_hash text, p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_nonce bytea, p_exp bigint, p_mac bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[]';

DO $assert_0080_inventory$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM private.function_inventory
    WHERE schema_name = 'private' AND function_name = 'partner_session_policy' AND note LIKE '%concurrent%'
  ) THEN
    RAISE EXCEPTION '0080: partner_session_policy function_inventory note was not updated';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM private.function_inventory
    WHERE schema_name = 'private' AND function_name = 'partner_session_mint' AND note LIKE '%0080%'
  ) THEN
    RAISE EXCEPTION '0080: partner_session_mint function_inventory note was not updated';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM private.function_inventory
    WHERE schema_name = 'private' AND function_name = 'partner_credential_register_first' AND note LIKE '%0080%'
  ) THEN
    RAISE EXCEPTION '0080: partner_credential_register_first function_inventory note was not updated';
  END IF;
  IF NOT has_function_privilege('partner_session_issuer', 'private.partner_session_policy(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION '0080: partner_session_issuer must EXECUTE partner_session_policy after DROP+CREATE';
  END IF;
END
$assert_0080_inventory$;

DROP POLICY current_user_edit_function_inventory_0080 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;
