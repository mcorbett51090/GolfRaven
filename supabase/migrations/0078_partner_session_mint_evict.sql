-- 0078_partner_session_mint_evict.sql
--
-- P5 §64: close the 0048 leftover that register_first (0054) already closed
-- for first-credential mint — sign-in mint must also keep at most three
-- live sessions of a person by REVOKING the oldest beyond that (design
-- §4.1 / §17.8 / §22.3). Uses private.partner_sessions_evict_oldest
-- (0054); keep = 3 to match register_first (admin keep=2 in the §4.1
-- table stays a separate departure).
--
-- WHAT THIS CHANGES
--   CREATE OR REPLACE private.partner_session_mint: after a successful
--   session INSERT, PERFORM partner_sessions_evict_oldest(user_id, 3).
--   COMMENT + function_inventory note mention eviction.
--
-- DELIBERATELY NOT HERE: admin keep=2, credential display-note PATCH,
-- IP/global alert-only rate buckets, pepper-rotation, OCR / aHash /
-- UI flag flips / CAMERA.
-- Nothing from 0001–0077 is edited.

-- ============================================================================
-- 1. Replace the mint under its owner (R5-L3 bracket)
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
  -- 9. 4.1: keep at most three live sessions of this person (REVOKE oldest beyond that; never DELETE — the 60/h count is from partner_session rows)
  PERFORM private.partner_sessions_evict_oldest(v_cred.user_id, 3);
  RETURN QUERY SELECT 'ok'::text, v_sid, 1::smallint, v_expires;
END
$$;

COMMENT ON FUNCTION private.partner_session_mint(text, bytea, bytea, bigint, bytea, bytea, bytea, bytea) IS
  '0048/0078. edge_partner_minter only; owned by partner_session_issuer. Mints a sign-in session from a WebAuthn assertion. Order: HMAC / purpose / expiry (the nonce is the challenge in clientDataJSON), the credential FROM app.partner_credential, at most 60 sign-ins per credential per hour (before any verification), the structural checks against app.partner_rp_config, the SQL signature check, the used nonce (primary key = single use), the counter compare-and-set, the session with its mint_* evidence, then eviction beyond three live sessions of the person via private.partner_sessions_evict_oldest (REVOKE, never DELETE). Returns a status row; never raises over a refusal. A signature that fails here and a counter regression write audit_log and app.partner_auth_alarm rows that commit with the refusal.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_session_issuer;
REVOKE partner_session_issuer FROM CURRENT_USER;

-- ============================================================================
-- 2. Inventory note
-- ============================================================================
UPDATE private.function_inventory
SET note = '0048/0078: edge_partner_minter only; owned by partner_session_issuer; mints a sign-in session from a WebAuthn assertion: HMAC / purpose / expiry, the credential from the table, 60 per hour per credential, structural checks against partner_rp_config, the SQL signature check, the used nonce, the counter compare-and-set, the session with its mint_* evidence, then eviction beyond three live sessions (partner_sessions_evict_oldest, keep=3, REVOKE not DELETE); every refusal is a status, never a RAISE'
WHERE schema_name = 'private' AND function_name = 'partner_session_mint'
  AND identity_args = 'p_token_hash text, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea';
