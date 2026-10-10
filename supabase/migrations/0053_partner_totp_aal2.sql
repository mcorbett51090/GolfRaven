-- 0053_partner_totp_aal2.sql
--
-- P5.1a, slice S1.4: PARTNER TOTP AND aal 2. docs/security/partner-auth-design.md (revision 5) is the specification: section 4.1 (aal gates every class; the aal 1
-- exception for an operator or admin with no confirmed TOTP), 5.1 (`partner_totp`, the Vault-derived seed), 6.3 (A3 enabled; A3 substitutes for PIN-less elevated members),
-- 6.4 (HOTP in SQL, gated enrolment, confirm in the enrolling session, reset by a higher role, admin bootstrap), 12 (S1.4), 12.1 (PA-20, PA-24, PA-28), 18.4 and 19.5 (seams
-- this file closes: mfa_until clearer on lock; otp_proof spend on TOTP enrol/confirm; A0_ENROL / A0_MFA). Migrations 0001-0052 are untouched; everything below is CREATE except
-- CREATE OR REPLACE of partner_authorize, partner_session_lock_for_partner, and the wrappers reclassed to A0_ENROL (otp-proof, reauth, GET pin).
--
-- WHAT THIS ADDS
--   1. private.hotp (RFC 4226 over public.hmac) and private.partner_totp_seed_derive (Vault secret partner_totp_key, labelled fixed-width message; the 0045 offline_seed_derive shape).
--   2. app.partner_totp (section 5.1): one row per person; the seed is DERIVED, never stored. FORCE RLS; no client, edge or service_role privilege. Written only by definers OWNED by
--      partner_totp_verifier (the role that also owns the only writer of aal / mfa_until, R5-L1, 0047).
--   3. Verifier-owned attempt / verify_apply / enrol_apply / confirm_apply / mfa_clear / reset_apply: every counter outcome is a STATUS, never a RAISE (0020). verify_apply is the ONLY
--      code that sets aal = 2 and mfa_until = now + 5 min (R5-L1).
--   4. partner_authorize (CREATE OR REPLACE): classes A0_MFA and A0_ENROL; A3 ENABLED; aal exception for A0_MFA always and for A0_ENROL while no confirmed TOTP (PA-20, PA-28);
--      A1 / A2 accept A3 as the substitute for a PIN-less elevated member (6.3).
--   5. The `_for_partner` family: totp enrol / confirm / verify / reset; admin enrolment issue; lock clears mfa_until; otp-proof / reauth / GET pin reclassed to A0_ENROL.
--   6. private.partner_admin_bootstrap_token (EXECUTE for nobody: ops SQL session as owner) and the A3 admin-issue wrapper.
--
-- WHAT THIS DOES NOT BUILD (seams stay intact): Edge TypeScript handlers and otpauth QR assembly (returns seed bytea + version + otpauth params; Edge builds the URI); the pgTAP
-- matrix / PA-20 oracle cells; full reach rule for TOTP reset (S1.5: this file's reset is admin-only lite); last-membership delete of partner_totp (PA-29, S1.5); pepper / key rotation.

-- ============================================================================
-- 1. The owner role this file writes functions for: the migrating role holds SET on it for the length of this file only (the 0047 / 0052 bracket, R5-L3)
-- ============================================================================
GRANT partner_totp_verifier TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;

-- ============================================================================
-- 2. HOTP core + seed derive (owned by private_definer). The seed derive is the ONLY reader of Vault secret partner_totp_key.
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 2a. RFC 4226 HOTP over public.hmac. Shared primitive with the offline code (N6): each caller picks digits and algo. IMMUTABLE: pure function of its arguments.
CREATE FUNCTION private.hotp(p_seed bytea, p_counter bigint, p_digits integer, p_algo text)
RETURNS text
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_msg bytea;
  v_hmac bytea;
  v_offset integer;
  v_bin bigint;
BEGIN
  IF p_seed IS NULL OR pg_catalog.octet_length(p_seed) < 16
     OR p_counter IS NULL OR p_counter < 0
     OR p_digits IS NULL OR p_digits NOT BETWEEN 6 AND 8
     OR p_algo IS NULL OR p_algo NOT IN ('sha1', 'sha256') THEN
    RAISE EXCEPTION 'hotp: seed (>=16 bytes), counter (>=0), digits (6..8) and algo (sha1|sha256) are required' USING ERRCODE = '22023';
  END IF;
  -- 8-byte big-endian counter (RFC 4226)
  v_msg := pg_catalog.set_byte(pg_catalog.set_byte(pg_catalog.set_byte(pg_catalog.set_byte(
           pg_catalog.set_byte(pg_catalog.set_byte(pg_catalog.set_byte(pg_catalog.set_byte(
             '\x0000000000000000'::bytea,
             0, ((p_counter >> 56) & 255)::integer),
             1, ((p_counter >> 48) & 255)::integer),
             2, ((p_counter >> 40) & 255)::integer),
             3, ((p_counter >> 32) & 255)::integer),
             4, ((p_counter >> 24) & 255)::integer),
             5, ((p_counter >> 16) & 255)::integer),
             6, ((p_counter >> 8) & 255)::integer),
             7, (p_counter & 255)::integer);
  v_hmac := public.hmac(v_msg, p_seed, p_algo);
  v_offset := pg_catalog.get_byte(v_hmac, pg_catalog.octet_length(v_hmac) - 1) & 15;
  v_bin := ((pg_catalog.get_byte(v_hmac, v_offset)::bigint & 127) << 24)
         | (pg_catalog.get_byte(v_hmac, v_offset + 1)::bigint << 16)
         | (pg_catalog.get_byte(v_hmac, v_offset + 2)::bigint << 8)
         |  pg_catalog.get_byte(v_hmac, v_offset + 3)::bigint;
  -- NOTE: in PostgreSQL `^` is bitwise XOR, not exponentiation. Use an explicit modulus table.
  RETURN pg_catalog.lpad(
    (v_bin % (CASE p_digits WHEN 6 THEN 1000000::bigint WHEN 7 THEN 10000000::bigint ELSE 100000000::bigint END))::text,
    p_digits, '0');
END
$$;

-- 2b. THE derivation. The only place partner_totp_key is read (0045 offline_seed_derive / 0052 partner_pin_core shape). Message after the label is FIXED WIDTH:
--     "golfraven/partner-totp/v1" (UTF-8) || 0x00 || user id (16 bytes) || int4send(seed_version)
-- EXECUTE for partner_totp_verifier and its OWNER private_definer; nobody else. The seed is never logged here.
CREATE FUNCTION private.partner_totp_seed_derive(p_user_id uuid, p_seed_version integer)
RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
BEGIN
  IF p_user_id IS NULL OR p_seed_version IS NULL OR p_seed_version < 1 THEN
    RAISE EXCEPTION 'partner_totp_seed_derive: a user and a seed version of at least 1 are required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'partner_totp_key';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'partner_totp_seed_derive: the partner TOTP key is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  RETURN public.hmac(
    pg_catalog.convert_to('golfraven/partner-totp/v1', 'UTF8')
      || pg_catalog.decode('00', 'hex')
      || pg_catalog.decode(pg_catalog.replace(p_user_id::text, '-', ''), 'hex')
      || pg_catalog.int4send(p_seed_version),
    pg_catalog.convert_to(v_key, 'UTF8'),
    'sha256');
END
$$;

-- 2c. PIN-less elevated member (6.3): admin OR active operator, and NO active staff/manager membership. A1 / A2 are met by A3 for such a member.
-- (partner_totp_confirmed and partner_authorize follow the table: confirmed is SQL and needs app.partner_totp to exist; authorize calls confirmed.)
CREATE FUNCTION private.partner_is_pinless_elevated(p_uid uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p_uid IS NOT NULL
     AND (private.is_admin(p_uid)
          OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_uid AND m.revoked_at IS NULL AND m.role = 'operator'))
     AND NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_uid AND m.revoked_at IS NULL AND m.role IN ('staff', 'manager'));
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. app.partner_totp
-- ============================================================================
CREATE TABLE app.partner_totp (
  -- one TOTP per PERSON (operator / admin factor, 4.1 / 6.4)
  user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  -- bumped on EVERY enrol (including an unconfirmed re-enrol) so an earlier shown seed is dead (H4). Start 0 so the first enrol becomes 1.
  seed_version integer NOT NULL DEFAULT 0 CHECK (seed_version >= 0),
  enrolled_at timestamptz,
  -- the session that called enrol; confirm must be the same session (ON DELETE SET NULL: a revoked session cannot confirm)
  enrol_session_id uuid REFERENCES app.partner_session (id) ON DELETE SET NULL,
  confirmed_at timestamptz,
  -- replay: a step is accepted only when last_step < step (UPDATE ... WHERE last_step < s)
  last_step bigint,
  failed_count smallint NOT NULL DEFAULT 0 CHECK (failed_count BETWEEN 0 AND 5),
  locked_until timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE app.partner_totp IS
  '0053 (design 5.1, 6.4). One row per person: seed_version (the seed is DERIVED from Vault partner_totp_key, never stored), enrolment / confirm state, HOTP replay (last_step), and lockout. FORCE RLS; no client, edge or service_role privilege. Written only by definers owned by partner_totp_verifier; delete_my_data''s window pair is the only other path.';
ALTER TABLE app.partner_totp ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_totp FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.partner_totp FROM PUBLIC, anon, authenticated, service_role;

-- 3a. partner_totp_verifier: the whole table (it is the table's only reader and writer), behind registered `ptv_*` policies keyed on the BINDING (never a settable GUC). Admin reset of
-- another's row is allowed by the same SELECT/UPDATE policies when the bound user is an admin (S1.4 lite reach; full reach is S1.5).
GRANT SELECT, INSERT, UPDATE ON app.partner_totp TO partner_totp_verifier;
GRANT SELECT (enrolment_until, otp_proof_until, id, user_id) ON app.partner_session TO partner_totp_verifier;
CREATE POLICY ptv_read_partner_totp ON app.partner_totp FOR SELECT TO partner_totp_verifier
  USING (user_id = private.partner_binding_user() OR private.is_admin(private.partner_binding_user()));
CREATE POLICY ptv_insert_partner_totp ON app.partner_totp FOR INSERT TO partner_totp_verifier
  WITH CHECK (user_id = private.partner_binding_user());
CREATE POLICY ptv_update_partner_totp ON app.partner_totp FOR UPDATE TO partner_totp_verifier
  USING (user_id = private.partner_binding_user() OR private.is_admin(private.partner_binding_user()))
  WITH CHECK (user_id = private.partner_binding_user() OR private.is_admin(private.partner_binding_user()));

-- 3b. private_definer: the delete_my_data registry pass ONLY (0016 window + partner conjunct InitPlan form, 0052). Nothing else.
GRANT SELECT (user_id), DELETE ON app.partner_totp TO private_definer;
CREATE POLICY pd_delete_partner_totp_user_id ON app.partner_totp
  FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_delete_partner_totp_user_id_r ON app.partner_totp
  FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- 3c. private_definer INSERT of admin enrolment tokens (bootstrap + A3 issue). Closed under a partner binding unless issued_by is the bound user.
GRANT INSERT ON app.partner_enrolment_token TO private_definer;
CREATE POLICY pd_insert_partner_enrolment_token_admin ON app.partner_enrolment_token
  FOR INSERT TO private_definer WITH CHECK (
    purpose = 'admin'
    AND (
      (issued_by IS NULL AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner')
      OR (issued_by IS NOT NULL AND issued_by = (SELECT private.partner_binding_user()))
    )
  );

-- ============================================================================
-- 4. partner_totp_confirmed (needs the table) + partner_authorize, then the verifier-owned writers (R5-L1)
-- ============================================================================
-- 4a. True iff the person holds a confirmed, non-revoked TOTP (PA-28). Owned by partner_totp_verifier so FORCE RLS lets it see the row (private_definer's only SELECT is the delete window). STABLE. Called from partner_authorize.
GRANT CREATE ON SCHEMA private TO partner_totp_verifier;
SET ROLE partner_totp_verifier;

CREATE FUNCTION private.partner_totp_confirmed(p_uid uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1 FROM app.partner_totp t
    WHERE t.user_id = p_uid AND t.confirmed_at IS NOT NULL AND t.revoked_at IS NULL
  );
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_totp_verifier;

-- 4b. partner_authorize: A3 ENABLED; A0_MFA / A0_ENROL; aal exception (PA-20 / PA-28); A3-for-PIN-less substitution (6.3). Same owner, ACL and signature.
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_authorize(p_facility_id text, p_trail_id text, p_roles app.partner_role[], p_class text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
  v_s record;
  v_pol record;
  v_write boolean;
  v_nku boolean;
BEGIN
  IF p_class IS NULL OR p_class NOT IN ('SESSION', 'PEEK', 'A0', 'A0_WRITE', 'A0_KEEPALIVE', 'A0_MFA', 'A0_ENROL', 'A1', 'A2', 'A3') THEN
    RAISE EXCEPTION 'partner_authorize: unknown action class' USING ERRCODE = '22023';
  END IF;
  -- 0. READ COMMITTED only (S1.1a gate, NIT)
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'partner_authorize: requires a READ COMMITTED transaction' USING ERRCODE = '42501';
  END IF;
  -- 1. a partner binding in THIS transaction
  SELECT b.actor_uid, b.session_id INTO v_uid, v_sid
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned() AND b.kind = 'partner';
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_authorize: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF p_class NOT IN ('SESSION', 'PEEK') AND (p_roles IS NULL OR cardinality(p_roles) = 0 OR p_roles && ARRAY['sponsor']::app.partner_role[]) THEN
    RAISE EXCEPTION 'partner_authorize: an explicit, non-empty role list without sponsor is required' USING ERRCODE = '22023';
  END IF;
  -- 2. lock the session row FIRST, and ONLY it (R3-M1). A0_MFA / A0_ENROL always take FOR NO KEY UPDATE: they write the session or totp rows that need a consistent lock (S1.3 gate LOW-1 shape).
  SELECT s.last_seen_at INTO v_s FROM app.partner_session s WHERE s.id = v_sid;
  v_write := p_class IN ('A1', 'A2', 'A3') OR (p_class NOT IN ('A0_KEEPALIVE', 'PEEK') AND (v_s.last_seen_at IS NULL OR v_s.last_seen_at < clock_timestamp() - interval '1 minute'));
  v_nku := v_write OR p_class IN ('A0_WRITE', 'A0_MFA', 'A0_ENROL', 'SESSION');
  IF v_nku THEN
    SELECT s.user_id, s.credential_id, s.aal, s.last_seen_at, s.expires_at, s.revoked_at, s.reauth_until, s.mfa_until INTO v_s
    FROM app.partner_session s WHERE s.id = v_sid FOR NO KEY UPDATE;
  ELSE
    SELECT s.user_id, s.credential_id, s.aal, s.last_seen_at, s.expires_at, s.revoked_at, s.reauth_until, s.mfa_until INTO v_s
    FROM app.partner_session s WHERE s.id = v_sid FOR SHARE;
  END IF;
  IF NOT FOUND OR v_s.user_id IS DISTINCT FROM v_uid THEN
    RAISE EXCEPTION 'partner_authorize: the session is not live' USING ERRCODE = '42501';
  END IF;
  IF v_s.revoked_at IS NOT NULL OR v_s.expires_at <= clock_timestamp() OR NOT private.partner_credential_live(v_s.credential_id) THEN
    RAISE EXCEPTION 'partner_authorize: the session is not live' USING ERRCODE = '42501';
  END IF;
  -- 3. role and scope re-read NOW
  IF private.is_demo_account(v_uid)
     OR NOT (private.is_admin(v_uid)
             OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL AND m.role <> 'sponsor')) THEN
    RAISE EXCEPTION 'partner_authorize: the member holds no active partner role' USING ERRCODE = '42501';
  END IF;
  SELECT p.* INTO v_pol FROM private.partner_session_policy(v_uid) p;
  IF v_s.last_seen_at + v_pol.idle <= clock_timestamp() THEN
    RAISE EXCEPTION 'partner_authorize: the session is not live' USING ERRCODE = '42501';
  END IF;
  IF p_class NOT IN ('SESSION', 'PEEK') THEN
    -- 4. aal gates EVERY class including A0 (M2), with the PA-20 / PA-28 exceptions (4.1):
    --    A0_MFA (step-up/totp) always allowed so an aal1 operator can raise;
    --    A0_ENROL (totp enrol/confirm, otp-proof, otp-target, reauth) only while the person has NO confirmed TOTP.
    IF v_s.aal < v_pol.required_aal THEN
      IF p_class = 'A0_MFA' THEN
        NULL;
      ELSIF p_class = 'A0_ENROL' AND NOT private.partner_totp_confirmed(v_uid) THEN
        NULL;
      ELSE
        RAISE EXCEPTION 'partner_authorize: the session''s assurance level is below the member''s required level' USING ERRCODE = '42501';
      END IF;
    END IF;
    IF p_facility_id IS NULL AND p_trail_id IS NULL THEN
      IF NOT (private.is_admin(v_uid)
              OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL AND m.role = ANY (p_roles))) THEN
        RAISE EXCEPTION 'partner_authorize: no scope' USING ERRCODE = '42501';
      END IF;
    ELSE
      IF p_facility_id IS NOT NULL AND NOT private.has_facility_scope(v_uid, p_facility_id, p_roles) THEN
        RAISE EXCEPTION 'partner_authorize: no scope' USING ERRCODE = '42501';
      END IF;
      IF p_trail_id IS NOT NULL AND NOT private.has_trail_scope(v_uid, p_trail_id, p_roles) THEN
        RAISE EXCEPTION 'partner_authorize: no scope' USING ERRCODE = '42501';
      END IF;
    END IF;
    -- class prerequisite. A1 / A2: PIN grant, OR (PIN-less elevated AND a fresh TOTP window). A3: aal >= 2 AND mfa_until > now.
    IF p_class = 'A1' AND NOT private.partner_pin_grant_consume() THEN
      IF NOT (private.partner_is_pinless_elevated(v_uid)
              AND v_s.mfa_until IS NOT NULL AND v_s.mfa_until > clock_timestamp()) THEN
        RAISE EXCEPTION 'partner_authorize: a PIN verified in the last minute and not yet used is required' USING ERRCODE = '42501';
      END IF;
    END IF;
    IF p_class = 'A2' THEN
      IF v_s.reauth_until IS NULL OR v_s.reauth_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'partner_authorize: a passkey assertion in the last 5 minutes is required' USING ERRCODE = '42501';
      END IF;
      IF NOT private.partner_pin_grant_consume_fresh(30) THEN
        IF NOT (private.partner_is_pinless_elevated(v_uid)
                AND v_s.mfa_until IS NOT NULL AND v_s.mfa_until > clock_timestamp()) THEN
          RAISE EXCEPTION 'partner_authorize: a PIN verified in the last 30 seconds and not yet used is required' USING ERRCODE = '42501';
        END IF;
      END IF;
    END IF;
    IF p_class = 'A3' THEN
      IF v_s.aal < 2 OR v_s.mfa_until IS NULL OR v_s.mfa_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'partner_authorize: aal 2 and a TOTP verified in the last 5 minutes are required' USING ERRCODE = '42501';
      END IF;
    END IF;
  END IF;
  IF v_write AND p_class NOT IN ('A0_KEEPALIVE', 'PEEK') AND v_s.last_seen_at < clock_timestamp() - interval '1 minute' THEN
    UPDATE app.partner_session s SET last_seen_at = clock_timestamp() WHERE s.id = v_sid;
  END IF;
  RETURN v_uid;
END;
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- 4c. The verifier-owned writers
GRANT CREATE ON SCHEMA private TO partner_totp_verifier;
SET ROLE partner_totp_verifier;

-- 4d. ONE ATTEMPT against a person's confirmed TOTP. Internal: EXECUTE for nobody. Locks the row FOR UPDATE. Statuses (never a RAISE):
--   unset | locked | unconfirmed | ok | wrong | retry_after
-- Replay: a candidate step <= last_step is skipped. Window: step-1, step, step+1. Lock: 5 failures -> locked_until = now + 15 min; failures during lock are not counted.
CREATE FUNCTION private.partner_totp_attempt(p_uid uuid, p_code text)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_t record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_seed bytea;
  v_step bigint;
  v_cand bigint;
  v_i integer;
  v_expected text;
  v_code text;
  v_match boolean;
  v_fc integer;
BEGIN
  IF p_uid IS NULL OR p_code IS NULL OR p_code !~ '^[0-9]{6}$' THEN
    RAISE EXCEPTION 'partner_totp_attempt: a user and a 6-digit code are required' USING ERRCODE = '22023';
  END IF;
  v_code := p_code;
  SELECT t.seed_version, t.confirmed_at, t.last_step, t.failed_count, t.locked_until, t.revoked_at INTO v_t
  FROM app.partner_totp t WHERE t.user_id = p_uid FOR UPDATE;
  IF NOT FOUND OR v_t.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'unset'::text, 0;
    RETURN;
  END IF;
  IF v_t.locked_until IS NOT NULL AND v_t.locked_until > v_now THEN
    RETURN QUERY SELECT 'locked'::text, pg_catalog.ceil(pg_catalog.date_part('epoch', v_t.locked_until - v_now))::integer;
    RETURN;
  END IF;
  IF v_t.confirmed_at IS NULL THEN
    RETURN QUERY SELECT 'unconfirmed'::text, 0;
    RETURN;
  END IF;
  IF v_t.seed_version < 1 THEN
    RETURN QUERY SELECT 'unset'::text, 0;
    RETURN;
  END IF;
  v_seed := private.partner_totp_seed_derive(p_uid, v_t.seed_version);
  v_step := pg_catalog.floor(pg_catalog.date_part('epoch', v_now) / 30.0)::bigint;
  FOR v_i IN 0..2 LOOP
    v_cand := v_step + (v_i - 1);
    IF v_cand < 0 THEN
      CONTINUE;
    END IF;
    IF v_t.last_step IS NOT NULL AND v_cand <= v_t.last_step THEN
      CONTINUE;
    END IF;
    v_expected := private.hotp(v_seed, v_cand, 6, 'sha1');
    -- compare via HMAC under the seed so equality does not short-circuit on a secret-derived value's bytes
    v_match := public.hmac(pg_catalog.convert_to(v_code, 'UTF8'), v_seed, 'sha256')
             = public.hmac(pg_catalog.convert_to(v_expected, 'UTF8'), v_seed, 'sha256');
    IF v_match THEN
      UPDATE app.partner_totp t
      SET last_step = v_cand, failed_count = 0, locked_until = NULL
      WHERE t.user_id = p_uid AND (t.last_step IS NULL OR t.last_step < v_cand);
      IF NOT FOUND THEN
        -- lost the compare-and-set (concurrent accept of the same or a later step): treat as wrong without counting
        RETURN QUERY SELECT 'wrong'::text, 0;
        RETURN;
      END IF;
      RETURN QUERY SELECT 'ok'::text, 0;
      RETURN;
    END IF;
  END LOOP;
  -- wrong: count toward lockout (5 consecutive -> 15 min lock; failed_count reset on lock so the unlock window starts clean)
  v_fc := v_t.failed_count + 1;
  IF v_fc >= 5 THEN
    UPDATE app.partner_totp t
    SET failed_count = 0, locked_until = v_now + interval '15 minutes'
    WHERE t.user_id = p_uid;
    RETURN QUERY SELECT 'locked'::text, 900;
    RETURN;
  END IF;
  UPDATE app.partner_totp t SET failed_count = v_fc WHERE t.user_id = p_uid;
  RETURN QUERY SELECT 'wrong'::text, 0;
END
$$;

-- 4b. THE step-up verifier (class A0_MFA caller). On ok sets aal = 2 and mfa_until = now + 5 min on the BOUND session ONLY (R5-L1).
CREATE FUNCTION private.partner_totp_verify_apply(p_code text)
RETURNS TABLE (o_status text, o_retry_after integer, o_mfa_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_sid uuid := private.partner_binding_session();
  v_a record;
  v_until timestamptz;
BEGIN
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_totp_verify_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  SELECT a.o_status, a.o_retry_after INTO v_a FROM private.partner_totp_attempt(v_uid, p_code) a;
  IF v_a.o_status IS DISTINCT FROM 'ok' THEN
    RETURN QUERY SELECT v_a.o_status, v_a.o_retry_after, NULL::timestamptz;
    RETURN;
  END IF;
  UPDATE app.partner_session s
  SET aal = 2, mfa_until = pg_catalog.clock_timestamp() + interval '5 minutes'
  WHERE s.id = v_sid
  RETURNING s.mfa_until INTO v_until;
  IF v_until IS NULL THEN
    RAISE EXCEPTION 'partner_totp_verify_apply: the bound session is not writable' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT 'ok'::text, 0, v_until;
END
$$;

-- 4c. ENROL: bump seed_version, clear confirmed_at, set enrolled_at and enrol_session_id. Refuses once confirmed (PA-24). Needs enrolment_until or otp_proof_until on the bound session.
-- Returns the derived seed ONCE (never stored) plus otpauth params (issuer GolfRaven, period 30, digits 6, algo SHA1). Every enrol bumps version so an earlier QR is dead (H4).
CREATE FUNCTION private.partner_totp_enrol_apply()
RETURNS TABLE (o_status text, o_seed bytea, o_seed_version integer, o_issuer text, o_period integer, o_digits integer, o_algo text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_sid uuid := private.partner_binding_session();
  v_s record;
  v_t record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_ver integer;
  v_seed bytea;
  v_n integer;
BEGIN
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_totp_enrol_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  SELECT s.enrolment_until, s.otp_proof_until INTO v_s FROM app.partner_session s WHERE s.id = v_sid;
  IF NOT FOUND OR NOT ((v_s.enrolment_until IS NOT NULL AND v_s.enrolment_until > v_now)
                       OR (v_s.otp_proof_until IS NOT NULL AND v_s.otp_proof_until > v_now)) THEN
    RAISE EXCEPTION 'partner_totp_enrol_apply: TOTP is enrolled only inside an enrolment window or after an email proof' USING ERRCODE = '42501';
  END IF;
  SELECT t.confirmed_at, t.seed_version INTO v_t FROM app.partner_totp t WHERE t.user_id = v_uid FOR UPDATE;
  IF FOUND AND v_t.confirmed_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_confirmed'::text, NULL::bytea, NULL::integer, NULL::text, NULL::integer, NULL::integer, NULL::text;
    RETURN;
  END IF;
  IF NOT FOUND THEN
    INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, enrol_session_id, confirmed_at, last_step, failed_count, locked_until, revoked_at, created_at)
    VALUES (v_uid, 1, v_now, v_sid, NULL, NULL, 0, NULL, NULL, v_now);
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n <> 1 THEN
      RAISE EXCEPTION 'partner_totp_enrol_apply: enrol insert failed' USING ERRCODE = '42501';
    END IF;
    v_ver := 1;
  ELSE
    v_ver := v_t.seed_version + 1;
    UPDATE app.partner_totp t
    SET seed_version = v_ver, enrolled_at = v_now, enrol_session_id = v_sid, confirmed_at = NULL,
        last_step = NULL, failed_count = 0, locked_until = NULL, revoked_at = NULL
    WHERE t.user_id = v_uid;
  END IF;
  v_seed := private.partner_totp_seed_derive(v_uid, v_ver);
  RETURN QUERY SELECT 'ok'::text, v_seed, v_ver, 'GolfRaven'::text, 30, 6, 'SHA1'::text;
END
$$;

-- 4d. CONFIRM: must be the same session as enrol_session_id; code must verify against the current UNCONFIRMED seed; sets confirmed_at.
CREATE FUNCTION private.partner_totp_confirm_apply(p_code text)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_sid uuid := private.partner_binding_session();
  v_t record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_seed bytea;
  v_step bigint;
  v_cand bigint;
  v_i integer;
  v_expected text;
  v_match boolean;
  v_fc integer;
BEGIN
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_totp_confirm_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF p_code IS NULL OR p_code !~ '^[0-9]{6}$' THEN
    RAISE EXCEPTION 'partner_totp_confirm_apply: a 6-digit code is required' USING ERRCODE = '22023';
  END IF;
  SELECT t.seed_version, t.confirmed_at, t.enrol_session_id, t.last_step, t.failed_count, t.locked_until, t.revoked_at INTO v_t
  FROM app.partner_totp t WHERE t.user_id = v_uid FOR UPDATE;
  IF NOT FOUND OR v_t.revoked_at IS NOT NULL OR v_t.seed_version < 1 THEN
    RETURN QUERY SELECT 'unset'::text, 0;
    RETURN;
  END IF;
  IF v_t.confirmed_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_confirmed'::text, 0;
    RETURN;
  END IF;
  IF v_t.enrol_session_id IS DISTINCT FROM v_sid THEN
    RETURN QUERY SELECT 'wrong_session'::text, 0;
    RETURN;
  END IF;
  IF v_t.locked_until IS NOT NULL AND v_t.locked_until > v_now THEN
    RETURN QUERY SELECT 'locked'::text, pg_catalog.ceil(pg_catalog.date_part('epoch', v_t.locked_until - v_now))::integer;
    RETURN;
  END IF;
  v_seed := private.partner_totp_seed_derive(v_uid, v_t.seed_version);
  v_step := pg_catalog.floor(pg_catalog.date_part('epoch', v_now) / 30.0)::bigint;
  FOR v_i IN 0..2 LOOP
    v_cand := v_step + (v_i - 1);
    IF v_cand < 0 THEN CONTINUE; END IF;
    IF v_t.last_step IS NOT NULL AND v_cand <= v_t.last_step THEN CONTINUE; END IF;
    v_expected := private.hotp(v_seed, v_cand, 6, 'sha1');
    v_match := public.hmac(pg_catalog.convert_to(p_code, 'UTF8'), v_seed, 'sha256')
             = public.hmac(pg_catalog.convert_to(v_expected, 'UTF8'), v_seed, 'sha256');
    IF v_match THEN
      UPDATE app.partner_totp t
      SET confirmed_at = v_now, last_step = v_cand, failed_count = 0, locked_until = NULL
      WHERE t.user_id = v_uid AND (t.last_step IS NULL OR t.last_step < v_cand);
      IF NOT FOUND THEN
        RETURN QUERY SELECT 'wrong'::text, 0;
        RETURN;
      END IF;
      RETURN QUERY SELECT 'ok'::text, 0;
      RETURN;
    END IF;
  END LOOP;
  v_fc := v_t.failed_count + 1;
  IF v_fc >= 5 THEN
    UPDATE app.partner_totp t SET failed_count = 0, locked_until = v_now + interval '15 minutes' WHERE t.user_id = v_uid;
    RETURN QUERY SELECT 'locked'::text, 900;
    RETURN;
  END IF;
  UPDATE app.partner_totp t SET failed_count = v_fc WHERE t.user_id = v_uid;
  RETURN QUERY SELECT 'wrong'::text, 0;
END
$$;

-- 4e. Clear mfa_until on the bound session (lock). EXECUTE for private_definer.
CREATE FUNCTION private.partner_totp_mfa_clear()
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  UPDATE app.partner_session s SET mfa_until = NULL
  WHERE s.id = private.partner_binding_session() AND s.mfa_until IS NOT NULL;
END
$$;

-- 4f. Admin reset of another's TOTP (S1.4 lite): bump seed_version, clear confirmed_at / enrol state. The wrapper checks admin + target shape; this writer is the only path that mutates another's row.
CREATE FUNCTION private.partner_totp_reset_apply(p_target uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_caller uuid := private.partner_binding_user();
  v_n integer;
BEGIN
  IF v_caller IS NULL OR p_target IS NULL OR p_target = v_caller THEN
    RAISE EXCEPTION 'partner_totp_reset_apply: a different target user is required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.is_admin(v_caller) THEN
    RAISE EXCEPTION 'partner_totp_reset_apply: only an admin may reset another person''s TOTP' USING ERRCODE = '42501';
  END IF;
  UPDATE app.partner_totp t
  SET seed_version = t.seed_version + 1,
      confirmed_at = NULL,
      enrolled_at = NULL,
      enrol_session_id = NULL,
      last_step = NULL,
      failed_count = 0,
      locked_until = NULL
  WHERE t.user_id = p_target AND t.revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    -- no row yet: insert a bumped unconfirmed placeholder so a later enrol starts at version 1 from a clean slate, OR simply report unset
    RETURN 'unset';
  END IF;
  RETURN 'ok';
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_totp_verifier;

-- ============================================================================
-- 5. The private_definer functions: the `_for_partner` family and admin bootstrap
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 5a. POST totp/enrol (class A0_ENROL, operator; admin passes anywhere). Spends otp_proof_until on ok (MEDIUM-1 / 19.5). Returns seed bytea + version + otpauth params for the Edge.
CREATE FUNCTION private.partner_totp_enrol_for_partner()
RETURNS TABLE (o_status text, o_seed bytea, o_seed_version integer, o_issuer text, o_period integer, o_digits integer, o_algo text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0_ENROL');
  SELECT a.o_status, a.o_seed, a.o_seed_version, a.o_issuer, a.o_period, a.o_digits, a.o_algo INTO v_r
  FROM private.partner_totp_enrol_apply() a;
  IF v_r.o_status = 'ok' THEN
    UPDATE app.partner_session s SET otp_proof_until = NULL
    WHERE s.id = private.partner_binding_session() AND s.otp_proof_until IS NOT NULL;
    PERFORM private.partner_audit_write('partner.totp.enrol', 'app.partner_totp', v_uid::text,
      pg_catalog.jsonb_build_object('seed_version', v_r.o_seed_version));
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_seed, v_r.o_seed_version, v_r.o_issuer, v_r.o_period, v_r.o_digits, v_r.o_algo;
END
$$;

-- 5b. POST totp/confirm (class A0_ENROL). Spends proof on ok if still set.
CREATE FUNCTION private.partner_totp_confirm_for_partner(p_code text)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0_ENROL');
  SELECT a.o_status, a.o_retry_after INTO v_r FROM private.partner_totp_confirm_apply(p_code) a;
  IF v_r.o_status = 'ok' THEN
    UPDATE app.partner_session s SET otp_proof_until = NULL
    WHERE s.id = private.partner_binding_session() AND s.otp_proof_until IS NOT NULL;
    PERFORM private.partner_audit_write('partner.totp.confirm', 'app.partner_totp', v_uid::text, '{}'::jsonb);
  ELSIF v_r.o_status IN ('wrong', 'locked') THEN
    PERFORM private.partner_audit_write(
      CASE WHEN v_r.o_status = 'locked' THEN 'partner.totp.locked' ELSE 'partner.totp.wrong' END,
      'app.partner_totp', v_uid::text, pg_catalog.jsonb_build_object('stage', 'confirm'));
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after;
END
$$;

-- 5c. POST session/step-up/totp (class A0_MFA). Audit wrong / locked.
CREATE FUNCTION private.partner_totp_verify_for_partner(p_code text)
RETURNS TABLE (o_status text, o_retry_after integer, o_mfa_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0_MFA');
  SELECT a.o_status, a.o_retry_after, a.o_mfa_until INTO v_r FROM private.partner_totp_verify_apply(p_code) a;
  IF v_r.o_status IN ('wrong', 'locked') THEN
    PERFORM private.partner_audit_write(
      CASE WHEN v_r.o_status = 'locked' THEN 'partner.totp.locked' ELSE 'partner.totp.wrong' END,
      'app.partner_totp', v_uid::text, pg_catalog.jsonb_build_object('stage', 'verify'));
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after, v_r.o_mfa_until;
END
$$;

-- 5d. POST members/{id}/totp-reset (class A3). Admin only; target is a different person who is an operator or admin (S1.4 lite reach; full reach is S1.5). Revokes the target's sessions.
CREATE FUNCTION private.partner_totp_reset_for_partner(p_target_uid uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_status text;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: only an admin may reset another person''s TOTP' USING ERRCODE = '42501';
  END IF;
  IF p_target_uid IS NULL OR p_target_uid = v_uid THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: a different target user is required' USING ERRCODE = '22023';
  END IF;
  IF NOT (private.is_admin(p_target_uid)
          OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_target_uid AND m.revoked_at IS NULL AND m.role = 'operator')) THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: the target must be an operator or an admin' USING ERRCODE = '42501';
  END IF;
  v_status := private.partner_totp_reset_apply(p_target_uid);
  PERFORM private.partner_sessions_revoke('user', p_target_uid, 'totp_reset');
  PERFORM private.partner_audit_write('partner.totp.reset', 'app.partner_totp', p_target_uid::text,
    pg_catalog.jsonb_build_object('status', v_status));
  RETURN QUERY SELECT v_status;
END
$$;

-- 5e. Ops bootstrap of the first admin enrolment token (6.4, M4). EXECUTE for nobody: run from a SQL session as private_definer after inserting admin_user.
CREATE FUNCTION private.partner_admin_bootstrap_token(p_user_id uuid, p_token_hash text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_id uuid;
BEGIN
  -- Check 14 (a0) refuses any dollar-sign in a *_for_partner body (comments included); keep this ops twin clean the same way.
  IF p_user_id IS NULL OR p_token_hash IS NULL
     OR pg_catalog.char_length(p_token_hash) <> 64
     OR p_token_hash !~ '^[0-9a-f]{64}' THEN
    RAISE EXCEPTION 'partner_admin_bootstrap_token: a user id and a 64-hex token hash are required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = p_user_id) THEN
    RAISE EXCEPTION 'partner_admin_bootstrap_token: the user does not exist' USING ERRCODE = '22023';
  END IF;
  IF NOT private.is_admin(p_user_id) THEN
    RAISE EXCEPTION 'partner_admin_bootstrap_token: the user must already be in app.admin_user' USING ERRCODE = '42501';
  END IF;
  INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, expires_at)
  VALUES (p_user_id, 'admin', NULL, p_token_hash, pg_catalog.clock_timestamp() + interval '24 hours')
  RETURNING id INTO v_id;
  RETURN v_id;
END
$$;

-- 5f. POST admin/enrolments (class A3): an admin issues an admin enrolment token for a different admin.
CREATE FUNCTION private.partner_admin_enrolment_issue_for_partner(p_user_id uuid, p_token_hash text)
RETURNS TABLE (o_status text, o_token_id uuid, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_id uuid;
  v_exp timestamptz;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_admin_enrolment_issue_for_partner: only an admin may issue an admin enrolment token' USING ERRCODE = '42501';
  END IF;
  -- Check 14 (a0): no dollar-sign in the body; length + anchored-prefix regex is the 64-hex check.
  IF p_user_id IS NULL OR p_user_id = v_uid OR p_token_hash IS NULL
     OR pg_catalog.char_length(p_token_hash) <> 64
     OR p_token_hash !~ '^[0-9a-f]{64}' THEN
    RAISE EXCEPTION 'partner_admin_enrolment_issue_for_partner: a different target user and a 64-hex token hash are required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.is_admin(p_user_id) THEN
    RAISE EXCEPTION 'partner_admin_enrolment_issue_for_partner: the target must be in app.admin_user' USING ERRCODE = '42501';
  END IF;
  v_exp := pg_catalog.clock_timestamp() + interval '24 hours';
  INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, expires_at)
  VALUES (p_user_id, 'admin', v_uid, p_token_hash, v_exp)
  RETURNING id INTO v_id;
  PERFORM private.partner_audit_write('partner.admin.enrolment_issue', 'app.partner_enrolment_token', v_id::text,
    pg_catalog.jsonb_build_object('target', p_user_id));
  RETURN QUERY SELECT 'ok'::text, v_id, v_exp;
END
$$;

-- 5g. Lock (0049), REDEFINED: also clears mfa_until through the totp-verifier-owned clearer (18.4).
CREATE OR REPLACE FUNCTION private.partner_session_lock_for_partner()
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
  PERFORM private.partner_totp_mfa_clear();
  UPDATE app.partner_session s SET otp_proof_until = NULL WHERE s.id = v_sid AND s.otp_proof_until IS NOT NULL;
END
$$;

-- 5h. Reclass otp-proof / otp-target / reauth to A0_ENROL (PA-28: reachable at aal 1 only while no confirmed TOTP; refused once confirmed).
-- GET pin stays A0 (staff/manager only; PA-28 does not list it; read-only, no FOR NO KEY UPDATE).
CREATE OR REPLACE FUNCTION private.partner_session_otp_target_for_partner()
RETURNS TABLE (o_email text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0_ENROL');
  RETURN QUERY SELECT pg_catalog.lower(pg_catalog.btrim(u.email))::text FROM auth.users u WHERE u.id = v_uid;
END
$$;

CREATE OR REPLACE FUNCTION private.partner_session_otp_proof_for_partner(p_gotrue_session_id uuid)
RETURNS TABLE (o_status text, o_otp_proof_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
  v_until timestamptz;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0_ENROL');
  v_sid := private.partner_binding_session();
  IF p_gotrue_session_id IS NULL THEN
    RAISE EXCEPTION 'partner_session_otp_proof_for_partner: a GoTrue session id is required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.sessions g
                 WHERE g.id = p_gotrue_session_id AND g.user_id = v_uid
                   AND g.created_at >= pg_catalog.clock_timestamp() - interval '60 seconds' AND g.created_at <= pg_catalog.clock_timestamp() + interval '60 seconds') THEN
    RETURN QUERY SELECT 'refused'::text, NULL::timestamptz;
    RETURN;
  END IF;
  UPDATE app.partner_session s SET otp_proof_until = pg_catalog.clock_timestamp() + interval '10 minutes', otp_proof_gotrue_session_id = p_gotrue_session_id
  WHERE s.id = v_sid
  RETURNING s.otp_proof_until INTO v_until;
  RETURN QUERY SELECT 'ok'::text, v_until;
END
$$;

CREATE OR REPLACE FUNCTION private.partner_session_reauth_options_for_partner()
RETURNS TABLE (o_nonce bytea, o_exp bigint, o_mac bytea, o_rp_id text, o_origin text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0_ENROL');
  v_sid := private.partner_binding_session();
  o_nonce := public.gen_random_bytes(32);
  o_exp := pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint + 120;
  SELECT c.o_mac INTO o_mac FROM private.partner_challenge_core(3::smallint, o_exp, o_nonce, v_sid, NULL) c;
  SELECT r.o_rp_id, r.o_origin INTO o_rp_id, o_origin FROM private.partner_rp_config_read() r;
  RETURN NEXT;
END
$$;

CREATE OR REPLACE FUNCTION private.partner_session_reauth_credential_for_partner(p_credential_id bytea)
RETURNS TABLE (o_credential_id uuid, o_user_id uuid, o_alg smallint, o_public_key bytea, o_sign_count bigint, o_rp_id text, o_origin text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0_ENROL');
  RETURN QUERY SELECT r.* FROM private.partner_reauth_credential_read(private.partner_binding_session(), p_credential_id) r;
END
$$;

CREATE OR REPLACE FUNCTION private.partner_session_reauth_for_partner(
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
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0_ENROL');
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
-- 6. EXECUTE grants (PUBLIC revoked first). Each as its OWNER.
-- ============================================================================
SET ROLE partner_totp_verifier;
REVOKE EXECUTE ON FUNCTION
  private.partner_totp_confirmed(uuid),
  private.partner_totp_attempt(uuid, text),
  private.partner_totp_verify_apply(text),
  private.partner_totp_enrol_apply(),
  private.partner_totp_confirm_apply(text),
  private.partner_totp_mfa_clear(),
  private.partner_totp_reset_apply(uuid)
FROM PUBLIC;
-- partner_totp_confirmed: private_definer only (partner_authorize). attempt: nobody. The apply/clear/reset writers: private_definer.
GRANT EXECUTE ON FUNCTION private.partner_totp_confirmed(uuid) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_totp_verify_apply(text) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_totp_enrol_apply() TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_totp_confirm_apply(text) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_totp_mfa_clear() TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_totp_reset_apply(uuid) TO private_definer;
COMMENT ON FUNCTION private.partner_totp_confirmed(uuid) IS
  '0053 (PA-28, 4.1). Owned by partner_totp_verifier so FORCE RLS lets it see the row. True iff the person holds a confirmed non-revoked TOTP; STABLE; called from partner_authorize. EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_totp_verify_apply(text) IS
  '0053 (R5-L1, 6.4). Owned by partner_totp_verifier, the only role that can write app.partner_session.aal and mfa_until. Evaluates the bound person''s TOTP (partner_totp_attempt: lock, window +/-1, replay, counters, all a returned STATUS) and sets aal=2 and mfa_until=now+5min only on ok. EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_totp_enrol_apply() IS
  '0053 (PA-24, 6.4). Owned by partner_totp_verifier. Bumps seed_version, clears confirmed_at, sets enrol_session_id; refuses once confirmed; needs enrolment_until or otp_proof_until. Returns the derived seed once plus otpauth params. EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_totp_confirm_apply(text) IS
  '0053 (PA-24, 6.4). Owned by partner_totp_verifier. Confirms the bound person''s unconfirmed TOTP in the same session that enrolled; sets confirmed_at. EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_totp_mfa_clear() IS
  '0053 (18.4). Owned by partner_totp_verifier. Clears mfa_until on the bound session (called from partner_session_lock_for_partner). EXECUTE for private_definer only.';
RESET ROLE;

SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION
  private.hotp(bytea, bigint, integer, text),
  private.partner_totp_seed_derive(uuid, integer),
  private.partner_is_pinless_elevated(uuid),
  private.partner_totp_enrol_for_partner(),
  private.partner_totp_confirm_for_partner(text),
  private.partner_totp_verify_for_partner(text),
  private.partner_totp_reset_for_partner(uuid),
  private.partner_admin_bootstrap_token(uuid, text),
  private.partner_admin_enrolment_issue_for_partner(uuid, text)
FROM PUBLIC;
-- cores: partner_totp_verifier (+ owner). pinless: nobody (sibling definers only). bootstrap: nobody.
GRANT EXECUTE ON FUNCTION private.hotp(bytea, bigint, integer, text) TO partner_totp_verifier;
GRANT EXECUTE ON FUNCTION private.partner_totp_seed_derive(uuid, integer) TO partner_totp_verifier;
GRANT EXECUTE ON FUNCTION private.partner_binding_user() TO partner_totp_verifier;
GRANT EXECUTE ON FUNCTION private.is_admin(uuid) TO partner_totp_verifier;
-- the partner lane
GRANT EXECUTE ON FUNCTION private.partner_totp_enrol_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_totp_confirm_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_totp_verify_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_totp_reset_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_admin_enrolment_issue_for_partner(uuid, text) TO edge_partner;
COMMENT ON FUNCTION private.partner_authorize(text, text, app.partner_role[], text) IS
  '0047, 0052, 0053. Executable by NOBODY (called from sibling definers; every *_for_partner function must call it as its first statement: check 14). Locks the bound session row only (FOR NO KEY UPDATE for A1, A2, A3, A0_WRITE, A0_MFA, A0_ENROL, SESSION and a stale idle bump; FOR SHARE otherwise), re-reads session / role / scope / aal / mfa_until on every call, enforces the class prerequisite (A1: PIN grant or PIN-less A3; A2: reauth + PIN-fresh or PIN-less A3; A3: aal2 + mfa_until; A0_MFA / A0_ENROL aal exceptions per 4.1), returns the member''s uid.';
COMMENT ON FUNCTION private.hotp(bytea, bigint, integer, text) IS
  '0053 (6.4, N6, PA-20). RFC 4226 HOTP over public.hmac: 8-byte BE counter, dynamic truncation, mod 10^digits. Algo sha1|sha256; digits 6..8. Shared primitive with the offline code; each caller picks the parameter set. EXECUTE for partner_totp_verifier and its owner private_definer.';
COMMENT ON FUNCTION private.partner_totp_seed_derive(uuid, integer) IS
  '0053 (5.1, 6.4). The ONLY reader of Vault secret partner_totp_key: HMAC-SHA256(key, golfraven/partner-totp/v1 || 0x00 || user_id_16 || int4send(version)). EXECUTE for partner_totp_verifier and its owner private_definer; the seed is never returned except through enrol_apply.';
COMMENT ON FUNCTION private.partner_admin_bootstrap_token(uuid, text) IS
  '0053 (6.4, M4). Ops bootstrap of the first admin enrolment token (purpose=admin, issued_by NULL, 24 h). EXECUTE for nobody: run from a SQL session as private_definer after inserting app.admin_user.';
RESET ROLE;

-- R5-L3: the migrating role keeps NO way to become the owner role
REVOKE partner_totp_verifier FROM CURRENT_USER;

-- ============================================================================
-- 7. Registries
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'hotp', 'p_seed bytea, p_counter bigint, p_digits integer, p_algo text', false, false, false, false, false, false, false, '0053 (PA-20): RFC 4226 HOTP over public.hmac; EXECUTE for partner_totp_verifier and its owner private_definer'),
  ('private', 'partner_totp_seed_derive', 'p_user_id uuid, p_seed_version integer', false, false, false, false, false, false, false, '0053: the ONLY reader of Vault secret partner_totp_key; EXECUTE for partner_totp_verifier and its owner private_definer; the seed is never logged'),
  ('private', 'partner_totp_confirmed', 'p_uid uuid', false, false, false, false, false, false, false, '0053 (PA-28): owned by partner_totp_verifier; true iff the person holds a confirmed non-revoked TOTP; STABLE; called from partner_authorize; EXECUTE for private_definer only'),
  ('private', 'partner_is_pinless_elevated', 'p_uid uuid', false, false, false, false, false, false, false, '0053 (6.3): admin or active operator with no staff/manager membership; A1/A2 substitution by A3; EXECUTE for nobody'),
  ('private', 'partner_totp_attempt', 'p_uid uuid, p_code text', false, false, false, false, false, false, false, '0053: owned by partner_totp_verifier; ONE attempt against a confirmed TOTP: lock, window +/-1, replay, counters; every outcome a status; EXECUTE for nobody'),
  ('private', 'partner_totp_verify_apply', 'p_code text', false, false, false, false, false, false, false, '0053 (R5-L1): owned by partner_totp_verifier; sets aal=2 and mfa_until=now+5min on the bound session only on ok; EXECUTE for private_definer only'),
  ('private', 'partner_totp_enrol_apply', '', false, false, false, false, false, false, false, '0053 (PA-24): owned by partner_totp_verifier; bumps seed_version, gated by enrolment/otp proof; returns seed once; EXECUTE for private_definer only'),
  ('private', 'partner_totp_confirm_apply', 'p_code text', false, false, false, false, false, false, false, '0053 (PA-24): owned by partner_totp_verifier; confirm in the enrolling session; EXECUTE for private_definer only'),
  ('private', 'partner_totp_mfa_clear', '', false, false, false, false, false, false, false, '0053 (18.4): owned by partner_totp_verifier; clears mfa_until on the bound session; EXECUTE for private_definer only'),
  ('private', 'partner_totp_reset_apply', 'p_target uuid', false, false, false, false, false, false, false, '0053: owned by partner_totp_verifier; admin reset of another person''s TOTP (bump version, clear confirmed); EXECUTE for private_definer only'),
  ('private', 'partner_totp_enrol_for_partner', '', false, false, false, false, false, true, false, '0053: edge_partner only; POST totp/enrol: class A0_ENROL (operator); spends otp_proof on ok; returns seed bytea + otpauth params'),
  ('private', 'partner_totp_confirm_for_partner', 'p_code text', false, false, false, false, false, true, false, '0053: edge_partner only; POST totp/confirm: class A0_ENROL; spends otp_proof on ok'),
  ('private', 'partner_totp_verify_for_partner', 'p_code text', false, false, false, false, false, true, false, '0053: edge_partner only; POST step-up/totp: class A0_MFA; sets aal 2 and mfa_until on ok; audit wrong/locked'),
  ('private', 'partner_totp_reset_for_partner', 'p_target_uid uuid', false, false, false, false, false, true, false, '0053: edge_partner only; POST members/totp-reset: class A3; admin only; lite reach (S1.5 full); revokes target sessions'),
  ('private', 'partner_admin_bootstrap_token', 'p_user_id uuid, p_token_hash text', false, false, false, false, false, false, false, '0053 (6.4, M4): ops bootstrap of an admin enrolment token; EXECUTE for nobody'),
  ('private', 'partner_admin_enrolment_issue_for_partner', 'p_user_id uuid, p_token_hash text', false, false, false, false, false, true, false, '0053: edge_partner only; POST admin/enrolments: class A3; admin issues an admin enrolment token for a different admin');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0053 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_totp', 'ptv_read_partner_totp', 'SELECT', true, 'S1.4: the TOTP verifier reads the BOUND person''s own row, or any row when the bound user is an admin (reset); keyed on private.partner_binding_user() / is_admin, never a settable value', 'partner_totp_verifier'),
  ('app', 'partner_totp', 'ptv_insert_partner_totp', 'INSERT', true, 'S1.4: the first TOTP row of the BOUND person only (WITH CHECK keyed on the binding)', 'partner_totp_verifier'),
  ('app', 'partner_totp', 'ptv_update_partner_totp', 'UPDATE', true, 'S1.4: counters / enrol / confirm of the BOUND person, or admin reset of another; USING and WITH CHECK keyed on the binding / is_admin', 'partner_totp_verifier'),
  ('app', 'partner_totp', 'pd_delete_partner_totp_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_totp.user_id = delete_row); the 0016 GUC window, DELETE ONLY, closed under a partner binding (0047 8a, check 15)', 'private_definer'),
  ('app', 'partner_totp', 'pd_delete_partner_totp_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_partner_totp_user_id; also delete_my_data''s post-condition count (column-level SELECT grant on user_id)', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_insert_partner_enrolment_token_admin', 'INSERT', true, 'S1.4: admin enrolment token insert (bootstrap with issued_by NULL outside a partner binding, or issued_by = bound user under a partner binding); purpose=admin only', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND pol.polname IN ('ptv_read_partner_totp', 'ptv_insert_partner_totp', 'ptv_update_partner_totp',
                      'pd_delete_partner_totp_user_id', 'pd_delete_partner_totp_user_id_r',
                      'pd_insert_partner_enrolment_token_admin');
DO $assert_0053_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN ('ptv_read_partner_totp', 'ptv_insert_partner_totp', 'ptv_update_partner_totp',
                            'pd_delete_partner_totp_user_id', 'pd_delete_partner_totp_user_id_r',
                            'pd_insert_partner_enrolment_token_admin')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 6 THEN
    RAISE EXCEPTION '0053: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0053_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0053 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

CREATE POLICY current_user_seed_partner_owner_privilege_0053 ON private.partner_owner_privilege
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.partner_owner_privilege (role_name, object_kind, object_name, privilege, column_name) VALUES
  ('partner_totp_verifier', 'relation', 'app.partner_totp', 'SELECT', NULL),
  ('partner_totp_verifier', 'relation', 'app.partner_totp', 'INSERT', NULL),
  ('partner_totp_verifier', 'relation', 'app.partner_totp', 'UPDATE', NULL),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'SELECT', 'enrolment_until'),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'SELECT', 'otp_proof_until'),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'SELECT', 'user_id'),
  ('partner_totp_verifier', 'function', 'private.partner_binding_user()', 'EXECUTE', NULL),
  ('partner_totp_verifier', 'function', 'private.hotp(bytea,bigint,integer,text)', 'EXECUTE', NULL),
  ('partner_totp_verifier', 'function', 'private.partner_totp_seed_derive(uuid,integer)', 'EXECUTE', NULL),
  ('partner_totp_verifier', 'function', 'private.is_admin(uuid)', 'EXECUTE', NULL);
-- note: partner_totp_confirmed is owned by partner_totp_verifier; its EXECUTE grant to private_definer is an outbound grant from the owner role, not an inbound privilege of the owner (not listed here)
DROP POLICY current_user_seed_partner_owner_privilege_0053 ON private.partner_owner_privilege;

GRANT INSERT ON private.pii_retention_policy TO CURRENT_USER;
CREATE POLICY current_user_seed_pii_retention_policy_0053 ON private.pii_retention_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'partner_totp', 'user_id', 'delete_row', 'the person''s own TOTP enrolment state and lockout counters (0053): deleted with the account by delete_my_data''s generic pass (and by FK cascade with the auth user)');
DROP POLICY current_user_seed_pii_retention_policy_0053 ON private.pii_retention_policy;
REVOKE INSERT ON private.pii_retention_policy FROM CURRENT_USER;

CREATE POLICY current_user_seed_pii_export_policy_0053 ON private.pii_export_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_export_policy (schema_name, table_name, action, reason) VALUES
  ('app', 'partner_totp', 'exclude', 'a login artefact: derived-seed version, confirmation timestamps and lockout counters, not the subject''s own data (the seed itself is never stored)');
DROP POLICY current_user_seed_pii_export_policy_0053 ON private.pii_export_policy;

-- ============================================================================
-- 8. Prove the grants
-- ============================================================================
DO $assert_0053_grants$
DECLARE
  v_role text;
  v_fn regprocedure;
  v_bad text;
  v_lane regprocedure[] := ARRAY[
    'private.partner_totp_enrol_for_partner()'::regprocedure,
    'private.partner_totp_confirm_for_partner(text)'::regprocedure,
    'private.partner_totp_verify_for_partner(text)'::regprocedure,
    'private.partner_totp_reset_for_partner(uuid)'::regprocedure,
    'private.partner_admin_enrolment_issue_for_partner(uuid, text)'::regprocedure];
  v_helpers regprocedure[] := ARRAY[
    'private.hotp(bytea, bigint, integer, text)'::regprocedure,
    'private.partner_totp_seed_derive(uuid, integer)'::regprocedure,
    'private.partner_totp_confirmed(uuid)'::regprocedure,
    'private.partner_is_pinless_elevated(uuid)'::regprocedure,
    'private.partner_totp_attempt(uuid, text)'::regprocedure,
    'private.partner_totp_verify_apply(text)'::regprocedure,
    'private.partner_totp_enrol_apply()'::regprocedure,
    'private.partner_totp_confirm_apply(text)'::regprocedure,
    'private.partner_totp_mfa_clear()'::regprocedure,
    'private.partner_totp_reset_apply(uuid)'::regprocedure,
    'private.partner_admin_bootstrap_token(uuid, text)'::regprocedure];
  -- helpers = no edge/client EXECUTE; confirmed is granted to private_definer only (asserted below)
BEGIN
  IF EXISTS (SELECT 1 FROM unnest(v_lane || v_helpers) f(oid) JOIN pg_proc p ON p.oid = f.oid WHERE NOT p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=""']) THEN
    RAISE EXCEPTION '0053: a new function is not SECURITY DEFINER with search_path=''''';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(ARRAY[
      'private.partner_totp_confirmed(uuid)', 'private.partner_totp_attempt(uuid, text)', 'private.partner_totp_verify_apply(text)', 'private.partner_totp_enrol_apply()',
      'private.partner_totp_confirm_apply(text)', 'private.partner_totp_mfa_clear()', 'private.partner_totp_reset_apply(uuid)']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'partner_totp_verifier'::regrole) THEN
    RAISE EXCEPTION '0053: a verifier function is not owned by partner_totp_verifier';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(v_lane || ARRAY[
      'private.hotp(bytea, bigint, integer, text)', 'private.partner_totp_seed_derive(uuid, integer)',
      'private.partner_is_pinless_elevated(uuid)',
      'private.partner_admin_bootstrap_token(uuid, text)']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'private_definer'::regrole) THEN
    RAISE EXCEPTION '0053: a private_definer function is not owned by private_definer';
  END IF;
  FOREACH v_fn IN ARRAY v_lane LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated', 'partner_totp_verifier', 'partner_pin_verifier'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0053: % can execute %; only edge_partner may', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_partner', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0053: edge_partner cannot execute %', v_fn;
    END IF;
  END LOOP;
  FOREACH v_fn IN ARRAY v_helpers LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0053: % can execute the helper %', v_role, v_fn;
      END IF;
    END LOOP;
  END LOOP;
  IF NOT (has_function_privilege('partner_totp_verifier', 'private.partner_binding_user()'::regprocedure, 'EXECUTE')
          AND has_function_privilege('partner_totp_verifier', 'private.hotp(bytea, bigint, integer, text)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('partner_totp_verifier', 'private.partner_totp_seed_derive(uuid, integer)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('partner_totp_verifier', 'private.is_admin(uuid)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_totp_confirmed(uuid)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_totp_verify_apply(text)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_totp_enrol_apply()'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_totp_confirm_apply(text)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_totp_mfa_clear()'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_totp_reset_apply(uuid)'::regprocedure, 'EXECUTE')) THEN
    RAISE EXCEPTION '0053: an internal EXECUTE grant did not take effect';
  END IF;
  IF has_function_privilege('private_definer', 'private.partner_totp_attempt(uuid, text)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0053: private_definer can execute partner_totp_attempt';
  END IF;
  FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated', 'service_role', 'edge_actor', 'edge_system', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'partner_pin_verifier', 'partner_reauth_verifier', 'partner_session_issuer', 'partner_session_toucher'] LOOP
    IF has_any_column_privilege(v_role, 'app.partner_totp', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(v_role, 'app.partner_totp', 'DELETE,TRUNCATE,TRIGGER') THEN
      RAISE EXCEPTION '0053: % holds a privilege on app.partner_totp', v_role;
    END IF;
  END LOOP;
  IF NOT (has_table_privilege('partner_totp_verifier', 'app.partner_totp', 'SELECT') AND has_table_privilege('partner_totp_verifier', 'app.partner_totp', 'INSERT')
          AND has_table_privilege('partner_totp_verifier', 'app.partner_totp', 'UPDATE') AND NOT has_table_privilege('partner_totp_verifier', 'app.partner_totp', 'DELETE')) THEN
    RAISE EXCEPTION '0053: a grant the TOTP table needs did not take effect, or partner_totp_verifier can delete';
  END IF;
  IF has_any_column_privilege('private_definer', 'app.partner_totp', 'INSERT,UPDATE,REFERENCES') OR NOT has_column_privilege('private_definer', 'app.partner_totp', 'user_id', 'SELECT')
     OR has_column_privilege('private_definer', 'app.partner_totp', 'seed_version', 'SELECT') THEN
    RAISE EXCEPTION '0053: private_definer holds more than SELECT (user_id) and DELETE on app.partner_totp';
  END IF;
  SELECT string_agg(c.relname, ', ') INTO v_bad FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND (has_any_column_privilege('edge_partner_minter', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_partner_minter', c.oid, 'DELETE,TRUNCATE,TRIGGER'));
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0053: edge_partner_minter holds a relation privilege: %', v_bad;
  END IF;
  IF has_column_privilege('private_definer', 'app.partner_session', 'aal', 'UPDATE')
     OR has_column_privilege('private_definer', 'app.partner_session', 'mfa_until', 'UPDATE')
     OR NOT has_column_privilege('partner_totp_verifier', 'app.partner_session', 'aal', 'UPDATE')
     OR NOT has_column_privilege('partner_totp_verifier', 'app.partner_session', 'mfa_until', 'UPDATE') THEN
    RAISE EXCEPTION '0053: aal/mfa_until are not writable by partner_totp_verifier alone';
  END IF;
  FOREACH v_role IN ARRAY ARRAY['edge_partner', 'edge_actor', 'edge_system', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated', 'partner_totp_verifier'] LOOP
    IF has_function_privilege(v_role, 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure, 'EXECUTE') THEN
      RAISE EXCEPTION '0053: % can execute partner_authorize', v_role;
    END IF;
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                 WHERE n.nspname = 'private' AND p.proname = 'partner_totp_confirmed' AND p.prosecdef AND p.provolatile = 's'
                   AND p.proowner = 'partner_totp_verifier'::regrole) THEN
    RAISE EXCEPTION '0053: partner_totp_confirmed is missing, not STABLE SECURITY DEFINER, or not owned by partner_totp_verifier';
  END IF;
END
$assert_0053_grants$;
