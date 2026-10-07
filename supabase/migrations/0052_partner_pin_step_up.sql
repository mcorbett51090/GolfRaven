-- 0052_partner_pin_step_up.sql
--
-- P5.1a, slice S1.3: THE PARTNER (STAFF) STEP-UP PIN. docs/security/partner-auth-design.md (revision 5, the S0 gate ruling, 16.2 / 16.5 / 17.8 / 18.4 above all) is the specification: section 6.3 (the PIN, the class
-- table A0 to A3, the departures D8 and N1), 4.3 (R5-L1: the verifier ROLE is the verification fact), 5.1 (`partner_pin`, the Vault pepper), 5.3 (a counter-writing definer returns a STATUS, never raises: the 0020
-- lesson), 8 (rate limits), 11 (R-P2) and 12.1 (PA-18, PA-19, PA-21). Migrations 0001-0049 are untouched; everything below is CREATE except one CREATE OR REPLACE (partner_authorize, section 2).
--
-- WHAT THIS ADDS
--   1. app.partner_pin (section 3): one row per person. The browser derives PBKDF2-HMAC-SHA256(PIN, salt, iterations) and sends ONLY the derived 32 bytes; the database stores
--      verifier = HMAC-SHA256(Vault pepper `partner_pin_pepper`, "golfraven/partner-pin/v1" || 0x00 || user id (16) || derived (32)), compares, counts failures and applies the lockout. FORCE RLS; no client, edge or
--      service_role privilege; written only by definers OWNED by partner_pin_verifier (the role that also owns the only writer of pin_grant_until, R5-L1).
--   2. The VERIFY definer (partner_pin_verify_apply): status `ok | wrong | locked | retry_after | unset | must_change`, never a RAISE (the failure counter COMMITS with the refusal). The row is locked FOR UPDATE, so N
--      concurrent attempts are evaluated one at a time. After the 3rd consecutive failure the next attempt is refused for 30 s, after the 4th for 5 min, the 5th LOCKS the PIN (a correct PIN on attempt 6 is still
--      refused); 20 failures in a (UTC) day lock whatever succeeded between them. A lock survives new sessions; only a manager's reset clears it (S1.5: the seam is stated below). On `ok` it sets the bound session's
--      pin_grant_until = now + 60 s (the S1.1a guard caps it at 60 s): a single-use, SESSION-BOUND grant.
--   3. The SET / CHANGE definer (partner_pin_set_apply): a PIN is set or changed ONLY inside an enrolment window (`enrolment_until`, the register session) or after an email proof (`otp_proof_until`); a passkey assertion
--      alone is refused (PA-21, 42501). A CHANGE of a live PIN also needs the current PIN (counted exactly like a verify). A `must_change` PIN (after a reset) is replaced under the proof, no current PIN. A LOCKED PIN is
--      never replaced here: a lock is cleared by a manager's reset, not by the person (else the lockout would protect nothing).
--   4. partner_authorize (CREATE OR REPLACE, same owner, ACL and signature): class A1 still consumes a PIN grant; class A2 is now ENABLED: A0 + a PIN grant AT MOST 30 s OLD (consumed) + reauth_until > now (a passkey
--      assertion at most 5 min old). Class A3 STILL FAILS CLOSED (S1.4). The A3-for-a-PIN-less-operator substitution of 6.3 is S1.4's and is NOT built: an operator or admin with no staff or manager role cannot set a PIN here (the
--      set definer authorises {staff, manager}), so A1 / A2 refuse them until S1.4.
--   5. The `_for_partner` family (edge_partner only; each begins with private.partner_authorize, check 14): partner_pin_params_for_partner, partner_pin_verify_for_partner, partner_pin_set_for_partner,
--      partner_pin_change_for_partner, partner_session_otp_target_for_partner, partner_session_otp_proof_for_partner. The OTP proof (6.1, 6.3): the Edge sends the email OTP to the member's OWN address
--      (partner_session_otp_target_for_partner), verifies it with GoTrue (anon key), and passes the GoTrue session id here; the S1.1a guard checks that it exists for THIS user and is fresh and the UNIQUE index lets one
--      GoTrue session prove at most one proof (the 0041 shape).
--
-- WHAT THIS DOES NOT BUILD (the seams stay intact): the manager's PIN RESET (S1.5: `partner_pin_reset_for_partner` needs the reach rule of 6.5, which is S1.5's; it will set must_change and clear the lock and counters
-- through its own writer, owned by a role whose policy is added and reviewed against the union at that time); the delete of a PIN row on the last-membership revoke (PA-29, S1.5, with the revoke flows); TOTP and the A3
-- class (S1.4); the aal-1 exception that lets a TOTP-less operator or admin reach otp-proof and reauth (S1.4, 4.1); pepper rotation (pepper_kid is stored and constant 'v1').
--
-- DEPARTURES: see the design doc, 19.3.

-- ============================================================================
-- 1. The owner role this file writes functions for: the migrating role holds SET on it for the length of this file only (the 0047 / 0048 / 0049 bracket, R5-L3)
-- ============================================================================
GRANT partner_pin_verifier TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;

-- ============================================================================
-- 2. partner_authorize: class A2 ENABLED (A3 still fails closed). The body is 0047's, with exactly the A2 prerequisite added and the A2 fail-closed line removed.
-- ============================================================================
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
BEGIN
  IF p_class IS NULL OR p_class NOT IN ('SESSION', 'PEEK', 'A0', 'A0_KEEPALIVE', 'A1', 'A2', 'A3') THEN
    RAISE EXCEPTION 'partner_authorize: unknown action class' USING ERRCODE = '22023';
  END IF;
  -- 0. READ COMMITTED only (S1.1a gate, NIT): every guarantee below (a revoke that committed while we waited for the lock is SEEN by the next statement; the scope re-read) relies on a fresh
  -- snapshot per statement. A REPEATABLE READ or SERIALIZABLE transaction would read stale authority, so it is refused, fail closed.
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
  -- 5. fail CLOSED on a class whose prerequisite is not implemented yet (S1.3 enabled A2; S1.4 enables A3: A3 refuses everything, admin included, until then).
  -- Placed first on purpose: no later change to the checks below can relax it. No interim relaxation is allowed (PA-4b).
  IF p_class = 'A3' THEN
    RAISE EXCEPTION 'partner_authorize: class % is not enabled (fails closed until its prerequisite exists)', p_class USING ERRCODE = '42501';
  END IF;
  IF p_class NOT IN ('SESSION', 'PEEK') AND (p_roles IS NULL OR cardinality(p_roles) = 0 OR p_roles && ARRAY['sponsor']::app.partner_role[]) THEN
    RAISE EXCEPTION 'partner_authorize: an explicit, non-empty role list without sponsor is required' USING ERRCODE = '22023';
  END IF;
  -- 2. lock the session row FIRST, and ONLY it (R3-M1 option a). FOR SHARE for a call that will not write it, FOR NO KEY UPDATE for a call that will (two FOR SHARE
  -- holders that both then UPDATE deadlock). The policy this needs is pd_partner_session_action (a lock is invisible without it under FORCE RLS, R2-M2).
  SELECT s.last_seen_at INTO v_s FROM app.partner_session s WHERE s.id = v_sid;
  v_write := p_class IN ('A1', 'A2') OR (p_class NOT IN ('A0_KEEPALIVE', 'PEEK') AND (v_s.last_seen_at IS NULL OR v_s.last_seen_at < clock_timestamp() - interval '1 minute'));
  IF v_write THEN
    SELECT s.user_id, s.credential_id, s.aal, s.last_seen_at, s.expires_at, s.revoked_at, s.reauth_until INTO v_s
    FROM app.partner_session s WHERE s.id = v_sid FOR NO KEY UPDATE;
  ELSE
    SELECT s.user_id, s.credential_id, s.aal, s.last_seen_at, s.expires_at, s.revoked_at, s.reauth_until INTO v_s
    FROM app.partner_session s WHERE s.id = v_sid FOR SHARE;
  END IF;
  -- a session that is not visible or not lockable is not live (0 rows, never an error: R2-M2)
  IF NOT FOUND OR v_s.user_id IS DISTINCT FROM v_uid THEN
    RAISE EXCEPTION 'partner_authorize: the session is not live' USING ERRCODE = '42501';
  END IF;
  -- a concurrent revoke that committed while we waited for the lock is seen here (READ COMMITTED: a fresh snapshot per statement)
  IF v_s.revoked_at IS NOT NULL OR v_s.expires_at <= clock_timestamp() OR NOT private.partner_credential_live(v_s.credential_id) THEN
    RAISE EXCEPTION 'partner_authorize: the session is not live' USING ERRCODE = '42501';
  END IF;
  -- 3. role and scope are re-read NOW, with the session row already locked, through the helpers and an EXPLICIT role array (never partner_role_rank, whose sponsor
  -- ties operator at 3). A revoker's / scope changer's trigger cannot touch the locked session: it waits for this transaction or is seen by it.
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
    -- 4. aal gates EVERY class including A0 (M2): an aal 1 session of an operator or admin is refused
    IF v_s.aal < v_pol.required_aal THEN
      RAISE EXCEPTION 'partner_authorize: the session''s assurance level is below the member''s required level' USING ERRCODE = '42501';
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
    -- the class prerequisite, consuming any single-use PIN grant in THIS transaction (a refused call rolls the consumption back with everything else).
    -- A1: a PIN verified in the last 60 s and not yet used. A2 (6.3): a PIN verified in the last 30 s and not yet used, AND a passkey assertion at most 5 minutes old (reauth_until).
    IF p_class = 'A1' AND NOT private.partner_pin_grant_consume() THEN
      RAISE EXCEPTION 'partner_authorize: a PIN verified in the last minute and not yet used is required' USING ERRCODE = '42501';
    END IF;
    IF p_class = 'A2' THEN
      IF v_s.reauth_until IS NULL OR v_s.reauth_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'partner_authorize: a passkey assertion in the last 5 minutes is required' USING ERRCODE = '42501';
      END IF;
      IF NOT private.partner_pin_grant_consume_fresh(30) THEN
        RAISE EXCEPTION 'partner_authorize: a PIN verified in the last 30 seconds and not yet used is required' USING ERRCODE = '42501';
      END IF;
    END IF;
  END IF;
  -- idle is extended only by user-initiated calls, at most once a minute (4.2); A0_KEEPALIVE and PEEK never
  IF v_write AND p_class NOT IN ('A0_KEEPALIVE', 'PEEK') AND v_s.last_seen_at < clock_timestamp() - interval '1 minute' THEN
    UPDATE app.partner_session s SET last_seen_at = clock_timestamp() WHERE s.id = v_sid;
  END IF;
  RETURN v_uid;
END;
$$;

-- the binding's USER (never a settable value): the predicate inside the partner_pin policies of partner_pin_verifier. EXECUTE for the role whose policy calls it, nobody else.
CREATE FUNCTION private.partner_binding_user()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT b.actor_uid
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned() AND b.kind = 'partner'
$$;

-- THE core. The only place the Vault pepper `partner_pin_pepper` is read (the 0045 offline_seed_derive / 0048 partner_challenge_core shape). EXECUTE for partner_pin_verifier ONLY: it computes the verifier for ANY
-- (user, derived) it is handed, so no session may reach it. The message is labelled and FIXED WIDTH after the label (so no two different tuples produce the same bytes):
--     "golfraven/partner-pin/v1" (UTF-8) || 0x00 || user id (16 bytes) || derived (32 bytes)
-- and the verifier is HMAC-SHA256 under the pepper (at least 32 bytes). Binding the user id means a verifier row copied to another person verifies nothing. A presented verifier is compared as
-- HMAC(K, stored) = HMAC(K, computed), so the comparison never depends on a byte-by-byte equality of a secret-derived value (0048). The failure message names no key material (the Edge maps 55000 to a bare 503).
CREATE FUNCTION private.partner_pin_core(p_uid uuid, p_derived bytea, p_stored bytea)
RETURNS TABLE (o_verifier bytea, o_match boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
  v_k bytea;
  v_msg bytea;
BEGIN
  IF p_uid IS NULL OR p_derived IS NULL OR pg_catalog.octet_length(p_derived) <> 32 THEN
    RAISE EXCEPTION 'partner_pin_core: a user and a 32-byte derived key are required' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'partner_pin_pepper';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'partner_pin_core: the partner PIN pepper is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  v_k := pg_catalog.convert_to(v_key, 'UTF8');
  v_msg := pg_catalog.convert_to('golfraven/partner-pin/v1', 'UTF8')
        || pg_catalog.decode('00', 'hex')
        || pg_catalog.decode(pg_catalog.replace(p_uid::text, '-', ''), 'hex')
        || p_derived;
  o_verifier := public.hmac(v_msg, v_k, 'sha256');
  o_match := p_stored IS NOT NULL AND public.hmac(p_stored, v_k, 'sha256') = public.hmac(o_verifier, v_k, 'sha256');
  RETURN NEXT;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. app.partner_pin
-- ============================================================================
CREATE TABLE app.partner_pin (
  -- one PIN per PERSON (not per org): PIN is the only per-person factor (4.1)
  user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  -- the browser's PBKDF2 inputs (public to the member: GET pin returns them). 16 random bytes chosen by the browser at set time; the iteration count is stored per row so it can rise on the next set
  salt bytea NOT NULL CHECK (pg_catalog.octet_length(salt) = 16),
  iterations integer NOT NULL CHECK (iterations BETWEEN 210000 AND 1000000),
  -- which pepper computed the verifier (rotation is not built: constant 'v1')
  pepper_kid text NOT NULL DEFAULT 'v1' CHECK (pepper_kid ~ '^[a-z0-9_-]{1,32}$'),
  -- HMAC-SHA256(pepper, label || user id || derived): useless without the Vault pepper
  verifier bytea NOT NULL CHECK (pg_catalog.octet_length(verifier) = 32),
  -- consecutive failures (reset by a success); locked at 5. The row is locked FOR UPDATE by every attempt
  failed_count smallint NOT NULL DEFAULT 0 CHECK (failed_count BETWEEN 0 AND 5),
  -- failures in the UTC day `failed_day` (NOT reset by a success: 20 a day lock regardless)
  failed_today smallint NOT NULL DEFAULT 0 CHECK (failed_today BETWEEN 0 AND 20),
  failed_day date,
  last_failed_at timestamptz,
  -- while in the future, an attempt is refused WITHOUT being evaluated (30 s after the 3rd consecutive failure, 5 min after the 4th)
  next_attempt_at timestamptz,
  -- set by the 5th consecutive failure (or the 20th of the day): an attempt is refused until a manager's reset (S1.5) clears it; survives sessions
  locked_at timestamptz,
  -- a reset (S1.5) or a reactivation sets it: the verifier is dead and a NEW PIN must be set under an email proof
  must_change boolean NOT NULL DEFAULT false,
  last_ok_at timestamptz,
  set_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE app.partner_pin IS
  '0052 (design 5.1, 6.3). One row per person: the PBKDF2 inputs the browser needs (salt, iterations), HMAC(Vault pepper, label || user || derived key) as the verifier, and the failure / lockout state. FORCE RLS; no client, edge or service_role privilege. Written only by definers owned by partner_pin_verifier, each keyed on the bound session''s user; delete_my_data''s window pair is the only other path. The PIN itself never reaches the server.';
ALTER TABLE app.partner_pin ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.partner_pin FORCE ROW LEVEL SECURITY;
REVOKE ALL ON app.partner_pin FROM PUBLIC, anon, authenticated, service_role;

-- 3a. partner_pin_verifier: the whole table (it is the table's only reader and writer), behind three registered `ppv_*` policies keyed on the BINDING's user (never a settable GUC: the HARD RULE). The role is
-- a member of nothing and nobody can become it (checks 9 and 12). It also reads the two session columns a PIN set needs to see (the enrolment window and the OTP proof), through its existing own-session policy.
GRANT SELECT, INSERT, UPDATE ON app.partner_pin TO partner_pin_verifier;
GRANT SELECT (enrolment_until, otp_proof_until) ON app.partner_session TO partner_pin_verifier;
CREATE POLICY ppv_read_partner_pin ON app.partner_pin FOR SELECT TO partner_pin_verifier USING (user_id = private.partner_binding_user());
CREATE POLICY ppv_insert_partner_pin ON app.partner_pin FOR INSERT TO partner_pin_verifier WITH CHECK (user_id = private.partner_binding_user());
CREATE POLICY ppv_update_partner_pin ON app.partner_pin FOR UPDATE TO partner_pin_verifier USING (user_id = private.partner_binding_user()) WITH CHECK (user_id = private.partner_binding_user());

-- 3b. private_definer: the delete_my_data registry pass ONLY (DELETE and its SELECT companion on the delete_row column), the 0016 window form with the partner conjunct (0047 8a): under a partner binding the
-- window is CLOSED, so a planted app.delete_my_data.target_user_id cannot make another person's PIN row readable or deletable by a definer a partner transaction reaches (check 15). Nothing else.
GRANT SELECT (user_id), DELETE ON app.partner_pin TO private_definer;
CREATE POLICY pd_delete_partner_pin_user_id ON app.partner_pin
  FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_delete_partner_pin_user_id_r ON app.partner_pin
  FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');

-- ============================================================================
-- 4. The verifier-owned definers (R5-L1: the ROLE that owns the writer of pin_grant_until / of the verifier IS the verification fact)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_pin_verifier;
SET ROLE partner_pin_verifier;

-- 4a. ONE ATTEMPT against a person's PIN. Internal: EXECUTE for nobody (the verify and the change definers below, the same owner, call it). It LOCKS the person's row FOR UPDATE first, so N concurrent
-- attempts are evaluated strictly one after the other and the counter is exact. EVERY outcome is a returned STATUS (never a RAISE: the counter write must COMMIT, 0020):
--   unset        no PIN row                                    locked       the PIN is locked (5 consecutive failures, or 20 in a day): nothing is compared
--   must_change  a reset left the PIN dead                     retry_after  the backoff is running: refused WITHOUT being evaluated (o_retry_after = whole seconds left)
--   ok           the derived key matched (consecutive failures reset)
--   wrong        it did not match (o_retry_after = the backoff this failure started, 0 if none); o_newly_locked is true on the failure that locked the PIN, which then answers `locked`
CREATE FUNCTION private.partner_pin_attempt(p_uid uuid, p_derived bytea)
RETURNS TABLE (o_status text, o_retry_after integer, o_newly_locked boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_p record;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_day date := (pg_catalog.clock_timestamp() AT TIME ZONE 'UTC')::date;
  v_match boolean;
  v_fc integer;
  v_ft integer;
  v_next timestamptz;
BEGIN
  IF p_uid IS NULL OR p_derived IS NULL OR pg_catalog.octet_length(p_derived) <> 32 THEN
    RAISE EXCEPTION 'partner_pin_attempt: a user and a 32-byte derived key are required' USING ERRCODE = '22023';
  END IF;
  SELECT p.verifier, p.failed_count, p.failed_today, p.failed_day, p.next_attempt_at, p.locked_at, p.must_change INTO v_p
  FROM app.partner_pin p WHERE p.user_id = p_uid FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unset'::text, 0, false;
    RETURN;
  END IF;
  IF v_p.locked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'locked'::text, 0, false;
    RETURN;
  END IF;
  IF v_p.must_change THEN
    RETURN QUERY SELECT 'must_change'::text, 0, false;
    RETURN;
  END IF;
  IF v_p.next_attempt_at IS NOT NULL AND v_p.next_attempt_at > v_now THEN
    RETURN QUERY SELECT 'retry_after'::text, pg_catalog.ceil(pg_catalog.date_part('epoch', v_p.next_attempt_at - v_now))::integer, false;
    RETURN;
  END IF;
  SELECT c.o_match INTO v_match FROM private.partner_pin_core(p_uid, p_derived, v_p.verifier) c;
  IF v_match THEN
    UPDATE app.partner_pin p SET failed_count = 0, next_attempt_at = NULL, last_ok_at = v_now WHERE p.user_id = p_uid;
    RETURN QUERY SELECT 'ok'::text, 0, false;
    RETURN;
  END IF;
  -- a wrong key: count it. failed_today is the count in THIS UTC day and a success does not reset it.
  v_fc := v_p.failed_count + 1;
  v_ft := CASE WHEN v_p.failed_day IS DISTINCT FROM v_day THEN 0 ELSE v_p.failed_today END + 1;
  IF v_fc >= 5 OR v_ft >= 20 THEN
    UPDATE app.partner_pin p
    SET failed_count = LEAST(v_fc, 5), failed_today = LEAST(v_ft, 20), failed_day = v_day, last_failed_at = v_now, next_attempt_at = NULL, locked_at = v_now
    WHERE p.user_id = p_uid;
    RETURN QUERY SELECT 'locked'::text, 0, true;
    RETURN;
  END IF;
  v_next := CASE v_fc WHEN 3 THEN v_now + interval '30 seconds' WHEN 4 THEN v_now + interval '5 minutes' ELSE NULL END;
  UPDATE app.partner_pin p
  SET failed_count = v_fc, failed_today = v_ft, failed_day = v_day, last_failed_at = v_now, next_attempt_at = v_next
  WHERE p.user_id = p_uid;
  RETURN QUERY SELECT 'wrong'::text, CASE v_fc WHEN 3 THEN 30 WHEN 4 THEN 300 ELSE 0 END, false;
END
$$;

-- 4b. THE verifier of the step-up PIN (class A0 caller: private.partner_pin_verify_for_partner). The person and the session come from the TRANSACTION'S binding, never an argument. On `ok` it is the ONLY code that
-- sets pin_grant_until (the column grant is this role's alone, R5-L1): now + 60 s, single use, bound to THIS session row. Statuses as partner_pin_attempt; the counter write commits with the refusal.
CREATE FUNCTION private.partner_pin_verify_apply(p_derived bytea)
RETURNS TABLE (o_status text, o_retry_after integer, o_newly_locked boolean, o_grant_until timestamptz)
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
    RAISE EXCEPTION 'partner_pin_verify_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  SELECT a.o_status, a.o_retry_after, a.o_newly_locked INTO v_a FROM private.partner_pin_attempt(v_uid, p_derived) a;
  IF v_a.o_status IS DISTINCT FROM 'ok' THEN
    RETURN QUERY SELECT v_a.o_status, v_a.o_retry_after, v_a.o_newly_locked, NULL::timestamptz;
    RETURN;
  END IF;
  -- partner_authorize has already locked the session row and refused a revoked one in this transaction
  UPDATE app.partner_session s SET pin_grant_until = pg_catalog.clock_timestamp() + interval '60 seconds'
  WHERE s.id = v_sid
  RETURNING s.pin_grant_until INTO v_until;
  IF v_until IS NULL THEN
    RAISE EXCEPTION 'partner_pin_verify_apply: the bound session is not writable' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT 'ok'::text, 0, false, v_until;
END
$$;

-- 4c. SET (first PIN, or the replacement after a reset) and CHANGE (replace a live PIN). The PREREQUISITE (PA-21) is checked HERE, by the role that owns the writer, before anything is read or counted: the bound
-- session must show an enrolment window (`enrolment_until`, the session `register_first` mints) or an email proof (`otp_proof_until`), else 42501. A passkey assertion alone is never enough: on a shared iPad
-- anyone with the passcode holds one (H2). The rest of the rule:
--   mode 'set'     the PIN does not exist yet, or a reset left it `must_change` (no current PIN: it is dead). A live PIN answers `already_set`; a LOCKED one answers `locked` (only a manager's reset clears a lock).
--   mode 'change'  the PIN must exist, not be locked and not be `must_change`; the CURRENT derived key must verify (a status, counted exactly like a verify: wrong / locked / retry_after).
-- Every status is returned, never raised; only malformed arguments (22023) and a missing prerequisite (42501) raise, and neither writes a counter. The new verifier is computed by the core under the pepper.
CREATE FUNCTION private.partner_pin_set_apply(p_mode text, p_derived bytea, p_salt bytea, p_iterations integer, p_current bytea)
RETURNS TABLE (o_status text, o_retry_after integer, o_newly_locked boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_sid uuid := private.partner_binding_session();
  v_s record;
  v_p record;
  v_a record;
  v_ver bytea;
  v_n integer;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF v_uid IS NULL OR v_sid IS NULL THEN
    RAISE EXCEPTION 'partner_pin_set_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  -- the prerequisite FIRST: nothing below may be reached (or counted) without it
  SELECT s.enrolment_until, s.otp_proof_until INTO v_s FROM app.partner_session s WHERE s.id = v_sid;
  IF NOT FOUND OR NOT ((v_s.enrolment_until IS NOT NULL AND v_s.enrolment_until > v_now) OR (v_s.otp_proof_until IS NOT NULL AND v_s.otp_proof_until > v_now)) THEN
    RAISE EXCEPTION 'partner_pin_set_apply: a PIN is set or changed only inside an enrolment window or after an email proof' USING ERRCODE = '42501';
  END IF;
  IF p_mode IS NULL OR p_mode NOT IN ('set', 'change')
     OR p_derived IS NULL OR pg_catalog.octet_length(p_derived) <> 32
     OR p_salt IS NULL OR pg_catalog.octet_length(p_salt) <> 16
     OR p_iterations IS NULL OR p_iterations NOT BETWEEN 210000 AND 1000000
     OR (p_mode = 'change' AND (p_current IS NULL OR pg_catalog.octet_length(p_current) <> 32)) THEN
    RAISE EXCEPTION 'partner_pin_set_apply: a mode (set or change), a 32-byte derived key, a 16-byte salt, 210000 to 1000000 iterations (and, for a change, the 32-byte current key) are required' USING ERRCODE = '22023';
  END IF;
  SELECT c.o_verifier INTO v_ver FROM private.partner_pin_core(v_uid, p_derived, NULL) c;

  IF p_mode = 'set' THEN
    -- a first PIN: no row to lock, so the INSERT is the claim (two concurrent first sets: exactly one inserts)
    INSERT INTO app.partner_pin (user_id, salt, iterations, pepper_kid, verifier, set_at, created_at)
    VALUES (v_uid, p_salt, p_iterations, 'v1', v_ver, v_now, v_now)
    ON CONFLICT (user_id) DO NOTHING;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n = 1 THEN
      RETURN QUERY SELECT 'ok'::text, 0, false;
      RETURN;
    END IF;
    SELECT p.locked_at, p.must_change INTO v_p FROM app.partner_pin p WHERE p.user_id = v_uid FOR UPDATE;
    IF v_p.locked_at IS NOT NULL THEN
      RETURN QUERY SELECT 'locked'::text, 0, false;
      RETURN;
    END IF;
    IF NOT v_p.must_change THEN
      RETURN QUERY SELECT 'already_set'::text, 0, false;
      RETURN;
    END IF;
  ELSE
    -- a change: the person's CURRENT PIN must verify first (this locks the row FOR UPDATE and counts a failure exactly as a verify does)
    PERFORM 1 FROM app.partner_pin p WHERE p.user_id = v_uid;
    IF NOT FOUND THEN
      RETURN QUERY SELECT 'no_pin'::text, 0, false;
      RETURN;
    END IF;
    SELECT a.o_status, a.o_retry_after, a.o_newly_locked INTO v_a FROM private.partner_pin_attempt(v_uid, p_current) a;
    IF v_a.o_status IS DISTINCT FROM 'ok' THEN
      RETURN QUERY SELECT v_a.o_status, v_a.o_retry_after, v_a.o_newly_locked;
      RETURN;
    END IF;
  END IF;
  -- the replacement: new salt, iterations and verifier; the lock and the consecutive-failure state are clear (a set after a reset, or a verified change); failed_today is kept on a change
  UPDATE app.partner_pin p
  SET salt = p_salt, iterations = p_iterations, pepper_kid = 'v1', verifier = v_ver, must_change = false, failed_count = 0, next_attempt_at = NULL,
      failed_today = CASE WHEN p_mode = 'set' THEN 0 ELSE p.failed_today END, set_at = v_now
  WHERE p.user_id = v_uid;
  RETURN QUERY SELECT 'ok'::text, 0, false;
END
$$;

-- 4d. What GET pin returns: the PBKDF2 inputs the browser needs to derive the key for THIS person, or the reason it cannot. Statuses `unset | must_change | locked | ok` (an `ok` row also reports a running backoff
-- in o_retry_after). A locked PIN returns NO salt (refused while locked, 6.3). Read-only.
CREATE FUNCTION private.partner_pin_params_read()
RETURNS TABLE (o_status text, o_salt bytea, o_iterations integer, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.partner_binding_user();
  v_p record;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'partner_pin_params_read: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  SELECT p.salt, p.iterations, p.next_attempt_at, p.locked_at, p.must_change INTO v_p FROM app.partner_pin p WHERE p.user_id = v_uid;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'unset'::text, NULL::bytea, NULL::integer, 0;
  ELSIF v_p.locked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'locked'::text, NULL::bytea, NULL::integer, 0;
  ELSIF v_p.must_change THEN
    RETURN QUERY SELECT 'must_change'::text, NULL::bytea, NULL::integer, 0;
  ELSE
    RETURN QUERY SELECT 'ok'::text, v_p.salt, v_p.iterations,
      CASE WHEN v_p.next_attempt_at IS NOT NULL AND v_p.next_attempt_at > v_now THEN pg_catalog.ceil(pg_catalog.date_part('epoch', v_p.next_attempt_at - v_now))::integer ELSE 0 END;
  END IF;
END
$$;

-- 4e. The A2 twin of partner_pin_grant_consume() (0047): spends the bound session's PIN grant ONLY if it is at most p_max_age_seconds OLD. A grant is minted with pin_grant_until = now + 60 s, so its age is
-- 60 s minus what is left: "at most 30 s old" is "more than 30 s left". ONE atomic UPDATE (so two concurrent actions cannot both spend one PIN), single use, session-bound.
CREATE FUNCTION private.partner_pin_grant_consume_fresh(p_max_age_seconds integer)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_max_age_seconds IS NULL OR p_max_age_seconds NOT BETWEEN 1 AND 60 THEN
    RAISE EXCEPTION 'partner_pin_grant_consume_fresh: the maximum age is 1 to 60 seconds' USING ERRCODE = '22023';
  END IF;
  UPDATE app.partner_session s SET pin_grant_until = NULL
  WHERE s.id = private.partner_binding_session() AND s.pin_grant_until IS NOT NULL
    AND s.pin_grant_until > pg_catalog.clock_timestamp() + ((60 - p_max_age_seconds) * interval '1 second');
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n = 1;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_pin_verifier;

-- ============================================================================
-- 5. The private_definer functions: the `_for_partner` family (ownership bracket as 0045 / 0047 / 0049)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 5a. GET pin: the PBKDF2 inputs for THIS person (class A0, staff or manager). `unset`, `must_change` and `locked` carry no salt.
CREATE FUNCTION private.partner_pin_params_for_partner()
RETURNS TABLE (o_status text, o_salt bytea, o_iterations integer, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  RETURN QUERY SELECT r.o_status, r.o_salt, r.o_iterations, r.o_retry_after FROM private.partner_pin_params_read() r;
END
$$;

-- 5b. POST step-up/pin: verify the derived key and, on `ok`, set the single-use PIN grant (class A0: verifying must not itself consume a grant). A wrong key and the failure that locks write an audit_log row
-- (bounded: at most 5 wrong keys per lock, and a locked PIN writes nothing more) and RETURN the status: this function raises nothing over a refusal, so the counter and the audit row COMMIT (0020).
CREATE FUNCTION private.partner_pin_verify_for_partner(p_derived bytea)
RETURNS TABLE (o_status text, o_retry_after integer, o_grant_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  SELECT a.o_status, a.o_retry_after, a.o_newly_locked, a.o_grant_until INTO v_r FROM private.partner_pin_verify_apply(p_derived) a;
  IF v_r.o_status = 'wrong' OR v_r.o_newly_locked THEN
    PERFORM private.partner_audit_write(CASE WHEN v_r.o_newly_locked THEN 'partner.pin.locked' ELSE 'partner.pin.wrong' END, 'app.partner_pin', v_uid::text, pg_catalog.jsonb_build_object('stage', 'verify'));
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after, v_r.o_grant_until;
END
$$;

-- 5c. POST pin/set: the first PIN, or the replacement after a reset. The prerequisite (an enrolment window or an email proof) is checked by the verifier-owned writer; this wrapper audits a success.
CREATE FUNCTION private.partner_pin_set_for_partner(p_derived bytea, p_salt bytea, p_iterations integer)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  -- the PIN is a staff / manager factor: an admin passes the anywhere branch of partner_authorize with no membership at all, and an admin or operator has NO PIN (6.3; the A3 substitution is S1.4's)
  IF NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL AND m.role IN ('staff', 'manager')) THEN
    RAISE EXCEPTION 'partner_pin_set_for_partner: only an active staff or manager member holds a PIN' USING ERRCODE = '42501';
  END IF;
  SELECT a.o_status, a.o_retry_after INTO v_r FROM private.partner_pin_set_apply('set', p_derived, p_salt, p_iterations, NULL) a;
  IF v_r.o_status = 'ok' THEN
    PERFORM private.partner_audit_write('partner.pin.set', 'app.partner_pin', v_uid::text, '{}'::jsonb);
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after;
END
$$;

-- 5d. POST pin/change: replace a live PIN. The prerequisite as above AND the current PIN (counted like a verify: a wrong current key and the failure that locks write an audit_log row and return the status).
CREATE FUNCTION private.partner_pin_change_for_partner(p_current bytea, p_derived bytea, p_salt bytea, p_iterations integer)
RETURNS TABLE (o_status text, o_retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_r record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A0');
  IF NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL AND m.role IN ('staff', 'manager')) THEN
    RAISE EXCEPTION 'partner_pin_change_for_partner: only an active staff or manager member holds a PIN' USING ERRCODE = '42501';
  END IF;
  SELECT a.o_status, a.o_retry_after, a.o_newly_locked INTO v_r FROM private.partner_pin_set_apply('change', p_derived, p_salt, p_iterations, p_current) a;
  IF v_r.o_status = 'ok' THEN
    PERFORM private.partner_audit_write('partner.pin.change', 'app.partner_pin', v_uid::text, '{}'::jsonb);
  ELSIF v_r.o_status = 'wrong' OR v_r.o_newly_locked THEN
    PERFORM private.partner_audit_write(CASE WHEN v_r.o_newly_locked THEN 'partner.pin.locked' ELSE 'partner.pin.wrong' END, 'app.partner_pin', v_uid::text, pg_catalog.jsonb_build_object('stage', 'change'));
  END IF;
  RETURN QUERY SELECT v_r.o_status, v_r.o_retry_after;
END
$$;

-- 5e. The member's OWN mailbox, for the email OTP of the proof (class A0: staff, manager or operator; an admin passes the "anywhere" branch). The Edge sends the OTP to this address and nowhere else, and never
-- returns it to the client. NULL when the account has no email.
CREATE FUNCTION private.partner_session_otp_target_for_partner()
RETURNS TABLE (o_email text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  RETURN QUERY SELECT pg_catalog.lower(pg_catalog.btrim(u.email))::text FROM auth.users u WHERE u.id = v_uid;
END
$$;

-- 5f. Records the email proof on the bound session: otp_proof_until = now + 10 min, bound to the GoTrue session the Edge's verifyOtp created. The S1.1a guard re-checks that this GoTrue session exists for THIS
-- user and is fresh (the 0041 mechanism: the one secret an injected call cannot know) and the UNIQUE index lets one GoTrue session prove at most one proof. A session that is not fresh for this user is a STATUS
-- (`refused`), nothing is written. Class A0.
CREATE FUNCTION private.partner_session_otp_proof_for_partner(p_gotrue_session_id uuid)
RETURNS TABLE (o_status text, o_otp_proof_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
  v_until timestamptz;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
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

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 6. EXECUTE grants (PUBLIC revoked first: a function created by a role other than the migrating role defaults to PUBLIC EXECUTE). Each as its OWNER.
-- ============================================================================
SET ROLE partner_pin_verifier;
REVOKE EXECUTE ON FUNCTION
  private.partner_pin_attempt(uuid, bytea),
  private.partner_pin_verify_apply(bytea),
  private.partner_pin_set_apply(text, bytea, bytea, integer, bytea),
  private.partner_pin_params_read(),
  private.partner_pin_grant_consume_fresh(integer)
FROM PUBLIC;
-- partner_pin_attempt: nobody (the same-owner definers above call it). The rest: only the wrappers that call them (private_definer), after partner_authorize
GRANT EXECUTE ON FUNCTION private.partner_pin_verify_apply(bytea) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_pin_set_apply(text, bytea, bytea, integer, bytea) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_pin_params_read() TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_pin_grant_consume_fresh(integer) TO private_definer;
COMMENT ON FUNCTION private.partner_pin_verify_apply(bytea) IS
  '0052 (R5-L1). Owned by partner_pin_verifier, the only role that can write app.partner_session.pin_grant_until. Takes the person and the session from the transaction''s binding, evaluates the derived key (partner_pin_attempt: lock, backoff, counters, all a returned STATUS) and sets pin_grant_until = now + 60 s only on ok. EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_pin_set_apply(text, bytea, bytea, integer, bytea) IS
  '0052 (PA-21). Owned by partner_pin_verifier. Sets or changes the bound person''s PIN only inside an enrolment window or after an email proof (42501 otherwise: a passkey alone is refused); a change also needs the current key (counted like a verify); a locked PIN is never replaced here. EXECUTE for private_definer only.';
RESET ROLE;

SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION
  private.partner_binding_user(),
  private.partner_pin_core(uuid, bytea, bytea),
  private.partner_pin_params_for_partner(),
  private.partner_pin_verify_for_partner(bytea),
  private.partner_pin_set_for_partner(bytea, bytea, integer),
  private.partner_pin_change_for_partner(bytea, bytea, bytea, integer),
  private.partner_session_otp_target_for_partner(),
  private.partner_session_otp_proof_for_partner(uuid)
FROM PUBLIC;
-- partner_binding_user and partner_pin_core: partner_pin_verifier only (the policy's function is EXECUTE-checked against the role the policy applies to; the core is called by the verifier's definers)
GRANT EXECUTE ON FUNCTION private.partner_binding_user() TO partner_pin_verifier;
GRANT EXECUTE ON FUNCTION private.partner_pin_core(uuid, bytea, bytea) TO partner_pin_verifier;
-- the partner lane: edge_partner, and nobody else (check 14 (d) and (e))
GRANT EXECUTE ON FUNCTION private.partner_pin_params_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_pin_verify_for_partner(bytea) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_pin_set_for_partner(bytea, bytea, integer) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_pin_change_for_partner(bytea, bytea, bytea, integer) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_session_otp_target_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_session_otp_proof_for_partner(uuid) TO edge_partner;
COMMENT ON FUNCTION private.partner_authorize(text, text, app.partner_role[], text) IS
  '0047, 0052. Executable by NOBODY (called from sibling definers; every *_for_partner function must call it as its first statement: check 14). Locks the bound session row only, re-reads session / role / scope / aal on every call, enforces the class prerequisite (A1: a PIN grant; A2: a PIN grant at most 30 s old and reauth_until; A3 fails closed until S1.4), returns the member''s uid.';
RESET ROLE;

-- R5-L3: the migrating role keeps NO way to become the owner role (a PG16+ CREATEROLE creator keeps ADMIN on the roles it creates, which is all that may remain)
REVOKE partner_pin_verifier FROM CURRENT_USER;

-- ============================================================================
-- 7. Registries
-- ============================================================================
-- 7a. private.function_inventory: every function above. expected_edge_partner true for the six edge_partner functions; everything else false.
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_binding_user', '', false, false, false, false, false, false, false, '0052: the bound partner USER (kind partner only), the predicate inside the partner_pin policies of partner_pin_verifier; EXECUTE for partner_pin_verifier only (a policy''s function is checked against the role it applies to)'),
  ('private', 'partner_pin_core', 'p_uid uuid, p_derived bytea, p_stored bytea', false, false, false, false, false, false, false, '0052: the ONLY reader of Vault secret partner_pin_pepper: HMAC-SHA256(pepper, label || 0x00 || user || derived) and the HMAC(K, stored) = HMAC(K, computed) comparison; EXECUTE for partner_pin_verifier only; the pepper is never returned'),
  ('private', 'partner_pin_attempt', 'p_uid uuid, p_derived bytea', false, false, false, false, false, false, false, '0052: owned by partner_pin_verifier; ONE attempt against a PIN: locks the row FOR UPDATE, applies lock and backoff, compares, counts; every outcome a returned status (never a RAISE); EXECUTE for nobody (the same-owner verify and change definers call it)'),
  ('private', 'partner_pin_verify_apply', 'p_derived bytea', false, false, false, false, false, false, false, '0052 (R5-L1): owned by partner_pin_verifier, the only role that can write partner_session.pin_grant_until; person and session from the binding; sets pin_grant_until = now + 60 s only on ok; EXECUTE for private_definer only'),
  ('private', 'partner_pin_set_apply', 'p_mode text, p_derived bytea, p_salt bytea, p_iterations integer, p_current bytea', false, false, false, false, false, false, false, '0052 (PA-21): owned by partner_pin_verifier; sets or changes the bound person''s PIN only inside an enrolment window or after an email proof (42501 otherwise); a change needs the current key; a locked PIN is never replaced; EXECUTE for private_definer only'),
  ('private', 'partner_pin_params_read', '', false, false, false, false, false, false, false, '0052: owned by partner_pin_verifier; the PBKDF2 inputs (salt, iterations) for the bound person, or unset / must_change / locked with no salt; EXECUTE for private_definer only'),
  ('private', 'partner_pin_grant_consume_fresh', 'p_max_age_seconds integer', false, false, false, false, false, false, false, '0052: owned by partner_pin_verifier; spends the bound session''s PIN grant only if at most p_max_age_seconds old (A2: 30); one atomic UPDATE; EXECUTE for private_definer only'),
  ('private', 'partner_pin_params_for_partner', '', false, false, false, false, false, true, false, '0052: edge_partner only; GET pin: class A0 (staff, manager); the PBKDF2 inputs for this person, never a locked person''s salt'),
  ('private', 'partner_pin_verify_for_partner', 'p_derived bytea', false, false, false, false, false, true, false, '0052: edge_partner only; POST step-up/pin: class A0; verifies the derived key and, on ok, sets the single-use PIN grant; every refusal a returned status (it commits); an audit_log row for a wrong key and for the lock'),
  ('private', 'partner_pin_set_for_partner', 'p_derived bytea, p_salt bytea, p_iterations integer', false, false, false, false, false, true, false, '0052: edge_partner only; POST pin/set: class A0; the first PIN or the replacement after a reset, only inside an enrolment window or after an email proof; the browser-derived key, never the PIN'),
  ('private', 'partner_pin_change_for_partner', 'p_current bytea, p_derived bytea, p_salt bytea, p_iterations integer', false, false, false, false, false, true, false, '0052: edge_partner only; POST pin/change: class A0; replaces a live PIN under the same prerequisite and the current key (counted like a verify)'),
  ('private', 'partner_session_otp_target_for_partner', '', false, false, false, false, false, true, false, '0052: edge_partner only; class A0; the member''s OWN mailbox for the email OTP of the proof (never returned to the client)'),
  ('private', 'partner_session_otp_proof_for_partner', 'p_gotrue_session_id uuid', false, false, false, false, false, true, false, '0052: edge_partner only; class A0; records otp_proof_until = now + 10 min bound to a fresh GoTrue session of this user (the 0041 mechanism, the S1.1a guard re-checks it); a stale session is a status');

-- 7b. private.definer_policy_allowlist: the five new policies, their expressions derived from the live policies (checks 5 / 6 compare the two, and the checked-in fixture is the third copy)
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0052 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_pin', 'ppv_read_partner_pin', 'SELECT', true, 'S1.3: the PIN verifier reads the BOUND person''s own row only (keyed on private.partner_binding_user(), never a settable value); nobody can become partner_pin_verifier', 'partner_pin_verifier'),
  ('app', 'partner_pin', 'ppv_insert_partner_pin', 'INSERT', true, 'S1.3: the first PIN of the BOUND person only (WITH CHECK keyed on the binding); nobody can become partner_pin_verifier', 'partner_pin_verifier'),
  ('app', 'partner_pin', 'ppv_update_partner_pin', 'UPDATE', true, 'S1.3: the counters, the lock and the verifier of the BOUND person''s own row only (USING and WITH CHECK keyed on the binding); nobody can become partner_pin_verifier', 'partner_pin_verifier'),
  ('app', 'partner_pin', 'pd_delete_partner_pin_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_pin.user_id = delete_row); the 0016 GUC window, DELETE ONLY, closed under a partner binding (0047 8a, check 15)', 'private_definer'),
  ('app', 'partner_pin', 'pd_delete_partner_pin_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_partner_pin_user_id; also delete_my_data''s post-condition count (column-level SELECT grant on user_id)', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND pol.polname IN ('ppv_read_partner_pin', 'ppv_insert_partner_pin', 'ppv_update_partner_pin', 'pd_delete_partner_pin_user_id', 'pd_delete_partner_pin_user_id_r');
DO $assert_0052_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE table_name = 'partner_pin' AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 5 THEN
    RAISE EXCEPTION '0052: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0052_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0052 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 7c. private.partner_owner_privilege: what partner_pin_verifier holds now, beyond 0047 (checks 9 / 12 re-derive the real set from the catalog and compare both ways; the fixture is its checked-in twin)
CREATE POLICY current_user_seed_partner_owner_privilege_0052 ON private.partner_owner_privilege
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.partner_owner_privilege (role_name, object_kind, object_name, privilege, column_name) VALUES
  ('partner_pin_verifier', 'relation', 'app.partner_pin', 'SELECT', NULL),
  ('partner_pin_verifier', 'relation', 'app.partner_pin', 'INSERT', NULL),
  ('partner_pin_verifier', 'relation', 'app.partner_pin', 'UPDATE', NULL),
  ('partner_pin_verifier', 'column', 'app.partner_session', 'SELECT', 'enrolment_until'),
  ('partner_pin_verifier', 'column', 'app.partner_session', 'SELECT', 'otp_proof_until'),
  ('partner_pin_verifier', 'function', 'private.partner_binding_user()', 'EXECUTE', NULL),
  ('partner_pin_verifier', 'function', 'private.partner_pin_core(uuid,bytea,bytea)', 'EXECUTE', NULL);
DROP POLICY current_user_seed_partner_owner_privilege_0052 ON private.partner_owner_privilege;

-- 7d. PII registries (E9): the FK to auth.users is classified, and the table has an export decision. delete_my_data and export_my_data fail closed without these.
GRANT INSERT ON private.pii_retention_policy TO CURRENT_USER;
CREATE POLICY current_user_seed_pii_retention_policy_0052 ON private.pii_retention_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'partner_pin', 'user_id', 'delete_row', 'the person''s own step-up PIN verifier and lockout state (0052): deleted with the account by delete_my_data''s generic pass (and by FK cascade with the auth user)');
DROP POLICY current_user_seed_pii_retention_policy_0052 ON private.pii_retention_policy;
REVOKE INSERT ON private.pii_retention_policy FROM CURRENT_USER;

CREATE POLICY current_user_seed_pii_export_policy_0052 ON private.pii_export_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_export_policy (schema_name, table_name, action, reason) VALUES
  ('app', 'partner_pin', 'exclude', 'a login artefact: a peppered verifier of a browser-derived PIN key and its lockout counters, not the subject''s own data');
DROP POLICY current_user_seed_pii_export_policy_0052 ON private.pii_export_policy;

-- ============================================================================
-- 8. Prove the grants (a refused or misapplied GRANT only warns, so the migration fails HERE rather than on the first request)
-- ============================================================================
DO $assert_0052_grants$
DECLARE
  v_role text;
  v_fn regprocedure;
  v_bad text;
  v_lane regprocedure[] := ARRAY[
    'private.partner_pin_params_for_partner()'::regprocedure,
    'private.partner_pin_verify_for_partner(bytea)'::regprocedure,
    'private.partner_pin_set_for_partner(bytea, bytea, integer)'::regprocedure,
    'private.partner_pin_change_for_partner(bytea, bytea, bytea, integer)'::regprocedure,
    'private.partner_session_otp_target_for_partner()'::regprocedure,
    'private.partner_session_otp_proof_for_partner(uuid)'::regprocedure];
  v_helpers regprocedure[] := ARRAY[
    'private.partner_binding_user()'::regprocedure,
    'private.partner_pin_core(uuid, bytea, bytea)'::regprocedure,
    'private.partner_pin_attempt(uuid, bytea)'::regprocedure,
    'private.partner_pin_verify_apply(bytea)'::regprocedure,
    'private.partner_pin_set_apply(text, bytea, bytea, integer, bytea)'::regprocedure,
    'private.partner_pin_params_read()'::regprocedure,
    'private.partner_pin_grant_consume_fresh(integer)'::regprocedure];
BEGIN
  IF EXISTS (SELECT 1 FROM unnest(v_lane || v_helpers) f(oid) JOIN pg_proc p ON p.oid = f.oid WHERE NOT p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=""']) THEN
    RAISE EXCEPTION '0052: a new function is not SECURITY DEFINER with search_path=''''';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(ARRAY['private.partner_pin_attempt(uuid, bytea)', 'private.partner_pin_verify_apply(bytea)', 'private.partner_pin_set_apply(text, bytea, bytea, integer, bytea)',
                                        'private.partner_pin_params_read()', 'private.partner_pin_grant_consume_fresh(integer)']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'partner_pin_verifier'::regrole) THEN
    RAISE EXCEPTION '0052: a verifier function is not owned by partner_pin_verifier';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(v_lane || ARRAY['private.partner_binding_user()', 'private.partner_pin_core(uuid, bytea, bytea)']::regprocedure[]) f(oid) JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'private_definer'::regrole) THEN
    RAISE EXCEPTION '0052: a private_definer function is not owned by private_definer';
  END IF;
  -- the partner lane: edge_partner, and no other client or edge role (and not the minter)
  FOREACH v_fn IN ARRAY v_lane LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated', 'partner_pin_verifier'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0052: % can execute %; only edge_partner may', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_partner', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0052: edge_partner cannot execute %', v_fn;
    END IF;
  END LOOP;
  -- the helpers: no edge or client role at all
  FOREACH v_fn IN ARRAY v_helpers LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0052: % can execute the helper %', v_role, v_fn;
      END IF;
    END LOOP;
  END LOOP;
  -- the internal callers
  IF NOT (has_function_privilege('partner_pin_verifier', 'private.partner_binding_user()'::regprocedure, 'EXECUTE')
          AND has_function_privilege('partner_pin_verifier', 'private.partner_pin_core(uuid, bytea, bytea)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_pin_verify_apply(bytea)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_pin_set_apply(text, bytea, bytea, integer, bytea)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_pin_params_read()'::regprocedure, 'EXECUTE')
          AND has_function_privilege('private_definer', 'private.partner_pin_grant_consume_fresh(integer)'::regprocedure, 'EXECUTE')) THEN
    RAISE EXCEPTION '0052: an internal EXECUTE grant did not take effect';
  END IF;
  -- private_definer must NOT reach the verifier's evaluation (partner_pin_attempt): it is owned by partner_pin_verifier and executable by nobody else. (The core is private_definer's own, like partner_challenge_core:
  -- it holds the Vault read, and the only role that can WRITE a verifier or a counter is partner_pin_verifier.)
  IF has_function_privilege('private_definer', 'private.partner_pin_attempt(uuid, bytea)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0052: private_definer can execute partner_pin_attempt';
  END IF;
  -- the table: nothing for any client, edge or service role; no privilege for private_definer beyond the delete_my_data pair
  FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated', 'service_role', 'edge_actor', 'edge_system', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'partner_reauth_verifier', 'partner_session_issuer', 'partner_session_toucher'] LOOP
    IF has_any_column_privilege(v_role, 'app.partner_pin', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(v_role, 'app.partner_pin', 'DELETE,TRUNCATE,TRIGGER') THEN
      RAISE EXCEPTION '0052: % holds a privilege on app.partner_pin', v_role;
    END IF;
  END LOOP;
  IF NOT (has_table_privilege('partner_pin_verifier', 'app.partner_pin', 'SELECT') AND has_table_privilege('partner_pin_verifier', 'app.partner_pin', 'INSERT')
          AND has_table_privilege('partner_pin_verifier', 'app.partner_pin', 'UPDATE') AND NOT has_table_privilege('partner_pin_verifier', 'app.partner_pin', 'DELETE')) THEN
    RAISE EXCEPTION '0052: a grant the PIN table needs did not take effect, or partner_pin_verifier can delete';
  END IF;
  IF has_any_column_privilege('private_definer', 'app.partner_pin', 'INSERT,UPDATE,REFERENCES') OR NOT has_column_privilege('private_definer', 'app.partner_pin', 'user_id', 'SELECT')
     OR has_column_privilege('private_definer', 'app.partner_pin', 'verifier', 'SELECT') THEN
    RAISE EXCEPTION '0052: private_definer holds more than SELECT (user_id) and DELETE on app.partner_pin';
  END IF;
  -- the minter still holds no privilege on any relation
  SELECT string_agg(c.relname, ', ') INTO v_bad FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND (has_any_column_privilege('edge_partner_minter', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_partner_minter', c.oid, 'DELETE,TRUNCATE,TRIGGER'));
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0052: edge_partner_minter holds a relation privilege: %', v_bad;
  END IF;
  -- the pin_grant_until writer is still ONLY partner_pin_verifier (R5-L1)
  IF has_column_privilege('private_definer', 'app.partner_session', 'pin_grant_until', 'UPDATE') OR NOT has_column_privilege('partner_pin_verifier', 'app.partner_session', 'pin_grant_until', 'UPDATE') THEN
    RAISE EXCEPTION '0052: pin_grant_until is not writable by partner_pin_verifier alone';
  END IF;
  -- partner_authorize is still executable by nobody
  FOREACH v_role IN ARRAY ARRAY['edge_partner', 'edge_actor', 'edge_system', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated', 'partner_pin_verifier'] LOOP
    IF has_function_privilege(v_role, 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure, 'EXECUTE') THEN
      RAISE EXCEPTION '0052: % can execute partner_authorize', v_role;
    END IF;
  END LOOP;
END
$assert_0052_grants$;
