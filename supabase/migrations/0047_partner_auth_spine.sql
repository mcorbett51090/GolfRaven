-- 0047_partner_auth_spine.sql
--
-- P5.1a, slice S1.1a: the DATABASE SPINE of partner (staff) authentication. docs/security/partner-auth-design.md (revision 5, gate rounds 1-5 passed; sections
-- 4.2-4.4, 5, 6.5, 12 and 13) is the specification; its "As built: S1.1a" section is the reading guide for this file. Migrations 0001-0045 are untouched
-- (0046 belongs to a parallel slice and is not created here).
--
-- WHAT THIS ADDS
--   1. Roles. edge_partner (the partner lane: NO privilege on any table; EXECUTE on exactly the binder and the two read-only binding helpers),
--      edge_partner_minter (the minting lane, S1.1b: USAGE on schema private and nothing else yet), the two session-writer roles of section 4.3
--      (partner_session_toucher / _issuer; the third, _flagger, was dropped at the S1.1a gate: the S1.6 re-verifier is moot) and, decided by gate round 5 (R5-L1), three VERIFIER-OWNER roles (partner_pin_verifier /
--      partner_totp_verifier / partner_reauth_verifier) so a verification fact is a ROLE (the only role that can write the column), never an `xmin`
--      comparison and never a GUC. Every one is NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS, a member of nothing; edge_gateway is the only member of the two
--      edge roles (SET TRUE, INHERIT FALSE); the five owner roles have NO member at all (the migrating role holds one only for the length of this file, to create
--      their functions, and loses SET and INHERIT again: R5-L3, the 0041 form).
--   2. The binding. private.actor_binding.kind gains 'partner' (and session_id); private.actor_uid() returns NULL for it (so every edge_actor policy and every
--      user-lane definer is blind to a partner binding); private.bind_partner_session(token_hash) is the only producer; private.partner_binding() /
--      partner_binding_kind() read it.
--   3. Tables (all FORCE RLS, no privilege for anon / authenticated / any edge role / service_role): partner_credential, partner_auth_challenge (the USED
--      nonces of stateless challenges), partner_session, partner_enrolment_token, partner_rp_config; and the partner_invite additions. partner_pin and
--      partner_totp are S1.3 / S1.4 (they carry the verifiers) and are NOT created here.
--   4. private.partner_authorize(facility, trail, roles[], class): the one authorization seam. Re-reads session, role and scope on EVERY call, locks the session row
--      ONLY (FOR SHARE, FOR NO KEY UPDATE when it writes) through the one policy pd_partner_session_action, fails CLOSED on classes A2 and A3 until S1.3 / S1.4,
--      gates every class on aal, is VOLATILE and executable by nobody.
--   5. Session protection with NO GUC window anywhere: the authority triggers (partner_member INSERT / UPDATE / DELETE, admin_user INSERT / DELETE, partner_scope
--      UPDATE / DELETE) are SECURITY DEFINER functions owned by partner_session_toucher with column grants only; partner_session_guard (BEFORE UPDATE,
--      SECURITY DEFINER, search_path = '', owned by private_definer, which owns no table and so cannot disable it: R5-N1); private.partner_sessions_revoke(kind, id,
--      reason) is subject-based, derives the sessions itself, writes one audit_log row per call and is callable by private_definer only (R5-L2).
--   6. Invariants: one facility org holds exactly one facility scope; a member's role must match the org's kind (explicit lists, never partner_role_rank).
--   7. D12 / section 5.5: the PostgREST read surface over partner data is revoked from `authenticated` (14 api views, the 14 base tables), api.offer and
--      api.my_offers() answer live offers with NULL budget and eligibility columns to EVERYONE, offer_read is narrowed to live offers.
--   8. X9: REVOKE EXECUTE on private.offline_code_record_step_for_actor FROM edge_actor (the function and its proofs stay).
--   9. Registries: function_inventory (two new role columns), definer_policy_allowlist (a role_name column: the policies of the new owner roles are registered
--      too), pii_retention_policy / pii_export_policy, and a registry of the exact privileges the five owner roles may hold.
--
-- THE HARD RULE (docs/security/p3-money-path-requirements.md, "What P5 must do"): no policy on an edge-reachable path is keyed on a settable GUC. The ONLY GUC-keyed
-- policies below are the delete_my_data window pairs (DELETE and its SELECT companion, and the set_null UPDATE pair) the registry-driven generic pass REQUIRES for every
-- classified FK to auth.users (verify-function-inventory check 8): they are the 0016 form, they grant no UPDATE to anything on a table that carries authority (the
-- set_null pairs sit behind COLUMN-level UPDATE grants of the one nulled column), and every partner definer filters by the binding (PA-4c plants the GUC and proves it).
-- Every other private_definer policy on partner_session is keyed on private.partner_binding_session(), a fact of the transaction's own binding.
--
-- OWNERSHIP BRACKET as 0030 / 0041 / 0045: GRANT CREATE ON SCHEMA private TO <owner>; SET ROLE <owner>; CREATE FUNCTION ...; RESET ROLE; REVOKE CREATE.
-- `migration_owner` is never named: CURRENT_USER is used wherever the migrating role is meant.

-- ============================================================================
-- 1. Roles
-- ============================================================================
DO $$
DECLARE
  v_role text;
BEGIN
  FOREACH v_role IN ARRAY ARRAY[
    'edge_partner', 'edge_partner_minter',
    'partner_session_toucher', 'partner_session_issuer',
    'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION', v_role);
    END IF;
    -- (SUPERUSER / BYPASSRLS / REPLICATION cannot be re-asserted by a non-superuser; they are fixed at CREATE ROLE and asserted below.)
    EXECUTE format('ALTER ROLE %I NOLOGIN NOINHERIT NOCREATEROLE NOCREATEDB', v_role);
  END LOOP;
END
$$;

-- The two edge roles: edge_gateway is the ONLY member, SET TRUE and INHERIT FALSE (the 0030 / 0041 shape).
GRANT edge_partner TO edge_gateway WITH INHERIT FALSE, SET TRUE;
GRANT edge_partner_minter TO edge_gateway WITH INHERIT FALSE, SET TRUE;
-- Name resolution only: every function in `private` has had PUBLIC EXECUTE revoked, so USAGE reaches only what is granted below. NO USAGE on schema app.
GRANT USAGE ON SCHEMA private TO edge_partner, edge_partner_minter;

-- The five owner roles: USAGE on app and private (R5-L4: a function owned by a role runs with that role's schema privileges).
GRANT USAGE ON SCHEMA app, private TO
  partner_session_toucher, partner_session_issuer,
  partner_pin_verifier, partner_totp_verifier, partner_reauth_verifier;

-- The migrating role must be able to SET ROLE to an owner for the bracket below (and ALTER ... OWNER); the membership is dropped again at the end of this
-- file, leaving at most ADMIN (the PG16+ CREATEROLE creator grant): R5-L3.
GRANT partner_session_toucher TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
GRANT partner_pin_verifier TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;

DO $assert_0047_roles$
DECLARE
  v_bad text;
BEGIN
  SELECT string_agg(r.rolname || ' has ' || a.attr, ', ') INTO v_bad
  FROM pg_roles r CROSS JOIN LATERAL (VALUES ('SUPERUSER', r.rolsuper), ('BYPASSRLS', r.rolbypassrls), ('REPLICATION', r.rolreplication),
    ('CREATEROLE', r.rolcreaterole), ('CREATEDB', r.rolcreatedb), ('INHERIT', r.rolinherit), ('LOGIN', r.rolcanlogin)) AS a(attr, is_on)
  WHERE r.rolname IN ('edge_partner', 'edge_partner_minter', 'partner_session_toucher', 'partner_session_issuer',
                      'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier') AND a.is_on;
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0047: a new role holds an attribute it must not (%)', v_bad;
  END IF;
  -- a refused GRANT only warns: prove edge_gateway holds each edge role SET TRUE, INHERIT FALSE, non-admin
  IF (SELECT count(*) FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
      WHERE r.rolname IN ('edge_partner', 'edge_partner_minter') AND m.rolname = 'edge_gateway' AND am.set_option AND NOT am.inherit_option AND NOT am.admin_option) <> 2 THEN
    RAISE EXCEPTION '0047: edge_gateway must be a SET TRUE, INHERIT FALSE, non-admin member of edge_partner and edge_partner_minter';
  END IF;
END
$assert_0047_roles$;

-- ============================================================================
-- 2. The binding: kind 'partner', session_id, and a NULL actor_uid() for it
-- ============================================================================
ALTER TABLE private.actor_binding DROP CONSTRAINT actor_binding_kind_check;
ALTER TABLE private.actor_binding ADD CONSTRAINT actor_binding_kind_check CHECK (kind IN ('user', 'system_delegate', 'partner'));
ALTER TABLE private.actor_binding ADD COLUMN session_id uuid;
-- a partner binding names its session; no other kind may
ALTER TABLE private.actor_binding ADD CONSTRAINT actor_binding_session_id_check CHECK ((kind = 'partner') = (session_id IS NOT NULL));
COMMENT ON COLUMN private.actor_binding.session_id IS
  '0047. The app.partner_session the binding was made for (kind = partner only; NULL for every other kind). Written only by private.bind_partner_session.';

-- ============================================================================
-- 3. Tables
-- ============================================================================
-- 3a. app.partner_credential: a WebAuthn credential belongs to the PERSON, not to an org (D13).
CREATE TABLE app.partner_credential (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
  public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 16 AND 1024),
  alg smallint NOT NULL CHECK (alg IN (-7, -257)),
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports text[] NOT NULL DEFAULT '{}',
  backup_eligible boolean NOT NULL DEFAULT false,
  backup_state boolean NOT NULL DEFAULT false,
  aaguid uuid,
  -- DERIVED BY THE DATABASE (trigger below): creation date, the AAGUID or "unknown", the creating credential's id prefix. Never client-supplied.
  label text NOT NULL DEFAULT '',
  -- member-chosen, DISPLAY ONLY: no security decision ever reads it
  note text CHECK (note IS NULL OR length(note) <= 40),
  created_via_credential_id uuid REFERENCES app.partner_credential (id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  revoked_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  revoke_reason text CHECK (revoke_reason IS NULL OR length(revoke_reason) <= 80)
);
CREATE INDEX partner_credential_user_active_idx ON app.partner_credential (user_id) WHERE revoked_at IS NULL;
COMMENT ON TABLE app.partner_credential IS
  '0047 (partner-auth-design 5.1). WebAuthn credentials of staff members. Holds key material: no client role, no edge role and not service_role has any privilege; reached only through definers. label is derived by trigger; note is display only.';

-- 3b. app.partner_auth_challenge: rows exist ONLY for challenges that were USED (challenges themselves are stateless HMAC tokens, 5.1). The primary key is what
-- makes a replay a unique violation.
CREATE TABLE app.partner_auth_challenge (
  nonce_hash bytea PRIMARY KEY CHECK (octet_length(nonce_hash) = 32),
  purpose text NOT NULL CHECK (purpose IN ('sign_in', 'register', 'reauth', 'countersign')),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  session_id uuid,
  used_at timestamptz NOT NULL DEFAULT now(),
  minted_session_id uuid
);
CREATE INDEX partner_auth_challenge_used_at_idx ON app.partner_auth_challenge (used_at);
CREATE INDEX partner_auth_challenge_user_idx ON app.partner_auth_challenge (user_id);
COMMENT ON TABLE app.partner_auth_challenge IS
  '0047 (5.1, R2-L6). The USED nonces of stateless sign-in / register / reauth challenges: sha256(nonce) is the primary key, so a replay is a unique violation. No row is written when a challenge is issued.';

-- 3c. app.partner_session: opaque, 256-bit random token, SHA-256 at rest.
CREATE TABLE app.partner_session (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  credential_id uuid NOT NULL REFERENCES app.partner_credential (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  aal smallint NOT NULL DEFAULT 1 CHECK (aal IN (1, 2)),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  pin_grant_until timestamptz,
  reauth_until timestamptz,
  otp_proof_until timestamptz,
  enrolment_until timestamptz,
  mfa_until timestamptz,
  pop_jkt text CHECK (pop_jkt IS NULL OR length(pop_jkt) <= 64),
  revoked_at timestamptz,
  revoke_reason text CHECK (revoke_reason IS NULL OR length(revoke_reason) <= 80),
  authority_touched_at timestamptz,
  otp_proof_gotrue_session_id uuid,
  mint_kind text NOT NULL CHECK (mint_kind IN ('sign_in', 'register')),
  mint_nonce_hash bytea NOT NULL UNIQUE CHECK (octet_length(mint_nonce_hash) = 32),
  mint_authenticator_data bytea NOT NULL CHECK (octet_length(mint_authenticator_data) BETWEEN 37 AND 4096),
  mint_client_data_json bytea NOT NULL CHECK (octet_length(mint_client_data_json) BETWEEN 2 AND 4096),
  -- NULL for a `register` mint (an `attestation: none` create ceremony carries no signature, R-P1); present for a `sign_in` mint
  mint_signature bytea CHECK (mint_signature IS NULL OR octet_length(mint_signature) BETWEEN 8 AND 1024),
  CHECK ((mint_kind = 'register') = (mint_signature IS NULL)),
  CHECK (expires_at > created_at)
);
CREATE INDEX partner_session_user_live_idx ON app.partner_session (user_id) WHERE revoked_at IS NULL;
CREATE INDEX partner_session_credential_idx ON app.partner_session (credential_id);
-- R5-L1 (as 0041): one GoTrue session proves at most one OTP proof
CREATE UNIQUE INDEX partner_session_otp_proof_gotrue_uidx ON app.partner_session (otp_proof_gotrue_session_id) WHERE otp_proof_gotrue_session_id IS NOT NULL;
COMMENT ON TABLE app.partner_session IS
  '0047 (5.1, 4.3). Opaque partner sessions: the token is 256 random bits and only its SHA-256 is stored. Written by NAMED roles only (partner_session_toucher / _issuer, the three verifier roles, and private_definer through ONE binding-keyed policy for its own row); every column that proves a verification can be written only by that verifier''s role; partner_session_guard enforces what no grant can.';

-- 3d. app.partner_enrolment_token: recovery and admin enrolment (a person, no org).
CREATE TABLE app.partner_enrolment_token (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  purpose text NOT NULL CHECK (purpose IN ('recover', 'admin')),
  -- NULL for the ops bootstrap of the first admin (6.4)
  issued_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  registered_credential_id uuid REFERENCES app.partner_credential (id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
  revoked_at timestamptz,
  attempts smallint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  CHECK (expires_at <= created_at + interval '24 hours')
);
CREATE INDEX partner_enrolment_token_user_idx ON app.partner_enrolment_token (user_id);
COMMENT ON TABLE app.partner_enrolment_token IS
  '0047 (5.1, 6.1, 6.4, 6.5). Single-use recovery and admin enrolment tokens; only the SHA-256 of the token is stored. Written only by the S1.1b / S1.5 definers.';

-- 3e. app.partner_rp_config: the relying party, ONE row, written by ops at deploy (a deploy-time fact: staging and production differ).
CREATE TABLE app.partner_rp_config (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  rp_id text NOT NULL CHECK (rp_id ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' AND length(rp_id) <= 253),
  origin text NOT NULL CHECK (origin ~ '^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$' AND length(origin) <= 300)
);
COMMENT ON TABLE app.partner_rp_config IS
  '0047 (5.1). The one-row relying-party configuration (RP ID and exact origin) the mint checks assertions against. No policy for any role yet: S1.1b adds the mint definers'' read, and the ops write is a SQL-session step at deploy. The mint refuses if the row is absent.';

-- 3f. app.partner_invite additions (E18, 5.2)
ALTER TABLE app.partner_invite
  ADD COLUMN accepted_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  ADD COLUMN registered_credential_id uuid REFERENCES app.partner_credential (id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
  ADD COLUMN revoked_at timestamptz,
  ADD COLUMN revoked_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
  ADD COLUMN attempts smallint NOT NULL DEFAULT 0 CHECK (attempts >= 0);
-- L4: the hash is exactly 64 hex characters; the ceiling on an invite's life is 7 days (the 72 h default is the writer's)
ALTER TABLE app.partner_invite ADD CONSTRAINT partner_invite_token_hash_hex CHECK (token_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE app.partner_invite ADD CONSTRAINT partner_invite_expiry_ceiling CHECK (expires_at <= created_at + interval '7 days');

-- Every new table: ENABLE + FORCE RLS, nothing for anyone (5.1, 5.4 item 1). Access is only through definers.
DO $$
DECLARE
  v_tbl text;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY['partner_credential', 'partner_auth_challenge', 'partner_session', 'partner_enrolment_token', 'partner_rp_config'] LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', v_tbl);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY', v_tbl);
    EXECUTE format('REVOKE ALL ON app.%I FROM PUBLIC, anon, authenticated, service_role', v_tbl);
  END LOOP;
END
$$;

-- ============================================================================
-- 4. Invariants (5.2): one facility org = one facility scope; role must match the org's kind
-- ============================================================================
-- Fail loudly, here, rather than silently ship a database in which the invariant already does not hold.
DO $assert_0047_existing_rows$
BEGIN
  IF EXISTS (SELECT 1 FROM app.partner_scope s JOIN app.partner_org o ON o.id = s.org_id
             WHERE o.kind = 'facility' AND (s.facility_id IS NULL OR s.trail_id IS NOT NULL OR s.sponsorship_id IS NOT NULL)) THEN
    RAISE EXCEPTION '0047: an existing facility org holds a non-facility scope row; fix the data first';
  END IF;
  IF EXISTS (SELECT 1 FROM app.partner_scope s JOIN app.partner_org o ON o.id = s.org_id WHERE o.kind = 'facility' GROUP BY s.org_id HAVING count(*) > 1) THEN
    RAISE EXCEPTION '0047: an existing facility org holds more than one scope row; fix the data first';
  END IF;
  IF EXISTS (SELECT 1 FROM app.partner_member m JOIN app.partner_org o ON o.id = m.org_id
             WHERE NOT ((o.kind = 'facility' AND m.role IN ('staff', 'manager')) OR (o.kind = 'operator' AND m.role = 'operator') OR (o.kind = 'sponsor' AND m.role = 'sponsor'))) THEN
    RAISE EXCEPTION '0047: an existing partner_member holds a role that does not match its org kind; fix the data first';
  END IF;
END
$assert_0047_existing_rows$;
ALTER TABLE app.partner_scope ADD CONSTRAINT partner_scope_org_facility_key UNIQUE (org_id, facility_id);

-- An org's kind never changes: both invariants are about the (kind, scope, role) triple, and a kind change would silently invalidate every row.
CREATE FUNCTION app.partner_org_kind_immutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF NEW.kind IS DISTINCT FROM OLD.kind THEN
    RAISE EXCEPTION 'partner_org: kind is immutable (% -> % refused, id=%)', OLD.kind, NEW.kind, OLD.id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER partner_org_kind_immutable_trg BEFORE UPDATE OF kind ON app.partner_org
FOR EACH ROW EXECUTE FUNCTION app.partner_org_kind_immutable();

-- The credential: identity columns never change, a revocation never comes back, the sign count never goes down; the label is derived HERE, never supplied.
CREATE FUNCTION app.partner_credential_label_trg() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.label := to_char(NEW.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
    || ' / ' || coalesce(NEW.aaguid::text, 'unknown')
    || CASE WHEN NEW.created_via_credential_id IS NOT NULL THEN ' / added via ' || left(NEW.created_via_credential_id::text, 8) ELSE '' END;
  RETURN NEW;
END;
$$;
CREATE TRIGGER partner_credential_label_trg BEFORE INSERT ON app.partner_credential
FOR EACH ROW EXECUTE FUNCTION app.partner_credential_label_trg();

CREATE FUNCTION app.partner_credential_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.public_key IS DISTINCT FROM OLD.public_key OR NEW.alg IS DISTINCT FROM OLD.alg OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.created_via_credential_id IS DISTINCT FROM OLD.created_via_credential_id OR NEW.label IS DISTINCT FROM OLD.label
     OR NEW.aaguid IS DISTINCT FROM OLD.aaguid THEN
    RAISE EXCEPTION 'partner_credential: identity columns are immutable (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION 'partner_credential: a revocation is final (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF NEW.sign_count < OLD.sign_count THEN
    RAISE EXCEPTION 'partner_credential: sign_count never decreases (% -> % refused, id=%)', OLD.sign_count, NEW.sign_count, OLD.id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER partner_credential_guard_trg BEFORE UPDATE ON app.partner_credential
FOR EACH ROW EXECUTE FUNCTION app.partner_credential_guard();

-- ============================================================================
-- 5. Grants and policies that the definers below rely on
-- ============================================================================
-- 5a. private_definer: what ITS functions touch. COLUMN-level wherever a whole-row grant would reach secrets or authority.
--   partner_session: the READ side excludes token_hash and the mint_* evidence (the S1.6 re-verifier reads those through its own definer); the WRITE side is the
--   three columns an action or a sign-out legitimately writes. pin_grant_until / aal / mfa_until / reauth_until are NOT here (R5-L1: only the verifier roles hold them);
--   otp_proof_* are, behind the guard (which checks the GoTrue session).
GRANT SELECT (id, user_id, credential_id, aal, created_at, last_seen_at, expires_at, pin_grant_until, reauth_until, otp_proof_until, enrolment_until, mfa_until,
              revoked_at, revoke_reason, authority_touched_at, otp_proof_gotrue_session_id, mint_kind) ON app.partner_session TO private_definer;
GRANT UPDATE (last_seen_at, revoked_at, revoke_reason, otp_proof_until, otp_proof_gotrue_session_id) ON app.partner_session TO private_definer;
GRANT DELETE ON app.partner_session TO private_definer;  -- delete_my_data's generic pass ONLY (the policies below admit nothing else)
--   the delete_my_data registry pass: DELETE (+ the SELECT companion) on delete_row columns, and the single nulled column on set_null columns
GRANT SELECT (id, user_id, alg, transports, backup_eligible, backup_state, aaguid, label, note, created_at, last_used_at, revoked_at, revoke_reason), DELETE ON app.partner_credential TO private_definer;
GRANT SELECT (revoked_by), UPDATE (revoked_by) ON app.partner_credential TO private_definer;
GRANT SELECT (id, user_id, issued_by), DELETE ON app.partner_enrolment_token TO private_definer;
GRANT UPDATE (issued_by) ON app.partner_enrolment_token TO private_definer;
GRANT SELECT (nonce_hash, user_id), DELETE ON app.partner_auth_challenge TO private_definer;
GRANT SELECT (accepted_by, revoked_by), UPDATE (accepted_by, revoked_by) ON app.partner_invite TO private_definer;
--   the role-to-org-kind and one-facility-scope invariants read the org's kind
GRANT SELECT (id, kind) ON app.partner_org TO private_definer;

-- 5b. The five owner roles. Every privilege below is registered in private.partner_owner_privilege (section 12) and re-derived from the catalog by checks 9 and 12.
--   toucher: revokes and touches sessions; reads authority; (S1.5) revokes credentials
GRANT SELECT (id, user_id, credential_id, token_hash, aal, created_at, last_seen_at, expires_at, revoked_at, revoke_reason, authority_touched_at) ON app.partner_session TO partner_session_toucher;
GRANT UPDATE (revoked_at, revoke_reason, authority_touched_at) ON app.partner_session TO partner_session_toucher;
GRANT SELECT (user_id, org_id, role, revoked_at) ON app.partner_member TO partner_session_toucher;
GRANT SELECT (id, org_id, facility_id, trail_id) ON app.partner_scope TO partner_session_toucher;
GRANT SELECT (id, user_id, revoked_at) ON app.partner_credential TO partner_session_toucher;
GRANT UPDATE (revoked_at, revoked_by, revoke_reason) ON app.partner_credential TO partner_session_toucher;
--   issuer (S1.1b): mints sessions and registers the first credential
GRANT SELECT (id, user_id, token_hash, revoked_at, created_at), INSERT ON app.partner_session TO partner_session_issuer;
GRANT SELECT (id, user_id, credential_id, revoked_at), INSERT ON app.partner_credential TO partner_session_issuer;
--   the three verifiers (R5-L1): each is the ONLY role that can write its columns
GRANT SELECT (id, pin_grant_until) ON app.partner_session TO partner_pin_verifier;
GRANT UPDATE (pin_grant_until) ON app.partner_session TO partner_pin_verifier;
GRANT SELECT (id, aal, mfa_until) ON app.partner_session TO partner_totp_verifier;
GRANT UPDATE (aal, mfa_until) ON app.partner_session TO partner_totp_verifier;
GRANT SELECT (id, reauth_until) ON app.partner_session TO partner_reauth_verifier;
GRANT UPDATE (reauth_until) ON app.partner_session TO partner_reauth_verifier;

-- ============================================================================
-- 6. The private_definer functions (ownership bracket)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 6a. THE identity every edge_actor policy is keyed on: now NULL for a partner binding (4.3 defence in depth). Same owner, ACL and signature (CREATE OR REPLACE).
CREATE OR REPLACE FUNCTION private.actor_uid()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT b.actor_uid
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned() AND b.kind <> 'partner'
$$;

-- 6b. The binding core, redefined from 0030 with exactly ONE change: a re-bind on a pooled connection also clears session_id (a stale partner row's session_id would
-- otherwise violate actor_binding_session_id_check when the next transaction on that backend binds a user).
CREATE OR REPLACE FUNCTION private.bind_actor_internal(p_uid uuid, p_kind text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_xact xid8;
BEGIN
  IF p_uid IS NULL THEN
    RAISE EXCEPTION 'bind_actor: the actor uid must not be NULL' USING ERRCODE = '22023';
  END IF;
  IF p_kind IS NULL OR p_kind NOT IN ('user', 'system_delegate') THEN
    RAISE EXCEPTION 'bind_actor: unknown binding kind' USING ERRCODE = '22023';
  END IF;
  -- Assigns the transaction id (an INSERT would anyway).
  v_xact := pg_current_xact_id();
  -- One bind per transaction, ever: this is what stops a delegate-bound or user-bound transaction
  -- from being re-pointed at another user half way through.
  IF EXISTS (SELECT 1 FROM private.actor_binding WHERE backend_pid = pg_backend_pid() AND xact = v_xact) THEN
    RAISE EXCEPTION 'bind_actor: this transaction already has a bound actor' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = p_uid) THEN
    RAISE EXCEPTION 'bind_actor: no such user' USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO private.actor_binding (backend_pid, xact, actor_uid, kind, session_id, bound_at)
  VALUES (pg_backend_pid(), v_xact, p_uid, p_kind, NULL, clock_timestamp())
  ON CONFLICT (backend_pid) DO UPDATE
    SET xact = EXCLUDED.xact, actor_uid = EXCLUDED.actor_uid, kind = EXCLUDED.kind, session_id = NULL, bound_at = EXCLUDED.bound_at;
END;
$$;

-- 6c. Read-only binding helpers. partner_binding() / partner_binding_kind(): edge_partner (the Edge's post-bind assertion). partner_binding_session(): the predicate
-- inside every own-session policy; EXECUTE for private_definer (owner) and the roles whose policy calls it, nobody else.
CREATE FUNCTION private.partner_binding()
RETURNS TABLE (kind text, session_id uuid)
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT b.kind, b.session_id
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned()
$$;

CREATE FUNCTION private.partner_binding_kind()
RETURNS text
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT b.kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned()
$$;

CREATE FUNCTION private.partner_binding_session()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT b.session_id
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned() AND b.kind = 'partner'
$$;

-- 6d. The assurance and idle policy of a person: the HIGHEST role they hold decides (admin > operator > manager or staff), recomputed on every call (4.1).
-- EXECUTE for nobody: bind_partner_session and partner_authorize (same owner) call it.
CREATE FUNCTION private.partner_session_policy(p_uid uuid)
RETURNS TABLE (required_aal smallint, idle interval, absolute interval)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT (CASE WHEN a.is_admin OR a.is_op THEN 2 ELSE 1 END)::smallint,
         CASE WHEN a.is_admin THEN interval '10 minutes' WHEN a.is_op THEN interval '15 minutes' ELSE interval '30 minutes' END,
         CASE WHEN a.is_admin THEN interval '1 hour' WHEN a.is_op THEN interval '4 hours' ELSE interval '8 hours' END
  FROM (
    SELECT private.is_admin(p_uid) AS is_admin,
           EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_uid AND m.revoked_at IS NULL AND m.role = 'operator') AS is_op
  ) a
$$;

-- 6e. THE ONLY PRODUCER of a partner binding (4.2). EVERY refusal is the same SQLSTATE and message (PA-2): unknown, idle-expired, absolute-expired, revoked, a revoked
-- credential, a demo account, a sponsor-only member and a member with no active membership are indistinguishable, and so is a second bind in one transaction.
CREATE FUNCTION private.bind_partner_session(p_token_hash text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_xact xid8;
  v_s record;
  v_pol record;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000';
  END IF;
  v_xact := pg_current_xact_id();
  -- refuses when ANY binding (user, delegate or partner) already exists in this transaction (R2-N2): a transaction cannot be re-bound
  IF EXISTS (SELECT 1 FROM private.actor_binding b WHERE b.backend_pid = pg_backend_pid() AND b.xact = v_xact) THEN
    RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000';
  END IF;
  SELECT s.* INTO v_s FROM private.partner_session_by_hash(p_token_hash) s;
  IF NOT FOUND OR v_s.revoked_at IS NOT NULL OR v_s.expires_at <= clock_timestamp() OR NOT v_s.credential_live THEN
    RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000';
  END IF;
  IF private.is_demo_account(v_s.user_id) THEN
    RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000';
  END IF;
  -- a member with at least one non-revoked membership whose role is not sponsor, or an admin
  IF NOT (private.is_admin(v_s.user_id)
          OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_s.user_id AND m.revoked_at IS NULL AND m.role <> 'sponsor')) THEN
    RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000';
  END IF;
  SELECT p.* INTO v_pol FROM private.partner_session_policy(v_s.user_id) p;
  IF v_s.last_seen_at + v_pol.idle <= clock_timestamp() THEN
    RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000';
  END IF;
  INSERT INTO private.actor_binding (backend_pid, xact, actor_uid, kind, session_id, bound_at)
  VALUES (pg_backend_pid(), v_xact, v_s.user_id, 'partner', v_s.id, clock_timestamp())
  ON CONFLICT (backend_pid) DO UPDATE
    SET xact = EXCLUDED.xact, actor_uid = EXCLUDED.actor_uid, kind = EXCLUDED.kind, session_id = EXCLUDED.session_id, bound_at = EXCLUDED.bound_at;
  -- "the user lane sees no actor" is checked from the row just written: actor_uid() must be NULL and the kind must read back as 'partner'
  IF private.actor_uid() IS NOT NULL OR private.partner_binding_kind() IS DISTINCT FROM 'partner' THEN
    RAISE EXCEPTION 'partner_session_refused' USING ERRCODE = '28000';
  END IF;
END;
$$;

-- 6f. One audit_log row for a partner action, the actor taken from the transaction's own binding (NULL for the system lane). EXECUTE for the toucher only (S1.1a).
CREATE FUNCTION private.partner_audit_write(p_action text, p_subject_table text, p_subject_id text, p_detail jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_actor uuid;
BEGIN
  IF p_action IS NULL OR p_action !~ '^partner\.[a-z_.]{3,60}$' OR p_subject_table IS NULL OR length(p_subject_table) > 80 OR length(coalesce(p_subject_id, '')) > 80 THEN
    RAISE EXCEPTION 'partner_audit_write: invalid action or subject' USING ERRCODE = '22023';
  END IF;
  SELECT b.actor_uid INTO v_actor
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned() AND b.kind = 'partner';
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (v_actor, p_action, p_subject_table, p_subject_id, coalesce(p_detail, '{}'::jsonb));
END;
$$;

-- 6g. THE ONE AUTHORIZATION SEAM (4.3). SECURITY DEFINER, VOLATILE, search_path = '', EXECUTE for nobody (called only from sibling definers: the
-- offline_seed_derive shape). Every refusal is 42501 (the handler maps it to 403, or 404 where the plan says a foreign id must not be probeable).
--
-- Classes: SESSION (sign-out, lock: a live session, no scope, no aal gate: 4.1; advances last_seen_at like any user-initiated call), PEEK (GET session: SESSION that NEVER
-- advances last_seen_at, so reading one's own session does not keep it alive: 4.2), A0 (a live session at the required aal), A0_KEEPALIVE (A0 that never
-- advances last_seen_at: the keep-alive-exempt routes of 4.2), A1 (A0 + a single-use PIN grant, consumed here), A2 and A3 (FAIL CLOSED until S1.3 / S1.4: PA-4b).
CREATE FUNCTION private.partner_authorize(p_facility_id text, p_trail_id text, p_roles app.partner_role[], p_class text)
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
  -- 5. fail CLOSED on a class whose prerequisite is not implemented yet (S1.1a ships A2 and A3 refusing everything, admin included; S1.3 / S1.4 enable them).
  -- Placed first on purpose: no later change to the checks below can relax it. No interim relaxation is allowed (PA-4b).
  IF p_class IN ('A2', 'A3') THEN
    RAISE EXCEPTION 'partner_authorize: class % is not enabled (fails closed until its prerequisite exists)', p_class USING ERRCODE = '42501';
  END IF;
  IF p_class NOT IN ('SESSION', 'PEEK') AND (p_roles IS NULL OR cardinality(p_roles) = 0 OR p_roles && ARRAY['sponsor']::app.partner_role[]) THEN
    RAISE EXCEPTION 'partner_authorize: an explicit, non-empty role list without sponsor is required' USING ERRCODE = '22023';
  END IF;
  -- 2. lock the session row FIRST, and ONLY it (R3-M1 option a). FOR SHARE for a call that will not write it, FOR NO KEY UPDATE for a call that will (two FOR SHARE
  -- holders that both then UPDATE deadlock). The policy this needs is pd_partner_session_action (a lock is invisible without it under FORCE RLS, R2-M2).
  SELECT s.last_seen_at INTO v_s FROM app.partner_session s WHERE s.id = v_sid;
  v_write := p_class = 'A1' OR (p_class NOT IN ('A0_KEEPALIVE', 'PEEK') AND (v_s.last_seen_at IS NULL OR v_s.last_seen_at < clock_timestamp() - interval '1 minute'));
  IF v_write THEN
    SELECT s.user_id, s.credential_id, s.aal, s.last_seen_at, s.expires_at, s.revoked_at INTO v_s
    FROM app.partner_session s WHERE s.id = v_sid FOR NO KEY UPDATE;
  ELSE
    SELECT s.user_id, s.credential_id, s.aal, s.last_seen_at, s.expires_at, s.revoked_at INTO v_s
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
    -- the class prerequisite, consuming any single-use PIN grant in THIS transaction (a refused call rolls the consumption back with everything else)
    IF p_class = 'A1' AND NOT private.partner_pin_grant_consume() THEN
      RAISE EXCEPTION 'partner_authorize: a PIN verified in the last minute and not yet used is required' USING ERRCODE = '42501';
    END IF;
  END IF;
  -- idle is extended only by user-initiated calls, at most once a minute (4.2); A0_KEEPALIVE and PEEK never
  IF v_write AND p_class NOT IN ('A0_KEEPALIVE', 'PEEK') AND v_s.last_seen_at < clock_timestamp() - interval '1 minute' THEN
    UPDATE app.partner_session s SET last_seen_at = clock_timestamp() WHERE s.id = v_sid;
  END IF;
  RETURN v_uid;
END;
$$;

-- 6h. partner_session_guard (R4-L1, R5-L1, R5-N1): a BEFORE UPDATE trigger enforcing what no column grant can, for EVERY writer. SECURITY DEFINER with search_path = ''
-- and owned by private_definer, which owns no table in app and so cannot DISABLE it (ALTER TABLE ... DISABLE TRIGGER needs table ownership). It no longer reads any
-- "artefact" row: a verification fact is the ROLE that wrote the column (the verifier roles). What remains: immutability, monotonicity and the "now + N" caps; and,
-- for the OTP proof, that the GoTrue session it names exists for THIS user and is fresh (the 0041 check). The caps use clock_timestamp(): a verifier sets now() + N.
CREATE FUNCTION private.partner_session_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.mint_kind IS DISTINCT FROM OLD.mint_kind OR NEW.mint_nonce_hash IS DISTINCT FROM OLD.mint_nonce_hash
     OR NEW.mint_authenticator_data IS DISTINCT FROM OLD.mint_authenticator_data OR NEW.mint_client_data_json IS DISTINCT FROM OLD.mint_client_data_json
     OR NEW.mint_signature IS DISTINCT FROM OLD.mint_signature
     OR NEW.enrolment_until IS DISTINCT FROM OLD.enrolment_until OR NEW.pop_jkt IS DISTINCT FROM OLD.pop_jkt THEN
    RAISE EXCEPTION 'partner_session_guard: identity, mint and enrolment columns never change after insert (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF NEW.expires_at > OLD.expires_at THEN
    RAISE EXCEPTION 'partner_session_guard: expires_at may not increase (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION 'partner_session_guard: a revoked session stays revoked, with its reason (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF NEW.aal < OLD.aal THEN
    RAISE EXCEPTION 'partner_session_guard: aal only goes from 1 to 2 (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF NEW.mfa_until IS DISTINCT FROM OLD.mfa_until AND NEW.mfa_until IS NOT NULL AND NEW.mfa_until > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'partner_session_guard: mfa_until is at most now + 5 minutes (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF NEW.pin_grant_until IS DISTINCT FROM OLD.pin_grant_until AND NEW.pin_grant_until IS NOT NULL AND NEW.pin_grant_until > clock_timestamp() + interval '60 seconds' THEN
    RAISE EXCEPTION 'partner_session_guard: pin_grant_until is at most now + 60 seconds (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF NEW.reauth_until IS DISTINCT FROM OLD.reauth_until AND NEW.reauth_until IS NOT NULL AND NEW.reauth_until > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'partner_session_guard: reauth_until is at most now + 5 minutes (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  -- the OTP proof: a NEW proof needs a NEW GoTrue session id that exists for this user and is fresh; the window is at most now + 10 minutes; the GoTrue session id itself is never cleared or re-pointed without a new fresh one (only otp_proof_until may be cleared or shortened)
  IF NEW.otp_proof_gotrue_session_id IS DISTINCT FROM OLD.otp_proof_gotrue_session_id THEN
    IF NEW.otp_proof_gotrue_session_id IS NULL
       OR NEW.otp_proof_until IS NULL OR NEW.otp_proof_until > clock_timestamp() + interval '10 minutes'
       OR NOT EXISTS (SELECT 1 FROM auth.sessions g
                      WHERE g.id = NEW.otp_proof_gotrue_session_id AND g.user_id = OLD.user_id
                        AND g.created_at >= clock_timestamp() - interval '60 seconds' AND g.created_at <= clock_timestamp() + interval '60 seconds') THEN
      RAISE EXCEPTION 'partner_session_guard: an OTP proof needs a fresh GoTrue session of this user and a window of at most 10 minutes (id=%)', OLD.id USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.otp_proof_until IS DISTINCT FROM OLD.otp_proof_until AND NEW.otp_proof_until IS NOT NULL
        AND (OLD.otp_proof_until IS NULL OR NEW.otp_proof_until > OLD.otp_proof_until) THEN
    RAISE EXCEPTION 'partner_session_guard: otp_proof_until may only be cleared or shortened without a new GoTrue session (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  IF NEW.last_seen_at < OLD.last_seen_at OR NEW.last_seen_at > clock_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'partner_session_guard: last_seen_at is monotone and at most now + 1 minute (id=%)', OLD.id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

-- 6h2. The INSERT guards (S1.1a gate M2). The issuer holds a relation-wide INSERT with WITH CHECK (true) (it is the mint's role), so WHAT may be inserted is the guard's
-- business, exactly as the UPDATE guard's: a session is born at aal 1 with no verification fact, no revocation, no OTP proof and no touch; its clocks are the database's (created_at and
-- last_seen_at within a minute of now); an enrolment window exists only on a `register` mint and is at most 15 minutes; and its absolute life is at most the person's role ceiling
-- (staff and manager 8 h, operator 4 h, admin 1 h, 4.1). Without it the issuer could insert an aal 2 session of 10 years with a PIN grant, and partner_authorize would pass it.
CREATE FUNCTION private.partner_session_insert_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_pol record;
BEGIN
  IF NEW.aal <> 1 THEN
    RAISE EXCEPTION 'partner_session_insert_guard: a session is born at aal 1 (id=%)', NEW.id USING ERRCODE = '23514';
  END IF;
  IF NEW.pin_grant_until IS NOT NULL OR NEW.reauth_until IS NOT NULL OR NEW.mfa_until IS NOT NULL OR NEW.otp_proof_until IS NOT NULL OR NEW.otp_proof_gotrue_session_id IS NOT NULL
     OR NEW.revoked_at IS NOT NULL OR NEW.revoke_reason IS NOT NULL OR NEW.authority_touched_at IS NOT NULL THEN
    RAISE EXCEPTION 'partner_session_insert_guard: a new session carries no verification fact, revocation, OTP proof or touch (id=%)', NEW.id USING ERRCODE = '23514';
  END IF;
  IF NEW.enrolment_until IS NOT NULL
     AND (NEW.mint_kind <> 'register' OR NEW.enrolment_until <= clock_timestamp() - interval '1 minute' OR NEW.enrolment_until > clock_timestamp() + interval '15 minutes') THEN
    RAISE EXCEPTION 'partner_session_insert_guard: an enrolment window belongs to a register mint and is at most 15 minutes (id=%)', NEW.id USING ERRCODE = '23514';
  END IF;
  IF NEW.created_at < clock_timestamp() - interval '1 minute' OR NEW.created_at > clock_timestamp() + interval '1 minute'
     OR NEW.last_seen_at < clock_timestamp() - interval '1 minute' OR NEW.last_seen_at > clock_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'partner_session_insert_guard: created_at and last_seen_at are the database''s own clock (id=%)', NEW.id USING ERRCODE = '23514';
  END IF;
  SELECT p.* INTO v_pol FROM private.partner_session_policy(NEW.user_id) p;
  IF NEW.expires_at > NEW.created_at + v_pol.absolute THEN
    RAISE EXCEPTION 'partner_session_insert_guard: the absolute life of this person''s sessions is at most % (id=%)', v_pol.absolute, NEW.id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

-- the credential's twin: the issuer may insert a credential, but a credential is BORN live, never used, never revoked, on the database's clock
CREATE FUNCTION private.partner_credential_insert_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL OR NEW.revoke_reason IS NOT NULL OR NEW.last_used_at IS NOT NULL THEN
    RAISE EXCEPTION 'partner_credential_insert_guard: a new credential is live and unused (id=%)', NEW.id USING ERRCODE = '23514';
  END IF;
  IF NEW.created_at < clock_timestamp() - interval '1 minute' OR NEW.created_at > clock_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'partner_credential_insert_guard: created_at is the database''s own clock (id=%)', NEW.id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

-- 6i. The two invariant triggers (5.2). SECURITY DEFINER (they read partner_org and partner_scope under their own narrow policies, whoever the writer is).
CREATE FUNCTION private.partner_member_role_invariant()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_kind app.partner_org_kind;
BEGIN
  SELECT o.kind INTO v_kind FROM app.partner_org o WHERE o.id = NEW.org_id;
  -- an org that does not exist is the foreign key's refusal, not this one's
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;
  -- explicit lists, never partner_role_rank (whose sponsor ties operator): staff and manager only in a facility org, operator only in an operator org, sponsor only in a sponsor org
  IF NOT ((v_kind = 'facility' AND NEW.role IN ('staff', 'manager'))
          OR (v_kind = 'operator' AND NEW.role = 'operator')
          OR (v_kind = 'sponsor' AND NEW.role = 'sponsor')) THEN
    RAISE EXCEPTION 'partner_member: role % is not allowed in an org of kind % (org %)', NEW.role, v_kind, NEW.org_id USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION private.partner_scope_invariant()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_kind app.partner_org_kind;
BEGIN
  SELECT o.kind INTO v_kind FROM app.partner_org o WHERE o.id = NEW.org_id;
  IF NOT FOUND THEN
    RETURN NEW;
  END IF;
  IF v_kind = 'facility' THEN
    -- a facility org holds exactly ONE scope row and it is a facility (G2): the grant "subset of the inviter's scope" then has a precise meaning
    IF NEW.facility_id IS NULL OR NEW.trail_id IS NOT NULL OR NEW.sponsorship_id IS NOT NULL THEN
      RAISE EXCEPTION 'partner_scope: a facility org holds only a facility scope (org %)', NEW.org_id USING ERRCODE = '23514';
    END IF;
    -- serialise concurrent writers for ONE org, so the count below cannot be raced past (each statement then sees the other's committed row). That RELIES on READ COMMITTED
    -- (a fresh snapshot per statement): under REPEATABLE READ or SERIALIZABLE the count would not see the winner's commit, so those isolation levels are refused, fail closed.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
      RAISE EXCEPTION 'partner_scope: a facility org scope is written under READ COMMITTED only (org %)', NEW.org_id USING ERRCODE = '25000';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('partner_scope:' || NEW.org_id::text, 47));
    IF EXISTS (SELECT 1 FROM app.partner_scope s WHERE s.org_id = NEW.org_id AND s.id <> NEW.id) THEN
      RAISE EXCEPTION 'partner_scope: a facility org holds at most one scope row (org %)', NEW.org_id USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 7. The toucher's functions (4.3, 5.2, R5-L2) and the pin verifier's grant consumption (R5-L1)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_session_toucher, partner_pin_verifier;
SET ROLE partner_session_toucher;

-- 7a. What the binder and partner_authorize need to read about a session and its credential, as a role that CAN read them (private_definer has no policy on
-- partner_credential, and a lookup BY token_hash cannot be an own-session policy: the binding does not exist yet). EXECUTE for private_definer only.
CREATE FUNCTION private.partner_session_by_hash(p_token_hash text)
RETURNS TABLE (id uuid, user_id uuid, credential_id uuid, aal smallint, last_seen_at timestamptz, expires_at timestamptz, revoked_at timestamptz, credential_live boolean)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT s.id, s.user_id, s.credential_id, s.aal, s.last_seen_at, s.expires_at, s.revoked_at,
         EXISTS (SELECT 1 FROM app.partner_credential c WHERE c.id = s.credential_id AND c.revoked_at IS NULL)
  FROM app.partner_session s
  WHERE s.token_hash = p_token_hash
$$;

CREATE FUNCTION private.partner_credential_live(p_credential_id uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (SELECT 1 FROM app.partner_credential c WHERE c.id = p_credential_id AND c.revoked_at IS NULL)
$$;

-- 7b. R5-L2: SUBJECT-based. `kind` is user (a uid), org (every member of an org: the panic button) or credential (every session that credential minted); the sessions are
-- DERIVED here, never passed in. An org revoke reaches the org's ACTIVE members only (a revoked member's sessions already died with the revoke, and they may be active in another
-- org: their sessions there stay). One audit_log row per call, naming the SUBJECT'S own table, carrying the caller's binding. EXECUTE for private_definer ONLY: it is called by the member-revoke, recover,
-- revoke-all, credential-revoke and TOTP-reset definers AFTER their own reach-rule and scope checks (S1.5 / S1.4). Revoking the session that makes the call is intended:
-- a revoke-all kills the revoker's own session too.
CREATE FUNCTION private.partner_sessions_revoke(p_kind text, p_id uuid, p_reason text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_kind IS NULL OR p_kind NOT IN ('user', 'org', 'credential') OR p_id IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z_]{3,40}$' THEN
    RAISE EXCEPTION 'partner_sessions_revoke: a kind (user, org or credential), a subject id and a reason are required' USING ERRCODE = '22023';
  END IF;
  UPDATE app.partner_session s SET revoked_at = clock_timestamp(), revoke_reason = p_reason
  WHERE s.revoked_at IS NULL
    AND CASE p_kind
          WHEN 'user' THEN s.user_id = p_id
          WHEN 'org' THEN s.user_id IN (SELECT m.user_id FROM app.partner_member m WHERE m.org_id = p_id AND m.revoked_at IS NULL)
          ELSE s.credential_id = p_id
        END;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  PERFORM private.partner_audit_write('partner.sessions_revoke',
                                      CASE p_kind WHEN 'user' THEN 'auth.users' WHEN 'org' THEN 'app.partner_org' ELSE 'app.partner_credential' END, p_id::text,
                                      jsonb_build_object('kind', p_kind, 'reason', p_reason, 'revoked', v_n));
  RETURN v_n;
END;
$$;

-- 7c. THE AUTHORITY TRIGGERS (5.2, R3-M1, R4-M1): every change of authority touches the affected user's sessions IN THE SAME TRANSACTION, and that UPDATE of a session row
-- WAITS for an in-flight action's lock on it, so a revoker cannot commit while an action that relied on the old authority is still open. They run as the TOUCHER with
-- column grants only: no GUC window, no wide private_definer policy. Membership INSERT / UPDATE / DELETE and admin_user INSERT / DELETE REVOKE; scope UPDATE / DELETE TOUCH.
CREATE FUNCTION private.partner_authority_revoke_sessions()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_exempt uuid := NULL;
  v_uids uuid[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_uids := ARRAY[NEW.user_id];
  ELSIF TG_OP = 'DELETE' THEN
    v_uids := ARRAY[OLD.user_id];
  ELSE
    v_uids := ARRAY[OLD.user_id, NEW.user_id];
  END IF;
  -- the ACCEPTING session itself is exempt (a branch-E accept inserts or reactivates the accepting member's own membership, 6.1): only for an INSERT or a
  -- reactivation, never for a revoke, so a member revoking themselves still loses their session
  -- (nested IFs on purpose: OLD is unassigned in an INSERT trigger and has no revoked_at on admin_user, and plpgsql does not promise short-circuit evaluation)
  IF TG_TABLE_NAME = 'partner_member' THEN
    IF TG_OP = 'INSERT' THEN
      v_exempt := private.partner_binding_session();
    ELSIF TG_OP = 'UPDATE' THEN
      IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN
        v_exempt := private.partner_binding_session();
      END IF;
    END IF;
  END IF;
  UPDATE app.partner_session s SET revoked_at = clock_timestamp(), revoke_reason = 'authority_changed'
  WHERE s.user_id = ANY (v_uids) AND s.revoked_at IS NULL AND s.id IS DISTINCT FROM v_exempt;
  RETURN NULL;
END;
$$;

CREATE FUNCTION private.partner_scope_authority_touch()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  -- scope loss is serialised behind an in-flight action like a revoke, without killing sessions (R3-M1): the sessions are TOUCHED, the next call re-reads
  UPDATE app.partner_session s SET authority_touched_at = clock_timestamp()
  WHERE s.revoked_at IS NULL
    AND s.user_id IN (SELECT m.user_id FROM app.partner_member m WHERE m.org_id = OLD.org_id OR (TG_OP = 'UPDATE' AND m.org_id = NEW.org_id));
  RETURN NULL;
END;
$$;

CREATE FUNCTION private.partner_authority_truncate_revoke()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  UPDATE app.partner_session s SET revoked_at = clock_timestamp(), revoke_reason = 'authority_changed' WHERE s.revoked_at IS NULL;
  RETURN NULL;
END;
$$;

RESET ROLE;
SET ROLE partner_pin_verifier;

-- 7d. Consumes the bound session's single-use PIN grant (4.3 step 4): ONE atomic UPDATE, so two concurrent actions cannot both spend one PIN. pin_grant_until is a column only
-- this role can write (R5-L1); the grant is SET by the S1.3 verifier (also owned by this role) and cleared here. EXECUTE for private_definer only.
CREATE FUNCTION private.partner_pin_grant_consume()
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  UPDATE app.partner_session s SET pin_grant_until = NULL
  WHERE s.id = private.partner_binding_session() AND s.pin_grant_until IS NOT NULL AND s.pin_grant_until > clock_timestamp();
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n = 1;
END;
$$;

RESET ROLE;

-- ============================================================================
-- 8. Triggers (created as the migrating role: CREATE TRIGGER needs EXECUTE on the function, which PUBLIC still holds until section 10) and policies
-- ============================================================================
CREATE TRIGGER partner_member_role_invariant_trg BEFORE INSERT OR UPDATE OF role, org_id ON app.partner_member
FOR EACH ROW EXECUTE FUNCTION private.partner_member_role_invariant();
CREATE TRIGGER partner_scope_invariant_trg BEFORE INSERT OR UPDATE OF org_id, facility_id, trail_id, sponsorship_id ON app.partner_scope
FOR EACH ROW EXECUTE FUNCTION private.partner_scope_invariant();

CREATE TRIGGER partner_member_authority_ins_trg AFTER INSERT ON app.partner_member
FOR EACH ROW EXECUTE FUNCTION private.partner_authority_revoke_sessions();
CREATE TRIGGER partner_member_authority_upd_trg AFTER UPDATE OF revoked_at, role, user_id, org_id ON app.partner_member
FOR EACH ROW EXECUTE FUNCTION private.partner_authority_revoke_sessions();
CREATE TRIGGER partner_member_authority_del_trg AFTER DELETE ON app.partner_member
FOR EACH ROW EXECUTE FUNCTION private.partner_authority_revoke_sessions();
CREATE TRIGGER admin_user_authority_ins_trg AFTER INSERT ON app.admin_user
FOR EACH ROW EXECUTE FUNCTION private.partner_authority_revoke_sessions();
CREATE TRIGGER admin_user_authority_del_trg AFTER DELETE ON app.admin_user
FOR EACH ROW EXECUTE FUNCTION private.partner_authority_revoke_sessions();
CREATE TRIGGER admin_user_authority_upd_trg AFTER UPDATE ON app.admin_user
FOR EACH ROW EXECUTE FUNCTION private.partner_authority_revoke_sessions();
-- TRUNCATE fires no row trigger: a statement trigger revokes EVERY live session (a truncated authority table leaves no per-person record to reason about)
CREATE TRIGGER partner_member_authority_trunc_trg BEFORE TRUNCATE ON app.partner_member
FOR EACH STATEMENT EXECUTE FUNCTION private.partner_authority_truncate_revoke();
CREATE TRIGGER admin_user_authority_trunc_trg BEFORE TRUNCATE ON app.admin_user
FOR EACH STATEMENT EXECUTE FUNCTION private.partner_authority_truncate_revoke();
CREATE TRIGGER partner_scope_authority_trunc_trg BEFORE TRUNCATE ON app.partner_scope
FOR EACH STATEMENT EXECUTE FUNCTION private.partner_authority_truncate_revoke();
CREATE TRIGGER partner_scope_authority_upd_trg AFTER UPDATE ON app.partner_scope
FOR EACH ROW EXECUTE FUNCTION private.partner_scope_authority_touch();
CREATE TRIGGER partner_scope_authority_del_trg AFTER DELETE ON app.partner_scope
FOR EACH ROW EXECUTE FUNCTION private.partner_scope_authority_touch();

CREATE TRIGGER partner_session_guard_trg BEFORE UPDATE ON app.partner_session
FOR EACH ROW EXECUTE FUNCTION private.partner_session_guard();
CREATE TRIGGER partner_session_insert_guard_trg BEFORE INSERT ON app.partner_session
FOR EACH ROW EXECUTE FUNCTION private.partner_session_insert_guard();
CREATE TRIGGER partner_credential_insert_guard_trg BEFORE INSERT ON app.partner_credential
FOR EACH ROW EXECUTE FUNCTION private.partner_credential_insert_guard();

-- 8a. private_definer's policies. The delete_my_data window pairs on the four tables THIS migration creates carry (from the start; 8c does the same for every other window in the schema) one extra conjunct, `private.partner_binding_kind() IS DISTINCT FROM 'partner'`:
-- under a partner binding the window is CLOSED, so a planted app.delete_my_data.target_user_id cannot make another person's session, credential, enrolment token or used challenge
-- readable, deletable or redactable by a definer a partner transaction reaches (probed 2026-10-04: without it a partner-bound private_definer DELETEd another user's session). The
-- delete_my_data pass itself runs under no partner binding, so it is unaffected. The "IS NULL" legs of the set-null SELECT companions are tied to an OPEN window (the setting is non-empty),
-- so without a window private_definer sees none of those rows (S1.1a gate M1: it used to see every pending invite's address and token hash).
-- partner_session: its OWN row only, keyed on the transaction's binding (the ONE lock-and-write policy of R3-M1 option a, and its row-visibility
-- companion: 0016 "_r companion" finding); the delete_my_data pairs follow the 0016 form (the registry pass requires them: check 8).
CREATE POLICY pd_partner_session_action ON app.partner_session
  FOR UPDATE TO private_definer USING (id = private.partner_binding_session()) WITH CHECK (id = private.partner_binding_session());
CREATE POLICY pd_partner_session_action_r ON app.partner_session
  FOR SELECT TO private_definer USING (id = private.partner_binding_session());
CREATE POLICY pd_delete_partner_session_user_id ON app.partner_session
  FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_delete_partner_session_user_id_r ON app.partner_session
  FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');

CREATE POLICY pd_delete_partner_credential_user_id ON app.partner_credential
  FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_delete_partner_credential_user_id_r ON app.partner_credential
  FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_setnull_partner_credential_revoked_by ON app.partner_credential
  FOR UPDATE TO private_definer USING (revoked_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner') WITH CHECK (revoked_by IS NULL);
CREATE POLICY pd_setnull_partner_credential_revoked_by_r ON app.partner_credential
  FOR SELECT TO private_definer USING (((revoked_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid) OR (revoked_by IS NULL AND nullif(current_setting('app.delete_my_data.target_user_id', true), '') IS NOT NULL)) AND private.partner_binding_kind() IS DISTINCT FROM 'partner');

CREATE POLICY pd_delete_partner_enrolment_token_user_id ON app.partner_enrolment_token
  FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_delete_partner_enrolment_token_user_id_r ON app.partner_enrolment_token
  FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_setnull_partner_enrolment_token_issued_by ON app.partner_enrolment_token
  FOR UPDATE TO private_definer USING (issued_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner') WITH CHECK (issued_by IS NULL);
CREATE POLICY pd_setnull_partner_enrolment_token_issued_by_r ON app.partner_enrolment_token
  FOR SELECT TO private_definer USING (((issued_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid) OR (issued_by IS NULL AND nullif(current_setting('app.delete_my_data.target_user_id', true), '') IS NOT NULL)) AND private.partner_binding_kind() IS DISTINCT FROM 'partner');

CREATE POLICY pd_delete_partner_auth_challenge_user_id ON app.partner_auth_challenge
  FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_delete_partner_auth_challenge_user_id_r ON app.partner_auth_challenge
  FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');

CREATE POLICY pd_setnull_partner_invite_accepted_by ON app.partner_invite
  FOR UPDATE TO private_definer USING (accepted_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner') WITH CHECK (accepted_by IS NULL);
CREATE POLICY pd_setnull_partner_invite_accepted_by_r ON app.partner_invite
  FOR SELECT TO private_definer USING (((accepted_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid) OR (accepted_by IS NULL AND nullif(current_setting('app.delete_my_data.target_user_id', true), '') IS NOT NULL)) AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
CREATE POLICY pd_setnull_partner_invite_revoked_by ON app.partner_invite
  FOR UPDATE TO private_definer USING (revoked_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner') WITH CHECK (revoked_by IS NULL);
CREATE POLICY pd_setnull_partner_invite_revoked_by_r ON app.partner_invite
  FOR SELECT TO private_definer USING (((revoked_by = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid) OR (revoked_by IS NULL AND nullif(current_setting('app.delete_my_data.target_user_id', true), '') IS NOT NULL)) AND private.partner_binding_kind() IS DISTINCT FROM 'partner');

-- the invariant triggers read the org's kind (id, kind only: column-level grant)
CREATE POLICY pd_read_partner_org_kind ON app.partner_org FOR SELECT TO private_definer USING (true);

-- 8b. The five owner roles' policies (R5-L4). Per ROLE: a policy of one role never applies to another, so there is no cross-role OR; the column grants of section 5 are the real limit.
CREATE POLICY pst_read_partner_member ON app.partner_member FOR SELECT TO partner_session_toucher USING (true);
CREATE POLICY pst_read_partner_scope ON app.partner_scope FOR SELECT TO partner_session_toucher USING (true);
CREATE POLICY pst_read_partner_credential ON app.partner_credential FOR SELECT TO partner_session_toucher USING (true);
CREATE POLICY pst_update_partner_credential ON app.partner_credential FOR UPDATE TO partner_session_toucher USING (true) WITH CHECK (true);
CREATE POLICY pst_read_partner_session ON app.partner_session FOR SELECT TO partner_session_toucher USING (true);
CREATE POLICY pst_update_partner_session ON app.partner_session FOR UPDATE TO partner_session_toucher USING (true) WITH CHECK (true);

CREATE POLICY psi_read_partner_session ON app.partner_session FOR SELECT TO partner_session_issuer USING (true);
CREATE POLICY psi_insert_partner_session ON app.partner_session FOR INSERT TO partner_session_issuer WITH CHECK (true);
CREATE POLICY psi_read_partner_credential ON app.partner_credential FOR SELECT TO partner_session_issuer USING (true);
CREATE POLICY psi_insert_partner_credential ON app.partner_credential FOR INSERT TO partner_session_issuer WITH CHECK (true);


CREATE POLICY ppv_read_partner_session ON app.partner_session FOR SELECT TO partner_pin_verifier USING (id = private.partner_binding_session());
CREATE POLICY ppv_update_partner_session ON app.partner_session FOR UPDATE TO partner_pin_verifier
  USING (id = private.partner_binding_session()) WITH CHECK (id = private.partner_binding_session());
CREATE POLICY ptv_read_partner_session ON app.partner_session FOR SELECT TO partner_totp_verifier USING (id = private.partner_binding_session());
CREATE POLICY ptv_update_partner_session ON app.partner_session FOR UPDATE TO partner_totp_verifier
  USING (id = private.partner_binding_session()) WITH CHECK (id = private.partner_binding_session());
CREATE POLICY prv_read_partner_session ON app.partner_session FOR SELECT TO partner_reauth_verifier USING (id = private.partner_binding_session());
CREATE POLICY prv_update_partner_session ON app.partner_session FOR UPDATE TO partner_reauth_verifier
  USING (id = private.partner_binding_session()) WITH CHECK (id = private.partner_binding_session());

-- 8c. THE WINDOWS (S1.1a gate H1). Every GUC-keyed private_definer policy in the schema is a "window": a transaction-local setting that some definer sets and a policy then reads
-- (delete_my_data's target user, the sign-in proof, the device link, the purge windows, the guards). A GUC is settable by ANY session, including edge_partner, and it persists into a
-- later SECURITY DEFINER call (R4-M1), so none of these may be open inside a PARTNER-bound transaction: with the window open and a partner binding, a private_definer-owned
-- definer a partner transaction can reach could un-revoke and promote a member (R3-M1), delete a membership or an admin_user row, or read pending invites. No window needs to be open under a partner
-- binding (delete_my_data, the purges and the guards all run under a user binding, a system delegate or none), so the one conjunct below is added to EVERY such policy, discovered from
-- the catalog (not named), in USING and in WITH CHECK wherever the policy has one. The tables of a slice that merges later are covered in two ways: a policy that exists when this
-- migration runs is closed here; a policy added afterwards must carry the conjunct itself, and verify-function-inventory check 15 (and PA-4c) fail the build until it does.
DO $close_windows_0047$
DECLARE
  v_pd oid := (SELECT oid FROM pg_roles WHERE rolname = 'private_definer');
  v_pol record;
  v_using text;
  v_check text;
  v_sql text;
  v_n integer := 0;
BEGIN
  FOR v_pol IN
    SELECT n.nspname, c.relname, pol.polname,
           pg_get_expr(pol.polqual, pol.polrelid) AS qual, pg_get_expr(pol.polwithcheck, pol.polrelid) AS wcheck
    FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE pol.polroles = ARRAY[v_pd]
      AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') LIKE '%current_setting(%' OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') LIKE '%current_setting(%')
      AND coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') NOT LIKE '%partner_binding_kind()%'
    ORDER BY n.nspname, c.relname, pol.polname
  LOOP
    v_sql := format('ALTER POLICY %I ON %I.%I', v_pol.polname, v_pol.nspname, v_pol.relname);
    IF v_pol.qual IS NOT NULL THEN
      v_sql := v_sql || format(' USING ((%s) AND private.partner_binding_kind() IS DISTINCT FROM ''partner'')', v_pol.qual);
    END IF;
    IF v_pol.wcheck IS NOT NULL THEN
      v_sql := v_sql || format(' WITH CHECK ((%s) AND private.partner_binding_kind() IS DISTINCT FROM ''partner'')', v_pol.wcheck);
    END IF;
    EXECUTE v_sql;
    v_n := v_n + 1;
  END LOOP;
  -- fail loudly: no GUC-keyed private_definer policy may remain open
  IF EXISTS (SELECT 1 FROM pg_policy pol
             WHERE pol.polroles = ARRAY[v_pd]
               AND (coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') LIKE '%current_setting(%' OR coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') LIKE '%current_setting(%')
               AND coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') NOT LIKE '%partner_binding_kind()%') THEN
    RAISE EXCEPTION '0047: a GUC-keyed private_definer policy is still open under a partner binding';
  END IF;
  RAISE NOTICE '0047: closed % GUC-keyed private_definer window polic(ies) under a partner binding', v_n;
END
$close_windows_0047$;

-- ============================================================================
-- 9. EXECUTE grants (PUBLIC revoked first: a function created by a role other than the migrating role defaults to PUBLIC EXECUTE). Each as its OWNER.
-- ============================================================================
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.partner_binding() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_binding_kind() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_binding_session() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_session_policy(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.bind_partner_session(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_audit_write(text, text, text, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_authorize(text, text, app.partner_role[], text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_session_guard() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_session_insert_guard() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_credential_insert_guard() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_member_role_invariant() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_scope_invariant() FROM PUBLIC;
-- edge_partner: EXACTLY the binder and the two read-only binding helpers (4.3, 5.3)
GRANT EXECUTE ON FUNCTION private.bind_partner_session(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_binding() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_binding_kind() TO edge_partner;
-- the roles whose policy (or trigger) calls it: a policy's function is EXECUTE-checked against the role the policy applies to
GRANT EXECUTE ON FUNCTION private.partner_binding_session() TO partner_session_toucher, partner_pin_verifier, partner_totp_verifier, partner_reauth_verifier;
GRANT EXECUTE ON FUNCTION private.partner_audit_write(text, text, text, jsonb) TO partner_session_toucher;
-- partner_authorize, partner_session_policy and the three trigger functions: nobody (owner only)
COMMENT ON FUNCTION private.bind_partner_session(text) IS
  '0047. edge_partner only. The ONLY producer of a partner binding: refuses (one SQLSTATE 28000, one message) an unknown, idle-expired, absolute-expired or revoked session, a revoked credential, a demo account, a sponsor-only member, a member with no active membership, a malformed hash, and ANY existing binding in the transaction.';
COMMENT ON FUNCTION private.partner_authorize(text, text, app.partner_role[], text) IS
  '0047. Executable by NOBODY (called from sibling definers; every *_for_partner function must call it as its first statement: check 14). Locks the bound session row only, re-reads session / role / scope / aal on every call, fails closed on A2 and A3 until S1.3 / S1.4, returns the member''s uid.';
RESET ROLE;

SET ROLE partner_session_toucher;
REVOKE EXECUTE ON FUNCTION private.partner_session_by_hash(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_credential_live(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_sessions_revoke(text, uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_authority_revoke_sessions() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_scope_authority_touch() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_authority_truncate_revoke() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_session_by_hash(text) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_credential_live(uuid) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_sessions_revoke(text, uuid, text) TO private_definer;
RESET ROLE;

SET ROLE partner_pin_verifier;
REVOKE EXECUTE ON FUNCTION private.partner_pin_grant_consume() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_pin_grant_consume() TO private_definer;
RESET ROLE;

REVOKE CREATE ON SCHEMA private FROM partner_session_toucher, partner_pin_verifier;
-- R5-L3: the migrating role keeps NO way to become an owner role (a PG16+ CREATEROLE creator keeps ADMIN on the roles it creates, which is all that may remain)
REVOKE partner_session_toucher FROM CURRENT_USER;
REVOKE partner_pin_verifier FROM CURRENT_USER;

-- ============================================================================
-- 10. D12 / section 5.5: revoke the PostgREST partner-lane read surface
-- ============================================================================
-- Mobile is unaffected (it uses only the Auth client and makes no PostgREST read: E22). Without this the same person's Supabase JWT, reachable by email OTP alone, reads partner
-- data with NO passkey (G1). Replaced by Edge reads in S1.5 / S2b / S3 / S5 / S6. service_role keeps its grants (the Edge no longer uses it, PR4b); edge roles never had any.
REVOKE SELECT ON
  api.staff_shift_log, api.staff_activity, api.special_marker_stock, api.special_marker_stock_movement,
  api.facility_programme, api.marker_code_batch, api.facility_qr, api.sponsorship, api.operator_rollup, api.sponsor_rollup,
  api.my_partner_org, api.my_partner_member, api.my_partner_scope, api.my_partner_invite
FROM authenticated;
-- L10: the base tables too, so a future view cannot inherit a grant that has no consumer (0009:15-31)
REVOKE SELECT ON
  app.partner_org, app.partner_member, app.partner_scope, app.partner_invite, app.facility_programme, app.attestation_shift_log,
  app.staff_activity, app.special_marker_stock, app.special_marker_stock_movement, app.sponsorship, app.operator_rollup, app.sponsor_rollup,
  app.marker_code_batch, app.facility_qr
FROM authenticated;

-- Redefined, NOT revoked (players need them): api.offer and api.my_offers() answer LIVE offers with the five scope-conditional columns NULL for EVERYONE (M1: a scoped
-- member's JWT read the operator's budget and RuleExpr through them, and drafts through offer_read). The partner read of offers moves to offers-admin (S6). CREATE OR REPLACE VIEW
-- can append but not drop a column (0024:73-76), so the columns stay, typed as before, constant NULL.
CREATE OR REPLACE VIEW api.offer WITH (security_invoker = true, security_barrier = true) AS
  SELECT
    id, terms_id, trail_id, facility_id, funder, sponsorship_id, valid_from, valid_to, status,
    NULL::jsonb AS eligibility,
    NULL::numeric AS budget_cap,
    NULL::numeric AS budget_used,
    NULL::numeric AS budget_reserved,
    NULL::int AS max_redemptions
  FROM app.offer;

CREATE OR REPLACE FUNCTION api.my_offers()
RETURNS TABLE (
  id uuid, terms_id text, trail_id text, facility_id text, funder app.offer_funder,
  sponsorship_id uuid, valid_from date, valid_to date, status app.offer_status,
  eligibility jsonb, budget_cap numeric, budget_used numeric, budget_reserved numeric,
  max_redemptions int
)
LANGUAGE sql STABLE
AS $$
  -- Live, currently-valid offers, with NO budget or eligibility to anyone (0047, D12 / M1): a partner reads those through the Edge only.
  SELECT
    o.id, o.terms_id, o.trail_id, o.facility_id, o.funder, o.sponsorship_id,
    o.valid_from, o.valid_to, o.status,
    NULL::jsonb, NULL::numeric, NULL::numeric, NULL::numeric, NULL::int
  FROM app.offer o
  WHERE o.status = 'live'
    AND (o.valid_from IS NULL OR o.valid_from <= current_date)
    AND (o.valid_to IS NULL OR o.valid_to >= current_date);
$$;

-- The row policy: live offers only. The scope legs are REMOVED (narrowed, never broadened): a scoped member's JWT no longer sees a draft, an approved or an ended offer.
ALTER POLICY offer_read ON app.offer USING (status = 'live');
-- (S1.1a gate L7, the 0009:15-31 / L10 reasoning applied to the one base table the masked view reads) `authenticated` keeps SELECT only on the columns api.offer and api.my_offers() expose,
-- never budget_cap / budget_used / budget_reserved / eligibility / max_redemptions: a whole-row grant would give a future non-invoker view, or a direct app.offer read, the operator's budget.
REVOKE SELECT ON app.offer FROM authenticated;
GRANT SELECT (id, terms_id, trail_id, facility_id, funder, sponsorship_id, valid_from, valid_to, status) ON app.offer TO authenticated;

-- ============================================================================
-- 11. X9: staff authority under a plain user binding is revoked from the Edge (the function and its atomic-replay proofs STAY)
-- ============================================================================
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.offline_code_record_step_for_actor(uuid, integer, bigint, text) FROM edge_actor;
RESET ROLE;

-- ============================================================================
-- 12. private.export_my_data: rebuilt from 0045's FINAL body with exactly ONE change (the partner_credential block, commented 0047)
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

  -- 0045: offline_seed_version added to the column list (a counter about the account's own device).
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, platform, attest_key_id, attest_counter, integrity_last, first_attested_at, offline_seed_version, first_seen, last_seen
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

  -- 0047 (partner-auth-design 5.4 item 3): the account's own partner credentials, METADATA ONLY. Not the public key, not the credential id, not the sign counter: nothing that
  -- could be replayed or used to fingerprint an authenticator. (Sessions, challenges and enrolment tokens are credential artefacts, not the subject's data: excluded.)
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT id, user_id, alg, transports, backup_eligible, backup_state, aaguid, label, note, created_at, last_used_at, revoked_at, revoke_reason
    FROM app.partner_credential WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('partner_credential', v_json);

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

  -- 0045: the account's own offline-code replay rows (which step of which of its OWN devices was accepted, at which facility, and when). The seed itself is
  -- DERIVED, never stored, and is never exported; the version on the device block is just a counter.
  SELECT coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) INTO v_json FROM (
    SELECT user_id, device_id, seed_version, step, facility_id, used_at
    FROM app.offline_code_step WHERE user_id = p_user_id
  ) t;
  v_result := v_result || jsonb_build_object('offline_code_step', v_json);

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

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 13. Registries
-- ============================================================================
-- 13a. private.function_inventory: the two new role columns (default false for every function) and the rows of this file
ALTER TABLE private.function_inventory
  ADD COLUMN expected_edge_partner boolean NOT NULL DEFAULT false,
  ADD COLUMN expected_edge_partner_minter boolean NOT NULL DEFAULT false;
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0047 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.function_inventory
SET expected_edge_actor = false,
    note = '0045 / 0047 (X9): the staff lane''s atomic replay record, kept as a PRIMITIVE with its proofs; EXECUTE REVOKED from edge_actor (staff authority under a plain user binding is not a Edge capability: staff-lane code runs under a partner binding, P5). Owner only; the proofs call it as private_definer after bind_actor.'
WHERE schema_name = 'private' AND function_name = 'offline_code_record_step_for_actor' AND identity_args = 'p_device_id uuid, p_seed_version integer, p_step bigint, p_facility_id text';
DO $assert_0047_x9$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM private.function_inventory WHERE function_name = 'offline_code_record_step_for_actor' AND NOT expected_edge_actor AND note LIKE '0045 / 0047 (X9)%') THEN
    RAISE EXCEPTION '0047: the X9 inventory row was not updated (an UPDATE that matches nothing is silent)';
  END IF;
END
$assert_0047_x9$;
DROP POLICY current_user_edit_function_inventory_0047 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, note)
VALUES
  ('app', 'partner_org_kind_immutable', '', false, false, false, false, false, false, '0047: trigger function (BEFORE UPDATE OF kind on app.partner_org): an org''s kind never changes; never EXECUTEd directly by any role'),
  ('app', 'partner_credential_label_trg', '', false, false, false, false, false, false, '0047: trigger function (BEFORE INSERT on app.partner_credential): the label is derived by the database, never client-supplied; never EXECUTEd directly by any role'),
  ('app', 'partner_credential_guard', '', false, false, false, false, false, false, '0047: trigger function (BEFORE UPDATE on app.partner_credential): identity columns immutable, a revocation final, sign_count never decreases; never EXECUTEd directly by any role'),
  ('private', 'bind_partner_session', 'p_token_hash text', false, false, false, false, false, true, '0047: edge_partner only; the ONLY producer of a partner binding; one uniform refusal (28000); refuses when any binding already exists in the transaction'),
  ('private', 'partner_binding', '', false, false, false, false, false, true, '0047: edge_partner; read-only: the kind and session id of THIS transaction''s binding'),
  ('private', 'partner_binding_kind', '', false, false, false, false, false, true, '0047: edge_partner; read-only: the kind of THIS transaction''s binding (the Edge''s post-bind assertion reads it)'),
  ('private', 'partner_binding_session', '', false, false, false, false, false, false, '0047: the predicate inside every own-session policy of app.partner_session; EXECUTE for private_definer (owner) and the toucher / verifier roles whose policy or trigger calls it, nobody else (private.partner_owner_privilege)'),
  ('private', 'partner_session_policy', 'p_uid uuid', false, false, false, false, false, false, '0047: required aal, idle timeout and absolute session ceiling of a person (highest role wins); no role has EXECUTE: bind_partner_session and partner_authorize call it'),
  ('private', 'partner_audit_write', 'p_action text, p_subject_table text, p_subject_id text, p_detail jsonb', false, false, false, false, false, false, '0047: one audit_log row for a partner action, the actor taken from the binding; EXECUTE for partner_session_toucher only (private.partner_owner_privilege)'),
  ('private', 'partner_authorize', 'p_facility_id text, p_trail_id text, p_roles app.partner_role[], p_class text', false, false, false, false, false, false, '0047: THE authorization seam; no role has EXECUTE (called only from sibling *_for_partner definers, whose first statement must call it: check 14)'),
  ('private', 'partner_session_guard', '', false, false, false, false, false, false, '0047: trigger function (BEFORE UPDATE on app.partner_session): immutability, monotonicity and now + N caps for every writer; never EXECUTEd directly by any role'),
  ('private', 'partner_session_insert_guard', '', false, false, false, false, false, false, '0047 (S1.1a gate M2): trigger function (BEFORE INSERT on app.partner_session): born at aal 1 with no verification fact, the database clock, the role ceiling on the absolute life; never EXECUTEd directly by any role'),
  ('private', 'partner_credential_insert_guard', '', false, false, false, false, false, false, '0047 (S1.1a gate M2): trigger function (BEFORE INSERT on app.partner_credential): born live, unused, on the database clock; never EXECUTEd directly by any role'),
  ('private', 'partner_member_role_invariant', '', false, false, false, false, false, false, '0047: trigger function (BEFORE INSERT OR UPDATE OF role, org_id on app.partner_member): the role must match the org kind; never EXECUTEd directly by any role'),
  ('private', 'partner_scope_invariant', '', false, false, false, false, false, false, '0047: trigger function (BEFORE INSERT OR UPDATE on app.partner_scope): a facility org holds exactly one facility scope; never EXECUTEd directly by any role'),
  ('private', 'partner_session_by_hash', 'p_token_hash text', false, false, false, false, false, false, '0047: owned by partner_session_toucher; the session and credential facts the binder needs; EXECUTE for private_definer only (private.partner_owner_privilege is for the owner; the grant to private_definer is checked by the inventory)'),
  ('private', 'partner_credential_live', 'p_credential_id uuid', false, false, false, false, false, false, '0047: owned by partner_session_toucher; is the credential present and not revoked; called by partner_authorize; no role but private_definer'),
  ('private', 'partner_sessions_revoke', 'p_kind text, p_id uuid, p_reason text', false, false, false, false, false, false, '0047 (R5-L2): owned by partner_session_toucher; SUBJECT-based (user, org, credential), derives the sessions itself, one audit_log row per call; callable by private_definer only, from the reach-checked definers'),
  ('private', 'partner_authority_revoke_sessions', '', false, false, false, false, false, false, '0047: trigger function (partner_member INSERT / UPDATE / DELETE, admin_user INSERT / UPDATE / DELETE) owned by partner_session_toucher: revokes the user''s sessions in the same transaction; never EXECUTEd directly by any role'),
  ('private', 'partner_scope_authority_touch', '', false, false, false, false, false, false, '0047: trigger function (partner_scope UPDATE / DELETE) owned by partner_session_toucher: touches the sessions of the org''s members; never EXECUTEd directly by any role'),
  ('private', 'partner_authority_truncate_revoke', '', false, false, false, false, false, false, '0047 (S1.1a gate L6): statement trigger function (BEFORE TRUNCATE on partner_member, admin_user, partner_scope) owned by partner_session_toucher: revokes every live session; never EXECUTEd directly by any role'),
  ('private', 'partner_pin_grant_consume', '', false, false, false, false, false, false, '0047 (R5-L1): owned by partner_pin_verifier; atomically consumes the bound session''s single-use PIN grant; EXECUTE for private_definer only');

-- 13b. private.definer_policy_allowlist: the policies of the five NEW owner roles are registered too. A role_name column (default private_definer: every existing row keeps its meaning) says
-- which role a row is for; checks 5 / 6 / 9 / 10 and the fixture compare it.
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0047 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
ALTER TABLE private.definer_policy_allowlist ADD COLUMN role_name text NOT NULL DEFAULT 'private_definer';
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_session', 'pd_partner_session_action', 'UPDATE', true, 'partner_authorize (FOR SHARE / FOR NO KEY UPDATE lock, last_seen_at), sign-out and own revoke: ONLY the bound session''s own row, keyed on the transaction''s binding (private.partner_binding_session()), never a GUC; the lock-and-write policy of R3-M1 option a; column grants + partner_session_guard narrow what it may change', 'private_definer'),
  ('app', 'partner_session', 'pd_partner_session_action_r', 'SELECT', true, 'row-visibility companion to pd_partner_session_action (UPDATE ... WHERE and a row lock need SELECT-level visibility under FORCE RLS, confirmed empirically)', 'private_definer'),
  ('app', 'partner_session', 'pd_delete_partner_session_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_session.user_id = delete_row); the 0016 GUC window, DELETE ONLY (no UPDATE policy is keyed on it: PA-4c plants it)', 'private_definer'),
  ('app', 'partner_session', 'pd_delete_partner_session_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_partner_session_user_id', 'private_definer'),
  ('app', 'partner_credential', 'pd_delete_partner_credential_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_credential.user_id = delete_row)', 'private_definer'),
  ('app', 'partner_credential', 'pd_delete_partner_credential_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_partner_credential_user_id; also the export read and delete_my_data''s post-condition count (column-level SELECT grant)', 'private_definer'),
  ('app', 'partner_credential', 'pd_setnull_partner_credential_revoked_by', 'UPDATE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_credential.revoked_by = set_null); the column-level UPDATE grant is revoked_by ONLY', 'private_definer'),
  ('app', 'partner_credential', 'pd_setnull_partner_credential_revoked_by_r', 'SELECT', true, 'row-visibility companion to pd_setnull_partner_credential_revoked_by (the 0016 form: ORs in the post-update condition)', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_delete_partner_enrolment_token_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_enrolment_token.user_id = delete_row)', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_delete_partner_enrolment_token_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_partner_enrolment_token_user_id', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_setnull_partner_enrolment_token_issued_by', 'UPDATE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_enrolment_token.issued_by = set_null); the column-level UPDATE grant is issued_by ONLY', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_setnull_partner_enrolment_token_issued_by_r', 'SELECT', true, 'row-visibility companion to pd_setnull_partner_enrolment_token_issued_by', 'private_definer'),
  ('app', 'partner_auth_challenge', 'pd_delete_partner_auth_challenge_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_auth_challenge.user_id = delete_row)', 'private_definer'),
  ('app', 'partner_auth_challenge', 'pd_delete_partner_auth_challenge_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_partner_auth_challenge_user_id', 'private_definer'),
  ('app', 'partner_invite', 'pd_setnull_partner_invite_accepted_by', 'UPDATE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_invite.accepted_by = set_null); the column-level UPDATE grant is accepted_by and revoked_by ONLY', 'private_definer'),
  ('app', 'partner_invite', 'pd_setnull_partner_invite_accepted_by_r', 'SELECT', true, 'row-visibility companion to pd_setnull_partner_invite_accepted_by', 'private_definer'),
  ('app', 'partner_invite', 'pd_setnull_partner_invite_revoked_by', 'UPDATE', true, 'delete_my_data''s generic pass (pii_retention_policy: partner_invite.revoked_by = set_null)', 'private_definer'),
  ('app', 'partner_invite', 'pd_setnull_partner_invite_revoked_by_r', 'SELECT', true, 'row-visibility companion to pd_setnull_partner_invite_revoked_by', 'private_definer'),
  ('app', 'partner_org', 'pd_read_partner_org_kind', 'SELECT', true, 'partner_member_role_invariant / partner_scope_invariant read an org''s kind for ANY org (column-level grant: id and kind only); the function body is the real scope', 'private_definer'),
  ('app', 'partner_member', 'pst_read_partner_member', 'SELECT', true, 'R5-L4: the authority triggers (partner_scope_authority_touch) read the members of an org; column-level grant (user_id, org_id, role, revoked_at)', 'partner_session_toucher'),
  ('app', 'partner_scope', 'pst_read_partner_scope', 'SELECT', true, 'R5-L4: the toucher reads scope rows (column-level grant: id, org_id, facility_id, trail_id)', 'partner_session_toucher'),
  ('app', 'partner_credential', 'pst_read_partner_credential', 'SELECT', true, 'R5-L4: partner_session_by_hash / partner_credential_live read a credential''s revocation state (column-level grant: id, user_id, revoked_at)', 'partner_session_toucher'),
  ('app', 'partner_credential', 'pst_update_partner_credential', 'UPDATE', true, 'S1.5 credential revoke (column-level grant: revoked_at, revoked_by, revoke_reason), after the reach rule; partner_credential_guard makes a revocation final', 'partner_session_toucher'),
  ('app', 'partner_session', 'pst_read_partner_session', 'SELECT', true, 'the authority triggers, partner_sessions_revoke and the binder lookup read sessions (column-level grant: no mint_* evidence)', 'partner_session_toucher'),
  ('app', 'partner_session', 'pst_update_partner_session', 'UPDATE', true, 'the authority triggers and partner_sessions_revoke: revoked_at, revoke_reason and authority_touched_at ONLY (column grant); partner_session_guard refuses an un-revoke', 'partner_session_toucher'),
  ('app', 'partner_session', 'psi_read_partner_session', 'SELECT', true, 'S1.1b mint / register_first (column-level grant); nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_session', 'psi_insert_partner_session', 'INSERT', false, 'S1.1b mint / register_first insert the session row; nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_credential', 'psi_read_partner_credential', 'SELECT', true, 'S1.1b register_first (column-level grant); nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_credential', 'psi_insert_partner_credential', 'INSERT', false, 'S1.1b register_first inserts the first credential; nobody can become partner_session_issuer', 'partner_session_issuer'),
  ('app', 'partner_session', 'ppv_read_partner_session', 'SELECT', true, 'R5-L1: the PIN verifier sees its own bound session (column-level grant: id, pin_grant_until), keyed on the binding', 'partner_pin_verifier'),
  ('app', 'partner_session', 'ppv_update_partner_session', 'UPDATE', true, 'R5-L1: the ONLY writer of pin_grant_until (column grant), its own bound session only, keyed on the binding', 'partner_pin_verifier'),
  ('app', 'partner_session', 'ptv_read_partner_session', 'SELECT', true, 'R5-L1: the TOTP verifier sees its own bound session (column-level grant: id, aal, mfa_until)', 'partner_totp_verifier'),
  ('app', 'partner_session', 'ptv_update_partner_session', 'UPDATE', true, 'R5-L1: the ONLY writer of aal and mfa_until (column grant), its own bound session only', 'partner_totp_verifier'),
  ('app', 'partner_session', 'prv_read_partner_session', 'SELECT', true, 'R5-L1: the reauth verifier sees its own bound session (column-level grant: id, reauth_until)', 'partner_reauth_verifier'),
  ('app', 'partner_session', 'prv_update_partner_session', 'UPDATE', true, 'R5-L1: the ONLY writer of reauth_until (column grant), its own bound session only', 'partner_reauth_verifier');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  -- the 0047 policies, and EVERY policy section 8c closed under a partner binding (its stored expression is a snapshot of the live one; checks 5 / 6 compare the two)
  AND (pol.polname LIKE 'pd\_%partner\_%' OR pol.polname LIKE 'pst\_%' OR pol.polname LIKE 'psi\_%'
       OR pol.polname LIKE 'ppv\_%' OR pol.polname LIKE 'ptv\_%' OR pol.polname LIKE 'prv\_%'
       OR coalesce(pg_get_expr(pol.polqual, pol.polrelid), '') || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '') LIKE '%partner_binding_kind()%')
  AND al.role_name <> '';
DO $assert_0047_allowlist$
BEGIN
  IF EXISTS (SELECT 1 FROM private.definer_policy_allowlist WHERE role_name <> 'private_definer' AND using_expr IS NULL AND with_check_expr IS NULL) THEN
    RAISE EXCEPTION '0047: an allowlist row of a new owner role names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0047_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0047 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 13c. PII registries (E9): every FK to auth.users is classified, and every table has an export decision. delete_my_data and export_my_data fail closed without these.
GRANT INSERT ON private.pii_retention_policy TO CURRENT_USER;
CREATE POLICY current_user_seed_pii_retention_policy_0047 ON private.pii_retention_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'partner_credential', 'user_id', 'delete_row', 'the person''s own WebAuthn credentials (0047): deleted with the account by delete_my_data''s generic pass (and by FK cascade with the auth user)'),
  ('app', 'partner_credential', 'revoked_by', 'set_null', 'who revoked a credential: the revoked credential row survives its revoker''s account (it is the credential owner''s record); only the revoker''s identity is redacted'),
  ('app', 'partner_session', 'user_id', 'delete_row', 'the person''s own partner sessions and their mint evidence (0047): deleted with the account'),
  ('app', 'partner_enrolment_token', 'user_id', 'delete_row', 'the person''s own recovery / admin enrolment tokens (0047): deleted with the account'),
  ('app', 'partner_enrolment_token', 'issued_by', 'set_null', 'who issued a token: the token row survives its issuer''s account until its own retention; only the issuer''s identity is redacted'),
  ('app', 'partner_auth_challenge', 'user_id', 'delete_row', 'the person''s used-challenge nonces (0047): deleted with the account'),
  ('app', 'partner_invite', 'accepted_by', 'set_null', 'who accepted an invite (0047): the invite row survives for its inviter / org audit until the 90-day purge; only the acceptor''s identity is redacted'),
  ('app', 'partner_invite', 'revoked_by', 'set_null', 'who revoked an invite (0047): only the revoker''s identity is redacted');
DROP POLICY current_user_seed_pii_retention_policy_0047 ON private.pii_retention_policy;
REVOKE INSERT ON private.pii_retention_policy FROM CURRENT_USER;

CREATE POLICY current_user_seed_pii_export_policy_0047 ON private.pii_export_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_export_policy (schema_name, table_name, action, reason) VALUES
  ('app', 'partner_credential', 'export', 'the subject''s own credential METADATA (alg, transports, backup flags, aaguid, derived label, note, timestamps): never the public key, the credential id or the sign counter'),
  ('app', 'partner_session', 'exclude', 'a login artefact: a hashed bearer token and the WebAuthn assertion evidence of its mint, which exist to detect a forged mint (S1.6), not to describe the subject'),
  ('app', 'partner_enrolment_token', 'exclude', 'a hashed single-use enrolment token: a credential-adjacent artefact, not the subject''s own data'),
  ('app', 'partner_auth_challenge', 'exclude', 'used challenge nonce hashes: replay-protection state of a login flow, not the subject''s own data');
DROP POLICY current_user_seed_pii_export_policy_0047 ON private.pii_export_policy;

-- 13d. The exact privileges the five owner roles may hold (5.4 item 5): re-derived from the catalog by checks 9 and 12, both directions, and compared with a checked-in fixture by the node check
CREATE TABLE private.partner_owner_privilege (
  role_name text NOT NULL,
  object_kind text NOT NULL CHECK (object_kind IN ('schema', 'relation', 'column', 'function')),
  object_name text NOT NULL,
  privilege text NOT NULL,
  column_name text,
  CHECK ((object_kind = 'column') = (column_name IS NOT NULL))
);
CREATE UNIQUE INDEX partner_owner_privilege_uidx ON private.partner_owner_privilege (role_name, object_kind, object_name, privilege, coalesce(column_name, ''));
ALTER TABLE private.partner_owner_privilege ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.partner_owner_privilege FORCE ROW LEVEL SECURITY;
GRANT SELECT ON private.partner_owner_privilege TO service_role;
CREATE POLICY current_user_seed_partner_owner_privilege_0047 ON private.partner_owner_privilege
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.partner_owner_privilege (role_name, object_kind, object_name, privilege, column_name) VALUES
  ('partner_session_toucher', 'schema', 'app', 'USAGE', NULL),
  ('partner_session_toucher', 'schema', 'private', 'USAGE', NULL),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'id'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'user_id'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'credential_id'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'token_hash'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'aal'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'created_at'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'last_seen_at'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'expires_at'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'revoked_at'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'revoke_reason'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'SELECT', 'authority_touched_at'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'UPDATE', 'revoked_at'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'UPDATE', 'revoke_reason'),
  ('partner_session_toucher', 'column', 'app.partner_session', 'UPDATE', 'authority_touched_at'),
  ('partner_session_toucher', 'column', 'app.partner_member', 'SELECT', 'user_id'),
  ('partner_session_toucher', 'column', 'app.partner_member', 'SELECT', 'org_id'),
  ('partner_session_toucher', 'column', 'app.partner_member', 'SELECT', 'role'),
  ('partner_session_toucher', 'column', 'app.partner_member', 'SELECT', 'revoked_at'),
  ('partner_session_toucher', 'column', 'app.partner_scope', 'SELECT', 'id'),
  ('partner_session_toucher', 'column', 'app.partner_scope', 'SELECT', 'org_id'),
  ('partner_session_toucher', 'column', 'app.partner_scope', 'SELECT', 'facility_id'),
  ('partner_session_toucher', 'column', 'app.partner_scope', 'SELECT', 'trail_id'),
  ('partner_session_toucher', 'column', 'app.partner_credential', 'SELECT', 'id'),
  ('partner_session_toucher', 'column', 'app.partner_credential', 'SELECT', 'user_id'),
  ('partner_session_toucher', 'column', 'app.partner_credential', 'SELECT', 'revoked_at'),
  ('partner_session_toucher', 'column', 'app.partner_credential', 'UPDATE', 'revoked_at'),
  ('partner_session_toucher', 'column', 'app.partner_credential', 'UPDATE', 'revoked_by'),
  ('partner_session_toucher', 'column', 'app.partner_credential', 'UPDATE', 'revoke_reason'),
  ('partner_session_toucher', 'function', 'private.partner_binding_session()', 'EXECUTE', NULL),
  ('partner_session_toucher', 'function', 'private.partner_audit_write(text,text,text,jsonb)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'schema', 'app', 'USAGE', NULL),
  ('partner_session_issuer', 'schema', 'private', 'USAGE', NULL),
  ('partner_session_issuer', 'column', 'app.partner_session', 'SELECT', 'id'),
  ('partner_session_issuer', 'column', 'app.partner_session', 'SELECT', 'user_id'),
  ('partner_session_issuer', 'column', 'app.partner_session', 'SELECT', 'token_hash'),
  ('partner_session_issuer', 'column', 'app.partner_session', 'SELECT', 'revoked_at'),
  ('partner_session_issuer', 'column', 'app.partner_session', 'SELECT', 'created_at'),
  ('partner_session_issuer', 'relation', 'app.partner_session', 'INSERT', NULL),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'SELECT', 'id'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'SELECT', 'user_id'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'SELECT', 'credential_id'),
  ('partner_session_issuer', 'column', 'app.partner_credential', 'SELECT', 'revoked_at'),
  ('partner_session_issuer', 'relation', 'app.partner_credential', 'INSERT', NULL),
  ('partner_pin_verifier', 'schema', 'app', 'USAGE', NULL),
  ('partner_pin_verifier', 'schema', 'private', 'USAGE', NULL),
  ('partner_pin_verifier', 'column', 'app.partner_session', 'SELECT', 'id'),
  ('partner_pin_verifier', 'column', 'app.partner_session', 'SELECT', 'pin_grant_until'),
  ('partner_pin_verifier', 'column', 'app.partner_session', 'UPDATE', 'pin_grant_until'),
  ('partner_pin_verifier', 'function', 'private.partner_binding_session()', 'EXECUTE', NULL),
  ('partner_totp_verifier', 'schema', 'app', 'USAGE', NULL),
  ('partner_totp_verifier', 'schema', 'private', 'USAGE', NULL),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'SELECT', 'id'),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'SELECT', 'aal'),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'SELECT', 'mfa_until'),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'UPDATE', 'aal'),
  ('partner_totp_verifier', 'column', 'app.partner_session', 'UPDATE', 'mfa_until'),
  ('partner_totp_verifier', 'function', 'private.partner_binding_session()', 'EXECUTE', NULL),
  ('partner_reauth_verifier', 'schema', 'app', 'USAGE', NULL),
  ('partner_reauth_verifier', 'schema', 'private', 'USAGE', NULL),
  ('partner_reauth_verifier', 'column', 'app.partner_session', 'SELECT', 'id'),
  ('partner_reauth_verifier', 'column', 'app.partner_session', 'SELECT', 'reauth_until'),
  ('partner_reauth_verifier', 'column', 'app.partner_session', 'UPDATE', 'reauth_until'),
  ('partner_reauth_verifier', 'function', 'private.partner_binding_session()', 'EXECUTE', NULL);
DROP POLICY current_user_seed_partner_owner_privilege_0047 ON private.partner_owner_privilege;
COMMENT ON TABLE private.partner_owner_privilege IS
  '0047. The registry of EXACTLY the privileges partner_session_toucher / _issuer and partner_pin_verifier / partner_totp_verifier / partner_reauth_verifier may hold (schema USAGE, table and column privileges, EXECUTE). tools/db/verify-function-inventory.mjs check 9 and the matrix re-derive the real set from the catalog and compare both ways; supabase/tests/fixtures/partner_owner_privileges.txt is its checked-in twin.';
