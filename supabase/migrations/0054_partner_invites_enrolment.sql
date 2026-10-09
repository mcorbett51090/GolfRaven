-- 0054_partner_invites_enrolment.sql
--
-- P5.1a, slice S1.5: INVITES, ENROLMENT AND MEMBERS (database half). docs/security/partner-auth-design.md (revision 5) is the specification: sections 5.1 (the register HMAC), 5.2 (last-membership
-- PIN / TOTP), 5.3 (the function list), 6.1 (invite, accept, enrol: branches N and E), 6.5 (the reach rule; recovery; revoke-all), 9 (retention), 12 (S1.5), 12.1 (PA-14, PA-15, PA-16, PA-22,
-- PA-23, PA-25, PA-29) and 21.4 (the seams S1.4 left: full reach for the TOTP reset, the last-membership delete). Migrations 0001-0053 are untouched; everything below is CREATE, GRANT, or
-- CREATE OR REPLACE of partner_totp_reset_for_partner (the S1.4 admin-lite reset, now under the full reach rule).
--
-- WHAT THIS ADDS
--   1. THE REGISTER CHALLENGE (5.1). partner_challenge_core / partner_challenge_verify get an OVERLOAD that appends ref_kind (1 byte: 1 invite, 2 enrolment token) || ref_id (16 bytes) ||
--      accepted_at_us (int8send, 8 bytes) for purpose 2 and refuses the refs for any other purpose. The 5-arg signatures are untouched (the matrix 26 vectors depend on them). The only
--      producer of a register challenge is private.partner_challenge_issue_register (EXECUTE for partner_session_issuer alone), called inside the accept definers after every check passed.
--   2. THE REACH RULE (6.5). private.partner_reach_covers(actor, target) is conditions (1) to (5) exactly; partner_reach_covers_org(actor, target, org) is the same rule for ONE membership (the
--      member revoke). Both are EXECUTE for nobody but the owner and the three owner roles whose registered policies call them (toucher, pin verifier). No edge role can call them.
--   3. THE MINTER LANE (edge_partner_minter, unbound; owned by partner_session_issuer like the 0048 / 0049 minter definers, so private_definer's M1 rule (it sees no invite without a binding) is
--      unchanged): partner_invite_email_for_token, partner_invite_accept, partner_enrolment_token_email_for_token, partner_enrolment_token_accept (every counter / mismatch outcome a STATUS that
--      commits, never a RAISE: PA-14) and partner_credential_register_first (the DB-side create checks of R4-L2, which parse the COSE key with partner_cose_parse; one registration per
--      acceptance; refuses an active credential and, for an invite, any other-org membership; mints the first session in the same transaction; evicts beyond three live sessions).
--   4. THE PARTNER LANE (edge_partner; class A0 / A2 / A3): invite create (explicit role arrays, grant subset through has_facility_scope, 72 h, refuses sponsor and an active member), list,
--      revoke, branch-E accept; member revoke (one membership), recover, pin reset (all under the reach rule); credential options / register (second) / list / revoke; org revoke-all;
--      partner_totp_reset_for_partner under the full reach rule.
--   5. THE LAST-MEMBERSHIP TRIGGER (5.2, PA-29): revoking or deleting a person's last active membership deletes their partner_pin and, unless they are in app.admin_user, their partner_totp.
--   6. THE PURGES (9): purge_partner_challenges / sessions / credentials / invites / enrolment_tokens / sign_in_failures, the 0040 shape (a constant LIMIT 5000, the floor repeated in a policy).
--   7. Policies, grants and registries: every new policy is keyed on the transaction's binding (or on an accepted invite row), never on a settable GUC, and has a definer_policy_allowlist row
--      and a line in supabase/tests/fixtures/definer_policy_exprs.txt; every privilege an owner role gains is in private.partner_owner_privilege and its fixture; every function is in
--      private.function_inventory.
--
-- WHAT THIS DOES NOT BUILD (seams stay intact): the Edge handlers (partner-invites, partner-members, enrolments/*, credentials) and their ports; the PWA screens; the out-of-band notice of a
-- credential add (open item U1: an audit_log row stands in); eviction of the oldest session on a SIGN-IN mint (0048 seam: register_first evicts, the sign-in mint is untouched); pepper / key
-- rotation. The Edge builds the WebAuthn create options (it needs partner_rp_config_read and the exclude list from partner_credential_options_for_partner).

-- ============================================================================
-- 1. The owner roles this file writes functions for: the migrating role holds SET on them for the length of this file only (the 0047 bracket, R5-L3)
-- ============================================================================
GRANT partner_session_toucher, partner_session_issuer, partner_pin_verifier TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;

-- the accept definers read whether the mailbox is confirmed (6.1): one more column of auth.users for private_definer's identity helper
GRANT SELECT (email_confirmed_at) ON auth.users TO private_definer;

-- ============================================================================
-- 2. private_definer, first pass: the reach rule, the register challenge, the identity helper (policies below call them, so they exist first)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 2a. The reach rule for ONE membership (6.5): may `actor` act on `target`'s membership in `org`?
--   (5) actor <> target; (3) an admin target needs an admin actor; the target must hold that ACTIVE membership; an admin actor then passes; (4) an operator (or sponsor) membership is an
--   admin matter; a staff membership needs a manager or operator above the org's one facility, a manager membership an operator, through has_facility_scope with EXPLICIT arrays (never
--   partner_role_rank, whose sponsor ties operator). A facility org with no facility scope row, or any other org kind, is admin-only: fail closed.
CREATE FUNCTION private.partner_reach_covers_org(p_actor uuid, p_target uuid, p_org uuid)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_role app.partner_role;
  v_kind app.partner_org_kind;
  v_fac text;
BEGIN
  IF p_actor IS NULL OR p_target IS NULL OR p_org IS NULL OR p_actor = p_target THEN
    RETURN false;
  END IF;
  IF private.is_admin(p_target) AND NOT private.is_admin(p_actor) THEN
    RETURN false;
  END IF;
  SELECT m.role, o.kind INTO v_role, v_kind
  FROM app.partner_member m JOIN app.partner_org o ON o.id = m.org_id
  WHERE m.user_id = p_target AND m.org_id = p_org AND m.revoked_at IS NULL;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  IF private.is_admin(p_actor) THEN
    RETURN true;
  END IF;
  IF v_role NOT IN ('staff', 'manager') OR v_kind <> 'facility' THEN
    RETURN false;
  END IF;
  SELECT s.facility_id INTO v_fac FROM app.partner_scope s WHERE s.org_id = p_org AND s.facility_id IS NOT NULL LIMIT 1;
  IF v_fac IS NULL THEN
    RETURN false;
  END IF;
  RETURN private.has_facility_scope(p_actor, v_fac,
    CASE WHEN v_role = 'staff' THEN ARRAY['manager', 'operator'] ELSE ARRAY['operator'] END::app.partner_role[]);
END
$$;

-- 2b. The reach rule for a PERSON (6.5, conditions (1) to (5)):
--   (5) actor <> target. (3) an admin target needs an admin actor (whatever memberships it also holds). An admin actor may act on any non-admin target INCLUDING one with no active membership,
--   and on a DIFFERENT admin (so a zero-membership admin is recoverable). For a non-admin actor and a non-admin target: (1) the target holds at least one active membership (a universal check
--   over zero memberships is vacuously true, so it is stated on its own); (4) no operator or sponsor membership (those are admin matters: partner_reach_covers_org is false for them); (2) for
--   EVERY active membership of the target the actor passes with a role strictly above the target's role in that org.
CREATE FUNCTION private.partner_reach_covers(p_actor uuid, p_target uuid)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_actor IS NULL OR p_target IS NULL OR p_actor = p_target THEN
    RETURN false;
  END IF;
  IF private.is_admin(p_actor) THEN
    RETURN true;
  END IF;
  IF private.is_admin(p_target) THEN
    RETURN false;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_target AND m.revoked_at IS NULL) THEN
    RETURN false;
  END IF;
  RETURN NOT EXISTS (
    SELECT 1 FROM app.partner_member m
    WHERE m.user_id = p_target AND m.revoked_at IS NULL AND NOT private.partner_reach_covers_org(p_actor, p_target, m.org_id)
  );
END
$$;

-- 2c. The register challenge, 8-argument overload (5.1). Message after the label, FIXED WIDTH:
--     label || 0x00 || purpose (1) || exp (8) || nonce (32) || binding (16) [ || ref_kind (1) || ref_id (16) || accepted_at_us (8) ]
-- The bracketed tail is present for purpose 2 and REFUSED (22023) for every other purpose, so no two different tuples produce the same bytes. EXECUTE for nobody: the owner's own
-- definers call it. Same Vault key and comparison as the 5-arg core (HMAC(K, presented) = HMAC(K, expected)).
CREATE FUNCTION private.partner_challenge_core(
  p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_presented bytea, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint)
RETURNS TABLE (o_mac bytea, o_ok boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_key text;
  v_k bytea;
  v_msg bytea;
BEGIN
  IF p_purpose IS NULL OR p_purpose NOT IN (1, 2, 3) OR p_exp IS NULL OR p_exp < 0 OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_binding IS NULL THEN
    RAISE EXCEPTION 'partner_challenge_core: a purpose (1 to 3), an expiry, a 32-byte nonce and a binding are required' USING ERRCODE = '22023';
  END IF;
  IF p_purpose = 2 THEN
    IF p_ref_kind IS NULL OR p_ref_kind NOT IN (1, 2) OR p_ref_id IS NULL OR p_accepted_at_us IS NULL OR p_accepted_at_us < 0 THEN
      RAISE EXCEPTION 'partner_challenge_core: a register challenge needs a ref kind (1 or 2), a ref id and an acceptance time' USING ERRCODE = '22023';
    END IF;
  ELSIF p_ref_kind IS NOT NULL OR p_ref_id IS NOT NULL OR p_accepted_at_us IS NOT NULL THEN
    RAISE EXCEPTION 'partner_challenge_core: only a register challenge carries a reference' USING ERRCODE = '22023';
  END IF;
  SELECT s.decrypted_secret INTO v_key FROM vault.decrypted_secrets s WHERE s.name = 'partner_challenge_key';
  IF v_key IS NULL OR pg_catalog.octet_length(pg_catalog.convert_to(v_key, 'UTF8')) < 32 THEN
    RAISE EXCEPTION 'partner_challenge_core: the partner challenge key is not provisioned in Vault' USING ERRCODE = '55000';
  END IF;
  v_k := pg_catalog.convert_to(v_key, 'UTF8');
  v_msg := pg_catalog.convert_to('golfraven/partner-challenge/v1', 'UTF8')
        || pg_catalog.decode('00', 'hex')
        || pg_catalog.set_byte('\x00'::bytea, 0, p_purpose::int)
        || pg_catalog.int8send(p_exp)
        || p_nonce
        || pg_catalog.decode(pg_catalog.replace(p_binding::text, '-', ''), 'hex');
  IF p_purpose = 2 THEN
    v_msg := v_msg
        || pg_catalog.set_byte('\x00'::bytea, 0, p_ref_kind::int)
        || pg_catalog.decode(pg_catalog.replace(p_ref_id::text, '-', ''), 'hex')
        || pg_catalog.int8send(p_accepted_at_us);
  END IF;
  o_mac := public.hmac(v_msg, v_k, 'sha256');
  o_ok := p_presented IS NOT NULL AND public.hmac(p_presented, v_k, 'sha256') = public.hmac(o_mac, v_k, 'sha256');
  RETURN NEXT;
END
$$;

-- 2d. Does this presented MAC belong to (purpose, exp, nonce, binding [, refs])? The ONLY thing register_first and the second-credential wrapper may ask of the key.
CREATE FUNCTION private.partner_challenge_verify(
  p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_mac bytea, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_ok boolean;
BEGIN
  SELECT c.o_ok INTO v_ok FROM private.partner_challenge_core(p_purpose, p_exp, p_nonce, p_binding, p_mac, p_ref_kind, p_ref_id, p_accepted_at_us) c;
  RETURN coalesce(v_ok, false);
END
$$;

-- 2e. THE ONLY ISSUER of a register challenge (6.1: issued only inside the accept definers, after the OTP, the email, the freshness and the credential and membership state were checked, for THAT
-- user and THAT invite or token). 32 random bytes, an expiry 10 minutes ahead (register_first re-checks the acceptance is under 15 minutes old) and the MAC. Refused inside any bound transaction
-- (a minter binds nothing). EXECUTE for partner_session_issuer alone: not for the minter role, so no handler can ask for one.
CREATE FUNCTION private.partner_challenge_issue_register(p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint)
RETURNS TABLE (o_nonce bytea, o_exp bigint, o_mac bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL OR p_ref_kind IS NULL OR p_ref_kind NOT IN (1, 2) OR p_ref_id IS NULL OR p_accepted_at_us IS NULL THEN
    RAISE EXCEPTION 'partner_challenge_issue_register: a user, a ref kind (1 or 2), a ref id and an acceptance time are required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_challenge_issue_register: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  o_nonce := public.gen_random_bytes(32);
  o_exp := pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint + 600;
  SELECT c.o_mac INTO o_mac
  FROM private.partner_challenge_core(2::smallint, o_exp, o_nonce, p_user_id, NULL, p_ref_kind, p_ref_id, p_accepted_at_us) c;
  RETURN NEXT;
END
$$;

-- 2f. What the issuer-owned accept definers need to know about a person and cannot read themselves (the owner roles hold no privilege on auth): the normalised email, whether the mailbox is
-- confirmed, whether the GoTrue session is still fresh (a session row of THIS user created within 60 s: the 0041 / 0052 window; NULL = not asked) and whether the person is an admin.
-- EXECUTE for partner_session_issuer alone.
CREATE FUNCTION private.partner_auth_identity(p_uid uuid, p_gotrue_session_id uuid)
RETURNS TABLE (o_email text, o_confirmed boolean, o_fresh boolean, o_is_admin boolean)
LANGUAGE sql SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT pg_catalog.lower(pg_catalog.btrim(u.email)),
         (u.email_confirmed_at IS NOT NULL),
         (p_gotrue_session_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM auth.sessions g
            WHERE g.id = p_gotrue_session_id AND g.user_id = u.id
              AND g.created_at >= pg_catalog.clock_timestamp() - interval '60 seconds' AND g.created_at <= pg_catalog.clock_timestamp() + interval '60 seconds')),
         private.is_admin(u.id)
  FROM auth.users u WHERE u.id = p_uid
$$;

REVOKE EXECUTE ON FUNCTION
  private.partner_reach_covers_org(uuid, uuid, uuid),
  private.partner_reach_covers(uuid, uuid),
  private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint),
  private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint),
  private.partner_challenge_issue_register(uuid, smallint, uuid, bigint),
  private.partner_auth_identity(uuid, uuid)
FROM PUBLIC;
-- the roles whose registered policies call the reach rule (the policy runs as the role that queries)
GRANT EXECUTE ON FUNCTION private.partner_reach_covers_org(uuid, uuid, uuid) TO partner_session_toucher;
GRANT EXECUTE ON FUNCTION private.partner_reach_covers(uuid, uuid) TO partner_pin_verifier;
GRANT EXECUTE ON FUNCTION private.partner_binding_user() TO partner_session_toucher;
-- the issuer: the register challenge verifier and issuer, the identity helper, the COSE parser and its CBOR head reader (plain plpgsql, not SECURITY DEFINER: the caller needs both), the audit writer
GRANT EXECUTE ON FUNCTION private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_challenge_issue_register(uuid, smallint, uuid, bigint) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_auth_identity(uuid, uuid) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_cose_parse(bytea) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_cbor_head(bytea, int) TO partner_session_issuer;
GRANT EXECUTE ON FUNCTION private.partner_audit_write(text, text, text, jsonb) TO partner_session_issuer;
COMMENT ON FUNCTION private.partner_reach_covers_org(uuid, uuid, uuid) IS
  '0054 (6.5). The reach rule for ONE membership: actor <> target; an admin target needs an admin actor; the target holds that active membership; an admin passes; an operator or sponsor membership is an admin matter; a staff membership needs a manager or operator above the org''s facility, a manager membership an operator (explicit arrays through has_facility_scope). EXECUTE for nobody but the owner and partner_session_toucher (its registered policy calls it).';
COMMENT ON FUNCTION private.partner_reach_covers(uuid, uuid) IS
  '0054 (6.5, PA-25). The reach rule for a PERSON, conditions (1) to (5): an admin may act on any non-admin (zero memberships included) and on a DIFFERENT admin; a non-admin needs a non-admin target with an active membership, none of them operator or sponsor, and covers EVERY active membership. EXECUTE for nobody but the owner and partner_pin_verifier (its registered policies call it).';
COMMENT ON FUNCTION private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint) IS
  '0054 (5.1). The 8-argument overload of the Vault-key core: for purpose 2 the message appends ref_kind (1 byte) || ref_id (16 bytes) || accepted_at_us (int8send, 8 bytes); any other purpose refuses a reference (22023). EXECUTE for nobody: it computes the MAC for any tuple it is handed.';
COMMENT ON FUNCTION private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint) IS
  '0054 (5.1). Does this presented MAC belong to (purpose, exp, nonce, binding, ref kind, ref id, acceptance time)? EXECUTE for partner_session_issuer (register_first).';
COMMENT ON FUNCTION private.partner_challenge_issue_register(uuid, smallint, uuid, bigint) IS
  '0054 (6.1, R3-M2). THE only producer of a register challenge: 32 random bytes, an expiry 600 s ahead and the MAC over uid, ref kind (1 invite / 2 enrolment token), ref id and acceptance time. Refused inside any bound transaction. EXECUTE for partner_session_issuer alone: called inside the accept definers after every check passed.';
COMMENT ON FUNCTION private.partner_auth_identity(uuid, uuid) IS
  '0054 (6.1). The normalised email, the confirmed flag, GoTrue-session freshness (60 s) and the admin flag of a person, for the issuer-owned accept definers (the owner roles hold no privilege on auth). EXECUTE for partner_session_issuer alone.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 3. Grants and policies the new definers rely on. Every policy is keyed on the transaction's BINDING (private.partner_binding_kind() / partner_binding_user()) or on a row a real acceptance
-- produced, never on a settable GUC (the HARD RULE), and is registered in section 9. A policy of one ROLE never applies to another, so there is no cross-role OR (R5-L4).
-- ============================================================================
-- 3a. private_definer (the bound partner lane): invites it creates, lists and revokes; the recover tokens it issues and revokes; the credentials it lists and revokes through the toucher;
-- the purge floors; the last-membership delete. COLUMN-level grants wherever a whole-row grant would reach more than the definers use.
GRANT INSERT (org_id, role, facility_id, trail_id, invited_by, invitee_email, token_hash, expires_at, created_at) ON app.partner_invite TO private_definer;
GRANT UPDATE (revoked_at) ON app.partner_invite TO private_definer;
GRANT SELECT (purpose, created_at, expires_at, consumed_at, revoked_at, attempts, registered_credential_id), UPDATE (revoked_at) ON app.partner_enrolment_token TO private_definer;
GRANT SELECT (credential_id) ON app.partner_credential TO private_definer;
GRANT SELECT (used_at) ON app.partner_auth_challenge TO private_definer;
GRANT SELECT (credential_id, cooldown_until, updated_at), DELETE ON app.partner_sign_in_failure TO private_definer;

-- invites: create (WITH CHECK ties invited_by to the BOUND user; the function checks the grant subset), read and revoke within the actor's scope (the inviter, an admin, a manager or operator of the facility)
CREATE POLICY pd_insert_partner_invite ON app.partner_invite FOR INSERT TO private_definer
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND invited_by = (SELECT private.partner_binding_user())
              AND role <> 'sponsor' AND accepted_at IS NULL AND accepted_by IS NULL AND revoked_at IS NULL AND revoked_by IS NULL AND attempts = 0 AND registered_credential_id IS NULL);
CREATE POLICY pd_read_partner_invite_scope ON app.partner_invite FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND (invited_by = (SELECT private.partner_binding_user())
              OR private.is_admin((SELECT private.partner_binding_user()))
              OR (facility_id IS NOT NULL AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['manager', 'operator']::app.partner_role[]))));
CREATE POLICY pd_revoke_partner_invite ON app.partner_invite FOR UPDATE TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner' AND accepted_at IS NULL AND revoked_at IS NULL
         AND (invited_by = (SELECT private.partner_binding_user())
              OR private.is_admin((SELECT private.partner_binding_user()))
              OR (facility_id IS NOT NULL AND private.has_facility_scope((SELECT private.partner_binding_user()), facility_id, ARRAY['manager', 'operator']::app.partner_role[]))))
  WITH CHECK ((SELECT private.partner_binding_kind()) = 'partner' AND accepted_at IS NULL AND revoked_at IS NOT NULL AND revoked_by = (SELECT private.partner_binding_user()));

-- recover tokens: the actor may insert, read and revoke a `recover` token only for a person the reach rule covers (the admin tokens keep their 0053 insert policy)
CREATE POLICY pd_insert_partner_enrolment_token_recover ON app.partner_enrolment_token FOR INSERT TO private_definer
  WITH CHECK (purpose = 'recover' AND (SELECT private.partner_binding_kind()) = 'partner' AND issued_by = (SELECT private.partner_binding_user())
              AND private.partner_reach_covers((SELECT private.partner_binding_user()), user_id)
              AND consumed_at IS NULL AND revoked_at IS NULL AND registered_credential_id IS NULL AND attempts = 0);
CREATE POLICY pd_read_partner_enrolment_token_recover ON app.partner_enrolment_token FOR SELECT TO private_definer
  USING (purpose = 'recover' AND (SELECT private.partner_binding_kind()) = 'partner'
         AND private.partner_reach_covers((SELECT private.partner_binding_user()), user_id));
CREATE POLICY pd_revoke_partner_enrolment_token_recover ON app.partner_enrolment_token FOR UPDATE TO private_definer
  USING (purpose = 'recover' AND consumed_at IS NULL AND revoked_at IS NULL AND (SELECT private.partner_binding_kind()) = 'partner'
         AND private.partner_reach_covers((SELECT private.partner_binding_user()), user_id))
  WITH CHECK (purpose = 'recover' AND revoked_at IS NOT NULL AND (SELECT private.partner_binding_kind()) = 'partner');

-- credentials: the bound person's own, and those of a person the reach rule covers (list; the revoke itself is the toucher's)
CREATE POLICY pd_read_partner_credential_bound ON app.partner_credential FOR SELECT TO private_definer
  USING ((SELECT private.partner_binding_kind()) = 'partner'
         AND (user_id = (SELECT private.partner_binding_user()) OR private.partner_reach_covers((SELECT private.partner_binding_user()), user_id)));

-- the purges (9): the retention floor of each class, repeated here so private_definer can neither read nor delete a younger row; closed under a partner binding
CREATE POLICY pd_purge_partner_auth_challenge ON app.partner_auth_challenge FOR DELETE TO private_definer
  USING (used_at < now() - interval '1 hour' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_auth_challenge_r ON app.partner_auth_challenge FOR SELECT TO private_definer
  USING (used_at < now() - interval '1 hour' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_session ON app.partner_session FOR DELETE TO private_definer
  USING (LEAST(expires_at, COALESCE(revoked_at, expires_at)) < now() - interval '30 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_session_r ON app.partner_session FOR SELECT TO private_definer
  USING (LEAST(expires_at, COALESCE(revoked_at, expires_at)) < now() - interval '30 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_credential ON app.partner_credential FOR DELETE TO private_definer
  USING (revoked_at < now() - interval '180 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_credential_r ON app.partner_credential FOR SELECT TO private_definer
  USING (revoked_at < now() - interval '180 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_invite ON app.partner_invite FOR DELETE TO private_definer
  USING (COALESCE(accepted_at, revoked_at, expires_at) < now() - interval '90 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_invite_r ON app.partner_invite FOR SELECT TO private_definer
  USING (COALESCE(accepted_at, revoked_at, expires_at) < now() - interval '90 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_enrolment_token ON app.partner_enrolment_token FOR DELETE TO private_definer
  USING (COALESCE(consumed_at, revoked_at, expires_at) < now() - interval '90 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_enrolment_token_r ON app.partner_enrolment_token FOR SELECT TO private_definer
  USING (COALESCE(consumed_at, revoked_at, expires_at) < now() - interval '90 days' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_sign_in_failure ON app.partner_sign_in_failure FOR DELETE TO private_definer
  USING (updated_at < now() - interval '1 day' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_partner_sign_in_failure_r ON app.partner_sign_in_failure FOR SELECT TO private_definer
  USING (updated_at < now() - interval '1 day' AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- the last-membership delete (5.2, PA-29): the policy itself carries the rule, derived from DATA (no active membership; for the TOTP, also not an admin), so it needs no binding and no setting
CREATE POLICY pd_lastmember_delete_partner_pin ON app.partner_pin FOR DELETE TO private_definer
  USING (NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = partner_pin.user_id AND m.revoked_at IS NULL));
CREATE POLICY pd_lastmember_delete_partner_pin_r ON app.partner_pin FOR SELECT TO private_definer
  USING (NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = partner_pin.user_id AND m.revoked_at IS NULL));
CREATE POLICY pd_lastmember_delete_partner_totp ON app.partner_totp FOR DELETE TO private_definer
  USING (NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = partner_totp.user_id AND m.revoked_at IS NULL)
         AND NOT EXISTS (SELECT 1 FROM app.admin_user a WHERE a.user_id = partner_totp.user_id));
CREATE POLICY pd_lastmember_delete_partner_totp_r ON app.partner_totp FOR SELECT TO private_definer
  USING (NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = partner_totp.user_id AND m.revoked_at IS NULL)
         AND NOT EXISTS (SELECT 1 FROM app.admin_user a WHERE a.user_id = partner_totp.user_id));

-- 3b. partner_session_toucher: the member revoke (UPDATE of revoked_at ONLY, so no role or org can change), and credential created_at for "created after T". The policy is the reach rule itself, keyed on the binding.
GRANT UPDATE (revoked_at) ON app.partner_member TO partner_session_toucher;
GRANT SELECT (created_at) ON app.partner_credential TO partner_session_toucher;
CREATE POLICY pst_revoke_partner_member ON app.partner_member FOR UPDATE TO partner_session_toucher
  USING (revoked_at IS NULL AND (SELECT private.partner_binding_kind()) = 'partner'
         AND private.partner_reach_covers_org((SELECT private.partner_binding_user()), user_id, org_id))
  WITH CHECK (revoked_at IS NOT NULL);

-- 3c. partner_pin_verifier: the reset of ANOTHER person's PIN row, only for a person the reach rule covers (its own-row policies of 0052 are untouched)
CREATE POLICY ppv_read_partner_pin_reach ON app.partner_pin FOR SELECT TO partner_pin_verifier
  USING (user_id <> (SELECT private.partner_binding_user()) AND private.partner_reach_covers((SELECT private.partner_binding_user()), user_id));
CREATE POLICY ppv_update_partner_pin_reach ON app.partner_pin FOR UPDATE TO partner_pin_verifier
  USING (user_id <> (SELECT private.partner_binding_user()) AND private.partner_reach_covers((SELECT private.partner_binding_user()), user_id))
  WITH CHECK (user_id <> (SELECT private.partner_binding_user()) AND private.partner_reach_covers((SELECT private.partner_binding_user()), user_id));

-- 3d. partner_session_issuer (the minter lane's owner): the accept definers read and count live invites / tokens by hash, write acceptance, activate the membership of the person who accepted,
-- and register_first records the one registration per acceptance. The membership policies admit a row ONLY when an invite accepted by that user for that org and role within the last two minutes
-- exists (so a planted GUC, or a call outside an acceptance, writes nothing).
GRANT SELECT (id, org_id, role, invited_by, invitee_email, token_hash, expires_at, accepted_at, accepted_by, revoked_at, attempts, registered_credential_id) ON app.partner_invite TO partner_session_issuer;
GRANT UPDATE (attempts, accepted_at, accepted_by, registered_credential_id) ON app.partner_invite TO partner_session_issuer;
CREATE POLICY psi_read_partner_invite ON app.partner_invite FOR SELECT TO partner_session_issuer USING (true);
CREATE POLICY psi_update_partner_invite_accept ON app.partner_invite FOR UPDATE TO partner_session_issuer
  USING (accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now())
  WITH CHECK (revoked_at IS NULL AND registered_credential_id IS NULL);
CREATE POLICY psi_update_partner_invite_register ON app.partner_invite FOR UPDATE TO partner_session_issuer
  USING (accepted_at IS NOT NULL AND registered_credential_id IS NULL AND revoked_at IS NULL)
  WITH CHECK (accepted_at IS NOT NULL AND registered_credential_id IS NOT NULL AND revoked_at IS NULL);

GRANT SELECT (id, user_id, purpose, token_hash, expires_at, consumed_at, registered_credential_id, revoked_at, attempts) ON app.partner_enrolment_token TO partner_session_issuer;
GRANT UPDATE (attempts, consumed_at, registered_credential_id) ON app.partner_enrolment_token TO partner_session_issuer;
CREATE POLICY psi_read_partner_enrolment_token ON app.partner_enrolment_token FOR SELECT TO partner_session_issuer USING (true);
CREATE POLICY psi_update_partner_enrolment_token_accept ON app.partner_enrolment_token FOR UPDATE TO partner_session_issuer
  USING (consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now())
  WITH CHECK (revoked_at IS NULL AND registered_credential_id IS NULL);
CREATE POLICY psi_update_partner_enrolment_token_register ON app.partner_enrolment_token FOR UPDATE TO partner_session_issuer
  USING (consumed_at IS NOT NULL AND registered_credential_id IS NULL AND revoked_at IS NULL)
  WITH CHECK (consumed_at IS NOT NULL AND registered_credential_id IS NOT NULL AND revoked_at IS NULL);

GRANT SELECT (user_id, org_id, role, revoked_at), INSERT (user_id, org_id, role, invited_by), UPDATE (revoked_at, role, invited_by) ON app.partner_member TO partner_session_issuer;
CREATE POLICY psi_read_partner_member ON app.partner_member FOR SELECT TO partner_session_issuer USING (true);
CREATE POLICY psi_insert_partner_member ON app.partner_member FOR INSERT TO partner_session_issuer
  WITH CHECK (revoked_at IS NULL AND EXISTS (
    SELECT 1 FROM app.partner_invite i
    WHERE i.org_id = partner_member.org_id AND i.role = partner_member.role AND i.accepted_by = partner_member.user_id AND i.invited_by = partner_member.invited_by
      AND i.accepted_at IS NOT NULL AND i.accepted_at > now() - interval '2 minutes' AND i.revoked_at IS NULL AND i.registered_credential_id IS NULL));
CREATE POLICY psi_update_partner_member ON app.partner_member FOR UPDATE TO partner_session_issuer
  USING (revoked_at IS NOT NULL)
  WITH CHECK (revoked_at IS NULL AND EXISTS (
    SELECT 1 FROM app.partner_invite i
    WHERE i.org_id = partner_member.org_id AND i.role = partner_member.role AND i.accepted_by = partner_member.user_id AND i.invited_by = partner_member.invited_by
      AND i.accepted_at IS NOT NULL AND i.accepted_at > now() - interval '2 minutes' AND i.revoked_at IS NULL AND i.registered_credential_id IS NULL));

-- ============================================================================
-- 4. The toucher's writers (6.5): the member revoke, the credential revokes, the oldest-session eviction. Each is subject-based and EXECUTE for private_definer (and, for the eviction, the issuer)
-- only; the wrappers do their own reach and scope checks first. The caller's identity is an ARGUMENT, so none of these reads the binding.
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_session_toucher;
SET ROLE partner_session_toucher;

-- 4a. Revoke ONE membership (the toucher's registered policy re-checks the reach rule against the binding). Returns ok | not_found.
CREATE FUNCTION private.partner_member_revoke_apply(p_user_id uuid, p_org_id uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_user_id IS NULL OR p_org_id IS NULL THEN
    RAISE EXCEPTION 'partner_member_revoke_apply: a user and an org are required' USING ERRCODE = '22023';
  END IF;
  UPDATE app.partner_member m SET revoked_at = pg_catalog.clock_timestamp()
  WHERE m.user_id = p_user_id AND m.org_id = p_org_id AND m.revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN CASE WHEN v_n = 1 THEN 'ok' ELSE 'not_found' END;
END
$$;

-- 4b. Revoke ONE credential. Returns ok | not_found (unknown, or already revoked).
CREATE FUNCTION private.partner_credential_revoke_apply(p_credential_id uuid, p_revoked_by uuid, p_reason text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_credential_id IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z_]{3,40}$' THEN
    RAISE EXCEPTION 'partner_credential_revoke_apply: a credential and a reason are required' USING ERRCODE = '22023';
  END IF;
  UPDATE app.partner_credential c SET revoked_at = pg_catalog.clock_timestamp(), revoked_by = p_revoked_by, revoke_reason = p_reason
  WHERE c.id = p_credential_id AND c.revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN CASE WHEN v_n = 1 THEN 'ok' ELSE 'not_found' END;
END
$$;

-- 4c. Revoke EVERY active credential of a person (recovery, 6.5), or only those created after p_created_after (the stolen-iPad button: "every credential created after T"). Returns the count.
CREATE FUNCTION private.partner_credentials_revoke_user(p_user_id uuid, p_revoked_by uuid, p_reason text, p_created_after timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_user_id IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z_]{3,40}$' THEN
    RAISE EXCEPTION 'partner_credentials_revoke_user: a person and a reason are required' USING ERRCODE = '22023';
  END IF;
  UPDATE app.partner_credential c SET revoked_at = pg_catalog.clock_timestamp(), revoked_by = p_revoked_by, revoke_reason = p_reason
  WHERE c.user_id = p_user_id AND c.revoked_at IS NULL AND (p_created_after IS NULL OR c.created_at > p_created_after);
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

-- 4d. Keep at most p_keep live sessions of a person: REVOKE the oldest beyond that (never a DELETE; a revoked session keeps its evidence for the 30-day purge). One audit row when something is evicted.
CREATE FUNCTION private.partner_sessions_evict_oldest(p_user_id uuid, p_keep integer)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_user_id IS NULL OR p_keep IS NULL OR p_keep < 1 OR p_keep > 10 THEN
    RAISE EXCEPTION 'partner_sessions_evict_oldest: a person and a limit of 1 to 10 are required' USING ERRCODE = '22023';
  END IF;
  UPDATE app.partner_session s SET revoked_at = pg_catalog.clock_timestamp(), revoke_reason = 'session_limit'
  WHERE s.id IN (
    SELECT x.id FROM app.partner_session x
    WHERE x.user_id = p_user_id AND x.revoked_at IS NULL AND x.expires_at > pg_catalog.clock_timestamp()
    ORDER BY x.created_at DESC, x.id
    OFFSET p_keep
  );
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n > 0 THEN
    PERFORM private.partner_audit_write('partner.sessions_evict', 'auth.users', p_user_id::text, pg_catalog.jsonb_build_object('evicted', v_n, 'kept', p_keep));
  END IF;
  RETURN v_n;
END
$$;

REVOKE EXECUTE ON FUNCTION
  private.partner_member_revoke_apply(uuid, uuid),
  private.partner_credential_revoke_apply(uuid, uuid, text),
  private.partner_credentials_revoke_user(uuid, uuid, text, timestamptz),
  private.partner_sessions_evict_oldest(uuid, integer)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_member_revoke_apply(uuid, uuid) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_credential_revoke_apply(uuid, uuid, text) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_credentials_revoke_user(uuid, uuid, text, timestamptz) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_sessions_evict_oldest(uuid, integer) TO private_definer, partner_session_issuer;
COMMENT ON FUNCTION private.partner_member_revoke_apply(uuid, uuid) IS
  '0054 (6.5). Owned by partner_session_toucher. Revokes ONE membership (UPDATE of revoked_at only); its registered policy pst_revoke_partner_member re-checks the reach rule against the transaction''s binding. The authority trigger kills the person''s sessions, the last-membership trigger deletes the PIN / TOTP. EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_credential_revoke_apply(uuid, uuid, text) IS
  '0054 (6.5). Owned by partner_session_toucher. Revokes ONE credential (revoked_at, revoked_by, revoke_reason). The caller (a _for_partner wrapper) has already applied A2 and the own-or-reach rule. EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_credentials_revoke_user(uuid, uuid, text, timestamptz) IS
  '0054 (6.5). Owned by partner_session_toucher. Revokes every active credential of a person (recovery), or only those created after a given time (the stolen-iPad button). EXECUTE for private_definer only.';
COMMENT ON FUNCTION private.partner_sessions_evict_oldest(uuid, integer) IS
  '0054 (4.1). Owned by partner_session_toucher. Keeps at most N live sessions of a person by REVOKING the oldest beyond that; one audit row when it evicts. EXECUTE for private_definer and partner_session_issuer (register_first).';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_session_toucher;

-- ============================================================================
-- 5. The PIN verifier's reset writer (6.3 / 6.5): clears the lock and every failure counter and sets must_change, so the person chooses a new PIN under an email proof. The wrapper has applied
-- A2 and the reach rule; the table policies (own row, or ppv_*_reach) are the second line. Also used for the person's OWN row on a reactivation (branch E).
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_pin_verifier;
SET ROLE partner_pin_verifier;

CREATE FUNCTION private.partner_pin_reset_apply(p_target_uid uuid)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_target_uid IS NULL THEN
    RAISE EXCEPTION 'partner_pin_reset_apply: a target person is required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_user() IS NULL THEN
    RAISE EXCEPTION 'partner_pin_reset_apply: no partner session is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  UPDATE app.partner_pin p
  SET failed_count = 0, failed_today = 0, failed_day = NULL, last_failed_at = NULL, next_attempt_at = NULL, locked_at = NULL, must_change = true
  WHERE p.user_id = p_target_uid;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN CASE WHEN v_n = 1 THEN 'ok' ELSE 'unset' END;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_pin_reset_apply(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_pin_reset_apply(uuid) TO private_definer;
COMMENT ON FUNCTION private.partner_pin_reset_apply(uuid) IS
  '0054 (6.3, 6.5). Owned by partner_pin_verifier. Clears locked_at and every failure counter and sets must_change on a person''s PIN row: ok | unset (no PIN row, or a row its policies do not admit: only the bound person''s own, or one the reach rule covers). EXECUTE for private_definer only.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_pin_verifier;

-- ============================================================================
-- 6. The issuer-owned definers: the minter lane (invite and enrolment-token accept, first credential registration) and the cores the partner lane shares.
-- Every refusal that must COMMIT something (an attempt count) is a STATUS row (PA-14); only malformed arguments (22023) and a bound transaction (42501) raise, and neither has written anything.
-- ============================================================================
GRANT CREATE ON SCHEMA private TO partner_session_issuer;
SET ROLE partner_session_issuer;

-- 6a. Is there a live invite for this token hash? The address the Edge sends the OTP to, or no row (unknown, expired, revoked, accepted and locked are all "no row": one 404, no oracle).
CREATE FUNCTION private.partner_invite_email_for_token(p_token_hash text)
RETURNS TABLE (o_email text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'partner_invite_email_for_token: a 64-hex token hash is required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_invite_email_for_token: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT pg_catalog.lower(pg_catalog.btrim(i.invitee_email))
  FROM app.partner_invite i
  WHERE i.token_hash = p_token_hash AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.attempts < 10 AND i.expires_at > pg_catalog.clock_timestamp();
END
$$;

-- 6b. THE ACCEPT CORE, shared by branch N (the minter lane) and branch E (a signed-in member), 6.1. In this order: lock the live invite; refuse a locked one (10 attempts); COUNT the attempt (so a
-- mismatch is counted: PA-14); the email in SQL (one lower(btrim) implementation) and confirmed; for N the GoTrue session still fresh; THEN the person's state, before writing anything:
--   N (a) an active credential: existing_member_sign_in, unconsumed;  N (b) an active membership in any org (or an admin) with no credential: recover_required, unconsumed;
--   E  an active membership in THIS org: already_member;
-- and only then (c) accepted_at / accepted_by, and the membership inserted or reactivated with the invite's role (the registered psi_* policies admit it because that acceptance now exists).
-- Statuses: ok | not_found | locked | email_mismatch | email_unconfirmed | session_stale | existing_member_sign_in | recover_required | already_member. EXECUTE for private_definer and the minter-lane wrapper (same owner).
CREATE FUNCTION private.partner_invite_accept_core(p_token_hash text, p_uid uuid, p_gotrue_session_id uuid, p_mode text)
RETURNS TABLE (o_status text, o_invite_id uuid, o_org_id uuid, o_role app.partner_role, o_accepted_at timestamptz, o_reactivated boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_i record;
  v_id record;
  v_acc timestamptz;
  v_n integer;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' OR p_uid IS NULL OR p_mode IS NULL OR p_mode NOT IN ('new', 'member') OR (p_mode = 'new' AND p_gotrue_session_id IS NULL) THEN
    RAISE EXCEPTION 'partner_invite_accept_core: a 64-hex token hash, a user, a mode (new or member) and, for new, a GoTrue session are required' USING ERRCODE = '22023';
  END IF;
  SELECT i.id, i.org_id, i.role, i.invitee_email, i.attempts, i.invited_by INTO v_i
  FROM app.partner_invite i
  WHERE i.token_hash = p_token_hash AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
    RETURN;
  END IF;
  IF v_i.attempts >= 10 THEN
    RETURN QUERY SELECT 'locked'::text, v_i.id, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
    RETURN;
  END IF;
  UPDATE app.partner_invite i SET attempts = i.attempts + 1 WHERE i.id = v_i.id;
  SELECT a.o_email, a.o_confirmed, a.o_fresh, a.o_is_admin INTO v_id
  FROM private.partner_auth_identity(p_uid, CASE WHEN p_mode = 'new' THEN p_gotrue_session_id END) a;
  IF NOT FOUND OR v_id.o_email IS NULL OR v_id.o_email IS DISTINCT FROM pg_catalog.lower(pg_catalog.btrim(v_i.invitee_email)) THEN
    RETURN QUERY SELECT 'email_mismatch'::text, v_i.id, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
    RETURN;
  END IF;
  IF NOT v_id.o_confirmed THEN
    RETURN QUERY SELECT 'email_unconfirmed'::text, v_i.id, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
    RETURN;
  END IF;
  IF p_mode = 'new' THEN
    IF NOT v_id.o_fresh THEN
      RETURN QUERY SELECT 'session_stale'::text, v_i.id, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
      RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM app.partner_credential c WHERE c.user_id = p_uid AND c.revoked_at IS NULL) THEN
      RETURN QUERY SELECT 'existing_member_sign_in'::text, v_i.id, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
      RETURN;
    END IF;
    IF v_id.o_is_admin OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_uid AND m.revoked_at IS NULL) THEN
      RETURN QUERY SELECT 'recover_required'::text, v_i.id, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
      RETURN;
    END IF;
  ELSIF EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_uid AND m.org_id = v_i.org_id AND m.revoked_at IS NULL) THEN
    RETURN QUERY SELECT 'already_member'::text, v_i.id, NULL::uuid, NULL::app.partner_role, NULL::timestamptz, false;
    RETURN;
  END IF;
  UPDATE app.partner_invite i SET accepted_at = pg_catalog.clock_timestamp(), accepted_by = p_uid WHERE i.id = v_i.id RETURNING i.accepted_at INTO v_acc;
  UPDATE app.partner_member m SET revoked_at = NULL, role = v_i.role, invited_by = v_i.invited_by
  WHERE m.user_id = p_uid AND m.org_id = v_i.org_id AND m.revoked_at IS NOT NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    INSERT INTO app.partner_member (user_id, org_id, role, invited_by) VALUES (p_uid, v_i.org_id, v_i.role, v_i.invited_by);
  END IF;
  RETURN QUERY SELECT 'ok'::text, v_i.id, v_i.org_id, v_i.role, v_acc, (v_n = 1);
END
$$;

-- 6c. Branch N, the minter-lane entry: the core, then (only on ok) the register challenge, bound to the uid, the invite id and the acceptance time. The Edge closes the GoTrue session AFTER this returns.
CREATE FUNCTION private.partner_invite_accept(p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid)
RETURNS TABLE (o_status text, o_user_id uuid, o_invite_id uuid, o_org_id uuid, o_role app.partner_role, o_nonce bytea, o_exp bigint, o_mac bytea, o_accepted_at_us bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v record;
  v_ch record;
  v_us bigint;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' OR p_verified_uid IS NULL OR p_gotrue_session_id IS NULL THEN
    RAISE EXCEPTION 'partner_invite_accept: a 64-hex token hash, a verified user and a GoTrue session are required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_invite_accept: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  SELECT c.o_status, c.o_invite_id, c.o_org_id, c.o_role, c.o_accepted_at INTO v
  FROM private.partner_invite_accept_core(p_token_hash, p_verified_uid, p_gotrue_session_id, 'new') c;
  IF v.o_status IS DISTINCT FROM 'ok' THEN
    RETURN QUERY SELECT v.o_status, NULL::uuid, v.o_invite_id, NULL::uuid, NULL::app.partner_role, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  v_us := (EXTRACT(EPOCH FROM v.o_accepted_at) * 1000000)::bigint;
  SELECT r.o_nonce, r.o_exp, r.o_mac INTO v_ch FROM private.partner_challenge_issue_register(p_verified_uid, 1::smallint, v.o_invite_id, v_us) r;
  PERFORM private.partner_audit_write('partner.invite.accept', 'app.partner_invite', v.o_invite_id::text, pg_catalog.jsonb_build_object('branch', 'new', 'user', p_verified_uid));
  RETURN QUERY SELECT 'ok'::text, p_verified_uid, v.o_invite_id, v.o_org_id, v.o_role, v_ch.o_nonce, v_ch.o_exp, v_ch.o_mac, v_us;
END
$$;

-- 6d. Enrolment tokens (recover | admin: a PERSON, no org). The address is the person's own auth email.
CREATE FUNCTION private.partner_enrolment_token_email_for_token(p_token_hash text)
RETURNS TABLE (o_email text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'partner_enrolment_token_email_for_token: a 64-hex token hash is required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_enrolment_token_email_for_token: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT a.o_email
  FROM app.partner_enrolment_token t, LATERAL private.partner_auth_identity(t.user_id, NULL) a
  WHERE t.token_hash = p_token_hash AND t.consumed_at IS NULL AND t.revoked_at IS NULL AND t.attempts < 10 AND t.expires_at > pg_catalog.clock_timestamp()
    AND a.o_email IS NOT NULL;
END
$$;

-- 6e. Accept an enrolment token (6.1 N-flow against this table; 6.4, 6.5). Same order as the invite: lock, locked?, count the attempt, the verified uid must BE the token's person (their own mailbox),
-- confirmed, fresh GoTrue session, an active credential refuses (email OTP never adds a credential to a person who has one), the purpose's own precondition (admin: in admin_user; recover: still
-- an active member or an admin); then consumed_at and the register challenge (ref_kind 2). Statuses: ok | not_found | locked | email_mismatch | email_unconfirmed | session_stale |
-- existing_member_sign_in | refused.
CREATE FUNCTION private.partner_enrolment_token_accept(p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid)
RETURNS TABLE (o_status text, o_user_id uuid, o_token_id uuid, o_purpose text, o_nonce bytea, o_exp bigint, o_mac bytea, o_accepted_at_us bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_t record;
  v_id record;
  v_acc timestamptz;
  v_ch record;
  v_us bigint;
BEGIN
  IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' OR p_verified_uid IS NULL OR p_gotrue_session_id IS NULL THEN
    RAISE EXCEPTION 'partner_enrolment_token_accept: a 64-hex token hash, a verified user and a GoTrue session are required' USING ERRCODE = '22023';
  END IF;
  IF private.partner_binding_kind() IS NOT NULL THEN
    RAISE EXCEPTION 'partner_enrolment_token_accept: refused inside a bound transaction' USING ERRCODE = '42501';
  END IF;
  SELECT t.id, t.user_id, t.purpose, t.attempts INTO v_t
  FROM app.partner_enrolment_token t
  WHERE t.token_hash = p_token_hash AND t.consumed_at IS NULL AND t.revoked_at IS NULL AND t.expires_at > pg_catalog.clock_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid, NULL::uuid, NULL::text, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  IF v_t.attempts >= 10 THEN
    RETURN QUERY SELECT 'locked'::text, NULL::uuid, v_t.id, v_t.purpose, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  UPDATE app.partner_enrolment_token t SET attempts = t.attempts + 1 WHERE t.id = v_t.id;
  SELECT a.o_email, a.o_confirmed, a.o_fresh, a.o_is_admin INTO v_id FROM private.partner_auth_identity(p_verified_uid, p_gotrue_session_id) a;
  IF NOT FOUND OR v_id.o_email IS NULL OR p_verified_uid IS DISTINCT FROM v_t.user_id THEN
    RETURN QUERY SELECT 'email_mismatch'::text, NULL::uuid, v_t.id, v_t.purpose, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  IF NOT v_id.o_confirmed THEN
    RETURN QUERY SELECT 'email_unconfirmed'::text, NULL::uuid, v_t.id, v_t.purpose, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  IF NOT v_id.o_fresh THEN
    RETURN QUERY SELECT 'session_stale'::text, NULL::uuid, v_t.id, v_t.purpose, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM app.partner_credential c WHERE c.user_id = p_verified_uid AND c.revoked_at IS NULL) THEN
    RETURN QUERY SELECT 'existing_member_sign_in'::text, NULL::uuid, v_t.id, v_t.purpose, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  IF (v_t.purpose = 'admin' AND NOT v_id.o_is_admin)
     OR (v_t.purpose = 'recover' AND NOT v_id.o_is_admin AND NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_verified_uid AND m.revoked_at IS NULL)) THEN
    RETURN QUERY SELECT 'refused'::text, NULL::uuid, v_t.id, v_t.purpose, NULL::bytea, NULL::bigint, NULL::bytea, NULL::bigint;
    RETURN;
  END IF;
  UPDATE app.partner_enrolment_token t SET consumed_at = pg_catalog.clock_timestamp() WHERE t.id = v_t.id RETURNING t.consumed_at INTO v_acc;
  v_us := (EXTRACT(EPOCH FROM v_acc) * 1000000)::bigint;
  SELECT r.o_nonce, r.o_exp, r.o_mac INTO v_ch FROM private.partner_challenge_issue_register(p_verified_uid, 2::smallint, v_t.id, v_us) r;
  PERFORM private.partner_audit_write('partner.enrolment.accept', 'app.partner_enrolment_token', v_t.id::text, pg_catalog.jsonb_build_object('purpose', v_t.purpose, 'user', p_verified_uid));
  RETURN QUERY SELECT 'ok'::text, p_verified_uid, v_t.id, v_t.purpose, v_ch.o_nonce, v_ch.o_exp, v_ch.o_mac, v_us;
END
$$;

-- 6f. THE CREATE CORE (R4-L2), shared by register_first and the second-credential wrapper. Every check a create ceremony allows, from the raw bytes: clientDataJSON parses, type webauthn.create,
-- crossOrigin not true, no topOrigin, origin = partner_rp_config.origin, challenge = the nonce (base64url); the attestation object is a CBOR map of exactly fmt / attStmt / authData with fmt
-- "none" and an empty attStmt; authData has rpIdHash = sha256(rp_id) and UP, UV and AT set (ED clear: no extension data) and parses to aaguid, credential id and COSE key, the credential id
-- and the key EQUAL the arguments being stored, the key parses (partner_cose_parse: two shapes, alg -7 or -257). Then the nonce is recorded (the primary key is single use) and the credential
-- inserted; sign count, backup flags and aaguid come FROM authData, never an argument. Statuses: ok | bad_client_data | bad_client_type | cross_origin | bad_origin | challenge_mismatch |
-- bad_attestation | bad_fmt | bad_authenticator_data | bad_rp_id_hash | flags_missing | bad_credential | bad_key | bad_transports | replayed | credential_in_use. EXECUTE: private_definer.
CREATE FUNCTION private.partner_credential_create_core(
  p_user_id uuid, p_nonce bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[],
  p_via_credential_id uuid, p_session_id uuid, p_minted_session_id uuid)
RETURNS TABLE (o_status text, o_credential_id uuid, o_auth_data bytea)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_rp record;
  v_cd jsonb;
  v_h record;
  v_len integer;
  v_pos integer;
  v_i integer;
  v_key bytea;
  v_fmt_seen boolean := false;
  v_stmt_seen boolean := false;
  v_auth_seen boolean := false;
  v_ad bytea;
  v_flags integer;
  v_idlen integer;
  v_aaguid_hex text;
  v_aaguid uuid;
  v_counter bigint;
  v_cose record;
  v_t text;
  v_cid uuid;
  v_n integer;
BEGIN
  IF p_user_id IS NULL OR p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_attestation_object IS NULL OR p_client_data_json IS NULL
     OR p_credential_id IS NULL OR p_public_key IS NULL THEN
    RAISE EXCEPTION 'partner_credential_create_core: a user, a 32-byte nonce, the attestation object, the client data, a credential id and a key are required' USING ERRCODE = '22023';
  END IF;
  SELECT r.rp_id, r.origin INTO v_rp FROM app.partner_rp_config r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_credential_create_core: app.partner_rp_config holds no relying party (a deploy step)' USING ERRCODE = '55000';
  END IF;
  -- clientDataJSON
  IF pg_catalog.octet_length(p_client_data_json) NOT BETWEEN 2 AND 4096 THEN
    RETURN QUERY SELECT 'bad_client_data'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  BEGIN
    v_cd := pg_catalog.convert_from(p_client_data_json, 'UTF8')::jsonb;
  EXCEPTION WHEN others THEN
    v_cd := NULL;
  END;
  IF v_cd IS NULL OR pg_catalog.jsonb_typeof(v_cd) <> 'object' THEN
    RETURN QUERY SELECT 'bad_client_data'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'type') IS DISTINCT FROM 'string' OR (v_cd ->> 'type') <> 'webauthn.create' THEN
    RETURN QUERY SELECT 'bad_client_type'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF (v_cd ? 'crossOrigin' AND (v_cd -> 'crossOrigin') <> 'false'::jsonb) OR v_cd ? 'topOrigin' THEN
    RETURN QUERY SELECT 'cross_origin'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'origin') IS DISTINCT FROM 'string' OR (v_cd ->> 'origin') <> v_rp.origin THEN
    RETURN QUERY SELECT 'bad_origin'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF pg_catalog.jsonb_typeof(v_cd -> 'challenge') IS DISTINCT FROM 'string'
     OR (v_cd ->> 'challenge') <> pg_catalog.rtrim(pg_catalog.translate(pg_catalog.encode(p_nonce, 'base64'), '+/', '-_'), '=') THEN
    RETURN QUERY SELECT 'challenge_mismatch'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  -- the attestation object: a definite CBOR map of exactly three text keys
  v_len := pg_catalog.octet_length(p_attestation_object);
  IF v_len < 16 OR v_len > 8192 THEN
    RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  SELECT * INTO v_h FROM private.partner_cbor_head(p_attestation_object, 0);
  IF NOT FOUND OR v_h.o_major <> 5 OR v_h.o_arg <> 3 THEN
    RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  v_pos := v_h.o_next;
  FOR v_i IN 1 .. 3 LOOP
    SELECT * INTO v_h FROM private.partner_cbor_head(p_attestation_object, v_pos);
    IF NOT FOUND OR v_h.o_major <> 3 OR v_h.o_arg NOT IN (3, 7, 8) OR v_h.o_next + v_h.o_arg > v_len THEN
      RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
      RETURN;
    END IF;
    v_key := pg_catalog.substring(p_attestation_object, v_h.o_next + 1, v_h.o_arg);
    v_pos := v_h.o_next + v_h.o_arg;
    SELECT * INTO v_h FROM private.partner_cbor_head(p_attestation_object, v_pos);
    IF NOT FOUND THEN
      RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
      RETURN;
    END IF;
    IF v_key = '\x666d74'::bytea AND NOT v_fmt_seen THEN
      v_fmt_seen := true;
      IF v_h.o_major <> 3 OR v_h.o_next + v_h.o_arg > v_len OR pg_catalog.substring(p_attestation_object, v_h.o_next + 1, v_h.o_arg) <> '\x6e6f6e65'::bytea THEN
        RETURN QUERY SELECT 'bad_fmt'::text, NULL::uuid, NULL::bytea;
        RETURN;
      END IF;
      v_pos := v_h.o_next + v_h.o_arg;
    ELSIF v_key = '\x61747453746d74'::bytea AND NOT v_stmt_seen THEN
      v_stmt_seen := true;
      IF v_h.o_major <> 5 THEN
        RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
        RETURN;
      END IF;
      IF v_h.o_arg <> 0 THEN
        RETURN QUERY SELECT 'bad_fmt'::text, NULL::uuid, NULL::bytea;
        RETURN;
      END IF;
      v_pos := v_h.o_next;
    ELSIF v_key = '\x6175746844617461'::bytea AND NOT v_auth_seen THEN
      v_auth_seen := true;
      IF v_h.o_major <> 2 OR v_h.o_next + v_h.o_arg > v_len THEN
        RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
        RETURN;
      END IF;
      v_ad := pg_catalog.substring(p_attestation_object, v_h.o_next + 1, v_h.o_arg);
      v_pos := v_h.o_next + v_h.o_arg;
    ELSE
      RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
      RETURN;
    END IF;
  END LOOP;
  IF v_pos <> v_len OR NOT (v_fmt_seen AND v_stmt_seen AND v_auth_seen) THEN
    RETURN QUERY SELECT 'bad_attestation'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  -- authenticatorData: rpIdHash (32) | flags (1) | counter (4) | aaguid (16) | credIdLen (2) | credId | COSE key (exactly the rest: no extension data)
  IF pg_catalog.octet_length(v_ad) < 55 OR pg_catalog.octet_length(v_ad) > 4096 THEN
    RETURN QUERY SELECT 'bad_authenticator_data'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF pg_catalog.substring(v_ad, 1, 32) <> pg_catalog.sha256(pg_catalog.convert_to(v_rp.rp_id, 'UTF8')) THEN
    RETURN QUERY SELECT 'bad_rp_id_hash'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  v_flags := pg_catalog.get_byte(v_ad, 32);
  IF v_flags & 1 = 0 OR v_flags & 4 = 0 OR v_flags & 64 = 0 THEN
    RETURN QUERY SELECT 'flags_missing'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF v_flags & 128 <> 0 OR (v_flags & 16 <> 0 AND v_flags & 8 = 0) THEN
    RETURN QUERY SELECT 'bad_authenticator_data'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  v_counter := pg_catalog.get_byte(v_ad, 33)::bigint * 16777216 + pg_catalog.get_byte(v_ad, 34) * 65536 + pg_catalog.get_byte(v_ad, 35) * 256 + pg_catalog.get_byte(v_ad, 36);
  v_aaguid_hex := pg_catalog.encode(pg_catalog.substring(v_ad, 38, 16), 'hex');
  v_aaguid := CASE WHEN v_aaguid_hex = '00000000000000000000000000000000' THEN NULL ELSE v_aaguid_hex::uuid END;
  v_idlen := pg_catalog.get_byte(v_ad, 53) * 256 + pg_catalog.get_byte(v_ad, 54);
  IF v_idlen < 16 OR v_idlen > 1023 OR pg_catalog.octet_length(v_ad) < 55 + v_idlen + 8
     OR pg_catalog.substring(v_ad, 56, v_idlen) <> p_credential_id OR pg_catalog.octet_length(p_credential_id) NOT BETWEEN 16 AND 1023 THEN
    RETURN QUERY SELECT 'bad_credential'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF pg_catalog.substring(v_ad, 56 + v_idlen) <> p_public_key OR pg_catalog.octet_length(p_public_key) NOT BETWEEN 16 AND 1024 THEN
    RETURN QUERY SELECT 'bad_key'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  SELECT * INTO v_cose FROM private.partner_cose_parse(p_public_key);
  IF NOT FOUND OR v_cose.o_alg NOT IN (-7, -257) THEN
    RETURN QUERY SELECT 'bad_key'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  IF p_transports IS NOT NULL THEN
    IF pg_catalog.cardinality(p_transports) > 8 THEN
      RETURN QUERY SELECT 'bad_transports'::text, NULL::uuid, NULL::bytea;
      RETURN;
    END IF;
    FOREACH v_t IN ARRAY p_transports LOOP
      IF v_t IS NULL OR v_t NOT IN ('usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card', 'cable') THEN
        RETURN QUERY SELECT 'bad_transports'::text, NULL::uuid, NULL::bytea;
        RETURN;
      END IF;
    END LOOP;
  END IF;
  -- the nonce, once (the primary key is the single use), then the credential
  INSERT INTO app.partner_auth_challenge (nonce_hash, purpose, user_id, session_id, minted_session_id)
  VALUES (pg_catalog.sha256(p_nonce), 'register', p_user_id, p_session_id, p_minted_session_id)
  ON CONFLICT (nonce_hash) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    RETURN QUERY SELECT 'replayed'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, sign_count, transports, backup_eligible, backup_state, aaguid, created_via_credential_id)
  VALUES (p_user_id, p_credential_id, p_public_key, v_cose.o_alg, v_counter, coalesce(p_transports, '{}'::text[]), (v_flags & 8) <> 0, (v_flags & 16) <> 0, v_aaguid, p_via_credential_id)
  ON CONFLICT (credential_id) DO NOTHING
  RETURNING id INTO v_cid;
  IF v_cid IS NULL THEN
    RETURN QUERY SELECT 'credential_in_use'::text, NULL::uuid, NULL::bytea;
    RETURN;
  END IF;
  RETURN QUERY SELECT 'ok'::text, v_cid, v_ad;
END
$$;

-- 6g. THE FIRST CREDENTIAL (6.1 step 4, R3-L3, R4-L2). In this order: the invite or token must have been accepted BY THIS UID, not revoked, not yet registered (one registration per acceptance) and
-- under 15 minutes ago; the challenge MAC (purpose 2, uid, ref kind, ref id, the acceptance time READ FROM THE ROW) and its expiry; no active credential (a race with another enrolment); for an
-- invite, no active membership in any org but the one it activated; then the create core (the DB-side ceremony checks), the registration recorded on the invite or token, and the FIRST SESSION in
-- the same transaction (mint_kind register, mint_signature NULL, enrolment_until = now + 15 min, 6.1 step 4), after which the oldest session beyond three is revoked. Every refusal is a status.
-- Statuses: ok | not_accepted | accept_expired | bad_challenge | expired | credential_exists | other_membership | already_registered, and the core's.
CREATE FUNCTION private.partner_credential_register_first(
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
  PERFORM private.partner_sessions_evict_oldest(p_user_id, 3);
  PERFORM private.partner_audit_write('partner.credential.register_first', 'app.partner_credential', v_c.o_credential_id::text,
    pg_catalog.jsonb_build_object('user', p_user_id, 'ref_kind', p_ref_kind, 'ref_id', p_ref_id));
  RETURN QUERY SELECT 'ok'::text, v_c.o_credential_id, v_sid, 1::smallint, v_expires, v_enrol;
END
$$;

REVOKE EXECUTE ON FUNCTION
  private.partner_invite_email_for_token(text),
  private.partner_invite_accept_core(text, uuid, uuid, text),
  private.partner_invite_accept(text, uuid, uuid),
  private.partner_enrolment_token_email_for_token(text),
  private.partner_enrolment_token_accept(text, uuid, uuid),
  private.partner_credential_create_core(uuid, bytea, bytea, bytea, bytea, bytea, text[], uuid, uuid, uuid),
  private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])
FROM PUBLIC;
-- the minter lane: edge_partner_minter, and nobody else (the relying party is read through the existing partner_rp_config_read)
GRANT EXECUTE ON FUNCTION private.partner_invite_email_for_token(text) TO edge_partner_minter;
GRANT EXECUTE ON FUNCTION private.partner_invite_accept(text, uuid, uuid) TO edge_partner_minter;
GRANT EXECUTE ON FUNCTION private.partner_enrolment_token_email_for_token(text) TO edge_partner_minter;
GRANT EXECUTE ON FUNCTION private.partner_enrolment_token_accept(text, uuid, uuid) TO edge_partner_minter;
GRANT EXECUTE ON FUNCTION private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[]) TO edge_partner_minter;
-- the two cores the partner lane shares: the _for_partner wrappers (private_definer), nobody else
GRANT EXECUTE ON FUNCTION private.partner_invite_accept_core(text, uuid, uuid, text) TO private_definer;
GRANT EXECUTE ON FUNCTION private.partner_credential_create_core(uuid, bytea, bytea, bytea, bytea, bytea, text[], uuid, uuid, uuid) TO private_definer;
COMMENT ON FUNCTION private.partner_invite_email_for_token(text) IS
  '0054 (6.1). edge_partner_minter only; owned by partner_session_issuer. The normalised invitee_email of a LIVE invite (unaccepted, unrevoked, unexpired, under 10 attempts) for accept/start, or no row: unknown, expired, revoked, accepted and locked are one answer. Refused inside a bound transaction.';
COMMENT ON FUNCTION private.partner_invite_accept_core(text, uuid, uuid, text) IS
  '0054 (6.1). Owned by partner_session_issuer; EXECUTE for private_definer. The accept order shared by branch N (minter lane) and branch E (a signed-in member): lock, locked at 10, COUNT the attempt, email in SQL, confirmed, fresh GoTrue session (N), person state BEFORE any write (N: active credential -> existing_member_sign_in, active membership or admin -> recover_required; E: already_member), then accepted_* and the membership. Every outcome a status.';
COMMENT ON FUNCTION private.partner_invite_accept(text, uuid, uuid) IS
  '0054 (6.1, PA-14, PA-23). edge_partner_minter only; owned by partner_session_issuer. Branch N: the accept core, then on ok the register challenge bound to uid, invite id and acceptance time. Mismatch / locked / recover_required / existing_member_sign_in are STATUS rows (the attempt count commits). The Edge closes the GoTrue session after this returns.';
COMMENT ON FUNCTION private.partner_enrolment_token_email_for_token(text) IS
  '0054 (6.1, 6.4, 6.5). edge_partner_minter only; owned by partner_session_issuer. The auth email of the person a LIVE recover / admin token belongs to, or no row.';
COMMENT ON FUNCTION private.partner_enrolment_token_accept(text, uuid, uuid) IS
  '0054 (6.1, 6.4, 6.5). edge_partner_minter only; owned by partner_session_issuer. The accept order against partner_enrolment_token: the verified uid must be the token''s person; an active credential refuses; purpose preconditions; consumed_at and the register challenge (ref kind 2). Statuses, never a RAISE.';
COMMENT ON FUNCTION private.partner_credential_create_core(uuid, bytea, bytea, bytea, bytea, bytea, text[], uuid, uuid, uuid) IS
  '0054 (R4-L2). Owned by partner_session_issuer; EXECUTE for private_definer. Every DB-side check of a webauthn.create ceremony (client data, attestation fmt none, authData flags and rpIdHash, credential id and COSE key parsed by partner_cose_parse and equal to what is stored), then the nonce and the credential insert. Sign count, backup flags and aaguid come from authData.';
COMMENT ON FUNCTION private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[]) IS
  '0054 (6.1, R2-L1, R3-L3, R4-L2, PA-7b, PA-7c). edge_partner_minter only; owned by partner_session_issuer. Re-verifies the acceptance (this uid, under 15 minutes, no registration yet), the challenge MAC with its refs, no active credential and no other-org membership (invite), runs the create checks, records the registration, mints the first session (mint_kind register, no signature, enrolment_until now + 15 min) and evicts beyond three live sessions.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM partner_session_issuer;

-- ============================================================================
-- 7. private_definer, second pass: the partner lane (_for_partner), the last-membership trigger function, the purges.
-- Check 14: every *_for_partner body begins with private.partner_authorize, holds no dollar sign, double quote, backslash, E-string or block comment, and no EXCEPTION block; its comments are
-- dollar-free too. Counter and attempt paths return STATUS rows; only malformed arguments (22023) and missing authority (42501) raise.
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 7a. POST invites (class A2; an admin passes A3 + reauth for a PIN-less admin). THE INVITE RULE (6.1):
--   role strictly below the inviter's own, by EXPLICIT array: a manager invites staff; an operator invites staff and manager; only an admin invites operator; sponsor invites stay disabled (22023);
--   the grant is a SUBSET of the inviter's reach: for a staff invite the inviter passes has_facility_scope over the org's one facility as manager or operator, for a manager invite as operator;
--   an invitee who already holds an ACTIVE membership in that org is refused with a status (409). The token is 32 random bytes in the Edge; only its SHA-256 (64 hex) arrives here; 72 hours.
CREATE FUNCTION private.partner_invite_create_for_partner(p_org_id uuid, p_role app.partner_role, p_invitee_email text, p_token_hash text)
RETURNS TABLE (o_status text, o_invite_id uuid, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_email text;
  v_kind app.partner_org_kind;
  v_fac text;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_exp timestamptz;
  v_id uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_role IS NULL OR p_role NOT IN ('staff', 'manager', 'operator') THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: a staff, manager or operator role is required (sponsor invites are disabled)' USING ERRCODE = '22023';
  END IF;
  IF p_org_id IS NULL OR p_invitee_email IS NULL OR p_token_hash IS NULL OR pg_catalog.char_length(p_token_hash) <> 64 OR p_token_hash !~ '^[0-9a-f]{64}' THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: an org, an invitee email and a 64-hex token hash are required' USING ERRCODE = '22023';
  END IF;
  v_email := pg_catalog.lower(pg_catalog.btrim(p_invitee_email));
  IF pg_catalog.char_length(v_email) NOT BETWEEN 3 AND 254 OR v_email ~ '[[:space:]]' OR v_email !~ '^[^@]+@[^@]+' THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: the invitee email is malformed' USING ERRCODE = '22023';
  END IF;
  SELECT o.kind INTO v_kind FROM app.partner_org o WHERE o.id = p_org_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'partner_invite_create_for_partner: no scope' USING ERRCODE = '42501';
  END IF;
  IF p_role = 'operator' THEN
    IF v_kind <> 'operator' OR NOT private.is_admin(v_uid) THEN
      RAISE EXCEPTION 'partner_invite_create_for_partner: only an admin invites an operator, into an operator org' USING ERRCODE = '42501';
    END IF;
  ELSE
    IF v_kind <> 'facility' THEN
      RAISE EXCEPTION 'partner_invite_create_for_partner: no scope' USING ERRCODE = '42501';
    END IF;
    SELECT s.facility_id INTO v_fac FROM app.partner_scope s WHERE s.org_id = p_org_id AND s.facility_id IS NOT NULL LIMIT 1;
    IF v_fac IS NULL
       OR NOT private.has_facility_scope(v_uid, v_fac,
            CASE WHEN p_role = 'staff' THEN ARRAY['manager', 'operator'] ELSE ARRAY['operator'] END::app.partner_role[]) THEN
      RAISE EXCEPTION 'partner_invite_create_for_partner: the grant is not a subset of the inviter reach' USING ERRCODE = '42501';
    END IF;
  END IF;
  IF EXISTS (SELECT 1 FROM app.partner_member m JOIN auth.users u ON u.id = m.user_id
             WHERE m.org_id = p_org_id AND m.revoked_at IS NULL AND pg_catalog.lower(pg_catalog.btrim(u.email)) = v_email) THEN
    RETURN QUERY SELECT 'already_member'::text, NULL::uuid, NULL::timestamptz;
    RETURN;
  END IF;
  v_exp := v_now + interval '72 hours';
  INSERT INTO app.partner_invite (org_id, role, facility_id, trail_id, invited_by, invitee_email, token_hash, expires_at, created_at)
  VALUES (p_org_id, p_role, v_fac, NULL, v_uid, v_email, p_token_hash, v_exp, v_now)
  RETURNING id INTO v_id;
  PERFORM private.partner_audit_write('partner.invite.create', 'app.partner_invite', v_id::text,
    pg_catalog.jsonb_build_object('org', p_org_id, 'role', p_role));
  RETURN QUERY SELECT 'ok'::text, v_id, v_exp;
END
$$;

-- 7b. GET invites (class A0, manager / operator / admin): the invites the actor's scope covers (the table policy is the filter), newest first, never the token hash.
CREATE FUNCTION private.partner_invite_list_for_partner(p_org_id uuid)
RETURNS TABLE (o_id uuid, o_org_id uuid, o_role app.partner_role, o_facility_id text, o_invitee_email text, o_invited_by uuid,
               o_created_at timestamptz, o_expires_at timestamptz, o_accepted_at timestamptz, o_revoked_at timestamptz, o_attempts smallint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A0');
  RETURN QUERY
  SELECT i.id, i.org_id, i.role, i.facility_id, i.invitee_email, i.invited_by, i.created_at, i.expires_at, i.accepted_at, i.revoked_at, i.attempts
  FROM app.partner_invite i
  WHERE p_org_id IS NULL OR i.org_id = p_org_id
  ORDER BY i.created_at DESC, i.id
  LIMIT 200;
END
$$;

-- 7c. DELETE invites/{id} (class A2): ok | not_found (an unknown id and an id outside the actor's scope are one answer) | already_accepted | already_revoked.
CREATE FUNCTION private.partner_invite_revoke_for_partner(p_invite_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_i record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_invite_id IS NULL THEN
    RAISE EXCEPTION 'partner_invite_revoke_for_partner: an invite id is required' USING ERRCODE = '22023';
  END IF;
  SELECT i.accepted_at, i.revoked_at INTO v_i FROM app.partner_invite i WHERE i.id = p_invite_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_i.accepted_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_accepted'::text;
    RETURN;
  END IF;
  IF v_i.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_revoked'::text;
    RETURN;
  END IF;
  UPDATE app.partner_invite i SET revoked_at = pg_catalog.clock_timestamp(), revoked_by = v_uid WHERE i.id = p_invite_id AND i.accepted_at IS NULL AND i.revoked_at IS NULL;
  PERFORM private.partner_audit_write('partner.invite.revoke', 'app.partner_invite', p_invite_id::text, '{}'::jsonb);
  RETURN QUERY SELECT 'ok'::text;
END
$$;

-- 7d. POST invites/accept, BRANCH E (class A2): an existing member with an active credential joins another org. The SESSION user's confirmed email must equal the invite's (a forwarded link
-- fails, and the attempt count commits: PA-14). A reactivated membership resets the person's PIN to must_change (6.1). No credential is created and no OTP is needed.
CREATE FUNCTION private.partner_invite_accept_for_partner(p_token_hash text)
RETURNS TABLE (o_status text, o_org_id uuid, o_role app.partner_role)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A2');
  IF p_token_hash IS NULL OR pg_catalog.char_length(p_token_hash) <> 64 OR p_token_hash !~ '^[0-9a-f]{64}' THEN
    RAISE EXCEPTION 'partner_invite_accept_for_partner: a 64-hex token hash is required' USING ERRCODE = '22023';
  END IF;
  SELECT c.o_status, c.o_invite_id, c.o_org_id, c.o_role, c.o_reactivated INTO v
  FROM private.partner_invite_accept_core(p_token_hash, v_uid, NULL, 'member') c;
  IF v.o_status IS DISTINCT FROM 'ok' THEN
    RETURN QUERY SELECT v.o_status, NULL::uuid, NULL::app.partner_role;
    RETURN;
  END IF;
  IF v.o_reactivated THEN
    PERFORM private.partner_pin_reset_apply(v_uid);
  END IF;
  PERFORM private.partner_audit_write('partner.invite.accept', 'app.partner_invite', v.o_invite_id::text,
    pg_catalog.jsonb_build_object('branch', 'member', 'org', v.o_org_id, 'reactivated', v.o_reactivated));
  RETURN QUERY SELECT 'ok'::text, v.o_org_id, v.o_role;
END
$$;

-- 7e. POST members/revoke (class A2): revoke ONE membership under the reach rule for that membership. Statuses: ok | not_found (no such ACTIVE membership). A target the actor does not reach is 42501.
-- The authority trigger revokes the person's sessions; the last-membership trigger deletes a PIN / TOTP that has no membership left to belong to.
CREATE FUNCTION private.partner_member_revoke_for_partner(p_target_uid uuid, p_org_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_status text;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_target_uid IS NULL OR p_org_id IS NULL OR p_target_uid = v_uid THEN
    RAISE EXCEPTION 'partner_member_revoke_for_partner: a different target person and an org are required' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_target_uid AND m.org_id = p_org_id AND m.revoked_at IS NULL) THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF NOT private.partner_reach_covers_org(v_uid, p_target_uid, p_org_id) THEN
    RAISE EXCEPTION 'partner_member_revoke_for_partner: the reach rule does not cover this membership' USING ERRCODE = '42501';
  END IF;
  v_status := private.partner_member_revoke_apply(p_target_uid, p_org_id);
  IF v_status = 'ok' THEN
    PERFORM private.partner_audit_write('partner.member.revoke', 'app.partner_member', p_target_uid::text, pg_catalog.jsonb_build_object('org', p_org_id));
  END IF;
  RETURN QUERY SELECT v_status;
END
$$;

-- 7f. POST members/recover (class A2): under the reach rule for the PERSON, revoke ALL of their credentials and sessions across every org, set must_change on the PIN, retire any earlier live recover
-- token and issue a new one (24 h, their own auth email, no org). The person then runs the branch-N flow against it (6.5). Statuses: ok | no_email.
CREATE FUNCTION private.partner_member_recover_for_partner(p_target_uid uuid, p_token_hash text)
RETURNS TABLE (o_status text, o_token_id uuid, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_exp timestamptz;
  v_id uuid;
  v_creds integer;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_target_uid IS NULL OR p_target_uid = v_uid OR p_token_hash IS NULL OR pg_catalog.char_length(p_token_hash) <> 64 OR p_token_hash !~ '^[0-9a-f]{64}' THEN
    RAISE EXCEPTION 'partner_member_recover_for_partner: a different target person and a 64-hex token hash are required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.partner_reach_covers(v_uid, p_target_uid) THEN
    RAISE EXCEPTION 'partner_member_recover_for_partner: the reach rule does not cover this person' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = p_target_uid AND u.email IS NOT NULL) THEN
    RETURN QUERY SELECT 'no_email'::text, NULL::uuid, NULL::timestamptz;
    RETURN;
  END IF;
  v_creds := private.partner_credentials_revoke_user(p_target_uid, v_uid, 'recovered', NULL);
  PERFORM private.partner_sessions_revoke('user', p_target_uid, 'recovered');
  PERFORM private.partner_pin_reset_apply(p_target_uid);
  UPDATE app.partner_enrolment_token t SET revoked_at = v_now
  WHERE t.user_id = p_target_uid AND t.purpose = 'recover' AND t.consumed_at IS NULL AND t.revoked_at IS NULL;
  v_exp := v_now + interval '24 hours';
  INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at)
  VALUES (p_target_uid, 'recover', v_uid, p_token_hash, v_now, v_exp)
  RETURNING id INTO v_id;
  PERFORM private.partner_audit_write('partner.member.recover', 'app.partner_enrolment_token', v_id::text,
    pg_catalog.jsonb_build_object('target', p_target_uid, 'credentials_revoked', v_creds));
  RETURN QUERY SELECT 'ok'::text, v_id, v_exp;
END
$$;

-- 7g. POST members/pin-reset (class A2): clear the lock and every failure counter and set must_change, under the reach rule, never for oneself (6.3). Statuses: ok | unset (the person has no PIN).
CREATE FUNCTION private.partner_pin_reset_for_partner(p_target_uid uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_status text;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_target_uid IS NULL OR p_target_uid = v_uid THEN
    RAISE EXCEPTION 'partner_pin_reset_for_partner: a different target person is required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.partner_reach_covers(v_uid, p_target_uid) THEN
    RAISE EXCEPTION 'partner_pin_reset_for_partner: the reach rule does not cover this person' USING ERRCODE = '42501';
  END IF;
  v_status := private.partner_pin_reset_apply(p_target_uid);
  PERFORM private.partner_audit_write('partner.pin.reset', 'app.partner_pin', p_target_uid::text, pg_catalog.jsonb_build_object('status', v_status));
  RETURN QUERY SELECT v_status;
END
$$;

-- 7h. POST orgs/{id}/sessions/revoke-all (class A2), the stolen-iPad button: revoke every live session of the org's ACTIVE members (the revoker's own included) and, when p_created_after is
-- given, every credential created after that time of each member the reach rule fully covers. A facility org needs a manager or operator of its facility; any other org is admin only.
-- Statuses: ok | not_found.
CREATE FUNCTION private.partner_org_sessions_revoke_for_partner(p_org_id uuid, p_created_after timestamptz)
RETURNS TABLE (o_status text, o_sessions integer, o_credentials integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind app.partner_org_kind;
  v_fac text;
  v_sessions integer;
  v_creds integer := 0;
  v_m record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['manager', 'operator']::app.partner_role[], 'A2');
  IF p_org_id IS NULL OR (p_created_after IS NOT NULL AND p_created_after > pg_catalog.clock_timestamp() + interval '1 minute') THEN
    RAISE EXCEPTION 'partner_org_sessions_revoke_for_partner: an org (and, when given, a time that is not in the future) is required' USING ERRCODE = '22023';
  END IF;
  SELECT o.kind INTO v_kind FROM app.partner_org o WHERE o.id = p_org_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, 0, 0;
    RETURN;
  END IF;
  IF NOT private.is_admin(v_uid) THEN
    IF v_kind <> 'facility' THEN
      RAISE EXCEPTION 'partner_org_sessions_revoke_for_partner: no scope' USING ERRCODE = '42501';
    END IF;
    SELECT s.facility_id INTO v_fac FROM app.partner_scope s WHERE s.org_id = p_org_id AND s.facility_id IS NOT NULL LIMIT 1;
    IF v_fac IS NULL OR NOT private.has_facility_scope(v_uid, v_fac, ARRAY['manager', 'operator']::app.partner_role[]) THEN
      RAISE EXCEPTION 'partner_org_sessions_revoke_for_partner: no scope' USING ERRCODE = '42501';
    END IF;
  END IF;
  IF p_created_after IS NOT NULL THEN
    FOR v_m IN SELECT m.user_id FROM app.partner_member m WHERE m.org_id = p_org_id AND m.revoked_at IS NULL AND m.user_id <> v_uid LOOP
      IF private.partner_reach_covers(v_uid, v_m.user_id) THEN
        v_creds := v_creds + private.partner_credentials_revoke_user(v_m.user_id, v_uid, 'panic_revoke', p_created_after);
      END IF;
    END LOOP;
  END IF;
  v_sessions := private.partner_sessions_revoke('org', p_org_id, 'panic_revoke_all');
  PERFORM private.partner_audit_write('partner.org.revoke_all', 'app.partner_org', p_org_id::text,
    pg_catalog.jsonb_build_object('sessions', v_sessions, 'credentials', v_creds));
  RETURN QUERY SELECT 'ok'::text, v_sessions, v_creds;
END
$$;

-- 7i. POST credentials/options (class A2 + reauth): the challenge for ADDING a second credential, the relying party and the person's own active credential ids to exclude. The challenge is the
-- reauth-purpose HMAC (purpose 3) bound to the BOUND SESSION id, never to an argument: a challenge issued for one session cannot be used from another. 120 s. Statuses: ok | too_many (5 active).
CREATE FUNCTION private.partner_credential_options_for_partner()
RETURNS TABLE (o_status text, o_nonce bytea, o_exp bigint, o_mac bytea, o_rp_id text, o_origin text, o_exclude bytea[])
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
  v_n integer;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A2');
  v_sid := private.partner_binding_session();
  SELECT pg_catalog.count(*) INTO v_n FROM app.partner_credential c WHERE c.user_id = v_uid AND c.revoked_at IS NULL;
  IF v_n >= 5 THEN
    RETURN QUERY SELECT 'too_many'::text, NULL::bytea, NULL::bigint, NULL::bytea, NULL::text, NULL::text, NULL::bytea[];
    RETURN;
  END IF;
  o_status := 'ok';
  o_nonce := public.gen_random_bytes(32);
  o_exp := pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint + 120;
  SELECT c.o_mac INTO o_mac FROM private.partner_challenge_core(3::smallint, o_exp, o_nonce, v_sid, NULL) c;
  SELECT r.o_rp_id, r.o_origin INTO o_rp_id, o_origin FROM private.partner_rp_config_read() r;
  SELECT pg_catalog.array_agg(c.credential_id ORDER BY c.created_at) INTO o_exclude FROM app.partner_credential c WHERE c.user_id = v_uid AND c.revoked_at IS NULL;
  RETURN NEXT;
END
$$;

-- 7j. POST credentials (class A2 + reauth): register a SECOND credential for the signed-in person. The create checks are the core's (R4-L2); the challenge is the session-bound purpose-3 HMAC
-- of the options call, single use through the nonce table. The label is derived by the database; created_via_credential_id is the session's own credential. Statuses: ok | bad_challenge | expired |
-- too_many, and the core's.
CREATE FUNCTION private.partner_credential_register_for_partner(
  p_nonce bytea, p_exp bigint, p_mac bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[])
RETURNS TABLE (o_status text, o_credential_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sid uuid;
  v_via uuid;
  v_n integer;
  v_c record;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A2');
  v_sid := private.partner_binding_session();
  IF p_nonce IS NULL OR pg_catalog.octet_length(p_nonce) <> 32 OR p_exp IS NULL OR p_mac IS NULL OR pg_catalog.octet_length(p_mac) > 128
     OR p_attestation_object IS NULL OR p_client_data_json IS NULL OR p_credential_id IS NULL OR p_public_key IS NULL THEN
    RAISE EXCEPTION 'partner_credential_register_for_partner: the challenge, the attestation object, the client data, a credential id and a key are required' USING ERRCODE = '22023';
  END IF;
  IF NOT private.partner_challenge_verify(3::smallint, p_exp, p_nonce, v_sid, p_mac) THEN
    RETURN QUERY SELECT 'bad_challenge'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_exp <= pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()))::bigint THEN
    RETURN QUERY SELECT 'expired'::text, NULL::uuid;
    RETURN;
  END IF;
  SELECT pg_catalog.count(*) INTO v_n FROM app.partner_credential c WHERE c.user_id = v_uid AND c.revoked_at IS NULL;
  IF v_n >= 5 THEN
    RETURN QUERY SELECT 'too_many'::text, NULL::uuid;
    RETURN;
  END IF;
  SELECT s.credential_id INTO v_via FROM app.partner_session s WHERE s.id = v_sid;
  SELECT k.o_status, k.o_credential_id INTO v_c
  FROM private.partner_credential_create_core(v_uid, p_nonce, p_attestation_object, p_client_data_json, p_credential_id, p_public_key, p_transports, v_via, v_sid, NULL) k;
  IF v_c.o_status = 'ok' THEN
    PERFORM private.partner_audit_write('partner.credential.add', 'app.partner_credential', v_c.o_credential_id::text, pg_catalog.jsonb_build_object('via', v_via));
  END IF;
  RETURN QUERY SELECT v_c.o_status, v_c.o_credential_id;
END
$$;

-- 7k. GET credentials (class A0): the person's own credentials (never the key or the id bytes). The label is database-derived; the note is display only and is not read by any decision.
CREATE FUNCTION private.partner_credential_list_for_partner()
RETURNS TABLE (o_id uuid, o_label text, o_note text, o_created_at timestamptz, o_last_used_at timestamptz, o_revoked_at timestamptz, o_backup_eligible boolean, o_backup_state boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A0');
  RETURN QUERY
  SELECT c.id, c.label, c.note, c.created_at, c.last_used_at, c.revoked_at, c.backup_eligible, c.backup_state
  FROM app.partner_credential c
  WHERE c.user_id = v_uid
  ORDER BY c.created_at DESC, c.id;
END
$$;

-- 7l. DELETE credentials/{id} (class A2 + reauth, a person's OWN credential included: a coworker with the passcode must not revoke them all): the person's own, or one the reach rule covers; the
-- credential's sessions are revoked with it. Statuses: ok | not_found (unknown, or outside the actor's reach: one answer) | already_revoked.
CREATE FUNCTION private.partner_credential_revoke_for_partner(p_credential_id uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_c record;
  v_status text;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager', 'operator']::app.partner_role[], 'A2');
  IF p_credential_id IS NULL THEN
    RAISE EXCEPTION 'partner_credential_revoke_for_partner: a credential id is required' USING ERRCODE = '22023';
  END IF;
  SELECT c.user_id, c.revoked_at INTO v_c FROM app.partner_credential c WHERE c.id = p_credential_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_c.user_id <> v_uid AND NOT private.partner_reach_covers(v_uid, v_c.user_id) THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  IF v_c.revoked_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_revoked'::text;
    RETURN;
  END IF;
  v_status := private.partner_credential_revoke_apply(p_credential_id, v_uid, 'revoked');
  IF v_status = 'ok' THEN
    PERFORM private.partner_sessions_revoke('credential', p_credential_id, 'credential_revoked');
    PERFORM private.partner_audit_write('partner.credential.revoke', 'app.partner_credential', p_credential_id::text,
      pg_catalog.jsonb_build_object('owner', v_c.user_id, 'own', v_c.user_id = v_uid));
  END IF;
  RETURN QUERY SELECT v_status;
END
$$;

-- 7m. members/totp-reset (class A3), REPLACING the S1.4 admin-lite reset with the full reach rule (6.4, 6.5): the target is an operator or an admin, and the reach rule covers it: an operator
-- target needs an admin actor, an admin target a DIFFERENT admin, never oneself. Same signature, owner and grants as 0053.
CREATE OR REPLACE FUNCTION private.partner_totp_reset_for_partner(p_target_uid uuid)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_status text;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_target_uid IS NULL OR p_target_uid = v_uid THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: a different target user is required' USING ERRCODE = '22023';
  END IF;
  IF NOT (private.is_admin(p_target_uid)
          OR EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = p_target_uid AND m.revoked_at IS NULL AND m.role = 'operator')) THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: the target must be an operator or an admin' USING ERRCODE = '42501';
  END IF;
  IF NOT private.partner_reach_covers(v_uid, p_target_uid) THEN
    RAISE EXCEPTION 'partner_totp_reset_for_partner: the reach rule does not cover this person' USING ERRCODE = '42501';
  END IF;
  v_status := private.partner_totp_reset_apply(p_target_uid);
  PERFORM private.partner_sessions_revoke('user', p_target_uid, 'totp_reset');
  PERFORM private.partner_audit_write('partner.totp.reset', 'app.partner_totp', p_target_uid::text,
    pg_catalog.jsonb_build_object('status', v_status));
  RETURN QUERY SELECT v_status;
END
$$;

-- 7n. THE LAST-MEMBERSHIP TRIGGER (5.2, PA-29): after a membership is revoked or deleted, a person with NO active membership left loses their partner_pin and, unless they are in
-- app.admin_user (an admin holds no membership and needs the TOTP regardless), their partner_totp. The rule is also in the delete policies (pd_lastmember_*), so the function is not trusted alone.
CREATE FUNCTION private.partner_member_last_membership()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_uid := OLD.user_id;
  ELSE
    IF NOT (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) THEN
      RETURN NULL;
    END IF;
    v_uid := NEW.user_id;
  END IF;
  IF EXISTS (SELECT 1 FROM app.partner_member m WHERE m.user_id = v_uid AND m.revoked_at IS NULL) THEN
    RETURN NULL;
  END IF;
  DELETE FROM app.partner_pin p WHERE p.user_id = v_uid;
  IF NOT private.is_admin(v_uid) THEN
    DELETE FROM app.partner_totp t WHERE t.user_id = v_uid;
  END IF;
  RETURN NULL;
END
$$;

-- 7o. THE PURGES (9): bounded (a constant LIMIT 5000, never a parameter), each floor repeated in a private_definer policy, EXECUTE for edge_system (the 0040 owner-approved shape).
CREATE FUNCTION private.purge_partner_challenges()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_auth_challenge c
  WHERE c.nonce_hash = ANY (ARRAY(SELECT s.nonce_hash FROM app.partner_auth_challenge s WHERE s.used_at < pg_catalog.now() - interval '1 hour' LIMIT v_limit));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

CREATE FUNCTION private.purge_partner_sessions()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_session d
  WHERE d.id = ANY (ARRAY(SELECT s.id FROM app.partner_session s
                          WHERE LEAST(s.expires_at, COALESCE(s.revoked_at, s.expires_at)) < pg_catalog.now() - interval '30 days' LIMIT v_limit));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

CREATE FUNCTION private.purge_partner_credentials()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_credential d
  WHERE d.id = ANY (ARRAY(SELECT s.id FROM app.partner_credential s WHERE s.revoked_at < pg_catalog.now() - interval '180 days' LIMIT v_limit));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

CREATE FUNCTION private.purge_partner_invites()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_invite d
  WHERE d.id = ANY (ARRAY(SELECT s.id FROM app.partner_invite s
                          WHERE COALESCE(s.accepted_at, s.revoked_at, s.expires_at) < pg_catalog.now() - interval '90 days' LIMIT v_limit));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

CREATE FUNCTION private.purge_partner_enrolment_tokens()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_enrolment_token d
  WHERE d.id = ANY (ARRAY(SELECT s.id FROM app.partner_enrolment_token s
                          WHERE COALESCE(s.consumed_at, s.revoked_at, s.expires_at) < pg_catalog.now() - interval '90 days' LIMIT v_limit));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

CREATE FUNCTION private.purge_partner_sign_in_failures()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.partner_sign_in_failure d
  WHERE d.credential_id = ANY (ARRAY(SELECT s.credential_id FROM app.partner_sign_in_failure s WHERE s.updated_at < pg_catalog.now() - interval '1 day' LIMIT v_limit));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

-- 7p. EXECUTE grants (PUBLIC revoked first)
REVOKE EXECUTE ON FUNCTION
  private.partner_invite_create_for_partner(uuid, app.partner_role, text, text),
  private.partner_invite_list_for_partner(uuid),
  private.partner_invite_revoke_for_partner(uuid),
  private.partner_invite_accept_for_partner(text),
  private.partner_member_revoke_for_partner(uuid, uuid),
  private.partner_member_recover_for_partner(uuid, text),
  private.partner_pin_reset_for_partner(uuid),
  private.partner_org_sessions_revoke_for_partner(uuid, timestamptz),
  private.partner_credential_options_for_partner(),
  private.partner_credential_register_for_partner(bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[]),
  private.partner_credential_list_for_partner(),
  private.partner_credential_revoke_for_partner(uuid),
  private.purge_partner_challenges(),
  private.purge_partner_sessions(),
  private.purge_partner_credentials(),
  private.purge_partner_invites(),
  private.purge_partner_enrolment_tokens(),
  private.purge_partner_sign_in_failures()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_invite_create_for_partner(uuid, app.partner_role, text, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_invite_list_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_invite_revoke_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_invite_accept_for_partner(text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_member_revoke_for_partner(uuid, uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_member_recover_for_partner(uuid, text) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_pin_reset_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_org_sessions_revoke_for_partner(uuid, timestamptz) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_credential_options_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_credential_register_for_partner(bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[]) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_credential_list_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_credential_revoke_for_partner(uuid) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.purge_partner_challenges() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_partner_sessions() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_partner_credentials() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_partner_invites() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_partner_enrolment_tokens() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_partner_sign_in_failures() TO edge_system;
COMMENT ON FUNCTION private.partner_invite_create_for_partner(uuid, app.partner_role, text, text) IS
  '0054 (6.1, PA-15). edge_partner only; class A2. Explicit role arrays (manager -> staff; operator -> staff, manager; admin -> operator; sponsor refused), the grant a subset of the inviter''s reach through has_facility_scope, 72 h, an active member of that org refused with a status.';
COMMENT ON FUNCTION private.partner_invite_list_for_partner(uuid) IS
  '0054 (6.1). edge_partner only; class A0. The invites the actor''s scope covers (a table policy is the filter); never the token hash.';
COMMENT ON FUNCTION private.partner_invite_revoke_for_partner(uuid) IS
  '0054 (6.1). edge_partner only; class A2. ok | not_found | already_accepted | already_revoked; an id outside the actor''s scope is not_found.';
COMMENT ON FUNCTION private.partner_invite_accept_for_partner(text) IS
  '0054 (6.1 branch E, PA-23). edge_partner only; class A2. The session user''s confirmed email must equal the invite''s; activates the membership (no credential, no OTP); a reactivation sets the PIN to must_change. Mismatch is a status and its attempt count commits.';
COMMENT ON FUNCTION private.partner_member_revoke_for_partner(uuid, uuid) IS
  '0054 (6.5). edge_partner only; class A2. Revokes ONE membership under the reach rule for that membership (42501 when not covered, ok | not_found otherwise).';
COMMENT ON FUNCTION private.partner_member_recover_for_partner(uuid, text) IS
  '0054 (6.5, PA-25). edge_partner only; class A2. Under the reach rule for the person: revokes every credential and session across all orgs, must_change on the PIN, retires earlier live recover tokens and issues a new 24 h recover token.';
COMMENT ON FUNCTION private.partner_pin_reset_for_partner(uuid) IS
  '0054 (6.3, 6.5). edge_partner only; class A2. Clears the lock and every failure counter and sets must_change on another person''s PIN, under the reach rule, never for oneself.';
COMMENT ON FUNCTION private.partner_org_sessions_revoke_for_partner(uuid, timestamptz) IS
  '0054 (6.5). edge_partner only; class A2. The stolen-iPad button: revokes every live session of an org''s active members and, with a time, every credential created after it of each member the reach rule fully covers.';
COMMENT ON FUNCTION private.partner_credential_options_for_partner() IS
  '0054 (4.5). edge_partner only; class A2. The challenge (purpose 3, bound to the BOUND session), the relying party and the person''s active credential ids to exclude, for adding a second credential.';
COMMENT ON FUNCTION private.partner_credential_register_for_partner(bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[]) IS
  '0054 (4.5, PA-22). edge_partner only; class A2. Adds a second credential to the signed-in person: the session-bound challenge, the create core''s DB-side checks, at most five active; the label is database-derived.';
COMMENT ON FUNCTION private.partner_credential_list_for_partner() IS
  '0054 (4.5). edge_partner only; class A0. The person''s own credentials (label, note, times, backup flags); never the key or the credential id.';
COMMENT ON FUNCTION private.partner_credential_revoke_for_partner(uuid) IS
  '0054 (6.5, PA-22, PA-25). edge_partner only; class A2 for every revoke, one''s own included. The person''s own credential, or one the reach rule covers; its sessions are revoked with it.';
COMMENT ON FUNCTION private.partner_totp_reset_for_partner(uuid) IS
  '0053, 0054. edge_partner only; class A3. The target is an operator or an admin and the full reach rule covers it (an operator target needs an admin, an admin target a DIFFERENT admin); bumps seed_version, revokes the target''s sessions.';
COMMENT ON FUNCTION private.partner_member_last_membership() IS
  '0054 (5.2, PA-29). Trigger function. After a membership is revoked or deleted: a person with no active membership left loses their partner_pin and, unless in app.admin_user, their partner_totp. Executable by nobody.';
COMMENT ON FUNCTION private.purge_partner_challenges() IS '0054 (9). edge_system. Deletes used challenge nonces more than an hour old, at most 5000 per call; returns the count.';
COMMENT ON FUNCTION private.purge_partner_sessions() IS '0054 (9). edge_system. Deletes sessions 30 days past expires_at or revoked_at (whichever came first), at most 5000 per call; returns the count.';
COMMENT ON FUNCTION private.purge_partner_credentials() IS '0054 (9). edge_system. Deletes credentials revoked more than 180 days ago, at most 5000 per call; returns the count. An active credential is never purged.';
COMMENT ON FUNCTION private.purge_partner_invites() IS '0054 (9). edge_system. Deletes invites 90 days past accepted_at, revoked_at or expires_at, at most 5000 per call; returns the count. A pending invite is never purged.';
COMMENT ON FUNCTION private.purge_partner_enrolment_tokens() IS '0054 (9). edge_system. Deletes enrolment tokens 90 days past consumed_at, revoked_at or expires_at, at most 5000 per call; returns the count.';
COMMENT ON FUNCTION private.purge_partner_sign_in_failures() IS '0054 (9). edge_system. Deletes sign-in failure counters not touched for a day (the window is an hour and the cooldown 15 minutes), at most 5000 per call; returns the count.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- the last-membership triggers (created as the migrating role: CREATE TRIGGER checks EXECUTE on the function once, at creation, and PUBLIC still holds it here); then PUBLIC loses it, so nobody but
-- the owner can call the trigger function (the 0047 shape for the invariant triggers)
CREATE TRIGGER partner_member_last_membership_upd_trg AFTER UPDATE OF revoked_at ON app.partner_member
FOR EACH ROW EXECUTE FUNCTION private.partner_member_last_membership();
CREATE TRIGGER partner_member_last_membership_del_trg AFTER DELETE ON app.partner_member
FOR EACH ROW EXECUTE FUNCTION private.partner_member_last_membership();
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.partner_member_last_membership() FROM PUBLIC;
RESET ROLE;

-- R5-L3: the migrating role keeps NO way to become an owner role
REVOKE partner_session_toucher, partner_session_issuer, partner_pin_verifier FROM CURRENT_USER;

-- ============================================================================
-- 8. Registries
-- ============================================================================
-- 8a. private.function_inventory: every function above (expected_edge_partner: the twelve _for_partner definers; expected_edge_partner_minter: the five minter-lane definers;
-- expected_edge_system: the six purges; every other flag false).
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_auth_identity', 'p_uid uuid, p_gotrue_session_id uuid', false, false, false, false, false, false, false, '0054 (6.1): normalised email, confirmed flag, GoTrue freshness and admin flag for the issuer-owned accept definers; EXECUTE for partner_session_issuer alone'),
  ('private', 'partner_challenge_core', 'p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_presented bytea, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint', false, false, false, false, false, false, false, '0054 (5.1): the 8-argument overload (ref_kind || ref_id || accepted_at_us for purpose 2); the ONLY reader of Vault partner_challenge_key besides the 5-arg core; EXECUTE for nobody'),
  ('private', 'partner_challenge_issue_register', 'p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint', false, false, false, false, false, false, false, '0054 (6.1, R3-M2): the ONLY producer of a register challenge; refused inside a bound transaction; EXECUTE for partner_session_issuer alone'),
  ('private', 'partner_challenge_verify', 'p_purpose smallint, p_exp bigint, p_nonce bytea, p_binding uuid, p_mac bytea, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint', false, false, false, false, false, false, false, '0054 (5.1): the 8-argument overload; EXECUTE for partner_session_issuer (register_first)'),
  ('private', 'partner_credential_create_core', 'p_user_id uuid, p_nonce bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[], p_via_credential_id uuid, p_session_id uuid, p_minted_session_id uuid', false, false, false, false, false, false, false, '0054 (R4-L2): owned by partner_session_issuer; the DB-side create-ceremony checks (calls partner_cose_parse) and the credential insert; EXECUTE for private_definer only'),
  ('private', 'partner_credential_list_for_partner', '', false, false, false, false, false, true, false, '0054 (4.5): edge_partner only; class A0; the person''s own credentials'),
  ('private', 'partner_credential_options_for_partner', '', false, false, false, false, false, true, false, '0054 (4.5): edge_partner only; class A2; challenge, relying party and exclude list for adding a second credential'),
  ('private', 'partner_credential_register_first', 'p_token_hash text, p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_nonce bytea, p_exp bigint, p_mac bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[]', false, false, false, false, false, false, true, '0054 (6.1, PA-7b, PA-7c): edge_partner_minter only; owned by partner_session_issuer; first credential + first session in one transaction; one registration per acceptance'),
  ('private', 'partner_credential_register_for_partner', 'p_nonce bytea, p_exp bigint, p_mac bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[]', false, false, false, false, false, true, false, '0054 (4.5, PA-22): edge_partner only; class A2; registers a second credential through the create core'),
  ('private', 'partner_credential_revoke_apply', 'p_credential_id uuid, p_revoked_by uuid, p_reason text', false, false, false, false, false, false, false, '0054 (6.5): owned by partner_session_toucher; revokes one credential; EXECUTE for private_definer only'),
  ('private', 'partner_credential_revoke_for_partner', 'p_credential_id uuid', false, false, false, false, false, true, false, '0054 (6.5, PA-22): edge_partner only; class A2 for every revoke; own credential or reach'),
  ('private', 'partner_credentials_revoke_user', 'p_user_id uuid, p_revoked_by uuid, p_reason text, p_created_after timestamp with time zone', false, false, false, false, false, false, false, '0054 (6.5): owned by partner_session_toucher; revokes every active credential of a person, or those created after T; EXECUTE for private_definer only'),
  ('private', 'partner_enrolment_token_accept', 'p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid', false, false, false, false, false, false, true, '0054 (6.1, 6.4, 6.5): edge_partner_minter only; owned by partner_session_issuer; recover / admin token accept + register challenge (ref kind 2)'),
  ('private', 'partner_enrolment_token_email_for_token', 'p_token_hash text', false, false, false, false, false, false, true, '0054 (6.1, 6.4, 6.5): edge_partner_minter only; owned by partner_session_issuer; the person''s auth email for a LIVE token or no row'),
  ('private', 'partner_invite_accept', 'p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid', false, false, false, false, false, false, true, '0054 (6.1, PA-14, PA-23): edge_partner_minter only; owned by partner_session_issuer; branch N accept + register challenge; every outcome a status'),
  ('private', 'partner_invite_accept_core', 'p_token_hash text, p_uid uuid, p_gotrue_session_id uuid, p_mode text', false, false, false, false, false, false, false, '0054 (6.1): owned by partner_session_issuer; the accept order shared by branch N and branch E; EXECUTE for private_definer only (the minter wrapper has the same owner)'),
  ('private', 'partner_invite_accept_for_partner', 'p_token_hash text', false, false, false, false, false, true, false, '0054 (6.1 branch E, PA-23): edge_partner only; class A2; the session user''s confirmed email must equal the invite''s'),
  ('private', 'partner_invite_create_for_partner', 'p_org_id uuid, p_role app.partner_role, p_invitee_email text, p_token_hash text', false, false, false, false, false, true, false, '0054 (6.1, PA-15): edge_partner only; class A2; explicit role arrays, grant subset, 72 h, sponsor refused'),
  ('private', 'partner_invite_email_for_token', 'p_token_hash text', false, false, false, false, false, false, true, '0054 (6.1): edge_partner_minter only; owned by partner_session_issuer; the address of a LIVE invite or no row'),
  ('private', 'partner_invite_list_for_partner', 'p_org_id uuid', false, false, false, false, false, true, false, '0054 (6.1): edge_partner only; class A0; invites within the actor''s scope'),
  ('private', 'partner_invite_revoke_for_partner', 'p_invite_id uuid', false, false, false, false, false, true, false, '0054 (6.1): edge_partner only; class A2'),
  ('private', 'partner_member_last_membership', '', false, false, false, false, false, false, false, '0054 (5.2, PA-29): trigger function; deletes the PIN (and, for a non-admin, the TOTP) of a person left with no active membership; EXECUTE for nobody'),
  ('private', 'partner_member_recover_for_partner', 'p_target_uid uuid, p_token_hash text', false, false, false, false, false, true, false, '0054 (6.5, PA-25): edge_partner only; class A2; revokes credentials and sessions across all orgs, must_change, issues a recover token'),
  ('private', 'partner_member_revoke_apply', 'p_user_id uuid, p_org_id uuid', false, false, false, false, false, false, false, '0054 (6.5): owned by partner_session_toucher; revokes one membership (revoked_at only); its policy re-checks the reach rule; EXECUTE for private_definer only'),
  ('private', 'partner_member_revoke_for_partner', 'p_target_uid uuid, p_org_id uuid', false, false, false, false, false, true, false, '0054 (6.5): edge_partner only; class A2; one membership under the reach rule'),
  ('private', 'partner_org_sessions_revoke_for_partner', 'p_org_id uuid, p_created_after timestamp with time zone', false, false, false, false, false, true, false, '0054 (6.5): edge_partner only; class A2; the stolen-iPad button (sessions, and credentials created after T)'),
  ('private', 'partner_pin_reset_apply', 'p_target_uid uuid', false, false, false, false, false, false, false, '0054 (6.3, 6.5): owned by partner_pin_verifier; clears lock and counters, sets must_change; EXECUTE for private_definer only'),
  ('private', 'partner_pin_reset_for_partner', 'p_target_uid uuid', false, false, false, false, false, true, false, '0054 (6.3, 6.5): edge_partner only; class A2; clears the lock, sets must_change, under the reach rule'),
  ('private', 'partner_reach_covers', 'p_actor uuid, p_target uuid', false, false, false, false, false, false, false, '0054 (6.5, PA-25): the reach rule, conditions (1) to (5); EXECUTE for nobody but the owner and partner_pin_verifier (its registered policies)'),
  ('private', 'partner_reach_covers_org', 'p_actor uuid, p_target uuid, p_org uuid', false, false, false, false, false, false, false, '0054 (6.5): reach rule for ONE membership; EXECUTE for nobody but the owner and partner_session_toucher (its registered policy)'),
  ('private', 'partner_sessions_evict_oldest', 'p_user_id uuid, p_keep integer', false, false, false, false, false, false, false, '0054 (4.1): owned by partner_session_toucher; keeps at most N live sessions by revoking the oldest; EXECUTE for private_definer and partner_session_issuer'),
  ('private', 'purge_partner_challenges', '', false, false, false, false, true, false, false, '0054 (9): edge_system; used nonces more than an hour old, 5000 per call'),
  ('private', 'purge_partner_credentials', '', false, false, false, false, true, false, false, '0054 (9): edge_system; credentials revoked more than 180 days ago, 5000 per call'),
  ('private', 'purge_partner_enrolment_tokens', '', false, false, false, false, true, false, false, '0054 (9): edge_system; enrolment tokens 90 days past consumed / revoked / expired, 5000 per call'),
  ('private', 'purge_partner_invites', '', false, false, false, false, true, false, false, '0054 (9): edge_system; invites 90 days past accepted / revoked / expired, 5000 per call'),
  ('private', 'purge_partner_sessions', '', false, false, false, false, true, false, false, '0054 (9): edge_system; sessions 30 days past expires_at or revoked_at, 5000 per call'),
  ('private', 'purge_partner_sign_in_failures', '', false, false, false, false, true, false, false, '0054 (9): edge_system; sign-in failure counters untouched for a day, 5000 per call');

-- 8b. private.definer_policy_allowlist: every policy this file adds (private_definer and the owner roles), expressions derived from the live policies, so the allow-list can only ever hold text the
-- catalog agrees with (and supabase/tests/fixtures/definer_policy_exprs.txt is its checked-in twin).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0054 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'partner_auth_challenge', 'pd_purge_partner_auth_challenge', 'DELETE', true, 'S1.5 purge: used nonces more than 1 hour old; closed under a partner binding', 'private_definer'),
  ('app', 'partner_auth_challenge', 'pd_purge_partner_auth_challenge_r', 'SELECT', true, 'row-visibility companion to pd_purge_partner_auth_challenge', 'private_definer'),
  ('app', 'partner_credential', 'pd_purge_partner_credential', 'DELETE', true, 'S1.5 purge: credentials revoked more than 180 days ago; closed under a partner binding', 'private_definer'),
  ('app', 'partner_credential', 'pd_purge_partner_credential_r', 'SELECT', true, 'row-visibility companion to pd_purge_partner_credential', 'private_definer'),
  ('app', 'partner_credential', 'pd_read_partner_credential_bound', 'SELECT', true, 'S1.5: credentials listed (own) and read for the revoke path (a person the reach rule covers) under a partner binding; never a GUC', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_insert_partner_enrolment_token_recover', 'INSERT', true, 'S1.5: recover token issue; purpose=recover only, issued_by = the bound user, for a person the reach rule covers (partner_reach_covers)', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_purge_partner_enrolment_token', 'DELETE', true, 'S1.5 purge: enrolment tokens 90 days past consumed / revoked / expired; closed under a partner binding', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_purge_partner_enrolment_token_r', 'SELECT', true, 'row-visibility companion to pd_purge_partner_enrolment_token', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_read_partner_enrolment_token_recover', 'SELECT', true, 'S1.5: row visibility of recover tokens for a person the bound actor''s reach covers (INSERT RETURNING and the revoke of earlier tokens)', 'private_definer'),
  ('app', 'partner_enrolment_token', 'pd_revoke_partner_enrolment_token_recover', 'UPDATE', true, 'S1.5: retire an earlier unconsumed recover token of a person the bound actor''s reach covers', 'private_definer'),
  ('app', 'partner_enrolment_token', 'psi_read_partner_enrolment_token', 'SELECT', true, 'S1.5: the enrolment-token accept / register definers read a token by hash; USING(true), the column grant is the scope', 'partner_session_issuer'),
  ('app', 'partner_enrolment_token', 'psi_update_partner_enrolment_token_accept', 'UPDATE', true, 'S1.5: attempts / consumed_at on a LIVE token only (unconsumed, unrevoked, unexpired)', 'partner_session_issuer'),
  ('app', 'partner_enrolment_token', 'psi_update_partner_enrolment_token_register', 'UPDATE', true, 'S1.5: registered_credential_id once, on a CONSUMED, unregistered, unrevoked token', 'partner_session_issuer'),
  ('app', 'partner_invite', 'pd_insert_partner_invite', 'INSERT', true, 'S1.5: invite create; WITH CHECK ties invited_by to the BOUND partner user (partner_binding_user), a non-sponsor role and a fresh, unaccepted, unrevoked row; the grant subset is the function''s, keyed on the binding, never a GUC', 'private_definer'),
  ('app', 'partner_invite', 'pd_purge_partner_invite', 'DELETE', true, 'S1.5 purge: invites 90 days past accepted / revoked / expired; closed under a partner binding', 'private_definer'),
  ('app', 'partner_invite', 'pd_purge_partner_invite_r', 'SELECT', true, 'row-visibility companion to pd_purge_partner_invite', 'private_definer'),
  ('app', 'partner_invite', 'pd_read_partner_invite_scope', 'SELECT', true, 'S1.5: invite list / lookup; visible only under a partner binding and only to the inviter, an admin, or a manager / operator of the invite''s facility (has_facility_scope); never a GUC', 'private_definer'),
  ('app', 'partner_invite', 'pd_revoke_partner_invite', 'UPDATE', true, 'S1.5: invite revoke; only an unaccepted, unrevoked invite within the bound actor''s scope; WITH CHECK revoked_by = the bound user', 'private_definer'),
  ('app', 'partner_invite', 'psi_read_partner_invite', 'SELECT', true, 'S1.5: the accept definers (issuer-owned) look an invite up by token hash; USING(true) because the column grant and the function''s live filter are the scope (psi_read_partner_session precedent)', 'partner_session_issuer'),
  ('app', 'partner_invite', 'psi_update_partner_invite_accept', 'UPDATE', true, 'S1.5: attempts / accepted_at / accepted_by on a LIVE invite only (unaccepted, unrevoked, unexpired); WITH CHECK keeps it unregistered', 'partner_session_issuer'),
  ('app', 'partner_invite', 'psi_update_partner_invite_register', 'UPDATE', true, 'S1.5: registered_credential_id once, on an ACCEPTED, unregistered, unrevoked invite (one registration per acceptance)', 'partner_session_issuer'),
  ('app', 'partner_member', 'psi_insert_partner_member', 'INSERT', true, 'S1.5: a membership may be inserted ONLY when an invite accepted by that user for that org and role (same inviter) within the last 2 minutes exists: no GUC, no binding', 'partner_session_issuer'),
  ('app', 'partner_member', 'psi_read_partner_member', 'SELECT', true, 'S1.5: the accept definers read the person''s memberships (the other-org / active-membership rules); USING(true), the column grant is the scope', 'partner_session_issuer'),
  ('app', 'partner_member', 'psi_update_partner_member', 'UPDATE', true, 'S1.5: a revoked membership may be reactivated ONLY under the same accepted-invite condition as psi_insert_partner_member', 'partner_session_issuer'),
  ('app', 'partner_member', 'pst_revoke_partner_member', 'UPDATE', true, 'S1.5: member revoke by the toucher: UPDATE of revoked_at only (column grant); USING keyed on the partner binding AND the per-membership reach rule; WITH CHECK revoked_at set', 'partner_session_toucher'),
  ('app', 'partner_pin', 'pd_lastmember_delete_partner_pin', 'DELETE', true, 'S1.5 PA-29: the PIN of a person with no active membership (the rule is derived from data: no binding, no setting)', 'private_definer'),
  ('app', 'partner_pin', 'pd_lastmember_delete_partner_pin_r', 'SELECT', true, 'row-visibility companion to pd_lastmember_delete_partner_pin', 'private_definer'),
  ('app', 'partner_pin', 'ppv_read_partner_pin_reach', 'SELECT', true, 'S1.5: another person''s PIN row, readable by partner_pin_verifier only when the bound user''s reach rule covers them', 'partner_pin_verifier'),
  ('app', 'partner_pin', 'ppv_update_partner_pin_reach', 'UPDATE', true, 'S1.5: the PIN reset of another person: USING and WITH CHECK keyed on the binding and the reach rule', 'partner_pin_verifier'),
  ('app', 'partner_session', 'pd_purge_partner_session', 'DELETE', true, 'S1.5 purge: sessions 30 days past expires_at / revoked_at; closed under a partner binding', 'private_definer'),
  ('app', 'partner_session', 'pd_purge_partner_session_r', 'SELECT', true, 'row-visibility companion to pd_purge_partner_session', 'private_definer'),
  ('app', 'partner_sign_in_failure', 'pd_purge_partner_sign_in_failure', 'DELETE', true, 'S1.5 purge: failure counters untouched for a day; closed under a partner binding', 'private_definer'),
  ('app', 'partner_sign_in_failure', 'pd_purge_partner_sign_in_failure_r', 'SELECT', true, 'row-visibility companion to pd_purge_partner_sign_in_failure', 'private_definer'),
  ('app', 'partner_totp', 'pd_lastmember_delete_partner_totp', 'DELETE', true, 'S1.5 PA-29: the TOTP of a person with no active membership who is NOT in admin_user (an admin needs the TOTP with no membership)', 'private_definer'),
  ('app', 'partner_totp', 'pd_lastmember_delete_partner_totp_r', 'SELECT', true, 'row-visibility companion to pd_lastmember_delete_partner_totp', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND pol.polname IN ('pd_purge_partner_auth_challenge', 'pd_purge_partner_auth_challenge_r', 'pd_purge_partner_credential', 'pd_purge_partner_credential_r', 'pd_read_partner_credential_bound', 'pd_insert_partner_enrolment_token_recover', 'pd_purge_partner_enrolment_token', 'pd_purge_partner_enrolment_token_r', 'pd_read_partner_enrolment_token_recover', 'pd_revoke_partner_enrolment_token_recover', 'psi_read_partner_enrolment_token', 'psi_update_partner_enrolment_token_accept', 'psi_update_partner_enrolment_token_register', 'pd_insert_partner_invite', 'pd_purge_partner_invite', 'pd_purge_partner_invite_r', 'pd_read_partner_invite_scope', 'pd_revoke_partner_invite', 'psi_read_partner_invite', 'psi_update_partner_invite_accept', 'psi_update_partner_invite_register', 'psi_insert_partner_member', 'psi_read_partner_member', 'psi_update_partner_member', 'pst_revoke_partner_member', 'pd_lastmember_delete_partner_pin', 'pd_lastmember_delete_partner_pin_r', 'ppv_read_partner_pin_reach', 'ppv_update_partner_pin_reach', 'pd_purge_partner_session', 'pd_purge_partner_session_r', 'pd_purge_partner_sign_in_failure', 'pd_purge_partner_sign_in_failure_r', 'pd_lastmember_delete_partner_totp', 'pd_lastmember_delete_partner_totp_r');
DO $assert_0054_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN ('pd_purge_partner_auth_challenge', 'pd_purge_partner_auth_challenge_r', 'pd_purge_partner_credential', 'pd_purge_partner_credential_r', 'pd_read_partner_credential_bound', 'pd_insert_partner_enrolment_token_recover', 'pd_purge_partner_enrolment_token', 'pd_purge_partner_enrolment_token_r', 'pd_read_partner_enrolment_token_recover', 'pd_revoke_partner_enrolment_token_recover', 'psi_read_partner_enrolment_token', 'psi_update_partner_enrolment_token_accept', 'psi_update_partner_enrolment_token_register', 'pd_insert_partner_invite', 'pd_purge_partner_invite', 'pd_purge_partner_invite_r', 'pd_read_partner_invite_scope', 'pd_revoke_partner_invite', 'psi_read_partner_invite', 'psi_update_partner_invite_accept', 'psi_update_partner_invite_register', 'psi_insert_partner_member', 'psi_read_partner_member', 'psi_update_partner_member', 'pst_revoke_partner_member', 'pd_lastmember_delete_partner_pin', 'pd_lastmember_delete_partner_pin_r', 'ppv_read_partner_pin_reach', 'ppv_update_partner_pin_reach', 'pd_purge_partner_session', 'pd_purge_partner_session_r', 'pd_purge_partner_sign_in_failure', 'pd_purge_partner_sign_in_failure_r', 'pd_lastmember_delete_partner_totp', 'pd_lastmember_delete_partner_totp_r')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 35 THEN
    RAISE EXCEPTION '0054: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0054_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0054 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 8c. private.partner_owner_privilege: exactly what the owner roles gained in this file (checks 9 and 12 re-derive the real privileges from the catalog and compare; the checked-in twin is
-- supabase/tests/fixtures/partner_owner_privileges.txt).
CREATE POLICY current_user_seed_partner_owner_privilege_0054 ON private.partner_owner_privilege
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.partner_owner_privilege (role_name, object_kind, object_name, privilege, column_name) VALUES
  ('partner_pin_verifier', 'function', 'private.partner_reach_covers(uuid,uuid)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_audit_write(text,text,text,jsonb)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_auth_identity(uuid,uuid)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_cbor_head(bytea,integer)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_challenge_issue_register(uuid,smallint,uuid,bigint)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_challenge_verify(smallint,bigint,bytea,uuid,bytea,smallint,uuid,bigint)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_cose_parse(bytea)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'function', 'private.partner_sessions_evict_oldest(uuid,integer)', 'EXECUTE', NULL),
  ('partner_session_issuer', 'column', 'app.partner_member', 'INSERT', 'invited_by'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'INSERT', 'org_id'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'INSERT', 'role'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'INSERT', 'user_id'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'attempts'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'consumed_at'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'expires_at'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'id'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'purpose'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'registered_credential_id'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'revoked_at'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'token_hash'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'SELECT', 'user_id'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'accepted_at'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'accepted_by'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'attempts'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'expires_at'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'id'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'invited_by'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'invitee_email'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'org_id'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'registered_credential_id'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'revoked_at'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'role'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'SELECT', 'token_hash'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'SELECT', 'org_id'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'SELECT', 'revoked_at'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'SELECT', 'role'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'SELECT', 'user_id'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'UPDATE', 'attempts'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'UPDATE', 'consumed_at'),
  ('partner_session_issuer', 'column', 'app.partner_enrolment_token', 'UPDATE', 'registered_credential_id'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'UPDATE', 'accepted_at'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'UPDATE', 'accepted_by'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'UPDATE', 'attempts'),
  ('partner_session_issuer', 'column', 'app.partner_invite', 'UPDATE', 'registered_credential_id'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'UPDATE', 'invited_by'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'UPDATE', 'revoked_at'),
  ('partner_session_issuer', 'column', 'app.partner_member', 'UPDATE', 'role'),
  ('partner_session_toucher', 'function', 'private.partner_binding_user()', 'EXECUTE', NULL),
  ('partner_session_toucher', 'function', 'private.partner_reach_covers_org(uuid,uuid,uuid)', 'EXECUTE', NULL),
  ('partner_session_toucher', 'column', 'app.partner_credential', 'SELECT', 'created_at'),
  ('partner_session_toucher', 'column', 'app.partner_member', 'UPDATE', 'revoked_at');
DROP POLICY current_user_seed_partner_owner_privilege_0054 ON private.partner_owner_privilege;

-- ============================================================================
-- 9. Prove the grants (a refused or misapplied GRANT only warns, so the migration fails HERE rather than on the first call)
-- ============================================================================
DO $assert_0054_grants$
DECLARE
  v_role text;
  v_fn regprocedure;
  v_lane regprocedure[] := ARRAY[
    'private.partner_invite_create_for_partner(uuid, app.partner_role, text, text)'::regprocedure,
    'private.partner_invite_list_for_partner(uuid)'::regprocedure,
    'private.partner_invite_revoke_for_partner(uuid)'::regprocedure,
    'private.partner_invite_accept_for_partner(text)'::regprocedure,
    'private.partner_member_revoke_for_partner(uuid, uuid)'::regprocedure,
    'private.partner_member_recover_for_partner(uuid, text)'::regprocedure,
    'private.partner_pin_reset_for_partner(uuid)'::regprocedure,
    'private.partner_org_sessions_revoke_for_partner(uuid, timestamptz)'::regprocedure,
    'private.partner_credential_options_for_partner()'::regprocedure,
    'private.partner_credential_register_for_partner(bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])'::regprocedure,
    'private.partner_credential_list_for_partner()'::regprocedure,
    'private.partner_credential_revoke_for_partner(uuid)'::regprocedure];
  v_minter regprocedure[] := ARRAY[
    'private.partner_invite_email_for_token(text)'::regprocedure,
    'private.partner_invite_accept(text, uuid, uuid)'::regprocedure,
    'private.partner_enrolment_token_email_for_token(text)'::regprocedure,
    'private.partner_enrolment_token_accept(text, uuid, uuid)'::regprocedure,
    'private.partner_credential_register_first(text, uuid, smallint, uuid, bytea, bigint, bytea, bytea, bytea, bytea, bytea, text[])'::regprocedure];
  v_purge regprocedure[] := ARRAY[
    'private.purge_partner_challenges()'::regprocedure, 'private.purge_partner_sessions()'::regprocedure, 'private.purge_partner_credentials()'::regprocedure,
    'private.purge_partner_invites()'::regprocedure, 'private.purge_partner_enrolment_tokens()'::regprocedure, 'private.purge_partner_sign_in_failures()'::regprocedure];
  v_helpers regprocedure[] := ARRAY[
    'private.partner_reach_covers_org(uuid, uuid, uuid)'::regprocedure,
    'private.partner_reach_covers(uuid, uuid)'::regprocedure,
    'private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)'::regprocedure,
    'private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)'::regprocedure,
    'private.partner_challenge_issue_register(uuid, smallint, uuid, bigint)'::regprocedure,
    'private.partner_auth_identity(uuid, uuid)'::regprocedure,
    'private.partner_member_revoke_apply(uuid, uuid)'::regprocedure,
    'private.partner_credential_revoke_apply(uuid, uuid, text)'::regprocedure,
    'private.partner_credentials_revoke_user(uuid, uuid, text, timestamptz)'::regprocedure,
    'private.partner_sessions_evict_oldest(uuid, integer)'::regprocedure,
    'private.partner_pin_reset_apply(uuid)'::regprocedure,
    'private.partner_invite_accept_core(text, uuid, uuid, text)'::regprocedure,
    'private.partner_credential_create_core(uuid, bytea, bytea, bytea, bytea, bytea, text[], uuid, uuid, uuid)'::regprocedure,
    'private.partner_member_last_membership()'::regprocedure];
BEGIN
  IF EXISTS (SELECT 1 FROM unnest(v_lane || v_minter || v_purge || v_helpers || ARRAY['private.partner_totp_reset_for_partner(uuid)'::regprocedure]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE NOT p.prosecdef OR p.proconfig IS DISTINCT FROM ARRAY['search_path=""']) THEN
    RAISE EXCEPTION '0054: a function is not SECURITY DEFINER with search_path=''''';
  END IF;
  -- ownership: the shared writers belong to the role that owns the privilege they use
  IF EXISTS (SELECT 1 FROM unnest(v_lane || v_purge || ARRAY[
        'private.partner_reach_covers_org(uuid, uuid, uuid)', 'private.partner_reach_covers(uuid, uuid)',
        'private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)', 'private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)',
        'private.partner_challenge_issue_register(uuid, smallint, uuid, bigint)', 'private.partner_auth_identity(uuid, uuid)', 'private.partner_member_last_membership()',
        'private.partner_totp_reset_for_partner(uuid)']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'private_definer'::regrole) THEN
    RAISE EXCEPTION '0054: a private_definer function is not owned by private_definer';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(v_minter || ARRAY['private.partner_invite_accept_core(text, uuid, uuid, text)',
        'private.partner_credential_create_core(uuid, bytea, bytea, bytea, bytea, bytea, text[], uuid, uuid, uuid)']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'partner_session_issuer'::regrole) THEN
    RAISE EXCEPTION '0054: an issuer function is not owned by partner_session_issuer';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(ARRAY['private.partner_member_revoke_apply(uuid, uuid)', 'private.partner_credential_revoke_apply(uuid, uuid, text)',
        'private.partner_credentials_revoke_user(uuid, uuid, text, timestamptz)', 'private.partner_sessions_evict_oldest(uuid, integer)']::regprocedure[]) f(oid)
             JOIN pg_proc p ON p.oid = f.oid WHERE p.proowner <> 'partner_session_toucher'::regrole)
     OR (SELECT proowner FROM pg_proc WHERE oid = 'private.partner_pin_reset_apply(uuid)'::regprocedure) <> 'partner_pin_verifier'::regrole THEN
    RAISE EXCEPTION '0054: a toucher / pin verifier function is not owned by its role';
  END IF;
  -- the partner lane: edge_partner and nobody else
  FOREACH v_fn IN ARRAY v_lane LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated', 'partner_totp_verifier', 'partner_pin_verifier', 'partner_session_issuer'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0054: % can execute %; only edge_partner may', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_partner', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0054: edge_partner cannot execute %', v_fn;
    END IF;
  END LOOP;
  -- the minter lane: edge_partner_minter and nobody else
  FOREACH v_fn IN ARRAY v_minter LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0054: % can execute the minter-lane function %', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_partner_minter', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0054: edge_partner_minter cannot execute %', v_fn;
    END IF;
  END LOOP;
  -- the purges: edge_system and nobody else
  FOREACH v_fn IN ARRAY v_purge LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_actor', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0054: % can execute the purge %', v_role, v_fn;
      END IF;
    END LOOP;
    IF NOT has_function_privilege('edge_system', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION '0054: edge_system cannot execute %', v_fn;
    END IF;
  END LOOP;
  -- the helpers: no edge role, client role or service_role can run any of them
  FOREACH v_fn IN ARRAY v_helpers LOOP
    FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_partner', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
      IF has_function_privilege(v_role, v_fn, 'EXECUTE') THEN
        RAISE EXCEPTION '0054: % can execute the helper %', v_role, v_fn;
      END IF;
    END LOOP;
  END LOOP;
  -- the Vault-key cores: the 8-argument core runs for nobody but its owner; the register verifier and issuer are the issuer's alone
  IF has_function_privilege('partner_session_issuer', 'private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('partner_session_toucher', 'private.partner_challenge_core(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('partner_session_issuer', 'private.partner_challenge_verify(smallint, bigint, bytea, uuid, bytea, smallint, uuid, bigint)'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('partner_session_issuer', 'private.partner_challenge_issue_register(uuid, smallint, uuid, bigint)'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('partner_session_issuer', 'private.partner_cose_parse(bytea)'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('partner_session_issuer', 'private.partner_cbor_head(bytea, integer)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0054: a register-challenge or COSE-parser EXECUTE grant is wrong';
  END IF;
  -- the reach rule is callable only where a registered policy calls it
  IF NOT (has_function_privilege('partner_session_toucher', 'private.partner_reach_covers_org(uuid, uuid, uuid)'::regprocedure, 'EXECUTE')
          AND has_function_privilege('partner_pin_verifier', 'private.partner_reach_covers(uuid, uuid)'::regprocedure, 'EXECUTE')
          AND NOT has_function_privilege('partner_session_issuer', 'private.partner_reach_covers(uuid, uuid)'::regprocedure, 'EXECUTE')
          AND NOT has_function_privilege('partner_totp_verifier', 'private.partner_reach_covers(uuid, uuid)'::regprocedure, 'EXECUTE')) THEN
    RAISE EXCEPTION '0054: a reach-rule EXECUTE grant is wrong';
  END IF;
  -- the partner_authorize seam is still executable by nobody
  FOREACH v_role IN ARRAY ARRAY['edge_partner', 'edge_actor', 'edge_system', 'edge_partner_minter', 'edge_gateway', 'service_role', 'anon', 'authenticated', 'partner_totp_verifier', 'partner_session_issuer'] LOOP
    IF has_function_privilege(v_role, 'private.partner_authorize(text, text, app.partner_role[], text)'::regprocedure, 'EXECUTE') THEN
      RAISE EXCEPTION '0054: % can execute partner_authorize', v_role;
    END IF;
  END LOOP;
  -- the edge roles still hold NO relation privilege in app; the new column privileges sit on the owner roles only
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN (VALUES ('edge_partner'), ('edge_partner_minter')) r(n)
             WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
               AND (has_any_column_privilege(r.n, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, c.oid, 'DELETE,TRUNCATE,TRIGGER'))) THEN
    RAISE EXCEPTION '0054: edge_partner or its minter holds a relation privilege in app';
  END IF;
  -- the membership writes: private_definer gained none (revoke is the toucher's revoked_at, activation the issuer's); the toucher can write nothing but revoked_at
  IF has_column_privilege('partner_session_toucher', 'app.partner_member', 'role', 'UPDATE') OR has_column_privilege('partner_session_toucher', 'app.partner_member', 'org_id', 'UPDATE')
     OR NOT has_column_privilege('partner_session_toucher', 'app.partner_member', 'revoked_at', 'UPDATE')
     OR has_table_privilege('partner_session_issuer', 'app.partner_member', 'DELETE') OR has_table_privilege('partner_session_issuer', 'app.partner_invite', 'INSERT')
     OR has_table_privilege('partner_session_issuer', 'app.partner_invite', 'DELETE') OR has_column_privilege('partner_session_issuer', 'app.partner_invite', 'token_hash', 'UPDATE')
     OR has_column_privilege('private_definer', 'app.partner_invite', 'accepted_at', 'UPDATE') OR has_column_privilege('private_definer', 'app.partner_invite', 'attempts', 'UPDATE') THEN
    RAISE EXCEPTION '0054: a membership or invite write privilege is not where it must be';
  END IF;
  IF NOT has_column_privilege('private_definer', 'auth.users', 'email_confirmed_at', 'SELECT') THEN
    RAISE EXCEPTION '0054: private_definer cannot read auth.users.email_confirmed_at';
  END IF;
  -- the two triggers exist on partner_member and the function is ours
  IF (SELECT count(*) FROM pg_trigger t WHERE t.tgrelid = 'app.partner_member'::regclass AND NOT t.tgisinternal AND t.tgfoid = 'private.partner_member_last_membership()'::regprocedure::oid) <> 2 THEN
    RAISE EXCEPTION '0054: the last-membership triggers are missing';
  END IF;
  -- register-challenge overloads: the 5-arg signatures still exist next to the 8-arg ones
  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'private' AND p.proname IN ('partner_challenge_core', 'partner_challenge_verify')) <> 4 THEN
    RAISE EXCEPTION '0054: partner_challenge_core / partner_challenge_verify must exist as exactly two overloads each';
  END IF;
END
$assert_0054_grants$;
