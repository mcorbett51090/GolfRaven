-- 0041_signin_proof_hardening.sql
-- Edge role PR #35: hardens the proof-bound cross-account Sign in with Apple link (0039, edge-role-design.md section 12.1) after the PR #31 security gate.
-- 0001-0040 are untouched.
--
-- L1  ANY UNBOUND edge_system TRANSACTION COULD MINT A PROOF.
--   0039 granted EXECUTE on private.signin_record_email_proof to edge_system, the role of the revocation drain, the queue operations, the catalog
--   importer (which parses publisher input) and retention-purge. The only target-specific corroboration was "the target's last_sign_in_at is within 60 s",
--   and any ordinary sign-in by the victim satisfies it: a statement injected into any of those system lanes could mint (attacker -> victim) and then poll
--   until the victim signed in. Two independent hardenings, both here:
--
--   (a) A DEDICATED MINTING ROLE, edge_signin_minter (NOLOGIN NOINHERIT NOBYPASSRLS, the shape of edge_actor / edge_system). edge_gateway is a member WITH
--       INHERIT FALSE, SET TRUE (exactly as 0030 does for edge_actor / edge_system). EXECUTE on the minter is MOVED from edge_system to it: it holds
--       USAGE on schema private (name resolution) and EXECUTE on that ONE function, and nothing else, ever: no table, no column, no policy, no other function,
--       no membership in any role, and no member but edge_gateway. The Edge runtime's mint path opens its transaction with kind "signin_mint"
--       (privileged.ts openScopedTx), which no other path can ask for (the privileged lint's privileged-mint-scope rule).
--       What this is and is not (stated plainly, see 12.1 "what the trust argument is now"): it removes the capability from every system lane as a
--       PRIVILEGE. A statement that runs as edge_system (a drain, queue, import or retention statement) can no longer call the minter. It is NOT a barrier
--       against an injection that can also switch role: edge_gateway, the session user of every lane, can SET ROLE edge_signin_minter (SET TRUE) just as it can
--       SET ROLE edge_actor and bind any uid, and `set_config('role', ...)` is a function call. That is R6 and unchanged. (b) is what covers that gap.
--
--   (b) THE PROOF IS BOUND TO THE SESSION verifyOtp CREATED. The mint now also takes the id of the GoTrue session the OTP verification created
--       (p_session_id) and refuses unless auth.sessions holds a row with that id, for the TARGET account, created within 60 s of now. A session id is an
--       unguessable uuid known to whoever called verifyOtp (it is the `session_id` claim of the access token verifyOtp returns); the minter role cannot read
--       auth.sessions, edge_actor / edge_system cannot read it, and the proof table keeps the id under a UNIQUE index so one session mints at most one proof.
--       So an injected mint (even by a caller that could switch to the minter role) fails unless it also knows a live session id of the victim, which the
--       database never discloses to any edge role. The handler signs that exact session out after the mint (it already signs the session out, F5).
--       `[unverified: training knowledge of GoTrue]` the columns used are auth.sessions.id, .user_id and .created_at, and verifyOtp is believed to create
--       a sessions row whose id is the access token's `session_id` claim. A project where any of that is untrue makes every mint refuse (fail closed,
--       email_proof_refused), and the P4 spike (a real project) would see it at once. The GRANT below is asserted, as 0039 asserts its own.
--
-- L2  EMAIL NORMALISATION DIFFERED (the database lower(btrim()), JavaScript toLowerCase()/trim()).
--   The address (and the provider subject) were hashed in JavaScript for the mint and in SQL for the redemption. Every mismatch failed closed (409), but
--   two implementations of one rule is the defect, and lower() is locale-dependent in PostgreSQL (no JavaScript function can mirror it). The mint now takes
--   the RAW address and the RAW subject and does ALL the normalising and hashing in the database, with the same expression the redemption uses:
--   lower(btrim(x)) and sha256 of it. JavaScript no longer hashes either value for the proof. (The OTP failure counter's bucket is now keyed on the TARGET
--   ACCOUNT the database resolved, not on a JavaScript spelling of the address: see methods-handler.ts.)
--
-- N2  pd_signin_proof_select / _delete admitted any row an hour past its expiry to ANY private_definer code. They now admit stale rows only inside the
--   purge window, a transaction-local GUC (app.signin.proof_purge = 'on') that purge_signin_email_proofs and the mint's own bounded stale-row cleanup open
--   and close around their DELETE (the 0030 purge_fix_coords pattern, the exact check-7 form).
--
-- THE GRANT CHANGES (all of them)
--   REVOKE ALL / DROP of the 0039 five-argument private.signin_record_email_proof(uuid, uuid, text, text, text): edge_system loses EXECUTE with it.
--   GRANT EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) TO edge_signin_minter   (the move)
--   GRANT USAGE ON SCHEMA private TO edge_signin_minter                                                             (the new role's only other privilege)
--   GRANT SELECT (id, user_id, created_at) ON auth.sessions TO private_definer                                      (what (b) reads, as the definer)
--   GRANT edge_signin_minter TO edge_gateway WITH INHERIT FALSE, SET TRUE                                           (membership, not a privilege)
--   Nothing is broadened: edge_actor, edge_system, service_role, anon and authenticated gain nothing; no edge policy and no edge table grant is added
--   (private.edge_policy_allowlist and its fixture are unchanged). Proved by the assertions at the end of this file and by checks 2 and 9-12 of
--   tools/db/verify-function-inventory.mjs (and matrix 10), which now also know the new role.
--
-- Same bracket as 0030/0035/0039: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; ...; RESET ROLE; REVOKE CREATE.
-- `migration_owner` is never named.

-- ============================================================================
-- 1. The role, its membership, and the refusal to run against a misconfigured one
-- ============================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'edge_signin_minter') THEN
    CREATE ROLE edge_signin_minter NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
END
$$;
-- (SUPERUSER / BYPASSRLS / REPLICATION cannot be re-asserted by a non-superuser; they are fixed at CREATE ROLE and asserted below.)
ALTER ROLE edge_signin_minter NOLOGIN NOINHERIT NOCREATEROLE NOCREATEDB;

GRANT edge_signin_minter TO edge_gateway WITH INHERIT FALSE, SET TRUE;
-- Schema USAGE only (name resolution); every function in `private` has had PUBLIC EXECUTE revoked, so this reaches only what is granted below.
GRANT USAGE ON SCHEMA private TO edge_signin_minter;

DO $assert_0041_role$
DECLARE
  v_bad text;
BEGIN
  SELECT string_agg(a.attr, ', ') INTO v_bad
  FROM pg_roles r CROSS JOIN LATERAL (VALUES ('SUPERUSER', r.rolsuper), ('BYPASSRLS', r.rolbypassrls), ('REPLICATION', r.rolreplication),
    ('CREATEROLE', r.rolcreaterole), ('CREATEDB', r.rolcreatedb), ('INHERIT', r.rolinherit), ('LOGIN', r.rolcanlogin)) AS a(attr, is_on)
  WHERE r.rolname = 'edge_signin_minter' AND a.is_on;
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0041: edge_signin_minter holds an attribute it must not (%)', v_bad;
  END IF;
  -- edge_gateway is a SET TRUE, INHERIT FALSE, non-admin member
  IF NOT EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
                 WHERE r.rolname = 'edge_signin_minter' AND m.rolname = 'edge_gateway' AND am.set_option AND NOT am.inherit_option AND NOT am.admin_option) THEN
    RAISE EXCEPTION '0041: edge_gateway must be a SET TRUE, INHERIT FALSE, non-admin member of edge_signin_minter (a refused GRANT only warns)';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
             WHERE r.rolname = 'edge_signin_minter' AND m.rolname = 'edge_gateway' AND (NOT am.set_option OR am.inherit_option OR am.admin_option)) THEN
    RAISE EXCEPTION '0041: a grant row of edge_signin_minter to edge_gateway has INHERIT or ADMIN or lacks SET (every row must be SET TRUE, INHERIT FALSE, non-admin)';
  END IF;
  -- the minter is a member of NOTHING; nobody but edge_gateway can SET ROLE to / inherit from it (the migrating role may hold it WITHOUT set / inherit)
  SELECT string_agg(m.rolname || ' is a member of ' || r.rolname, '; ') INTO v_bad
  FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
  WHERE m.rolname = 'edge_signin_minter';
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0041: edge_signin_minter must be a member of no role: %', v_bad;
  END IF;
  SELECT string_agg(m.rolname, ', ') INTO v_bad
  FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
  WHERE r.rolname = 'edge_signin_minter' AND m.rolname <> 'edge_gateway' AND (am.set_option OR am.inherit_option OR NOT (m.rolsuper OR m.rolcreaterole));
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0041: a role other than edge_gateway can reach edge_signin_minter: %', v_bad;
  END IF;
END
$assert_0041_role$;

-- ============================================================================
-- 2. What private_definer needs on auth.sessions (the session binding, (b)), proved
-- ============================================================================
GRANT SELECT (id, user_id, created_at) ON auth.sessions TO private_definer;
-- A GRANT the grantor may not make only WARNS (0035, F8): prove it took, so a project that refuses it fails HERE, not on the first mint.
DO $assert_sessions$
BEGIN
  IF NOT (has_column_privilege('private_definer', 'auth.sessions', 'id', 'SELECT')
          AND has_column_privilege('private_definer', 'auth.sessions', 'user_id', 'SELECT')
          AND has_column_privilege('private_definer', 'auth.sessions', 'created_at', 'SELECT')) THEN
    RAISE EXCEPTION '0041: the GRANT SELECT (id, user_id, created_at) ON auth.sessions TO private_definer did not take effect (a refused grant only warns); signin_record_email_proof cannot bind a proof to a session without it';
  END IF;
END
$assert_sessions$;

-- ============================================================================
-- 3. The proof table: the session id (one session, one proof) and the narrowed stale-row window (N2)
-- ============================================================================
ALTER TABLE private.signin_email_proof ADD COLUMN session_id uuid;
-- nullable only for a proof minted before this migration (<= 10 minutes of life); the minter below never writes NULL
CREATE UNIQUE INDEX signin_email_proof_session_uidx ON private.signin_email_proof (session_id) WHERE session_id IS NOT NULL;
COMMENT ON COLUMN private.signin_email_proof.session_id IS
  '0041. The GoTrue session (auth.sessions.id) the OTP verification created; the minter refused unless it existed for the target, fresh. Unique: one session mints at most one proof. Never NULL for a proof minted by 0041 code.';

-- N2: stale rows (an hour past expiry) are visible / deletable only inside the purge window, not to any private_definer code.
ALTER POLICY pd_signin_proof_select ON private.signin_email_proof
  USING (
    id::text = nullif(current_setting('app.signin.proof_id', true), '')
    OR caller_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR target_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR (nullif(current_setting('app.signin.proof_purge', true), '') = 'on' AND expires_at < now() - interval '1 hour')
  );
ALTER POLICY pd_signin_proof_delete ON private.signin_email_proof
  USING (
    caller_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR target_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR (nullif(current_setting('app.signin.proof_purge', true), '') = 'on' AND expires_at < now() - interval '1 hour')
  );

-- ============================================================================
-- 4. The definers (ownership bracket)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- The 0039 five-argument minter takes a JavaScript-computed hash and no session: it goes, with its grant to edge_system (the move, step one).
DROP FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text);

-- 4a. THE MINTER. edge_signin_minter ONLY. Refuses inside an actor-bound transaction; checks the email binding, GoTrue's sign-in stamp AND the session.
-- The address and the subject arrive RAW and are normalised and hashed HERE, with the expression the redemption uses (L2).
CREATE FUNCTION private.signin_record_email_proof(
  p_caller_user_id uuid, p_target_user_id uuid, p_email text, p_provider text, p_provider_sub text, p_session_id uuid
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_id uuid;
  v_email text;
  v_target_email text;
  v_last_sign_in timestamptz;
  v_session_created timestamptz;
BEGIN
  IF p_caller_user_id IS NULL OR p_target_user_id IS NULL OR p_provider IS NULL OR p_provider NOT IN ('apple', 'google')
     OR p_email IS NULL OR btrim(p_email) = '' OR length(p_email) > 320
     OR p_provider_sub IS NULL OR btrim(p_provider_sub) = '' OR length(p_provider_sub) > 255 THEN
    RAISE EXCEPTION 'signin_record_email_proof: invalid caller, target, provider, address or subject' USING ERRCODE = '22023';
  END IF;
  IF p_session_id IS NULL THEN
    RAISE EXCEPTION 'signin_record_email_proof: a session id is required' USING ERRCODE = '22023';
  END IF;
  IF p_caller_user_id = p_target_user_id THEN
    RAISE EXCEPTION 'signin_record_email_proof: a proof is for ANOTHER account (the caller is the target)' USING ERRCODE = '22023';
  END IF;
  -- Minting and redeeming are different transactions on purpose: a transaction that already has an actor bound (the per-user lane, or a system
  -- delegate) may not mint, even if it switched role with SET ROLE.
  IF EXISTS (SELECT 1 FROM private.actor_binding b WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned()) THEN
    RAISE EXCEPTION 'signin_record_email_proof: a proof cannot be minted inside an actor-bound transaction' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = p_caller_user_id) THEN
    RAISE EXCEPTION 'signin_record_email_proof: no such caller' USING ERRCODE = 'P0002';
  END IF;
  SELECT lower(btrim(u.email)), u.last_sign_in_at INTO v_target_email, v_last_sign_in FROM auth.users u WHERE u.id = p_target_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'signin_record_email_proof: no such target account' USING ERRCODE = 'P0002';
  END IF;
  -- the ONE normalisation (L2): the same lower(btrim()) the redemption applies to the address it is handed, on both sides of the comparison
  v_email := lower(btrim(p_email));
  -- the email binding is the DATABASE's: the proven address must be the target account's own, right now
  IF v_target_email IS NULL OR v_target_email = '' OR v_email <> v_target_email THEN
    RAISE EXCEPTION 'email_proof_refused: the proven address is not the target account''s address' USING ERRCODE = '28000';
  END IF;
  -- GoTrue's own bookkeeping must show the target signing in around now: a verifyOtp for that account really happened. The window is symmetric so a
  -- small clock skew between GoTrue and the database cannot refuse a genuine proof.
  IF v_last_sign_in IS NULL OR v_last_sign_in < clock_timestamp() - interval '60 seconds' OR v_last_sign_in > clock_timestamp() + interval '60 seconds' THEN
    RAISE EXCEPTION 'email_proof_refused: the target account has no sign-in within the last 60 seconds to corroborate the proof' USING ERRCODE = '28000';
  END IF;
  -- (b) the session verifyOtp created: it must exist, for the TARGET, and be fresh. The id is a secret only the caller of verifyOtp holds.
  SELECT s.created_at INTO v_session_created FROM auth.sessions s WHERE s.id = p_session_id AND s.user_id = p_target_user_id;
  IF NOT FOUND OR v_session_created IS NULL OR v_session_created < clock_timestamp() - interval '60 seconds' OR v_session_created > clock_timestamp() + interval '60 seconds' THEN
    RAISE EXCEPTION 'email_proof_refused: the target account has no session of that id created within the last 60 seconds to bind the proof to' USING ERRCODE = '28000';
  END IF;
  -- Retention does not wait for a scheduler: every mint also removes (a bounded batch of) proofs already an hour past their expiry, inside the purge
  -- window of pd_signin_proof_select / _delete (N2: the window is closed again right after).
  PERFORM set_config('app.signin.proof_purge', 'on', true);
  DELETE FROM private.signin_email_proof p
  WHERE p.id IN (SELECT s.id FROM private.signin_email_proof s WHERE s.expires_at < now() - interval '1 hour' ORDER BY s.expires_at LIMIT 100);
  PERFORM set_config('app.signin.proof_purge', '', true);
  v_id := gen_random_uuid();
  PERFORM set_config('app.signin.proof_id', v_id::text, true);
  BEGIN
    INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, session_id, created_at, expires_at)
    VALUES (v_id, p_caller_user_id, p_target_user_id, p_provider,
            encode(sha256(convert_to(v_email, 'UTF8')), 'hex'),
            encode(sha256(convert_to(p_provider || ':' || p_provider_sub, 'UTF8')), 'hex'),
            p_session_id, now(), now() + interval '5 minutes');
  EXCEPTION WHEN unique_violation THEN
    PERFORM set_config('app.signin.proof_id', '', true);
    RAISE EXCEPTION 'email_proof_refused: that session already minted a proof' USING ERRCODE = '28000';
  END;
  PERFORM set_config('app.signin.proof_id', '', true);
  RETURN v_id;
END;
$$;

-- 4b. Retention (N2): stale rows are reached only inside the purge window, opened and closed here. Same identity, grants, owner and bound as 0040.
CREATE OR REPLACE FUNCTION private.purge_signin_email_proofs()
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n int;
BEGIN
  PERFORM set_config('app.signin.proof_purge', 'on', true);
  DELETE FROM private.signin_email_proof p
  WHERE p.id IN (
    SELECT s.id FROM private.signin_email_proof s
    WHERE s.expires_at < now() - interval '1 hour'
    ORDER BY s.expires_at, s.id
    LIMIT v_limit
  );
  GET DIAGNOSTICS v_n = ROW_COUNT;
  PERFORM set_config('app.signin.proof_purge', '', true);
  RETURN v_n;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) FROM PUBLIC;
-- the move, step two: the ONLY role that can mint
GRANT EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) TO edge_signin_minter;

COMMENT ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) IS
  '0041 (was 0039). edge_signin_minter ONLY. Mints the single-use, 5-minute proof that the caller proved control of the TARGET account''s mailbox. Takes the RAW address and subject and normalises / hashes them here (lower(btrim()), sha256). Refuses inside an actor-bound transaction; unless the address matches the target''s current auth.users.email; unless the target signed in within 60 seconds per GoTrue (last_sign_in_at); and unless auth.sessions holds a session with the given id for the target created within 60 seconds (one session, one proof). The only writer of private.signin_email_proof; also deletes a bounded batch of proofs an hour past expiry (inside the purge window).';
COMMENT ON FUNCTION private.purge_signin_email_proofs() IS
  '0039/0040/0041. System work (edge_system, service_role): deletes proofs an hour past their expiry, oldest first, at most 5000 per call, returns the count. Opens (and closes) the app.signin.proof_purge window the stale-row policies require.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 5. Prove the grants: a refused or misapplied GRANT only warns, so the migration fails HERE rather than on the first mint
-- ============================================================================
DO $assert_0041_grants$
DECLARE
  v_role text;
  v_mint regprocedure := 'private.signin_record_email_proof(uuid, uuid, text, text, text, uuid)'::regprocedure;
  v_bad text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = v_mint AND p.prosecdef AND p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""']) THEN
    RAISE EXCEPTION '0041: the minter is not SECURITY DEFINER owned by private_definer with search_path=''''';
  END IF;
  -- the minter, exactly one role
  FOREACH v_role IN ARRAY ARRAY['edge_system', 'edge_actor', 'edge_gateway', 'service_role', 'anon', 'authenticated'] LOOP
    IF has_function_privilege(v_role, v_mint, 'EXECUTE') THEN
      RAISE EXCEPTION '0041: % can execute the minter; only edge_signin_minter may', v_role;
    END IF;
  END LOOP;
  IF NOT has_function_privilege('edge_signin_minter', v_mint, 'EXECUTE') THEN
    RAISE EXCEPTION '0041: edge_signin_minter cannot execute the minter';
  END IF;
  -- the old five-argument minter is gone (with its edge_system grant)
  IF to_regprocedure('private.signin_record_email_proof(uuid, uuid, text, text, text)') IS NOT NULL THEN
    RAISE EXCEPTION '0041: the 0039 five-argument minter still exists';
  END IF;
  -- the purge kept its grants through CREATE OR REPLACE
  IF NOT (has_function_privilege('edge_system', 'private.purge_signin_email_proofs()', 'EXECUTE') AND has_function_privilege('service_role', 'private.purge_signin_email_proofs()', 'EXECUTE'))
     OR has_function_privilege('edge_actor', 'private.purge_signin_email_proofs()', 'EXECUTE') OR has_function_privilege('edge_signin_minter', 'private.purge_signin_email_proofs()', 'EXECUTE') THEN
    RAISE EXCEPTION '0041: the purge grants changed';
  END IF;
  -- the minter holds nothing else: no function but the one, no privilege on any table or sequence in any schema
  SELECT string_agg(n.nspname || '.' || p.proname, ', ') INTO v_bad
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname IN ('app', 'api', 'private') AND p.oid <> v_mint AND has_function_privilege('edge_signin_minter', p.oid, 'EXECUTE');
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0041: edge_signin_minter can execute other functions: %', v_bad;
  END IF;
  SELECT string_agg(n.nspname || '.' || c.relname, ', ') INTO v_bad
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%'
    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
    AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('edge_signin_minter', c.oid, 'USAGE,SELECT,UPDATE')
             ELSE has_any_column_privilege('edge_signin_minter', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_signin_minter', c.oid, 'DELETE,TRUNCATE,TRIGGER') END;
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0041: edge_signin_minter holds a privilege on a relation: %', v_bad;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%' AND has_schema_privilege('edge_signin_minter', n.oid, 'CREATE')) THEN
    RAISE EXCEPTION '0041: edge_signin_minter can CREATE in a schema';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_policy pol WHERE (SELECT oid FROM pg_roles WHERE rolname = 'edge_signin_minter') = ANY (pol.polroles)) THEN
    RAISE EXCEPTION '0041: a policy names edge_signin_minter';
  END IF;
END
$assert_0041_grants$;

-- ============================================================================
-- 6. Registries
-- ============================================================================
-- 6a. private.function_inventory: the new role's EXECUTE column (default false for every function; only the minter is true), and the minter's row
ALTER TABLE private.function_inventory ADD COLUMN expected_edge_signin_minter boolean NOT NULL DEFAULT false;
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0041 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.function_inventory
SET identity_args = 'p_caller_user_id uuid, p_target_user_id uuid, p_email text, p_provider text, p_provider_sub text, p_session_id uuid',
    expected_edge_system = false,
    expected_edge_signin_minter = true,
    note = '0041 (was 0039): edge_signin_minter ONLY (EXECUTE MOVED from edge_system); mints the single-use 5-minute proof that the caller proved the TARGET account''s mailbox; takes the RAW address and subject (normalised and hashed in the database); refuses inside an actor-bound transaction, unless the address matches the target''s auth.users.email, the target signed in within 60 s (GoTrue''s last_sign_in_at) and auth.sessions holds a fresh session of that id for the target; the only writer of private.signin_email_proof'
WHERE schema_name = 'private' AND function_name = 'signin_record_email_proof'
  AND identity_args = 'p_caller_user_id uuid, p_target_user_id uuid, p_email_hash text, p_provider text, p_sub_hash text';
UPDATE private.function_inventory SET note = '0039/0040/0041: delete proofs an hour past their expiry, at most 5000 per call, inside the app.signin.proof_purge window; system work (service_role, edge_system)'
WHERE schema_name = 'private' AND function_name = 'purge_signin_email_proofs' AND identity_args = '';
DO $assert_0041_inventory$
BEGIN
  IF (SELECT count(*) FROM private.function_inventory WHERE expected_edge_signin_minter) <> 1 THEN
    RAISE EXCEPTION '0041: the inventory must expect edge_signin_minter EXECUTE on exactly one function';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM private.function_inventory WHERE schema_name = 'private' AND function_name = 'signin_record_email_proof' AND expected_edge_signin_minter
                   AND NOT expected_edge_system AND NOT expected_edge_actor AND NOT expected_service_role AND NOT expected_anon AND NOT expected_authenticated
                   AND identity_args = 'p_caller_user_id uuid, p_target_user_id uuid, p_email text, p_provider text, p_provider_sub text, p_session_id uuid') THEN
    RAISE EXCEPTION '0041: the minter''s inventory row was not updated (an UPDATE that matches nothing is silent)';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM private.function_inventory WHERE function_name = 'purge_signin_email_proofs' AND note LIKE '0039/0040/0041:%') THEN
    RAISE EXCEPTION '0041: the purge''s inventory row was not updated';
  END IF;
END
$assert_0041_inventory$;
DROP POLICY current_user_edit_function_inventory_0041 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

-- 6b. private.definer_policy_allowlist: the two policies whose text changed (N2). The row's expressions are re-derived from the live policy (the 0035 pattern).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0041 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid),
    note = CASE al.policy_name
      WHEN 'pd_signin_proof_select' THEN 'private.signin_*proof*: ONE proof (app.signin.proof_id), or the proofs an account being deleted is a party to (app.delete_my_data.target_user_id), or (0041, N2) rows an hour past expiry ONLY inside the purge window (app.signin.proof_purge = on, opened and closed by purge_signin_email_proofs and the minter''s bounded cleanup); exact nullif form of check 7. Also the visibility companion for UPDATE / DELETE ... WHERE'
      ELSE 'delete_my_data (the account''s proofs as caller or target) and, inside the purge window only (0041, N2), purge_signin_email_proofs and the minter''s bounded cleanup (rows an hour past expiry); never a live proof of another account' END
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN ('pd_signin_proof_select', 'pd_signin_proof_delete');
DO $assert_0041_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN ('pd_signin_proof_select', 'pd_signin_proof_delete') AND using_expr LIKE '%app.signin.proof_purge%') <> 2 THEN
    RAISE EXCEPTION '0041: the two stale-row policies'' allowlist rows were not updated';
  END IF;
END
$assert_0041_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0041 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;
