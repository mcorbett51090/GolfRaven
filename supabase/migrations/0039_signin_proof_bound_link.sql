-- 0039_signin_proof_bound_link.sql
-- Edge role PR4a: the PROOF-BOUND cross-account Sign in with Apple link in EDGE_DB_MODE=edge. 0001-0038 are untouched.
--
-- THE PROBLEM
--   §3.4 rule 2: an Apple identity whose verified email belongs to ANOTHER account is never auto-linked; the player proves
--   the existing account with an email OTP first, and the identity is then linked to the PROVEN account, never to the caller.
--   In `legacy` mode the Edge runtime (service_role) does that with private.signin_link_identity(<proven uid>, ...). In `edge`
--   mode (0035/0037, edge-role-design.md §12) there was deliberately NO definer for it: an edge_actor that could attach an
--   identity to an account of its choosing is an account-takeover primitive, so the path answered `501
--   email_proof_link_unavailable`. The owner decided (2026-10-02) to build it rather than ship the 501.
--
-- THE DESIGN (what binds the target account, in the database)
--   The Edge runtime verifies the OTP with Supabase Auth (GoTrue verifyOtp, anon key): the database cannot call GoTrue, so the
--   runtime's word that "the OTP verified" is unavoidable. This migration makes that word NOT sufficient on its own, and makes
--   the target of the link a database fact instead of an argument:
--
--   1. private.signin_email_proof: a single-use, short-lived (<= 5 minutes by the minter, <= 10 minutes by a CHECK constraint)
--      proof row binding FIVE things: the CALLER (the session that proved), the TARGET account, the email hash, the provider and
--      a hash of the provider subject (the Apple `sub`). FORCE RLS; no edge grant of any kind; registered in the PII registries.
--   2. private.signin_record_email_proof(...)  -- the ONLY writer of that table. EXECUTE: edge_system ONLY (no edge_actor, no
--      service_role: the legacy lane does not use it). service_role cannot be the minter because in `edge` mode the Edge runtime
--      HAS no service_role pool (PR4b deletes the legacy one); edge_system is the narrowest role the runtime does hold that is
--      not the per-user lane. The definer refuses, in the database, unless ALL of:
--        a. NO actor is bound in this transaction (so a bound edge_actor transaction cannot mint even after SET ROLE edge_system:
--           minting and linking are different transactions by construction);
--        b. the proven email hashes to the TARGET account's CURRENT auth.users.email (the email binding is checked, not asserted);
--        c. the target account signed in within the last 60 seconds per GoTrue's own bookkeeping (auth.users.last_sign_in_at):
--           a corroboration that a verifyOtp for that account really happened just now. `[unverified: real GoTrue is believed to
--           stamp last_sign_in_at when verifyOtp issues its session; a project where it does not makes every mint refuse
--           (fail closed, error email_proof_refused), which the P4 spike would see at once]`;
--        d. caller and target exist and differ.
--   3. private.signin_link_identity_with_proof_for_actor(...)  -- edge_actor ONLY; requires a kind = 'user' binding (the caller).
--      It locks the TARGET's per-account advisory lock (the same lock link / unlink / store_token / enqueue take), locks the
--      proof row FOR UPDATE and refuses unless it is unconsumed, unexpired (clock_timestamp(), not the transaction start), issued
--      for THIS caller, for THIS provider and subject hash, for THIS email hash, and the target's address still hashes to it. It
--      then marks the proof consumed and links + stores the token for proof.target_user_id -- never actor_uid() -- by calling the
--      0035 cores (so the §3.4 rules, the duplicate-identity 23505 and the last-method rule are the SAME code as the legacy path).
--      One definer does the link AND the token store so the proof is consumed exactly once.
--   4. private.purge_signin_email_proofs() -- stale rows (1 hour past expiry); edge_system and service_role (system work).
--   5. private.delete_my_data is redefined to delete the account's proofs (as caller or target) -- see 3d.
--
-- WHAT A FULLY COMPROMISED EDGE RUNTIME CAN STILL DO (R6, edge-role-design.md section 8) -- stated plainly, not hidden
--   It holds the edge_gateway login, so it can `SET ROLE edge_actor`, `bind_actor(<any uid>)` and call the PRE-EXISTING 0035
--   wrapper signin_link_identity_for_actor to attach any identity to THAT account, with no proof at all; it also holds the GoTrue
--   service key. This migration does not create that capability and does not remove it. What it adds is narrower than R6:
--   a bound-as-A actor (a handler bug, an injected statement in a per-user transaction) can link to ANOTHER account only with a
--   proof that the database itself checked against the target's own email and GoTrue's sign-in stamp, that was minted by a
--   different role in a different transaction, and that is bound to this caller, this Apple subject and this address. A runtime
--   that can already bind any uid gains nothing from the proof path and loses nothing; closing R6 itself is PR5 (a JWT-verifying binder).
--
-- No edge policy and no edge table grant is added: private.edge_policy_allowlist and its fixture are unchanged; checks 9-13 see
-- nothing new (the table is PII-registered and edge_system holds no privilege on it). The only grants are EXECUTE on the new
-- functions and a column SELECT for private_definer on auth.users.last_sign_in_at (asserted below, as 0035 asserts its own).

-- ============================================================================
-- 1. What private_definer needs on auth.users (the corroboration column), proved
-- ============================================================================
GRANT SELECT (last_sign_in_at) ON auth.users TO private_definer;
-- A GRANT the grantor may not make only WARNS (0035, F8): prove it took, so a project that refuses it fails HERE, not on the first link.
DO $assert_users_last_sign_in$
BEGIN
  IF NOT has_column_privilege('private_definer', 'auth.users', 'last_sign_in_at', 'SELECT') THEN
    RAISE EXCEPTION '0039: the GRANT SELECT (last_sign_in_at) ON auth.users TO private_definer did not take effect (a refused grant only warns); signin_record_email_proof cannot corroborate a proof without it';
  END IF;
END
$assert_users_last_sign_in$;

-- ============================================================================
-- 2. private.signin_email_proof
-- ============================================================================
CREATE TABLE private.signin_email_proof (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- the session that did the proving: only this caller may redeem the proof
  caller_user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  -- the account whose mailbox was proven: the ONLY account the proof can link to
  target_user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('apple', 'google')),
  -- sha256 hex of lower(btrim(email)) and of provider || ':' || subject: a hash, never the address or the Apple sub itself
  email_hash text NOT NULL CHECK (email_hash ~ '^[0-9a-f]{64}$'),
  sub_hash text NOT NULL CHECK (sub_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CONSTRAINT signin_email_proof_ttl CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
  CONSTRAINT signin_email_proof_cross_account CHECK (caller_user_id <> target_user_id)
);
CREATE INDEX signin_email_proof_caller_idx ON private.signin_email_proof (caller_user_id);
CREATE INDEX signin_email_proof_target_idx ON private.signin_email_proof (target_user_id);
CREATE INDEX signin_email_proof_expires_idx ON private.signin_email_proof (expires_at);
COMMENT ON TABLE private.signin_email_proof IS
  '0039. Single-use, <= 10 minute proofs that a caller proved control of the TARGET account''s mailbox (an email OTP, verified by GoTrue) for one provider identity. Written only by private.signin_record_email_proof (edge_system), redeemed only by private.signin_link_identity_with_proof_for_actor (edge_actor, kind = user); holds user ids and two hashes, no address and no provider subject. PII-registered (retention: deleted with the account and purged 1 hour after expiry; export: exclude). No role but private_definer has any privilege on it.';

ALTER TABLE private.signin_email_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.signin_email_proof FORCE ROW LEVEL SECURITY;
-- column-level UPDATE: the only thing that ever changes on a proof is consumed_at
GRANT SELECT, INSERT, DELETE ON private.signin_email_proof TO private_definer;
GRANT UPDATE (consumed_at) ON private.signin_email_proof TO private_definer;

-- Scoping (the exact check-7 form for every GUC read): a definer sees / writes ONE proof, named by app.signin.proof_id (set and
-- cleared inside the definer), or, for the account deletion, the proofs the account is a party to (app.delete_my_data.target_user_id,
-- set first by delete_my_data), or, for the purge, rows already an hour past their expiry (nothing live is ever visible to the purge).
CREATE POLICY pd_signin_proof_select ON private.signin_email_proof
  FOR SELECT TO private_definer
  USING (
    id::text = nullif(current_setting('app.signin.proof_id', true), '')
    OR caller_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR target_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR expires_at < now() - interval '1 hour'
  );
CREATE POLICY pd_signin_proof_insert ON private.signin_email_proof
  FOR INSERT TO private_definer
  WITH CHECK (id::text = nullif(current_setting('app.signin.proof_id', true), ''));
CREATE POLICY pd_signin_proof_update ON private.signin_email_proof
  FOR UPDATE TO private_definer
  USING (id::text = nullif(current_setting('app.signin.proof_id', true), ''))
  WITH CHECK (id::text = nullif(current_setting('app.signin.proof_id', true), ''));
CREATE POLICY pd_signin_proof_delete ON private.signin_email_proof
  FOR DELETE TO private_definer
  USING (
    caller_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR target_user_id::text = nullif(current_setting('app.delete_my_data.target_user_id', true), '')
    OR expires_at < now() - interval '1 hour'
  );

-- ============================================================================
-- 3. The definer functions (ownership bracket: 0020 / 0022 / 0035) + delete_my_data redefined
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. THE MINTER. edge_system only; refuses inside an actor-bound transaction; checks the email binding and GoTrue's sign-in stamp.
CREATE FUNCTION private.signin_record_email_proof(
  p_caller_user_id uuid, p_target_user_id uuid, p_email_hash text, p_provider text, p_sub_hash text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_id uuid;
  v_email text;
  v_last_sign_in timestamptz;
BEGIN
  IF p_caller_user_id IS NULL OR p_target_user_id IS NULL OR p_provider IS NULL OR p_provider NOT IN ('apple', 'google')
     OR p_email_hash IS NULL OR p_email_hash !~ '^[0-9a-f]{64}$' OR p_sub_hash IS NULL OR p_sub_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'signin_record_email_proof: invalid caller, target, provider or hash' USING ERRCODE = '22023';
  END IF;
  IF p_caller_user_id = p_target_user_id THEN
    RAISE EXCEPTION 'signin_record_email_proof: a proof is for ANOTHER account (the caller is the target)' USING ERRCODE = '22023';
  END IF;
  -- Minting and redeeming are different transactions on purpose: a transaction that already has an actor bound (the per-user lane)
  -- may not mint, even if it switched to edge_system with SET ROLE.
  IF EXISTS (SELECT 1 FROM private.actor_binding b WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned()) THEN
    RAISE EXCEPTION 'signin_record_email_proof: a proof cannot be minted inside an actor-bound transaction' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = p_caller_user_id) THEN
    RAISE EXCEPTION 'signin_record_email_proof: no such caller' USING ERRCODE = 'P0002';
  END IF;
  SELECT lower(btrim(u.email)), u.last_sign_in_at INTO v_email, v_last_sign_in FROM auth.users u WHERE u.id = p_target_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'signin_record_email_proof: no such target account' USING ERRCODE = 'P0002';
  END IF;
  -- the email binding is the DATABASE's: the proven address must be the target account's own, right now
  IF v_email IS NULL OR v_email = '' OR encode(sha256(convert_to(v_email, 'UTF8')), 'hex') <> p_email_hash THEN
    RAISE EXCEPTION 'email_proof_refused: the proven address is not the target account''s address' USING ERRCODE = '28000';
  END IF;
  -- GoTrue's own bookkeeping must show the target signing in around now: a verifyOtp for that account really happened. The window is
  -- symmetric so a small clock skew between GoTrue and the database cannot refuse a genuine proof.
  IF v_last_sign_in IS NULL OR v_last_sign_in < clock_timestamp() - interval '60 seconds' OR v_last_sign_in > clock_timestamp() + interval '60 seconds' THEN
    RAISE EXCEPTION 'email_proof_refused: the target account has no sign-in within the last 60 seconds to corroborate the proof' USING ERRCODE = '28000';
  END IF;
  -- Retention does not wait for a scheduler: every mint also removes (a bounded batch of) proofs already an hour past their expiry, under the
  -- stale-row predicate of pd_signin_proof_delete. (purge_signin_email_proofs, run by the revocation drain, is the other path; both are idempotent.)
  DELETE FROM private.signin_email_proof p
  WHERE p.id IN (SELECT s.id FROM private.signin_email_proof s WHERE s.expires_at < now() - interval '1 hour' ORDER BY s.expires_at LIMIT 100);
  v_id := gen_random_uuid();
  PERFORM set_config('app.signin.proof_id', v_id::text, true);
  INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, created_at, expires_at)
  VALUES (v_id, p_caller_user_id, p_target_user_id, p_provider, p_email_hash, p_sub_hash, now(), now() + interval '5 minutes');
  PERFORM set_config('app.signin.proof_id', '', true);
  RETURN v_id;
END;
$$;

-- 3b. THE REDEEMER. edge_actor only, kind = 'user' binding required. The target is the PROOF's, never actor_uid().
CREATE FUNCTION private.signin_link_identity_with_proof_for_actor(
  p_proof_id uuid, p_provider text, p_provider_sub text, p_email text, p_email_verified boolean, p_is_private_relay boolean,
  p_ciphertext bytea, p_dek_wrapped bytea, p_kek_id text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_actor uuid;
  v_target uuid;
  v_proof private.signin_email_proof%ROWTYPE;
  v_created boolean;
BEGIN
  v_actor := private.signin_bound_user('signin_link_identity_with_proof_for_actor');
  IF p_proof_id IS NULL OR p_provider IS NULL OR p_provider NOT IN ('apple', 'google')
     OR p_provider_sub IS NULL OR btrim(p_provider_sub) = '' OR length(p_provider_sub) > 255
     OR p_email IS NULL OR btrim(p_email) = '' OR length(p_email) > 320 THEN
    RAISE EXCEPTION 'signin_link_identity_with_proof_for_actor: invalid proof, provider, subject or email' USING ERRCODE = '22023';
  END IF;
  -- rule (1)/(3): a proof is about a mailbox. An unverified email or a private-relay address is never the proof path.
  IF p_email_verified IS NOT TRUE OR p_is_private_relay IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'signin_link_identity_with_proof_for_actor: the proof path takes a verified, non-relay email only' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.signin.proof_id', p_proof_id::text, true);
  SELECT p.target_user_id INTO v_target FROM private.signin_email_proof p WHERE p.id = p_proof_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'email_proof_refused: no such proof' USING ERRCODE = '28000';
  END IF;
  -- Lock order: the per-account advisory lock FIRST (the lock link / unlink / store_token / enqueue / delete all take), then the proof
  -- row. Two redemptions of one proof therefore serialise on the target's lock and the second sees consumed_at set.
  PERFORM pg_advisory_xact_lock(hashtextextended('signin:' || v_target::text, 0));
  SELECT * INTO v_proof FROM private.signin_email_proof p WHERE p.id = p_proof_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'email_proof_refused: no such proof' USING ERRCODE = '28000';
  END IF;
  IF v_proof.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'email_proof_refused: that proof was already used' USING ERRCODE = '28000';
  END IF;
  IF v_proof.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'email_proof_refused: that proof has expired' USING ERRCODE = '28000';
  END IF;
  IF v_proof.caller_user_id <> v_actor THEN
    RAISE EXCEPTION 'email_proof_refused: that proof was issued to another caller' USING ERRCODE = '28000';
  END IF;
  IF v_proof.provider <> p_provider OR v_proof.sub_hash <> encode(sha256(convert_to(p_provider || ':' || p_provider_sub, 'UTF8')), 'hex') THEN
    RAISE EXCEPTION 'email_proof_refused: that proof was issued for a different identity' USING ERRCODE = '28000';
  END IF;
  IF v_proof.email_hash <> encode(sha256(convert_to(lower(btrim(p_email)), 'UTF8')), 'hex') THEN
    RAISE EXCEPTION 'email_proof_refused: that proof was issued for a different address' USING ERRCODE = '28000';
  END IF;
  -- the address must STILL be the proven account's (it can change hands between the proof and the link)
  IF NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = v_proof.target_user_id AND encode(sha256(convert_to(lower(btrim(u.email)), 'UTF8')), 'hex') = v_proof.email_hash) THEN
    RAISE EXCEPTION 'email_proof_refused: the proven address no longer belongs to the target account' USING ERRCODE = '28000';
  END IF;
  UPDATE private.signin_email_proof p SET consumed_at = clock_timestamp() WHERE p.id = v_proof.id;
  PERFORM set_config('app.signin.proof_id', '', true);
  -- The same cores the legacy path calls, on the PROOF's target. The caller (v_actor) appears nowhere below this line.
  v_created := private.signin_link_identity(v_proof.target_user_id, p_provider, p_provider_sub, lower(btrim(p_email)), true, false);
  PERFORM private.signin_store_token(v_proof.target_user_id, p_provider, p_ciphertext, p_dek_wrapped, p_kek_id);
  RETURN v_created;
END;
$$;

-- 3c. Retention: proofs an hour past their expiry (consumed or not). System work.
CREATE FUNCTION private.purge_signin_email_proofs()
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n int;
BEGIN
  DELETE FROM private.signin_email_proof p WHERE p.expires_at < now() - interval '1 hour';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_link_identity_with_proof_for_actor(uuid, text, text, text, boolean, boolean, bytea, bytea, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.purge_signin_email_proofs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text) TO edge_system;
GRANT EXECUTE ON FUNCTION private.signin_link_identity_with_proof_for_actor(uuid, text, text, text, boolean, boolean, bytea, bytea, text) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.purge_signin_email_proofs() TO service_role, edge_system;

COMMENT ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text) IS
  '0039. edge_system ONLY. Mints the single-use, 5-minute proof that the caller proved control of the TARGET account''s mailbox. Refuses inside an actor-bound transaction, unless the proven address hashes to the target''s current auth.users.email, and unless the target signed in within 60 seconds per GoTrue (auth.users.last_sign_in_at). The only writer of private.signin_email_proof; also deletes a bounded batch of proofs an hour past expiry.';
COMMENT ON FUNCTION private.signin_link_identity_with_proof_for_actor(uuid, text, text, text, boolean, boolean, bytea, bytea, text) IS
  '0039. edge_actor only (kind = user binding). Redeems a proof ATOMICALLY (advisory lock on the target, FOR UPDATE on the proof; unconsumed, unexpired, issued to this caller, for this provider/subject hash and this address hash) and links the identity AND stores its token for the PROOF''s target account, never actor_uid().';
COMMENT ON FUNCTION private.purge_signin_email_proofs() IS
  '0039. System work (edge_system, service_role): deletes proofs an hour past their expiry.';

-- 3d. delete_my_data, redefined from its current body (0032, L1) with ONE addition: the account's own proofs (as caller or as target) are
-- deleted, next to the rate-limit purge, under the pd_signin_proof_delete policy keyed on the same GUC delete_my_data sets first. Same
-- signature, owner, search_path, grants and comment; nothing else changed.
CREATE OR REPLACE FUNCTION private.delete_my_data(p_user_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
  v_handle text;
  v_email text;
  v_result jsonb := '{}'::jsonb;
  v_pol record;
  v_row_count int;
  v_key_id uuid;
  v_key_secret text;
  v_pseudonym_candidate text;
  v_post_pol record;
  v_remaining int;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'delete_my_data: user_id is required';
  END IF;

  -- S1 close-out (gate round 3): this function is owned by `private_definer`
  -- (0016_private_definer.sql), a NOLOGIN NOSUPERUSER NOBYPASSRLS role that
  -- is NOT the table owner — every table below stays ENABLE + FORCE ROW
  -- LEVEL SECURITY, and private_definer reaches rows only through the
  -- explicit, narrow policies 0016 defines, each scoped to this session-
  -- local GUC. Set it FIRST, before the very first table read below, since
  -- even `app.profile`'s own SELECT now goes through a policy keyed on it.
  PERFORM set_config('app.delete_my_data.target_user_id', p_user_id::text, true);

  SELECT handle INTO v_handle FROM app.profile WHERE user_id = p_user_id;
  SELECT email INTO v_email FROM auth.users WHERE id = p_user_id;
  -- Fully qualified: this function runs with search_path = '' (below),
  -- and pgcrypto is installed into `public` (confirmed this session via
  -- `pg_extension.extnamespace`), so an unqualified hmac()/digest() would
  -- 42883 ("function ... does not exist") here even though the extension
  -- is present.
  --
  -- ⛔ FIX (M1, post-P3a re-gate): the pseudonym key is NEVER read from a
  -- GUC any more (0015/0016's prior `current_setting('app.pseudonym_hmac')`
  -- design had four confirmed problems: readable by anon/authenticated,
  -- overridable by any caller's own `SET LOCAL`, silently accepted an
  -- empty value with no error, and production never sets an `app.*` GUC
  -- at all — see supabase/tests/shim.sql's own note on this, where the
  -- fix is explained in full). The key now comes from Supabase Vault
  -- (`vault.decrypted_secrets`, real in production, shimmed locally) —
  -- read INSIDE this SECURITY DEFINER function body, which no other role
  -- can do (private_definer's own narrow, column-level grant on that
  -- view, 0018_pseudonym_vault.sql — anon/authenticated get none).
  --
  -- Rotation: EVERY row named `pseudonym_hmac%` in the vault is an
  -- "active" key (0018's own deploy-check note explains the naming
  -- convention). A pseudonym was computed, at WRITE time, with WHATEVER
  -- key was active then — so finding it again means trying every
  -- currently-active key, not just the newest one, or a row written
  -- under an older key becomes permanently unfindable the moment a new
  -- key is added. The loop below (right before the one place this
  -- function actually MATCHES rows by pseudonym, attestation_shift_log)
  -- does exactly that: for each active key, validate it, compute this
  -- user's pseudonym under it, and run the shift-log UPDATE once per
  -- key — safe to repeat (idempotent: a row already updated on an
  -- earlier key's pass no longer matches ANY later key's WHERE clause,
  -- since its own player_pseudonym column never changes).
  -- The two derived GUCs the "special" policies (partner_invite,
  -- public_profile_projection) match on — set once either value is
  -- known; empty string (not NULL) when there is nothing to match, so
  -- `current_setting(..., true)` never returns NULL into a `column =
  -- NULL` comparison (which would be neither true nor false and so
  -- would never permit a row — the intended, fail-closed behaviour when
  -- e.g. the account has no email on file). `target_pseudonym` is set
  -- per-key, in the loop right above the attestation_shift_log UPDATE
  -- below — see that block for why.
  PERFORM set_config('app.delete_my_data.target_email', COALESCE(v_email, ''), true);
  PERFORM set_config('app.delete_my_data.target_handle', COALESCE(v_handle, ''), true);

  -- ==========================================================================
  -- Generic pass: every FK-to-auth.users column in `app`, driven by
  -- private.pii_retention_policy. Fails closed on anything unclassified.
  -- ==========================================================================
  FOR v_pol IN
    SELECT
      cl.relname AS table_name,
      a.attname AS column_name,
      pol.action,
      pol.reason
    FROM pg_catalog.pg_constraint con
    JOIN pg_catalog.pg_class cl ON cl.oid = con.conrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = cl.relnamespace
    JOIN pg_catalog.pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
    LEFT JOIN private.pii_retention_policy pol
      ON pol.schema_name = 'app' AND pol.table_name = cl.relname AND pol.column_name = a.attname
    WHERE con.contype = 'f'
      AND n.nspname = 'app'
      AND con.confrelid = 'auth.users'::regclass
  LOOP
    IF v_pol.action IS NULL THEN
      RAISE EXCEPTION
        'delete_my_data: app.%.% references auth.users but has no private.pii_retention_policy row — classify it (delete_row / set_null / special) before this function can run',
        v_pol.table_name, v_pol.column_name;
    ELSIF v_pol.action = 'delete_row' THEN
      EXECUTE format('DELETE FROM app.%I WHERE %I = $1', v_pol.table_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'set_null' THEN
      EXECUTE format('UPDATE app.%I SET %I = NULL WHERE %I = $1', v_pol.table_name, v_pol.column_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'special' THEN
      CONTINUE; -- handled below, by name, not generically
    END IF;
  END LOOP;

  -- ==========================================================================
  -- Special cases (each cross-referenced to its private.pii_retention_policy
  -- row and reason).
  -- ==========================================================================

  -- entitlement: detach activated_device_id UNCONDITIONALLY, for every
  -- state (including `redeemed`, which is terminal and never voided) — the
  -- device row is about to be deleted by the generic pass above (device.
  -- user_id is a delete_row policy) and RESTRICT (the default) on
  -- entitlement.activated_device_id would otherwise block that delete.
  -- This is not a pii_retention_policy row because activated_device_id
  -- does not reference auth.users — it references app.device — so it is
  -- outside the auth.users-driven loop above by construction; called out
  -- here because it was exactly B3's "handle the RESTRICT FK on
  -- activated_device_id" finding.
  UPDATE app.entitlement SET activated_device_id = NULL, devicecheck_token_hash = NULL
    WHERE user_id = p_user_id;
  -- entitlement.play_id / offer_code.play_id (H1, post-P3a gate): also
  -- references app.play, which the generic pass below deletes (play.user_id
  -- = delete_row) — the FK itself is now ON DELETE SET NULL DEFERRABLE
  -- INITIALLY DEFERRED (0017), so this is belt-and-suspenders, not load-
  -- bearing, but detaching explicitly here matches activated_device_id's
  -- own pattern immediately above and keeps the intent visible at the
  -- call site rather than only in the FK definition.
  UPDATE app.entitlement SET play_id = NULL WHERE user_id = p_user_id;
  UPDATE app.offer_code SET play_id = NULL WHERE user_id = p_user_id;
  -- Then, per line 2759 / O9-O10: void any UNREDEEMED entitlement or stock
  -- voucher (redeemed stays redeemed — terminal, kept for the stock ledger).
  UPDATE app.entitlement
  SET state = 'void'
  WHERE user_id = p_user_id
    AND kind = 'special_marker'
    AND state IN ('earned', 'held_review', 'redeemable', 'vouchered');
  -- offer_code.activated_device_id has the same RESTRICT shape; offer_code
  -- rows for this user are deleted by the generic pass (offer_code.user_id
  -- = delete_row), so no separate detach is needed there — but another
  -- user's already-activated offer_code could in principle point at a
  -- device this user owns only if devices were ever shared, which they are
  -- not (app.device.user_id is 1:1 with the owning account) — no action
  -- needed.

  -- attestation.player_user_id (special): nulled, not deleted (line 841).
  UPDATE app.attestation SET player_user_id = NULL WHERE player_user_id = p_user_id;
  -- attestation.staff_user_id is handled by the generic pass above (it is
  -- now a plain `set_null` policy row, gate round 2 fix) — no bespoke code
  -- needed here; staff_pseudonym (populated at attest time, out of this
  -- stage's scope) survives so the row stays verifiable as "staff-attested".

  -- audit_log.actor_user_id (special): redacted via the trigger's one
  -- narrow exception (0006) — covers every historical row matching, "older
  -- audit_log rows" included, since the WHERE has no date bound.
  UPDATE app.audit_log SET actor_user_id = NULL WHERE actor_user_id = p_user_id;

  -- receipt_fingerprint.user_id (special): nulled, row kept (24-month
  -- fraud retention, line 835).
  UPDATE app.receipt_fingerprint SET user_id = NULL WHERE user_id = p_user_id;

  -- fraud_signal.user_id (special): nulled, row kept — an admin fraud
  -- record survives its subject's account deletion.
  UPDATE app.fraud_signal SET user_id = NULL WHERE user_id = p_user_id;

  -- partner_invite (special): deleted on EITHER match — the inviter
  -- deleting their account (invited_by), or the invite naming the deleted
  -- user's own verified email (invitee_email) — task instruction: "Cover
  -- ... partner_invite.invitee_email".
  DELETE FROM app.partner_invite
  WHERE invited_by = p_user_id
     OR (v_email IS NOT NULL AND invitee_email = v_email);

  -- attestation_shift_log: match by the durable player_pseudonym (HMAC of
  -- user_id), NOT by the current handle (B3 fix — a handle can change or
  -- be reused after being freed; the projection never stores a user id at
  -- all, line 842). A row logged before this stage's pseudonym column
  -- existed falls back to matching the pre-deletion handle.
  --
  -- ⛔ FIX (should-fix, post-P3a re-gate: "key rotation ... match on each
  -- row's recorded hmac id and raise if that key is missing"): the PRIOR
  -- version tried every vault row whose NAME matched 'pseudonym_hmac%' —
  -- renaming a retired key out of that naming convention (e.g.
  -- 'pseudonym_hmac_v1' -> 'retired_v1') silently dropped it from this
  -- loop even though rows still carry its id in their OWN
  -- player_pseudonym_hmac_id column, "succeeding" while leaving that
  -- key's rows unredacted. This version drives the loop from the DATA
  -- instead of the vault's naming convention: every id ever recorded
  -- against a player_pseudonym/staff_pseudonym pair is resolved BY ID
  -- (name-independent, so a rename never matters), and a recorded id that
  -- no longer resolves in vault.decrypted_secrets at all (deleted, not
  -- merely renamed — should-fix "FK into vault.secrets", 0018, dropped
  -- the FK specifically so this can be validated here instead of relying
  -- on referential integrity to prevent it) RAISES rather than silently
  -- skipping that key's rows.
  --
  -- ⛔ FIX (should-fix 2, post-P3a re-gate): "replace the broad
  -- pd_shift_log_discover_hmac_id policy (USING(true)) with a small
  -- registry of key ids ever used ... deletion iterates the registry."
  -- The SOURCE of this loop's key ids is now private.
  -- pseudonym_key_registry (0018), populated at WRITE time by the
  -- app.attestation/app.attestation_shift_log validation triggers (also
  -- 0018) — NOT a live, row-unscoped SELECT over the wide
  -- attestation_shift_log table any more, which is what let the broad
  -- discovery policy this replaces be narrowed away entirely.
  FOR v_key_id IN
    SELECT key_id FROM private.pseudonym_key_registry
  LOOP
    SELECT decrypted_secret INTO v_key_secret FROM vault.decrypted_secrets WHERE id = v_key_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'delete_my_data: attestation_shift_log references pseudonym key id % that no longer resolves in vault.decrypted_secrets (deleted or otherwise gone) — cannot safely determine whether it matches this user', v_key_id;
    END IF;
    IF v_key_secret IS NULL OR length(v_key_secret) < 32 THEN
      RAISE EXCEPTION 'delete_my_data: pseudonym key % in vault.decrypted_secrets is NULL or shorter than 32 bytes', v_key_id;
    END IF;
    v_pseudonym_candidate := encode(public.hmac(p_user_id::text, v_key_secret, 'sha256'), 'hex');
    -- `app.delete_my_data.target_pseudonym` is re-set per key so
    -- 0016_private_definer.sql's RLS policy (which independently checks
    -- the same GUC, since private_definer reaches this table only
    -- through that policy) agrees with this statement's own WHERE clause
    -- on each pass.
    PERFORM set_config('app.delete_my_data.target_pseudonym', v_pseudonym_candidate, true);
    UPDATE app.attestation_shift_log
    SET player_handle_snapshot = 'deleted player'
    WHERE player_pseudonym_hmac_id = v_key_id AND player_pseudonym = v_pseudonym_candidate;
  END LOOP;
  -- Legacy fallback: a row logged before player_pseudonym/
  -- player_pseudonym_hmac_id existed at all has neither set — matched by
  -- the pre-deletion handle instead, same as always (0016's own RLS
  -- policy already has a SEPARATE branch for exactly this shape, keyed
  -- on target_handle, not target_pseudonym).
  UPDATE app.attestation_shift_log
  SET player_handle_snapshot = 'deleted player'
  WHERE player_pseudonym IS NULL AND player_pseudonym_hmac_id IS NULL
    AND v_handle IS NOT NULL AND player_handle_snapshot = v_handle;

  -- receipt objects in storage.objects (task instruction: "receipt objects
  -- in storage.objects"). Matched by `owner` (set at upload time by the
  -- out-of-scope receipts Edge Function) and, defensively, by the
  -- `receipts/<user_id>/...` path convention (line 868) in case `owner`
  -- was never populated for an older object.
  DELETE FROM storage.objects
  WHERE bucket_id = 'receipts'
    AND (owner = p_user_id OR name LIKE 'receipts/' || p_user_id::text || '/%');

  -- public_profile_projection + profile: profile is deleted by the
  -- generic pass (delete_row); its projection has no FK (holds no user
  -- id, line 825) so it is removed here by the handle captured above,
  -- before profile's row (and therefore v_handle's source) is gone.
  IF v_handle IS NOT NULL THEN
    DELETE FROM app.public_profile_projection WHERE handle = v_handle;
  END IF;

  -- ==========================================================================
  -- P3d gate round 2, should-fix 3: "Rate-limit keys. During deletion,
  -- remove the user's own rate_limit_bucket keys, i.e. those prefixed with
  -- their uid, inside delete_my_data or me-delete. It's fine to keep the
  -- in-flight me-delete bucket so retries stay limited, if you document
  -- it. Or wire the purge. Say which you chose."
  --
  -- CHOSEN: inside delete_my_data (here), not me-delete's own handler —
  -- this is the same transaction as the deletion itself, so it is
  -- automatically atomic with (and rolls back together with) everything
  -- else in this function, and it fires for EVERY caller of this
  -- function, not only the me-delete Edge Function specifically.
  --
  -- Scope: every bucket_key `hitRateLimitForActor` (privileged.ts) ever
  -- writes for THIS user is prefixed `<uid>:...` (that function's own
  -- `scopedBucketKey = \`${actor.uid}:${bucketKey}\``) — so a LIKE-prefix
  -- match on `p_user_id::text || ':%'` covers every bucket this user has
  -- ever hit, across every endpoint, with no separate registry needed.
  --
  -- EXCLUDED, deliberately: the in-flight `me-delete:user` bucket itself
  -- (me-delete/index.ts's own `hitRateLimitForActor(actor, "me-delete:
  -- user", ...)`, scoped key `<uid>:me-delete:user`) — kept so a RETRY of
  -- THIS SAME deletion call (delete-handler.ts's own doc: the one
  -- legitimate reason to call this endpoint again in a short window,
  -- e.g. after a partial failure) stays rate-limited exactly the way a
  -- first attempt already is, rather than becoming unbounded the moment
  -- one successful run has purged its own counter. Every OTHER bucket —
  -- evidence submission, redemption, check-in, etc. — is purged: those
  -- limits exist to bound abuse by a live account, and this account no
  -- longer has personal data to abuse anything with.
  --
  -- No new RLS policy needed: private_definer already holds an unscoped
  -- DELETE policy on this table (`pd_rate_limit_purge`, 0016), the SAME
  -- one `private.purge_rate_limit_buckets`'s own nightly sweep already
  -- uses — its own `_r` companion (`pd_rate_limit_purge_r`) already
  -- exists too.
  DELETE FROM private.rate_limit_bucket
  WHERE bucket_key LIKE p_user_id::text || ':%'
    AND bucket_key <> p_user_id::text || ':me-delete:user';

  -- 0039 (edge role PR4a): the account's email-OTP link proofs, as the caller who proved or as the proven target. private.signin_email_proof
  -- is a PRIVATE table (so the generic pass above, which is driven by FKs in `app`, does not see it); private_definer reaches it through
  -- pd_signin_proof_delete, keyed on the same GUC this function set first. The FK to auth.users also cascades them away with the auth user.
  DELETE FROM private.signin_email_proof
  WHERE caller_user_id = p_user_id OR target_user_id = p_user_id;

  -- ==========================================================================
  -- P3d should-fix 2: fail-closed POST-CONDITION. Re-reads every table this
  -- function's own registry (private.pii_retention_policy) names, through
  -- private_definer's own SELECT visibility, and RAISES if ANY subject row
  -- still remains. See this file's own header for why `entitlement.user_id`
  -- is the one deliberate exclusion (redeemed/terminal rows are
  -- intentionally retained, O9/O10).
  --
  -- ⛔ CORRECTED COMMENT (P3d gate round 3, S4 — the PRIOR wording here
  -- overclaimed what this post-condition is trustworthy against). The
  -- prior comment said the "_r companion" check (tools/db/verify-
  -- function-inventory.mjs check 8 / 10_function_inventory.sql check 11)
  -- guarantees this post-condition can see every row it re-counts. That
  -- was TRUE only up to the granularity that check actually verified,
  -- which round 2's version did NOT match: it was TABLE-level ("does
  -- SOME SELECT policy exist for private_definer on this table at all"),
  -- while this post-condition re-counts PER COLUMN, under RLS, using the
  -- SAME session GUC every DELETE/UPDATE policy is scoped to. A table
  -- with TWO classified columns — one with a real, correctly-scoped
  -- SELECT companion, one with none — passed the OLD table-level check
  -- (the table has *a* SELECT policy), while this post-condition's
  -- re-count for the SECOND column would ALSO see zero rows for the
  -- SAME reason RLS hid the evidence from the ORIGINAL delete/update —
  -- reporting success while a row for that column genuinely survives,
  -- table-level check notwithstanding. The check below THIS comment was
  -- fixed for this round: check 8/11/12 are now COLUMN-level (every
  -- `pii_retention_policy` (table, column) pair requires its OWN SELECT
  -- policy whose USING clause matches the exact `nullif(current_setting
  -- (...))` form on THAT column, not merely "some policy on this
  -- table") — proven against a planted must-fail fixture
  -- (`app.zz_two`, two columns, a SELECT companion on only one) this
  -- round. THAT is what makes the post-condition below trustworthy now.
  -- ==========================================================================
  FOR v_post_pol IN
    SELECT table_name, column_name
    FROM private.pii_retention_policy
    WHERE schema_name = 'app'
      AND NOT (table_name = 'entitlement' AND column_name = 'user_id')
  LOOP
    EXECUTE format('SELECT count(*) FROM app.%I WHERE %I = $1', v_post_pol.table_name, v_post_pol.column_name)
      INTO v_remaining USING p_user_id;
    IF v_remaining > 0 THEN
      RAISE EXCEPTION
        'delete_my_data: post-condition failed — % row(s) still remain in app.%.% for user % after deletion (fail-closed; a missing/misscoped RLS policy can let a DELETE/UPDATE silently affect 0 rows while reporting success — see private.pii_retention_policy and the column-level "_r companion" check in tools/db/verify-function-inventory.mjs)',
        v_remaining, v_post_pol.table_name, v_post_pol.column_name, p_user_id;
    END IF;
  END LOOP;

  v_result := jsonb_build_object('user_id', p_user_id, 'deleted_at', now());
  -- Logged via a plain INSERT — this is a NEW audit row about the
  -- deletion event itself, not a mutation of an old one, so the
  -- insert-only trigger does not apply to it.
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (NULL, 'delete_my_data', 'app.profile', p_user_id::text, v_result);

  RETURN v_result;
END;
$function$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Registries
-- ============================================================================
-- 4a. private.definer_policy_allowlist (the four policies above) -- the 0035 pattern (temporary current-user policy).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0039 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('private', 'signin_email_proof', 'pd_signin_proof_select', 'SELECT', true, 'private.signin_*proof*: ONE proof (app.signin.proof_id), or the proofs an account being deleted is a party to (app.delete_my_data.target_user_id), or rows already an hour past expiry (the purge); exact nullif form of check 7. Also the visibility companion for UPDATE / DELETE ... WHERE'),
  ('private', 'signin_email_proof', 'pd_signin_proof_insert', 'INSERT', true, 'signin_record_email_proof: the one row whose id the definer set in app.signin.proof_id'),
  ('private', 'signin_email_proof', 'pd_signin_proof_update', 'UPDATE', true, 'signin_link_identity_with_proof_for_actor: marks the ONE redeemed proof consumed (column grant: consumed_at only)'),
  ('private', 'signin_email_proof', 'pd_signin_proof_delete', 'DELETE', true, 'delete_my_data (the account''s proofs as caller or target) and purge_signin_email_proofs (rows an hour past expiry); never a live proof of another account');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN ('pd_signin_proof_select', 'pd_signin_proof_insert', 'pd_signin_proof_update', 'pd_signin_proof_delete');
DROP POLICY current_user_seed_definer_policy_allowlist_0039 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- 4b. PII registries: the proof holds two user ids (and two hashes). Retention: deleted with the account (delete_my_data above) and
-- purged an hour past expiry; export: excluded (it is a credential-adjacent artefact of a login flow, not the subject's own data).
-- The retention rows are for a PRIVATE table, so delete_my_data's generic pass (app only) does not drive them; they are what check 12
-- and the registry-driven tests read, and the delete is explicit in the function body.
GRANT INSERT ON private.pii_retention_policy TO CURRENT_USER;
CREATE POLICY current_user_seed_pii_retention_policy_0039 ON private.pii_retention_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('private', 'signin_email_proof', 'caller_user_id', 'delete_row', 'proof of a mailbox the caller proved (0039): deleted with the caller''s account by an explicit statement in delete_my_data, deleted by FK cascade with the auth user, and purged an hour after its (<= 5 minute) expiry'),
  ('private', 'signin_email_proof', 'target_user_id', 'delete_row', 'same table, the proven account: same deletion paths as caller_user_id');
DROP POLICY current_user_seed_pii_retention_policy_0039 ON private.pii_retention_policy;
REVOKE INSERT ON private.pii_retention_policy FROM CURRENT_USER;

CREATE POLICY current_user_seed_pii_export_policy_0039 ON private.pii_export_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_export_policy (schema_name, table_name, action, reason) VALUES
  ('private', 'signin_email_proof', 'exclude', 'a short-lived (<= 5 minute) proof artefact of a login flow: two user ids and two hashes, no address, no provider subject; not the subject''s own data and not a record that outlives the flow (0039)');
DROP POLICY current_user_seed_pii_export_policy_0039 ON private.pii_export_policy;

-- 4c. private.function_inventory (the 0017 INSERT policy is still in place)
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('private', 'signin_record_email_proof', 'p_caller_user_id uuid, p_target_user_id uuid, p_email_hash text, p_provider text, p_sub_hash text', false, false, false, false, true, '0039: edge_system ONLY; mints the single-use 5-minute proof that the caller proved the TARGET account''s mailbox; refuses inside an actor-bound transaction, unless the address hashes to the target''s auth.users.email and the target signed in within 60 s (GoTrue''s last_sign_in_at); the only writer of private.signin_email_proof'),
  ('private', 'signin_link_identity_with_proof_for_actor', 'p_proof_id uuid, p_provider text, p_provider_sub text, p_email text, p_email_verified boolean, p_is_private_relay boolean, p_ciphertext bytea, p_dek_wrapped bytea, p_kek_id text', false, false, false, true, false, '0039: edge_actor only (kind = user binding); redeems a proof atomically and links the identity and stores its token for the PROOF''s target account, never actor_uid()'),
  ('private', 'purge_signin_email_proofs', '', false, false, true, false, true, '0039: delete proofs an hour past their expiry; system work (service_role, edge_system)');
