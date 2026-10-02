-- 0035_signin_providers.sql
-- O12 sign-in providers, server side (build plan §3.4 Auth row, §4.4 `signin_provider_token`, §4.8, §7.8, P4 AT 17-19).
-- Migrations 0033 and 0034 are reserved for other builders; 0001-0032 are untouched.
--
-- WHAT THIS ADDS
--   1. private.signin_revocation_queue  the DURABLE queue behind "a revocation that fails is retried for 72 h and
--      logged, and never blocks the deletion" (§7.8, Apple 5.1.1(v)). A row carries the SAME envelope-encrypted
--      refresh token as app.signin_provider_token (ciphertext + wrapped DEK + kek id, copied, never decrypted in the
--      database) and NO column that names a user, so it survives the account deletion that removes the grant row
--      without keeping a personal row (see "REGISTRY CLASSIFICATION" below).
--   2. The definers the me-signin-methods / me-delete Edge code calls, each in two lanes, the way delete_my_data is:
--        * a CORE function taking the user id (service_role; the lane the Edge code runs on today), and
--        * a `_for_actor` wrapper taking NO user id (edge_actor; the bound kind = 'user' actor's uid), for the
--          NOBYPASSRLS flip (docs/security/edge-role-design.md, PR2-PR4). The core is unchanged between lanes.
--      Plus private.get_signin_token_kek (the Vault-held KEK, §4.8), the OTP-proof failure counter (§4.7 item 8) and
--      the queue's claim / complete / purge (service_role and edge_system: they are system work, not an actor's).
--   3. Policies for private_definer on app.signin_provider_token, scoped to ONE user by a transaction-local GUC
--      (`app.signin.target_user_id`, the exact check-#7 form `nullif(current_setting(.., true), '')` and compared as
--      TEXT, so a leftover '' or a non-uuid value on a reused pooled connection raises nothing and admits nothing).
--
-- WHAT THIS DOES NOT ADD (and why)
--   * No edge_actor / edge_system policy and no edge grant on any table. Every edge path to these tables is a
--     definer (the P3f / PR1b design: edge_actor has no write on a credential table), so private.edge_policy_allowlist
--     (check 10) is unchanged and edge_actor still sees only (user_id, provider) of signin_provider_token (0031).
--   * Nothing exports the grant: 0022's pii_export_policy keeps `signin_provider_token` = exclude.
--   * No change to private.delete_my_data. The Edge code enqueues the revocation (this file) in its OWN transaction
--     BEFORE calling it, then revokes at the provider, THEN deletes: the stored token is gone from
--     app.signin_provider_token only after the provider has been told (or the retry row exists).
--
-- REGISTRY CLASSIFICATION (build plan: every new table needs one)
--   private.pii_retention_policy is DERIVED from FKs to auth.users (0014); private.pii_export_policy classifies the
--   tables it names. signin_revocation_queue has NO column and NO FK that names a user (the same position the P3f
--   install-link tombstone takes, 15_rewards_activation.sql): it holds a vendor-side credential, not a person. So there is
--   nothing for either registry to classify, and the pgTAP file proves that stays true (no FK to auth.users, no user-id
--   column). The only registries that apply are private.definer_policy_allowlist (its four private_definer policies)
--   and private.function_inventory (every function below), both filled in at the end of this file.
--
-- [unverified] on a real Supabase project (verify on a branch before the first deploy; the harness shim reproduces the
-- shape only):
--   (a) `GRANT ... ON auth.identities TO private_definer` by the project's own `postgres` role, and that
--       auth.identities carries no RLS that would hide its rows from a non-owner definer (the same class of caveat
--       0018 records for Vault);
--   (b) GoTrue's auth.identities columns (provider_id, identity_data, the generated email, ON DELETE CASCADE from
--       auth.users) and that a row INSERTed here is accepted by GoTrue as a real identity. Supabase's supported
--       surface for linking an id-token identity SERVER-side is not known to this build; if the P4 spike finds one
--       (manual linking via the Auth API), swap the link/unlink definers for it: the Edge code reaches them only through
--       `SigninRepo` (supabase/functions/_shared/signin/types.ts);
--   (c) that Vault accepts secrets named `siwa_token_kek_<id>` (the KEK, one 32-byte key, base64) and that
--       vault.decrypted_secrets exposes `created_at` (0029 already relies on that).
--
-- OPS RULE (the same as the pseudonym keys, docs/security/p3-money-path-requirements.md): never delete a Vault
-- `siwa_token_kek_*` secret while any app.signin_provider_token or pending private.signin_revocation_queue row
-- still names its id in kek_id. Retire a KEK only after re-wrapping those rows; there is no re-wrap job yet (a live
-- follow-up), so until there is one a KEK is never retired.

-- ============================================================================
-- 1. What private_definer needs on tables it does not yet touch
-- ============================================================================
-- auth.identities: column-level (the generated `email` column is neither selectable-needed nor insertable). DELETE has
-- no column form, so it is the whole-table privilege; the definers below only ever delete the one (user, provider) row.
GRANT SELECT (user_id, provider, provider_id, identity_data, created_at) ON auth.identities TO private_definer;
GRANT INSERT (provider_id, user_id, identity_data, provider, last_sign_in_at) ON auth.identities TO private_definer;
GRANT DELETE ON auth.identities TO private_definer;
-- A GRANT the grantor may not make (no GRANT OPTION on the table, a role that does not own it) does NOT fail: PostgreSQL
-- raises a WARNING ("no privileges were granted") and carries on. So the grants above are PROVED here, privilege by privilege,
-- and the migration stops if any did not take. Without this a project that refuses the grant would apply 0035 cleanly and fail
-- later, at run time, on the first link. (security gate F8)
DO $assert_identities_grants$
DECLARE
  v_col text;
BEGIN
  FOREACH v_col IN ARRAY ARRAY['user_id', 'provider', 'provider_id', 'identity_data', 'created_at'] LOOP
    IF NOT has_column_privilege('private_definer', 'auth.identities', v_col, 'SELECT') THEN
      RAISE EXCEPTION '0035: the GRANT SELECT (%) ON auth.identities TO private_definer did not take effect (a refused grant only warns); the sign-in definers cannot work without it', v_col;
    END IF;
  END LOOP;
  FOREACH v_col IN ARRAY ARRAY['provider_id', 'user_id', 'identity_data', 'provider', 'last_sign_in_at'] LOOP
    IF NOT has_column_privilege('private_definer', 'auth.identities', v_col, 'INSERT') THEN
      RAISE EXCEPTION '0035: the GRANT INSERT (%) ON auth.identities TO private_definer did not take effect (a refused grant only warns); the sign-in definers cannot work without it', v_col;
    END IF;
  END LOOP;
  IF NOT has_table_privilege('private_definer', 'auth.identities', 'DELETE') THEN
    RAISE EXCEPTION '0035: the GRANT DELETE ON auth.identities TO private_definer did not take effect (a refused grant only warns); signin_unlink_identity cannot work without it';
  END IF;
END
$assert_identities_grants$;

-- app.signin_provider_token: 0016 gave private_definer SELECT and DELETE (delete_my_data's generic pass, GUC-scoped to
-- app.delete_my_data.target_user_id). The sign-in definers also INSERT and UPDATE it, under their own GUC window.
GRANT INSERT, UPDATE ON app.signin_provider_token TO private_definer;
CREATE POLICY pd_signin_token_select ON app.signin_provider_token
  FOR SELECT TO private_definer
  USING (user_id::text = nullif(current_setting('app.signin.target_user_id', true), ''));
CREATE POLICY pd_signin_token_insert ON app.signin_provider_token
  FOR INSERT TO private_definer
  WITH CHECK (user_id::text = nullif(current_setting('app.signin.target_user_id', true), ''));
CREATE POLICY pd_signin_token_update ON app.signin_provider_token
  FOR UPDATE TO private_definer
  USING (user_id::text = nullif(current_setting('app.signin.target_user_id', true), ''))
  WITH CHECK (user_id::text = nullif(current_setting('app.signin.target_user_id', true), ''));
CREATE POLICY pd_signin_token_delete ON app.signin_provider_token
  FOR DELETE TO private_definer
  USING (user_id::text = nullif(current_setting('app.signin.target_user_id', true), ''));

-- ============================================================================
-- 2. private.signin_revocation_queue
-- ============================================================================
CREATE TABLE private.signin_revocation_queue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL CHECK (provider IN ('apple', 'google')),
  -- why the row exists: the account is being deleted, the method was unlinked, or a re-capture replaced the stored token
  -- (the superseded refresh token is still valid at the provider until revoked).
  source text NOT NULL CHECK (source IN ('account_delete', 'unlink', 'replaced')),
  -- md5 of the ciphertext: makes enqueueing idempotent (a retried DELETE /v1/me re-reads the same, still-present grant row
  -- and must not create a second queue row). Not reversible to the token; the ciphertext carries a random IV.
  token_fingerprint text NOT NULL,
  refresh_token_ciphertext bytea,
  dek_wrapped bytea,
  kek_id text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'revoked', 'expired')),
  attempts int NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  -- §7.8: "retried for 72 h". After this the row is `expired` (still unrevoked at the provider; logged) and its
  -- credential material is wiped.
  expires_at timestamptz NOT NULL DEFAULT now() + interval '72 hours',
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_attempt_at timestamptz,
  -- a short machine code only, never provider response text: it could echo a token.
  last_error text CHECK (last_error IS NULL OR last_error ~ '^[a-z0-9_:.-]{1,64}$'),
  completed_at timestamptz,
  -- a pending row carries the whole envelope; a finished row carries none of it (no credential outlives its purpose).
  CONSTRAINT signin_revocation_queue_material CHECK (
    (status = 'pending' AND refresh_token_ciphertext IS NOT NULL AND dek_wrapped IS NOT NULL AND kek_id IS NOT NULL)
    OR (status <> 'pending' AND refresh_token_ciphertext IS NULL AND dek_wrapped IS NULL AND kek_id IS NULL)
  )
);
CREATE UNIQUE INDEX signin_revocation_queue_fingerprint_uidx ON private.signin_revocation_queue (provider, token_fingerprint);
CREATE INDEX signin_revocation_queue_due_idx ON private.signin_revocation_queue (next_attempt_at) WHERE status = 'pending';
COMMENT ON TABLE private.signin_revocation_queue IS
  '0035. Durable retry queue for revoking an Apple / Google sign-in grant at the provider (build plan §7.8, Apple 5.1.1(v)). Holds the envelope-encrypted refresh token copied from app.signin_provider_token and NO user id: it outlives the account deletion that removes the grant row without being a personal row. Written and read only by the private.signin_* definers; no role but private_definer has any privilege on it.';

ALTER TABLE private.signin_revocation_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.signin_revocation_queue FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON private.signin_revocation_queue TO private_definer;
-- USING (true): the table carries no user data and the definers below are the whole scope (the same position as
-- pd_pseudonym_key_registry_*, 0018). UPDATE and DELETE need SELECT-level visibility, so the SELECT policy covers them.
CREATE POLICY pd_signin_queue_select ON private.signin_revocation_queue FOR SELECT TO private_definer USING (true);
CREATE POLICY pd_signin_queue_insert ON private.signin_revocation_queue FOR INSERT TO private_definer WITH CHECK (true);
CREATE POLICY pd_signin_queue_update ON private.signin_revocation_queue FOR UPDATE TO private_definer USING (true) WITH CHECK (true);
CREATE POLICY pd_signin_queue_delete ON private.signin_revocation_queue FOR DELETE TO private_definer USING (true);

-- ============================================================================
-- 3. The definer functions (ownership bracket: 0020 / 0022 / 0030)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. THE bound-actor helper for the `_for_actor` wrappers: the uid of a kind = 'user' binding in THIS transaction, else
-- an exception. A system delegate never touches sign-in methods. No role is granted EXECUTE; only the wrappers call it.
CREATE FUNCTION private.signin_bound_user(p_who text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION '%: no actor is bound in this transaction', p_who USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION '%: a system delegate may not manage sign-in methods', p_who USING ERRCODE = '42501';
  END IF;
  RETURN v_uid;
END;
$$;

-- 3b. The Vault-held KEK (§4.8: "a per-row DEK wrapped by a KEK ... otherwise Vault"). One 32-byte key per secret named
-- `siwa_token_kek_<kek_id>`, base64. NULL kek_id = the NEWEST one (by created_at, then name), used to wrap a new DEK;
-- a named kek_id is used to unwrap a stored one. The Edge runtime does the AES-GCM work (the plaintext token and the
-- DEK never reach the database, so they never reach its parameter logging); only the KEK crosses here, as a function
-- RESULT, never as a parameter or in a message. Honest limit (R6, edge-role-design.md): any runtime allowed to call this
-- can read the KEK; that is the §4.8 "decrypted only inside connector functions" boundary, not a stronger one.
CREATE FUNCTION private.get_signin_token_kek(p_kek_id text)
RETURNS TABLE (o_kek_id text, o_kek_b64 text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_name text;
  v_secret text;
BEGIN
  IF p_kek_id IS NOT NULL THEN
    IF p_kek_id !~ '^[a-z0-9][a-z0-9_-]{0,31}$' THEN
      RAISE EXCEPTION 'get_signin_token_kek: malformed kek id' USING ERRCODE = '22023';
    END IF;
    SELECT s.name, s.decrypted_secret INTO v_name, v_secret
    FROM vault.decrypted_secrets s WHERE s.name = 'siwa_token_kek_' || p_kek_id;
  ELSE
    SELECT s.name, s.decrypted_secret INTO v_name, v_secret
    FROM vault.decrypted_secrets s
    WHERE s.name LIKE 'siwa\_token\_kek\_%' AND s.name ~ '^siwa_token_kek_[a-z0-9][a-z0-9_-]{0,31}$'
    ORDER BY s.created_at DESC, s.name DESC LIMIT 1;
  END IF;
  IF v_name IS NULL THEN
    RAISE EXCEPTION 'get_signin_token_kek: no such key in Vault' USING ERRCODE = 'P0002';
  END IF;
  -- exactly one 32-byte AES-256 key in standard base64 (44 characters, one pad). Never echoed.
  IF v_secret IS NULL OR v_secret !~ '^[A-Za-z0-9+/]{43}=$' THEN
    RAISE EXCEPTION 'get_signin_token_kek: the Vault secret is not a base64 32-byte key' USING ERRCODE = '22023';
  END IF;
  o_kek_id := substr(v_name, length('siwa_token_kek_') + 1);
  o_kek_b64 := v_secret;
  RETURN NEXT;
END;
$$;

-- 3c. Email lookup for the "one account per verified email" rule (§3.4 rule 1). Returns only an id. Cross-user by design.
-- Deterministic (ORDER BY) even though GoTrue keeps lower(email) unique. EXECUTE: service_role only. An edge_actor reaches it
-- through signin_find_account_by_email_for_actor (3l), which requires a kind = 'user' binding (security gate F7).
CREATE FUNCTION private.signin_find_account_by_email(p_email text)
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  IF p_email IS NULL OR btrim(p_email) = '' OR length(p_email) > 320 THEN
    RETURN NULL;
  END IF;
  SELECT u.id INTO v_uid FROM auth.users u WHERE lower(u.email) = lower(btrim(p_email)) ORDER BY u.id LIMIT 1;
  RETURN v_uid;
END;
$$;

-- 3d. The enqueue core (no EXECUTE for anyone: the callers below set the GUC window first). Copies the grant row(s) into
-- the queue (all of the user's, or one provider's) and returns the ids of the PENDING rows that now cover them. Idempotent
-- on (provider, token_fingerprint): a second call finds the same pending row.
CREATE FUNCTION private.signin_enqueue_internal(p_user_id uuid, p_provider text, p_source text)
RETURNS TABLE (o_queue_id uuid, o_provider text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_source IS NULL OR p_source NOT IN ('account_delete', 'unlink', 'replaced') THEN
    RAISE EXCEPTION 'signin_enqueue: unknown source' USING ERRCODE = '22023';
  END IF;
  INSERT INTO private.signin_revocation_queue (provider, source, token_fingerprint, refresh_token_ciphertext, dek_wrapped, kek_id)
  SELECT t.provider, p_source, md5(t.refresh_token_ciphertext), t.refresh_token_ciphertext, t.dek_wrapped, t.kek_id
  FROM app.signin_provider_token t
  WHERE t.user_id = p_user_id AND (p_provider IS NULL OR t.provider = p_provider)
  ON CONFLICT (provider, token_fingerprint) DO NOTHING;
  RETURN QUERY
  SELECT q.id, q.provider
  FROM private.signin_revocation_queue q
  JOIN app.signin_provider_token t
    ON t.user_id = p_user_id AND t.provider = q.provider AND md5(t.refresh_token_ciphertext) = q.token_fingerprint
  WHERE q.status = 'pending' AND (p_provider IS NULL OR q.provider = p_provider);
END;
$$;

-- 3e. List the user's sign-in methods (identities in Supabase Auth). The subject is returned to the Edge code (it needs it
-- to compare with a verified token's `sub`); the Edge code never sends it to a client.
CREATE FUNCTION private.signin_methods(p_user_id uuid)
RETURNS TABLE (o_provider text, o_subject text, o_email text, o_is_private_relay boolean, o_linked_at timestamptz, o_has_token boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'signin_methods: the user id is required' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.signin.target_user_id', p_user_id::text, true);
  RETURN QUERY
  SELECT i.provider, i.provider_id, lower(i.identity_data ->> 'email'),
         coalesce((i.identity_data ->> 'is_private_email') = 'true', false)
           OR coalesce(lower(i.identity_data ->> 'email') LIKE '%@privaterelay.appleid.com', false),
         i.created_at,
         EXISTS (SELECT 1 FROM app.signin_provider_token t WHERE t.user_id = p_user_id AND t.provider = i.provider)
  FROM auth.identities i
  WHERE i.user_id = p_user_id
  ORDER BY i.created_at, i.provider;
  PERFORM set_config('app.signin.target_user_id', '', true);
END;
$$;

-- 3f. Link a provider identity to an account. Returns true if a row was created, false if THIS user already holds that
-- exact identity (idempotent: the "capture" re-run). Raises 23505 when the identity belongs to ANOTHER account (never
-- moved: unique (provider, provider_id) is also GoTrue's own rule) or when this account already holds a DIFFERENT identity
-- of the same provider (one Apple and one Google per account). Only apple / google here: an email identity is created by
-- GoTrue's own OTP sign-in, never by this function. Serialised per account by an advisory lock so link / unlink / the
-- last-method count never interleave.
CREATE FUNCTION private.signin_link_identity(
  p_user_id uuid, p_provider text, p_subject text, p_email text, p_email_verified boolean, p_is_private_relay boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_owner uuid;
BEGIN
  IF p_user_id IS NULL OR p_provider IS NULL OR p_provider NOT IN ('apple', 'google')
     OR p_subject IS NULL OR btrim(p_subject) = '' OR length(p_subject) > 255 THEN
    RAISE EXCEPTION 'signin_link_identity: invalid user, provider or subject' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = p_user_id) THEN
    RAISE EXCEPTION 'signin_link_identity: no such user' USING ERRCODE = 'P0002';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('signin:' || p_user_id::text, 0));
  SELECT i.user_id INTO v_owner FROM auth.identities i WHERE i.provider = p_provider AND i.provider_id = p_subject;
  IF FOUND THEN
    IF v_owner = p_user_id THEN
      RETURN false;
    END IF;
    RAISE EXCEPTION 'identity_conflict: that identity belongs to another account' USING ERRCODE = '23505';
  END IF;
  IF EXISTS (SELECT 1 FROM auth.identities i WHERE i.user_id = p_user_id AND i.provider = p_provider) THEN
    RAISE EXCEPTION 'provider_already_linked: this account already has a different % identity', p_provider USING ERRCODE = '23505';
  END IF;
  INSERT INTO auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at)
  VALUES (
    p_subject, p_user_id,
    jsonb_strip_nulls(jsonb_build_object(
      'sub', p_subject,
      'provider_id', p_subject,
      'iss', CASE p_provider WHEN 'apple' THEN 'https://appleid.apple.com' ELSE 'https://accounts.google.com' END,
      'email', nullif(lower(btrim(coalesce(p_email, ''))), ''),
      'email_verified', coalesce(p_email_verified, false),
      'is_private_email', coalesce(p_is_private_relay, false)
    )),
    p_provider, now()
  );
  RETURN true;
END;
$$;

-- 3g. Store (or replace) the envelope-encrypted refresh token for a LINKED identity. The ciphertext, the wrapped DEK and the
-- kek id are opaque here: this function never decrypts. Replacing a different token queues the superseded one for
-- revocation (its grant stays valid at the provider until revoked).
CREATE FUNCTION private.signin_store_token(
  p_user_id uuid, p_provider text, p_ciphertext bytea, p_dek_wrapped bytea, p_kek_id text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL OR p_provider IS NULL OR p_provider NOT IN ('apple', 'google')
     OR p_ciphertext IS NULL OR octet_length(p_ciphertext) NOT BETWEEN 29 AND 8192
     OR p_dek_wrapped IS NULL OR octet_length(p_dek_wrapped) NOT BETWEEN 61 AND 256
     OR p_kek_id IS NULL OR p_kek_id !~ '^[a-z0-9][a-z0-9_-]{0,31}$' THEN
    RAISE EXCEPTION 'signin_store_token: invalid arguments' USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('signin:' || p_user_id::text, 0));
  PERFORM set_config('app.signin.target_user_id', p_user_id::text, true);
  IF NOT EXISTS (SELECT 1 FROM auth.identities i WHERE i.user_id = p_user_id AND i.provider = p_provider) THEN
    PERFORM set_config('app.signin.target_user_id', '', true);
    RAISE EXCEPTION 'signin_store_token: this account has no % identity to attach a token to', p_provider USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (SELECT 1 FROM app.signin_provider_token t
             WHERE t.user_id = p_user_id AND t.provider = p_provider AND md5(t.refresh_token_ciphertext) <> md5(p_ciphertext)) THEN
    PERFORM 1 FROM private.signin_enqueue_internal(p_user_id, p_provider, 'replaced');
  END IF;
  INSERT INTO app.signin_provider_token (user_id, provider, refresh_token_ciphertext, dek_wrapped, kek_id)
  VALUES (p_user_id, p_provider, p_ciphertext, p_dek_wrapped, p_kek_id)
  ON CONFLICT (user_id, provider) DO UPDATE
    SET refresh_token_ciphertext = EXCLUDED.refresh_token_ciphertext,
        dek_wrapped = EXCLUDED.dek_wrapped,
        kek_id = EXCLUDED.kek_id,
        created_at = now();
  PERFORM set_config('app.signin.target_user_id', '', true);
END;
$$;

-- ⚠ Unlinking 'email' removes only the auth.identities row. It is NOT claimed to end email-OTP access: GoTrue's OTP sign-in probably
-- looks the user up by auth.users.email, not by an identity row, so the address may still sign in after the unlink. [unverified: P4
-- spike item, docs/security/p3-money-path-requirements.md O12 "F2"]. Nothing in the API or UI may say "unlinking email revokes email access".
-- 3h. Unlink a method, only while another remains (§3.4 rule 4). One transaction, one advisory lock: the count of the
-- account's distinct providers, the queueing of the provider grant, the grant row's deletion and the identity's deletion
-- cannot interleave with a concurrent link or unlink of the same account. Raises P0002 (not linked) and 55000 (the last
-- method: the Edge code answers 422). Returns the queue id of the revocation it created (none for an email identity or a
-- method that never had a token).
CREATE FUNCTION private.signin_unlink_identity(p_user_id uuid, p_provider text)
RETURNS TABLE (o_queue_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_methods int;
BEGIN
  IF p_user_id IS NULL OR p_provider IS NULL OR p_provider NOT IN ('email', 'apple', 'google') THEN
    RAISE EXCEPTION 'signin_unlink_identity: invalid user or provider' USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('signin:' || p_user_id::text, 0));
  PERFORM set_config('app.signin.target_user_id', p_user_id::text, true);
  IF NOT EXISTS (SELECT 1 FROM auth.identities i WHERE i.user_id = p_user_id AND i.provider = p_provider) THEN
    PERFORM set_config('app.signin.target_user_id', '', true);
    RAISE EXCEPTION 'signin_unlink_identity: that method is not linked to this account' USING ERRCODE = 'P0002';
  END IF;
  SELECT count(DISTINCT i.provider) INTO v_methods FROM auth.identities i WHERE i.user_id = p_user_id;
  IF v_methods <= 1 THEN
    PERFORM set_config('app.signin.target_user_id', '', true);
    RAISE EXCEPTION 'last_sign_in_method: the only remaining sign-in method cannot be unlinked' USING ERRCODE = '55000';
  END IF;
  RETURN QUERY SELECT e.o_queue_id FROM private.signin_enqueue_internal(p_user_id, p_provider, 'unlink') e;
  DELETE FROM app.signin_provider_token t WHERE t.user_id = p_user_id AND t.provider = p_provider;
  DELETE FROM auth.identities i WHERE i.user_id = p_user_id AND i.provider = p_provider;
  PERFORM set_config('app.signin.target_user_id', '', true);
END;
$$;

-- 3i. DELETE /v1/me: queue every grant of the account for revocation BEFORE private.delete_my_data removes the rows.
CREATE FUNCTION private.signin_enqueue_revocations(p_user_id uuid)
RETURNS TABLE (o_queue_id uuid, o_provider text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'signin_enqueue_revocations: the user id is required' USING ERRCODE = '22023';
  END IF;
  -- The same per-account lock link / store_token / unlink take. Called inside the DELETE transaction (delete-orchestrator.ts step 3)
  -- it is held until that transaction commits, so a link racing the deletion either lands before this call (and is queued by it) or
  -- waits until the grant rows are gone: no grant can be stored between "queued" and "deleted" (security gate F6).
  PERFORM pg_advisory_xact_lock(hashtextextended('signin:' || p_user_id::text, 0));
  PERFORM set_config('app.signin.target_user_id', p_user_id::text, true);
  RETURN QUERY SELECT e.o_queue_id, e.o_provider FROM private.signin_enqueue_internal(p_user_id, NULL, 'account_delete') e;
  PERFORM set_config('app.signin.target_user_id', '', true);
END;
$$;

-- 3j. The queue's system operations. claim: expires what ran out its 72 h, then leases up to p_limit due rows (optionally
-- only the named ones) by pushing their next_attempt_at, so two workers never revoke the same row at once. The expiry is
-- logged (RAISE LOG: queue id and provider only, no user, no token).
CREATE FUNCTION private.claim_signin_revocations(p_ids uuid[], p_limit int, p_lease_seconds int)
RETURNS TABLE (o_id uuid, o_provider text, o_ciphertext bytea, o_dek_wrapped bytea, o_kek_id text, o_attempts int, o_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_gone record;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 OR p_lease_seconds IS NULL OR p_lease_seconds < 30 OR p_lease_seconds > 900 THEN
    RAISE EXCEPTION 'claim_signin_revocations: invalid limit or lease' USING ERRCODE = '22023';
  END IF;
  FOR v_gone IN
    UPDATE private.signin_revocation_queue q
    SET status = 'expired', refresh_token_ciphertext = NULL, dek_wrapped = NULL, kek_id = NULL,
        completed_at = now(), last_error = coalesce(q.last_error, 'expired_unrevoked')
    WHERE q.status = 'pending' AND q.expires_at <= now()
    RETURNING q.id AS gone_id, q.provider AS gone_provider, q.attempts AS gone_attempts
  LOOP
    RAISE LOG 'signin_revocation: gave up after 72h, grant NOT revoked at the provider (queue_id=%, provider=%, attempts=%)',
      v_gone.gone_id, v_gone.gone_provider, v_gone.gone_attempts;
  END LOOP;
  RETURN QUERY
  WITH due AS (
    SELECT q.id FROM private.signin_revocation_queue q
    WHERE q.status = 'pending' AND q.next_attempt_at <= now() AND (p_ids IS NULL OR q.id = ANY (p_ids))
    ORDER BY q.next_attempt_at, q.created_at
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  ), leased AS (
    UPDATE private.signin_revocation_queue q
    SET next_attempt_at = now() + make_interval(secs => p_lease_seconds)
    FROM due WHERE q.id = due.id
    RETURNING q.id, q.provider, q.refresh_token_ciphertext, q.dek_wrapped, q.kek_id, q.attempts, q.expires_at
  )
  SELECT l.id, l.provider, l.refresh_token_ciphertext, l.dek_wrapped, l.kek_id, l.attempts, l.expires_at FROM leased l;
END;
$$;

-- complete: 'revoked' wipes the credential material and closes the row; 'retry' records the attempt, the short error code
-- and the next attempt (30 s .. 6 h out). Idempotent on a row that already finished. Returns the row's resulting status.
CREATE FUNCTION private.complete_signin_revocation(p_id uuid, p_outcome text, p_error text, p_backoff_seconds int)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_status text;
  v_error text;
BEGIN
  IF p_outcome IS NULL OR p_outcome NOT IN ('revoked', 'retry') THEN
    RAISE EXCEPTION 'complete_signin_revocation: outcome must be revoked or retry' USING ERRCODE = '22023';
  END IF;
  v_error := CASE WHEN p_error ~ '^[a-z0-9_:.-]{1,64}$' THEN p_error ELSE 'unclassified' END;
  SELECT q.status INTO v_status FROM private.signin_revocation_queue q WHERE q.id = p_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'complete_signin_revocation: no such queue row' USING ERRCODE = 'P0002';
  END IF;
  IF v_status <> 'pending' THEN
    RETURN v_status;
  END IF;
  IF p_outcome = 'revoked' THEN
    UPDATE private.signin_revocation_queue q
    SET status = 'revoked', refresh_token_ciphertext = NULL, dek_wrapped = NULL, kek_id = NULL,
        attempts = q.attempts + 1, last_attempt_at = now(), last_error = NULL, completed_at = now()
    WHERE q.id = p_id;
    RETURN 'revoked';
  END IF;
  UPDATE private.signin_revocation_queue q
  SET attempts = q.attempts + 1, last_attempt_at = now(), last_error = v_error,
      next_attempt_at = now() + make_interval(secs => least(greatest(coalesce(p_backoff_seconds, 60), 30), 21600))
  WHERE q.id = p_id;
  RETURN 'pending';
END;
$$;

-- purge: finished rows (revoked / expired) older than p_older_than (1 .. 365 days). A pending row is never purged.
CREATE FUNCTION private.purge_signin_revocation_queue(p_older_than interval)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n int;
BEGIN
  IF p_older_than IS NULL OR p_older_than < interval '1 day' OR p_older_than > interval '365 days' THEN
    RAISE EXCEPTION 'purge_signin_revocation_queue: the age must be between 1 and 365 days' USING ERRCODE = '22023';
  END IF;
  DELETE FROM private.signin_revocation_queue q
  WHERE q.status <> 'pending' AND q.completed_at < now() - p_older_than;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END;
$$;

-- 3k. The OTP-proof failure counter (§4.7 item 8: "5 failed OTP proofs per target email per hour"). The bucket key is built
-- HERE from a sha256 hex of the lower-cased target email (the caller never names a bucket, and no email address is stored
-- in a bucket key). peek reads the current window without touching it; reserve / release take and give back one attempt. Fixed one-hour windows, the
-- same arithmetic as private.hit_rate_limit; purge_rate_limit_buckets removes old windows.
CREATE FUNCTION private.peek_signin_otp_failures(p_email_hash text)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_window_start timestamptz;
  v_count int;
BEGIN
  IF p_email_hash IS NULL OR p_email_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'peek_signin_otp_failures: the email hash must be 64 lowercase hex characters' USING ERRCODE = '22023';
  END IF;
  v_window_start := to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600);
  SELECT coalesce(sum(b.count), 0)::int INTO v_count
  FROM private.rate_limit_bucket b
  WHERE b.bucket_key = 'signin-otp-fail:' || p_email_hash AND b.window_start = v_window_start;
  RETURN v_count;
END;
$$;

-- reserve: the attempt is taken BEFORE the proof is verified, in ONE statement that both checks the cap and increments, so N parallel
-- proofs cannot all pass a peek and reach the verifier (the cap is no longer check-then-act; security gate F3). Returns the number
-- of attempts used in this window INCLUDING this one, or -1 when the cap (5) is already reached (nothing is incremented then).
-- ON CONFLICT ... DO UPDATE ... WHERE takes the row lock, so concurrent reservations serialise on it.
CREATE FUNCTION private.reserve_signin_otp_attempt(p_email_hash text)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_window_start timestamptz;
  v_count int;
BEGIN
  IF p_email_hash IS NULL OR p_email_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'reserve_signin_otp_attempt: the email hash must be 64 lowercase hex characters' USING ERRCODE = '22023';
  END IF;
  v_window_start := to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600);
  INSERT INTO private.rate_limit_bucket AS b (bucket_key, window_start, count)
  VALUES ('signin-otp-fail:' || p_email_hash, v_window_start, 1)
  ON CONFLICT (bucket_key, window_start)
  DO UPDATE SET count = b.count + 1 WHERE b.count < 5
  RETURNING b.count INTO v_count;
  RETURN coalesce(v_count, -1);
END;
$$;

-- release: undoes ONE reservation (a proof that SUCCEEDED, or that never reached a verdict because the transport failed, is not a
-- failure). Never below zero; a no-op when the window has rolled over.
CREATE FUNCTION private.release_signin_otp_attempt(p_email_hash text)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_window_start timestamptz;
  v_count int;
BEGIN
  IF p_email_hash IS NULL OR p_email_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'release_signin_otp_attempt: the email hash must be 64 lowercase hex characters' USING ERRCODE = '22023';
  END IF;
  v_window_start := to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600);
  UPDATE private.rate_limit_bucket b SET count = greatest(b.count - 1, 0)
  WHERE b.bucket_key = 'signin-otp-fail:' || p_email_hash AND b.window_start = v_window_start
  RETURNING b.count INTO v_count;
  RETURN coalesce(v_count, 0);
END;
$$;

-- 3l. The `_for_actor` wrappers (edge_actor): the same operations for the BOUND kind = 'user' actor, with no user argument.
-- signin_link_identity_for_actor links to the actor's OWN account only: the Edge code's OTP-proven link to ANOTHER account
-- (build plan §3.4 rule 2) is a service_role-lane operation and has no edge-lane definer on purpose (it would be an
-- "attach an identity to any account" primitive); PR2 must design that path before the flip (see the design doc).
CREATE FUNCTION private.signin_methods_for_actor()
RETURNS TABLE (o_provider text, o_subject text, o_email text, o_is_private_relay boolean, o_linked_at timestamptz, o_has_token boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RETURN QUERY SELECT m.o_provider, m.o_subject, m.o_email, m.o_is_private_relay, m.o_linked_at, m.o_has_token
  FROM private.signin_methods(private.signin_bound_user('signin_methods_for_actor')) m;
END;
$$;

CREATE FUNCTION private.signin_link_identity_for_actor(
  p_provider text, p_subject text, p_email text, p_email_verified boolean, p_is_private_relay boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RETURN private.signin_link_identity(private.signin_bound_user('signin_link_identity_for_actor'), p_provider, p_subject, p_email, p_email_verified, p_is_private_relay);
END;
$$;

CREATE FUNCTION private.signin_store_token_for_actor(p_provider text, p_ciphertext bytea, p_dek_wrapped bytea, p_kek_id text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.signin_store_token(private.signin_bound_user('signin_store_token_for_actor'), p_provider, p_ciphertext, p_dek_wrapped, p_kek_id);
END;
$$;

CREATE FUNCTION private.signin_unlink_identity_for_actor(p_provider text)
RETURNS TABLE (o_queue_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RETURN QUERY SELECT u.o_queue_id FROM private.signin_unlink_identity(private.signin_bound_user('signin_unlink_identity_for_actor'), p_provider) u;
END;
$$;

CREATE FUNCTION private.signin_enqueue_revocations_for_actor()
RETURNS TABLE (o_queue_id uuid, o_provider text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RETURN QUERY SELECT e.o_queue_id, e.o_provider FROM private.signin_enqueue_revocations(private.signin_bound_user('signin_enqueue_revocations_for_actor')) e;
END;
$$;

-- The email lookup for an edge_actor: refuses unless a kind = 'user' actor is bound in this transaction (an unbound actor, or a
-- system delegate, gets 42501 and no answer). Without this wrapper "does an account hold this email" would be answerable by any
-- edge_actor connection, bound or not (security gate F7). Same answer as the core: an id, or NULL.
CREATE FUNCTION private.signin_find_account_by_email_for_actor(p_email text)
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  PERFORM private.signin_bound_user('signin_find_account_by_email_for_actor');
  RETURN private.signin_find_account_by_email(p_email);
END;
$$;

-- 3m. EXECUTE grants. PUBLIC first (private_definer-created functions default to PUBLIC), then exactly the roles below.
REVOKE EXECUTE ON FUNCTION private.signin_bound_user(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.get_signin_token_kek(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_find_account_by_email(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_enqueue_internal(uuid, text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_methods(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_link_identity(uuid, text, text, text, boolean, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_store_token(uuid, text, bytea, bytea, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_unlink_identity(uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_enqueue_revocations(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.claim_signin_revocations(uuid[], int, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.complete_signin_revocation(uuid, text, text, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.purge_signin_revocation_queue(interval) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.peek_signin_otp_failures(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.reserve_signin_otp_attempt(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.release_signin_otp_attempt(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_find_account_by_email_for_actor(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_methods_for_actor() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_link_identity_for_actor(text, text, text, boolean, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_store_token_for_actor(text, bytea, bytea, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_unlink_identity_for_actor(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.signin_enqueue_revocations_for_actor() FROM PUBLIC;

-- service_role: the core lane the Edge code runs on today.
GRANT EXECUTE ON FUNCTION private.get_signin_token_kek(text) TO service_role, edge_actor, edge_system;
GRANT EXECUTE ON FUNCTION private.signin_find_account_by_email(text) TO service_role;
GRANT EXECUTE ON FUNCTION private.signin_methods(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION private.signin_link_identity(uuid, text, text, text, boolean, boolean) TO service_role;
GRANT EXECUTE ON FUNCTION private.signin_store_token(uuid, text, bytea, bytea, text) TO service_role;
GRANT EXECUTE ON FUNCTION private.signin_unlink_identity(uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION private.signin_enqueue_revocations(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION private.peek_signin_otp_failures(text) TO service_role, edge_actor;
GRANT EXECUTE ON FUNCTION private.reserve_signin_otp_attempt(text) TO service_role, edge_actor;
GRANT EXECUTE ON FUNCTION private.release_signin_otp_attempt(text) TO service_role, edge_actor;
-- the queue's system operations: service_role now, edge_system after the flip (they act on no particular user).
GRANT EXECUTE ON FUNCTION private.claim_signin_revocations(uuid[], int, int) TO service_role, edge_system;
GRANT EXECUTE ON FUNCTION private.complete_signin_revocation(uuid, text, text, int) TO service_role, edge_system;
GRANT EXECUTE ON FUNCTION private.purge_signin_revocation_queue(interval) TO service_role, edge_system;
-- edge_actor: the bound-actor wrappers only.
GRANT EXECUTE ON FUNCTION private.signin_methods_for_actor() TO edge_actor;
GRANT EXECUTE ON FUNCTION private.signin_link_identity_for_actor(text, text, text, boolean, boolean) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.signin_store_token_for_actor(text, bytea, bytea, text) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.signin_unlink_identity_for_actor(text) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.signin_enqueue_revocations_for_actor() TO edge_actor;
GRANT EXECUTE ON FUNCTION private.signin_find_account_by_email_for_actor(text) TO edge_actor;

COMMENT ON FUNCTION private.get_signin_token_kek(text) IS
  '0035. The Vault-held KEK for the envelope encryption of app.signin_provider_token / private.signin_revocation_queue (build plan §4.8): NULL = the newest `siwa_token_kek_<id>`, a kek id = that one. Returns the key as a function result only.';
COMMENT ON FUNCTION private.signin_unlink_identity(uuid, text) IS
  '0035. Unlinks one sign-in method only while another remains (55000 otherwise), queueing the provider-grant revocation first; one transaction under a per-account advisory lock.';
COMMENT ON FUNCTION private.signin_enqueue_revocations(uuid) IS
  '0035. DELETE /v1/me: copies every sign-in provider grant of the account into private.signin_revocation_queue BEFORE private.delete_my_data removes the rows. Idempotent.';
COMMENT ON FUNCTION private.signin_link_identity_for_actor(text, text, text, boolean, boolean) IS
  '0035. edge_actor only. Links to the BOUND actor''s own account only; the OTP-proven link to another account has no edge-lane definer on purpose.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Registries: private.definer_policy_allowlist and private.function_inventory
-- ============================================================================
-- No edge policy was added (see the header), so private.edge_policy_allowlist is untouched.
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0035 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('app', 'signin_provider_token', 'pd_signin_token_select', 'SELECT', true, 'private.signin_*: ONE user''s grant rows, GUC-scoped (app.signin.target_user_id, set and cleared inside the definer, compared as text; the exact nullif form of check 7)'),
  ('app', 'signin_provider_token', 'pd_signin_token_insert', 'INSERT', true, 'signin_store_token: the grant row of the one user named by the GUC window'),
  ('app', 'signin_provider_token', 'pd_signin_token_update', 'UPDATE', true, 'signin_store_token''s ON CONFLICT DO UPDATE (re-capture): the one user''s own row only'),
  ('app', 'signin_provider_token', 'pd_signin_token_delete', 'DELETE', true, 'signin_unlink_identity: the one user''s own row for the unlinked provider (delete_my_data keeps its own GUC-scoped delete policy, 0016)'),
  ('private', 'signin_revocation_queue', 'pd_signin_queue_select', 'SELECT', false, 'the signin_* queue definers; the table carries no user id (a vendor credential queue), so the definers are the whole scope; also the visibility companion for UPDATE / DELETE ... WHERE'),
  ('private', 'signin_revocation_queue', 'pd_signin_queue_insert', 'INSERT', false, 'signin_enqueue_internal: copies a grant row into the queue; idempotent on (provider, token_fingerprint)'),
  ('private', 'signin_revocation_queue', 'pd_signin_queue_update', 'UPDATE', false, 'claim_signin_revocations (lease, expiry) and complete_signin_revocation (revoked / retry)'),
  ('private', 'signin_revocation_queue', 'pd_signin_queue_delete', 'DELETE', false, 'purge_signin_revocation_queue: finished rows older than the caller''s age (1..365 days) only');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_signin_token_select', 'pd_signin_token_insert', 'pd_signin_token_update', 'pd_signin_token_delete',
    'pd_signin_queue_select', 'pd_signin_queue_insert', 'pd_signin_queue_update', 'pd_signin_queue_delete');
DROP POLICY current_user_seed_definer_policy_allowlist_0035 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('private', 'signin_bound_user', 'p_who text', false, false, false, false, false, '0035: the bound kind=user actor helper for the signin_*_for_actor wrappers; reachable only through them (no role is granted EXECUTE)'),
  ('private', 'signin_enqueue_internal', 'p_user_id uuid, p_provider text, p_source text', false, false, false, false, false, '0035: the queue-copy core; reachable only through signin_store_token / signin_unlink_identity / signin_enqueue_revocations (no role is granted EXECUTE)'),
  ('private', 'get_signin_token_kek', 'p_kek_id text', false, false, true, true, true, '0035: the Vault-held KEK (a function result only), for envelope encryption of the sign-in provider grants (build plan §4.8)'),
  ('private', 'signin_find_account_by_email', 'p_email text', false, false, true, false, false, '0035: id of the account holding an email (the one-account-per-verified-email rule, §3.4 rule 1); service_role lane, deterministic'),
  ('private', 'signin_methods', 'p_user_id uuid', false, false, true, false, false, '0035: a user''s sign-in methods (Supabase Auth identities), service_role lane'),
  ('private', 'signin_link_identity', 'p_user_id uuid, p_provider text, p_subject text, p_email text, p_email_verified boolean, p_is_private_relay boolean', false, false, true, false, false, '0035: link an apple/google identity; 23505 when the identity is another account''s or the provider is already linked; service_role lane'),
  ('private', 'signin_store_token', 'p_user_id uuid, p_provider text, p_ciphertext bytea, p_dek_wrapped bytea, p_kek_id text', false, false, true, false, false, '0035: store/replace the envelope-encrypted refresh token for a linked identity; service_role lane'),
  ('private', 'signin_unlink_identity', 'p_user_id uuid, p_provider text', false, false, true, false, false, '0035: unlink a method only while another remains (55000), queueing the provider revocation; service_role lane'),
  ('private', 'signin_enqueue_revocations', 'p_user_id uuid', false, false, true, false, false, '0035: DELETE /v1/me, queue every provider grant for revocation before the rows are deleted; service_role lane'),
  ('private', 'claim_signin_revocations', 'p_ids uuid[], p_limit integer, p_lease_seconds integer', false, false, true, false, true, '0035: expire the 72h-old, lease due revocation rows; system work (service_role now, edge_system after the flip)'),
  ('private', 'complete_signin_revocation', 'p_id uuid, p_outcome text, p_error text, p_backoff_seconds integer', false, false, true, false, true, '0035: record a revocation attempt (revoked / retry); system work'),
  ('private', 'purge_signin_revocation_queue', 'p_older_than interval', false, false, true, false, true, '0035: delete finished revocation rows older than 1..365 days; system work'),
  ('private', 'peek_signin_otp_failures', 'p_email_hash text', false, false, true, true, false, '0035: failed OTP proofs for one target email in the current hour (the bucket key is built in the database)'),
  ('private', 'reserve_signin_otp_attempt', 'p_email_hash text', false, false, true, true, false, '0035: take one OTP-proof attempt for a target email BEFORE verifying (atomic cap check + increment, -1 at the cap of 5 per hour)'),
  ('private', 'release_signin_otp_attempt', 'p_email_hash text', false, false, true, true, false, '0035: give back one reserved OTP-proof attempt (the proof succeeded or never reached a verdict)'),
  ('private', 'signin_methods_for_actor', '', false, false, false, true, false, '0035: edge_actor only; signin_methods for the BOUND kind=user actor (no uid argument)'),
  ('private', 'signin_link_identity_for_actor', 'p_provider text, p_subject text, p_email text, p_email_verified boolean, p_is_private_relay boolean', false, false, false, true, false, '0035: edge_actor only; links to the bound actor''s OWN account only'),
  ('private', 'signin_store_token_for_actor', 'p_provider text, p_ciphertext bytea, p_dek_wrapped bytea, p_kek_id text', false, false, false, true, false, '0035: edge_actor only; signin_store_token for the bound actor'),
  ('private', 'signin_unlink_identity_for_actor', 'p_provider text', false, false, false, true, false, '0035: edge_actor only; signin_unlink_identity for the bound actor'),
  ('private', 'signin_enqueue_revocations_for_actor', '', false, false, false, true, false, '0035: edge_actor only; signin_enqueue_revocations for the bound actor'),
  ('private', 'signin_find_account_by_email_for_actor', 'p_email text', false, false, false, true, false, '0035: edge_actor only; signin_find_account_by_email, refused unless a kind=user actor is bound (F7)');
