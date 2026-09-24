-- 0018_pseudonym_vault.sql
-- M1 (post-P3a re-gate): move the pseudonym HMAC key off a GUC and onto
-- Supabase Vault (`vault.decrypted_secrets` — real in production, shimmed
-- locally by supabase/tests/shim.sql; see that file's own comment for the
-- schema source and what the shim does/doesn't reproduce).

-- ============================================================================
-- 1. private_definer's grant on the vault — narrow, column-level, and the
--    ONLY grant anyone but postgres/migration_owner ever gets on it (the
--    shim deliberately grants nothing to anon/authenticated/PUBLIC).
-- ============================================================================
GRANT USAGE ON SCHEMA vault TO private_definer;
GRANT SELECT (id, name, decrypted_secret) ON vault.decrypted_secrets TO private_definer;

-- ============================================================================
-- 2. pseudonym_key_id columns "beside each pseudonym" — which active vault
--    key actually computed the value stored next to it. private.
--    delete_my_data (0015) does not need this to MATCH a row (it tries
--    every active key, which is correct regardless of rotation state and
--    needs no per-row bookkeeping to stay correct) — it is audit/
--    provenance metadata: given a pseudonym value, which key produced it,
--    without recomputing against every active key to find out.
-- ============================================================================
ALTER TABLE app.attestation ADD COLUMN player_pseudonym_key_id uuid REFERENCES vault.secrets (id);
ALTER TABLE app.attestation ADD COLUMN staff_pseudonym_key_id uuid REFERENCES vault.secrets (id);
ALTER TABLE app.attestation_shift_log ADD COLUMN player_pseudonym_key_id uuid REFERENCES vault.secrets (id);

COMMENT ON COLUMN app.attestation.player_pseudonym_key_id IS
  'Which vault.secrets row (name LIKE ''pseudonym_key%'') computed player_pseudonym, at write time. Written by the (out-of-scope-this-stage) attest Edge Function alongside player_pseudonym itself. Audit/provenance only -- private.delete_my_data does not need it to find a row (it tries every currently-active key).';
COMMENT ON COLUMN app.attestation.staff_pseudonym_key_id IS
  'Same as player_pseudonym_key_id, for staff_pseudonym.';
COMMENT ON COLUMN app.attestation_shift_log.player_pseudonym_key_id IS
  'Same as app.attestation.player_pseudonym_key_id.';

-- ============================================================================
-- 3. Deploy check (should-fix): a real deploy with no pseudonym_key in
--    Vault must fail loudly, not silently leave PII behind the first time
--    someone calls delete_my_data. private.delete_my_data itself already
--    RAISEs at CALL time if the vault has no active key (0015) -- this
--    function lets a deploy/CI step check BEFORE anyone calls it (see
--    tools/db/test.sh's own post-migrate smoke check, and
--    docs/security/p3-money-path-requirements.md).
--
--    A plain VIEW here would run with the CALLER's own privileges (views
--    are not security-definable in Postgres, only functions are) --
--    service_role has no grant on vault.decrypted_secrets (only
--    private_definer does, deliberately narrow), so a view would fail
--    with "permission denied" for the very role meant to run this check.
--    A SECURITY DEFINER function, owned by private_definer like every
--    other function that reaches the vault, sidesteps that: it runs with
--    private_definer's own rights regardless of who calls it.
-- ============================================================================
CREATE OR REPLACE FUNCTION private.pseudonym_key_status()
RETURNS TABLE (active_key_count int, all_keys_valid boolean)
LANGUAGE sql SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT count(*)::int, bool_and(decrypted_secret IS NOT NULL AND length(decrypted_secret) >= 32)
  FROM vault.decrypted_secrets
  WHERE name LIKE 'pseudonym_key%';
$$;

ALTER FUNCTION private.pseudonym_key_status() OWNER TO private_definer;
REVOKE EXECUTE ON FUNCTION private.pseudonym_key_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.pseudonym_key_status() TO service_role;

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('private', 'pseudonym_key_status', '', false, false, true, 'deploy-check helper (M1, post-P3a re-gate): fails a deploy check if no valid pseudonym_key exists in Vault');
