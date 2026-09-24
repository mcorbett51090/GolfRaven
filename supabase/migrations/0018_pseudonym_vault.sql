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
-- 2. pseudonym_hmac_id columns "beside each pseudonym" — which active vault
--    key actually computed the value stored next to it. private.
--    delete_my_data (0015) does not need this to MATCH a row (it tries
--    every active key, which is correct regardless of rotation state and
--    needs no per-row bookkeeping to stay correct) — it is audit/
--    provenance metadata: given a pseudonym value, which key produced it,
--    without recomputing against every active key to find out.
-- ============================================================================
-- ⛔ FIX (should-fix, post-P3a re-gate: "FK into vault.secrets ...
-- fragile across Vault upgrades. Store the key name/version and validate
-- it inside the definer instead of using the FK."): NO FOREIGN KEY to
-- vault.secrets(id) -- Supabase Vault's own internal table shape is not
-- this project's to depend on structurally (an upgrade could change its
-- primary key, partition it, or move it, breaking every FK into it at
-- once). The vault row's own id still serves as the "which key version
-- wrote this" identifier (stored here as a plain, unconstrained uuid),
-- but its VALIDITY is checked programmatically, at read time, inside
-- private.delete_my_data (0015) -- a SECURITY DEFINER function, the only
-- place that ever needs to resolve one of these ids back to a real vault
-- key -- rather than by the database enforcing referential integrity
-- against a table this project does not own the schema of.
ALTER TABLE app.attestation ADD COLUMN player_pseudonym_hmac_id uuid;
ALTER TABLE app.attestation ADD COLUMN staff_pseudonym_hmac_id uuid;
ALTER TABLE app.attestation_shift_log ADD COLUMN player_pseudonym_hmac_id uuid;

COMMENT ON COLUMN app.attestation.player_pseudonym_hmac_id IS
  'Which vault.secrets row computed player_pseudonym, at write time (id only -- NO foreign key, see this migration''s own note above; validated at read time by private.delete_my_data). Written by the (out-of-scope-this-stage) attest Edge Function alongside player_pseudonym itself. Load-bearing for app.attestation_shift_log''s own copy of this column (should-fix, post-P3a re-gate): delete_my_data resolves EXACTLY this recorded id, not every currently-active key by name, and raises if it cannot.';
COMMENT ON COLUMN app.attestation.staff_pseudonym_hmac_id IS
  'Same as player_pseudonym_hmac_id, for staff_pseudonym.';
COMMENT ON COLUMN app.attestation_shift_log.player_pseudonym_hmac_id IS
  'Same as app.attestation.player_pseudonym_hmac_id -- this is the column private.delete_my_data actually reads to know which vault key to resolve for a given row (should-fix, post-P3a re-gate).';

-- ============================================================================
-- ⛔ FIX (M1 BLOCKING, post-P3a re-gate): "delete_my_data silently leaves
-- PII behind when a shift-log row has a pseudonym but a NULL key id."
-- Repro: `UPDATE app.attestation_shift_log SET player_pseudonym_hmac_id =
-- NULL` on a v1-written row, then delete_my_data(A) succeeds and leaves
-- player_a's row untouched -- the discovery loop (0015) only scans
-- DISTINCT non-NULL hmac ids, and the legacy fallback only matches rows
-- where BOTH player_pseudonym and player_pseudonym_hmac_id are NULL, so a
-- row with pseudonym SET but hmac_id NULL (or the reverse) falls through
-- both paths and is never redacted, never raising, never even being
-- looked at.
--
-- Two independent layers close this, at WRITE time (not merely at
-- delete_my_data's later read time):
--
-- 1. A pairing CHECK on every table carrying one of these pairs: the
--    pseudonym and its hmac id must be NULL together or set together --
--    the exact "pseudonym set, hmac_id NULL" shape the repro constructs
--    becomes structurally impossible to write, full stop.
-- 2. A write-time trigger, through a private_definer SECURITY DEFINER
--    function, that validates a non-NULL hmac id actually resolves to a
--    real, valid (>=32 byte) key in vault.decrypted_secrets BEFORE the
--    row is ever written -- so a row can never reference a bad/unknown
--    key in the first place, which also retires the earlier "one bad id
--    blocks every deletion" should-fix concern for the common case: a
--    key can now only become unresolvable AFTER having been validated at
--    write time, by a deliberate later administrative action (deleting
--    it from Vault while rows still reference it) -- which is exactly
--    the should-fix-4 test's own scenario, and is correctly still
--    fail-closed (see private.delete_my_data's own RAISE, 0015), not a
--    silent leak.
-- ============================================================================

-- app.attestation_shift_log: player_pseudonym is nullable (0004) -- a
-- LEGACY row (logged before this pseudonym scheme existed at all) has
-- BOTH columns NULL and is matched by handle instead (0015's own legacy
-- fallback); this CHECK only forbids the MIXED shape (one set, one not).
ALTER TABLE app.attestation_shift_log ADD CONSTRAINT attestation_shift_log_pseudonym_hmac_id_paired
  CHECK ((player_pseudonym IS NULL) = (player_pseudonym_hmac_id IS NULL));

-- app.attestation: player_pseudonym/staff_pseudonym are NOT NULL (0004) --
-- there is no "legacy, neither set" shape here at all, so this pairing
-- CHECK collapses in practice to "the hmac id column is never NULL".
-- Written in the same paired form as attestation_shift_log's own CHECK
-- for one consistent, self-documenting shape across every table carrying
-- this kind of pair (M1's own text: "plus the staff equivalent, on ...
-- any other table carrying pseudonym + hmac_id pairs"). Both existing
-- INSERT call sites already supply both ids together (supabase/tests/
-- helpers.sql); the one fixture that omits them (06_partner_scope_
-- matrix.sql's self-attestation CHECK-violation test) is already
-- expected to fail with 23514 for an unrelated CHECK, and still does.
ALTER TABLE app.attestation ADD CONSTRAINT attestation_player_pseudonym_hmac_id_paired
  CHECK ((player_pseudonym IS NULL) = (player_pseudonym_hmac_id IS NULL));
ALTER TABLE app.attestation ADD CONSTRAINT attestation_staff_pseudonym_hmac_id_paired
  CHECK ((staff_pseudonym IS NULL) = (staff_pseudonym_hmac_id IS NULL));

-- ============================================================================
-- private.pseudonym_key_registry: should-fix 2 (post-P3a re-gate) --
-- "replace the broad pd_shift_log_discover_hmac_id policy (0017,
-- USING(true)) with a small registry of key ids ever used. The
-- attest-time write trigger from M1 inserts into it (ON CONFLICT DO
-- NOTHING), and deletion iterates the registry." A key id row here is
-- provenance metadata only (which vault key wrote SOME row, never who),
-- so this table is safe to iterate broadly by construction -- the same
-- justification the broad discovery policy it replaces already carried,
-- just narrowed from "every row of a real player-data table" down to
-- "every key id ever seen", which is strictly less than that table ever
-- exposed.
-- ============================================================================
CREATE TABLE private.pseudonym_key_registry (
  key_id uuid PRIMARY KEY,
  first_seen_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE private.pseudonym_key_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.pseudonym_key_registry FORCE ROW LEVEL SECURITY;

GRANT SELECT, INSERT ON private.pseudonym_key_registry TO private_definer;
CREATE POLICY pd_pseudonym_key_registry_all ON private.pseudonym_key_registry
  FOR ALL TO private_definer USING (true) WITH CHECK (true);

-- service_role gets SELECT/INSERT/DELETE directly (BYPASSRLS, per 0009 --
-- the FORCE RLS policy above never even applies to it) so it can do
-- legitimate operational cleanup of a permanently-retired key's registry
-- row without needing a bespoke SECURITY DEFINER maintenance function for
-- that one narrow case; this is NOT a replay-style risk the way
-- private.consumed_nonce's DELETE grant was (should-fix 2, 0017) -- a
-- registry row records only "this key id was once used", and removing it
-- just means delete_my_data will no longer try to resolve that
-- particular key (a correctness/availability concern, not a PII-leak
-- one: pairing CHECK + the write-time trigger above are what actually
-- prevent a leak, independent of this table's own contents).
GRANT SELECT, INSERT, DELETE ON private.pseudonym_key_registry TO service_role;

-- The write-time validator + registrar: SECURITY DEFINER, owned by
-- private_definer (the only role vault.decrypted_secrets and this
-- registry are ever granted to), so it runs with the right privileges
-- regardless of which role is actually inserting/updating the row
-- (normally service_role, via the out-of-scope attest Edge Function).
CREATE OR REPLACE FUNCTION private.validate_and_register_pseudonym_hmac_id(p_key_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM vault.decrypted_secrets
    WHERE id = p_key_id AND decrypted_secret IS NOT NULL AND length(decrypted_secret) >= 32
  ) THEN
    RAISE EXCEPTION 'pseudonym_hmac_id % does not resolve to a valid (present, >=32 byte) key in vault.decrypted_secrets -- cannot write a row referencing it', p_key_id
      USING ERRCODE = '23514';
  END IF;
  INSERT INTO private.pseudonym_key_registry (key_id) VALUES (p_key_id) ON CONFLICT DO NOTHING;
END;
$$;

-- REVOKE/GRANT EXECUTE before the OWNER TO transfer, same ordering
-- discipline as every other private_definer-owned function in this
-- migration set (see private.pseudonym_hmac_status's own note on this,
-- above, and private.purge_consumed_nonce's, 0017) -- confirmed
-- empirically (again) this session for THIS function too.
REVOKE EXECUTE ON FUNCTION private.validate_and_register_pseudonym_hmac_id(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.validate_and_register_pseudonym_hmac_id(uuid) TO service_role;

GRANT CREATE ON SCHEMA private TO private_definer;
ALTER FUNCTION private.validate_and_register_pseudonym_hmac_id(uuid) OWNER TO private_definer;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- The two write-time trigger functions. Plain (invoker-rights) functions
-- that call the SECURITY DEFINER validator above -- NOT themselves
-- SECURITY DEFINER, so no ownership-transfer/schema-CREATE dance is
-- needed for them; they run as whichever role is actually writing the
-- row (service_role, which now holds EXECUTE on the validator above).
-- Scoped to fire only on INSERT or on an UPDATE that actually TOUCHES the
-- hmac id column(s) -- not on every unrelated UPDATE (e.g.
-- delete_my_data's own generic-pass UPDATE of player_user_id, or its
-- attestation_shift_log redaction UPDATE of player_handle_snapshot,
-- neither of which ever changes these columns) -- so a key that was
-- valid at write time and is later deleted from Vault does not suddenly
-- start blocking unrelated writes to the same row; it is still correctly
-- caught by private.delete_my_data's own RAISE when THAT specific key is
-- actually resolved (should-fix-4's scenario).
CREATE OR REPLACE FUNCTION app.attestation_shift_log_validate_hmac_id() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.player_pseudonym_hmac_id IS NOT NULL THEN
    PERFORM private.validate_and_register_pseudonym_hmac_id(NEW.player_pseudonym_hmac_id);
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER attestation_shift_log_validate_hmac_id_trg
BEFORE INSERT OR UPDATE OF player_pseudonym_hmac_id ON app.attestation_shift_log
FOR EACH ROW EXECUTE FUNCTION app.attestation_shift_log_validate_hmac_id();

CREATE OR REPLACE FUNCTION app.attestation_validate_hmac_ids() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.player_pseudonym_hmac_id IS NOT NULL THEN
    PERFORM private.validate_and_register_pseudonym_hmac_id(NEW.player_pseudonym_hmac_id);
  END IF;
  IF NEW.staff_pseudonym_hmac_id IS NOT NULL THEN
    PERFORM private.validate_and_register_pseudonym_hmac_id(NEW.staff_pseudonym_hmac_id);
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER attestation_validate_hmac_ids_trg
BEFORE INSERT OR UPDATE OF player_pseudonym_hmac_id, staff_pseudonym_hmac_id ON app.attestation
FOR EACH ROW EXECUTE FUNCTION app.attestation_validate_hmac_ids();

-- Backfill: any row already present when this migration runs (a fresh
-- test/CI database has none at this point, since fixtures load AFTER
-- migrations -- see supabase/tests/helpers.sql's own header comment --
-- but a real, already-deployed database could) is registered too, so the
-- registry starts complete rather than only growing from this point
-- forward.
INSERT INTO private.pseudonym_key_registry (key_id)
SELECT DISTINCT player_pseudonym_hmac_id FROM app.attestation_shift_log WHERE player_pseudonym_hmac_id IS NOT NULL
UNION
SELECT DISTINCT player_pseudonym_hmac_id FROM app.attestation WHERE player_pseudonym_hmac_id IS NOT NULL
UNION
SELECT DISTINCT staff_pseudonym_hmac_id FROM app.attestation WHERE staff_pseudonym_hmac_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('private', 'validate_and_register_pseudonym_hmac_id', 'p_key_id uuid', false, false, true, 'M1 (post-P3a re-gate): write-time Vault-resolution check + registration into private.pseudonym_key_registry, SECURITY DEFINER owned by private_definer; called from the app.attestation/app.attestation_shift_log write-time trigger functions below (which run as service_role, the actual writer)'),
  ('app', 'attestation_shift_log_validate_hmac_id', '', false, false, false, 'trigger function (app.attestation_shift_log_validate_hmac_id_trg) -- never EXECUTEd directly by any role'),
  ('app', 'attestation_validate_hmac_ids', '', false, false, false, 'trigger function (app.attestation_validate_hmac_ids_trg) -- never EXECUTEd directly by any role');

-- Register pd_pseudonym_key_registry_all in private.definer_policy_
-- allowlist (0016) -- 0017 already revoked the CURRENT_USER INSERT/UPDATE
-- grant its own temporary seeding policy needed, so this migration redoes
-- the same narrow, self-revoked pattern for its own new row.
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0018 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('private', 'pseudonym_key_registry', 'pd_pseudonym_key_registry_all', 'ALL', false, 'M1/should-fix 2 (post-P3a re-gate): private_definer''s own registry table -- a key id here is provenance metadata only (which vault key wrote SOME row, never who), so full access for private_definer is safe and matches the table''s own narrow purpose');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name = 'pd_pseudonym_key_registry_all';
DROP POLICY current_user_seed_definer_policy_allowlist_0018 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 3. Deploy check (should-fix): a real deploy with no pseudonym_hmac in
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
CREATE OR REPLACE FUNCTION private.pseudonym_hmac_status()
RETURNS TABLE (active_key_count int, all_keys_valid boolean)
LANGUAGE sql SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT count(*)::int, bool_and(decrypted_secret IS NOT NULL AND length(decrypted_secret) >= 32)
  FROM vault.decrypted_secrets
  WHERE name LIKE 'pseudonym_hmac%';
$$;

-- ⛔ FIX (post-P3a re-gate, found while regression-testing under
-- HARNESS_MODE=restricted): REVOKE/GRANT EXECUTE must run BEFORE the
-- OWNER TO transfer below, not after — once ownership moves to
-- private_definer, migration_owner (who just CREATEd the function) is no
-- longer its owner and holds no GRANT OPTION on it either, so a REVOKE/
-- GRANT issued afterward 42501s ("permission denied for function
-- pseudonym_hmac_status"), confirmed empirically this session. 0015/0016
-- avoid this by doing delete_my_data's own REVOKE/GRANT EXECUTE at the
-- END of 0015, entirely before 0016 transfers ITS ownership in a later
-- migration — same ordering constraint, different file layout.
REVOKE EXECUTE ON FUNCTION private.pseudonym_hmac_status() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.pseudonym_hmac_status() TO service_role;

-- 0016 REVOKEd CREATE ON SCHEMA private FROM private_definer once its own
-- ownership transfers were done -- this function's transfer needs it
-- again, briefly, for the same reason (Postgres checks the new owner has
-- CREATE in the object's schema for an ownership transfer). Re-revoked
-- immediately after, same discipline as 0016.
GRANT CREATE ON SCHEMA private TO private_definer;
ALTER FUNCTION private.pseudonym_hmac_status() OWNER TO private_definer;
REVOKE CREATE ON SCHEMA private FROM private_definer;

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, note)
VALUES
  ('private', 'pseudonym_hmac_status', '', false, false, true, 'deploy-check helper (M1, post-P3a re-gate): fails a deploy check if no valid pseudonym_hmac exists in Vault');
