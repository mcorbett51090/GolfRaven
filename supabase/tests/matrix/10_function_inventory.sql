-- 10_function_inventory.sql
-- build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1206-1215): "The
-- function inventory is derived, not maintained ... No hand list is
-- authoritative." ⛔ REWRITE (B2, gate round 2): this file used to check
-- only the two `api.*` RPCs by name. It now derives the FULL inventory —
-- every function in app/api/private — from `pg_proc`, fails if any of
-- them has no row in `private.function_inventory` (0014_hardening, the
-- manifest `tools/db/verify-function-inventory.mjs` reads independently),
-- asserts every function's ACTUAL EXECUTE grants match that manifest's
-- expected grants (the "function × role" matrix cell), and asserts every
-- SECURITY DEFINER function sets `search_path` in `proconfig`.

BEGIN;
SELECT plan(164);

-- S1 restricted-mode fix: this file reads private.function_inventory and
-- private.definer_policy_allowlist directly (both ENABLE+FORCE RLS,
-- SELECT granted to service_role only, 0014/0016) -- under
-- HARNESS_MODE=restricted the pgTAP matrix itself connects as
-- migration_owner (NOSUPERUSER NOBYPASSRLS, no policy on either table),
-- so without this every row in both tables is invisible to the check
-- itself, which is a data-integrity/inventory check needing full
-- visibility, not an authorization boundary under test -- the same
-- reasoning as 07_rate_limit.sql/09_delete_my_data.sql's own fix.
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- (1) Every function in app/api/private has a private.function_inventory
-- row. A new function with no row fails here immediately — this is the
-- literal "CI fails if a function in the inventory has no matrix cells."
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    LEFT JOIN private.function_inventory fi
      ON fi.schema_name = n.nspname AND fi.function_name = p.proname
      AND fi.identity_args = pg_get_function_identity_arguments(p.oid)
    WHERE n.nspname IN ('app', 'api', 'private')
      AND p.prokind = 'f'
      AND fi.schema_name IS NULL
  ),
  0,
  'every function in app/api/private has a private.function_inventory row (derived from pg_proc)'
);

-- (2) Reverse direction: every manifest row still names a real function
-- (catches a stale/removed entry).
SELECT is(
  (
    SELECT count(*)::int
    FROM private.function_inventory fi
    WHERE NOT EXISTS (
      SELECT 1 FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = fi.schema_name AND p.proname = fi.function_name
        AND pg_get_function_identity_arguments(p.oid) = fi.identity_args
    )
  ),
  0,
  'every private.function_inventory row still names a function that exists'
);

-- (3)-(5) Matrix cells: for every manifest row, the actual EXECUTE grant
-- for anon/authenticated/service_role matches the declared expectation.
-- One assertion per role, over the WHOLE manifest at once (a mismatch on
-- ANY function fails the corresponding role's assertion, and the failure
-- message — via a custom diag — names which).
DO $$
DECLARE
  v_row record;
  v_oid oid;
  v_mismatches text[] := '{}';
BEGIN
  FOR v_row IN SELECT * FROM private.function_inventory LOOP
    SELECT p.oid INTO v_oid
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_row.schema_name AND p.proname = v_row.function_name
      AND pg_get_function_identity_arguments(p.oid) = v_row.identity_args;
    IF has_function_privilege('anon', v_oid, 'EXECUTE') <> v_row.expected_anon THEN
      v_mismatches := v_mismatches || format('%s.%s: anon expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_anon, has_function_privilege('anon', v_oid, 'EXECUTE'));
    END IF;
  END LOOP;
  IF array_length(v_mismatches, 1) > 0 THEN
    RAISE EXCEPTION 'anon EXECUTE mismatches: %', array_to_string(v_mismatches, '; ');
  END IF;
END
$$;
SELECT pass('every function''s actual anon EXECUTE grant matches private.function_inventory.expected_anon');

DO $$
DECLARE
  v_row record;
  v_oid oid;
  v_mismatches text[] := '{}';
BEGIN
  FOR v_row IN SELECT * FROM private.function_inventory LOOP
    SELECT p.oid INTO v_oid
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_row.schema_name AND p.proname = v_row.function_name
      AND pg_get_function_identity_arguments(p.oid) = v_row.identity_args;
    IF has_function_privilege('authenticated', v_oid, 'EXECUTE') <> v_row.expected_authenticated THEN
      v_mismatches := v_mismatches || format('%s.%s: authenticated expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_authenticated, has_function_privilege('authenticated', v_oid, 'EXECUTE'));
    END IF;
  END LOOP;
  IF array_length(v_mismatches, 1) > 0 THEN
    RAISE EXCEPTION 'authenticated EXECUTE mismatches: %', array_to_string(v_mismatches, '; ');
  END IF;
END
$$;
SELECT pass('every function''s actual authenticated EXECUTE grant matches private.function_inventory.expected_authenticated');

DO $$
DECLARE
  v_row record;
  v_oid oid;
  v_mismatches text[] := '{}';
BEGIN
  FOR v_row IN SELECT * FROM private.function_inventory LOOP
    SELECT p.oid INTO v_oid
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_row.schema_name AND p.proname = v_row.function_name
      AND pg_get_function_identity_arguments(p.oid) = v_row.identity_args;
    IF has_function_privilege('service_role', v_oid, 'EXECUTE') <> v_row.expected_service_role THEN
      v_mismatches := v_mismatches || format('%s.%s: service_role expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_service_role, has_function_privilege('service_role', v_oid, 'EXECUTE'));
    END IF;
  END LOOP;
  IF array_length(v_mismatches, 1) > 0 THEN
    RAISE EXCEPTION 'service_role EXECUTE mismatches: %', array_to_string(v_mismatches, '; ');
  END IF;
END
$$;
SELECT pass('every function''s actual service_role EXECUTE grant matches private.function_inventory.expected_service_role');

-- ==========================================================================
-- (7)-(10) 0016_private_definer.sql / gate round 3 step 5 + M2 (post-P3a
-- gate): "Add a pgTAP inventory assertion: every private.* SECURITY
-- DEFINER function is owned by private_definer, and every policy granted
-- to private_definer appears in an explicit allow-list table."
-- ==========================================================================

-- ⛔ FIX (should-fix, post-P3a re-gate): "also flag extension-member
-- functions whose extension is not in a fixed allow-list (postgis,
-- pgtap, pgcrypto, ...)." The PRIOR version excluded EVERY extension-
-- owned function unconditionally (`pg_depend deptype='e'` alone) — an
-- extension this project never intentionally installs could ship its own
-- SECURITY DEFINER function and sail through silently, the exact "not
-- checked at all" gap the should-fix names. A fixed allow-list of the
-- extensions this project genuinely installs (grepped every
-- `CREATE EXTENSION` in supabase/migrations/ + the harness bootstrap
-- this session: postgis and pgcrypto via 0001_schemas.sql, pgtap via the
-- harness/CI bootstrap only, never a real migration) means only THOSE
-- extensions' own member functions are exempted; a function belonging to
-- any OTHER extension is no longer exempted at all, and falls through to
-- the same private/private_definer + search_path checks as product code
-- — which it will almost certainly fail, surfacing it here rather than
-- silently passing. Inlined as a repeated EXISTS (not a helper function)
-- so this stays a pure read — no schema object to create/rollback inside
-- a test file's own transaction.

-- (7) M2(c): every SECURITY DEFINER function ANYWHERE in this database
-- (not just app/api/private -- a definer function planted in `public` or
-- `tests` was invisible to the old, schema-scoped check) is checked two
-- ways at once: it must live in schema `private`, AND be owned by
-- `private_definer` -- fails on either a definer function outside
-- `private` (app/api/public/tests/anywhere else) or one inside `private`
-- but not private_definer-owned. Only ALLOW-LISTED-extension-owned
-- functions (postgis/pgtap/pgcrypto — see the note above) are excluded,
-- the same "not product code" carve-out 03_views_and_rpc.sql already
-- applies to extension-owned views — an extension outside that list gets
-- no such exemption.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    LEFT JOIN pg_roles r ON r.oid = p.proowner
    WHERE p.prosecdef
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend d
        JOIN pg_extension e ON e.oid = d.refobjid
        WHERE d.objid = p.oid AND d.deptype = 'e' AND e.extname IN ('postgis', 'pgtap', 'pgcrypto')
          AND (e.extname, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)) IN (
          -- should-fix (post-P3a re-gate): "ALTER EXTENSION pgcrypto ADD
          -- FUNCTION public.evil4() passes both checks. Pin the
          -- definer-function set inside allow-listed extensions." Merely
          -- checking "is pg_depend deptype='e' for an allow-listed
          -- extension" is itself forgeable -- ALTER EXTENSION ... ADD
          -- FUNCTION attaches ANY existing function (created by anyone
          -- with the right privilege) to an extension's own dependency
          -- record, making it look genuinely extension-shipped to a check
          -- that only asks "which extension owns this". Pinned instead to
          -- the SPECIFIC (extension, schema, function, identity_args)
          -- tuples verified to be genuinely part of that extension's own
          -- install script -- currently EMPTY (confirmed empirically this
          -- session: postgis/pgtap/pgcrypto ship ZERO SECURITY DEFINER
          -- functions between them, in this project's installed
          -- versions), so NOTHING is exempted by extension membership
          -- alone any more; add a real row here only when a specific one
          -- is confirmed to exist in a real install.
          SELECT NULL::text, NULL::text, NULL::text, NULL::text WHERE false
        )
      )
      AND (n.nspname <> 'private' OR NOT (coalesce(r.rolname, '') = ANY (ARRAY['private_definer', 'partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier'])))
  ),
  0,
  'every non-allowlisted-extension SECURITY DEFINER function anywhere lives in schema private AND is owned by private_definer (or, 0047, one of the six partner owner roles)'
);

-- (8) M2(c): every SECURITY DEFINER function anywhere (same scope/
-- extension-allowlist as (7)) sets search_path in proconfig -- not
-- scoped to app/api/private, since the whole point is catching a definer
-- function planted somewhere the old check never looked.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.prosecdef
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend d
        JOIN pg_extension e ON e.oid = d.refobjid
        WHERE d.objid = p.oid AND d.deptype = 'e' AND e.extname IN ('postgis', 'pgtap', 'pgcrypto')
          AND (e.extname, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)) IN (
          -- should-fix (post-P3a re-gate): "ALTER EXTENSION pgcrypto ADD
          -- FUNCTION public.evil4() passes both checks. Pin the
          -- definer-function set inside allow-listed extensions." Merely
          -- checking "is pg_depend deptype='e' for an allow-listed
          -- extension" is itself forgeable -- ALTER EXTENSION ... ADD
          -- FUNCTION attaches ANY existing function (created by anyone
          -- with the right privilege) to an extension's own dependency
          -- record, making it look genuinely extension-shipped to a check
          -- that only asks "which extension owns this". Pinned instead to
          -- the SPECIFIC (extension, schema, function, identity_args)
          -- tuples verified to be genuinely part of that extension's own
          -- install script -- currently EMPTY (confirmed empirically this
          -- session: postgis/pgtap/pgcrypto ship ZERO SECURITY DEFINER
          -- functions between them, in this project's installed
          -- versions), so NOTHING is exempted by extension membership
          -- alone any more; add a real row here only when a specific one
          -- is confirmed to exist in a real install.
          SELECT NULL::text, NULL::text, NULL::text, NULL::text WHERE false
        )
      )
      AND NOT EXISTS (
        SELECT 1 FROM unnest(COALESCE(p.proconfig, '{}'::text[])) cfg WHERE cfg LIKE 'search_path=%'
      )
  ),
  0,
  'every SECURITY DEFINER function anywhere (non-allowlisted-extension) sets search_path in proconfig'
);

-- (9) Forward direction: every RLS policy that APPLIES TO private_definer
-- -- granted directly (private_definer in polroles) OR implicitly via a
-- PUBLIC policy (M2(b): "Include PUBLIC policies (polroles @> '{0}')" --
-- a PUBLIC policy applies to every role, private_definer included, and
-- the old check missed it entirely since it only matched
-- private_definer's own oid) -- has a matching row in
-- private.definer_policy_allowlist, AND (M2(a)) that row's stored
-- using_expr/with_check_expr still matches what the LIVE policy actually
-- says: a later `CREATE OR REPLACE POLICY` that broadens either clause
-- changes pg_get_expr's output without changing the policy's name, which
-- the old name-only match could not have caught.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_policy pol
    JOIN pg_class cl ON cl.oid = pol.polrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    CROSS JOIN pg_roles pr
    WHERE pr.rolname = ANY (ARRAY['private_definer', 'partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier'])
      AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
      AND NOT EXISTS (
        SELECT 1 FROM private.definer_policy_allowlist al
        WHERE al.schema_name = n.nspname
          AND al.table_name = cl.relname
          AND al.policy_name = pol.polname
          AND al.role_name = pr.rolname
          AND al.command = CASE pol.polcmd
                WHEN 'r' THEN 'SELECT'
                WHEN 'a' THEN 'INSERT'
                WHEN 'w' THEN 'UPDATE'
                WHEN 'd' THEN 'DELETE'
                WHEN '*' THEN 'ALL'
                ELSE pol.polcmd::text
              END
          AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
          AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)
      )
  ),
  0,
  'every RLS policy applying to private_definer or one of the six 0047 owner roles (direct grant or PUBLIC) is registered in private.definer_policy_allowlist with the same role_name and a matching USING/WITH CHECK expression'
);

-- (10) Reverse direction: every allow-list row still names a real policy
-- actually applying to private_definer, with matching expressions
-- (catches a stale/removed entry OR one whose expression silently
-- narrowed/changed shape without the allow-list being updated).
SELECT is(
  (
    SELECT count(*)::int
    FROM private.definer_policy_allowlist al
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_policy pol
      JOIN pg_class cl ON cl.oid = pol.polrelid
      JOIN pg_namespace n ON n.oid = cl.relnamespace
      CROSS JOIN pg_roles pr
      WHERE pr.rolname = al.role_name
        AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
        AND n.nspname = al.schema_name
        AND cl.relname = al.table_name
        AND pol.polname = al.policy_name
        AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
        AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)
    )
  ),
  0,
  'every private.definer_policy_allowlist row still names a real policy applying to its role_name with a matching expression'
);

-- (11) P3d gate round 3, S4: COLUMN-level "_r companion" check --
-- REPLACES round 2's table-level version (kept the same check number;
-- this is a fix to the check, not an addition). Round 2's table-level
-- check ("does SOME SELECT(/ALL) policy exist for private_definer on
-- this table at all") was found insufficient THIS round: a table with
-- TWO classified columns, one with a real SELECT companion and one with
-- none, PASSED it, even though `delete_my_data`'s own post-condition
-- (0022) and `export_my_data` (0022) both re-read PER COLUMN, under RLS
-- gated on that SAME column -- a column with no companion is invisible
-- to both, "reporting success while the row survives" for exactly that
-- column, table-level check notwithstanding. See 0022's own
-- post-condition comment for the full corrected account (P3d gate round
-- 3, S4 also asked for that correction).
--
-- This version requires, for every `private.pii_retention_policy`
-- (table, column) pair classified delete_row/set_null, a private_definer
-- SELECT(/ALL) policy on the SAME table whose USING clause guards THAT
-- SPECIFIC column with the EXACT `nullif(current_setting(...))` form --
-- reusing check 7's own "exact form, not a loose substring" discipline
-- (pg_get_expr's canonical deparsed shape). Built as a DO block (not a
-- single `is()` SELECT) so the regex pattern can be assembled with
-- `chr(39)` for each literal single quote it needs to match, rather than
-- fighting SQL string-literal quote-doubling inside a doubly-nested
-- string -- same "build the awkward literal with chr(39)" technique this
-- file's own earlier checks are free to reach for.
DO $$
DECLARE
  v_q text := chr(39);
  v_rp record;
  v_pattern text;
  v_guarded boolean;
BEGIN
  FOR v_rp IN
    SELECT schema_name, table_name, column_name
    FROM private.pii_retention_policy
    WHERE schema_name = 'app' AND action IN ('delete_row', 'set_null')
  LOOP
    v_pattern := '\m' || v_rp.column_name || '\M\s*=\s*\(?NULLIF\(current_setting\(' || v_q
      || '[^' || v_q || ']*' || v_q || '::text,\s*true\),\s*' || v_q || v_q || '::text\)\)?(::\w+)?';
    SELECT bool_or(pg_get_expr(pol.polqual, pol.polrelid) ~ v_pattern) INTO v_guarded
    FROM pg_policy pol
    JOIN pg_class cl ON cl.oid = pol.polrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    CROSS JOIN pg_roles pr
    WHERE pr.rolname = 'private_definer'
      AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
      AND pol.polcmd IN ('r', '*')
      AND n.nspname = v_rp.schema_name
      AND cl.relname = v_rp.table_name;
    IF NOT COALESCE(v_guarded, false) THEN
      RAISE EXCEPTION 'column-level "_r companion" check: %.%.% (delete_row/set_null) has no private_definer SELECT(/ALL) policy whose USING clause guards that column with the exact nullif(current_setting(...)) form', v_rp.schema_name, v_rp.table_name, v_rp.column_name;
    END IF;
  END LOOP;
END
$$;
SELECT pass('every private.pii_retention_policy (table, column) pair classified delete_row/set_null has a private_definer SELECT(/ALL) "_r companion" policy guarding THAT SPECIFIC column (column-level, P3d gate round 3 S4)');

-- (12) P3d gate round 3, S4: must-fail fixture, proving check 11's own
-- logic is genuinely column-level and not vacuously true (this project's
-- real schema has zero live violations, so check 11 alone never proves
-- it would actually CATCH one). Reviewer's own repro shape: a table with
-- TWO delete_row-classified columns, a private_definer SELECT "_r
-- companion" policy on only ONE of them.
--
-- Reverts to the CONNECTING role first (tests.clear_actor(), a plain
-- RESET ROLE): this file authenticated as service_role at its very top
-- (line 25) and never switched back — service_role owns neither schema
-- app nor its own CREATE grant on it, so a CREATE TABLE app.zz_two
-- while still impersonating it fails "permission denied for schema app".
-- The connecting role itself (migration_owner under HARNESS_MODE=
-- restricted; postgres under HARNESS_MODE=superuser) is what actually
-- OWNS schema app (0001_schemas.sql's own CREATE SCHEMA, applied by
-- whichever role runs migrations) and needs no extra grant.
SELECT lives_ok($$SELECT tests.clear_actor()$$, 'setup (S4 fixture): revert to the connecting role, which owns schema app');
SELECT lives_ok(
  $$CREATE TABLE app.zz_two (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_a uuid, user_b uuid)$$,
  'setup (S4 fixture): create app.zz_two'
);
ALTER TABLE app.zz_two ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.zz_two FORCE ROW LEVEL SECURITY;
SELECT lives_ok(
  $$CREATE POLICY zz_two_delete_a ON app.zz_two FOR DELETE TO private_definer USING (user_a = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid)$$,
  'setup (S4 fixture): DELETE policy on user_a'
);
SELECT lives_ok(
  $$CREATE POLICY zz_two_delete_b ON app.zz_two FOR DELETE TO private_definer USING (user_b = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid)$$,
  'setup (S4 fixture): DELETE policy on user_b'
);
SELECT lives_ok(
  $$CREATE POLICY zz_two_select_a_r ON app.zz_two FOR SELECT TO private_definer USING (user_a = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid)$$,
  'setup (S4 fixture): SELECT "_r companion" policy on user_a ONLY -- user_b deliberately has none'
);
-- private.pii_retention_policy has FORCE ROW LEVEL SECURITY (0014) —
-- and (found by this exact fixture, empirically): unlike
-- pseudonym_key_registry, table OWNERSHIP alone does not carry an
-- implicit INSERT/DELETE grant here either — 0019_evidence_intake.sql
-- hit the SAME "permission denied for table pii_retention_policy" when
-- it needed to insert a fixture row into this exact table, and its own
-- fix is reused verbatim here: an explicit `GRANT INSERT/DELETE ...
-- TO CURRENT_USER` alongside the usual self-granting temporary policy
-- (row-visibility) — a GRANT and a POLICY answer two DIFFERENT
-- questions (table-level privilege vs. row-level visibility) and FORCE
-- RLS means BOTH are needed even for the connecting/owning role.
GRANT INSERT, DELETE ON private.pii_retention_policy TO CURRENT_USER;
SELECT lives_ok(
  $$CREATE POLICY current_user_seed_pii_retention_policy_s4_test ON private.pii_retention_policy FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true)$$,
  'setup (S4 fixture): temporary self-granting policy on private.pii_retention_policy'
);
SELECT lives_ok(
  $$INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason)
    VALUES ('app', 'zz_two', 'user_a', 'delete_row', 'fixture (S4 must-fail proof, removed before this file ends)'),
           ('app', 'zz_two', 'user_b', 'delete_row', 'fixture (S4 must-fail proof, removed before this file ends)')$$,
  'setup (S4 fixture): register both zz_two columns in private.pii_retention_policy'
);

-- Re-runs check 11's OWN logic, scoped to zz_two only, as a real query
-- (not prose) -- this assertion FAILS THE BUILD if the column-level fix
-- ever regresses back to table-level (a table-level check would report
-- BOTH columns as fine, since zz_two has *a* SELECT policy).
SELECT is(
  (
    SELECT array_agg(v.column_name ORDER BY v.column_name)
    FROM (
      SELECT rp.column_name
      FROM private.pii_retention_policy rp
      WHERE rp.schema_name = 'app' AND rp.table_name = 'zz_two' AND rp.action = 'delete_row'
        AND NOT EXISTS (
          SELECT 1
          FROM pg_policy pol
          JOIN pg_class cl ON cl.oid = pol.polrelid
          JOIN pg_namespace n ON n.oid = cl.relnamespace
          CROSS JOIN pg_roles pr
          WHERE pr.rolname = 'private_definer'
            AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
            AND pol.polcmd IN ('r', '*')
            AND n.nspname = 'app' AND cl.relname = 'zz_two'
            AND pg_get_expr(pol.polqual, pol.polrelid) ~ (
              '\m' || rp.column_name || '\M\s*=\s*\(?NULLIF\(current_setting\(' || chr(39)
              || '[^' || chr(39) || ']*' || chr(39) || '::text,\s*true\),\s*' || chr(39) || chr(39) || '::text\)\)?(::\w+)?'
            )
        )
    ) v
  ),
  ARRAY['user_b'],
  'S4 must-fail fixture: the column-level check flags EXACTLY zz_two.user_b (DELETE policy, no SELECT companion) and NOT zz_two.user_a (DELETE policy, WITH a SELECT companion) -- proves the check is column-level, not merely table-level'
);

SELECT lives_ok(
  $$DELETE FROM private.pii_retention_policy WHERE schema_name = 'app' AND table_name = 'zz_two'$$,
  'cleanup (S4 fixture): remove fixture pii_retention_policy rows'
);
SELECT lives_ok(
  $$DROP POLICY current_user_seed_pii_retention_policy_s4_test ON private.pii_retention_policy$$,
  'cleanup (S4 fixture): drop the temporary self-granting policy on private.pii_retention_policy'
);
REVOKE INSERT, DELETE ON private.pii_retention_policy FROM CURRENT_USER;
SELECT lives_ok($$DROP TABLE app.zz_two$$, 'cleanup (S4 fixture): drop app.zz_two (cascades its own policies)');


-- ==========================================================================
-- The edge roles (0030 / 0031): docs/security/edge-role-design.md
-- ==========================================================================
-- tools/db/verify-function-inventory.mjs runs the SAME four queries (checks 9-12) against the live
-- cluster; this file proves each one on the clean schema AND must-fails it on a planted defect.
-- Each fixture defect is created and undone INSIDE this transaction (the file's ROLLBACK).
--
-- First: the EXECUTE columns of private.function_inventory for the two edge roles (check 2's twin of
-- the three DO blocks above).
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
DO $$
DECLARE
  v_row record;
  v_oid oid;
  v_mismatches text[] := '{}';
BEGIN
  FOR v_row IN SELECT * FROM private.function_inventory LOOP
    SELECT p.oid INTO v_oid
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_row.schema_name AND p.proname = v_row.function_name
      AND pg_get_function_identity_arguments(p.oid) = v_row.identity_args;
    IF has_function_privilege('edge_actor', v_oid, 'EXECUTE') <> v_row.expected_edge_actor THEN
      v_mismatches := v_mismatches || format('%s.%s: edge_actor expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_edge_actor, has_function_privilege('edge_actor', v_oid, 'EXECUTE'));
    END IF;
  END LOOP;
  IF array_length(v_mismatches, 1) > 0 THEN
    RAISE EXCEPTION 'edge_actor EXECUTE mismatches: %', array_to_string(v_mismatches, '; ');
  END IF;
END
$$;
SELECT pass('every function''s actual edge_actor EXECUTE grant matches private.function_inventory.expected_edge_actor');
DO $$
DECLARE
  v_row record;
  v_oid oid;
  v_mismatches text[] := '{}';
BEGIN
  FOR v_row IN SELECT * FROM private.function_inventory LOOP
    SELECT p.oid INTO v_oid
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_row.schema_name AND p.proname = v_row.function_name
      AND pg_get_function_identity_arguments(p.oid) = v_row.identity_args;
    IF has_function_privilege('edge_system', v_oid, 'EXECUTE') <> v_row.expected_edge_system THEN
      v_mismatches := v_mismatches || format('%s.%s: edge_system expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_edge_system, has_function_privilege('edge_system', v_oid, 'EXECUTE'));
    END IF;
  END LOOP;
  IF array_length(v_mismatches, 1) > 0 THEN
    RAISE EXCEPTION 'edge_system EXECUTE mismatches: %', array_to_string(v_mismatches, '; ');
  END IF;
END
$$;
SELECT pass('every function''s actual edge_system EXECUTE grant matches private.function_inventory.expected_edge_system');
DO $$
DECLARE
  v_row record;
  v_oid oid;
  v_mismatches text[] := '{}';
BEGIN
  FOR v_row IN SELECT * FROM private.function_inventory LOOP
    SELECT p.oid INTO v_oid
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_row.schema_name AND p.proname = v_row.function_name
      AND pg_get_function_identity_arguments(p.oid) = v_row.identity_args;
    IF has_function_privilege('edge_signin_minter', v_oid, 'EXECUTE') <> v_row.expected_edge_signin_minter THEN
      v_mismatches := v_mismatches || format('%s.%s: edge_signin_minter expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_edge_signin_minter, has_function_privilege('edge_signin_minter', v_oid, 'EXECUTE'));
    END IF;
  END LOOP;
  IF array_length(v_mismatches, 1) > 0 THEN
    RAISE EXCEPTION 'edge_signin_minter EXECUTE mismatches: %', array_to_string(v_mismatches, '; ');
  END IF;
END
$$;
SELECT pass('every function''s actual edge_signin_minter EXECUTE grant matches private.function_inventory.expected_edge_signin_minter (0041: exactly one function)');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE expected_edge_signin_minter), 1, 'edge_signin_minter: the inventory expects it to execute exactly ONE function');
SELECT is(
  (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'private' AND c.relname IN ('actor_binding', 'edge_policy_allowlist') AND c.relrowsecurity AND c.relforcerowsecurity),
  2, 'the two tables 0030/0031 add to schema private keep ENABLE + FORCE ROW LEVEL SECURITY');

-- The four checks, as session-local functions returning the violation list (NULL = clean).
CREATE FUNCTION pg_temp.edge_check_9() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
WITH RECURSIVE edge AS (
  SELECT oid, rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter')
), closure(roleid, path) AS (
  SELECT e.oid, ARRAY[e.oid] FROM edge e
  UNION
  SELECT m.roleid, c.path || m.roleid FROM closure c JOIN pg_auth_members m ON m.member = c.roleid WHERE NOT (m.roleid = ANY (c.path))
)
SELECT 'an edge role can reach a role outside the edge set: ' || r.rolname
FROM closure c JOIN pg_roles r ON r.oid = c.roleid WHERE c.roleid NOT IN (SELECT oid FROM edge)
UNION ALL
SELECT 'edge role attribute: ' || r.rolname || ' has ' || a.attr
FROM pg_roles r CROSS JOIN LATERAL (VALUES ('SUPERUSER', r.rolsuper), ('BYPASSRLS', r.rolbypassrls), ('CREATEROLE', r.rolcreaterole),
  ('CREATEDB', r.rolcreatedb), ('REPLICATION', r.rolreplication), ('INHERIT', r.rolinherit)) AS a(attr, is_on)
WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter') AND a.is_on
UNION ALL
SELECT 'edge role can log in but must not: ' || rolname FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter') AND rolcanlogin
UNION ALL
SELECT 'role ' || m.rolname || ' can SET ROLE to / inherit from edge role ' || r.rolname
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter') AND m.rolname NOT IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter') AND (am.set_option OR am.inherit_option)
UNION ALL
SELECT 'edge role membership holds ADMIN OPTION for a role that is neither a superuser nor a CREATEROLE role (only the migrating role may): ' || m.rolname || ' -> ' || r.rolname
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter') AND am.admin_option AND NOT (m.rolsuper OR m.rolcreaterole)
UNION ALL
SELECT 'edge_gateway is not a SET TRUE, INHERIT FALSE member of ' || t.rolname
FROM pg_roles t WHERE t.rolname IN ('edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter')
  AND NOT EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.member
                  WHERE am.roleid = t.oid AND g.rolname = 'edge_gateway' AND am.set_option AND NOT am.inherit_option)
UNION ALL
SELECT 'edge_gateway membership of ' || r.rolname || ' has INHERIT or lacks SET (every grant row must be SET TRUE, INHERIT FALSE)'
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE m.rolname = 'edge_gateway' AND r.rolname IN ('edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter') AND (am.inherit_option OR NOT am.set_option)
UNION ALL
SELECT 'edge role is missing (migration 0041 creates edge_signin_minter, 0047 edge_partner and edge_partner_minter): ' || n.rolname
FROM (VALUES ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) n(rolname) WHERE NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = n.rolname)
UNION ALL
SELECT m.rolname || ' is a member of ' || r.rolname || ' (the minter must be a member of nothing)'
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member WHERE m.rolname IN ('edge_signin_minter', 'edge_partner', 'edge_partner_minter')
UNION ALL
SELECT 'edge role ' || m.rolname || ' is a member of ' || r.rolname || ' (only edge_gateway may be)'
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('edge_signin_minter', 'edge_partner', 'edge_partner_minter') AND m.rolname IN ('edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter')
UNION ALL
SELECT 'owner role is missing (migration 0047 creates it): ' || n.rolname
FROM (VALUES ('partner_session_toucher'), ('partner_session_issuer'), ('partner_pin_verifier'), ('partner_totp_verifier'), ('partner_reauth_verifier')) n(rolname)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = n.rolname)
UNION ALL
SELECT 'owner role attribute: ' || r.rolname || ' has ' || a.attr
FROM pg_roles r CROSS JOIN LATERAL (VALUES ('SUPERUSER', r.rolsuper), ('BYPASSRLS', r.rolbypassrls), ('CREATEROLE', r.rolcreaterole),
  ('CREATEDB', r.rolcreatedb), ('REPLICATION', r.rolreplication), ('INHERIT', r.rolinherit), ('LOGIN', r.rolcanlogin)) AS a(attr, is_on)
WHERE r.rolname IN ('partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier') AND a.is_on
UNION ALL
SELECT 'owner role ' || m.rolname || ' is a member of ' || r.rolname || ' (an owner role must be a member of nothing)'
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE m.rolname IN ('partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier')
UNION ALL
SELECT 'role ' || m.rolname || ' is a member of owner role ' || r.rolname || ' (an owner role has no member; the migrating role may keep ADMIN only, never SET or INHERIT)'
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier')
  AND NOT m.rolsuper AND (NOT m.rolcreaterole OR am.set_option OR am.inherit_option)
  ) AS t(v)
$f$;

CREATE FUNCTION pg_temp.edge_check_10() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
WITH live AS (
  SELECT n.nspname AS schema_name, cl.relname AS table_name, pol.polname AS policy_name, pol.oid AS pol_oid,
         CASE pol.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' END AS command,
         CASE WHEN pol.polroles = ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'edge_actor')] THEN 'edge_actor'
              WHEN pol.polroles = ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'edge_system')] THEN 'edge_system'
              ELSE 'MULTI_OR_PUBLIC' END AS role_name,
         pg_get_expr(pol.polqual, pol.polrelid) AS using_expr, pg_get_expr(pol.polwithcheck, pol.polrelid) AS with_check_expr
  FROM pg_policy pol
  JOIN pg_class cl ON cl.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = cl.relnamespace
  WHERE pol.polroles @> ARRAY[0]::oid[]
     OR pol.polroles && ARRAY(SELECT oid FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system'))
)
SELECT 'live edge policy missing from private.edge_policy_allowlist, or its role/command/text differs: ' || l.schema_name || '.' || l.table_name || '.' || l.policy_name
FROM live l
WHERE NOT EXISTS (
  SELECT 1 FROM private.edge_policy_allowlist al
  WHERE al.schema_name = l.schema_name AND al.table_name = l.table_name AND al.policy_name = l.policy_name
    AND al.command = l.command AND al.role_name = l.role_name
    AND al.using_expr IS NOT DISTINCT FROM l.using_expr AND al.with_check_expr IS NOT DISTINCT FROM l.with_check_expr)
UNION ALL
SELECT 'private.edge_policy_allowlist row names no matching live policy: ' || al.schema_name || '.' || al.table_name || '.' || al.policy_name
FROM private.edge_policy_allowlist al
WHERE NOT EXISTS (
  SELECT 1 FROM live l
  WHERE al.schema_name = l.schema_name AND al.table_name = l.table_name AND al.policy_name = l.policy_name
    AND al.command = l.command AND al.role_name = l.role_name
    AND al.using_expr IS NOT DISTINCT FROM l.using_expr AND al.with_check_expr IS NOT DISTINCT FROM l.with_check_expr)
UNION ALL
SELECT 'a policy applies to ' || r.rolname || ' (it may have none): ' || n.nspname || '.' || cl.relname || '.' || pol.polname
FROM pg_policy pol JOIN pg_class cl ON cl.oid = pol.polrelid JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN pg_roles r ON r.oid = ANY (pol.polroles) AND r.rolname IN ('edge_signin_minter', 'edge_partner', 'edge_partner_minter')
  ) AS t(v)
$f$;

CREATE FUNCTION pg_temp.edge_check_11() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
WITH live AS (
  SELECT n.nspname AS schema_name, cl.relname AS table_name, pol.polname AS policy_name, pol.oid AS pol_oid,
         CASE pol.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' END AS command,
         CASE WHEN pol.polroles = ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'edge_actor')] THEN 'edge_actor'
              WHEN pol.polroles = ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'edge_system')] THEN 'edge_system'
              ELSE 'MULTI_OR_PUBLIC' END AS role_name,
         pg_get_expr(pol.polqual, pol.polrelid) AS using_expr, pg_get_expr(pol.polwithcheck, pol.polrelid) AS with_check_expr
  FROM pg_policy pol
  JOIN pg_class cl ON cl.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = cl.relnamespace
  WHERE pol.polroles @> ARRAY[0]::oid[]
     OR pol.polroles && ARRAY(SELECT oid FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system'))
)
SELECT 'edge policy reads an identity source other than private.actor_uid(): ' || l.schema_name || '.' || l.table_name || '.' || l.policy_name
FROM live l
WHERE (coalesce(l.using_expr, '') || ' ' || coalesce(l.with_check_expr, '')) ~* '(auth\.(uid|jwt|role|email)\s*\(|current_setting\s*\(|set_config\s*\(|request\.jwt|session_user|current_user)'
UNION ALL
SELECT 'edge policy depends on function ' || fp.oid::regprocedure::text || ': ' || l.schema_name || '.' || l.table_name || '.' || l.policy_name
FROM live l
JOIN pg_depend d ON d.classid = 'pg_policy'::regclass AND d.objid = l.pol_oid AND d.refclassid = 'pg_proc'::regclass
JOIN pg_proc fp ON fp.oid = d.refobjid
WHERE fp.oid::regprocedure::text NOT IN ('private.actor_uid()', 'private.account_pseudonyms(uuid)')
UNION ALL
SELECT 'actor-scope edge policy does not contain private.actor_uid(): ' || l.schema_name || '.' || l.table_name || '.' || l.policy_name
FROM live l JOIN private.edge_policy_allowlist al
  ON al.schema_name = l.schema_name AND al.table_name = l.table_name AND al.policy_name = l.policy_name
WHERE al.scope = 'actor' AND (coalesce(l.using_expr, '') || ' ' || coalesce(l.with_check_expr, '')) NOT LIKE '%private.actor_uid()%'
UNION ALL
SELECT 'open_read edge policy is not SELECT USING (true): ' || al.schema_name || '.' || al.table_name || '.' || al.policy_name
FROM private.edge_policy_allowlist al
WHERE al.scope = 'open_read' AND (al.command <> 'SELECT' OR al.using_expr IS DISTINCT FROM 'true' OR al.role_name <> 'edge_actor')
UNION ALL
SELECT 'edge_system policy is not system_write scope: ' || al.schema_name || '.' || al.table_name || '.' || al.policy_name
FROM private.edge_policy_allowlist al
WHERE al.role_name = 'edge_system' AND al.scope <> 'system_write'
  ) AS t(v)
$f$;

CREATE FUNCTION pg_temp.edge_check_12() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
WITH pii AS (
  SELECT schema_name, table_name FROM private.pii_retention_policy
  UNION
  SELECT schema_name, table_name FROM private.pii_export_policy
)
SELECT 'edge_system has a policy on a PII-registered table: ' || n.nspname || '.' || cl.relname || '.' || pol.polname
FROM pg_policy pol JOIN pg_class cl ON cl.oid = pol.polrelid JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN pii ON pii.schema_name = n.nspname AND pii.table_name = cl.relname
WHERE pol.polroles @> ARRAY[0]::oid[] OR pol.polroles @> ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'edge_system')]
UNION ALL
SELECT 'edge_system holds a privilege on a PII-registered table: ' || n.nspname || '.' || cl.relname
FROM pii JOIN pg_namespace n ON n.nspname = pii.schema_name JOIN pg_class cl ON cl.relnamespace = n.oid AND cl.relname = pii.table_name
WHERE has_any_column_privilege('edge_system', cl.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_system', cl.oid, 'DELETE,TRUNCATE,TRIGGER')
UNION ALL
SELECT 'an edge role holds a privilege on a table outside app, or on an app table without FORCE ROW LEVEL SECURITY: ' || n.nspname || '.' || cl.relname || ' (' || r.rolname || ')'
FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter')) r
WHERE cl.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = cl.oid AND d.deptype = 'e')
  AND (has_any_column_privilege(r.rolname, cl.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.rolname, cl.oid, 'DELETE,TRUNCATE,TRIGGER'))
  AND (n.nspname <> 'app' OR NOT (cl.relrowsecurity AND cl.relforcerowsecurity))
UNION ALL
SELECT 'an edge role can CREATE in schema ' || n.nspname || ' (' || r.rolname || ')'
FROM pg_namespace n
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter')) r
WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
  AND has_schema_privilege(r.rolname, n.oid, 'CREATE')
UNION ALL
SELECT r.rolname || ' holds a privilege on a relation (it may hold none, in any schema): ' || n.nspname || '.' || cl.relname
FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_signin_minter', 'edge_partner', 'edge_partner_minter')) r
WHERE cl.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = cl.oid AND d.deptype = 'e')
  AND CASE WHEN cl.relkind = 'S' THEN has_sequence_privilege(r.rolname, cl.oid, 'USAGE,SELECT,UPDATE')
           ELSE has_any_column_privilege(r.rolname, cl.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.rolname, cl.oid, 'DELETE,TRUNCATE,TRIGGER') END
UNION ALL
SELECT r.rolname || ' has USAGE on schema app (edge_partner and its minter name nothing there)'
FROM pg_roles r WHERE r.rolname IN ('edge_partner', 'edge_partner_minter') AND has_schema_privilege(r.rolname, 'app', 'USAGE')
UNION ALL
SELECT 'owner role holds a privilege that private.partner_owner_privilege does not list: ' || a.role_name || ' ' || a.privilege || ' ON ' || a.object_kind || ' ' || a.object_name || coalesce('.' || a.column_name, '')
FROM (
  SELECT o.rolname::text AS role_name, 'schema'::text AS object_kind, n.nspname::text AS object_name, a.privilege_type::text AS privilege, NULL::text AS column_name
  FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a JOIN pg_roles o ON o.oid = a.grantee
  WHERE o.rolname IN ('partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier') AND a.grantee <> n.nspowner
  UNION ALL
  SELECT o.rolname::text, 'relation', n.nspname || '.' || c.relname, a.privilege_type::text, NULL
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles o ON o.oid = a.grantee
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND a.grantee <> c.relowner
    AND o.rolname IN ('partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier')
  UNION ALL
  SELECT o.rolname::text, 'column', n.nspname || '.' || c.relname, a.privilege_type::text, att.attname::text
  FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(att.attacl) a JOIN pg_roles o ON o.oid = a.grantee
  WHERE att.attnum > 0 AND NOT att.attisdropped
    AND o.rolname IN ('partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier')
  UNION ALL
  SELECT o.rolname::text, 'function', p.oid::regprocedure::text, a.privilege_type::text, NULL
  FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles o ON o.oid = a.grantee
  WHERE a.grantee <> p.proowner AND o.rolname IN ('partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier')
) a
WHERE NOT EXISTS (SELECT 1 FROM private.partner_owner_privilege e
                  WHERE e.role_name = a.role_name AND e.object_kind = a.object_kind AND e.object_name = a.object_name AND e.privilege = a.privilege AND e.column_name IS NOT DISTINCT FROM a.column_name)
UNION ALL
SELECT 'private.partner_owner_privilege lists a privilege the role does not hold: ' || e.role_name || ' ' || e.privilege || ' ON ' || e.object_kind || ' ' || e.object_name || coalesce('.' || e.column_name, '')
FROM private.partner_owner_privilege e
WHERE NOT EXISTS (
  SELECT 1 FROM (
    SELECT o.rolname::text AS role_name, 'schema'::text AS object_kind, n.nspname::text AS object_name, a.privilege_type::text AS privilege, NULL::text AS column_name
    FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a JOIN pg_roles o ON o.oid = a.grantee WHERE a.grantee <> n.nspowner
    UNION ALL
    SELECT o.rolname::text, 'relation', n.nspname || '.' || c.relname, a.privilege_type::text, NULL
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_roles o ON o.oid = a.grantee
    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND a.grantee <> c.relowner
    UNION ALL
    SELECT o.rolname::text, 'column', n.nspname || '.' || c.relname, a.privilege_type::text, att.attname::text
    FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(att.attacl) a JOIN pg_roles o ON o.oid = a.grantee
    WHERE att.attnum > 0 AND NOT att.attisdropped
    UNION ALL
    SELECT o.rolname::text, 'function', p.oid::regprocedure::text, a.privilege_type::text, NULL
    FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles o ON o.oid = a.grantee WHERE a.grantee <> p.proowner
  ) a
  WHERE e.role_name = a.role_name AND e.object_kind = a.object_kind AND e.object_name = a.object_name AND e.privilege = a.privilege AND e.column_name IS NOT DISTINCT FROM a.column_name)
  ) AS t(v)
$f$;


CREATE FUNCTION pg_temp.edge_check_13() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
SELECT 'SECURITY DEFINER function reads an unqualified pg_ relation (a temp relation of that name would shadow the catalog): ' || n.nspname || '.' || p.proname || ' -> ' || m[1]
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN LATERAL regexp_matches(regexp_replace(p.prosrc, '--[^\n]*', '', 'g'), '(?:\m(?:from|join|update|into|table|using)\s+|,\s*)(pg_[a-z_]+)\M(?!\.|\s*\()', 'gi') AS m
WHERE p.prosecdef AND n.nspname IN ('app', 'api', 'private')
  ) AS t(v)
$f$;

CREATE FUNCTION pg_temp.edge_check_14() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
WITH RECURSIVE fam AS (
  SELECT p.oid, n.nspname, p.proname, l.lanname, p.prosrc AS raw,
         n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS ident,
         regexp_replace(p.prosrc, '((?:/\*(?:[^*]|\*+[^*/])*\*+/)|(?:--[^\n]*))|(''(?:[^'']|'''')*'')', ' \2', 'g') AS kept
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
  WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND p.proname LIKE '%\_for\_partner'
), body AS (
  SELECT f.*, trim(lower(regexp_replace(regexp_replace(f.kept, '''(?:[^'']|'''')*''', '''''', 'g'), '\s+', ' ', 'g'))) AS b
  FROM fam f
), first AS (
  SELECT f.oid, f.nspname, f.proname,
         trim(split_part(CASE WHEN f.lanname = 'plpgsql' THEN coalesce(substring(f.b from '(?:^| )begin (.*)$'), '') ELSE f.b END, ';', 1)) AS stmt
  FROM body f
), collapse(oid, nspname, proname, s, n) AS (
  SELECT oid, nspname, proname, stmt, 0 FROM first
  UNION ALL
  SELECT oid, nspname, proname, regexp_replace(s, '\([^()]*\)', '', 'g'), n + 1 FROM collapse WHERE n < 12 AND s ~ '[()]'
)
SELECT '(a) a *_for_partner function whose first executable statement is not a call of private.partner_authorize: ' || c.nspname || '.' || c.proname
FROM collapse c
WHERE c.n = (SELECT max(c2.n) FROM collapse c2 WHERE c2.oid = c.oid)
  AND c.s !~ '^(perform |[a-z_][a-z0-9_]* := |select )private\.partner_authorize\s*( into [a-z_][a-z0-9_]*)?\s*$'
UNION ALL
SELECT '(a0) a *_for_partner function body contains a dollar quote, a double-quoted identifier, a backslash, an E-string or a nested comment, which the first-statement check cannot lex: ' || f.ident
FROM fam f
WHERE strpos(f.raw, chr(36)) > 0 OR strpos(f.raw, chr(34)) > 0 OR strpos(f.raw, chr(92)) > 0 OR f.raw ~* '(^|[^a-z0-9_])e'''
   OR strpos(f.kept, '/*') > 0 OR strpos(f.kept, '*/') > 0
UNION ALL
SELECT '(a2) a *_for_partner function has an EXCEPTION ... WHEN block, which could swallow the 42501 of private.partner_authorize: ' || f.ident
FROM body f
WHERE f.b ~ '\mexception\s+when\M'
UNION ALL
SELECT '(a3) a *_for_partner function whose private.partner_authorize class is not a string literal in A0 / A0_WRITE / A0_KEEPALIVE / A0_MFA / A0_ENROL / A1 / A2 / A3 (SESSION and PEEK only for a function named in supabase/tests/fixtures/partner_session_class_functions.txt): ' || c.ident
FROM (
  SELECT f.ident,
         (regexp_match((regexp_match(f.kept, 'private\.partner_authorize\s*\(([^;]*)\)\s*(?:;|$)', 'i'))[1], ',\s*''([A-Za-z0-9_]+)''\s*$'))[1] AS cls
  FROM fam f
) c
WHERE c.cls IS NULL
   OR (c.cls NOT IN ('A0', 'A0_WRITE', 'A0_KEEPALIVE', 'A0_MFA', 'A0_ENROL', 'A1', 'A2', 'A3') AND NOT (c.cls IN ('SESSION', 'PEEK') AND c.ident = ANY (/* session_class_functions */ ARRAY['private.partner_whoami_for_partner()', 'private.partner_session_revoke_for_partner()', 'private.partner_session_lock_for_partner()'] /* end_session_class_functions */)))
UNION ALL
SELECT '(b) an edge_actor-executable definer outside the *_for_partner family evaluates partner scope: ' || n.nspname || '.' || p.proname
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND p.prosecdef AND has_function_privilege('edge_actor', p.oid, 'EXECUTE')
  AND p.proname NOT LIKE '%\_for\_partner'
  AND regexp_replace(p.prosrc, '(?:/\*(?:[^*]|\*+[^*/])*\*+/)|(?:--[^\n]*)|(?:''(?:[^'']|'''')*'')', ' ', 'g')
        ~* '\m(has_facility_scope|has_trail_scope|has_sponsorship_scope|is_staff_or_manager_of_facility|is_manager_or_operator_of_facility|is_operator_of_facility|is_org_member|is_admin|partner_member|partner_scope)\M'
UNION ALL
SELECT '(c) a function outside the *_for_partner family reads the actor binding or kind = ''partner'' (put it in the family, or name it in supabase/tests/fixtures/partner_kind_readers.txt after review): ' || n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f'
  AND p.proname NOT LIKE '%\_for\_partner'
  AND (regexp_replace(p.prosrc, '((?:/\*(?:[^*]|\*+[^*/])*\*+/)|(?:--[^\n]*))|(''(?:[^'']|'''')*'')', ' \2', 'g') ~ '''partner'''
       OR regexp_replace(p.prosrc, '((?:/\*(?:[^*]|\*+[^*/])*\*+/)|(?:--[^\n]*))|(''(?:[^'']|'''')*'')', ' \2', 'g') ~* '\m(actor_binding|partner_binding(_kind|_session)?)\M')
  AND (n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')') <> ALL (/* kind_readers */ ARRAY['private.actor_uid()', 'private.bind_actor_internal(p_uid uuid, p_kind text)', 'private.bind_partner_session(p_token_hash text)', 'private.partner_binding()', 'private.partner_binding_kind()', 'private.partner_binding_session()', 'private.partner_authorize(p_facility_id text, p_trail_id text, p_roles app.partner_role[], p_class text)', 'private.partner_audit_write(p_action text, p_subject_table text, p_subject_id text, p_detail jsonb)', 'private.partner_authority_revoke_sessions()', 'private.partner_pin_grant_consume()', 'private.activate_entitlement_for_actor(p_entitlement_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb)', 'private.activate_offer_code_for_actor(p_code_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb)', 'private.claim_device_platform_for_actor(p_device_id uuid, p_platform text)', 'private.delete_my_data_for_actor()', 'private.export_my_data_for_actor()', 'private.offline_code_bound_staff()', 'private.offline_code_record_step_for_actor(p_device_id uuid, p_seed_version integer, p_step bigint, p_facility_id text)', 'private.offline_seed_for_actor(p_device_id uuid, p_rotate boolean)', 'private.register_attest_key_for_actor(p_device_id uuid, p_key_id text, p_public_key bytea)', 'private.signin_bound_user(p_who text)', 'private.signin_record_email_proof(p_caller_user_id uuid, p_target_user_id uuid, p_email text, p_provider text, p_provider_sub text, p_session_id uuid)', 'private.course_pin_attempt_for_actor(p_facility_id text, p_pin text, p_at timestamp with time zone)', 'private.course_qr_public_key_for_actor(p_kid text, p_purpose text)', 'private.marker_cosignal_attach_for_actor(p_facility_id text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid)', 'private.offer_offline_confirm_for_actor(p_facility_id text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid)', 'private.receipt_intake_for_actor(p_facility_id text, p_phash text, p_storage_object text, p_local_date date, p_receipt_number_ocr text)', 'private.marker_scan_for_actor(p_facility_id text, p_variant text, p_nonce_hash text, p_qr_kid text, p_pin text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid)', 'private.partner_challenge_issue_sign_in()', 'private.partner_session_mint(p_token_hash text, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)', 'private.hit_partner_rate_limit(p_bucket_key text, p_window interval, p_max integer)', 'private.partner_credential_lookup(p_credential_id bytea)', 'private.partner_sign_in_failure_record(p_credential_id bytea)', 'private.partner_reauth_apply(p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)', 'private.partner_reauth_clear()', 'private.partner_binding_user()', 'private.partner_pin_verify_apply(p_derived bytea)', 'private.partner_pin_set_apply(p_mode text, p_derived bytea, p_salt bytea, p_iterations integer, p_current bytea)', 'private.partner_pin_params_read()', 'private.partner_pin_grant_consume_fresh(p_max_age_seconds integer)', 'private.partner_totp_enrol_apply()', 'private.partner_totp_confirm_apply(p_code text)', 'private.partner_totp_verify_apply(p_code text)', 'private.partner_totp_mfa_clear()', 'private.partner_challenge_issue_register(p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint)', 'private.partner_invite_email_for_token(p_token_hash text)', 'private.partner_invite_accept(p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid)', 'private.partner_enrolment_token_email_for_token(p_token_hash text)', 'private.partner_enrolment_token_accept(p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid)', 'private.partner_credential_register_first(p_token_hash text, p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_nonce bytea, p_exp bigint, p_mac bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[])', 'private.partner_bound_staff_at(p_facility_id text)', 'private.partner_bound_manager_at(p_facility_id text)', 'private.partner_bound_staff_any()', 'private.partner_bound_admin()', 'private.partner_bound_operator_at_trail(p_trail_id text)'] /* end_kind_readers */)
UNION ALL
SELECT '(d) a *_for_partner function is EXECUTE-able by edge_actor, edge_system or PUBLIC (the partner lane is edge_partner alone): ' || n.nspname || '.' || p.proname
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND p.proname LIKE '%\_for\_partner'
  AND (has_function_privilege('edge_actor', p.oid, 'EXECUTE') OR has_function_privilege('edge_system', p.oid, 'EXECUTE')
       OR EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))
UNION ALL
SELECT '(e) edge_partner holds an EXECUTE grant outside its allowed set (bind_partner_session, partner_binding, partner_binding_kind, hit_partner_rate_limit and the *_for_partner family): ' || n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind IN ('f', 'p') AND has_function_privilege('edge_partner', p.oid, 'EXECUTE')
  AND (n.nspname || '.' || p.proname || '(' || oidvectortypes(p.proargtypes) || ')') <> ALL (ARRAY['private.bind_partner_session(text)', 'private.partner_binding()', 'private.partner_binding_kind()', 'private.hit_partner_rate_limit(text, interval, integer)'])
  AND p.proname NOT LIKE '%\_for\_partner'

  ) AS t(v)
$f$;

CREATE FUNCTION pg_temp.edge_check_15() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
WITH tails(tail) AS (
  VALUES (' AND (private.partner_binding_kind() IS DISTINCT FROM ''partner''::text))'),
         (' AND (( SELECT private.partner_binding_kind() AS partner_binding_kind) IS DISTINCT FROM ''partner''::text))')
), exprs AS (
  SELECT n.nspname, c.relname, pol.polname, 'USING' AS part, pg_get_expr(pol.polqual, pol.polrelid) AS e, pol.oid AS poloid
  FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE pol.polroles = ARRAY[(SELECT r.oid FROM pg_roles r WHERE r.rolname = 'private_definer')]
  UNION ALL
  SELECT n.nspname, c.relname, pol.polname, 'WITH CHECK', pg_get_expr(pol.polwithcheck, pol.polrelid), pol.oid
  FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE pol.polroles = ARRAY[(SELECT r.oid FROM pg_roles r WHERE r.rolname = 'private_definer')]
), win AS (
  SELECT * FROM exprs x WHERE x.e IS NOT NULL AND (x.e ~* '\mcurrent_setting\s*\(' OR x.e ~* '\mpg_settings\M'
    OR EXISTS (SELECT 1 FROM pg_depend d JOIN pg_proc fp ON fp.oid = d.refobjid WHERE d.classid = 'pg_policy'::regclass AND d.objid = x.poloid AND d.refclassid = 'pg_proc'::regclass
      AND (CASE WHEN fp.prokind IN ('f', 'p') THEN pg_get_functiondef(fp.oid) END ~* '\mcurrent_setting\s*\(' OR CASE WHEN fp.prokind IN ('f', 'p') THEN pg_get_functiondef(fp.oid) END ~* '\mpg_settings\M')))
), trail AS (
  SELECT w.nspname, w.relname, w.polname, w.part, left(w.e, length(w.e) - length(t.tail)) AS prefix
  FROM win w JOIN tails t ON right(w.e, length(t.tail)) = t.tail
), depth AS (
  SELECT tr.nspname, tr.relname, tr.polname, tr.part, min(x.d) AS lo, (array_agg(x.d ORDER BY x.i DESC))[1] AS hi
  FROM trail tr
  CROSS JOIN LATERAL (
    SELECT s.i, sum(CASE s.ch WHEN '(' THEN 1 WHEN ')' THEN -1 ELSE 0 END) OVER (ORDER BY s.i) AS d
    FROM regexp_split_to_table(regexp_replace(tr.prefix, '''(?:[^'']|'''')*''', '', 'g'), '') WITH ORDINALITY AS s(ch, i)
  ) x
  GROUP BY tr.nspname, tr.relname, tr.polname, tr.part
)
SELECT DISTINCT '(15) a GUC-keyed private_definer policy is OPEN under a partner binding (end its USING / WITH CHECK that reads the setting with the TOP-LEVEL conjunct AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM ''partner'' (or the direct call); an OR-form, a conjunct that is not the LAST top-level AND, or one buried in another expression does not count): ' || w.nspname || '.' || w.relname || '.' || w.polname
FROM win w
WHERE NOT EXISTS (SELECT 1 FROM depth d WHERE d.nspname = w.nspname AND d.relname = w.relname AND d.polname = w.polname AND d.part = w.part AND d.lo >= 1 AND d.hi = 1)
  ) AS t(v)
$f$;

-- ---- check 9: the membership closure of the three edge roles is clean ----
SELECT is(pg_temp.edge_check_9(), NULL::text[], 'check 9: no edge role reaches a role outside {edge_gateway, edge_actor, edge_system}; none holds SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION/INHERIT; only edge_gateway can log in; nobody else can SET ROLE to one');
SELECT tests.clear_actor();
CREATE ROLE zz_edge_member NOLOGIN;
GRANT zz_edge_member TO edge_system;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%zz_edge_member%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL: edge_system made a member of another role (the closure reaches zz_edge_member)');
SELECT tests.clear_actor();
REVOKE zz_edge_member FROM edge_system;
ALTER ROLE edge_actor CREATEROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%edge_actor has CREATEROLE%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL: edge_actor given CREATEROLE');
SELECT tests.clear_actor();
ALTER ROLE edge_actor NOCREATEROLE;
GRANT edge_actor TO zz_edge_member WITH SET TRUE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%zz_edge_member can SET ROLE to / inherit from edge role edge_actor%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL: another role can SET ROLE to edge_actor');
SELECT tests.clear_actor();
REVOKE edge_actor FROM zz_edge_member;
GRANT edge_actor TO zz_edge_member WITH ADMIN TRUE, SET FALSE, INHERIT FALSE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%ADMIN OPTION%zz_edge_member -> edge_actor') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (L2): a non-superuser, non-CREATEROLE role holds ADMIN OPTION on edge_actor (it could re-grant it)');
SELECT is((SELECT bool_or(v LIKE '%SET ROLE to / inherit from%') FROM unnest(pg_temp.edge_check_9()) v), false, 'check 9 (L2): ... and ONLY the admin finding fires (the membership has neither SET nor INHERIT)');
SELECT tests.clear_actor();
REVOKE edge_actor FROM zz_edge_member;
DROP ROLE zz_edge_member;

-- ---- check 10: the live edge policies equal private.edge_policy_allowlist, both directions ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_10(), NULL::text[], 'check 10: every policy that applies to edge_actor / edge_system (or PUBLIC) is in private.edge_policy_allowlist with the same role, command and text, and every row names a live policy');
SELECT tests.clear_actor();
CREATE POLICY zz_edge_probe ON app.play FOR SELECT TO edge_actor USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%app.play.zz_edge_probe%') FROM unnest(pg_temp.edge_check_10()) v), true, 'check 10 MUST FAIL: a policy added for edge_actor with no allowlist row');
SELECT tests.clear_actor();
DROP POLICY zz_edge_probe ON app.play;
ALTER POLICY edge_actor_play_select ON app.play USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%app.play.edge_actor_play_select%') FROM unnest(pg_temp.edge_check_10()) v), true, 'check 10 MUST FAIL: a registered policy whose USING was broadened to true');
SELECT tests.clear_actor();
ALTER POLICY edge_actor_play_select ON app.play USING (user_id = (SELECT private.actor_uid()));
DROP POLICY edge_actor_device_update ON app.device;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'private.edge_policy_allowlist row names no matching live policy: app.device.edge_actor_device_update') FROM unnest(pg_temp.edge_check_10()) v), true, 'check 10 MUST FAIL: an allowlist row whose policy was dropped (stale row)');

-- ---- check 11: edge_actor policies reference private.actor_uid() only ----
SELECT tests.clear_actor();
CREATE POLICY edge_actor_device_update ON app.device FOR UPDATE TO edge_actor USING (user_id = (SELECT private.actor_uid())) WITH CHECK (user_id = (SELECT private.actor_uid()));
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_11(), NULL::text[], 'check 11: no edge policy reads auth.uid()/auth.jwt()/current_setting()/session_user/current_user, none depends on a function but private.actor_uid(), every actor-scope policy contains it, every open_read policy is SELECT USING (true)');
SELECT tests.clear_actor();
CREATE POLICY zz_edge_auth ON app.play FOR SELECT TO edge_actor USING (user_id = auth.uid());
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%identity source%app.play.zz_edge_auth') FROM unnest(pg_temp.edge_check_11()) v), true, 'check 11 MUST FAIL: an edge_actor policy keyed on auth.uid()');
SELECT tests.clear_actor();
DROP POLICY zz_edge_auth ON app.play;
CREATE POLICY zz_edge_guc ON app.play FOR SELECT TO edge_actor USING (user_id = nullif(current_setting('request.jwt.claim.sub', true), '')::uuid);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%identity source%app.play.zz_edge_guc') FROM unnest(pg_temp.edge_check_11()) v), true, 'check 11 MUST FAIL: an edge_actor policy keyed on a GUC');
SELECT tests.clear_actor();
DROP POLICY zz_edge_guc ON app.play;
ALTER POLICY edge_actor_play_select ON app.play USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'actor-scope edge policy does not contain private.actor_uid(): app.play.edge_actor_play_select') FROM unnest(pg_temp.edge_check_11()) v), true, 'check 11 MUST FAIL: an actor-scope policy that does not use private.actor_uid() at all');
SELECT tests.clear_actor();
ALTER POLICY edge_actor_play_select ON app.play USING (user_id = (SELECT private.actor_uid()));

-- ---- check 12: edge_system has nothing on personal data; edge roles hold privileges only on FORCE-RLS app tables ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_12(), NULL::text[], 'check 12: no edge_system policy or privilege on any PII-registered table; no edge role holds a privilege outside app or on an app table without FORCE RLS');
SELECT tests.clear_actor();
CREATE POLICY zz_edge_system_pii ON app.evidence FOR SELECT TO edge_system USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_system has a policy on a PII-registered table: app.evidence.zz_edge_system_pii') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL: an edge_system policy on app.evidence');
SELECT tests.clear_actor();
DROP POLICY zz_edge_system_pii ON app.evidence;
CREATE POLICY zz_public_pii ON app.play FOR SELECT TO PUBLIC USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_system has a policy on a PII-registered table: app.play.zz_public_pii') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL: a PUBLIC policy on app.play (it applies to edge_system too)');
SELECT tests.clear_actor();
DROP POLICY zz_public_pii ON app.play;
GRANT SELECT ON app.play TO edge_system;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_system holds a privilege on a PII-registered table: app.play') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL: a table GRANT to edge_system on app.play (no policy needed to be wrong)');
SELECT tests.clear_actor();
REVOKE SELECT ON app.play FROM edge_system;
GRANT SELECT ON private.consumed_nonce TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%private.consumed_nonce (edge_actor)') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL: edge_actor granted a table in schema private');
SELECT tests.clear_actor();
REVOKE SELECT ON private.consumed_nonce FROM edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_12(), NULL::text[], 'check 12: clean again after the earlier fixtures are undone');
-- 0032 L2: every non-system schema is covered (not a fixed list), and schema CREATE is checked.
SELECT tests.clear_actor();
CREATE SCHEMA zz_edge_schema;
CREATE TABLE zz_edge_schema.zz_edge_t (a int);
GRANT USAGE ON SCHEMA zz_edge_schema TO edge_actor;
GRANT SELECT ON zz_edge_schema.zz_edge_t TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%zz_edge_schema.zz_edge_t (edge_actor)') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (L2): an edge role granted a table in a schema that is NOT in the old fixed list (zz_edge_schema)');
SELECT tests.clear_actor();
GRANT CREATE ON SCHEMA zz_edge_schema TO edge_system;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'an edge role can CREATE in schema zz_edge_schema (edge_system)') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (L2): edge_system can CREATE in a schema');
SELECT tests.clear_actor();
DROP SCHEMA zz_edge_schema CASCADE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_12(), NULL::text[], 'check 12: clean again after the schema fixtures are dropped (postgis'' own public tables are exempt)');

-- ---- 0041 (PR #35): the proof-minter role edge_signin_minter, in checks 2, 9, 10 and 12 ----
CREATE FUNCTION pg_temp.minter_exec_mismatches() RETURNS text[] LANGUAGE sql AS $f$
  SELECT array_agg(v ORDER BY v) FROM (
    SELECT r.rolname || ' EXECUTE on ' || fi.function_name || ': expected=' || r.exp || ' actual=' || has_function_privilege(r.rolname, p.oid, 'EXECUTE')
    FROM private.function_inventory fi
    JOIN pg_namespace n ON n.nspname = fi.schema_name
    JOIN pg_proc p ON p.pronamespace = n.oid AND p.proname = fi.function_name AND pg_get_function_identity_arguments(p.oid) = fi.identity_args
    CROSS JOIN LATERAL (VALUES ('edge_system', fi.expected_edge_system), ('edge_actor', fi.expected_edge_actor), ('edge_signin_minter', fi.expected_edge_signin_minter), ('service_role', fi.expected_service_role)) r(rolname, exp)
    WHERE has_function_privilege(r.rolname, p.oid, 'EXECUTE') <> r.exp
  ) AS t(v)
$f$;
SELECT is(pg_temp.minter_exec_mismatches(), NULL::text[], 'check 2 (0041): edge_system, edge_actor, service_role and edge_signin_minter hold EXECUTE on exactly what the inventory expects');
SELECT tests.clear_actor();
SET ROLE private_definer;
GRANT EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) TO edge_system;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_system EXECUTE on signin_record_email_proof: expected=false actual=true') FROM unnest(pg_temp.minter_exec_mismatches()) v), true,
  'check 2 MUST FAIL (0041, L1): the mint EXECUTE re-granted to edge_system (any unbound system lane could mint again)');
SELECT tests.clear_actor();
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) FROM edge_system;
GRANT EXECUTE ON FUNCTION private.purge_signin_email_proofs() TO edge_signin_minter;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_signin_minter EXECUTE on purge_signin_email_proofs: expected=false actual=true') FROM unnest(pg_temp.minter_exec_mismatches()) v), true,
  'check 2 MUST FAIL (0041): the minter given EXECUTE on a second function');
SELECT tests.clear_actor();
SET ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.purge_signin_email_proofs() FROM edge_signin_minter;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.minter_exec_mismatches(), NULL::text[], 'check 2 (0041): clean again after the grant fixtures are undone');

SELECT tests.clear_actor();
GRANT edge_actor TO edge_signin_minter;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_signin_minter is a member of edge_actor%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0041): the minter made a member of edge_actor (the minter must be a member of nothing)');
SELECT tests.clear_actor();
REVOKE edge_actor FROM edge_signin_minter;
GRANT edge_signin_minter TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge role edge_actor is a member of edge_signin_minter%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0041): edge_actor made a member of the minter (an actor could SET ROLE into it)');
SELECT tests.clear_actor();
REVOKE edge_signin_minter FROM edge_actor;
ALTER ROLE edge_signin_minter LOGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge role can log in but must not: edge_signin_minter') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0041): the minter given LOGIN');
SELECT tests.clear_actor();
ALTER ROLE edge_signin_minter NOLOGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_9(), NULL::text[], 'check 9 (0041): clean again with the minter in the set (edge_gateway is its one SET TRUE, INHERIT FALSE member)');

SELECT tests.clear_actor();
GRANT edge_signin_minter TO edge_gateway WITH INHERIT TRUE, SET TRUE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_gateway membership of edge_signin_minter has INHERIT or lacks SET%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0041): edge_gateway holds the minter WITH INHERIT (it would hold the minter''s privilege in every lane, not only after a SET ROLE)');
SELECT tests.clear_actor();
GRANT edge_signin_minter TO edge_gateway WITH INHERIT FALSE, SET TRUE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_9(), NULL::text[], 'check 9 (0041): clean again after the membership is restored');

SELECT tests.clear_actor();
CREATE POLICY zz_minter_probe ON app.play FOR SELECT TO edge_signin_minter USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'a policy applies to edge_signin_minter%app.play.zz_minter_probe') FROM unnest(pg_temp.edge_check_10()) v), true, 'check 10 MUST FAIL (0041): a policy for the minter (it may have none)');
SELECT tests.clear_actor();
DROP POLICY zz_minter_probe ON app.play;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_10(), NULL::text[], 'check 10 (0041): clean again');

SELECT tests.clear_actor();
GRANT SELECT ON app.play TO edge_signin_minter;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_signin_minter holds a privilege on a relation%app.play') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0041): the minter granted SELECT on a FORCE-RLS app table (the generic rule allows that for the other roles; the minter may hold none)');
SELECT tests.clear_actor();
REVOKE SELECT ON app.play FROM edge_signin_minter;
GRANT SELECT ON private.signin_email_proof TO edge_signin_minter;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_signin_minter holds a privilege on a relation%private.signin_email_proof') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0041): the minter granted the proof table itself (only the definer may write it)');
SELECT tests.clear_actor();
REVOKE SELECT ON private.signin_email_proof FROM edge_signin_minter;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_12(), NULL::text[], 'check 12 (0041): clean again');

-- ---- check 13 (0032, L1): no SECURITY DEFINER function reads an unqualified pg_* relation ----
SELECT is(pg_temp.edge_check_13(), NULL::text[], 'check 13: no SECURITY DEFINER function in app/api/private reads an unqualified pg_* relation (private.delete_my_data qualified them in 0032)');
SELECT tests.clear_actor();
CREATE FUNCTION private.zz_edge_shadow() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT count(*)::int FROM pg_class $z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%private.zz_edge_shadow -> pg_class') FROM unnest(pg_temp.edge_check_13()) v), true, 'check 13 MUST FAIL: a definer that reads pg_class unqualified');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_edge_shadow();
CREATE FUNCTION private.zz_edge_shadow() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$
  -- the word pg_class in a comment is not a read:  FROM pg_class
  SELECT count(*)::int FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = pg_catalog.current_schema() $z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_13(), NULL::text[], 'check 13: a definer that qualifies pg_catalog (and mentions an unqualified name only in a comment) is clean');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_edge_shadow();
-- 0033 (PR1b gate LOW-2): the comma-list and USING shapes the first version of the pattern missed.
CREATE FUNCTION private.zz_edge_shadow() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$
  SELECT count(*)::int FROM app.device d, pg_class c WHERE c.oid = 0 $z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%private.zz_edge_shadow -> pg_class') FROM unnest(pg_temp.edge_check_13()) v), true, 'check 13 MUST FAIL (LOW-2): a comma list `FROM app.device d, pg_class c`');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_edge_shadow();
CREATE FUNCTION private.zz_edge_shadow() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  DELETE FROM app.device d USING pg_roles r WHERE r.rolname = 'zz_none' AND d.id = d.id AND false;
  RETURN 0;
END; $z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '%private.zz_edge_shadow -> pg_roles') FROM unnest(pg_temp.edge_check_13()) v), true, 'check 13 MUST FAIL (LOW-2): DELETE ... USING pg_roles');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_edge_shadow();
CREATE FUNCTION private.zz_edge_shadow() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  RETURN (SELECT count(*)::int FROM app.device d, pg_catalog.pg_class c, pg_temp.nothing n WHERE false);
END; $z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_13(), NULL::text[], 'check 13: qualified comma-list members (pg_catalog.pg_class, pg_temp.x) are not flagged');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_edge_shadow();
SELECT tests.authenticate_as('service_role', '{}'::jsonb);


-- ==========================================================================
-- 0047 (partner-auth spine, S1.1a): the partner lane's roles, the six owner roles, the role_name column of the policy allow-list, and check 14
-- ==========================================================================
-- ---- the two new EXECUTE columns of private.function_inventory (check 2's twin) ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
DO $$
DECLARE
  v_row record;
  v_oid oid;
  v_mismatches text[] := '{}';
BEGIN
  FOR v_row IN SELECT * FROM private.function_inventory LOOP
    SELECT p.oid INTO v_oid
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_row.schema_name AND p.proname = v_row.function_name
      AND pg_get_function_identity_arguments(p.oid) = v_row.identity_args;
    IF has_function_privilege('edge_partner', v_oid, 'EXECUTE') <> v_row.expected_edge_partner THEN
      v_mismatches := v_mismatches || format('%s.%s: edge_partner expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_edge_partner, has_function_privilege('edge_partner', v_oid, 'EXECUTE'));
    END IF;
    IF has_function_privilege('edge_partner_minter', v_oid, 'EXECUTE') <> v_row.expected_edge_partner_minter THEN
      v_mismatches := v_mismatches || format('%s.%s: edge_partner_minter expected=%s actual=%s', v_row.schema_name, v_row.function_name, v_row.expected_edge_partner_minter, has_function_privilege('edge_partner_minter', v_oid, 'EXECUTE'));
    END IF;
  END LOOP;
  IF array_length(v_mismatches, 1) > 0 THEN
    RAISE EXCEPTION 'partner lane EXECUTE mismatches: %', array_to_string(v_mismatches, '; ');
  END IF;
END
$$;
SELECT pass('every function''s actual edge_partner and edge_partner_minter EXECUTE grants match private.function_inventory (0047)');
SELECT is(
  (SELECT array_agg(function_name::text ORDER BY function_name::text COLLATE "C") FROM private.function_inventory WHERE expected_edge_partner),
  ARRAY['bind_partner_session', 'course_pin_rotate_for_partner', 'course_pin_show_for_partner', 'course_qr_mint_for_partner', 'course_qr_print_key_for_partner', 'course_qr_print_read_for_partner', 'course_qr_print_write_for_partner', 'course_qr_refresh_for_partner', 'hit_partner_rate_limit', 'partner_admin_enrolment_issue_for_partner', 'partner_attest_for_partner', 'partner_binding', 'partner_binding_kind',
        'partner_credential_list_for_partner', 'partner_credential_options_for_partner', 'partner_credential_register_for_partner', 'partner_credential_revoke_for_partner',
        'partner_entitlement_queue_for_partner', 'partner_entitlement_redeem_for_partner', 'partner_entitlement_voucher_for_partner',
        'partner_facility_programme_list_for_partner', 'partner_facility_programme_upsert_for_partner',
        'partner_handover_mint_for_partner',
        'partner_held_queue_for_partner',
        'partner_invite_accept_for_partner', 'partner_invite_create_for_partner', 'partner_invite_list_for_partner', 'partner_invite_revoke_for_partner',
        'partner_member_recover_for_partner', 'partner_member_revoke_for_partner',
        'partner_offer_approve_for_partner', 'partner_offer_end_for_partner', 'partner_offer_upsert_for_partner', 'partner_offers_list_for_partner',
        'partner_offers_queue_for_partner', 'partner_offers_redeem_for_partner', 'partner_offers_redeem_offline_for_partner',
        'partner_offline_attest_for_partner', 'partner_operator_rollup_for_partner', 'partner_org_sessions_revoke_for_partner', 'partner_pin_change_for_partner',
        'partner_pin_params_for_partner', 'partner_pin_reset_for_partner', 'partner_pin_set_for_partner', 'partner_pin_verify_for_partner',
        'partner_resolve_held_entitlement_for_partner', 'partner_resolve_held_offer_code_for_partner', 'partner_review_sla_for_partner',
        'partner_session_lock_for_partner',
        'partner_session_otp_proof_for_partner', 'partner_session_otp_target_for_partner', 'partner_session_reauth_credential_for_partner', 'partner_session_reauth_for_partner',
        'partner_session_reauth_options_for_partner', 'partner_session_revoke_for_partner', 'partner_settlement_export_for_partner', 'partner_shift_log_for_partner',
        'partner_sponsor_rollup_for_partner', 'partner_sponsorship_approve_for_partner', 'partner_sponsorship_upsert_for_partner', 'partner_sponsorships_list_for_partner',
        'partner_staff_activity_for_partner', 'partner_stock_move_for_partner', 'partner_stock_read_for_partner', 'partner_totp_confirm_for_partner', 'partner_totp_enrol_for_partner',
        'partner_totp_reset_for_partner', 'partner_totp_verify_for_partner', 'partner_trail_programme_read_for_partner', 'partner_trail_programme_upsert_for_partner', 'partner_whoami_for_partner'],
  'edge_partner executes EXACTLY the binder, the two read-only binding helpers (4.3), the rate-limit twin, the seven _for_partner definers of 0049 (S1.2), the six of 0052 (S1.3) the five of 0053 (S1.4) and the twelve of 0054 (S1.5) and the seven of 0055 (S2b) and the four of 0056 (S3) and the four of 0057 (S4) and the six of 0058 (S5) and the thirteen of 0059 (S6) and the three of 0060 (P5.1b) and the one of 0062 (offline offer redeem)');
SELECT is((SELECT array_agg(function_name::text ORDER BY function_name::text COLLATE "C") FROM private.function_inventory WHERE expected_edge_partner_minter), ARRAY['partner_challenge_issue_sign_in', 'partner_credential_lookup', 'partner_credential_register_first', 'partner_enrolment_token_accept', 'partner_enrolment_token_email_for_token', 'partner_invite_accept', 'partner_invite_email_for_token', 'partner_rp_config_read', 'partner_session_mint', 'partner_sign_in_failure_record'], 'edge_partner_minter executes exactly the two mint functions of 0048 (S1.1b) and the three minter-lane definers of 0049 (S1.2) and the five of 0054 (S1.5)');
SELECT tests.clear_actor();

-- ---- check 9, the 0047 roles ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_9(), NULL::text[], 'check 9 (0047): clean with edge_partner / edge_partner_minter in the edge set and the six owner roles NOLOGIN, attribute-free, members of nothing, with no member but the migrating role''s ADMIN');
SELECT tests.clear_actor();
ALTER ROLE edge_partner LOGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v = 'edge role can log in but must not: edge_partner') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047): edge_partner given LOGIN');
SELECT tests.clear_actor();
ALTER ROLE edge_partner NOLOGIN;
GRANT edge_actor TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_partner is a member of edge_actor%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047): edge_partner made a member of edge_actor (the lane must be a member of nothing)');
SELECT tests.clear_actor();
REVOKE edge_actor FROM edge_partner;
GRANT edge_partner TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge role edge_actor is a member of edge_partner (only edge_gateway may be)') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047): edge_actor made a member of edge_partner');
SELECT tests.clear_actor();
REVOKE edge_partner FROM edge_actor;
-- the six owner roles
ALTER ROLE partner_session_toucher LOGIN;
ALTER ROLE partner_totp_verifier CREATEROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v = 'owner role attribute: partner_session_toucher has LOGIN') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047): an owner role given LOGIN');
SELECT is((SELECT bool_or(v = 'owner role attribute: partner_totp_verifier has CREATEROLE') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047): an owner role given CREATEROLE');
SELECT tests.clear_actor();
ALTER ROLE partner_session_toucher NOLOGIN;
ALTER ROLE partner_totp_verifier NOCREATEROLE;
CREATE ROLE zz_owner_member NOLOGIN;
GRANT partner_totp_verifier TO zz_owner_member WITH SET TRUE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'role zz_owner_member is a member of owner role partner_totp_verifier%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047, R5-L3): an ordinary role holds an owner role WITH SET (it could become the owner of every flagger function)');
SELECT tests.clear_actor();
REVOKE partner_totp_verifier FROM zz_owner_member;
GRANT partner_totp_verifier TO zz_owner_member WITH ADMIN TRUE, SET FALSE, INHERIT FALSE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'role zz_owner_member is a member of owner role partner_totp_verifier%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047): an ordinary role holds ADMIN on an owner role (it could re-grant SET to itself)');
SELECT tests.clear_actor();
REVOKE partner_totp_verifier FROM zz_owner_member;
GRANT zz_owner_member TO partner_pin_verifier;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'owner role partner_pin_verifier is a member of zz_owner_member%') FROM unnest(pg_temp.edge_check_9()) v), true, 'check 9 MUST FAIL (0047): an owner role made a member of another role');
SELECT tests.clear_actor();
REVOKE zz_owner_member FROM partner_pin_verifier;
DROP ROLE zz_owner_member;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_9(), NULL::text[], 'check 9 (0047): clean again after the fixtures are undone');
SELECT tests.clear_actor();

-- ---- check 10, the 0047 roles: a policy for edge_partner or its minter ----
CREATE POLICY zz_partner_probe ON app.play FOR SELECT TO edge_partner USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'a policy applies to edge_partner (it may have none): app.play.zz_partner_probe') FROM unnest(pg_temp.edge_check_10()) v), true, 'check 10 MUST FAIL (0047): a policy for edge_partner (the lane has NO policy: it holds no table privilege)');
SELECT tests.clear_actor();
DROP POLICY zz_partner_probe ON app.play;
CREATE POLICY zz_partner_minter_probe ON app.play FOR SELECT TO edge_partner_minter USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'a policy applies to edge_partner_minter (it may have none): app.play.zz_partner_minter_probe') FROM unnest(pg_temp.edge_check_10()) v), true, 'check 10 MUST FAIL (0047): a policy for edge_partner_minter');
SELECT tests.clear_actor();
DROP POLICY zz_partner_minter_probe ON app.play;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_10(), NULL::text[], 'check 10 (0047): clean again');
SELECT tests.clear_actor();

-- ---- check 12, the 0047 roles: edge_partner and its minter hold NOTHING; the owner roles hold exactly private.partner_owner_privilege ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_12(), NULL::text[], 'check 12 (0047): clean: edge_partner and edge_partner_minter hold no privilege on any relation and no USAGE on schema app; the six owner roles hold EXACTLY the registered privileges');
SELECT tests.clear_actor();
GRANT SELECT ON app.play TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_partner holds a privilege on a relation%app.play') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): edge_partner granted SELECT on a FORCE-RLS app table (the lane holds NO table privilege)');
SELECT tests.clear_actor();
REVOKE SELECT ON app.play FROM edge_partner;
GRANT USAGE ON SCHEMA app TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_partner has USAGE on schema app%') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): edge_partner granted USAGE on schema app');
SELECT tests.clear_actor();
REVOKE USAGE ON SCHEMA app FROM edge_partner;
GRANT SELECT ON app.play TO edge_partner_minter;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'edge_partner_minter holds a privilege on a relation%app.play') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): edge_partner_minter granted SELECT on an app table');
SELECT tests.clear_actor();
REVOKE SELECT ON app.play FROM edge_partner_minter;
-- an owner role widened beyond its registry rows (a column, a table, a function, a schema), and a registry row the role does not hold
GRANT UPDATE (expires_at) ON app.partner_session TO partner_session_toucher;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v = 'owner role holds a privilege that private.partner_owner_privilege does not list: partner_session_toucher UPDATE ON column app.partner_session.expires_at') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): the toucher granted UPDATE on expires_at (it could extend a session)');
SELECT tests.clear_actor();
REVOKE UPDATE (expires_at) ON app.partner_session FROM partner_session_toucher;
GRANT SELECT ON app.partner_credential TO partner_session_issuer;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v = 'owner role holds a privilege that private.partner_owner_privilege does not list: partner_session_issuer SELECT ON relation app.partner_credential') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): the issuer granted table-level SELECT on partner_credential (it holds the public keys)');
SELECT tests.clear_actor();
REVOKE SELECT ON app.partner_credential FROM partner_session_issuer;
-- (a table-level REVOKE removes the COLUMN-level grants too: put the issuer's own back)
GRANT SELECT (id, user_id, credential_id, revoked_at, public_key, alg, sign_count) ON app.partner_credential TO partner_session_issuer;
GRANT USAGE ON SCHEMA public TO partner_totp_verifier;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v = 'owner role holds a privilege that private.partner_owner_privilege does not list: partner_totp_verifier USAGE ON schema public') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): the flagger granted USAGE on a schema');
SELECT tests.clear_actor();
REVOKE USAGE ON SCHEMA public FROM partner_totp_verifier;
SET LOCAL ROLE private_definer;
GRANT EXECUTE ON FUNCTION private.partner_authorize(text, text, app.partner_role[], text) TO partner_totp_verifier;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE 'owner role holds a privilege that private.partner_owner_privilege does not list: partner_totp_verifier EXECUTE ON function private.partner_authorize(text,text,app.partner_role[],text)') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): a verifier granted EXECUTE on partner_authorize (which has none)');
SELECT tests.clear_actor();
SET LOCAL ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.partner_authorize(text, text, app.partner_role[], text) FROM partner_totp_verifier;
REVOKE EXECUTE ON FUNCTION private.partner_binding_session() FROM partner_reauth_verifier;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v = 'private.partner_owner_privilege lists a privilege the role does not hold: partner_reauth_verifier EXECUTE ON function private.partner_binding_session()') FROM unnest(pg_temp.edge_check_12()) v), true, 'check 12 MUST FAIL (0047): a registry row for a privilege the role no longer holds (stale registry)');
SELECT tests.clear_actor();
SET LOCAL ROLE private_definer;
GRANT EXECUTE ON FUNCTION private.partner_binding_session() TO partner_reauth_verifier;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_12(), NULL::text[], 'check 12 (0047): clean again after the owner-privilege fixtures are undone');
SELECT tests.clear_actor();

-- ---- the role_name column of private.definer_policy_allowlist: a policy of an owner role with no row, and a row for another role, both fail ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
CREATE FUNCTION pg_temp.definer_policy_unregistered() RETURNS int LANGUAGE sql AS $f$
  SELECT count(*)::int
  FROM pg_policy pol
  JOIN pg_class cl ON cl.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = cl.relnamespace
  CROSS JOIN pg_roles pr
  WHERE pr.rolname = ANY (ARRAY['private_definer', 'partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier'])
    AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
    AND NOT EXISTS (
      SELECT 1 FROM private.definer_policy_allowlist al
      WHERE al.schema_name = n.nspname AND al.table_name = cl.relname AND al.policy_name = pol.polname AND al.role_name = pr.rolname
        AND al.command = CASE pol.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' ELSE pol.polcmd::text END
        AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
        AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid))
$f$;
SELECT is(pg_temp.definer_policy_unregistered(), 0, 'definer policies (0047): every policy of private_definer and of the six owner roles is registered with its role_name');
SELECT tests.clear_actor();
CREATE POLICY zz_toucher_probe ON app.partner_session FOR SELECT TO partner_session_toucher USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.definer_policy_unregistered(), 1, 'definer policies MUST FAIL (0047, R5-L4): a policy for the toucher with no allowlist row');
SELECT tests.clear_actor();
DROP POLICY zz_toucher_probe ON app.partner_session;
CREATE POLICY zz_public_partner_probe ON app.partner_credential FOR SELECT TO PUBLIC USING (true);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.definer_policy_unregistered(), 6, 'definer policies MUST FAIL (0047): a PUBLIC policy applies to private_definer AND all five owner roles, and none of the six has a row');
SELECT tests.clear_actor();
DROP POLICY zz_public_partner_probe ON app.partner_credential;
-- a row registered for the WRONG role does not satisfy the policy of another (the role_name is part of the match)
GRANT INSERT, UPDATE, DELETE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY zz_seed_allowlist ON private.definer_policy_allowlist FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
UPDATE private.definer_policy_allowlist SET role_name = 'partner_session_issuer' WHERE policy_name = 'pst_read_partner_session';
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.definer_policy_unregistered(), 1, 'definer policies MUST FAIL (0047): the toucher''s policy is registered under the issuer''s name (the role_name is part of the match)');
SELECT tests.clear_actor();
UPDATE private.definer_policy_allowlist SET role_name = 'partner_session_toucher' WHERE policy_name = 'pst_read_partner_session';
DROP POLICY zz_seed_allowlist ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE, DELETE ON private.definer_policy_allowlist FROM CURRENT_USER;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.definer_policy_unregistered(), 0, 'definer policies (0047): clean again');
SELECT tests.clear_actor();

-- ---- check 14: the partner family (partner-auth-design 4.3) ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_14(), NULL::text[], 'check 14: no *_for_partner function lacks the first-statement call; no edge_actor-executable definer outside the family evaluates partner scope; no function outside the family reads kind = ''partner'' except private.actor_uid()');
SELECT tests.clear_actor();
-- clause (a): the first-statement rule. A function that passes, in both accepted shapes, is clean.
CREATE FUNCTION private.zz_ok1_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
DECLARE
  v_n int := 1;
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  RETURN v_n;
END
$z$;
CREATE FUNCTION private.zz_ok2_for_partner() RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
DECLARE
  v_uid uuid;
BEGIN
  -- a comment first is fine: comments are stripped before the statement is read
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['staff', 'manager']::app.partner_role[], 'A1');
  RETURN v_uid;
END
$z$;
REVOKE EXECUTE ON FUNCTION private.zz_ok1_for_partner() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.zz_ok2_for_partner() FROM PUBLIC;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_14(), NULL::text[], 'check 14 (a): a PERFORM and an assignment of private.partner_authorize as the first statement (after a comment) both pass');
SELECT tests.clear_actor();
CREATE FUNCTION private.zz_bad1_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a)%private.zz_bad1_for_partner') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a) MUST FAIL: a *_for_partner function that never calls private.partner_authorize');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_bad1_for_partner();
CREATE FUNCTION private.zz_bad2_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  -- PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  /* PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0'); */
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a)%private.zz_bad2_for_partner') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a) MUST FAIL (N3): the call written only in a line comment and a block comment satisfies nothing');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_bad2_for_partner();
CREATE FUNCTION private.zz_bad3_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  RAISE NOTICE 'PERFORM private.partner_authorize(1)';
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a)%private.zz_bad3_for_partner') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a) MUST FAIL: the call is present but not FIRST (a statement, here one naming it only in a string literal, comes before)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_bad3_for_partner();
CREATE FUNCTION private.zz_bad4_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0') WHERE (false);
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a)%private.zz_bad4_for_partner') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a) MUST FAIL: the call is first but guarded by a WHERE (false), so it never runs (the paren-collapsing reader sees the trailing WHERE)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_bad4_for_partner();
DROP FUNCTION private.zz_ok1_for_partner();
DROP FUNCTION private.zz_ok2_for_partner();
-- clause (b): an edge_actor-executable definer that evaluates partner scope (PA-9c). The OLD recorder is the real one (E21): re-granting it to edge_actor must light the check.
SET LOCAL ROLE private_definer;
GRANT EXECUTE ON FUNCTION private.offline_code_record_step_for_actor(uuid, integer, bigint, text) TO edge_actor;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v = '(b) an edge_actor-executable definer outside the *_for_partner family evaluates partner scope: private.offline_code_record_step_for_actor') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (b) MUST FAIL (PA-9c): with EXECUTE re-granted to edge_actor, offline_code_record_step_for_actor (is_staff_or_manager_of_facility) is found: this is the clause that would have caught E21');
SELECT tests.clear_actor();
SET LOCAL ROLE private_definer;
REVOKE EXECUTE ON FUNCTION private.offline_code_record_step_for_actor(uuid, integer, bigint, text) FROM edge_actor;
RESET ROLE;
CREATE FUNCTION private.zz_scope_probe() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT private.has_facility_scope('00000000-0000-0000-0000-000000000000'::uuid, 'fac_x') $z$;
GRANT EXECUTE ON FUNCTION private.zz_scope_probe() TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(b)%private.zz_scope_probe') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (b) MUST FAIL (PA-9c): a planted edge_actor-executable definer that calls has_facility_scope');
SELECT tests.clear_actor();
REVOKE EXECUTE ON FUNCTION private.zz_scope_probe() FROM edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(b)%zz_scope_probe') FROM unnest(pg_temp.edge_check_14()) v), NULL, 'check 14 (b): the same function NOT executable by edge_actor is not a finding (control)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_scope_probe();
CREATE FUNCTION private.zz_scope_probe() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT EXISTS (SELECT 1 FROM app.partner_member) $z$;
GRANT EXECUTE ON FUNCTION private.zz_scope_probe() TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(b)%private.zz_scope_probe') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (b) MUST FAIL: a planted edge_actor-executable definer that reads app.partner_member directly');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_scope_probe();
CREATE FUNCTION private.zz_scope_probe() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT 'is_admin and partner_member in a string'::text /* has_facility_scope in a comment */ $z$;
GRANT EXECUTE ON FUNCTION private.zz_scope_probe() TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(b)%zz_scope_probe') FROM unnest(pg_temp.edge_check_14()) v), NULL, 'check 14 (b): the names only inside a string literal and a comment are not a finding (control)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_scope_probe();
-- clause (c): a function outside the family reading kind = 'partner'
CREATE FUNCTION private.zz_kind_probe() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$
  SELECT EXISTS (SELECT 1 FROM private.actor_binding b WHERE b.backend_pid = pg_backend_pid() AND b.kind = 'partner')
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(c)%private.zz_kind_probe()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (c) MUST FAIL: a function outside the family that reads kind = ''partner''');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_kind_probe();
CREATE FUNCTION private.zz_kindread_for_partner() RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  RETURN EXISTS (SELECT 1 FROM private.actor_binding b WHERE b.backend_pid = pg_backend_pid() AND b.kind = 'partner');
END
$z$;
REVOKE EXECUTE ON FUNCTION private.zz_kindread_for_partner() FROM PUBLIC;
CREATE FUNCTION private.zz_kind_probe() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$
  SELECT 1 /* b.kind = 'partner' only in a comment */
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_14(), NULL::text[], 'check 14 (c): the same read INSIDE the partner family, and the literal only in a comment, are clean (controls)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_kindread_for_partner();
DROP FUNCTION private.zz_kind_probe();
-- ---- S1.1a gate L2: the evasions the first version of check 14 let through ----
-- (a0) text the first-statement reader cannot lex is refused outright: a dollar-quoted string, a quoted identifier, a backslash / E-string, a nested comment
CREATE FUNCTION private.zz_dq_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
DECLARE
  v_x text := $q$ begin perform private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0'); $q$;
BEGIN
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a0)%private.zz_dq_for_partner()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a0) MUST FAIL: a dollar-quoted string in DECLARE that spells ''begin perform private.partner_authorize(...)'' (it used to satisfy the first-statement reader)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_dq_for_partner();
CREATE FUNCTION private.zz_qi_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
DECLARE
  "x begin perform private.partner_authorize(NULL, NULL, NULL, 'A0');" int := 1;
BEGIN
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a0)%private.zz_qi_for_partner()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a0) MUST FAIL: a double-quoted identifier that spells the call');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_qi_for_partner();
CREATE FUNCTION private.zz_nc_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  /* outer /* inner */ PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0'); */
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a0)%private.zz_nc_for_partner()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a0) MUST FAIL: a NESTED block comment that hides the call from a naive comment stripper (a comment to PostgreSQL, a first statement to a regex)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_nc_for_partner();
CREATE FUNCTION private.zz_es_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
DECLARE
  v_x text := E'it\'s';
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a0)%private.zz_es_for_partner()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a0) MUST FAIL: an E-string with a backslash escape (it would end the string early for the quote stripper)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_es_for_partner();
-- (a2) an EXCEPTION block can swallow the 42501 the seam raises
CREATE FUNCTION private.zz_ex_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  RETURN 1;
EXCEPTION WHEN OTHERS THEN
  RETURN 0;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a2)%private.zz_ex_for_partner()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a2) MUST FAIL: the call is first, but an outer EXCEPTION WHEN OTHERS swallows its refusal');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_ex_for_partner();
-- (a3) the class: a literal, and SESSION / PEEK only for a named function (a class-SESSION call is a scope no-op)
CREATE FUNCTION private.zz_sess_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize(NULL, NULL, NULL, 'SESSION');
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a3)%private.zz_sess_for_partner()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a3) MUST FAIL: an unlisted *_for_partner function calling the seam with class SESSION (no scope, no aal gate)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_sess_for_partner();
CREATE FUNCTION private.zz_peek_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize(NULL, NULL, NULL, 'PEEK');
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a3)%private.zz_peek_for_partner()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a3) MUST FAIL: the same with class PEEK');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_peek_for_partner();
CREATE FUNCTION private.zz_var_for_partner(p_class text) RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], p_class);
  RETURN 1;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(a3)%private.zz_var_for_partner(p_class text)') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (a3) MUST FAIL: a class that is a variable, not a literal (the caller would choose the gate)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_var_for_partner(text);
-- (b) is no longer exempt by NAME: a partner_-named edge_actor-executable function that evaluates scope is a finding
CREATE FUNCTION private.partner_zz_scope_probe() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT private.has_facility_scope('00000000-0000-0000-0000-000000000000'::uuid, 'fac_x') $z$;
GRANT EXECUTE ON FUNCTION private.partner_zz_scope_probe() TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(b)%private.partner_zz_scope_probe') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (b) MUST FAIL: a function NAMED partner_* (it used to be exempt) that evaluates scope and is executable by edge_actor');
SELECT tests.clear_actor();
DROP FUNCTION private.partner_zz_scope_probe();
-- (c) also catches a reader that goes through the binding table or the helpers, with no 'partner' literal in the body; and a partner_-named function is no longer exempt by name
CREATE FUNCTION private.zz_helper_probe() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT private.partner_binding_kind() $z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(c)%private.zz_helper_probe()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (c) MUST FAIL: a function outside the family that reads the kind through private.partner_binding_kind() (no ''partner'' literal)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_helper_probe();
CREATE FUNCTION private.partner_zz_kind_probe() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$
  SELECT EXISTS (SELECT 1 FROM private.actor_binding b WHERE b.backend_pid = pg_backend_pid() AND b.kind = 'partner')
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(c)%private.partner_zz_kind_probe()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (c) MUST FAIL: a function named partner_* outside the family (it used to be exempt by name) reading the binding');
SELECT tests.clear_actor();
DROP FUNCTION private.partner_zz_kind_probe();
-- KNOWN LIMIT of (c), pinned: a body that ASSEMBLES the names at run time is not seen (the check is a tripwire; the limit is stated in verify-function-inventory.mjs and the design)
CREATE FUNCTION private.zz_dyn_probe() RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
DECLARE
  v_t text := 'private.actor_' || 'binding';
  v_k text := 'part' || 'ner';
  v_r boolean;
BEGIN
  EXECUTE 'SELECT EXISTS (SELECT 1 FROM ' || v_t || ' WHERE kind = ' || quote_literal(v_k) || ')' INTO v_r;
  RETURN v_r;
END
$z$;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(c)%private.zz_dyn_probe()') FROM unnest(pg_temp.edge_check_14()) v), NULL, 'check 14 (c) KNOWN LIMIT: a body that assembles ''private.actor_'' || ''binding'' and ''part'' || ''ner'' at run time is NOT found (pinned: the tripwire''s stated limit)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_dyn_probe();
-- (d) a *_for_partner function must not be executable by edge_actor, edge_system or PUBLIC
CREATE FUNCTION private.zz_pub_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  RETURN 1;
END
$z$;
GRANT EXECUTE ON FUNCTION private.zz_pub_for_partner() TO PUBLIC;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(d)%private.zz_pub_for_partner') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (d) MUST FAIL: a *_for_partner function left with the default PUBLIC EXECUTE');
SELECT tests.clear_actor();
REVOKE EXECUTE ON FUNCTION private.zz_pub_for_partner() FROM PUBLIC;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(d)%private.zz_pub_for_partner') FROM unnest(pg_temp.edge_check_14()) v), NULL, 'check 14 (d): the same function with PUBLIC revoked is clean (control)');
SELECT tests.clear_actor();
GRANT EXECUTE ON FUNCTION private.zz_pub_for_partner() TO edge_actor;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(d)%private.zz_pub_for_partner') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (d) MUST FAIL: a *_for_partner function executable by edge_actor');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_pub_for_partner();
-- (e) (S1.1a gate LOW 1) the EXECUTE set of edge_partner is EXACTLY the binder, the two read-only binding helpers, hit_partner_rate_limit and the *_for_partner family
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_14(), NULL::text[], 'check 14 (e): in the clean schema edge_partner executes only the binder and the two binding helpers (nothing else is granted to it)');
SELECT tests.clear_actor();
CREATE FUNCTION private.zz_e_helper() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT 1 $z$;
REVOKE EXECUTE ON FUNCTION private.zz_e_helper() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.zz_e_helper() TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%private.zz_e_helper()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (e) MUST FAIL: a helper that is NOT a *_for_partner function, granted to edge_partner');
SELECT tests.clear_actor();
REVOKE EXECUTE ON FUNCTION private.zz_e_helper() FROM edge_partner;
GRANT EXECUTE ON FUNCTION private.zz_e_helper() TO PUBLIC;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%private.zz_e_helper()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (e) MUST FAIL: the same helper left with the default PUBLIC EXECUTE reaches edge_partner through PUBLIC');
SELECT tests.clear_actor();
REVOKE EXECUTE ON FUNCTION private.zz_e_helper() FROM PUBLIC;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%private.zz_e_helper()') FROM unnest(pg_temp.edge_check_14()) v), NULL, 'check 14 (e): the same helper with nothing granted to edge_partner is clean (control)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_e_helper();
-- an OVERLOAD of an allowed name is a different function: the allow-list is by IDENTITY (schema, name, argument types), not by name (the S1.1b gate's L-1)
CREATE FUNCTION private.bind_partner_session(p_x int) RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT 1 $z$;
REVOKE EXECUTE ON FUNCTION private.bind_partner_session(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.bind_partner_session(int) TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%private.bind_partner_session(p_x integer)') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (e) MUST FAIL: an OVERLOAD of bind_partner_session (other argument types) granted to edge_partner');
SELECT tests.clear_actor();
DROP FUNCTION private.bind_partner_session(int);
CREATE FUNCTION private.partner_binding_kind(p_x int) RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT 'x'::text $z$;
REVOKE EXECUTE ON FUNCTION private.partner_binding_kind(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_binding_kind(int) TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%private.partner_binding_kind(p_x integer)') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (e) MUST FAIL: an overload of partner_binding_kind granted to edge_partner');
SELECT tests.clear_actor();
DROP FUNCTION private.partner_binding_kind(int);
CREATE FUNCTION app.hit_partner_rate_limit(p_key text, p_window interval, p_max int) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT true $z$;
REVOKE EXECUTE ON FUNCTION app.hit_partner_rate_limit(text, interval, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.hit_partner_rate_limit(text, interval, int) TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%app.hit_partner_rate_limit(%') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (e) MUST FAIL: the allowed NAME in another schema (app.hit_partner_rate_limit) granted to edge_partner');
SELECT tests.clear_actor();
DROP FUNCTION app.hit_partner_rate_limit(text, interval, int);
-- a PROCEDURE is a function for this purpose (prokind 'p'), and an allowed NAME in another schema's identity is still a different function
CREATE PROCEDURE private.zz_e_proc() LANGUAGE sql AS $z$ SELECT 1 $z$;
REVOKE EXECUTE ON PROCEDURE private.zz_e_proc() FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE private.zz_e_proc() TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%private.zz_e_proc()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (e) MUST FAIL: a PROCEDURE granted to edge_partner (prokind p is covered, not only functions)');
SELECT tests.clear_actor();
DROP PROCEDURE private.zz_e_proc();
CREATE FUNCTION app.partner_authorize() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $z$ SELECT 1 $z$;
REVOKE EXECUTE ON FUNCTION app.partner_authorize() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.partner_authorize() TO edge_partner;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%app.partner_authorize()') FROM unnest(pg_temp.edge_check_14()) v), true, 'check 14 (e) MUST FAIL: the authorization seam''s own name, granted to edge_partner (the seam is reached only from inside a *_for_partner definer, never by the lane directly)');
SELECT tests.clear_actor();
DROP FUNCTION app.partner_authorize();
-- the allowed names: a *_for_partner function and hit_partner_rate_limit may be granted to edge_partner
CREATE FUNCTION private.zz_e_ok_for_partner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $z$
BEGIN
  PERFORM private.partner_authorize('fac_x', NULL, ARRAY['staff']::app.partner_role[], 'A0');
  RETURN 1;
END
$z$;
REVOKE EXECUTE ON FUNCTION private.zz_e_ok_for_partner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.zz_e_ok_for_partner() TO edge_partner;
-- (S1.2, 0049: the real private.hit_partner_rate_limit(text, interval, integer) exists and is granted to edge_partner, so it is the control; the planted look-alike this cell used before 0049 would collide with it)
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(e)%') FROM unnest(pg_temp.edge_check_14()) v), NULL, 'check 14 (e): a *_for_partner function and the real hit_partner_rate_limit are allowed on edge_partner (controls)');
SELECT tests.clear_actor();
DROP FUNCTION private.zz_e_ok_for_partner();
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_14(), NULL::text[], 'check 14: clean again after every fixture function is dropped');
SELECT tests.clear_actor();

-- ---- check 15 (S1.1a gate H1): every GUC-keyed private_definer policy is closed under a partner binding ----
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(pg_temp.edge_check_15(), NULL::text[], 'check 15: every GUC-keyed private_definer policy in the schema carries the partner conjunct (section 8c of 0047 closed 102 of them)');
SELECT tests.clear_actor();
CREATE TABLE app.zz15_t (id int, owner_id uuid);
ALTER TABLE app.zz15_t ENABLE ROW LEVEL SECURITY;
CREATE POLICY zz15_open ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_open') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: a new GUC-keyed private_definer SELECT policy with no partner conjunct (what a later slice''s window would look like)');
SELECT tests.clear_actor();
DROP POLICY zz15_open ON app.zz15_t;
CREATE POLICY zz15_wc ON app.zz15_t FOR INSERT TO private_definer WITH CHECK (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_wc') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: the same in a WITH CHECK only (an INSERT window)');
SELECT tests.clear_actor();
DROP POLICY zz15_wc ON app.zz15_t;
CREATE POLICY zz15_closed ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_closed') FROM unnest(pg_temp.edge_check_15()) v), NULL, 'check 15: the same policy WITH the conjunct is clean (control)');
SELECT tests.clear_actor();
DROP POLICY zz15_closed ON app.zz15_t;
-- (S1.1a gate LOW 2) the conjunct must be the TOP-LEVEL TRAILING AND: text that merely CONTAINS it does not close the window
CREATE POLICY zz15_initplan ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_initplan') FROM unnest(pg_temp.edge_check_15()) v), NULL, 'check 15: the InitPlan form of the conjunct is clean (control: accepted for a future policy, used by the two alarm policies of 0048 and, since 0050, by the 118 that 0047 section 8c closed; the direct call is still accepted too, see 17.3)');
SELECT tests.clear_actor();
DROP POLICY zz15_initplan ON app.zz15_t;
CREATE POLICY zz15_three ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND id > 0 AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_three') FROM unnest(pg_temp.edge_check_15()) v), NULL, 'check 15: a THREE-term AND whose LAST term is the conjunct is clean (control)');
SELECT tests.clear_actor();
DROP POLICY zz15_three ON app.zz15_t;
-- a string literal holding a parenthesis in the prefix does not confuse the nesting profile (the literals are stripped before the parentheses are counted)
CREATE POLICY zz15_lit ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND owner_id::text <> ')))' AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_lit') FROM unnest(pg_temp.edge_check_15()) v), NULL, 'check 15: a closed policy whose prefix holds a string literal of three closing parentheses is clean (control: the literals are stripped before the depth profile)');
SELECT tests.clear_actor();
DROP POLICY zz15_lit ON app.zz15_t;
-- (S1.1b gate L-2) a GUC read BEHIND A WRAPPER FUNCTION is a window: the policy's own text never says current_setting(, the function it calls does (one level deep, as check 7b parses it)
CREATE FUNCTION private.zz15_guc() RETURNS text LANGUAGE sql STABLE AS $z$ SELECT nullif(current_setting('app.zz15.wrapped', true), '') $z$;
CREATE POLICY zz15_wrap ON app.zz15_t FOR SELECT TO private_definer USING (owner_id::text = private.zz15_guc());
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_wrap') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: a policy whose WRAPPER FUNCTION reads the setting, with no partner conjunct');
SELECT tests.clear_actor();
DROP POLICY zz15_wrap ON app.zz15_t;
CREATE POLICY zz15_wrap_ok ON app.zz15_t FOR SELECT TO private_definer USING (owner_id::text = private.zz15_guc() AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_wrap_ok') FROM unnest(pg_temp.edge_check_15()) v), NULL, 'check 15: the same wrapper policy WITH the conjunct is clean (control)');
SELECT tests.clear_actor();
DROP POLICY zz15_wrap_ok ON app.zz15_t;
DROP FUNCTION private.zz15_guc();
CREATE POLICY zz15_or ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid OR (id > 0 AND private.partner_binding_kind() IS DISTINCT FROM 'partner'));
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_or') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: an OR-form that ENDS with the conjunct text (the window is open through the first branch)');
SELECT tests.clear_actor();
DROP POLICY zz15_or ON app.zz15_t;
CREATE POLICY zz15_or2 ON app.zz15_t FOR SELECT TO private_definer USING ((owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner') OR id > 0);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_or2') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: the conjunct inside an AND that is one branch of an OR');
SELECT tests.clear_actor();
DROP POLICY zz15_or2 ON app.zz15_t;
CREATE POLICY zz15_mid ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner' AND id > 0);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_mid') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: the conjunct in the MIDDLE of the AND, not last');
SELECT tests.clear_actor();
DROP POLICY zz15_mid ON app.zz15_t;
CREATE POLICY zz15_first ON app.zz15_t FOR SELECT TO private_definer USING (private.partner_binding_kind() IS DISTINCT FROM 'partner' OR owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_first') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: the conjunct text as the FIRST branch of an OR');
SELECT tests.clear_actor();
DROP POLICY zz15_first ON app.zz15_t;
CREATE POLICY zz15_exists ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND EXISTS (SELECT 1 WHERE private.partner_binding_kind() IS DISTINCT FROM 'partner'));
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_exists') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: the conjunct buried inside an EXISTS sub-select');
SELECT tests.clear_actor();
DROP POLICY zz15_exists ON app.zz15_t;
CREATE POLICY zz15_other ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'device');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_other') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: the same shape against another kind (not partner)');
SELECT tests.clear_actor();
DROP POLICY zz15_other ON app.zz15_t;
CREATE POLICY zz15_deep ON app.zz15_t FOR SELECT TO private_definer USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND (id > 0 OR (id < 0 AND private.partner_binding_kind() IS DISTINCT FROM 'partner')));
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_deep') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: the conjunct trailing a NESTED AND inside an OR inside the top-level AND (its text ends the expression, its position does not)');
SELECT tests.clear_actor();
DROP POLICY zz15_deep ON app.zz15_t;
-- an UPDATE policy: the window may be in USING and in WITH CHECK, and EACH needs the conjunct
CREATE POLICY zz15_upd ON app.zz15_t FOR UPDATE TO private_definer
  USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner')
  WITH CHECK (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_upd') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: an UPDATE policy closed in USING but open in WITH CHECK');
SELECT tests.clear_actor();
DROP POLICY zz15_upd ON app.zz15_t;
CREATE POLICY zz15_upd_ok ON app.zz15_t FOR UPDATE TO private_definer
  USING (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner')
  WITH CHECK (owner_id = nullif(current_setting('app.zz15.target', true), '')::uuid AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_upd_ok') FROM unnest(pg_temp.edge_check_15()) v), NULL, 'check 15: an UPDATE policy closed in BOTH clauses (one InitPlan, one direct) is clean (control)');
SELECT is(pg_temp.edge_check_15() IS NULL OR cardinality(pg_temp.edge_check_15()) = 0, true, 'check 15: and nothing else in the schema is open (the direct and the InitPlan forms are both accepted)');
SELECT tests.clear_actor();
DROP POLICY zz15_upd_ok ON app.zz15_t;
-- the check-15 follow-up (S1.2): a window is recognised from the function's DEPARSED definition (pg_get_functiondef), not from prosrc, and pg_settings counts as a reading of settings
-- W3: a BEGIN ATOMIC wrapper (its prosrc is empty: the body lives in prosqlbody, so a prosrc scan never saw it)
CREATE FUNCTION private.zz15_atomic() RETURNS text LANGUAGE sql STABLE BEGIN ATOMIC SELECT nullif(current_setting('app.zz15.atomic', true), ''); END;
CREATE POLICY zz15_atomic ON app.zz15_t FOR SELECT TO private_definer USING (owner_id::text = private.zz15_atomic());
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_atomic') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL (W3): a policy whose BEGIN ATOMIC wrapper function reads the setting, with no partner conjunct');
SELECT tests.clear_actor();
DROP POLICY zz15_atomic ON app.zz15_t;
CREATE POLICY zz15_atomic_ok ON app.zz15_t FOR SELECT TO private_definer USING (owner_id::text = private.zz15_atomic() AND private.partner_binding_kind() IS DISTINCT FROM 'partner');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_atomic_ok') FROM unnest(pg_temp.edge_check_15()) v), NULL, 'check 15 (W3): the same BEGIN ATOMIC wrapper policy WITH the conjunct is clean (control)');
SELECT tests.clear_actor();
DROP POLICY zz15_atomic_ok ON app.zz15_t;
DROP FUNCTION private.zz15_atomic();
-- W4: a space between the function name and its parenthesis in the wrapper source (the old `ILIKE '%current_setting(%'` missed it)
CREATE FUNCTION private.zz15_space() RETURNS text LANGUAGE sql STABLE AS $z$ SELECT nullif(current_setting ('app.zz15.space', true), '') $z$;
CREATE POLICY zz15_space ON app.zz15_t FOR SELECT TO private_definer USING (owner_id::text = private.zz15_space());
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_space') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL (W4): a wrapper whose source writes current_setting ( with a space, no partner conjunct');
SELECT tests.clear_actor();
DROP POLICY zz15_space ON app.zz15_t;
DROP FUNCTION private.zz15_space();
-- pg_settings: reading the setting through the view is a window just the same (policy text, then a wrapper)
CREATE POLICY zz15_pgs ON app.zz15_t FOR SELECT TO private_definer USING (owner_id::text = (SELECT s.setting FROM pg_settings s WHERE s.name = 'app.zz15.pgs'));
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_pgs') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: a private_definer policy whose own text reads pg_settings, with no partner conjunct');
SELECT tests.clear_actor();
DROP POLICY zz15_pgs ON app.zz15_t;
CREATE FUNCTION private.zz15_pgs() RETURNS text LANGUAGE sql STABLE AS $z$ SELECT s.setting FROM pg_settings s WHERE s.name = 'app.zz15.pgsw' $z$;
CREATE POLICY zz15_pgs_w ON app.zz15_t FOR SELECT TO private_definer USING (owner_id::text = private.zz15_pgs());
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT bool_or(v LIKE '(15)%app.zz15_t.zz15_pgs_w') FROM unnest(pg_temp.edge_check_15()) v), true, 'check 15 MUST FAIL: a wrapper function that reads pg_settings, with no partner conjunct');
SELECT tests.clear_actor();
DROP POLICY zz15_pgs_w ON app.zz15_t;
DROP FUNCTION private.zz15_pgs();
DROP TABLE app.zz15_t;

SELECT * FROM finish();
ROLLBACK;
