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
SELECT plan(9);

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
      AND (n.nspname <> 'private' OR r.rolname IS DISTINCT FROM 'private_definer')
  ),
  0,
  'every non-allowlisted-extension SECURITY DEFINER function anywhere lives in schema private AND is owned by private_definer'
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
    WHERE pr.rolname = 'private_definer'
      AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
      AND NOT EXISTS (
        SELECT 1 FROM private.definer_policy_allowlist al
        WHERE al.schema_name = n.nspname
          AND al.table_name = cl.relname
          AND al.policy_name = pol.polname
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
  'every RLS policy applying to private_definer (direct grant or PUBLIC) is registered in private.definer_policy_allowlist with a matching USING/WITH CHECK expression'
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
      WHERE pr.rolname = 'private_definer'
        AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
        AND n.nspname = al.schema_name
        AND cl.relname = al.table_name
        AND pol.polname = al.policy_name
        AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
        AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)
    )
  ),
  0,
  'every private.definer_policy_allowlist row still names a real policy applying to private_definer with a matching expression'
);

SELECT * FROM finish();
ROLLBACK;
