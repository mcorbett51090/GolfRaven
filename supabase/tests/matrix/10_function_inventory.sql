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
SELECT plan(6);

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

-- (7) Every SECURITY DEFINER function sets search_path (B2: "Assert that
-- every SECURITY DEFINER function has search_path set in proconfig") —
-- checked directly against pg_proc, independent of the manifest, so it
-- can't be bypassed by forgetting to add an inventory row.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('app', 'api', 'private')
      AND p.prosecdef
      AND NOT EXISTS (
        SELECT 1 FROM unnest(COALESCE(p.proconfig, '{}'::text[])) cfg WHERE cfg LIKE 'search_path=%'
      )
  ),
  0,
  'every SECURITY DEFINER function in app/api/private sets search_path in proconfig'
);

SELECT * FROM finish();
ROLLBACK;
