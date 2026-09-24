#!/usr/bin/env node
// tools/db/verify-function-inventory.mjs
//
// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1206-1215): "The
// function inventory is derived, not maintained." Standalone counterpart
// to supabase/tests/matrix/10_function_inventory.sql — same derivation
// (pg_proc across app/api/private, cross-checked against
// private.function_inventory, 0014_hardening.sql), runnable outside
// pg_prove/pgTAP (a plain CLI check, e.g. for a quick local/CI sanity
// pass without spinning up the whole pgTAP matrix).
//
// Talks to Postgres via `psql` (no npm dependency added — tools/db/ is
// scripts, not a workspace package, consistent with the rest of this
// directory). Connection is via the standard PG* environment variables
// (PGHOST/PGPORT/PGUSER/PGDATABASE), same as tools/db/test.sh sets up.
//
// Usage: node tools/db/verify-function-inventory.mjs
// Exit 0: every function in app/api/private is inventoried, every
//   inventory row's EXECUTE grants match, every SECURITY DEFINER function
//   sets search_path.
// Exit 1: at least one mismatch — printed to stderr.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

function psql(sql) {
  const result = spawnSync("psql", ["-v", "ON_ERROR_STOP=1", "-A", "-t", "-F", "\t", "-c", sql], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`psql failed (exit ${result.status}): ${result.stderr}`);
  }
  return result.stdout
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => line.split("\t"));
}

const failures = [];

// 1. Every function/procedure in app/api/private is inventoried.
// ⛔ FIX (should-fix, post-P3a gate): "Include procedures (prokind IN
// ('f','p'))." — p.prokind = 'f' alone missed a CREATE PROCEDURE, which
// carries the exact same EXECUTE-grant/search_path concerns as a
// function but was invisible to this check entirely.
const uninventoried = psql(`
  SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  LEFT JOIN private.function_inventory fi
    ON fi.schema_name = n.nspname AND fi.function_name = p.proname
    AND fi.identity_args = pg_get_function_identity_arguments(p.oid)
  WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind IN ('f', 'p') AND fi.schema_name IS NULL
`);
for (const [fn] of uninventoried) {
  failures.push(`uninventoried function: ${fn} — add a row to private.function_inventory (supabase/migrations/0014_hardening.sql) before this can pass`);
}

// 2. Every inventory row's EXECUTE grants match, for each role.
const grantRows = psql(`
  SELECT
    fi.schema_name, fi.function_name, fi.identity_args,
    fi.expected_anon, fi.expected_authenticated, fi.expected_service_role,
    has_function_privilege('anon', p.oid, 'EXECUTE'),
    has_function_privilege('authenticated', p.oid, 'EXECUTE'),
    has_function_privilege('service_role', p.oid, 'EXECUTE')
  FROM private.function_inventory fi
  JOIN pg_proc p ON p.proname = fi.function_name
  JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = fi.schema_name
  WHERE pg_get_function_identity_arguments(p.oid) = fi.identity_args
`);
for (const row of grantRows) {
  const [schema, name, args, expAnon, expAuth, expSvc, actAnon, actAuth, actSvc] = row;
  const label = `${schema}.${name}(${args})`;
  if (expAnon !== actAnon) failures.push(`${label}: anon EXECUTE expected=${expAnon} actual=${actAnon}`);
  if (expAuth !== actAuth) failures.push(`${label}: authenticated EXECUTE expected=${expAuth} actual=${actAuth}`);
  if (expSvc !== actSvc) failures.push(`${label}: service_role EXECUTE expected=${expSvc} actual=${actSvc}`);
}

// 3. Every SECURITY DEFINER function/procedure ANYWHERE (not just
// app/api/private — should-fix mirrors 10_function_inventory.sql's own
// M2(c) widening) sets search_path, excluding functions owned by an
// ALLOW-LISTED extension only (postgis/pgtap/pgcrypto — should-fix,
// post-P3a re-gate: a function from any OTHER extension is no longer
// exempted at all).
const missingSearchPath = psql(`
  SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE p.prokind IN ('f', 'p') AND p.prosecdef
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND NOT EXISTS (SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid WHERE d.objid = p.oid AND d.deptype = 'e' AND e.extname IN ('postgis', 'pgtap', 'pgcrypto'))
    AND NOT EXISTS (SELECT 1 FROM unnest(COALESCE(p.proconfig, '{}'::text[])) cfg WHERE cfg LIKE 'search_path=%')
`);
for (const [fn] of missingSearchPath) {
  failures.push(`SECURITY DEFINER function with no search_path set: ${fn}`);
}

// 4. M2(c)/should-fix: every SECURITY DEFINER function/procedure
// anywhere (non-allowlisted-extension) lives in schema `private` AND is owned by
// `private_definer` — the standalone-CLI mirror of
// 10_function_inventory.sql's own check.
const misplacedOrMisowned = psql(`
  SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         n.nspname, COALESCE(r.rolname, '<none>')
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  LEFT JOIN pg_roles r ON r.oid = p.proowner
  WHERE p.prokind IN ('f', 'p') AND p.prosecdef
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND NOT EXISTS (SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid WHERE d.objid = p.oid AND d.deptype = 'e' AND e.extname IN ('postgis', 'pgtap', 'pgcrypto'))
    AND (n.nspname <> 'private' OR r.rolname IS DISTINCT FROM 'private_definer')
`);
for (const [fn, schema, owner] of misplacedOrMisowned) {
  failures.push(`SECURITY DEFINER function outside private/not owned by private_definer: ${fn} (schema=${schema}, owner=${owner})`);
}

// 5. should-fix: every RLS policy applying to private_definer (direct
// grant or PUBLIC) is registered in private.definer_policy_allowlist,
// with a matching USING/WITH CHECK expression — the standalone-CLI
// mirror of 10_function_inventory.sql's own allow-list checks (both
// directions).
const unregisteredPolicies = psql(`
  SELECT n.nspname || '.' || cl.relname || '.' || pol.polname
  FROM pg_policy pol
  JOIN pg_class cl ON cl.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = cl.relnamespace
  CROSS JOIN pg_roles pr
  WHERE pr.rolname = 'private_definer'
    AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
    AND NOT EXISTS (
      SELECT 1 FROM private.definer_policy_allowlist al
      WHERE al.schema_name = n.nspname AND al.table_name = cl.relname AND al.policy_name = pol.polname
        AND al.command = CASE pol.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' ELSE pol.polcmd::text END
        AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
        AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)
    )
`);
for (const [p] of unregisteredPolicies) {
  failures.push(`RLS policy applying to private_definer with no matching private.definer_policy_allowlist row (or a mismatched expression): ${p}`);
}
const staleAllowlistRows = psql(`
  SELECT al.schema_name || '.' || al.table_name || '.' || al.policy_name
  FROM private.definer_policy_allowlist al
  WHERE NOT EXISTS (
    SELECT 1 FROM pg_policy pol
    JOIN pg_class cl ON cl.oid = pol.polrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    CROSS JOIN pg_roles pr
    WHERE pr.rolname = 'private_definer'
      AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
      AND n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
      AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
      AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)
  )
`);
for (const [row] of staleAllowlistRows) {
  failures.push(`private.definer_policy_allowlist row names no real policy applying to private_definer (stale or mismatched expression): ${row}`);
}

// 6. should-fix (post-P3a re-gate): "test 9's companion" — a checked-in
// fixture of the expected pg_get_expr() text for every
// private.definer_policy_allowlist row (supabase/tests/fixtures/
// definer_policy_exprs.txt), so a migration that changes a
// private_definer-scoped policy TOGETHER WITH its own allow-list row
// (self-consistent, so checks 5 above pass unchanged either way) still
// produces a VISIBLE diff in review: this file must be hand-regenerated
// and its diff reviewed whenever a real policy expression changes.
//
// This comparison lives HERE, not inside 10_function_inventory.sql's own
// pgTAP suite: reading an external file from plain SQL needs either
// `COPY ... FROM '<path>'` (server-side, requires superuser or
// pg_read_server_files — migration_owner has neither under
// HARNESS_MODE=restricted) or psql's own `\copy` meta-command (not
// reliably available through pg_prove's default TAP driver, which this
// harness uses when present). A plain Node script has ordinary
// filesystem access with neither constraint.
const fixturePath = join(import.meta.dirname, "..", "..", "supabase", "tests", "fixtures", "definer_policy_exprs.txt");
let fixtureRows;
try {
  fixtureRows = readFileSync(fixturePath, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => JSON.parse(line));
} catch (err) {
  failures.push(`could not read/parse ${fixturePath}: ${err.message}`);
  fixtureRows = [];
}

const keyOf = (r) => `${r.schema_name}\u0000${r.table_name}\u0000${r.policy_name}\u0000${r.command}`;
const fixtureByKey = new Map(fixtureRows.map((r) => [keyOf(r), r]));

// psql -A -t prints an empty field for a SQL NULL; a SQL boolean/USING
// expression is never itself an empty string, so treating "" as null
// here is unambiguous for this specific column's domain.
const liveRows = psql(`
  SELECT schema_name, table_name, policy_name, command, using_expr, with_check_expr
  FROM private.definer_policy_allowlist
  ORDER BY schema_name, table_name, policy_name, command
`).map(([schema_name, table_name, policy_name, command, using_expr, with_check_expr]) => ({
  schema_name,
  table_name,
  policy_name,
  command,
  using_expr: using_expr === "" ? null : using_expr,
  with_check_expr: with_check_expr === "" ? null : with_check_expr,
}));
const liveByKey = new Map(liveRows.map((r) => [keyOf(r), r]));

if (fixtureRows.length > 0 || liveRows.length > 0) {
  for (const live of liveRows) {
    const k = keyOf(live);
    const fx = fixtureByKey.get(k);
    if (!fx) {
      failures.push(
        `private.definer_policy_allowlist row ${live.schema_name}.${live.table_name}.${live.policy_name} (${live.command}) has no entry in supabase/tests/fixtures/definer_policy_exprs.txt — regenerate the fixture (see its own header comment)`,
      );
    } else if (fx.using_expr !== live.using_expr || fx.with_check_expr !== live.with_check_expr) {
      failures.push(
        `private.definer_policy_allowlist row ${live.schema_name}.${live.table_name}.${live.policy_name} (${live.command}) does not match supabase/tests/fixtures/definer_policy_exprs.txt — expected using_expr=${JSON.stringify(fx.using_expr)}/with_check_expr=${JSON.stringify(fx.with_check_expr)}, got using_expr=${JSON.stringify(live.using_expr)}/with_check_expr=${JSON.stringify(live.with_check_expr)}`,
      );
    }
  }
  for (const fx of fixtureRows) {
    const k = keyOf(fx);
    if (!liveByKey.has(k)) {
      failures.push(
        `supabase/tests/fixtures/definer_policy_exprs.txt names a row with no live match in private.definer_policy_allowlist: ${fx.schema_name}.${fx.table_name}.${fx.policy_name} (${fx.command}) — stale fixture entry, regenerate`,
      );
    }
  }
}

if (failures.length > 0) {
  console.error(`verify-function-inventory: ${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log("verify-function-inventory: OK — every app/api/private function is inventoried, grants match, search_path set.");
process.exit(0);
