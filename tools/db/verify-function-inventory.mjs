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

// 1. Every function in app/api/private is inventoried.
const uninventoried = psql(`
  SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  LEFT JOIN private.function_inventory fi
    ON fi.schema_name = n.nspname AND fi.function_name = p.proname
    AND fi.identity_args = pg_get_function_identity_arguments(p.oid)
  WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND fi.schema_name IS NULL
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

// 3. Every SECURITY DEFINER function sets search_path.
const missingSearchPath = psql(`
  SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname IN ('app', 'api', 'private') AND p.prosecdef
    AND NOT EXISTS (SELECT 1 FROM unnest(COALESCE(p.proconfig, '{}'::text[])) cfg WHERE cfg LIKE 'search_path=%')
`);
for (const [fn] of missingSearchPath) {
  failures.push(`SECURITY DEFINER function with no search_path set: ${fn}`);
}

if (failures.length > 0) {
  console.error(`verify-function-inventory: ${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log("verify-function-inventory: OK — every app/api/private function is inventoried, grants match, search_path set.");
process.exit(0);
