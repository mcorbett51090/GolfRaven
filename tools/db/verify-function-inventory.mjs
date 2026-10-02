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

// ⛔ FIX (BLOCKING follow-up, post-P3a re-gate round 4): `psql()` above
// (tab-per-column, newline-per-ROW) silently corrupts any column whose
// OWN value contains a literal newline -- every prior check only ever
// selected identifiers/booleans/short deparsed expressions, none of
// which do, so this never surfaced before. `pg_proc.prosrc` (check 7b,
// below) is a real function BODY and routinely spans multiple lines
// (both this project's real functions and this fix's own probe
// functions) -- confirmed empirically on a scratch cluster that pulling
// a multi-line prosrc through the plain `psql()` helper splits ONE
// logical row into several, silently breaking the 7b check (it looked
// like it was working against single-line SQL bodies in isolation, but
// failed to find the SAME probe row once its body spanned multiple
// lines). Used only where a column can legitimately contain embedded
// newlines: each output line is one JSON object (`row_to_json`), so an
// embedded newline is escaped `\n` inside the JSON string, never a
// literal line break in psql's own output.
function psqlJsonRows(sql) {
  const result = spawnSync("psql", ["-v", "ON_ERROR_STOP=1", "-A", "-t", "-c", sql], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`psql failed (exit ${result.status}): ${result.stderr}`);
  }
  return result.stdout
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));
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

// 2. Every inventory row's EXECUTE grants match, for each role (anon, authenticated, service_role and, since
// 0030, the two edge roles: private.function_inventory.expected_edge_actor / expected_edge_system).
const grantRows = psql(`
  SELECT
    fi.schema_name, fi.function_name, fi.identity_args,
    fi.expected_anon, fi.expected_authenticated, fi.expected_service_role,
    fi.expected_edge_actor, fi.expected_edge_system,
    has_function_privilege('anon', p.oid, 'EXECUTE'),
    has_function_privilege('authenticated', p.oid, 'EXECUTE'),
    has_function_privilege('service_role', p.oid, 'EXECUTE'),
    has_function_privilege('edge_actor', p.oid, 'EXECUTE'),
    has_function_privilege('edge_system', p.oid, 'EXECUTE')
  FROM private.function_inventory fi
  JOIN pg_proc p ON p.proname = fi.function_name
  JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = fi.schema_name
  WHERE pg_get_function_identity_arguments(p.oid) = fi.identity_args
`);
for (const row of grantRows) {
  const [schema, name, args, expAnon, expAuth, expSvc, expEdgeActor, expEdgeSystem, actAnon, actAuth, actSvc, actEdgeActor, actEdgeSystem] = row;
  const label = `${schema}.${name}(${args})`;
  if (expAnon !== actAnon) failures.push(`${label}: anon EXECUTE expected=${expAnon} actual=${actAnon}`);
  if (expAuth !== actAuth) failures.push(`${label}: authenticated EXECUTE expected=${expAuth} actual=${actAuth}`);
  if (expSvc !== actSvc) failures.push(`${label}: service_role EXECUTE expected=${expSvc} actual=${actSvc}`);
  if (expEdgeActor !== actEdgeActor) failures.push(`${label}: edge_actor EXECUTE expected=${expEdgeActor} actual=${actEdgeActor}`);
  if (expEdgeSystem !== actEdgeSystem) failures.push(`${label}: edge_system EXECUTE expected=${expEdgeSystem} actual=${actEdgeSystem}`);
}

// 3. Every SECURITY DEFINER function/procedure ANYWHERE (not just
// app/api/private — should-fix mirrors 10_function_inventory.sql's own
// M2(c) widening) sets search_path, excluding functions owned by an
// ALLOW-LISTED extension only (postgis/pgtap/pgcrypto — should-fix,
// post-P3a re-gate: a function from any OTHER extension is no longer
// exempted at all) AND pinned to a specific, empty-by-default allow-list
// of (extension, schema, function, args) tuples — should-fix, post-P3a
// re-gate: "ALTER EXTENSION pgcrypto ADD FUNCTION public.evil4() passes
// both checks", since mere pg_depend extension-membership is forgeable
// via that exact DDL command. See 10_function_inventory.sql's own,
// longer comment on this same pin for the full reasoning.
const missingSearchPath = psql(`
  SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE p.prokind IN ('f', 'p') AND p.prosecdef
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND NOT EXISTS (SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid WHERE d.objid = p.oid AND d.deptype = 'e' AND e.extname IN ('postgis', 'pgtap', 'pgcrypto') AND (e.extname, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)) IN (SELECT NULL::text, NULL::text, NULL::text, NULL::text WHERE false))
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
    AND NOT EXISTS (SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid WHERE d.objid = p.oid AND d.deptype = 'e' AND e.extname IN ('postgis', 'pgtap', 'pgcrypto') AND (e.extname, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)) IN (SELECT NULL::text, NULL::text, NULL::text, NULL::text WHERE false))
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

// ⛔ Read through psqlJsonRows (one JSON object per row), NOT psql(): a deparsed policy expression with a
// sub-select (pd_rescore_play_read, 0030; every edge policy that uses EXISTS) contains real newlines, which
// the tab/newline-split psql() helper silently turns into several bogus rows (the problem psqlJsonRows's own
// header describes). A SQL NULL arrives as JSON null, so no "" -> null mapping is needed.
const liveRows = psqlJsonRows(`
  SELECT row_to_json(t) FROM (
    SELECT schema_name, table_name, policy_name, command, using_expr, with_check_expr
    FROM private.definer_policy_allowlist
    ORDER BY schema_name, table_name, policy_name, command
  ) t
`);
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

// 7. ⛔ FIX (HIGH-1 regression, post-P3a re-gate round 3): every
// current_setting( call inside ANY RLS policy expression (USING or WITH
// CHECK), anywhere, must be wrapped in nullif(..., ''). Repro this round:
// set_config(name, value, true) ("is_local = true") only means "roll this
// back if the CURRENT transaction aborts" -- once that transaction
// COMMITS, the GUC keeps reading its set value (or, after a later RESET/
// clear, reads '' -- Postgres's own session-default for an unset text
// GUC, never NULL) for the REST of the session, and PostgREST/Supavisor
// reuse connections across unrelated requests. A bare
// current_setting(...)::uuid then raises "invalid input syntax for type
// uuid: """ the moment ANY later query on that same connection touches a
// table carrying that policy -- and since Postgres evaluates EVERY
// candidate policy for a role and ORs them together (it does not
// short-circuit past one that errors), ONE unwrapped policy anywhere on
// a table breaks every later query against it, even one a completely
// unrelated function runs for a completely unrelated reason (the
// concrete repro: private.offer_code_play_guard's own narrowly-scoped
// re-read started raising because of an UNRELATED older policy's
// unwrapped cast). nullif(x, '') turns a leftover '' into a genuine SQL
// NULL before any cast runs; NULL::uuid is simply NULL, never an error,
// and `col = NULL` is never true either way, so the fail-closed behaviour
// (no rows visible with no real target set) is unchanged -- only the
// ERROR is gone. Scans pg_policies system-wide (not just private_definer
// policies), since ANY role's policy carrying this shape is the same
// live bug waiting to happen.
//
// ⛔ FIX (BLOCKING follow-up, post-P3a re-gate round 4): "require the
// EXACT deparsed form ... flag any current_setting( that is not in
// exactly that shape, including a wrong sentinel or a missing
// missing_ok." The prior version of this check only looked 7 characters
// back for a case-insensitive "NULLIF(" prefix -- it would have PASSED
// nullif(current_setting('x', true), 'zz') (a wrong sentinel: masks
// every non-'zz' leftover value as well as the real '' placeholder, a
// silent over-broad match) and nullif(current_setting('x'), '') (missing
// the `, true` missing_ok argument: current_setting with ONE argument
// RAISES if the GUC has never been set at all in this session, rather
// than returning NULL -- a different, also-live failure mode this
// column was never checking for). Both are now required to match this
// EXACT substring, byte for byte:
//   NULLIF(current_setting('<any-guc-name>'::text, true), ''::text)
// -- confirmed empirically (probe policies on a throwaway scratch
// cluster, this round) that this is pg_get_expr's own canonical
// deparsed form for every CORRECTLY wrapped occurrence in this project's
// real migrations (the `::text` cast on the literal, the single space
// after each comma, and NULLIF rendered upper-case while current_setting
// stays lower-case are all pg_get_expr's own deparser behaviour, not
// this project's SQL source formatting -- confirmed the deparser
// produces this same shape regardless of how the source SQL itself was
// spaced/cased). A current_setting( occurrence whose surrounding text
// does not match this exact pattern -- wrong sentinel, missing
// missing_ok, wrong case, extra/missing whitespace, or no wrapping at
// all -- is flagged.
function findUnwrappedCurrentSetting(expr) {
  const exactFormRe = /NULLIF\(current_setting\('[^']*'::text, true\), ''::text\)/g;
  const validStarts = new Set();
  let m;
  while ((m = exactFormRe.exec(expr)) !== null) {
    validStarts.add(m.index + "NULLIF(".length); // start index of THIS match's "current_setting("
  }
  const needle = "current_setting(";
  let idx = 0;
  for (;;) {
    const found = expr.indexOf(needle, idx);
    if (found === -1) return false;
    if (!validStarts.has(found)) return true;
    idx = found + needle.length;
  }
}
const policyExprRows = psql(`
  SELECT schemaname || '.' || tablename || '.' || policyname,
         COALESCE(qual, ''), COALESCE(with_check, '')
  FROM pg_policies
  WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
    AND (COALESCE(qual, '') LIKE '%current_setting(%' OR COALESCE(with_check, '') LIKE '%current_setting(%')
`);
for (const [policy, qual, withCheck] of policyExprRows) {
  if (findUnwrappedCurrentSetting(qual)) {
    failures.push(`RLS policy ${policy}: USING expression contains a current_setting( not in the exact required form NULLIF(current_setting('...'::text, true), ''::text) — HIGH-1 regression, post-P3a re-gate round 3/4: ${qual}`);
  }
  if (findUnwrappedCurrentSetting(withCheck)) {
    failures.push(`RLS policy ${policy}: WITH CHECK expression contains a current_setting( not in the exact required form NULLIF(current_setting('...'::text, true), ''::text) — HIGH-1 regression, post-P3a re-gate round 3/4: ${withCheck}`);
  }
}

// 7b. ⛔ FIX (BLOCKING follow-up, post-P3a re-gate round 4): "wrapper
// functions. Extend #7 to find functions referenced from policy
// expressions ... and apply the same exact-form rule to their bodies."
// Check 7 above only ever looked at a policy's OWN qual/with_check TEXT
// -- a policy that reads the GUC indirectly, by calling a wrapper
// function (e.g. `USING (user_id = private.guc_uid())`), never contains
// the literal substring "current_setting(" in its own qual at all, so it
// was invisible to check 7 regardless of what that wrapper's body
// actually does. Closes that gap by finding every function each policy
// DEPENDS ON (via pg_depend, recorded when the policy was created against
// its USING/WITH CHECK expression -- precise, not a name-matching
// heuristic that could mismatch on an overloaded/shadowed name) and
// applying the SAME exact-form rule to that function's body (pg_proc.
// prosrc).
//
// ⛔ LIMIT (documented per the fix's own instruction -- also recorded in
// docs/security/p3-money-path-requirements.md): this follows ONE level
// of indirection only -- a policy calling function A is checked against
// A's own body, but if A's body itself calls a function B that reads the
// GUC, B is NOT checked. A second (or deeper) hop of indirection is a
// known, accepted gap, not silently unhandled -- there is no wrapper
// function in this project's own migrations more than one level deep
// today (confirmed by grep), so this is a documented residual risk for a
// FUTURE wrapper-of-a-wrapper, not a live bug.
//
// ⛔ DELIBERATE DIVERGENCE from check 7's own matcher, found empirically
// (probe policies + a probe WRAPPER FUNCTION on a scratch cluster, this
// round) before landing this: `pg_proc.prosrc` is the function body
// EXACTLY as the author wrote it in the CREATE FUNCTION statement --
// Postgres never runs it through pg_get_expr's deparser the way it does
// a policy's qual/with_check (which is why check 7's regex can safely
// require literal upper-case "NULLIF" and an inserted "::text" cast: that
// is pg_get_expr's own canonical rendering, confirmed empirically, not
// this project's source style). Reusing check 7's EXACT regex here
// verifiably FALSE-POSITIVES on a perfectly correct, lower-case,
// no-explicit-cast `nullif(current_setting('x', true), '')` function
// body -- confirmed on the scratch probe before this comment was
// written. `findUnwrappedCurrentSettingInSource` below enforces the same
// SEMANTIC shape (missing_ok literally `true`, sentinel literally `''`)
// but is case-insensitive and tolerates an optional `::text` cast either
// author may or may not have written, since that is the correct
// requirement for raw, un-deparsed source text.
function findUnwrappedCurrentSettingInSource(expr) {
  const exactFormRe = /nullif\s*\(\s*current_setting\s*\(\s*'[^']*'(?:\s*::\s*text)?\s*,\s*true\s*\)\s*,\s*''(?:\s*::\s*text)?\s*\)/gi;
  const validStarts = new Set();
  let m;
  while ((m = exactFormRe.exec(expr)) !== null) {
    const inner = /current_setting\s*\(/i.exec(m[0]);
    if (inner) validStarts.add(m.index + inner.index);
  }
  const needleRe = /current_setting\s*\(/gi;
  let mm;
  while ((mm = needleRe.exec(expr)) !== null) {
    if (!validStarts.has(mm.index)) return true;
  }
  return false;
}
const policyFunctionRows = psqlJsonRows(`
  SELECT row_to_json(t) FROM (
    SELECT pn.nspname || '.' || pc.relname || '.' || pol.polname AS policy,
           fn.nspname || '.' || fp.proname AS function_name,
           fp.prosrc AS prosrc
    FROM pg_policy pol
    JOIN pg_class pc ON pc.oid = pol.polrelid
    JOIN pg_namespace pn ON pn.oid = pc.relnamespace
    JOIN pg_depend d ON d.classid = 'pg_policy'::regclass AND d.objid = pol.oid AND d.refclassid = 'pg_proc'::regclass
    JOIN pg_proc fp ON fp.oid = d.refobjid
    JOIN pg_namespace fn ON fn.oid = fp.pronamespace
    WHERE pn.nspname NOT IN ('pg_catalog', 'information_schema')
      AND fp.prosrc ILIKE '%current_setting(%'
  ) t
`);
for (const { policy, function_name: functionName, prosrc } of policyFunctionRows) {
  if (findUnwrappedCurrentSettingInSource(prosrc)) {
    failures.push(
      `RLS policy ${policy} depends on function ${functionName}(), whose body contains a current_setting( not in the required shape nullif(current_setting('...', true), '') (case-insensitive, ::text cast optional — this is raw function source, never deparsed) — HIGH-1 regression, post-P3a re-gate round 4 (wrapper-function follow-up, one level deep): ${prosrc}`,
    );
  }
}

// 8. P3d gate round 3, S4: COLUMN-level "_r companion" check (was
// table-level in round 2). Table-level was insufficient — found this
// round: it passes as long as SOME SELECT(/ALL) policy exists ANYWHERE
// on a table, even if the SPECIFIC column a DELETE/UPDATE policy is
// scoped to has no SELECT visibility of its own. That matters because
// both `private.delete_my_data`'s own post-condition and
// `private.export_my_data` (0022) re-read through PER-COLUMN, RLS-gated
// SELECTs — a table-level "some policy exists" check can pass while one
// specific column is silently invisible to private_definer, which is
// EXACTLY the "reports success while the row survives" shape this check
// exists to prevent (see 0022's own post-condition comment for the full
// account, including the correction from round 2's table-level version).
//
// For every `private.pii_retention_policy` (table, column) pair
// classified `delete_row`/`set_null` — the exact set `delete_my_data`'s
// own generic pass touches via dynamic SQL — this requires a
// private_definer SELECT(/ALL) policy on the SAME table whose USING
// clause guards THAT column with the EXACT `nullif(current_setting(...))`
// form, reusing check 7's own "exact form, not a loose substring match"
// discipline (pg_get_expr's canonical deparsed shape, confirmed against
// this project's own real policies — see `NULLIF_COLUMN_RE` below).
const NULLIF_COLUMN_RE = /(\w+)\s*=\s*\(?NULLIF\(current_setting\('[^']*'::text,\s*true\),\s*''::text\)\)?(?:::\w+)?/g;
function columnsGuardedByNullifCurrentSetting(usingExpr) {
  const cols = new Set();
  if (!usingExpr) return cols;
  const re = new RegExp(NULLIF_COLUMN_RE.source, "g");
  let m;
  while ((m = re.exec(usingExpr)) !== null) cols.add(m[1]);
  return cols;
}
const selectPolicyRowsForRCompanion = psql(`
  SELECT n.nspname, cl.relname, pg_get_expr(pol.polqual, pol.polrelid)
  FROM pg_policy pol
  JOIN pg_class cl ON cl.oid = pol.polrelid
  JOIN pg_namespace n ON n.oid = cl.relnamespace
  CROSS JOIN pg_roles pr
  WHERE pr.rolname = 'private_definer'
    AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
    AND pol.polcmd IN ('r', '*')
`);
const rCompanionGuardedColumnsByTable = new Map(); // "schema.table" -> Set<column>
for (const [schema, table, usingExpr] of selectPolicyRowsForRCompanion) {
  const key = `${schema}.${table}`;
  let set = rCompanionGuardedColumnsByTable.get(key);
  if (!set) {
    set = new Set();
    rCompanionGuardedColumnsByTable.set(key, set);
  }
  for (const col of columnsGuardedByNullifCurrentSetting(usingExpr)) set.add(col);
}
const registryColumnRowsForRCompanion = psql(`
  SELECT schema_name, table_name, column_name
  FROM private.pii_retention_policy
  WHERE schema_name = 'app' AND action IN ('delete_row', 'set_null')
`);
const missingRCompanion = registryColumnRowsForRCompanion.filter(([schema, table, column]) => {
  const guarded = rCompanionGuardedColumnsByTable.get(`${schema}.${table}`);
  return !guarded || !guarded.has(column);
});
for (const [schema, table, column] of missingRCompanion) {
  failures.push(`private.pii_retention_policy column ${schema}.${table}.${column} (delete_row/set_null) has no private_definer SELECT(/ALL) policy whose USING clause guards THAT column with the exact nullif(current_setting(...)) form — column-level "_r companion" check, P3d gate round 3 S4: ${schema}.${table}.${column}`);
}


// 9-13. The edge roles (supabase/migrations/0030_edge_role_core.sql, 0031_edge_role_policies.sql, 0032_edge_role_hardening.sql;
// docs/security/edge-role-design.md). The five queries below are the SAME text as the session-local functions
// in supabase/tests/matrix/10_function_inventory.sql, which proves each one on the clean schema and must-fails
// it on a planted defect; here they run against the live cluster as a standalone CLI check. Each returns one
// row per violation (none = clean).
//
//  9  the membership closure of edge_gateway / edge_actor / edge_system is clean: it reaches no role outside
//     the three, none holds SUPERUSER / BYPASSRLS / CREATEROLE / CREATEDB / REPLICATION / INHERIT, only
//     edge_gateway can log in, nobody else can SET ROLE to one of them, edge_gateway holds
//     SET TRUE / INHERIT FALSE membership of the other two, and (0032, L2) no membership of an edge role carries
//     ADMIN OPTION unless its holder is a superuser or a CREATEROLE role (the migrating role).
//  10 every RLS policy that applies to edge_actor or edge_system (directly or through PUBLIC) is in
//     private.edge_policy_allowlist with the same role, command and deparsed text, and every allowlist row
//     names a live policy (both directions) -- plus the checked-in fixture (below) so a self-consistent
//     policy+row edit still shows as a diff in review.
//  11 edge policies reference private.actor_uid() and no other identity source (no auth.uid() / jwt / GUC /
//     session_user / current_user, no dependency on any function but actor_uid() and, for the pseudonym-keyed
//     install-link tombstone, account_pseudonyms()); an actor-scope policy
//     must contain it; an open_read policy must be SELECT USING (true).
//  12 edge_system has no policy and no privilege on any PII-registered table; no edge role holds a privilege
//     outside schema app, or on an app table without FORCE ROW LEVEL SECURITY -- in EVERY non-system schema (0032, L2:
//     not a fixed list; extension-owned relations such as postgis' spatial_ref_sys are exempt) -- and no edge role
//     can CREATE in any schema.
//  13 (0032, L1) no SECURITY DEFINER function in app/api/private reads an UNQUALIFIED pg_* relation: edge_actor holds
//     TEMP, pg_temp is searched before pg_catalog for relations even with search_path = '', so a temp table named
//     pg_constraint would shadow the catalog under the definer. (All definers, a superset of "reachable from edge_*".)
const edgeChecks = [
  [9, "membership closure / attributes", `WITH RECURSIVE edge AS (
  SELECT oid, rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system')
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
WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system') AND a.is_on
UNION ALL
SELECT 'edge role can log in but must not: ' || rolname FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system') AND rolcanlogin
UNION ALL
SELECT 'role ' || m.rolname || ' can SET ROLE to / inherit from edge role ' || r.rolname
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system') AND m.rolname NOT IN ('edge_gateway', 'edge_actor', 'edge_system') AND (am.set_option OR am.inherit_option)
UNION ALL
SELECT 'edge role membership holds ADMIN OPTION for a role that is neither a superuser nor a CREATEROLE role (only the migrating role may): ' || m.rolname || ' -> ' || r.rolname
FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system') AND am.admin_option AND NOT (m.rolsuper OR m.rolcreaterole)
UNION ALL
SELECT 'edge_gateway is not a SET TRUE, INHERIT FALSE member of ' || t.rolname
FROM pg_roles t WHERE t.rolname IN ('edge_actor', 'edge_system')
  AND NOT EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.member
                  WHERE am.roleid = t.oid AND g.rolname = 'edge_gateway' AND am.set_option AND NOT am.inherit_option)`],
  [10, "policy allowlist, both directions", `WITH live AS (
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
    AND al.using_expr IS NOT DISTINCT FROM l.using_expr AND al.with_check_expr IS NOT DISTINCT FROM l.with_check_expr)`],
  [11, "identity source", `WITH live AS (
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
WHERE (coalesce(l.using_expr, '') || ' ' || coalesce(l.with_check_expr, '')) ~* '(auth\\.(uid|jwt|role|email)\\s*\\(|current_setting\\s*\\(|set_config\\s*\\(|request\\.jwt|session_user|current_user)'
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
WHERE al.role_name = 'edge_system' AND al.scope <> 'system_write'`],
  [12, "PII tables / FORCE RLS", `WITH pii AS (
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
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system')) r
WHERE cl.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = cl.oid AND d.deptype = 'e')
  AND (has_any_column_privilege(r.rolname, cl.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.rolname, cl.oid, 'DELETE,TRUNCATE,TRIGGER'))
  AND (n.nspname <> 'app' OR NOT (cl.relrowsecurity AND cl.relforcerowsecurity))
UNION ALL
SELECT 'an edge role can CREATE in schema ' || n.nspname || ' (' || r.rolname || ')'
FROM pg_namespace n
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system')) r
WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'
  AND has_schema_privilege(r.rolname, n.oid, 'CREATE')`],
  [13, "definer bodies: unqualified catalog relations", `SELECT 'SECURITY DEFINER function reads an unqualified pg_ relation (a temp relation of that name would shadow the catalog): ' || n.nspname || '.' || p.proname || ' -> ' || m[1]
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN LATERAL regexp_matches(regexp_replace(p.prosrc, '--[^\\n]*', '', 'g'), '\\m(?:from|join|update|into|table)\\s+(pg_[a-z_]+)\\M(?!\\.|\\s*\\()', 'gi') AS m
WHERE p.prosecdef AND n.nspname IN ('app', 'api', 'private')`],
];
for (const [num, label, sql] of edgeChecks) {
  for (const [violation] of psql(sql)) {
    failures.push(`edge-role check ${num} (${label}): ${violation}`);
  }
}

// 10b. The checked-in fixture of every private.edge_policy_allowlist row's deparsed text
// (supabase/tests/fixtures/edge_policy_exprs.txt) -- the edge twin of check 6 above, for the same reason.
const edgeFixturePath = join(import.meta.dirname, "..", "..", "supabase", "tests", "fixtures", "edge_policy_exprs.txt");
let edgeFixtureRows;
try {
  edgeFixtureRows = readFileSync(edgeFixturePath, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => JSON.parse(line));
} catch (err) {
  failures.push(`could not read/parse ${edgeFixturePath}: ${err.message}`);
  edgeFixtureRows = [];
}
const edgeKeyOf = (r) => `${r.schema_name}\u0000${r.table_name}\u0000${r.policy_name}`;
const edgeFixtureByKey = new Map(edgeFixtureRows.map((r) => [edgeKeyOf(r), r]));
// psqlJsonRows for the same reason as check 6 above (edge policies deparse with embedded newlines).
const edgeLiveRows = psqlJsonRows(`
  SELECT row_to_json(t) FROM (
    SELECT schema_name, table_name, policy_name, role_name, command, scope, using_expr, with_check_expr
    FROM private.edge_policy_allowlist
    ORDER BY schema_name, table_name, policy_name
  ) t
`);
const edgeLiveByKey = new Map(edgeLiveRows.map((r) => [edgeKeyOf(r), r]));
for (const live of edgeLiveRows) {
  const fx = edgeFixtureByKey.get(edgeKeyOf(live));
  const name = `${live.schema_name}.${live.table_name}.${live.policy_name}`;
  if (!fx) {
    failures.push(`private.edge_policy_allowlist row ${name} has no entry in supabase/tests/fixtures/edge_policy_exprs.txt -- regenerate the fixture (see its own header comment)`);
  } else if (
    fx.role_name !== live.role_name || fx.command !== live.command || fx.scope !== live.scope ||
    fx.using_expr !== live.using_expr || fx.with_check_expr !== live.with_check_expr
  ) {
    failures.push(`private.edge_policy_allowlist row ${name} does not match supabase/tests/fixtures/edge_policy_exprs.txt -- expected ${JSON.stringify(fx)}, got ${JSON.stringify(live)}`);
  }
}
for (const fx of edgeFixtureRows) {
  if (!edgeLiveByKey.has(edgeKeyOf(fx))) {
    failures.push(`supabase/tests/fixtures/edge_policy_exprs.txt names a row with no live match in private.edge_policy_allowlist: ${fx.schema_name}.${fx.table_name}.${fx.policy_name} -- stale fixture entry, regenerate`);
  }
}

if (failures.length > 0) {
  console.error(`verify-function-inventory: ${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log("verify-function-inventory: OK — every app/api/private function is inventoried, grants match, search_path set.");
process.exit(0);
