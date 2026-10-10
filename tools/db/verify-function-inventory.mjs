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
import { readdirSync, readFileSync } from "node:fs";
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
// 0030, the two edge roles: private.function_inventory.expected_edge_actor / expected_edge_system; since 0041, the proof minter
// edge_signin_minter: expected_edge_signin_minter, true for exactly one function; and, since 0047, edge_partner and edge_partner_minter).
const grantRows = psql(`
  SELECT
    fi.schema_name, fi.function_name, fi.identity_args,
    fi.expected_anon, fi.expected_authenticated, fi.expected_service_role,
    fi.expected_edge_actor, fi.expected_edge_system, fi.expected_edge_signin_minter,
    fi.expected_edge_partner, fi.expected_edge_partner_minter,
    has_function_privilege('anon', p.oid, 'EXECUTE'),
    has_function_privilege('authenticated', p.oid, 'EXECUTE'),
    has_function_privilege('service_role', p.oid, 'EXECUTE'),
    has_function_privilege('edge_actor', p.oid, 'EXECUTE'),
    has_function_privilege('edge_system', p.oid, 'EXECUTE'),
    has_function_privilege('edge_signin_minter', p.oid, 'EXECUTE'),
    has_function_privilege('edge_partner', p.oid, 'EXECUTE'),
    has_function_privilege('edge_partner_minter', p.oid, 'EXECUTE')
  FROM private.function_inventory fi
  JOIN pg_proc p ON p.proname = fi.function_name
  JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = fi.schema_name
  WHERE pg_get_function_identity_arguments(p.oid) = fi.identity_args
`);
for (const row of grantRows) {
  const [schema, name, args, expAnon, expAuth, expSvc, expEdgeActor, expEdgeSystem, expEdgeMinter, expEdgePartner, expEdgePartnerMinter, actAnon, actAuth, actSvc, actEdgeActor, actEdgeSystem, actEdgeMinter, actEdgePartner, actEdgePartnerMinter] = row;
  const label = `${schema}.${name}(${args})`;
  if (expAnon !== actAnon) failures.push(`${label}: anon EXECUTE expected=${expAnon} actual=${actAnon}`);
  if (expAuth !== actAuth) failures.push(`${label}: authenticated EXECUTE expected=${expAuth} actual=${actAuth}`);
  if (expSvc !== actSvc) failures.push(`${label}: service_role EXECUTE expected=${expSvc} actual=${actSvc}`);
  if (expEdgeActor !== actEdgeActor) failures.push(`${label}: edge_actor EXECUTE expected=${expEdgeActor} actual=${actEdgeActor}`);
  if (expEdgeSystem !== actEdgeSystem) failures.push(`${label}: edge_system EXECUTE expected=${expEdgeSystem} actual=${actEdgeSystem}`);
  if (expEdgeMinter !== actEdgeMinter) failures.push(`${label}: edge_signin_minter EXECUTE expected=${expEdgeMinter} actual=${actEdgeMinter}`);
  if (expEdgePartner !== actEdgePartner) failures.push(`${label}: edge_partner EXECUTE expected=${expEdgePartner} actual=${actEdgePartner}`);
  if (expEdgePartnerMinter !== actEdgePartnerMinter) failures.push(`${label}: edge_partner_minter EXECUTE expected=${expEdgePartnerMinter} actual=${actEdgePartnerMinter}`);
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
    AND (n.nspname <> 'private' OR NOT (coalesce(r.rolname, '') = ANY (ARRAY['private_definer', 'partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier'])))
`);
for (const [fn, schema, owner] of misplacedOrMisowned) {
  failures.push(`SECURITY DEFINER function outside private/not owned by private_definer (or one of the six 0047 owner roles): ${fn} (schema=${schema}, owner=${owner})`);
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
  WHERE pr.rolname = ANY (ARRAY['private_definer', 'partner_session_toucher', 'partner_session_issuer', 'partner_pin_verifier', 'partner_totp_verifier', 'partner_reauth_verifier'])
    AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
    AND NOT EXISTS (
      SELECT 1 FROM private.definer_policy_allowlist al
      WHERE al.schema_name = n.nspname AND al.table_name = cl.relname AND al.policy_name = pol.polname AND al.role_name = pr.rolname
        AND al.command = CASE pol.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' WHEN '*' THEN 'ALL' ELSE pol.polcmd::text END
        AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
        AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)
    )
`);
for (const [p] of unregisteredPolicies) {
  failures.push(`RLS policy applying to private_definer or one of the six 0047 owner roles with no matching private.definer_policy_allowlist row (same role_name, command and expressions): ${p}`);
}
const staleAllowlistRows = psql(`
  SELECT al.schema_name || '.' || al.table_name || '.' || al.policy_name
  FROM private.definer_policy_allowlist al
  WHERE NOT EXISTS (
    SELECT 1 FROM pg_policy pol
    JOIN pg_class cl ON cl.oid = pol.polrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    CROSS JOIN pg_roles pr
    WHERE pr.rolname = al.role_name
      AND (pr.oid = ANY (pol.polroles) OR pol.polroles @> ARRAY[0]::oid[])
      AND n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
      AND al.using_expr IS NOT DISTINCT FROM pg_get_expr(pol.polqual, pol.polrelid)
      AND al.with_check_expr IS NOT DISTINCT FROM pg_get_expr(pol.polwithcheck, pol.polrelid)
  )
`);
for (const [row] of staleAllowlistRows) {
  failures.push(`private.definer_policy_allowlist row names no real policy applying to its role_name (stale or mismatched expression): ${row}`);
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
    SELECT schema_name, table_name, policy_name, command, using_expr, with_check_expr, role_name
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
    } else if (fx.using_expr !== live.using_expr || fx.with_check_expr !== live.with_check_expr || (fx.role_name ?? "private_definer") !== live.role_name) {
      failures.push(
        `private.definer_policy_allowlist row ${live.schema_name}.${live.table_name}.${live.policy_name} (${live.command}) does not match supabase/tests/fixtures/definer_policy_exprs.txt — expected role_name=${fx.role_name ?? "private_definer"}/using_expr=${JSON.stringify(fx.using_expr)}/with_check_expr=${JSON.stringify(fx.with_check_expr)}, got role_name=${live.role_name}/ using_expr=${JSON.stringify(live.using_expr)}/with_check_expr=${JSON.stringify(live.with_check_expr)}`,
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
           CASE WHEN fp.prokind IN ('f', 'p') THEN pg_get_functiondef(fp.oid) END AS prosrc
    FROM pg_policy pol
    JOIN pg_class pc ON pc.oid = pol.polrelid
    JOIN pg_namespace pn ON pn.oid = pc.relnamespace
    JOIN pg_depend d ON d.classid = 'pg_policy'::regclass AND d.objid = pol.oid AND d.refclassid = 'pg_proc'::regclass
    JOIN pg_proc fp ON fp.oid = d.refobjid
    JOIN pg_namespace fn ON fn.oid = fp.pronamespace
    WHERE pn.nspname NOT IN ('pg_catalog', 'information_schema')
      AND fp.prokind IN ('f', 'p')
      AND pg_get_functiondef(fp.oid) ~* '\\mcurrent_setting\\s*\\('
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
//     (0047) The same closure covers edge_partner and edge_partner_minter (NOLOGIN, a member of nothing, edge_gateway their only member), and the six OWNER
//     roles partner_session_toucher / _issuer / partner_pin_verifier / _totp_verifier / _reauth_verifier: NOLOGIN, none of the attributes, a member of
//     nothing and with NO member (R5-L3, the 0041 form: the migrating role may keep ADMIN, never SET or INHERIT).
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
//  13 (0032, L1; widened in 0033 for the PR1b gate's LOW-2: comma lists `FROM a, pg_class c` and `DELETE ... USING pg_roles`)
//     no SECURITY DEFINER function in app/api/private reads an UNQUALIFIED pg_* relation: edge_actor holds
//     TEMP, pg_temp is searched before pg_catalog for relations even with search_path = '', so a temp table named
//     pg_constraint would shadow the catalog under the definer. (All definers, a superset of "reachable from edge_*".)
const edgeChecks = [
  [9, "membership closure / attributes", `WITH RECURSIVE edge AS (
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
  AND NOT m.rolsuper AND (NOT m.rolcreaterole OR am.set_option OR am.inherit_option)`],
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
    AND al.using_expr IS NOT DISTINCT FROM l.using_expr AND al.with_check_expr IS NOT DISTINCT FROM l.with_check_expr)
UNION ALL
SELECT 'a policy applies to ' || r.rolname || ' (it may have none): ' || n.nspname || '.' || cl.relname || '.' || pol.polname
FROM pg_policy pol JOIN pg_class cl ON cl.oid = pol.polrelid JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN pg_roles r ON r.oid = ANY (pol.polroles) AND r.rolname IN ('edge_signin_minter', 'edge_partner', 'edge_partner_minter')`],
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
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter')) r
WHERE cl.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = cl.oid AND d.deptype = 'e')
  AND (has_any_column_privilege(r.rolname, cl.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.rolname, cl.oid, 'DELETE,TRUNCATE,TRIGGER'))
  AND (n.nspname <> 'app' OR NOT (cl.relrowsecurity AND cl.relforcerowsecurity))
UNION ALL
SELECT 'an edge role can CREATE in schema ' || n.nspname || ' (' || r.rolname || ')'
FROM pg_namespace n
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter', 'edge_partner', 'edge_partner_minter')) r
WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'
  AND has_schema_privilege(r.rolname, n.oid, 'CREATE')
UNION ALL
SELECT r.rolname || ' holds a privilege on a relation (it may hold none, in any schema): ' || n.nspname || '.' || cl.relname
FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace
CROSS JOIN (SELECT rolname FROM pg_roles WHERE rolname IN ('edge_signin_minter', 'edge_partner', 'edge_partner_minter')) r
WHERE cl.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'
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
  WHERE e.role_name = a.role_name AND e.object_kind = a.object_kind AND e.object_name = a.object_name AND e.privilege = a.privilege AND e.column_name IS NOT DISTINCT FROM a.column_name)`],
  [13, "definer bodies: unqualified catalog relations", `SELECT 'SECURITY DEFINER function reads an unqualified pg_ relation (a temp relation of that name would shadow the catalog): ' || n.nspname || '.' || p.proname || ' -> ' || m[1]
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN LATERAL regexp_matches(regexp_replace(p.prosrc, '--[^\\n]*', '', 'g'), '(?:\\m(?:from|join|update|into|table|using)\\s+|,\\s*)(pg_[a-z_]+)\\M(?!\\.|\\s*\\()', 'gi') AS m
WHERE p.prosecdef AND n.nspname IN ('app', 'api', 'private')`],
  [14, "partner family: first-statement rule, lexing limits, no EXCEPTION, class literal, no user-lane partner scope, no stray kind reader, lane-only EXECUTE, the edge_partner EXECUTE set", `WITH RECURSIVE fam AS (
  SELECT p.oid, n.nspname, p.proname, l.lanname, p.prosrc AS raw,
         n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS ident,
         regexp_replace(p.prosrc, '((?:/\\*(?:[^*]|\\*+[^*/])*\\*+/)|(?:--[^\\n]*))|(''(?:[^'']|'''')*'')', ' \\2', 'g') AS kept
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
  WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND p.proname LIKE '%\\_for\\_partner'
), body AS (
  SELECT f.*, trim(lower(regexp_replace(regexp_replace(f.kept, '''(?:[^'']|'''')*''', '''''', 'g'), '\\s+', ' ', 'g'))) AS b
  FROM fam f
), first AS (
  SELECT f.oid, f.nspname, f.proname,
         trim(split_part(CASE WHEN f.lanname = 'plpgsql' THEN coalesce(substring(f.b from '(?:^| )begin (.*)$'), '') ELSE f.b END, ';', 1)) AS stmt
  FROM body f
), collapse(oid, nspname, proname, s, n) AS (
  SELECT oid, nspname, proname, stmt, 0 FROM first
  UNION ALL
  SELECT oid, nspname, proname, regexp_replace(s, '\\([^()]*\\)', '', 'g'), n + 1 FROM collapse WHERE n < 12 AND s ~ '[()]'
)
SELECT '(a) a *_for_partner function whose first executable statement is not a call of private.partner_authorize: ' || c.nspname || '.' || c.proname
FROM collapse c
WHERE c.n = (SELECT max(c2.n) FROM collapse c2 WHERE c2.oid = c.oid)
  AND c.s !~ '^(perform |[a-z_][a-z0-9_]* := |select )private\\.partner_authorize\\s*( into [a-z_][a-z0-9_]*)?\\s*$'
UNION ALL
SELECT '(a0) a *_for_partner function body contains a dollar quote, a double-quoted identifier, a backslash, an E-string or a nested comment, which the first-statement check cannot lex: ' || f.ident
FROM fam f
WHERE strpos(f.raw, chr(36)) > 0 OR strpos(f.raw, chr(34)) > 0 OR strpos(f.raw, chr(92)) > 0 OR f.raw ~* '(^|[^a-z0-9_])e'''
   OR strpos(f.kept, '/*') > 0 OR strpos(f.kept, '*/') > 0
UNION ALL
SELECT '(a2) a *_for_partner function has an EXCEPTION ... WHEN block, which could swallow the 42501 of private.partner_authorize: ' || f.ident
FROM body f
WHERE f.b ~ '\\mexception\\s+when\\M'
UNION ALL
SELECT '(a3) a *_for_partner function whose private.partner_authorize class is not a string literal in A0 / A0_WRITE / A0_KEEPALIVE / A0_MFA / A0_ENROL / A1 / A2 / A3 (SESSION and PEEK only for a function named in supabase/tests/fixtures/partner_session_class_functions.txt): ' || c.ident
FROM (
  SELECT f.ident,
         (regexp_match((regexp_match(f.kept, 'private\\.partner_authorize\\s*\\(([^;]*)\\)\\s*(?:;|$)', 'i'))[1], ',\\s*''([A-Za-z0-9_]+)''\\s*$'))[1] AS cls
  FROM fam f
) c
WHERE c.cls IS NULL
   OR (c.cls NOT IN ('A0', 'A0_WRITE', 'A0_KEEPALIVE', 'A0_MFA', 'A0_ENROL', 'A1', 'A2', 'A3') AND NOT (c.cls IN ('SESSION', 'PEEK') AND c.ident = ANY (/* session_class_functions */ ARRAY['private.partner_whoami_for_partner()', 'private.partner_session_revoke_for_partner()', 'private.partner_session_lock_for_partner()'] /* end_session_class_functions */)))
UNION ALL
SELECT '(b) an edge_actor-executable definer outside the *_for_partner family evaluates partner scope: ' || n.nspname || '.' || p.proname
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND p.prosecdef AND has_function_privilege('edge_actor', p.oid, 'EXECUTE')
  AND p.proname NOT LIKE '%\\_for\\_partner'
  AND regexp_replace(p.prosrc, '(?:/\\*(?:[^*]|\\*+[^*/])*\\*+/)|(?:--[^\\n]*)|(?:''(?:[^'']|'''')*'')', ' ', 'g')
        ~* '\\m(has_facility_scope|has_trail_scope|has_sponsorship_scope|is_staff_or_manager_of_facility|is_manager_or_operator_of_facility|is_operator_of_facility|is_org_member|is_admin|partner_member|partner_scope)\\M'
UNION ALL
SELECT '(c) a function outside the *_for_partner family reads the actor binding or kind = ''partner'' (put it in the family, or name it in supabase/tests/fixtures/partner_kind_readers.txt after review): ' || n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f'
  AND p.proname NOT LIKE '%\\_for\\_partner'
  AND (regexp_replace(p.prosrc, '((?:/\\*(?:[^*]|\\*+[^*/])*\\*+/)|(?:--[^\\n]*))|(''(?:[^'']|'''')*'')', ' \\2', 'g') ~ '''partner'''
       OR regexp_replace(p.prosrc, '((?:/\\*(?:[^*]|\\*+[^*/])*\\*+/)|(?:--[^\\n]*))|(''(?:[^'']|'''')*'')', ' \\2', 'g') ~* '\\m(actor_binding|partner_binding(_kind|_session)?)\\M')
  AND (n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')') <> ALL (/* kind_readers */ ARRAY['private.actor_uid()', 'private.bind_actor_internal(p_uid uuid, p_kind text)', 'private.bind_partner_session(p_token_hash text)', 'private.partner_binding()', 'private.partner_binding_kind()', 'private.partner_binding_session()', 'private.partner_authorize(p_facility_id text, p_trail_id text, p_roles app.partner_role[], p_class text)', 'private.partner_audit_write(p_action text, p_subject_table text, p_subject_id text, p_detail jsonb)', 'private.partner_authority_revoke_sessions()', 'private.partner_pin_grant_consume()', 'private.activate_entitlement_for_actor(p_entitlement_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb)', 'private.activate_offer_code_for_actor(p_code_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb)', 'private.claim_device_platform_for_actor(p_device_id uuid, p_platform text)', 'private.delete_my_data_for_actor()', 'private.export_my_data_for_actor()', 'private.offline_code_bound_staff()', 'private.offline_code_record_step_for_actor(p_device_id uuid, p_seed_version integer, p_step bigint, p_facility_id text)', 'private.offline_seed_for_actor(p_device_id uuid, p_rotate boolean)', 'private.register_attest_key_for_actor(p_device_id uuid, p_key_id text, p_public_key bytea)', 'private.signin_bound_user(p_who text)', 'private.signin_record_email_proof(p_caller_user_id uuid, p_target_user_id uuid, p_email text, p_provider text, p_provider_sub text, p_session_id uuid)', 'private.course_pin_attempt_for_actor(p_facility_id text, p_pin text, p_at timestamp with time zone)', 'private.course_qr_public_key_for_actor(p_kid text, p_purpose text)', 'private.marker_cosignal_attach_for_actor(p_facility_id text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid)', 'private.offer_offline_confirm_for_actor(p_facility_id text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid)', 'private.receipt_intake_for_actor(p_facility_id text, p_phash text, p_storage_object text, p_local_date date, p_receipt_number_ocr text)', 'private.marker_scan_for_actor(p_facility_id text, p_variant text, p_nonce_hash text, p_qr_kid text, p_pin text, p_at timestamp with time zone, p_cosignal_grade text, p_cosignal_fix_id text, p_cosignal_evidence_id uuid)', 'private.partner_challenge_issue_sign_in()', 'private.partner_session_mint(p_token_hash text, p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)', 'private.hit_partner_rate_limit(p_bucket_key text, p_window interval, p_max integer)', 'private.partner_credential_lookup(p_credential_id bytea)', 'private.partner_sign_in_failure_record(p_credential_id bytea)', 'private.partner_reauth_apply(p_credential_id bytea, p_nonce bytea, p_exp bigint, p_mac bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea)', 'private.partner_reauth_clear()', 'private.partner_binding_user()', 'private.partner_pin_verify_apply(p_derived bytea)', 'private.partner_pin_set_apply(p_mode text, p_derived bytea, p_salt bytea, p_iterations integer, p_current bytea)', 'private.partner_pin_params_read()', 'private.partner_pin_grant_consume_fresh(p_max_age_seconds integer)', 'private.partner_totp_enrol_apply()', 'private.partner_totp_confirm_apply(p_code text)', 'private.partner_totp_verify_apply(p_code text)', 'private.partner_totp_mfa_clear()', 'private.partner_challenge_issue_register(p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_accepted_at_us bigint)', 'private.partner_invite_email_for_token(p_token_hash text)', 'private.partner_invite_accept(p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid)', 'private.partner_enrolment_token_email_for_token(p_token_hash text)', 'private.partner_enrolment_token_accept(p_token_hash text, p_verified_uid uuid, p_gotrue_session_id uuid)', 'private.partner_credential_register_first(p_token_hash text, p_user_id uuid, p_ref_kind smallint, p_ref_id uuid, p_nonce bytea, p_exp bigint, p_mac bytea, p_attestation_object bytea, p_client_data_json bytea, p_credential_id bytea, p_public_key bytea, p_transports text[])', 'private.partner_bound_staff_at(p_facility_id text)', 'private.partner_bound_manager_at(p_facility_id text)', 'private.partner_bound_staff_any()', 'private.partner_bound_admin()', 'private.partner_bound_operator_at_trail(p_trail_id text)'] /* end_kind_readers */)
UNION ALL
SELECT '(d) a *_for_partner function is EXECUTE-able by edge_actor, edge_system or PUBLIC (the partner lane is edge_partner alone): ' || n.nspname || '.' || p.proname
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND p.proname LIKE '%\\_for\\_partner'
  AND (has_function_privilege('edge_actor', p.oid, 'EXECUTE') OR has_function_privilege('edge_system', p.oid, 'EXECUTE')
       OR EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))
UNION ALL
SELECT '(e) edge_partner holds an EXECUTE grant outside its allowed set (bind_partner_session, partner_binding, partner_binding_kind, hit_partner_rate_limit and the *_for_partner family): ' || n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind IN ('f', 'p') AND has_function_privilege('edge_partner', p.oid, 'EXECUTE')
  AND (n.nspname || '.' || p.proname || '(' || oidvectortypes(p.proargtypes) || ')') <> ALL (ARRAY['private.bind_partner_session(text)', 'private.partner_binding()', 'private.partner_binding_kind()', 'private.hit_partner_rate_limit(text, interval, integer)'])
  AND p.proname NOT LIKE '%\\_for\\_partner'
`],
  [15, "every GUC-keyed private_definer policy ends its window with the top-level partner conjunct", `WITH tails(tail) AS (
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
  SELECT * FROM exprs x WHERE x.e IS NOT NULL AND (x.e ~* '\\mcurrent_setting\\s*\\(' OR x.e ~* '\\mpg_settings\\M'
    OR EXISTS (SELECT 1 FROM pg_depend d JOIN pg_proc fp ON fp.oid = d.refobjid WHERE d.classid = 'pg_policy'::regclass AND d.objid = x.poloid AND d.refclassid = 'pg_proc'::regclass
      AND (CASE WHEN fp.prokind IN ('f', 'p') THEN pg_get_functiondef(fp.oid) END ~* '\\mcurrent_setting\\s*\\(' OR CASE WHEN fp.prokind IN ('f', 'p') THEN pg_get_functiondef(fp.oid) END ~* '\\mpg_settings\\M')))
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
WHERE NOT EXISTS (SELECT 1 FROM depth d WHERE d.nspname = w.nspname AND d.relname = w.relname AND d.polname = w.polname AND d.part = w.part AND d.lo >= 1 AND d.hi = 1)`],
];
// 14 (c) and (a3): two named lists, each a checked-in fixture (one `schema.name(identity args)` per line, '#' comments).
//   * supabase/tests/fixtures/partner_kind_readers.txt: functions OUTSIDE the *_for_partner family that may read the actor binding or kind = 'partner' (the binders and their
//     helpers, the user-lane `_for_actor` definers that refuse a non-user binding, actor_uid()). Every entry was reviewed; a new reader is added HERE, after review, or put in the family.
//   * supabase/tests/fixtures/partner_session_class_functions.txt: the *_for_partner functions that may use the SESSION or PEEK class (no scope, no aal gate: sign-out, lock, GET
//     session). Empty today. A function acting on an object must use A0 / A0_WRITE / A0_KEEPALIVE / A0_MFA / A0_ENROL / A1 / A2 / A3 with a facility or trail.
// The check's SQL carries the SAME lists inline between marker comments (so the matrix twin in 10_function_inventory.sql is textually identical); this reader substitutes each fixture's
// list between its markers, and the matrix twin is held to the fixtures by supabase/tests/unit/function-inventory-check-parity.test.ts.
// KNOWN LIMIT of (c): it is a TRIPWIRE, not a proof. It lexes the body (comments dropped, strings kept) and looks for the literal 'partner', the table actor_binding and the helpers
// partner_binding*; a body that assembles those names at run time (EXECUTE 'private.actor_' || 'binding') evades it, as does one that reads the kind through a function it calls (which
// is itself on the list, or flagged). Closing that would mean forbidding dynamic SQL in every definer; it is documented, and review reads each new list entry.
function readFixtureList(name) {
  const path = join(import.meta.dirname, "..", "..", "supabase", "tests", "fixtures", name);
  try {
    return readFileSync(path, "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"));
  } catch (err) {
    failures.push(`could not read ${path}: ${err.message}`);
    return [];
  }
}
const sqlArray = (items) => (items.length > 0 ? `ARRAY[${items.map((e) => `'${e.replaceAll("'", "''")}'`).join(", ")}]` : "ARRAY[]::text[]");
const withList = (sql, marker, items) => sql.replace(new RegExp(`/\\* ${marker} \\*/.*?/\\* end_${marker} \\*/`, "s"), () => `/* ${marker} */ ${sqlArray(items)} /* end_${marker} */`);
const partnerKindExceptions = readFixtureList("partner_kind_readers.txt");
const partnerSessionClassFunctions = readFixtureList("partner_session_class_functions.txt");
for (const [num, label, rawSql] of edgeChecks) {
  const sql = num === 14 ? withList(withList(rawSql, "kind_readers", partnerKindExceptions), "session_class_functions", partnerSessionClassFunctions) : rawSql;
  for (const [violation] of psql(sql)) {
    failures.push(`edge-role check ${num} (${label}): ${violation}`);
  }
}

// 14 (a), second half: every *_for_partner function has at least one behavioural pgTAP cell: a matrix file that names it AND expects 42501 (called under a partner binding with no scope,
// it raises). A text check cannot prove the cell is right; it makes "no cell at all" a build failure, and the review reads the cell.
{
  const matrixDir = join(import.meta.dirname, "..", "..", "supabase", "tests", "matrix");
  const matrixText = readdirSync(matrixDir).filter((f) => f.endsWith(".sql")).map((f) => readFileSync(join(matrixDir, f), "utf8"));
  for (const [fn] of psql(`SELECT n.nspname || '.' || p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('app', 'api', 'private') AND p.prokind = 'f' AND p.proname LIKE '%\\_for\\_partner' ORDER BY 1`)) {
    const bare = fn.split(".")[1];
    if (!matrixText.some((t) => t.includes(bare) && t.includes("42501"))) {
      failures.push(`edge-role check 14 (a): ${fn} has no behavioural cell: no supabase/tests/matrix file names it and expects 42501 (called under a partner binding with no scope it must raise)`);
    }
  }
}

// 12b. The checked-in twin of private.partner_owner_privilege (supabase/tests/fixtures/partner_owner_privileges.txt): the privileges the six owner roles may hold, as reviewed text, so a migration that
// widens one TOGETHER WITH its registry row (self-consistent for check 12) still shows as a diff. Same reason as check 6 and 10b.
{
  const ownerFixturePath = join(import.meta.dirname, "..", "..", "supabase", "tests", "fixtures", "partner_owner_privileges.txt");
  let ownerFixtureRows;
  try {
    ownerFixtureRows = readFileSync(ownerFixturePath, "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"))
      .map((line) => JSON.parse(line));
  } catch (err) {
    failures.push(`could not read/parse ${ownerFixturePath}: ${err.message}`);
    ownerFixtureRows = [];
  }
  const ownerKey = (r) => [r.role_name, r.object_kind, r.object_name, r.privilege, r.column_name ?? ""].join("\u0000");
  const ownerLive = psqlJsonRows(`
    SELECT row_to_json(t) FROM (
      SELECT role_name, object_kind, object_name, privilege, column_name FROM private.partner_owner_privilege
      ORDER BY role_name, object_kind, object_name, privilege, column_name
    ) t
  `);
  const ownerLiveKeys = new Set(ownerLive.map(ownerKey));
  const ownerFixtureKeys = new Set(ownerFixtureRows.map(ownerKey));
  for (const r of ownerLive) {
    if (!ownerFixtureKeys.has(ownerKey(r))) failures.push(`private.partner_owner_privilege row ${ownerKey(r).replaceAll("\u0000", " ")} has no entry in supabase/tests/fixtures/partner_owner_privileges.txt -- regenerate the fixture (see its own header comment)`);
  }
  for (const r of ownerFixtureRows) {
    if (!ownerLiveKeys.has(ownerKey(r))) failures.push(`supabase/tests/fixtures/partner_owner_privileges.txt names a row with no live match in private.partner_owner_privilege: ${ownerKey(r).replaceAll("\u0000", " ")} -- stale fixture entry, regenerate`);
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
