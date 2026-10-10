// supabase/tests/unit/review-account-gate.test.ts
//
// Structural guarantees for the App Store review account's gate (0051) that a behavioural test cannot state as strongly: they read the source, like marker-scan-entrypoint.test.ts does.
//
//   1. THE CHOKE POINT: every Edge function that authenticates a caller does it through `getActorFromRequest`, and nothing in supabase/functions builds an `Actor` any other way, so
//      the one gate inside `getActorFromRequest` cannot be bypassed by a new entrypoint that forgets it.
//   2. The gate runs AFTER Auth verified the token and BEFORE the Actor is returned, on the session id of that token, as `edge_system` (the only role holding EXECUTE), and its
//      three answers are handled with `disabled` a 403 `review_account_disabled` and anything unexpected failing CLOSED.
//   3. It is NOT called from a request transaction (no second pooled connection while one is held: the hitRateLimitForActor ordering rule): it opens its own via `openScopedTx`.
//   4. The migration: the gate never RAISEs over the outcome (the audit row commits with the refusal), reads the clock with clock_timestamp(), canonicalises the session id, and the
//      binder backstop is the ONLY place `bind_actor_internal` consults the window.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SUPABASE = join(import.meta.dirname, "..", "..");
const FUNCTIONS = join(SUPABASE, "functions");
const read = (p: string) => readFileSync(p, "utf8");
const stripComments = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "vendor") continue;
      out.push(...walk(p));
    } else if (p.endsWith(".ts")) {
      out.push(p);
    }
  }
  return out;
}

const privileged = stripComments(read(join(FUNCTIONS, "_shared", "privileged.ts")));
const fnBody = (src: string, header: string): string => {
  const start = src.indexOf(header);
  expect(start, `${header} is present`).toBeGreaterThan(-1);
  const open = src.indexOf("{", src.indexOf(")", start));
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(open, i + 1);
  }
  throw new Error("unbalanced braces");
};

describe("every authenticated Edge function authenticates through getActorFromRequest", () => {
  const entrypoints = readdirSync(FUNCTIONS)
    .filter((n) => !n.startsWith("_") && statSync(join(FUNCTIONS, n)).isDirectory())
    .map((n) => ({ name: n, path: join(FUNCTIONS, n, "index.ts") }));
  // the system functions authenticate a SCHEDULER or a signed webhook, not a user: they never mint an Actor
  const SYSTEM = new Set(["import-catalog", "retention-purge", "signin-revocation-drain", "exports-purge", "rollups-refresh"]);
  // the partner lane (S1.2, 0049; S1.5, 0054) authenticates a partner SESSION TOKEN through its own binder (or, for the accept routes, an emailed code and an invite token), never a player identity: it must not call getActorFromRequest at all (which refuses gr_ps_ tokens)
  const PARTNER_LANE = new Set([
    "partner-session",
    "partner-invites",
    "partner-members",
    "course-qr",
    "qr-print",
    "partner-attest",
    "partner-review",
    "stock-admin",
    "partner-entitlements",
    "programme-config",
    "offers-admin",
    "sponsorships-admin",
    "partner-offers-redeem",
    "settlement-export",
  ]);

  it("the user-facing entrypoints all call it, inside handleRequest", () => {
    const users = entrypoints.filter((e) => !SYSTEM.has(e.name) && !PARTNER_LANE.has(e.name));
    expect(users.length).toBeGreaterThanOrEqual(12);
    for (const e of users) {
      const code = stripComments(read(e.path));
      expect(code, `${e.name} calls getActorFromRequest`).toContain("getActorFromRequest(");
      expect(code.indexOf("handleRequest("), `${e.name} wraps it in handleRequest (an HttpError becomes its response)`).toBeGreaterThan(-1);
      expect(code.indexOf("handleRequest("), e.name).toBeLessThan(code.indexOf("getActorFromRequest("));
    }
  });

  // The two catalog orchestrators build an Actor for a system DELEGATE (the system acting on ONE queued row of its owner, bound through the edge_system delegate binders): that is
  // not a sign-in, and the binder's window check deliberately refuses only the user kind. Listed by name so a third site is a deliberate review decision.
  const DELEGATE_ACTOR_SITES = ["catalog/drain-orchestrator.ts", "catalog/rescore-orchestrator.ts"];
  it("the partner lane's entrypoints do not use the player identity (a partner token is never a player's)", () => {
    for (const e of entrypoints.filter((x) => PARTNER_LANE.has(x.name))) expect(stripComments(read(e.path)), e.name).not.toContain("getActorFromRequest");
  });

  it("nothing under supabase/functions builds an Actor literal except privileged.ts's getActorFromRequest (and the two named delegate sites)", () => {
    const offenders: string[] = [];
    for (const f of walk(FUNCTIONS)) {
      if (f.endsWith(join("_shared", "privileged.ts"))) continue;
      if (DELEGATE_ACTOR_SITES.some((s) => f.endsWith(join("_shared", s)))) continue;
      const code = stripComments(read(f));
      if (/role:\s*"authenticated"\s*[,}]/.test(code) && /\buid\b\s*[:,]/.test(code) && !/types\.ts$/.test(f)) offenders.push(f);
    }
    expect(offenders).toEqual([]);
  });
});

describe("privileged.ts#getActorFromRequest runs the review-account gate", () => {
  const body = fnBody(privileged, "export async function getActorFromRequest(");
  it("only after Auth verified the token, with the token's own session id, before returning the Actor", () => {
    const verified = body.indexOf("auth.getUser(token)");
    const nullOut = body.indexOf("if (error || !data?.user) return null");
    const gate = body.indexOf("reviewAccountGate(data.user.id, sessionIdOfAccessToken(token))");
    const ret = body.indexOf('return { uid: data.user.id, role: "authenticated" }');
    expect(verified).toBeGreaterThan(-1);
    expect(nullOut).toBeGreaterThan(verified);
    expect(gate).toBeGreaterThan(nullOut);
    expect(ret).toBeGreaterThan(gate);
  });

  it("composes with the partner-token refusal (PA-11): gr_ps_ / gr_inv_ are refused BEFORE the environment is read, any client exists or GoTrue is asked, so before the gate", () => {
    const prefix = body.indexOf('lowered.startsWith("gr_ps_") || lowered.startsWith("gr_inv_")');
    const env = body.indexOf('Deno.env.get("SUPABASE_URL")');
    const client = body.indexOf("createClient(");
    const verified = body.indexOf("auth.getUser(token)");
    const gate = body.indexOf("reviewAccountGate(");
    expect(prefix).toBeGreaterThan(-1);
    expect(prefix).toBeLessThan(env);
    expect(env).toBeLessThan(client);
    expect(client).toBeLessThan(verified);
    expect(verified).toBeLessThan(gate);
    expect(body.slice(prefix, env)).toContain("return null");
  });

  it("a disabled answer is a 403 review_account_disabled, thrown (never returned as an Actor)", () => {
    expect(body).toMatch(/verdict === "disabled"\) throw new HttpError\(403, REVIEW_ACCOUNT_DISABLED_CODE/);
    expect(privileged).toContain('export const REVIEW_ACCOUNT_DISABLED_CODE = "review_account_disabled"');
  });
});

describe("privileged.ts#reviewAccountGate", () => {
  const body = fnBody(privileged, "async function reviewAccountGate(");
  it("opens its OWN edge_system transaction (never from inside a request transaction) and calls only the gate", () => {
    expect(body).toContain('openScopedTx("system", { expectedUid: null }');
    expect(body).toContain("private.review_account_gate(");
    expect(body).not.toContain("withOwnership");
    expect(body.match(/private\./g)!.length).toBe(1);
  });
  it("fails CLOSED on any answer that is not one of the two it knows", () => {
    expect(body).toMatch(/if \(verdict === "not_review" \|\| verdict === "allowed"\) \{[\s\S]*?return verdict;\s*\}\s*return "disabled";/);
  });
  it("remembers ONLY the answer not_review (never allowed or disabled), for a bounded time, in a bounded map", () => {
    const set = body.indexOf("reviewGateNegativeCache.set(");
    const guard = body.lastIndexOf('if (verdict === "not_review") {', set);
    expect(set).toBeGreaterThan(-1);
    expect(guard).toBeGreaterThan(-1);
    expect(body.match(/reviewGateNegativeCache\.set\(/g)).toHaveLength(1);
    expect(body).toContain("cachedUntil > now");
    expect(body).toContain("reviewGateNegativeCache.size >= REVIEW_GATE_NEGATIVE_MAX");
    expect(privileged).toMatch(/const REVIEW_GATE_NEGATIVE_TTL_MS = 30_000;/);
  });
});

describe("migration 0051", () => {
  const sql = read(join(SUPABASE, "migrations", "0051_review_account_window.sql"));
  const code = sql.replace(/--.*$/gm, "");
  const gate = code.slice(code.indexOf("CREATE FUNCTION private.review_account_gate"), code.indexOf("CREATE OR REPLACE FUNCTION private.bind_actor_internal"));

  it("the gate returns a status and raises only for a NULL uid (the audit row commits with the refusal: the 0020 lesson)", () => {
    const raises = gate.match(/RAISE EXCEPTION[^;]*;/g) ?? [];
    expect(raises).toHaveLength(1);
    expect(raises[0]).toContain("22023");
    expect(gate).toContain("EXCEPTION WHEN unique_violation THEN");
  });
  it("reads the clock with clock_timestamp() (not now()) and canonicalises the session id", () => {
    expect(gate).toContain("review_window_open_at(clock_timestamp())");
    expect(gate).not.toMatch(/\bnow\(\)/);
    expect(gate).toContain("lower(p_session_id)");
  });
  it("the audit row holds the outcome and nothing else", () => {
    expect(gate).toContain("pg_catalog.jsonb_build_object('outcome',");
    expect(gate).not.toMatch(/email|ip_address|user_agent|token/i);
  });
  it("only edge_system may execute the gate, and the window predicate is not executable by an edge role", () => {
    expect(code).toContain("GRANT EXECUTE ON FUNCTION private.review_account_gate(uuid, text) TO edge_system;");
    expect(code).toContain("GRANT EXECUTE ON FUNCTION private.review_window_open_at(timestamptz) TO service_role;");
    expect(code).not.toMatch(/GRANT[^;]*\bTO\b[^;]*\b(anon|authenticated|edge_actor)\b/);
  });
  it("the window table is FORCE RLS with no client grant", () => {
    expect(code).toContain("ALTER TABLE app.app_review_window FORCE ROW LEVEL SECURITY;");
    expect(code).toContain("GRANT SELECT, INSERT, UPDATE, DELETE ON app.app_review_window TO service_role;");
  });
  it("the binder backstop refuses only the user kind: a RETIRED account always, any other review account outside a window", () => {
    expect(code).toContain("IF p_kind = 'user' AND private.is_demo_account(p_uid) THEN");
    const at = code.indexOf("IF p_kind = 'user' AND private.is_demo_account(p_uid) THEN");
    const retired = code.indexOf("the review account is retired", at);
    const window = code.indexOf("IF NOT private.review_window_open_at(clock_timestamp()) THEN", at);
    expect(retired).toBeGreaterThan(at);
    expect(window).toBeGreaterThan(retired); // retired is judged first, and independently of any window
    expect(code.slice(at, retired)).toContain("retired_at IS NOT NULL");
  });
  it("the gate refuses a RETIRED account always (the window is not even consulted for it), and a retired row stays a review account", () => {
    expect(gate).toContain("v_retired := EXISTS (SELECT 1 FROM app.app_review_demo_account d WHERE d.user_id = p_uid AND d.retired_at IS NOT NULL);");
    expect(gate).toContain("v_open := NOT v_retired AND private.review_window_open_at(clock_timestamp());");
    expect(code).not.toMatch(/CREATE OR REPLACE FUNCTION private\.is_demo_account/); // is_demo_account (0007) is untouched: true for a retired row
  });
  it("retired is one-way and the row is kept while its Auth user exists (the guard), and the unique index is over ACTIVE rows", () => {
    expect(code).toContain("CREATE UNIQUE INDEX app_review_demo_account_single ON app.app_review_demo_account ((true)) WHERE retired_at IS NULL;");
    expect(code).toContain("NEW.retired_at IS DISTINCT FROM OLD.retired_at OR NEW.user_id IS DISTINCT FROM OLD.user_id");
    expect(code).toContain("OLD.retired_at IS NOT NULL AND EXISTS (SELECT 1 FROM auth.users u WHERE u.id = OLD.user_id)");
    expect(code).toContain("BEFORE UPDATE OR DELETE ON app.app_review_demo_account");
    expect(code).not.toMatch(/GRANT[^;]*review_account_retire_guard/);
  });

});
