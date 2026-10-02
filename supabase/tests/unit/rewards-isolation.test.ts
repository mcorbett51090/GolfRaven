// supabase/tests/unit/rewards-isolation.test.ts
//
// Structural guarantees for rewards-activate that a behavioural test cannot
// state as strongly (they read the source, like tools/service-role-lint's
// with-ownership.test.ts does):
//
//   1. "A reward earned by a server-side re-score reads no bits until
//      activation" (§7.5; AT 9): nothing on the EARNING side (evidence intake,
//      scoring, the check-in challenge/token, catalog skew, me-*) imports the
//      rewards module or names a DeviceCheck / device-recall call. The only code
//      that can read a persistent bit is under _shared/rewards/, and the only
//      entrypoint that wires it is rewards-activate.
//   2. The rewards modules never reach the environment or a secret themselves:
//      configuration arrives as an argument (privileged.ts reads it).
//   3. The decision table imports nothing at all but types (it stays pure).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const FUNCTIONS = join(import.meta.dirname, "..", "..", "functions");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "vendor") continue; // the generated scoring bundle
      out.push(...walk(p));
    } else if (p.endsWith(".ts")) {
      out.push(p);
    }
  }
  return out;
}
const rel = (p: string) => p.slice(FUNCTIONS.length + 1);
const src = (p: string) => readFileSync(p, "utf8");

const EARNING_SIDE = ["_shared/evidence", "_shared/scoring", "_shared/checkin", "_shared/catalog", "_shared/me", "evidence", "evidence-batch", "checkin-challenge", "checkin-token", "me-delete", "me-export", "me-push-token"];

describe("the earning side never reads a persistent device bit", () => {
  const earningFiles = EARNING_SIDE.flatMap((d) => {
    try {
      return walk(join(FUNCTIONS, d));
    } catch {
      return [];
    }
  });

  it("finds the earning-side files it is meant to police", () => {
    expect(earningFiles.length).toBeGreaterThan(10);
    expect(earningFiles.some((f) => rel(f) === "_shared/evidence/handler.ts")).toBe(true);
  });

  it("none of them imports anything under _shared/rewards or the rewards-activate function", () => {
    for (const f of earningFiles) {
      const text = src(f);
      expect(text, rel(f)).not.toMatch(/from\s+["'][^"']*rewards[^"']*["']/);
    }
  });

  it("none of them names a DeviceCheck / device-recall / bit-reading call", () => {
    for (const f of earningFiles) {
      const text = src(f).replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      expect(text, rel(f)).not.toMatch(/query_two_bits|update_two_bits|queryTwoBits|updateTwoBits|readBits|setBit0|deviceRecall|api\.devicecheck/i);
    }
  });

  it("only rewards-activate/index.ts wires the vendor ports, and only privileged.ts loads their configuration", () => {
    const wiring = walk(FUNCTIONS).filter((f) => /buildAttestationPorts|loadRewardsAttestationConfig/.test(src(f)) && !rel(f).startsWith("_shared/rewards/"));
    expect(wiring.map(rel).sort()).toEqual(["_shared/privileged.ts", "rewards-activate/index.ts"]);
  });
});

describe("the rewards modules", () => {
  const files = walk(join(FUNCTIONS, "_shared", "rewards"));

  it("exist", () => {
    expect(files.map(rel).sort()).toEqual(
      [
        "_shared/rewards/activate-handler.ts",
        "_shared/rewards/app-attest.ts",
        "_shared/rewards/binding.ts",
        "_shared/rewards/decision-table.ts",
        "_shared/rewards/devicecheck-client.ts",
        "_shared/rewards/play-integrity-client.ts",
        "_shared/rewards/play-integrity.ts",
        "_shared/rewards/production-ports.ts",
        "_shared/rewards/request-shape.ts",
        "_shared/rewards/types.ts",
        "_shared/rewards/vendor-http.ts",
      ].sort(),
    );
  });

  it("never touch the environment, a secret name, or a service-role client", () => {
    for (const f of files) {
      const text = src(f).replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      expect(text, rel(f)).not.toMatch(/\bDeno\b|\bprocess\b|globalThis|SERVICE_ROLE|DB_URL|createClient|supabase-js/i);
    }
  });

  it("decision-table.ts imports only types", () => {
    const imports = src(join(FUNCTIONS, "_shared", "rewards", "decision-table.ts")).match(/^import .*$/gm) ?? [];
    expect(imports.every((i) => i.startsWith("import type "))).toBe(true);
  });

  it("the production vendor adapters never hard-code a credential: no PEM body, no JWT, no bearer literal", () => {
    for (const f of files) {
      const text = src(f);
      expect(text, rel(f)).not.toMatch(/-----BEGIN [A-Z ]+-----\s*[A-Za-z0-9+/=]{20,}/);
      expect(text, rel(f)).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/);
    }
  });
});

describe("the migration", () => {
  it("0027 is the only migration that defines the activation functions, and none of them is SECURITY DEFINER", () => {
    const migrations = join(FUNCTIONS, "..", "migrations");
    // DEFINITIONS only (comments stripped): a later migration may legitimately GRANT EXECUTE on these functions
    // (0031_edge_role_policies.sql gives the edge_actor role EXECUTE on the activation functions) without defining them.
    const stripComments = (sql: string) => sql.replace(/^\s*--.*$/gm, "");
    const hits = readdirSync(migrations).filter((n) =>
      /CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+app\.(activate_|resolve_held_)/i.test(stripComments(readFileSync(join(migrations, n), "utf8"))),
    );
    expect(hits).toEqual(["0027_rewards_activation.sql"]);
    const text = readFileSync(join(migrations, "0027_rewards_activation.sql"), "utf8").replace(/^\s*--.*$/gm, "");
    // Exactly ONE SECURITY DEFINER function, and it is the vault reader (N4): no app.* function is one.
    const definers = [...text.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)\s*\([^$]*?LANGUAGE\s+\w+\s+SECURITY\s+DEFINER/gis)].map((m) => m[1]);
    expect(definers).toEqual(["private.account_pseudonyms"]);
    expect(text).not.toMatch(/DISABLE ROW LEVEL SECURITY|NO FORCE ROW LEVEL SECURITY/i);
  });

  it("no migration turns an activation / reservation function into SECURITY DEFINER by ALTER FUNCTION either", () => {
    // 0032 NIT: the check above reads 0027's CREATE statements only; a LATER `ALTER FUNCTION app.activate_offer_code(...)
    // SECURITY DEFINER` would bypass it (inventory check 3 backstops it in the database; this keeps it out of review too).
    // The sanctioned way to give the edge role these paths is a private.* definer that CALLS the invoker-rights function.
    const migrations = join(FUNCTIONS, "..", "migrations");
    const stripComments = (sql: string) => sql.replace(/^\s*--.*$/gm, "");
    const offenders = readdirSync(migrations).filter((n) =>
      /ALTER\s+FUNCTION\s+app\.(activate_|resolve_held_|reserve_offer|release_offer|release_account|consume_offer|hold_play|play_held_review|offer_code_reservation)\w*\s*\([^)]*\)[^;]*\bSECURITY\s+DEFINER/i.test(stripComments(readFileSync(join(migrations, n), "utf8"))),
    );
    expect(offenders).toEqual([]);
  });

  it("0029 redefines exactly one function — the install-link pseudonym — with a domain-separated HMAC input", () => {
    const text = readFileSync(join(FUNCTIONS, "..", "migrations", "0029_install_link_pseudonym_domain.sql"), "utf8").replace(/^\s*--.*$/gm, "");
    expect([...text.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)/gi)].map((m) => m[1])).toEqual(["private.account_pseudonyms"]);
    expect(text).toMatch(/hmac\('install_link_account:' \|\| p_user_id::text/);
    expect(text).not.toMatch(/hmac\(p_user_id::text/);
    expect(text).not.toMatch(/max\(v\.name\)/);
  });
});
