// supabase/tests/unit/rewards-isolation.test.ts
//
// Structural guarantees for rewards-activate that a behavioural test cannot
// state as strongly (they read the source, like tools/service-role-lint's
// with-ownership.test.ts does):
//
//   1. "A reward earned by a server-side re-score reads no bits until
//      activation" (§7.5; AT 9): nothing on the EARNING side (evidence intake,
//      scoring, the check-in challenge/token, catalog skew, me-*) names a
//      DeviceCheck / device-recall call, and the ONLY rewards modules it may import
//      are the VERIFICATION-ONLY ones (VERIFICATION_ONLY below: the assertion and
//      Play Integrity verifiers, the bindings, the Play Integrity decode client, the
//      HTTP shim, the verification-only port builder), none of which can read or
//      write a persistent bit. `checkin-token` verifies an attestation (G3-08) with
//      exactly those. The only code that can read a persistent bit is under
//      _shared/rewards/, and the only entrypoint that wires it is rewards-activate.
//   2. The rewards modules never reach the environment or a secret themselves:
//      configuration arrives as an argument (privileged.ts reads it).
//   3. The decision table imports nothing at all but types (it stays pure).
//   4. (Transitive.) Checking a file's DIRECT imports says nothing about what its imports import, so the earning side's whole RUNTIME import closure
//      (type-only imports ignored; supabase/tests/unit/import-closure.ts) is computed from `checkin-token/index.ts` and every other earning-side
//      entrypoint and file, and `devicecheck-client`, `production-ports`, `activate-handler` and the rewards-activate entrypoint must be absent from it,
//      and no file in it may name a persistent-bit call. The walker is itself tested on synthetic graphs (import-closure.test.ts), and the rule was
//      proven to catch a TRANSITIVE import by mutation (security doc, "Attestation follow-ups").

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { chainTo, runtimeClosure, stripComments as stripCommentsStrict } from "./import-closure.js";

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

/** The only rewards modules the earning side may import: each can verify an attestation and none can reach DeviceCheck. `types.ts` is
 * imported for the vendor error classes and the narrow port types (it declares the iOS port's bit methods as TYPES, which the earning side
 * never names or implements: the per-file check below bans the NAMES in the earning files themselves). */
const VERIFICATION_ONLY = ["attestation-evidence.ts", "binding.ts", "string-binding.ts", "app-attest.ts", "play-integrity.ts", "play-integrity-client.ts", "vendor-http.ts", "vendor-log.ts", "verification-ports.ts", "types.ts"];
/** Names that mean "read or write a persistent device bit". */
const BIT_NAMES = /query_two_bits|update_two_bits|queryTwoBits|updateTwoBits|readBits|setBit0|deviceRecall|api\.devicecheck|devicecheck-client/i;
const stripComments = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

const EARNING_SIDE = ["_shared/evidence", "_shared/scoring", "_shared/checkin", "_shared/catalog", "_shared/me", "evidence", "evidence-batch", "checkin-challenge", "checkin-token", "me-delete", "me-export", "me-push-token", "me-offline-seed", "_shared/offline-code", "marker-scan", "_shared/course-qr", "receipts", "_shared/receipts"];

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

  it("none of them imports the rewards-activate function, or any rewards module that is not verification-only", () => {
    for (const f of earningFiles) {
      const text = src(f);
      expect(text, rel(f)).not.toMatch(/from\s+["'][^"']*rewards-activate[^"']*["']/);
      for (const m of text.matchAll(/from\s+["']([^"']*\/rewards\/([^"'/]+))["']/g)) {
        expect(VERIFICATION_ONLY, `${rel(f)} imports ${m[1]}`).toContain(m[2]);
      }
      // the bare directory name, or a re-export, is not a way round it
      for (const m of text.matchAll(/(?:from|import)\s+["'][^"']*rewards[^"']*["']/g)) {
        expect(m[0], rel(f)).toMatch(/\/rewards\/(attestation-evidence|binding|string-binding|app-attest|play-integrity|play-integrity-client|vendor-http|vendor-log|verification-ports|types)\.ts["']/);
      }
    }
  });

  it("the verification-only modules the earning side may import never name a persistent-bit call (types.ts, which types the iOS port, is the one exception)", () => {
    for (const name of VERIFICATION_ONLY.filter((n) => n !== "types.ts")) {
      const text = stripComments(src(join(FUNCTIONS, "_shared", "rewards", name)));
      expect(text, name).not.toMatch(BIT_NAMES);
    }
  });

  it("the earning side does import the verification-only verifiers it needs (checkin/token-handler.ts), so the allow-list above is not vacuous", () => {
    const text = src(join(FUNCTIONS, "_shared", "checkin", "token-handler.ts"));
    expect(text).toMatch(/rewards\/binding\.ts/);
    expect(text).toMatch(/rewards\/string-binding\.ts/);
    expect(text).toMatch(/rewards\/verification-ports\.ts/);
  });

  it("none of them names a DeviceCheck / device-recall / bit-reading call", () => {
    for (const f of earningFiles) {
      const text = stripComments(src(f));
      expect(text, rel(f)).not.toMatch(BIT_NAMES);
    }
  });

  it("only rewards-activate/index.ts wires the vendor ports, and only privileged.ts loads their configuration", () => {
    const wiring = walk(FUNCTIONS).filter((f) => /buildAttestationPorts|loadRewardsAttestationConfig/.test(src(f)) && !rel(f).startsWith("_shared/rewards/"));
    expect(wiring.map(rel).sort()).toEqual(["_shared/privileged.ts", "rewards-activate/index.ts"]);
  });

  it("only checkin-token/index.ts wires the verification-only ports, and only privileged.ts loads their configuration", () => {
    const wiring = walk(FUNCTIONS).filter((f) => /buildVerificationPorts|loadCheckinAttestationConfig/.test(src(f)) && !rel(f).startsWith("_shared/rewards/"));
    expect(wiring.map(rel).sort()).toEqual(["_shared/privileged.ts", "checkin-token/index.ts"]);
  });

  it("checkin-token/index.ts never imports production-ports (the DeviceCheck adapter) or reads a rewards-activate configuration", () => {
    const text = stripComments(src(join(FUNCTIONS, "checkin-token", "index.ts")));
    expect(text).not.toMatch(/production-ports|loadRewardsAttestationConfig|buildAttestationPorts|devicecheck/i);
  });
});

/** The roots of the earning side's runtime closure: every entrypoint (`<fn>/index.ts`) and every file under the earning-side directories. */
function earningRoots(): string[] {
  const roots = new Set<string>();
  for (const d of EARNING_SIDE) {
    try {
      for (const f of walk(join(FUNCTIONS, d))) roots.add(f);
    } catch {
      /* a directory this checkout does not have */
    }
  }
  return [...roots];
}

/** What the earning side may never reach at runtime, by file: the persistent-bit adapter and the entrypoint's wiring of it, the activation handler
 * (which calls the bit methods), and the rewards-activate function itself. */
const FORBIDDEN_REACHABLE = [
  "_shared/rewards/devicecheck-client.ts",
  "_shared/rewards/production-ports.ts",
  "_shared/rewards/activate-handler.ts",
  "rewards-activate/index.ts",
];

describe("the earning side's RUNTIME import closure never reaches a persistent-bit path (transitive, `import type` ignored)", () => {
  const roots = earningRoots();
  const closure = runtimeClosure(roots);
  const closureRel = [...closure.files].map(rel).sort();

  it("starts from every earning-side entrypoint (checkin-token among them) and is not vacuous: it reaches the verifiers and privileged.ts", () => {
    for (const entry of ["checkin-token", "checkin-challenge", "evidence", "evidence-batch", "me-delete", "me-export", "me-push-token", "me-offline-seed", "marker-scan"]) {
      expect(roots.map(rel), entry).toContain(`${entry}/index.ts`);
    }
    for (const reached of ["checkin-token/index.ts", "_shared/checkin/token-handler.ts", "_shared/rewards/verification-ports.ts", "_shared/rewards/app-attest.ts", "_shared/rewards/play-integrity-client.ts", "_shared/rewards/attestation-evidence.ts", "_shared/privileged.ts"]) {
      expect(closureRel, reached).toContain(reached);
    }
    // a hop that only exists transitively: checkin-token/index.ts -> verification-ports.ts -> play-integrity-client.ts -> vendor-http.ts
    expect(closureRel).toContain("_shared/rewards/vendor-http.ts");
    expect(closure.files.size).toBeGreaterThan(40);
  });

  it("resolves every relative import it follows (an unresolved one would be a blind spot) and finds no dynamic import it cannot read", () => {
    expect(closure.unresolved.map((u) => `${rel(u.from)} -> ${u.specifier}`)).toEqual([]);
    expect(closure.dynamicNonLiteral.map(rel)).toEqual([]);
  });

  it("does not reach devicecheck-client, production-ports, the activation handler or rewards-activate (the chain is printed if it does)", () => {
    for (const forbidden of FORBIDDEN_REACHABLE) {
      const hit = [...closure.files].find((f) => rel(f) === forbidden);
      expect(hit === undefined ? null : chainTo(closure, hit, rel), `${forbidden} is reachable from the earning side`).toBeNull();
    }
  });

  it("names no persistent-bit call in ANY file of the closure (rewards/types.ts, which declares the iOS port's methods as TYPES, is the one exception)", () => {
    const offenders: string[] = [];
    for (const f of closure.files) {
      if (rel(f) === "_shared/rewards/types.ts") continue;
      if (BIT_NAMES.test(stripCommentsStrict(src(f)))) offenders.push(chainTo(closure, f, rel));
    }
    expect(offenders).toEqual([]);
  });

  it("every rewards file in the closure is a verification-only one, plus the one pure constant privileged.ts embeds (nothing else under _shared/rewards/)", () => {
    // apple-app-attest-root.ts is Apple's published App Attest ROOT CA (a data constant); privileged.ts imports it for key REGISTRATION, which the
    // earning side never runs. It reads no bit and imports nothing, so it is reachable by construction and is named here rather than allow-listed for direct import.
    const PURE_CONSTANTS = ["apple-app-attest-root.ts"];
    const rewardsReached = closureRel.filter((f) => f.startsWith("_shared/rewards/")).map((f) => f.slice("_shared/rewards/".length));
    for (const f of rewardsReached) expect([...VERIFICATION_ONLY, ...PURE_CONSTANTS], `${f} is reachable from the earning side but is not on the verification-only list`).toContain(f);
  });
});

describe("the rewards modules", () => {
  const files = walk(join(FUNCTIONS, "_shared", "rewards"));

  it("exist", () => {
    expect(files.map(rel).sort()).toEqual(
      [
        "_shared/rewards/activate-handler.ts",
        "_shared/rewards/app-attest-registration.ts",
        "_shared/rewards/app-attest.ts",
        "_shared/rewards/apple-app-attest-root.ts",
        "_shared/rewards/attest-key-handler.ts",
        "_shared/rewards/attest-key-request.ts",
        "_shared/rewards/attestation-evidence.ts",
        "_shared/rewards/binding.ts",
        "_shared/rewards/cbor-strict.ts",
        "_shared/rewards/decision-table.ts",
        "_shared/rewards/der.ts",
        "_shared/rewards/devicecheck-client.ts",
        "_shared/rewards/play-integrity-client.ts",
        "_shared/rewards/play-integrity.ts",
        "_shared/rewards/production-ports.ts",
        "_shared/rewards/request-shape.ts",
        "_shared/rewards/string-binding.ts",
        "_shared/rewards/types.ts",
        "_shared/rewards/vendor-http.ts",
        "_shared/rewards/vendor-log.ts",
        "_shared/rewards/verification-ports.ts",
        "_shared/rewards/x509-lite.ts",
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
    // 0027 defines them; 0061 (AT(10) issuance staff gate) replaces activate_offer_code and resolve_held_offer_code as invoker-rights.
    expect(hits).toEqual(["0027_rewards_activation.sql", "0061_at10_issuance_staff_gate.sql"]);
    for (const file of hits) {
      const text = readFileSync(join(migrations, file), "utf8").replace(/^\s*--.*$/gm, "");
      // No app.* activation / resolve_held function is SECURITY DEFINER (N4). 0027's only definer is the vault reader.
      const appDefiners = [...text.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(app\.[\w]+)\s*\([^$]*?LANGUAGE\s+\w+\s+SECURITY\s+DEFINER/gis)].map((m) => m[1]);
      expect(appDefiners, file).toEqual([]);
      expect(text).not.toMatch(/DISABLE ROW LEVEL SECURITY|NO FORCE ROW LEVEL SECURITY/i);
    }
    const text27 = readFileSync(join(migrations, "0027_rewards_activation.sql"), "utf8").replace(/^\s*--.*$/gm, "");
    const definers27 = [...text27.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)\s*\([^$]*?LANGUAGE\s+\w+\s+SECURITY\s+DEFINER/gis)].map((m) => m[1]);
    expect(definers27).toEqual(["private.account_pseudonyms"]);
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
