// supabase/tests/unit/attest-key-isolation.test.ts
//
// Structural guarantees for App Attest KEY REGISTRATION (devices-attest-key, 0034) that a behavioural test cannot
// state as strongly (they read the source, like rewards-isolation.test.ts):
//
//   1. THE TRUST ANCHOR IS PINNED IN CODE AND SUPPLIED ONLY BY privileged.ts. `createAttestationVerifier` is
//      constructed by exactly one module outside its own definition (devices-attest-key/index.ts), `trustAnchorDer`
//      is assigned exactly once under supabase/functions (in privileged.ts, to APPLE_APP_ATTEST_ROOT_DER), and no
//      environment variable, request field or database read can name another root.
//   2. The registration modules never reach the environment, a secret, or the network.
//   3. Configuration is read ONLY in privileged.ts.
//   4. The migration adds no table, exactly one SECURITY DEFINER function (in private), and grants nothing to anon,
//      authenticated or PUBLIC.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const FUNCTIONS = join(import.meta.dirname, "..", "..", "functions");
const MIGRATIONS = join(FUNCTIONS, "..", "migrations");

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
const rel = (p: string) => p.slice(FUNCTIONS.length + 1);
const stripTs = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
const stripSql = (t: string) => t.replace(/^\s*--.*$/gm, "");
const code = (p: string) => stripTs(readFileSync(p, "utf8"));
const all = walk(FUNCTIONS);

describe("the trust anchor", () => {
  it("createAttestationVerifier is constructed only by devices-attest-key/index.ts", () => {
    const builders = all.filter((f) => /createAttestationVerifier\s*\(/.test(code(f))).map(rel).sort();
    expect(builders).toEqual(["_shared/rewards/app-attest-registration.ts", "devices-attest-key/index.ts"]);
  });

  it("trustAnchorDer is given a value in exactly one place outside the verifier: privileged.ts, from the pinned constant", () => {
    const assignments = all.filter((f) => !rel(f).endsWith("app-attest-registration.ts")).flatMap((f) => [...code(f).matchAll(/trustAnchorDer\s*[:=]\s*([^,}\n]+)/g)].map((m) => `${rel(f)} -> ${m[1]!.trim()}`));
    expect(assignments).toEqual(["_shared/privileged.ts -> APPLE_APP_ATTEST_ROOT_DER"]);
  });

  it("the pinned root is imported by privileged.ts and by no other module but its own test", () => {
    const importers = all.filter((f) => /apple-app-attest-root/.test(code(f)) && !rel(f).endsWith("apple-app-attest-root.ts")).map(rel);
    expect(importers).toEqual(["_shared/privileged.ts"]);
  });

  it("no source reads a root certificate, PEM or anchor from the environment, the network or the database", () => {
    for (const f of all) {
      const text = code(f);
      if (rel(f) === "_shared/rewards/apple-app-attest-root.ts") continue;
      expect(text, rel(f)).not.toMatch(/ROOT_CA|TRUST_ANCHOR|APPATTEST_ROOT|APP_ATTEST_ROOT_PEM/i);
    }
    // ...and the pinned module carries exactly the public certificate, no private key.
    expect(readFileSync(join(FUNCTIONS, "_shared", "rewards", "apple-app-attest-root.ts"), "utf8")).not.toMatch(/PRIVATE KEY/);
  });
});

describe("the registration modules", () => {
  const files = ["app-attest-registration", "attest-key-handler", "attest-key-request", "cbor-strict", "der", "x509-lite", "apple-app-attest-root", "string-binding"].map((n) => join(FUNCTIONS, "_shared", "rewards", `${n}.ts`));

  it("never touch the environment, a secret name, the network or a service-role client", () => {
    for (const f of files) {
      expect(code(f), rel(f)).not.toMatch(/\bDeno\b|\bprocess\b|globalThis|SERVICE_ROLE|DB_URL|createClient|supabase-js|\bfetch\s*\(|XMLHttpRequest|WebSocket/i);
    }
  });

  it("never hard-code a credential: no PEM private key, no JWT, no bearer literal", () => {
    for (const f of files) {
      const text = readFileSync(f, "utf8");
      expect(text, rel(f)).not.toMatch(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
      expect(text, rel(f)).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/);
    }
  });
});

describe("configuration", () => {
  it("the App Attest environment variables are read only in privileged.ts", () => {
    const readers = all.filter((f) => /GR_APPLE_APPATTEST_ENV/.test(code(f))).map(rel);
    expect(readers).toEqual(["_shared/privileged.ts"]);
  });

  it("privileged.ts fails closed: every variable must be present and sane, or the loader returns null", () => {
    const text = code(join(FUNCTIONS, "_shared", "privileged.ts"));
    const loader = text.slice(text.indexOf("export function loadAttestKeyVerifierConfig"));
    expect(loader).toMatch(/return null/);
    expect(loader).toMatch(/environment !== "production" && environment !== "development"/);
  });
});

describe("migration 0034", () => {
  const sql = stripSql(readFileSync(join(MIGRATIONS, "0034_attest_key_registration.sql"), "utf8"));

  it("adds no table, and never disables or un-forces row level security", () => {
    expect(sql).not.toMatch(/CREATE\s+TABLE/i);
    expect(sql).not.toMatch(/DISABLE ROW LEVEL SECURITY|NO FORCE ROW LEVEL SECURITY/i);
  });

  it("defines exactly one SECURITY DEFINER function, in private, and it is the bound-actor wrapper", () => {
    const definers = [...sql.matchAll(/CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w.]+)\s*\([^$]*?LANGUAGE\s+\w+\s+SECURITY\s+DEFINER/gis)].map((m) => m[1]);
    expect(definers).toEqual(["private.register_attest_key_for_actor"]);
    expect(sql).toMatch(/SET search_path = ''/);
  });

  it("grants nothing to anon, authenticated or PUBLIC (EXECUTE is revoked from PUBLIC and given to named roles)", () => {
    expect(sql).not.toMatch(/GRANT[^;]*\bTO\b[^;]*\b(anon|authenticated|PUBLIC)\b/i);
    expect(sql).toMatch(/REVOKE EXECUTE ON FUNCTION app\.register_attest_key\(uuid, uuid, text, bytea\) FROM PUBLIC/);
    expect(sql).toMatch(/REVOKE EXECUTE ON FUNCTION private\.register_attest_key_for_actor\(uuid, text, bytea\) FROM PUBLIC/);
  });

  it("gives edge_actor nothing on the key columns: its only new privilege is EXECUTE on the wrapper", () => {
    const edgeGrants = [...sql.matchAll(/GRANT[^;]*\bTO\b[^;]*\bedge_actor\b[^;]*;/gi)].map((m) => m[0].replace(/\s+/g, " "));
    expect(edgeGrants).toEqual(["GRANT EXECUTE ON FUNCTION private.register_attest_key_for_actor(uuid, text, bytea) TO edge_actor;"]);
    expect(sql).not.toMatch(/CREATE\s+POLICY[^;]*\bTO\s+edge_actor\b/i);
  });

  it("is the only migration that UPDATEs the key columns of app.device", () => {
    const writers = readdirSync(MIGRATIONS).filter((n) => /UPDATE\s+app\.device\s+SET[^;]*\battest_(key_id|public_key)\s*=/i.test(stripSql(readFileSync(join(MIGRATIONS, n), "utf8"))));
    expect(writers).toEqual(["0034_attest_key_registration.sql"]);
  });
});
