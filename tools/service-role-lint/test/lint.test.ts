import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lintSource } from "../src/lint.js";

// build plan §10 P3 AT(2) (docs/golf-trails/02-build-plan.md:2759):
// "The authorization and service-role lint queries fail on seeded bad
// fixtures and pass on clean ones." §4.7.1a (line 1204-1205). Hardened
// per the gate-round-2 review (B5): aliased/namespace imports,
// re-exports, `new SupabaseClient`, dynamic import(), every named
// specifier shape, non-literal env access, globalThis, a shadowed
// `withOwnership`, and alias-chained client variables — each its own
// must-fail fixture.

const FIXTURES_ROOT = join(import.meta.dirname, "..", "..", "..", "supabase", "functions", "__fixtures__");

function lintFixture(relPath: string) {
  const full = join(FIXTURES_ROOT, relPath);
  const source = readFileSync(full, "utf8");
  return lintSource(source, full);
}

describe("bad fixtures (must fail) — original five", () => {
  it("flags a service-role .update() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-update.ts");
    expect(findings.some((f) => f.rule === "service-role-construction")).toBe(true);
    expect(findings.some((f) => f.rule === "privileged-call-outside-withOwnership")).toBe(true);
  });

  it("flags a service-role .upsert() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-upsert.ts");
    expect(
      findings.some((f) => f.rule === "privileged-call-outside-withOwnership" && f.message.includes("upsert")),
    ).toBe(true);
  });

  it("flags a service-role .rpc() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-rpc.ts");
    expect(findings.some((f) => f.rule === "privileged-call-outside-withOwnership" && f.message.includes("rpc"))).toBe(
      true,
    );
  });

  it("flags a raw Postgres driver import and a DB_URL-named env reference", () => {
    const findings = lintFixture("bad/raw-sql-db-url.ts");
    expect(findings.some((f) => f.rule === "banned-import-specifier" && f.message.includes("postgres"))).toBe(true);
    expect(findings.some((f) => f.message.toUpperCase().includes("DB_URL"))).toBe(true);
  });

  it("flags a service-role Storage .upload() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-storage-upload.ts");
    expect(
      findings.some((f) => f.rule === "privileged-call-outside-withOwnership" && f.message.includes("upload")),
    ).toBe(true);
  });
});

describe("bad fixtures (must fail) — gate-round-2 bypass vectors (B5)", () => {
  it("flags an ALIASED createClient import (import { createClient as cc })", () => {
    const findings = lintFixture("bad/aliased-import.ts");
    expect(findings.some((f) => f.rule === "service-role-construction")).toBe(true);
    expect(findings.some((f) => f.rule === "privileged-call-outside-withOwnership")).toBe(true);
  });

  it("flags a NAMESPACE import (import * as supa; supa.createClient(...))", () => {
    const findings = lintFixture("bad/namespace-import.ts");
    expect(findings.some((f) => f.rule === "service-role-construction")).toBe(true);
    expect(findings.some((f) => f.rule === "privileged-call-outside-withOwnership")).toBe(true);
  });

  it("flags a RE-EXPORT of createClient from a banned specifier", () => {
    const findings = lintFixture("bad/reexport.ts");
    expect(findings.some((f) => f.rule === "reexport-of-privileged-symbol")).toBe(true);
  });

  it("flags `new SupabaseClient(...)`", () => {
    const findings = lintFixture("bad/new-supabase-client.ts");
    expect(findings.some((f) => f.rule === "service-role-construction" && f.message.includes("new SupabaseClient"))).toBe(
      true,
    );
  });

  it("flags a DYNAMIC import() of a banned specifier", () => {
    const findings = lintFixture("bad/dynamic-import.ts");
    expect(findings.some((f) => f.rule === "banned-import-specifier" && f.message.includes("dynamic import"))).toBe(
      true,
    );
  });

  it("flags every named driver specifier shape (npm:, jsr:, deno.land/x:)", () => {
    const findings = lintFixture("bad/driver-specifier-variants.ts");
    const bannedImports = findings.filter((f) => f.rule === "banned-import-specifier");
    expect(bannedImports.length).toBe(4);
    expect(bannedImports.some((f) => f.message.includes("npm:postgres"))).toBe(true);
    expect(bannedImports.some((f) => f.message.includes("npm:pg"))).toBe(true);
    expect(bannedImports.some((f) => f.message.includes("jsr:@db/postgres"))).toBe(true);
    expect(bannedImports.some((f) => f.message.includes("deno.land/x/postgres"))).toBe(true);
  });

  it("flags a NON-LITERAL env var read (name built from a variable/concatenation)", () => {
    const findings = lintFixture("bad/non-literal-env-access.ts");
    expect(findings.some((f) => f.rule === "non-literal-env-access")).toBe(true);
  });

  it("flags globalThis access", () => {
    const findings = lintFixture("bad/globalthis-access.ts");
    expect(findings.some((f) => f.rule === "globalthis-access")).toBe(true);
  });

  it("flags a local declaration that SHADOWS withOwnership", () => {
    const findings = lintFixture("bad/withownership-shadow.ts");
    expect(findings.some((f) => f.rule === "withownership-shadowed")).toBe(true);
    // still also flagged for the raw construction + unguarded call it wraps
    expect(findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  it("flags calls through an ALIASED client variable, transitively (a -> b -> c)", () => {
    const findings = lintFixture("bad/aliased-client-variable.ts");
    expect(
      findings.some((f) => f.rule === "privileged-call-outside-withOwnership" && f.message.includes('"handle"')),
    ).toBe(true);
  });

  it("flags process.env static/computed access to a secret name", () => {
    const source = `
      const a = process.env.SUPABASE_SERVICE_ROLE_KEY;
      const b = process.env["SUPABASE_DB_URL"];
      const name = "X";
      const c = process.env[name];
    `;
    const findings = lintSource(source, "/repo/supabase/functions/leaky/index.ts");
    expect(findings.filter((f) => f.rule === "literal-secret-env-var").length).toBe(2);
    expect(findings.some((f) => f.rule === "non-literal-env-access")).toBe(true);
  });

  it("flags require() of a banned specifier (CJS interop)", () => {
    const source = `const { createClient } = require("@supabase/supabase-js");`;
    const findings = lintSource(source, "/repo/supabase/functions/cjs-leak/index.cjs");
    expect(findings.some((f) => f.rule === "banned-import-specifier")).toBe(true);
  });
});

describe("bad fixtures (must fail) — M3, post-P3a gate (bypass-resistant rework)", () => {
  it("flags versioned/URL specifiers (esm.sh, deno.land/x, npm: with @version) by normalised package name", () => {
    const findings = lintFixture("bad/versioned-specifier.ts");
    const bannedImports = findings.filter((f) => f.rule === "banned-import-specifier");
    expect(bannedImports.length).toBe(3);
    expect(bannedImports.some((f) => f.message.includes("esm.sh"))).toBe(true);
    expect(bannedImports.some((f) => f.message.includes("deno.land/x/postgresjs"))).toBe(true);
    expect(bannedImports.some((f) => f.message.includes("npm:pg@8"))).toBe(true);
  });

  it("flags a destructured `const { env } = Deno; env.get(...)` read", () => {
    const findings = lintFixture("bad/destructured-env.ts");
    expect(findings.some((f) => f.rule === "literal-secret-env-var")).toBe(true);
  });

  it("flags Deno.env.toObject()[...] and .toObject().KEY reads", () => {
    const findings = lintFixture("bad/env-to-object.ts");
    // Both the acquisition (.toObject() itself) and the specific computed
    // read are flagged, so this fixture alone produces several findings.
    expect(findings.some((f) => f.rule === "non-literal-env-access" && f.message.includes("toObject"))).toBe(true);
  });

  it("flags a raw fetch() carrying a service-role key read from env", () => {
    const findings = lintFixture("bad/raw-fetch-with-secret.ts");
    expect(findings.some((f) => f.rule === "raw-fetch-with-secret")).toBe(true);
  });

  it("does NOT flag a read of a public, allow-listed env var (SUPABASE_URL)", () => {
    const source = `
      export function readUrl() {
        return Deno.env.get("SUPABASE_URL");
      }
      declare const Deno: { env: { get(name: string): string | undefined } };
    `;
    const findings = lintSource(source, "/repo/supabase/functions/public-var/index.ts");
    expect(findings.filter((f) => f.rule === "literal-secret-env-var" || f.rule === "non-literal-env-access")).toEqual([]);
  });

});

describe("clean fixtures (must pass)", () => {
  it("passes a function that only touches the client inside withOwnership()", () => {
    expect(lintFixture("good/evidence-insert.ts")).toEqual([]);
  });

  it("passes a handler that receives an already-scoped client as a parameter (no supabase-js import at all)", () => {
    expect(lintFixture("good/read-only-jwt-forwarded.ts")).toEqual([]);
  });
});

describe("the exemption is an EXACT path match, not endsWith (B5)", () => {
  const source = `
    import { createClient } from "@supabase/supabase-js";
    const c = createClient("url", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));
    c.from("play").update({});
  `;

  it("still flags a file whose path merely ENDS WITH '_shared/privileged.ts'", () => {
    // "evil_shared/privileged.ts" ends with the same string suffix an
    // endsWith() check would have matched — it must NOT be exempted.
    const findings = lintSource(source, "/repo/supabase/functions/evil_shared/privileged.ts");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("still flags privileged.ts sitting in the WRONG directory", () => {
    const findings = lintSource(source, "/repo/supabase/functions/not_shared/privileged.ts");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("exempts only the exact supabase/functions/_shared/privileged.ts path", () => {
    expect(lintSource(source, "/repo/supabase/functions/_shared/privileged.ts")).toEqual([]);
  });
});

describe("real code under withOwnership() is exempt from rule (b)", () => {
  it("does not flag .from()/.rpc() calls made inside the withOwnership callback body", () => {
    const source = `
      import { withOwnership } from "../_shared/privileged.ts";
      export function handle(actor) {
        return withOwnership(actor, (repo) => {
          return repo.from("evidence").insert({});
        });
      }
    `;
    // "repo" here is the callback's own parameter, not a tracked
    // service-role identifier, so rule (b) never applies to it in the
    // first place — this asserts the common real-code shape produces zero
    // findings end to end.
    expect(lintSource(source, "/repo/supabase/functions/evidence/index.ts")).toEqual([]);
  });
});
