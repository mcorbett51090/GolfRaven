import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lintSource } from "../src/lint.js";

// build plan §10 P3 AT(2) (docs/golf-trails/02-build-plan.md:2759):
// "The authorization and service-role lint queries fail on seeded bad
// fixtures and pass on clean ones." §4.7.1a (line 1204-1205): "Its
// must-fail fixtures are one file each for .update, .upsert, .rpc, raw SQL
// through the DB URL, and a Storage .upload outside withOwnership."

const FIXTURES_ROOT = join(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "supabase",
  "functions",
  "__fixtures__",
);

function lintFixture(relPath: string) {
  const full = join(FIXTURES_ROOT, relPath);
  const source = readFileSync(full, "utf8");
  return lintSource(source, full);
}

describe("bad fixtures (must fail)", () => {
  it("flags a service-role .update() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-update.ts");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.rule === "service-role-construction")).toBe(
      true,
    );
    expect(
      findings.some((f) => f.rule === "privileged-call-outside-withOwnership"),
    ).toBe(true);
  });

  it("flags a service-role .upsert() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-upsert.ts");
    expect(
      findings.some(
        (f) =>
          f.rule === "privileged-call-outside-withOwnership" &&
          f.message.includes("upsert"),
      ),
    ).toBe(true);
  });

  it("flags a service-role .rpc() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-rpc.ts");
    expect(
      findings.some(
        (f) =>
          f.rule === "privileged-call-outside-withOwnership" &&
          f.message.includes("rpc"),
      ),
    ).toBe(true);
  });

  it("flags a raw Postgres driver import and SUPABASE_DB_URL reference", () => {
    const findings = lintFixture("bad/raw-sql-db-url.ts");
    const dbUrlFindings = findings.filter((f) => f.rule === "db-url-or-driver");
    expect(dbUrlFindings.length).toBeGreaterThanOrEqual(2); // the import AND the env var reference
    expect(dbUrlFindings.some((f) => f.message.includes("postgres"))).toBe(
      true,
    );
    expect(
      dbUrlFindings.some((f) => f.message.includes("SUPABASE_DB_URL")),
    ).toBe(true);
  });

  it("flags a service-role Storage .upload() call outside withOwnership", () => {
    const findings = lintFixture("bad/direct-storage-upload.ts");
    expect(
      findings.some(
        (f) =>
          f.rule === "privileged-call-outside-withOwnership" &&
          f.message.includes("upload"),
      ),
    ).toBe(true);
  });
});

describe("clean fixtures (must pass)", () => {
  it("passes a function that only touches the client inside withOwnership()", () => {
    expect(lintFixture("good/evidence-insert.ts")).toEqual([]);
  });

  it("passes a plain JWT-forwarded read with no service-role client", () => {
    expect(lintFixture("good/read-only-jwt-forwarded.ts")).toEqual([]);
  });
});

describe("privileged.ts itself is exempt", () => {
  it("never flags the allow-listed file, however it constructs its client", () => {
    const source = `
      import { createClient } from "@supabase/supabase-js";
      const c = createClient("url", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));
      export function withOwnership(actor, op) { return op(c); }
      c.from("play").update({});
    `;
    expect(
      lintSource(source, "/repo/supabase/functions/_shared/privileged.ts"),
    ).toEqual([]);
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
    expect(
      lintSource(source, "/repo/supabase/functions/evidence/index.ts"),
    ).toEqual([]);
  });
});
