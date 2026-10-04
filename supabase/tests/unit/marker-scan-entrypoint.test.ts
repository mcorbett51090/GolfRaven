// supabase/tests/unit/marker-scan-entrypoint.test.ts
//
// Structural guarantees for POST /v1/marker-scan (P5.1a S2a) that a behavioural test cannot state as strongly: they read the source, like rewards-isolation.test.ts does.
//
//   1. ORDER in the entrypoint: strict body parse, THEN the per-user rate limit, THEN `withOwnership` (a hit from inside the transaction would hold a second pooled connection;
//      the rate limit has to count refused requests too, so it comes before the handler), and the handler runs inside ONE `withOwnership`.
//   2. A committed refusal (`outcome.kind === "refused"`) is answered AFTER the transaction; the entrypoint reads no environment variable and logs nothing (the scan's inputs are a QR
//      and a PIN).
//   3. The PIN derivation label exists in NO production TypeScript (the PIN is derived in Postgres only; the reference implementation is a test), and no file under supabase/functions imports
//      the test-only key minting.
//   4. The handler's persisted-vs-rolled-back split: only the two refusals that must commit are RETURNED (`kind: "refused"`); every other refusal is THROWN.
//   5. Every database access in the player-lane modules goes through `Repo` (privileged.ts): none imports a database driver or names a table.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const FUNCTIONS = join(import.meta.dirname, "..", "..", "functions");
const read = (rel: string) => readFileSync(join(FUNCTIONS, rel), "utf8");
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

describe("marker-scan/index.ts: the request's order", () => {
  const code = stripComments(read("marker-scan/index.ts"));
  const at = (needle: string) => {
    const i = code.indexOf(needle);
    expect(i, `${needle} is present`).toBeGreaterThan(-1);
    return i;
  };

  it("parses strictly, then hits the rate limit, then opens withOwnership, then answers", () => {
    const parse = at("parseMarkerScanBody(");
    const limit = at("hitRateLimitForActor(");
    const own = at("withOwnership(");
    const refused = at('outcome.kind === "refused"');
    expect(parse).toBeLessThan(limit);
    expect(limit).toBeLessThan(own);
    expect(own).toBeLessThan(refused);
  });

  it("authenticates before it reads the body, and refuses a non-POST first", () => {
    expect(at('req.method !== "POST"')).toBeLessThan(at("getActorFromRequest("));
    expect(at("getActorFromRequest(")).toBeLessThan(at("readJsonBody("));
  });

  it("uses exactly one withOwnership, and the rate limit hit is not inside it", () => {
    expect(code.match(/withOwnership\(/g)).toHaveLength(1);
    const own = code.indexOf("withOwnership(");
    expect(code.slice(own)).not.toMatch(/hitRateLimitForActor/);
  });

  it("uses the documented bucket (20 / user / day)", () => {
    expect(code).toMatch(/hitRateLimitForActor\(actor, MARKER_SCAN_BUCKET, MARKER_SCAN_WINDOW_SECONDS, MARKER_SCAN_PER_USER_DAY\)/);
    const params = stripComments(read("_shared/course-qr/params.ts"));
    expect(params).toMatch(/MARKER_SCAN_BUCKET = "marker-scan:user"/);
    expect(params).toMatch(/MARKER_SCAN_WINDOW_SECONDS = 86_400;/);
    expect(params).toMatch(/MARKER_SCAN_PER_USER_DAY = 20;/);
  });

  it("answers a no-store response and reads no environment variable and writes no log", () => {
    expect(code).toMatch(/"cache-control": "no-store"/);
    expect(code).not.toMatch(/Deno\.env|process\.env/);
    expect(code).not.toMatch(/console\./);
  });
});

describe("the player-lane modules", () => {
  const dirs = [join(FUNCTIONS, "_shared", "course-qr"), join(FUNCTIONS, "marker-scan")];
  const files = dirs.flatMap((d) => walk(d));

  it("none reads the environment, logs, or imports a database driver", () => {
    expect(files.length).toBeGreaterThan(5);
    for (const f of files) {
      const code = stripComments(readFileSync(f, "utf8"));
      expect(code, f).not.toMatch(/Deno\.env|process\.env/);
      expect(code, f).not.toMatch(/console\./);
      expect(code, f).not.toMatch(/from "postgres|postgresjs|@supabase\/supabase-js/);
      expect(code, f).not.toMatch(/\b(?:app|private)\.[a-z_]+\b/); // no table or function is named outside privileged.ts
    }
  });

  it("the daily PIN's derivation label appears in no production TypeScript", () => {
    for (const f of walk(FUNCTIONS)) expect(readFileSync(f, "utf8"), f).not.toMatch(/golfraven\/course-pin/);
  });

  it("nothing under supabase/functions imports the test-only key minting", () => {
    for (const f of walk(FUNCTIONS)) expect(stripComments(readFileSync(f, "utf8")), f).not.toMatch(/course-qr-test-keys|fake-marker-scan-repo|marker-scan-world/);
  });
});

describe("scan-handler.ts: which refusals commit and which roll back", () => {
  const code = stripComments(read("_shared/course-qr/scan-handler.ts"));

  it("returns exactly three committed refusals (forged rotating QR, forged printed QR, wrong PIN) plus the locked PIN; everything else is thrown", () => {
    const returned = code.match(/return \{ kind: "refused"/g) ?? [];
    // forged rotating, forged printed, wrong PIN, locked PIN
    expect(returned).toHaveLength(4);
  });

  it("the QR is verified, and the PIN gate decided, BEFORE the check-in token is consumed or anything is written", () => {
    const verify = code.indexOf("verifyRotatingToken(");
    const forged = code.indexOf('fraudSignal.insert("course_qr_forged"');
    const gate = code.indexOf("attemptPin(");
    const count = code.lastIndexOf("await countCoSignal(repo, deps, body, facilityId, tz)");
    const record = code.indexOf("markerScan.record(");
    expect(verify).toBeGreaterThan(-1);
    expect(forged).toBeGreaterThan(verify);
    expect(gate).toBeGreaterThan(forged);
    expect(count).toBeGreaterThan(gate);
    expect(record).toBeGreaterThan(count);
  });

  it("a database refusal after the fix was counted is thrown, never returned", () => {
    const after = code.slice(code.indexOf("markerScan.record("));
    expect(after).toMatch(/throw mapRecordRefusal\(/);
    expect(after).not.toMatch(/kind: "refused"/);
  });
});
