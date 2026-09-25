// supabase/tests/unit/rules-vendor-freshness.test.ts
//
// Fails CI if supabase/functions/_shared/scoring/vendor/ has drifted from
// a fresh copy (generate-bundle.sh's own header comment: "packages/rules/
// dist ... stays the single source of truth ... never hand-edited").
// Two independent checks: (1) byte-for-byte equality against a freshly
// regenerated copy in a scratch directory, and (2) a functional smoke
// test — the vendored scorePlay produces the EXACT SAME result as
// packages/rules' own dist build on a real fixture, proving the vendor
// step didn't silently change behaviour even if some future edit to
// generate-bundle.sh changed its byte-for-byte output incidentally.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(import.meta.dirname, "..", "..", "..");
const VENDOR_DIR = join(REPO_ROOT, "supabase", "functions", "_shared", "scoring", "vendor");
const GENERATE_SCRIPT = join(REPO_ROOT, "supabase", "functions", "_shared", "scoring", "generate-bundle.sh");

const VENDORED_FILES = ["score-play.js", "parse-evidence.js", "internal/classify.js", "catalog/geo.js", "catalog/common.js", "catalog/index.js", "catalog/region-codes.json", "catalog/tzdb-backward-links.json"];

describe("rules vendor freshness", () => {
  it("packages/rules/dist and packages/catalog/dist exist (pnpm -r build has run)", () => {
    expect(existsSync(join(REPO_ROOT, "packages/rules/dist/score-play.js"))).toBe(true);
    expect(existsSync(join(REPO_ROOT, "packages/catalog/dist/geo.js"))).toBe(true);
  });

  it("the committed vendor/ tree matches a fresh regeneration byte-for-byte", () => {
    // ⛔ FIX (P3c gate round 2, should-fix nit): "the freshness test must
    // not overwrite the committed tree; regenerate into a temp dir and
    // diff." generate-bundle.sh now takes an optional output-dir argument
    // (default: its own committed vendor/) specifically so this test can
    // regenerate into an isolated scratch directory and compare — the
    // committed tree is only ever READ here, never written, so a failing
    // assertion (or a crash mid-test) can never leave the working tree
    // modified.
    const scratchOut = mkdtempSync(join(tmpdir(), "gr-vendor-check-"));
    try {
      execFileSync("bash", [GENERATE_SCRIPT, scratchOut], { stdio: "pipe" });
      for (const f of VENDORED_FILES) {
        const committedPath = join(VENDOR_DIR, f);
        const freshPath = join(scratchOut, f);
        expect(existsSync(committedPath), `${f} is not in the committed vendor/ tree`).toBe(true);
        expect(existsSync(freshPath), `${f} was not produced by a fresh regeneration`).toBe(true);
        const committed = readFileSync(committedPath);
        const fresh = readFileSync(freshPath);
        expect(fresh.equals(committed), `${f} drifted from the committed vendor/ tree — re-run generate-bundle.sh and commit the result`).toBe(true);
      }
    } finally {
      rmSync(scratchOut, { recursive: true, force: true });
    }
  });

  it("functional smoke test: the vendored scorePlay matches packages/rules' own dist build on a real fixture", async () => {
    const real = await import(join(REPO_ROOT, "packages/rules/dist/score-play.js"));
    const vendored = await import(join(VENDOR_DIR, "score-play.js"));

    const ctx = { playFacilityId: "fac_test", playLocalDate: "2026-06-01", playCourseId: "course_test", facilityTz: "Atlantic/Reykjavik" };
    const fix = {
      fixId: "fix_1",
      facilityId: "fac_test",
      fromApp: true,
      simulated: false,
      foreground: true,
      challenge: "live",
      token: { present: true, grade: "attested" },
      verificationTier: "play-verified",
      geometryKind: "polygon",
      insideBuffer: true,
      accuracyMeters: 10,
      capturedAt: Date.parse("2026-06-01T12:00:00.000Z"),
      localDate: "2026-06-01",
    };
    const evidence = [{ id: "ev_1", facilityId: "fac_test", courseId: "course_test", localDate: "2026-06-01", source: "staff_presence", scanAt: Date.parse("2026-06-01T12:05:00.000Z"), coSignalFix: fix }];

    const realResult = real.scorePlay(evidence, ctx);
    const vendoredResult = vendored.scorePlay(evidence, ctx);
    expect(vendoredResult).toEqual(realResult);
    expect(realResult.ok).toBe(true);
  });
});
