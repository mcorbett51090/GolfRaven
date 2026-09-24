/**
 * Should-fix (ESM): confirms the *built* `dist/index.js` loads and runs
 * under plain Node ESM (`node --input-type=module`), not just under
 * vitest's own transform pipeline — this is what actually exercises the
 * `sax` default-import fix (`import sax from "sax"`, matching
 * `tools/p0`), since a subtly wrong import style can typecheck fine
 * under `tsc`/vitest but still fail at real module-resolution time.
 *
 * **Builds `dist/` itself in `beforeAll` if it's missing**, rather than
 * skipping — a skip that quietly passes is indistinguishable from a real
 * pass in a CI summary, and this check exists specifically to catch a
 * class of bug (a wrong import style) that only surfaces outside
 * vitest's own transform. `pnpm test` alone (without a prior `pnpm
 * build`) still exercises this test fully; it just pays the one-time
 * build cost first.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
const distIndex = path.resolve(packageRoot, "dist/index.js");
const tsBuildInfo = path.resolve(packageRoot, "tsconfig.build.tsbuildinfo");
const tscBin = path.resolve(packageRoot, "node_modules/.bin/tsc");

let builtByThisTest = false;

beforeAll(() => {
  if (existsSync(distIndex)) return;
  // `tsc -b`'s incremental cache (`tsconfig.build.tsbuildinfo`) can
  // believe the build is current even after `dist/` was deleted out from
  // under it (it doesn't re-verify output files exist, only its own
  // recorded state) — remove it so this is always a real, from-scratch
  // build, not a build that trusts stale state and emits nothing.
  if (existsSync(tsBuildInfo)) rmSync(tsBuildInfo);
  execFileSync(tscBin, ["-b", "tsconfig.build.json"], { cwd: packageRoot, stdio: "pipe" });
  builtByThisTest = true;
}, 60_000);

afterAll(() => {
  // Leave no trace on a machine that only ran `pnpm test`: if this test
  // is what created `dist/`, other tests in this same run may still be
  // relying on it existing (none currently do), so this only logs —
  // deleting it here would be surprising for anyone re-running `pnpm
  // build`/inspecting `dist/` right after a test run.
  if (builtByThisTest) {
    // eslint-disable-next-line no-console
    console.log("dist-esm.test.ts: built dist/ because it was missing (this is normal for a bare `pnpm test`).");
  }
});

describe("dist/index.js under plain Node ESM", () => {
  it("imports cleanly and exports the public API, with parseGpxFile actually working", () => {
    expect(existsSync(distIndex)).toBe(true);

    // The import specifier must be a literal string (ESM import
    // declarations aren't computed), so the file URL is resolved here,
    // outside the generated script, and spliced in as a JSON string.
    const distUrl = pathToFileURL(distIndex).href;
    const script = `
      import * as mod from ${JSON.stringify(distUrl)};
      const expected = ["parseFitFile","parseGpxFile","parseCsvFile","parseRound","toMatcherInput","correlationKey"];
      const missing = expected.filter((k) => typeof mod[k] !== "function");
      if (missing.length > 0) throw new Error("missing exports: " + missing.join(","));
      const gpx = '<?xml version="1.0"?><gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1"><trk><trkseg><trkpt lat="43.65" lon="-79.38"><time>2026-06-01T14:00:00Z</time></trkpt></trkseg></trk></gpx>';
      const bytes = new TextEncoder().encode(gpx);
      const result = mod.parseGpxFile(bytes);
      if (!result.ok || result.round.fixes.length !== 1) throw new Error("parseGpxFile didn't work under plain Node ESM");
      console.log("OK");
    `;
    const out = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
    });
    expect(out.trim()).toBe("OK");
  });
});
