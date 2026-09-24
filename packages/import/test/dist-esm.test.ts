/**
 * Should-fix (ESM): confirms the *built* `dist/index.js` loads and runs
 * under plain Node ESM (`node --input-type=module`), not just under
 * vitest's own transform pipeline — this is what actually exercises the
 * `sax` default-import fix (`import sax from "sax"`, matching
 * `tools/p0`), since a subtly wrong import style can typecheck fine
 * under `tsc`/vitest but still fail at real module-resolution time.
 *
 * Requires `dist/` to already exist (`pnpm build`) — skipped rather than
 * failed when it doesn't, since a bare `pnpm test` without a prior build
 * is a normal thing to run during development.
 */
import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const distIndex = path.resolve(here, "../dist/index.js");
const distExists = existsSync(distIndex);

describe.skipIf(!distExists)("dist/index.js under plain Node ESM", () => {
  it("imports cleanly and exports the public API, with parseGpxFile actually working", () => {
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
