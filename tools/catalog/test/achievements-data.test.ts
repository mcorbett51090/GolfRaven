/**
 * P1 AT(1): "verify-catalog validates every file" — `data/achievements/*.json`
 * (build plan §8.1: "Every badge is written out in full below. Each row is
 * a numbered P1 must-pass fixture"). Reads the REAL committed directory
 * (the same `contract-freshness.test.ts` pattern: a real file, not a
 * fixture), so a badge that stops validating fails this package's own
 * `test` script — and therefore `pnpm -r test` from the repo root.
 *
 * Every file here is validated with `validateAchievementFile` (schema +
 * `checkRuleExpr` in `badge` mode, per `verify-catalog.ts`'s module doc:
 * every §8.1 badge runs badge mode) rather than through the full
 * bundle/ledger `verifyCatalog` pipeline — see that function's own doc for
 * why (`data/id-ledger.json` "stays genuinely empty" in this repo, so
 * there is no real ledger yet for `data/achievements/*.json` to be
 * cross-referenced against).
 */
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { validateAchievementFile } from "../src/verify-catalog.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ACHIEVEMENTS_DIR = join(REPO_ROOT, "data", "achievements");

async function loadAll(): Promise<{ file: string; raw: unknown }[]> {
  const entries = await readdir(ACHIEVEMENTS_DIR);
  const jsonFiles = entries.filter((f) => f.endsWith(".json")).sort();
  return Promise.all(
    jsonFiles.map(async (file) => ({
      file,
      raw: JSON.parse(await readFile(join(ACHIEVEMENTS_DIR, file), "utf8")),
    })),
  );
}

describe("data/achievements/*.json (every §8.1 badge, G2-01/G3-02)", () => {
  it("has at least one file per §8.1 row R-01–R-13 (18 files: R-02/R-06 have several thresholds each)", async () => {
    const entries = await readdir(ACHIEVEMENTS_DIR);
    const jsonFiles = entries.filter((f) => f.endsWith(".json"));
    expect(jsonFiles.length).toBe(18);
  });

  it("every file passes AchievementDefSchema + checkRuleExpr(mode: 'badge')", async () => {
    const all = await loadAll();
    for (const { file, raw } of all) {
      const result = validateAchievementFile(raw);
      if (!result.ok) {
        throw new Error(`${file} failed: ${JSON.stringify(result.issues)}`);
      }
      expect(result.ok).toBe(true);
    }
  });

  it("every id is unique across the directory", async () => {
    const all = await loadAll();
    const ids = all.map(({ raw }) => (raw as { id: string }).id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every definition is scope: 'verified-only' (task instruction)", async () => {
    const all = await loadAll();
    for (const { file, raw } of all) {
      expect((raw as { scope: string }).scope, file).toBe("verified-only");
    }
  });
});
