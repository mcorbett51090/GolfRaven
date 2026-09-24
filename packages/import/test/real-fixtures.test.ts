import { describe, it } from "vitest";

/**
 * Placeholder for real, trimmed Garmin Approach S62 scorecard FIT
 * fixtures (build plan §7.3 lane 2; `test/fixtures/real/README.md`).
 *
 * Skipped because `test/fixtures/real/` holds no real device data today —
 * the owner will supply trimmed files later. Once one exists, replace
 * this `it.skip` with real assertions against `parseFitFile` and (once
 * `parse-fit-scorecard.ts` is updated against the confirmed layout)
 * `extractGolfScorecard`.
 */
describe("real Garmin S62 scorecard fixtures", () => {
  it.skip("parses a real, trimmed Approach S62 scorecard FIT file", () => {
    // const bytes = await readFile("test/fixtures/real/<trimmed-file>.fit");
    // const result = await parseFitFile(bytes);
    // expect(result.ok).toBe(true);
  });
});
