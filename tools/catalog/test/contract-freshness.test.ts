/**
 * Wires `verify-contract` into the existing `pnpm -r test` path (build
 * plan §3.5: "CI regenerates `contract/catalog.schema.json` and fails on
 * any diff"), by checking the REAL committed file at the repo root — not
 * a fixture — so a stale schema fails this package's own `test` script,
 * and therefore `pnpm -r test` from the repo root. `.github/workflows/ci.yml`
 * also runs `verify-contract` directly as its own step, for a clearer,
 * dedicated failure message in CI — see this repo's `ci.yml` and the P1a
 * report for why both.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkContract } from "../src/verify-contract.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CONTRACT_PATH = join(REPO_ROOT, "contract", "catalog.schema.json");

describe("contract/catalog.schema.json freshness", () => {
  it("matches what the current §4.1 Zod schema generates", async () => {
    const result = await checkContract(CONTRACT_PATH);
    if (result.stale) {
      throw new Error(
        result.reason === "missing"
          ? `${CONTRACT_PATH} does not exist. Run: node tools/catalog/dist/verify-contract.js --write`
          : `${CONTRACT_PATH} is stale (does not match packages/catalog's Zod schema). Run: node tools/catalog/dist/verify-contract.js --write`,
      );
    }
    expect(result.stale).toBe(false);
  });
});
