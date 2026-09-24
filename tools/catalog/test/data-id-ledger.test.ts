/**
 * `data/id-ledger.json` is the real, committed ledger file (§3.5) — this
 * checks it against `IdLedgerSchema` so a malformed edit to it fails
 * `pnpm -r test`, the same way `contract-freshness.test.ts` guards
 * `contract/catalog.schema.json`. P1a scope: this file is expected to be
 * empty (no real id has been minted yet — see `data/README.md`).
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { IdLedgerSchema } from "@golfraven/catalog";

const REPO_ROOT = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
);
const LEDGER_PATH = join(REPO_ROOT, "data", "id-ledger.json");

describe("data/id-ledger.json", () => {
  it("is valid against IdLedgerSchema", async () => {
    const raw = JSON.parse(await readFile(LEDGER_PATH, "utf8"));
    const result = IdLedgerSchema.safeParse(raw);
    expect(result.success).toBe(true);
  });

  it("is empty in P1a (no real id minted yet)", async () => {
    const raw = JSON.parse(await readFile(LEDGER_PATH, "utf8")) as {
      entries: Record<string, unknown>;
    };
    expect(Object.keys(raw.entries)).toHaveLength(0);
  });
});
