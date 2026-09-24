import { describe, expect, it } from "vitest";
import { canonicalJsonString, checkContract, generateContractSchema } from "../src/verify-contract.js";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("generateContractSchema", () => {
  it("produces a registry with every implemented top-level entity, including AchievementDef (part B)", () => {
    const generated = generateContractSchema() as { schemas: Record<string, unknown> };
    // "__shared" is Zod's own JSON-Schema-generator bucket for the
    // recursive RuleExpr type's $defs (AchievementDef.rule) — not a
    // top-level §4.1 entity, but part of what z.toJSONSchema emits once a
    // registered schema recurses. Present since AchievementDef joined the
    // registry (part B); asserted here so its appearance is intentional,
    // not silently ignored.
    expect(Object.keys(generated.schemas).sort()).toEqual(
      [
        "AchievementDef",
        "Course",
        "Designer",
        "Facility",
        "Hole",
        "OfferTerms",
        "Region",
        "RosterVersion",
        "Source",
        "Tee",
        "Trail",
        "__shared",
      ].sort(),
    );
  });
});

describe("checkContract (the committed-file staleness check)", () => {
  it("reports 'missing' when the contract file does not exist", async () => {
    const dir = await mkdtemp(join(tmpdir(), "catalog-contract-"));
    try {
      const result = await checkContract(join(dir, "does-not-exist.json"));
      expect(result.stale).toBe(true);
      expect(result.reason).toBe("missing");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reports 'diff' when the committed file does not match the generated schema", async () => {
    const dir = await mkdtemp(join(tmpdir(), "catalog-contract-"));
    try {
      const file = join(dir, "catalog.schema.json");
      await writeFile(file, '{"not":"the real schema"}\n', "utf8");
      const result = await checkContract(file);
      expect(result.stale).toBe(true);
      expect(result.reason).toBe("diff");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("reports not stale when the committed file matches exactly (including key order)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "catalog-contract-"));
    try {
      const file = join(dir, "catalog.schema.json");
      await writeFile(file, canonicalJsonString(generateContractSchema()), "utf8");
      const result = await checkContract(file);
      expect(result.stale).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("canonicalJsonString", () => {
  it("sorts object keys so committed-file diffs are never just key-order noise", () => {
    const a = canonicalJsonString({ b: 1, a: 2 });
    const b = canonicalJsonString({ a: 2, b: 1 });
    expect(a).toBe(b);
  });
});
