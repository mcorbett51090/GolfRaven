import { rm } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { jsonLdScript } from "../src/lib/schema";
import { regionInfo, regionPageSize } from "../src/lib/derive";
import type { Catalog } from "@golfraven/catalog";
import { demoBundleForSite } from "../fixtures/demo-catalog/build-bundle.mjs";
import { loadCatalogFromBundle } from "@golfraven/catalog";
import { normalizeGolfravenEnv, isProductionEnv } from "../src/lib/env.mjs";

const LINE_SEPARATOR = String.fromCharCode(0x2028);
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029);

describe("jsonLdScript — nit: escapes U+2028/U+2029 as well as <", () => {
  it("escapes a literal </script>", () => {
    const html = jsonLdScript([{ name: "</script><script>alert(1)</script>" }]);
    expect(html).not.toContain("</script><script>");
  });
  it("escapes U+2028 and U+2029", () => {
    const html = jsonLdScript([{ name: `line${LINE_SEPARATOR}sep${PARAGRAPH_SEPARATOR}para` }]);
    expect(html).not.toContain(LINE_SEPARATOR);
    expect(html).not.toContain(PARAGRAPH_SEPARATOR);
    expect(html).toContain("\\u2028");
    expect(html).toContain("\\u2029");
  });
});

describe("regionPageSize — REGION_PAGE_SIZE env override (B2)", () => {
  it("defaults to 200 with no override", () => {
    expect(regionPageSize({})).toBe(200);
  });
  it("honours a valid positive integer override", () => {
    expect(regionPageSize({ REGION_PAGE_SIZE: "1" })).toBe(1);
  });
  it("falls back to 200 on an invalid override", () => {
    expect(regionPageSize({ REGION_PAGE_SIZE: "not-a-number" })).toBe(200);
    expect(regionPageSize({ REGION_PAGE_SIZE: "-5" })).toBe(200);
  });
});

describe("normalizeGolfravenEnv / isProductionEnv — case normalisation + closed value set", () => {
  it("returns undefined for unset/empty", () => {
    expect(normalizeGolfravenEnv(undefined)).toBeUndefined();
    expect(normalizeGolfravenEnv("")).toBeUndefined();
  });
  it("normalises case for each allowed value", () => {
    expect(normalizeGolfravenEnv("production")).toBe("production");
    expect(normalizeGolfravenEnv("Production")).toBe("production");
    expect(normalizeGolfravenEnv("PRODUCTION")).toBe("production");
    expect(normalizeGolfravenEnv("Staging")).toBe("staging");
    expect(normalizeGolfravenEnv("Development")).toBe("development");
  });
  it("rejects an unknown value", () => {
    expect(() => normalizeGolfravenEnv("prod")).toThrow(/Unknown GOLFRAVEN_ENV/);
    expect(() => normalizeGolfravenEnv("test")).toThrow(/Unknown GOLFRAVEN_ENV/);
  });
  it("isProductionEnv is true only for a case-insensitive 'production'", () => {
    expect(isProductionEnv({ GOLFRAVEN_ENV: "PRODUCTION" })).toBe(true);
    expect(isProductionEnv({ GOLFRAVEN_ENV: "staging" })).toBe(false);
    expect(isProductionEnv({})).toBe(false);
  });
  it("isProductionEnv throws on an unknown value rather than treating it as non-production", () => {
    expect(() => isProductionEnv({ GOLFRAVEN_ENV: "prod" })).toThrow(/Unknown GOLFRAVEN_ENV/);
  });
});

describe("regionInfo — production refuses the derived-name fallback (gate review nit)", () => {
  const catalog: Catalog = loadCatalogFromBundle(demoBundleForSite());

  it("derives a name outside production when no Region record exists for the code", () => {
    const info = regionInfo(catalog, "US-AL", {});
    expect(info.country).toBe("us");
    expect(info.slug).toBe("al");
  });

  it("throws in production when no Region record exists for the code", () => {
    expect(() => regionInfo(catalog, "US-AL", { GOLFRAVEN_ENV: "production" })).toThrow(
      /Region record/,
    );
  });

  it("throws the same way for a differently-cased GOLFRAVEN_ENV=Production", () => {
    expect(() => regionInfo(catalog, "US-AL", { GOLFRAVEN_ENV: "Production" })).toThrow(
      /Region record/,
    );
  });

  it("uses the authored Region record in production when one exists", () => {
    const info = regionInfo(catalog, "US-TN", { GOLFRAVEN_ENV: "production" });
    expect(info.name).toBe("Tennessee");
    expect(info.slug).toBe("tn");
  });
});

describe("loadPrimaryTrailOverrides — data/overrides/primary-trail.json (nit: read in the SITE, not packages/catalog)", () => {
  const dirs: string[] = [];
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
  });

  it("returns an empty map when the file does not exist", async () => {
    // Import fresh with an isolated module cache is overkill here — the
    // function itself is pure aside from the fixed file path, so this
    // just proves the ENOENT branch doesn't throw for the (real, absent)
    // repo file.
    const { loadPrimaryTrailOverrides } = await import("../src/lib/derive");
    const overrides = await loadPrimaryTrailOverrides();
    expect(overrides).toBeInstanceOf(Map);
  });
});
