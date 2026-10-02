// supabase/tests/unit/manifest-artifact.test.ts
import { describe, expect, it } from "vitest";
import { canonicalStringify, compareCatalogVersions, compareCodePoints, parseCatalogManifest, parseManifestSignature, parseVersionsArray, parseVersionsSignature } from "../../functions/_shared/catalog/manifest-artifact.js";

describe("canonicalStringify", () => {
  it("sorts object keys by code point, recursively, with a trailing newline", () => {
    expect(canonicalStringify({ b: 1, a: { d: 2, c: 3 } })).toBe('{\n  "a": {\n    "c": 3,\n    "d": 2\n  },\n  "b": 1\n}\n');
  });

  it("leaves array element order untouched", () => {
    expect(canonicalStringify([3, 1, 2])).toBe("[\n  3,\n  1,\n  2\n]\n");
  });
});

describe("compareCodePoints", () => {
  it("orders plain ASCII the same as normal string comparison", () => {
    expect(compareCodePoints("a", "b")).toBeLessThan(0);
    expect(compareCodePoints("b", "a")).toBeGreaterThan(0);
    expect(compareCodePoints("a", "a")).toBe(0);
  });
});

const VALID_MANIFEST = {
  contractVersion: 1,
  catalogVersion: "20260925-abc1234",
  minAppVersion: "1.0.0",
  kid: "kid-1",
  revokedKids: [],
  generatedAt: "2026-09-25T00:00:00.000Z",
  shards: [{ path: "id-ledger.json", sha256: "a".repeat(64), bytes: 10 }],
};

describe("parseCatalogManifest", () => {
  it("accepts a well-formed manifest", () => {
    const r = parseCatalogManifest(VALID_MANIFEST);
    expect(r.ok).toBe(true);
  });

  it("rejects a non-object", () => {
    expect(parseCatalogManifest("nope").ok).toBe(false);
  });

  it("rejects a malformed catalogVersion", () => {
    const r = parseCatalogManifest({ ...VALID_MANIFEST, catalogVersion: "not-a-version" });
    expect(r.ok).toBe(false);
  });

  it("rejects a shard path containing ..", () => {
    const r = parseCatalogManifest({ ...VALID_MANIFEST, shards: [{ path: "../escape.json", sha256: "a".repeat(64), bytes: 1 }] });
    expect(r.ok).toBe(false);
  });

  it("rejects an absolute shard path", () => {
    const r = parseCatalogManifest({ ...VALID_MANIFEST, shards: [{ path: "/etc/passwd", sha256: "a".repeat(64), bytes: 1 }] });
    expect(r.ok).toBe(false);
  });

  it("rejects a bad kid format", () => {
    const r = parseCatalogManifest({ ...VALID_MANIFEST, kid: "KID WITH SPACES" });
    expect(r.ok).toBe(false);
  });
});

describe("parseManifestSignature", () => {
  it("accepts a well-formed signature envelope", () => {
    const r = parseManifestSignature({ catalogVersion: "20260925-abc1234", contractVersion: 1, kid: "kid-1", manifestSha: "a".repeat(64), sig: "sig" });
    expect(r.ok).toBe(true);
  });

  it("rejects a non-hex manifestSha", () => {
    const r = parseManifestSignature({ catalogVersion: "20260925-abc1234", contractVersion: 1, kid: "kid-1", manifestSha: "zz", sig: "sig" });
    expect(r.ok).toBe(false);
  });

  it("rejects an empty sig", () => {
    const r = parseManifestSignature({ catalogVersion: "20260925-abc1234", contractVersion: 1, kid: "kid-1", manifestSha: "a".repeat(64), sig: "" });
    expect(r.ok).toBe(false);
  });
});

describe("parseVersionsArray", () => {
  it("accepts a well-formed array", () => {
    const r = parseVersionsArray([{ version: "20260925-abc1234", publishedAt: "2026-09-25T00:00:00.000Z", kid: "kid-1", sha256: "a".repeat(64) }]);
    expect(r.ok).toBe(true);
  });

  it("rejects a non-array", () => {
    expect(parseVersionsArray({}).ok).toBe(false);
  });

  it("rejects an entry with a malformed publishedAt (no milliseconds)", () => {
    const r = parseVersionsArray([{ version: "20260925-abc1234", publishedAt: "2026-09-25T00:00:00Z", kid: "kid-1", sha256: "a".repeat(64) }]);
    expect(r.ok).toBe(false);
  });
});

describe("parseVersionsSignature", () => {
  it("accepts a well-formed envelope", () => {
    expect(parseVersionsSignature({ kid: "kid-1", versionsSha: "a".repeat(64), sig: "sig" }).ok).toBe(true);
  });
  it("rejects a missing versionsSha", () => {
    expect(parseVersionsSignature({ kid: "kid-1", sig: "sig" }).ok).toBe(false);
  });
});

describe("compareCatalogVersions", () => {
  it("orders primarily by date", () => {
    expect(compareCatalogVersions("20260101-aaaaaaa", "20260201-aaaaaaa")).toBeLessThan(0);
  });
  it("falls back to a code-point compare of the sha suffix on the same date", () => {
    expect(compareCatalogVersions("20260101-aaaaaaa", "20260101-bbbbbbb")).toBeLessThan(0);
  });
  it("reports equal versions as equal", () => {
    expect(compareCatalogVersions("20260101-aaaaaaa", "20260101-aaaaaaa")).toBe(0);
  });
});
