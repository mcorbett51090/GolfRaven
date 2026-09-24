import { describe, expect, it } from "vitest";
import {
  appendVersion,
  assertVersionsAppendOnly,
  canonicalStringify,
  sha256Hex,
  sortById,
  type VersionEntry,
} from "../src/manifest.js";

describe("canonicalStringify", () => {
  it("sorts object keys recursively", () => {
    const a = canonicalStringify({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalStringify({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
  });

  it("leaves array element order exactly as given", () => {
    const s = canonicalStringify({ list: [{ z: 1 }, { a: 1 }] });
    const parsed = JSON.parse(s) as { list: unknown[] };
    expect(Object.keys(parsed.list[0] as object)).toEqual(["z"]);
    expect(Object.keys(parsed.list[1] as object)).toEqual(["a"]);
  });

  it("ends with a trailing newline", () => {
    expect(canonicalStringify({ a: 1 }).endsWith("\n")).toBe(true);
  });
});

describe("sha256Hex", () => {
  it("is a known, stable digest for a known input", () => {
    // sha256("") — a fixed, well-known value, so this test also catches an
    // accidental hash-algorithm swap.
    expect(sha256Hex(Buffer.from(""))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

describe("sortById", () => {
  it("sorts by id without mutating the input array", () => {
    const input = [{ id: "b" }, { id: "a" }, { id: "c" }];
    const sorted = sortById(input);
    expect(sorted.map((x) => x.id)).toEqual(["a", "b", "c"]);
    expect(input.map((x) => x.id)).toEqual(["b", "a", "c"]);
  });
});

function version(overrides: Partial<VersionEntry> = {}): VersionEntry {
  return {
    version: "20260101-abc0001",
    publishedAt: "2026-01-01T00:00:00.000Z",
    kid: "test-kid-1",
    sha256: "a".repeat(64),
    ...overrides,
  };
}

describe("assertVersionsAppendOnly", () => {
  it("passes when next is previous plus new entries at the end", () => {
    const previous = [version()];
    const next = [version(), version({ version: "20260102-abc0002" })];
    expect(() => assertVersionsAppendOnly(previous, next)).not.toThrow();
  });

  it("throws when an earlier entry is dropped", () => {
    const previous = [version(), version({ version: "20260102-abc0002" })];
    const next = [version({ version: "20260102-abc0002" })];
    expect(() => assertVersionsAppendOnly(previous, next)).toThrow(/append-only violation/);
  });

  it("throws when an earlier entry's content is changed", () => {
    const previous = [version()];
    const next = [version({ sha256: "b".repeat(64) })];
    expect(() => assertVersionsAppendOnly(previous, next)).toThrow(/append-only violation/);
  });

  it("throws when an earlier entry is reordered", () => {
    const previous = [version({ version: "v1" }), version({ version: "v2" })];
    const next = [version({ version: "v2" }), version({ version: "v1" })];
    expect(() => assertVersionsAppendOnly(previous, next)).toThrow(/append-only violation/);
  });
});

describe("appendVersion", () => {
  it("appends a genuinely new version", () => {
    const previous = [version()];
    const next = appendVersion(previous, version({ version: "20260102-abc0002" }));
    expect(next.map((v) => v.version)).toEqual(["20260101-abc0001", "20260102-abc0002"]);
  });

  it("is idempotent for an identical republish of the same version", () => {
    const previous = [version()];
    const next = appendVersion(previous, version());
    expect(next).toEqual(previous);
  });

  it("refuses a republish of an existing version under different content", () => {
    const previous = [version()];
    expect(() => appendVersion(previous, version({ sha256: "c".repeat(64) }))).toThrow(
      /already published with different content/,
    );
  });
});
