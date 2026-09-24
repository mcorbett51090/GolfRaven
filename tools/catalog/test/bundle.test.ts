import { describe, expect, it } from "vitest";
import { parseCatalogBundle } from "../src/bundle.js";

describe("parseCatalogBundle", () => {
  it("returns ok:false with dotted paths on a malformed bundle", () => {
    const result = parseCatalogBundle({ contractVersion: 0 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      const paths = result.schemaIssues.map((i) => i.path);
      expect(paths).toContain("facilities");
      expect(paths).toContain("trails");
      expect(paths).toContain("idLedger");
    }
  });

  it("rejects a bundle with an unexpected top-level property", () => {
    const result = parseCatalogBundle({
      contractVersion: 0,
      facilities: [],
      trails: [],
      idLedger: { entries: {} },
      somethingElse: true,
    });
    expect(result.ok).toBe(false);
  });

  it("accepts a minimal, otherwise-empty bundle", () => {
    const result = parseCatalogBundle({
      contractVersion: 0,
      facilities: [],
      trails: [],
      idLedger: { entries: {} },
    });
    expect(result.ok).toBe(true);
  });

  // Blocking #2 (gate review, post-e9b3ab0): neither field is part of the
  // schema any more — a bundle asserting either is rejected outright.
  it("S2/blocking #2: rejects a bundle carrying its own labels[]", () => {
    const result = parseCatalogBundle({
      contractVersion: 0,
      facilities: [],
      trails: [],
      idLedger: { entries: {} },
      labels: ["geometry-reviewed", "contact-reviewed"],
    });
    expect(result.ok).toBe(false);
  });

  it("blocking #2: rejects a bundle carrying its own bookingHostAllowList", () => {
    const result = parseCatalogBundle({
      contractVersion: 0,
      facilities: [],
      trails: [],
      idLedger: { entries: {} },
      bookingHostAllowList: ["evil.example.net"],
    });
    expect(result.ok).toBe(false);
  });
});
