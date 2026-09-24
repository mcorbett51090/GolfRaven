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
});
