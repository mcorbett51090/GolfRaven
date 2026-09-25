// supabase/tests/unit/provider-revocation.test.ts
//
// Unit tests for the AT 6 "revokes connectors" / O12-AT-19 seam
// (_shared/me/provider-revocation.ts) — task instruction: "Apple/Google
// revocation is P4 (AT 19). Leave a clearly marked seam."

import { describe, expect, it } from "vitest";
import { revokeConnectors, revokeSigninProviders } from "../../functions/_shared/me/provider-revocation.js";

describe("revokeSigninProviders", () => {
  it("returns one deferred outcome per provider, never marking anything as actually revoked", () => {
    const outcomes = revokeSigninProviders(["apple", "google"]);
    expect(outcomes).toHaveLength(2);
    for (const o of outcomes) {
      expect(o.revoked).toBe(false);
      expect(o.deferred).toBe(true);
      expect(o.reason).toMatch(/P4/);
      expect(o.reason.toLowerCase()).toContain("revocation");
    }
    expect(outcomes.map((o) => o.provider)).toEqual(["apple", "google"]);
  });

  it("returns an empty array for no providers", () => {
    expect(revokeSigninProviders([])).toEqual([]);
  });
});

describe("revokeConnectors", () => {
  it("returns one deferred outcome per provider, distinct reason text naming P8", () => {
    const outcomes = revokeConnectors(["ghin", "garmin"]);
    expect(outcomes).toHaveLength(2);
    for (const o of outcomes) {
      expect(o.revoked).toBe(false);
      expect(o.deferred).toBe(true);
      expect(o.reason).toMatch(/P8/);
    }
  });

  it("returns an empty array for no providers", () => {
    expect(revokeConnectors([])).toEqual([]);
  });
});
