// supabase/tests/unit/provider-revocation.test.ts
//
// Unit tests for the AT 6 "revokes connectors" seam (_shared/me/provider-revocation.ts). The Apple / Google SIGN-IN grants are no
// longer a seam (O12, migration 0035: signin-revocation.test.ts covers the real thing); only the P8 connector deferral remains.

import { describe, expect, it } from "vitest";
import * as mod from "../../functions/_shared/me/provider-revocation.js";
import { revokeConnectors } from "../../functions/_shared/me/provider-revocation.js";

describe("the sign-in seam is gone", () => {
  it("revokeSigninProviders no longer exists: nothing can report a sign-in grant as 'deferred' any more", () => {
    expect((mod as Record<string, unknown>).revokeSigninProviders).toBeUndefined();
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
