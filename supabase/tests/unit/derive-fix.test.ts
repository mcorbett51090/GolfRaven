// supabase/tests/unit/derive-fix.test.ts
import { describe, expect, it } from "vitest";
import { deriveFix } from "../../functions/_shared/evidence/derive-fix.js";
import type { FixSubmission } from "../../functions/_shared/evidence/request-shape.js";

function fix(overrides: Partial<FixSubmission> = {}): FixSubmission {
  return {
    fixId: "fix_1",
    lat: 1,
    lng: 2,
    accuracyMeters: 5,
    capturedAt: 1000,
    simulated: false,
    foreground: true,
    fromApp: true,
    ...overrides,
  };
}

describe("deriveFix", () => {
  it("with no checkinTokenJti and no lookup: challenge is 'none', token is {present:false, hardwareSupportsAttestation:false}", () => {
    const derived = deriveFix({ fix: fix(), resolvedFacilityId: "fac_x", localDate: "2026-06-01", match: null, tokenLookup: null });
    expect(derived.challenge).toBe("none");
    expect(derived.token).toEqual({ present: false, hardwareSupportsAttestation: false });
  });

  it("with a real token lookup: challenge/grade come from the SESSION, never the client", () => {
    const derived = deriveFix({
      fix: fix({ checkinTokenJti: "jti_1" }),
      resolvedFacilityId: "fac_x",
      localDate: "2026-06-01",
      match: null,
      tokenLookup: { userId: "u1", facilityId: "fac_x", attestationGrade: "unattestable", challengeKind: "live", expiresAt: "2099-01-01T00:00:00.000Z" },
    });
    expect(derived.challenge).toBe("live");
    expect(derived.token).toEqual({ present: true, grade: "unattestable" });
  });

  it("with no course anchor (match: null): defaults conservatively — never a co-signal via geometry", () => {
    const derived = deriveFix({ fix: fix(), resolvedFacilityId: "fac_x", localDate: "2026-06-01", match: null, tokenLookup: null });
    expect(derived.verificationTier).toBe("unverified");
    expect(derived.geometryKind).toBe("radius");
    expect(derived.insideBuffer).toBe(false);
  });

  it("passes through a REAL PostGIS match result untouched", () => {
    const derived = deriveFix({
      fix: fix(),
      resolvedFacilityId: "fac_x",
      localDate: "2026-06-01",
      match: { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true },
      tokenLookup: null,
    });
    expect(derived.verificationTier).toBe("play-verified");
    expect(derived.geometryKind).toBe("polygon");
    expect(derived.insideBuffer).toBe(true);
  });

  it("every fix's facilityId is the EVIDENCE ROW's resolved facility, never a per-fix client claim", () => {
    const derived = deriveFix({ fix: fix(), resolvedFacilityId: "fac_resolved", localDate: "2026-06-01", match: null, tokenLookup: null });
    expect(derived.facilityId).toBe("fac_resolved");
  });
});
