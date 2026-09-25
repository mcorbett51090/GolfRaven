// supabase/tests/unit/request-shape.test.ts
//
// Unit tests for supabase/functions/_shared/evidence/request-shape.ts.
// Lives OUTSIDE supabase/functions/** deliberately — tools/service-role
// -lint scans every .ts file under supabase/functions/**, and a vitest
// test file necessarily imports the bare specifier "vitest", which the
// lint would flag as a banned import outside privileged.ts. Every test
// file in this directory imports the real module under test via a
// relative path into supabase/functions/_shared, so it exercises the
// EXACT file the Edge Functions ship, never a copy.
import { describe, expect, it } from "vitest";
import { parseEvidenceSubmission, REJECTED_SOURCES } from "../../functions/_shared/evidence/request-shape.js";

function goodFix(overrides: Record<string, unknown> = {}) {
  return {
    fixId: "fix_abc123",
    lat: 36.1467,
    lng: -86.7816,
    accuracyMeters: 10,
    capturedAt: Date.parse("2026-06-01T12:00:00.000Z"),
    simulated: false,
    foreground: true,
    fromApp: true,
    ...overrides,
  };
}

function baseBody(overrides: Record<string, unknown> = {}) {
  return {
    source: "foreground_checkin",
    deviceId: "dev_1",
    facilityId: "fac_x",
    courseId: "crs_x1",
    localDate: "2026-06-01",
    catalogVersion: 1,
    fix: goodFix(),
    ...overrides,
  };
}

describe("parseEvidenceSubmission", () => {
  it("accepts a well-formed foreground_checkin submission", () => {
    const result = parseEvidenceSubmission(baseBody());
    expect(result.ok).toBe(true);
  });

  it("rejects every trust-table-restricted source with a clear error (security doc §2)", () => {
    for (const source of REJECTED_SOURCES) {
      const result = parseEvidenceSubmission({ ...baseBody(), source, fix: undefined });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.issues.some((i) => i.path === "source" && i.message.includes("its own server path"))).toBe(true);
      }
    }
  });

  it("rejects an unrecognized source", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), source: "not_a_real_source" });
    expect(result.ok).toBe(false);
  });

  it("rejects courseId: null (must be OMITTED, never a literal null — security doc §2)", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), courseId: null });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((i) => i.path === "courseId")).toBe(true);
    }
  });

  it("accepts an omitted courseId (facility-level evidence, H3 residual rule)", () => {
    const body = baseBody();
    delete (body as Record<string, unknown>).courseId;
    const result = parseEvidenceSubmission(body);
    expect(result.ok).toBe(true);
  });

  it("rejects a fixId that is standard (padded) base64 rather than unpadded base64url", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), fix: goodFix({ fixId: "abc+def/==" }) });
    expect(result.ok).toBe(false);
  });

  it("rejects an unrecognized extra key (strict object)", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), extraField: "nope" });
    expect(result.ok).toBe(false);
  });

  it("rejects a non-real calendar date", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), localDate: "2026-02-31" });
    expect(result.ok).toBe(false);
  });

  it("rejects an implausible capturedAt (year 1900)", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), fix: goodFix({ capturedAt: Date.parse("1900-01-01") }) });
    expect(result.ok).toBe(false);
  });

  it("accepts a well-formed foreground_dwell submission", () => {
    const body = {
      source: "foreground_dwell",
      deviceId: "dev_1",
      facilityId: "fac_x",
      courseId: "crs_x1",
      localDate: "2026-06-01",
      catalogVersion: 1,
      checkinFix: goodFix({ fixId: "fix_in" }),
      checkoutFix: goodFix({ fixId: "fix_out" }),
      apartMinutes: 95,
      holes: 18,
    };
    const result = parseEvidenceSubmission(body);
    expect(result.ok).toBe(true);
  });

  it("rejects manifestSig with a non-base64url signature", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", signatureB64Url: "not+valid/" } });
    expect(result.ok).toBe(false);
  });

  it("accepts a self_report submission with no fix at all", () => {
    const body = baseBody({ source: "self_report" });
    delete (body as Record<string, unknown>).fix;
    const result = parseEvidenceSubmission(body);
    expect(result.ok).toBe(true);
  });
});
