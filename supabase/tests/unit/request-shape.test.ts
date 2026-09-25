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
//
// ⛔ FIX (P3c gate round 2, item 7): `deviceId` bodies below now use a real
// UUID — request-shape.ts's own fix ("validate deviceId as a UUID; a
// non-UUID currently returns 500") means a non-UUID literal like "dev_1"
// is no longer a valid fixture value for a WELL-FORMED submission.
// ⛔ FIX (item 6): `holes` is no longer a client-submitted
// `foreground_dwell` field at all — see this file's own new test for the
// positive assertion that submitting it is now a rejected extra key.
import { describe, expect, it } from "vitest";
import { parseEvidenceSubmission, REJECTED_SOURCES } from "../../functions/_shared/evidence/request-shape.js";

const DEVICE_ID = "11111111-1111-4111-8111-111111111111";

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
    deviceId: DEVICE_ID,
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

  // ⛔ FIX (P3c gate round 2, item 6): "reject connect_iq, health_route and
  // file_import the way REJECTED_SOURCES does" — asserted by name, not
  // merely by membership in the set this test iterates above, so a future
  // accidental removal from REJECTED_SOURCES fails this test directly.
  it("connect_iq, health_route and file_import are specifically among REJECTED_SOURCES", () => {
    expect(REJECTED_SOURCES.has("connect_iq")).toBe(true);
    expect(REJECTED_SOURCES.has("health_route")).toBe(true);
    expect(REJECTED_SOURCES.has("file_import")).toBe(true);
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

  // ⛔ FIX (P3c gate round 2, item 7): "validate deviceId as a UUID; a
  // non-UUID currently returns 500." — the positive assertion that a
  // non-UUID deviceId is now a clean 400-shaped parse failure, never
  // reaching a driver call at all.
  it("rejects a non-UUID deviceId", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), deviceId: "dev_1" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((i) => i.path === "deviceId")).toBe(true);
    }
  });

  it("accepts a well-formed foreground_dwell submission", () => {
    const body = {
      source: "foreground_dwell",
      deviceId: DEVICE_ID,
      facilityId: "fac_x",
      courseId: "crs_x1",
      localDate: "2026-06-01",
      catalogVersion: 1,
      checkinFix: goodFix({ fixId: "fix_in" }),
      checkoutFix: goodFix({ fixId: "fix_out" }),
      apartMinutes: 95,
    };
    const result = parseEvidenceSubmission(body);
    expect(result.ok).toBe(true);
  });

  // ⛔ FIX (P3c gate round 2, item 6): `holes` is no longer client
  // -submittable at all — a client that still sends it now hits the
  // strict-object "unrecognized key" rejection, the same as any other
  // removed/forged field.
  it("rejects a foreground_dwell submission that still sends a client `holes` claim", () => {
    const body = {
      source: "foreground_dwell",
      deviceId: DEVICE_ID,
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
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((i) => i.path === "holes")).toBe(true);
    }
  });

  it("rejects manifestSig with a non-base64url signature", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", signatureB64Url: "not+valid/", manifestSha256: "0".repeat(64) } });
    expect(result.ok).toBe(false);
  });

  // should-fix (P3c gate round 2): "sign a domain-tagged payload that
  // binds the version and the manifest sha256" — manifestSha256 is now a
  // required field of manifestSig itself.
  it("rejects manifestSig missing manifestSha256", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", signatureB64Url: "AAAA" } });
    expect(result.ok).toBe(false);
  });

  it("rejects manifestSig with a non-hex/wrong-length manifestSha256", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", signatureB64Url: "AAAA", manifestSha256: "not-hex" } });
    expect(result.ok).toBe(false);
  });

  it("accepts a well-formed manifestSig", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", signatureB64Url: "AAAA", manifestSha256: "0".repeat(64) } });
    expect(result.ok).toBe(true);
  });

  it("accepts a self_report submission with no fix at all", () => {
    const body = baseBody({ source: "self_report" });
    delete (body as Record<string, unknown>).fix;
    const result = parseEvidenceSubmission(body);
    expect(result.ok).toBe(true);
  });
});
