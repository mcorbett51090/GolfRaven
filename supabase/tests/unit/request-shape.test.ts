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
// P3e round 2 gate, H1: the site version string (yyyymmdd-gitsha7),
// not the old internal int — every fixture below submits this same
// well-formed shape.
const SITE_VERSION = "20260601-abc1234";

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
    catalogVersion: SITE_VERSION,
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

  // P5 §46: receipt_green_fee is written only by receipt intake — never via POST /v1/evidence.
  it("receipt_green_fee stays in REJECTED_SOURCES (own path is POST /v1/receipts)", () => {
    expect(REJECTED_SOURCES.has("receipt_green_fee")).toBe(true);
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
      catalogVersion: SITE_VERSION,
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
      catalogVersion: SITE_VERSION,
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

  // ⛔ FIX (P3e round 2 gate, H1): manifestSig is now the REAL P1
  // manifest.sig.json shape verbatim — {kid, contractVersion, sig,
  // manifestSha} — not the old {kid, signatureB64Url, manifestSha256}.
  // `signature` is STANDARD (padded) base64 (B1: the real P1 signer's
  // own encoding), never base64url — see request-shape.ts's own
  // `BASE64_STD_RE` note.
  it("rejects manifestSig with a non-base64 signature", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", contractVersion: 1, sig: "not+valid/-not-base64", manifestSha: "0".repeat(64) } });
    expect(result.ok).toBe(false);
  });

  // should-fix (P3c gate round 2): "sign a domain-tagged payload that
  // binds the version and the manifest sha256" — manifestSha is now a
  // required field of manifestSig itself.
  it("rejects manifestSig missing manifestSha", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", contractVersion: 1, sig: "AAAA" } });
    expect(result.ok).toBe(false);
  });

  it("rejects manifestSig with a non-hex/wrong-length manifestSha", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", contractVersion: 1, sig: "AAAA", manifestSha: "not-hex" } });
    expect(result.ok).toBe(false);
  });

  it("rejects manifestSig with a non-integer contractVersion", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", contractVersion: 1.5, sig: "AAAA", manifestSha: "0".repeat(64) } });
    expect(result.ok).toBe(false);
  });

  it("accepts a well-formed manifestSig", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { kid: "k1", contractVersion: 1, sig: "AAAA", manifestSha: "0".repeat(64) } });
    expect(result.ok).toBe(true);
  });

  // Round 2 gate LOW: P1's own signature-file names, an allow-list, and the
  // parsed value rebuilt from exactly the known fields.
  const SIG = { kid: "k1", contractVersion: 1, sig: "AAAA", manifestSha: "0".repeat(64) };
  it("rejects manifestSig carrying the OLD `signature` field name (the wire name is P1's own `sig`)", () => {
    const { sig, ...rest } = SIG;
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { ...rest, signature: sig } });
    expect(result.ok).toBe(false);
  });
  it("rejects manifestSig with any unknown key", () => {
    const result = parseEvidenceSubmission({ ...baseBody(), manifestSig: { ...SIG, extra: "x" } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues.some((i) => i.path === "manifestSig.extra")).toBe(true);
  });
  it("accepts the P1 file's own optional catalogVersion only when it equals the submission's, and the parsed value carries exactly the four known fields", () => {
    const body = baseBody();
    const same = parseEvidenceSubmission({ ...body, manifestSig: { ...SIG, catalogVersion: body.catalogVersion } });
    expect(same.ok).toBe(true);
    if (same.ok) expect(same.value.manifestSig).toEqual(SIG);
    const other = parseEvidenceSubmission({ ...body, manifestSig: { ...SIG, catalogVersion: "20200101-0000000" } });
    expect(other.ok).toBe(false);
  });

  it("accepts a self_report submission with no fix at all", () => {
    const body = baseBody({ source: "self_report" });
    delete (body as Record<string, unknown>).fix;
    const result = parseEvidenceSubmission(body);
    expect(result.ok).toBe(true);
  });
});
