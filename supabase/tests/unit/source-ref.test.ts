// supabase/tests/unit/source-ref.test.ts
import { describe, expect, it } from "vitest";
import { deriveSourceRef } from "../../functions/_shared/evidence/source-ref.js";
import type { EvidenceSubmission } from "../../functions/_shared/evidence/request-shape.js";

function checkinSubmission(fixId: string): EvidenceSubmission {
  return {
    source: "foreground_checkin",
    deviceId: "dev_1",
    facilityId: "fac_x",
    courseId: "crs_x1",
    localDate: "2026-06-01",
    catalogVersion: 1,
    fix: {
      fixId,
      lat: 1,
      lng: 2,
      accuracyMeters: 5,
      capturedAt: 1000,
      simulated: false,
      foreground: true,
      fromApp: true,
    },
  } as EvidenceSubmission;
}

describe("deriveSourceRef", () => {
  it("uses the fix's own fixId as a natural ref for foreground_checkin", async () => {
    const ref = await deriveSourceRef(checkinSubmission("fix_abc"));
    expect(ref).toBe("fix:fix_abc");
  });

  it("is deterministic: the SAME submission always derives the SAME ref (AT 3 replay convergence)", async () => {
    const a = await deriveSourceRef(checkinSubmission("fix_xyz"));
    const b = await deriveSourceRef(checkinSubmission("fix_xyz"));
    expect(a).toBe(b);
  });

  it("falls back to a content hash for a source with no natural ref (self_report)", async () => {
    const submission = {
      source: "self_report",
      deviceId: "dev_1",
      facilityId: "fac_x",
      localDate: "2026-06-01",
      catalogVersion: 1,
    } as EvidenceSubmission;
    const ref = await deriveSourceRef(submission);
    expect(ref).toMatch(/^hash:[0-9a-f]{64}$/);
  });

  it("the content-hash fallback is independent of key order (canonicalized JSON)", async () => {
    const digestCalls: Uint8Array[] = [];
    const digestHex = async (_alg: "SHA-256", data: Uint8Array) => {
      digestCalls.push(data);
      return new ArrayBuffer(32);
    };
    const a = { source: "self_report", deviceId: "d", facilityId: "f", localDate: "2026-06-01", catalogVersion: 1 } as EvidenceSubmission;
    const b = { catalogVersion: 1, localDate: "2026-06-01", facilityId: "f", deviceId: "d", source: "self_report" } as EvidenceSubmission;
    await deriveSourceRef(a, digestHex);
    await deriveSourceRef(b, digestHex);
    const textA = new TextDecoder().decode(digestCalls[0]);
    const textB = new TextDecoder().decode(digestCalls[1]);
    expect(textA).toBe(textB);
  });

  it("a different self_report payload (different localDate) hashes differently", async () => {
    const a = await deriveSourceRef({ source: "self_report", deviceId: "d", facilityId: "f", localDate: "2026-06-01", catalogVersion: 1 } as EvidenceSubmission);
    const b = await deriveSourceRef({ source: "self_report", deviceId: "d", facilityId: "f", localDate: "2026-06-02", catalogVersion: 1 } as EvidenceSubmission);
    expect(a).not.toBe(b);
  });
});
