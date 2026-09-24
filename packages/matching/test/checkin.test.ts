import { describe, expect, it } from "vitest";
import { matchCheckIn, type CandidateCourse } from "../src/index.js";
import { ORIGIN, offset, rectangle } from "./helpers.js";

const polygonCourse: CandidateCourse = {
  id: "crs_checkin_polygon",
  facilityId: "fac_checkin",
  verificationTier: "play-verified",
  polygon: rectangle(ORIGIN, 400, 300),
};

const radiusCourse: CandidateCourse = {
  id: "crs_checkin_radius",
  facilityId: "fac_checkin_radius",
  verificationTier: "listed-verified",
  radiusFallback: { center: ORIGIN, radiusMeters: 400 },
};

describe("matchCheckIn (build plan §7.4 step 5)", () => {
  it("accepts a clean fix inside the polygon", () => {
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 10, simulated: false, timestamp: 1000 },
      polygonCourse,
    );
    expect(result).toMatchObject({
      accepted: true,
      courseId: "crs_checkin_polygon",
      facilityId: "fac_checkin",
      geometryKind: "polygon",
    });
  });

  it("passes an opaque attestation assertion through untouched", () => {
    const result = matchCheckIn(
      {
        point: ORIGIN,
        accuracyMeters: 10,
        simulated: false,
        timestamp: 1000,
        attestationAssertion: "opaque-base64-assertion",
      },
      polygonCourse,
    );
    expect(result.accepted).toBe(true);
    if (result.accepted) {
      expect(result.attestationAssertion).toBe("opaque-base64-assertion");
    }
  });

  it("rejects a simulated fix even when otherwise inside and accurate", () => {
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 5, simulated: true, timestamp: 1000 },
      polygonCourse,
    );
    expect(result).toEqual({ accepted: false, reason: "simulated" });
  });

  it("rejects a fix with accuracy worse than 50 m", () => {
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 51, simulated: false, timestamp: 1000 },
      polygonCourse,
    );
    expect(result).toEqual({ accepted: false, reason: "inaccurate" });
  });

  it("accepts a fix at exactly 50 m accuracy (boundary is inclusive)", () => {
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 50, simulated: false, timestamp: 1000 },
      polygonCourse,
    );
    expect(result.accepted).toBe(true);
  });

  it("rejects a fix well outside the polygon + 50 m buffer", () => {
    const farAway = offset(ORIGIN, 1000, 0);
    const result = matchCheckIn(
      { point: farAway, accuracyMeters: 5, simulated: false, timestamp: 1000 },
      polygonCourse,
    );
    expect(result).toEqual({ accepted: false, reason: "outside_polygon" });
  });

  it("accepts a fix within the polygon's 50 m buffer even if just outside the ring", () => {
    // The rectangle spans ±200 m east-west from ORIGIN; put the fix 30 m past that edge.
    const justOutside = offset(ORIGIN, 230, 0);
    const result = matchCheckIn(
      { point: justOutside, accuracyMeters: 5, simulated: false, timestamp: 1000 },
      polygonCourse,
    );
    expect(result.accepted).toBe(true);
  });

  it("works against a radius-fallback circle too", () => {
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 10, simulated: false, timestamp: 1000 },
      radiusCourse,
    );
    expect(result).toMatchObject({ accepted: true, geometryKind: "radius", courseId: "crs_checkin_radius" });
  });

  it("reports no_geometry for a candidate with neither a polygon nor a radius circle", () => {
    const bare: CandidateCourse = {
      id: "crs_bare",
      facilityId: "fac_bare",
      verificationTier: "unverified",
    };
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 10, simulated: false, timestamp: 1000 },
      bare,
    );
    expect(result).toEqual({ accepted: false, reason: "no_geometry" });
  });
});
