import { describe, expect, it } from "vitest";
import { haversineDistanceMeters, tzLikelyContainsCoordinates } from "../src/geo.js";

describe("haversineDistanceMeters", () => {
  it("returns 0 for identical coordinates", () => {
    const p = { lat: 36.16, lng: -86.78 };
    expect(haversineDistanceMeters(p, p)).toBeCloseTo(0, 5);
  });

  it("returns a small distance for two nearby points (< 150 m)", () => {
    const a = { lat: 36.16, lng: -86.78 };
    // ~0.001 deg lat is about 111 m.
    const b = { lat: 36.161, lng: -86.78 };
    expect(haversineDistanceMeters(a, b)).toBeLessThan(150);
  });

  it("returns a large distance for two far-apart points", () => {
    const nashville = { lat: 36.16, lng: -86.78 };
    const tokyo = { lat: 35.68, lng: 139.65 };
    expect(haversineDistanceMeters(nashville, tokyo)).toBeGreaterThan(1_000_000);
  });
});

/**
 * Gate-review-mandated cases (post-e9b3ab0): the ±3 h longitude heuristic
 * this replaced could not discriminate any of these — see `geo.ts`'s
 * module doc for the `tz-lookup@6.1.25` pin this now uses instead.
 */
describe("tzLikelyContainsCoordinates", () => {
  describe("must FAIL (wrong zone)", () => {
    it("Seattle tagged America/New_York", () => {
      expect(
        tzLikelyContainsCoordinates("America/New_York", { lat: 47.6, lng: -122.3 }),
      ).toBe(false);
    });
    it("Knoxville TN tagged America/Chicago (true: America/New_York)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Chicago", { lat: 35.96, lng: -83.92 }),
      ).toBe(false);
    });
    it("Phoenix AZ tagged America/Denver (true: America/Phoenix)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Denver", { lat: 33.45, lng: -112.07 }),
      ).toBe(false);
    });
    it("Kenora ON tagged America/Toronto (true: America/Winnipeg)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Toronto", { lat: 49.77, lng: -94.49 }),
      ).toBe(false);
    });
    it("Indianapolis tagged America/Chicago (true: America/Indiana/Indianapolis)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Chicago", { lat: 39.77, lng: -86.16 }),
      ).toBe(false);
    });
  });

  describe("must PASS (correct zone, including tricky real cases)", () => {
    it("Phoenix AZ tagged America/Phoenix", () => {
      expect(
        tzLikelyContainsCoordinates("America/Phoenix", { lat: 33.45, lng: -112.07 }),
      ).toBe(true);
    });
    it("Indianapolis tagged America/Indiana/Indianapolis", () => {
      expect(
        tzLikelyContainsCoordinates("America/Indiana/Indianapolis", {
          lat: 39.77,
          lng: -86.16,
        }),
      ).toBe(true);
    });
    it("a Saskatchewan course tagged America/Regina", () => {
      expect(
        tzLikelyContainsCoordinates("America/Regina", { lat: 50.45, lng: -104.6 }),
      ).toBe(true);
    });
    it("Nashville TN tagged America/Chicago", () => {
      expect(
        tzLikelyContainsCoordinates("America/Chicago", { lat: 36.16, lng: -86.78 }),
      ).toBe(true);
    });
  });
});
