import { describe, expect, it } from "vitest";
import {
  canonicalizeTimeZone,
  haversineDistanceMeters,
  tzLikelyContainsCoordinates,
} from "../src/geo.js";

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

  /**
   * Round 2 (gate review): the tzdb backward-links table + ~5 km border
   * tolerance. Each case here is one the round-1 exact-string comparison
   * could NOT pass, for a documented reason.
   */
  describe("round 2: tzdb link-table canonicalization", () => {
    it("Thunder Bay ON tagged America/Toronto (tz-lookup's 2019 data still says America/Thunder_Bay)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Toronto", { lat: 48.38, lng: -89.25 }),
      ).toBe(true);
    });
    it("Pangnirtung NU tagged America/Iqaluit (tz-lookup's 2019 data still says America/Pangnirtung)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Iqaluit", { lat: 66.15, lng: -65.7 }),
      ).toBe(true);
    });
    it("Indianapolis tagged with the LEGACY alias America/Indianapolis", () => {
      expect(
        tzLikelyContainsCoordinates("America/Indianapolis", { lat: 39.77, lng: -86.16 }),
      ).toBe(true);
    });
  });

  describe("round 2: ~5 km border tolerance", () => {
    it("Rainy River ON tagged America/Winnipeg (tz-lookup's simplified polygon reads the center point as America/Chicago)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Winnipeg", { lat: 48.72, lng: -94.57 }),
      ).toBe(true);
    });
  });

  describe("round 2: link table + border tolerance never widen a genuinely wrong zone", () => {
    it("Seattle tagged America/New_York still fails (not a link, not within 5 km)", () => {
      expect(
        tzLikelyContainsCoordinates("America/New_York", { lat: 47.6, lng: -122.3 }),
      ).toBe(false);
    });
    it("Knoxville tagged America/Chicago still fails", () => {
      expect(
        tzLikelyContainsCoordinates("America/Chicago", { lat: 35.96, lng: -83.92 }),
      ).toBe(false);
    });
    it("Phoenix tagged America/Denver still fails", () => {
      expect(
        tzLikelyContainsCoordinates("America/Denver", { lat: 33.45, lng: -112.07 }),
      ).toBe(false);
    });
    it("Kenora tagged America/Toronto still fails (Kenora is genuinely Winnipeg, not a Toronto-linked name)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Toronto", { lat: 49.77, lng: -94.49 }),
      ).toBe(false);
    });
    it("Indianapolis tagged America/Chicago still fails (Indianapolis links to Indiana/Indianapolis, not Chicago)", () => {
      expect(
        tzLikelyContainsCoordinates("America/Chicago", { lat: 39.77, lng: -86.16 }),
      ).toBe(false);
    });
  });
});

describe("canonicalizeTimeZone", () => {
  it("resolves a legacy alias to its canonical zone", () => {
    expect(canonicalizeTimeZone("America/Indianapolis")).toBe(
      "America/Indiana/Indianapolis",
    );
    expect(canonicalizeTimeZone("America/Thunder_Bay")).toBe("America/Toronto");
    expect(canonicalizeTimeZone("America/Pangnirtung")).toBe("America/Iqaluit");
    expect(canonicalizeTimeZone("US/Eastern")).toBe("America/New_York");
  });

  it("returns an already-canonical name unchanged", () => {
    expect(canonicalizeTimeZone("America/Chicago")).toBe("America/Chicago");
    expect(canonicalizeTimeZone("America/Toronto")).toBe("America/Toronto");
  });

  it("returns an unrecognised name unchanged (no throw)", () => {
    expect(canonicalizeTimeZone("Not/AZone")).toBe("Not/AZone");
  });
});
