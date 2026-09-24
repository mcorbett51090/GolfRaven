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

describe("tzLikelyContainsCoordinates", () => {
  it("accepts a facility's real tz for its coordinates (Chicago)", () => {
    expect(
      tzLikelyContainsCoordinates("America/Chicago", { lat: 41.88, lng: -87.63 }),
    ).toBe(true);
  });

  it("accepts a facility's real tz for its coordinates (Nashville, America/Chicago)", () => {
    expect(
      tzLikelyContainsCoordinates("America/Chicago", { lat: 36.16, lng: -86.78 }),
    ).toBe(true);
  });

  it("rejects an unambiguously wrong zone (Illinois coordinates tagged Asia/Tokyo)", () => {
    expect(
      tzLikelyContainsCoordinates("Asia/Tokyo", { lat: 41.88, lng: -87.63 }),
    ).toBe(false);
  });
});
