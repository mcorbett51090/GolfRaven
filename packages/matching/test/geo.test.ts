import { describe, expect, it } from "vitest";
import { computeInsideRatio, haversineMeters, isInsidePolygonWithBuffer } from "../src/index.js";

// These assertions are placed at the equator (lat = 0) deliberately: there,
// the package's local equirectangular projection has zero cos(lat)
// distortion, so a plain degree offset and the true geodesic distance
// agree almost exactly. That makes these checks independent of
// test/helpers.ts's own offset technique (used elsewhere for fixtures).

describe("haversineMeters", () => {
  it("matches the well-known ~111.32 km length of one degree at the equator", () => {
    const a = { lat: 0, lon: 0 };
    const b = { lat: 0, lon: 1 };
    expect(haversineMeters(a, b)).toBeGreaterThan(111_000);
    expect(haversineMeters(a, b)).toBeLessThan(111_700);
  });

  it("matches the well-known ~111.19 km length of one degree of latitude at the equator", () => {
    const a = { lat: 0, lon: 0 };
    const b = { lat: 1, lon: 0 };
    expect(haversineMeters(a, b)).toBeGreaterThan(110_500);
    expect(haversineMeters(a, b)).toBeLessThan(111_700);
  });

  it("is zero for a point against itself", () => {
    const p = { lat: 35.9, lon: -84.3 };
    expect(haversineMeters(p, p)).toBe(0);
  });
});

describe("isInsidePolygonWithBuffer", () => {
  // A ~222 m square centered on the equator/prime-meridian origin, built
  // directly from degree offsets (0.001 deg ≈ 111.3 m at the equator).
  const square = [
    { lat: -0.001, lon: -0.001 },
    { lat: -0.001, lon: 0.001 },
    { lat: 0.001, lon: 0.001 },
    { lat: 0.001, lon: -0.001 },
  ];

  it("is true for the center", () => {
    expect(isInsidePolygonWithBuffer({ lat: 0, lon: 0 }, square, 0)).toBe(true);
  });

  it("is true for a vertex", () => {
    expect(isInsidePolygonWithBuffer(square[0]!, square, 0)).toBe(true);
  });

  it("is false ~ 200 m outside with no buffer, true with a generous buffer", () => {
    const farOutside = { lat: 0, lon: 0.003 }; // ~333 m east of center, ~222 m past the edge
    expect(isInsidePolygonWithBuffer(farOutside, square, 0)).toBe(false);
    expect(isInsidePolygonWithBuffer(farOutside, square, 300)).toBe(true);
  });

  it("treats an unbuffered near-boundary outside point as outside, and a 30 m buffer as inside", () => {
    // The square's east edge sits at lon = 0.001 (~111.3 m from center).
    // Put a point ~20 m further east.
    const justOutside = { lat: 0, lon: 0.001 + 0.00018 }; // ~20 m past the edge
    expect(isInsidePolygonWithBuffer(justOutside, square, 0)).toBe(false);
    expect(isInsidePolygonWithBuffer(justOutside, square, 30)).toBe(true);
  });
});

describe("computeInsideRatio", () => {
  const square = [
    { lat: -0.001, lon: -0.001 },
    { lat: -0.001, lon: 0.001 },
    { lat: 0.001, lon: 0.001 },
    { lat: 0.001, lon: -0.001 },
  ];

  it("is 0 for an empty point list", () => {
    expect(computeInsideRatio([], square, 30)).toBe(0);
  });

  it("is the fraction of points inside", () => {
    const points = [
      { lat: 0, lon: 0 }, // inside
      { lat: 0, lon: 0 }, // inside
      { lat: 0, lon: 0.003 }, // outside, well past any buffer
    ];
    expect(computeInsideRatio(points, square, 0)).toBeCloseTo(2 / 3, 5);
  });
});
