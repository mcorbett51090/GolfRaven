import { describe, expect, it } from "vitest";
import { simplifyToMaxPoints } from "../src/index.js";
import { ORIGIN, offset } from "./helpers.js";

describe("simplifyToMaxPoints", () => {
  it("leaves a short route untouched", () => {
    const points = [offset(ORIGIN, 0, 0), offset(ORIGIN, 10, 0), offset(ORIGIN, 20, 5)];
    expect(simplifyToMaxPoints(points, 500)).toEqual(points);
  });

  it("reduces a route above the cap to at most the cap, keeping start and end", () => {
    // A noisy zig-zag path along a straight corridor, well above 500 points
    // (build plan §7.4 step 1).
    const points = Array.from({ length: 2000 }, (_, i) => {
      const t = i / 1999;
      const jitter = Math.sin(i * 0.7) * 2; // small deterministic wobble, meters
      return offset(ORIGIN, t * 1000, jitter);
    });
    const simplified = simplifyToMaxPoints(points, 500);
    expect(simplified.length).toBeLessThanOrEqual(500);
    expect(simplified.length).toBeGreaterThan(1);
    expect(simplified[0]).toEqual(points[0]);
    expect(simplified[simplified.length - 1]).toEqual(points[points.length - 1]);
  });

  it("is deterministic: repeated calls on the same input produce identical output", () => {
    const points = Array.from({ length: 800 }, (_, i) => offset(ORIGIN, i, Math.cos(i * 0.3) * 5));
    const first = simplifyToMaxPoints(points, 300);
    const second = simplifyToMaxPoints(points, 300);
    expect(second).toEqual(first);
  });

  it("respects a smaller cap", () => {
    const points = Array.from({ length: 1000 }, (_, i) => offset(ORIGIN, i, Math.sin(i * 0.1) * 10));
    const simplified = simplifyToMaxPoints(points, 50);
    expect(simplified.length).toBeLessThanOrEqual(50);
  });

  it("collapses a degenerate (all-identical) route to its two endpoints", () => {
    const same = offset(ORIGIN, 0, 0);
    const points = Array.from({ length: 600 }, () => same);
    const simplified = simplifyToMaxPoints(points, 500);
    expect(simplified).toEqual([same, same]);
  });
});
