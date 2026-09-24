import { describe, expect, it } from "vitest";
import type { CandidateCourse } from "@golfraven/matching";
import { toMatcherInput } from "../src/to-matcher-input.js";
import type { ImportedRound } from "../src/types.js";

const CANDIDATES: CandidateCourse[] = [
  {
    id: "crs_1",
    facilityId: "fac_1",
    verificationTier: "play-verified",
    polygon: [
      { lat: 43.64, lon: -79.39 },
      { lat: 43.64, lon: -79.37 },
      { lat: 43.66, lon: -79.37 },
      { lat: 43.66, lon: -79.39 },
    ],
  },
];

function routeWithFixes(): ImportedRound {
  return {
    source: "file_import",
    format: "gpx",
    warnings: [],
    fixes: [
      { lat: 43.65, lon: -79.38, timestamp: 1_000 },
      { lat: 43.651, lon: -79.379, timestamp: 2_000, accuracyMeters: 8 },
    ],
  };
}

describe("toMatcherInput", () => {
  it("returns undefined for a routeless round", () => {
    const round: ImportedRound = { source: "file_import", format: "csv", fixes: [], warnings: [] };
    expect(toMatcherInput(round, { candidates: CANDIDATES })).toBeUndefined();
  });

  it("maps fixes into the matcher's RouteFix shape, never asserting simulated", () => {
    const input = toMatcherInput(routeWithFixes(), { candidates: CANDIDATES });
    expect(input).toBeDefined();
    expect(input!.fixes).toEqual([
      { point: { lat: 43.65, lon: -79.38 }, timestamp: 1_000 },
      { point: { lat: 43.651, lon: -79.379 }, timestamp: 2_000, accuracyMeters: 8 },
    ]);
    expect(input!.fixes.every((f) => !("simulated" in f))).toBe(true);
    expect(input!.candidates).toBe(CANDIDATES);
  });

  it("passes through optional matcher tuning parameters", () => {
    const input = toMatcherInput(routeWithFixes(), {
      candidates: CANDIDATES,
      catalogVersion: "v42",
      tieThreshold: 0.2,
      acceptInsideRatio: 0.7,
    });
    expect(input?.catalogVersion).toBe("v42");
    expect(input?.tieThreshold).toBe(0.2);
    expect(input?.acceptInsideRatio).toBe(0.7);
  });
});
