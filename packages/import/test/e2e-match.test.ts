import { describe, expect, it } from "vitest";
import { matchRoute } from "@golfraven/matching";
import type { CandidateCourse } from "@golfraven/matching";
import { parseGpxFile } from "../src/parse-gpx.js";
import { toMatcherInput } from "../src/to-matcher-input.js";

/** A synthetic ~1.5 km × 2.2 km course polygon, well within the matcher's
 * default 3 km candidate search radius of the round below. */
const CANDIDATES: CandidateCourse[] = [
  {
    id: "crs_pinehill",
    facilityId: "fac_pinehill",
    verificationTier: "play-verified",
    polygon: [
      { lat: 43.64, lon: -79.39 },
      { lat: 43.64, lon: -79.37 },
      { lat: 43.66, lon: -79.37 },
      { lat: 43.66, lon: -79.39 },
    ],
  },
];

function buildGpxRound(): string {
  const start = Date.parse("2026-06-01T14:00:00Z");
  const points = Array.from({ length: 20 }, (_, i) => {
    // A small loop entirely inside the polygon above, 9 minutes apart —
    // 20 points span ~2h51m, inside the 1.5–6h acceptance window.
    const lat = 43.649 + 0.0005 * Math.sin(i);
    const lon = -79.381 + 0.0005 * Math.cos(i);
    const time = new Date(start + i * 9 * 60_000).toISOString();
    return `<trkpt lat="${lat}" lon="${lon}"><time>${time}</time></trkpt>`;
  }).join("\n");

  return `<?xml version="1.0"?>
<gpx version="1.1" creator="Test Watch" xmlns="http://www.topografix.com/GPX/1/1">
  <trk><name>Pinehill Links Round</name><trkseg>
    ${points}
  </trkseg></trk>
</gpx>`;
}

describe("end to end: GPX import -> toMatcherInput -> matchRoute", () => {
  it("matches the synthetic round to the synthetic course", () => {
    const parsed = parseGpxFile(new TextEncoder().encode(buildGpxRound()));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.round.fixes.length).toBeGreaterThan(0);

    const matcherInput = toMatcherInput(parsed.round, {
      candidates: CANDIDATES,
    });
    expect(matcherInput).toBeDefined();
    if (!matcherInput) return;

    const outcome = matchRoute(matcherInput);
    expect(outcome.kind).toBe("matched");
    if (outcome.kind !== "matched") return;
    expect(outcome.course.courseId).toBe("crs_pinehill");
    expect(outcome.course.geometryKind).toBe("polygon");
  });
});
