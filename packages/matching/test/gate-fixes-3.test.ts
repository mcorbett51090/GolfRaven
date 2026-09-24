/**
 * Round 4 (should-fix items after the Opus gate passed on 21bceda):
 * document the Connect IQ sampling constraint with a concrete failing
 * fixture, and pin the `MIN_OBSERVED_COVERAGE` floor and the
 * `MAX_GAP_SECONDS` cap with an exact boundary pair. Fixture shapes
 * mirror /tmp/mprobe/probe4.mjs.
 */
import { describe, expect, it } from "vitest";
import { matchRoute, type CandidateCourse } from "../src/index.js";
import { fixesAlong, ORIGIN, offset } from "./helpers.js";

const HOUR = 3_600_000;
const MIN = 60_000;

const A: CandidateCourse = {
  id: "crs_A",
  facilityId: "fac_A",
  verificationTier: "play-verified",
  polygon: [
    offset(ORIGIN, -250, -250),
    offset(ORIGIN, 250, -250),
    offset(ORIGIN, 250, 250),
    offset(ORIGIN, -250, 250),
  ],
};

/** A slowly-winding loop that stays comfortably inside A's 500×500
 * polygon at every point, whatever `n` is sampled — the amplitude (180 m)
 * never approaches the polygon's 250 m half-width. Matches
 * `/tmp/mprobe/probe4.mjs`'s `loop(n)` shape, so geometry is never the
 * limiting factor in these tests — only `observedCoverage` is. */
function loopPoint(i: number, n: number) {
  const t = (i / n) * 2 * Math.PI * 3;
  return offset(ORIGIN, 180 * Math.cos(t), 180 * Math.sin(t * 1.3));
}

/** `n` fixes spaced exactly `intervalMinutes` apart, spanning as close to
 * `hours` as an integer number of intervals allows (probe4's own
 * construction: `floor(hours*60/intervalMinutes) + 1` fixes). */
function evenlySpacedFixes(intervalMinutes: number, hours: number) {
  const n = Math.floor((hours * 60) / intervalMinutes) + 1;
  return Array.from({ length: n }, (_, i) => ({
    point: loopPoint(i, n),
    timestamp: i * intervalMinutes * MIN,
  }));
}

describe("should-fix 1: Connect IQ sampling constraint (apps/ciq/README.md)", () => {
  it("an 8-fix Connect IQ trace over 3 hours (~25.7 min between fixes — far past the documented ≤10 min ceiling) is too sparse to match → typeahead", () => {
    const points = Array.from({ length: 8 }, (_, i) => loopPoint(i, 8));
    const outcome = matchRoute({
      fixes: fixesAlong(points, 0, 3 * HOUR),
      candidates: [A],
    });
    expect(outcome.kind).toBe("typeahead");
    expect(outcome.summary.observedCoverage).toBeLessThan(0.5);
  });
});

describe("should-fix 2 & 3: pin the coverage floor and the 300 s cap together", () => {
  it("G2: two inside fixes 4 h apart → typeahead (all but 5 of the 240 minutes is an uncapped gap)", () => {
    const fixes = [
      { point: ORIGIN, timestamp: 0 },
      { point: offset(ORIGIN, 5, 5), timestamp: 4 * HOUR },
    ];
    const outcome = matchRoute({ fixes, candidates: [A] });
    expect(outcome.kind).toBe("typeahead");
    expect(outcome.summary.observedCoverage).toBeLessThan(0.5);
  });

  it("sampling every 10 minutes over 4 h lands EXACTLY on the 0.5 coverage floor → matched (24 gaps × capped 300 s ÷ 14,400 s = 0.5)", () => {
    const fixes = evenlySpacedFixes(10, 4);
    const outcome = matchRoute({ fixes, candidates: [A] });
    // Pins three separate mutations at once (see the round's should-fix
    // items 2–3, verified against a mutation copy):
    //  - MIN_OBSERVED_COVERAGE lowered to 0/0.4 would not flip this case
    //    (0.5 already clears either), so this assertion alone doesn't
    //    catch that — the 11-minute case below does.
    //  - `>=` becoming `>` in route-match.ts's qualifiesCoverage check
    //    WOULD flip this exact case (0.5 > 0.5 is false), so this is the
    //    boundary that specifically pins `>=`.
    //  - MAX_GAP_SECONDS raised to 3000 would make every 600 s gap here
    //    uncapped (coverage → 1), which still matches — so this case
    //    alone doesn't pin the cap either; the 11-minute case does.
    expect(outcome.summary.observedCoverage).toBe(0.5);
    expect(outcome.kind).toBe("matched");
  });

  it("sampling every 11 minutes over 4 h falls just under the floor → typeahead (21 gaps × capped 300 s ÷ 13,860 s ≈ 0.4545)", () => {
    const fixes = evenlySpacedFixes(11, 4);
    const outcome = matchRoute({ fixes, candidates: [A] });
    // This is the case that pins MIN_OBSERVED_COVERAGE (fails if lowered
    // to 0 or 0.4 — 0.4545 would then qualify) AND MAX_GAP_SECONDS
    // (fails if raised to 3000 — every 660 s gap would go uncapped,
    // coverage → 1, and it would match).
    expect(outcome.summary.observedCoverage).toBeCloseTo(0.454545455, 8);
    expect(outcome.summary.observedCoverage).toBeLessThan(0.5);
    expect(outcome.kind).toBe("typeahead");
  });
});
