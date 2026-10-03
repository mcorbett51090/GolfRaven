/**
 * P4.2c: matching a foreground check-in to a course (`src/checkin/match.ts`, over `@golfraven/matching`'s `matchCheckIn`): the §4.2 radius fallback by site size, a polygon when
 * the device has one, the §4.3 shared-geometry user pick, the "did you mean" search and the facility-local date.
 */
import { describe, expect, it } from "vitest";
import { candidateFor, distanceToFacility, localDateInTz, matchCourse, nearbyCourses, pickGuard, radiusMetersFor, type DeviceFix } from "../src/checkin";
import { NASHVILLE, NOW0, entryOf, facility, indexOf } from "./support/checkin-rig";
import { VECTORS } from "./support/edge-fixtures";

const north = (m: number): number => NASHVILLE.lat + m / 111_195;
const fixAt = (over: Partial<DeviceFix> = {}): DeviceFix => ({ lat: NASHVILLE.lat, lng: NASHVILLE.lng, accuracyMeters: 10, capturedAt: NOW0, simulated: false, ...over });

describe("the §4.2 radius-fallback circle: 9 holes 250 m, 18 holes 400 m, larger sites 550 m (by the SITE's holes)", () => {
  it.each([
    [[{ id: "crs_a", holes: 9 }], 250],
    [[{ id: "crs_a", holes: 18 }], 400],
    [[{ id: "crs_a" }], 400], // holes unknown: 18
    [[{ id: "crs_a", holes: 9 }, { id: "crs_b", holes: 9 }], 400],
    [[{ id: "crs_a", holes: 18 }, { id: "crs_b", holes: 9 }], 550],
    [[{ id: "crs_a", holes: 18 }, { id: "crs_b", holes: 18 }, { id: "crs_c", holes: 18 }], 550],
  ])("%j -> %i m", (courses, radius) => {
    expect(radiusMetersFor(entryOf(facility({ courses })))).toBe(radius);
    expect(candidateFor(entryOf(facility({ courses })))?.radiusFallback).toEqual({ center: { lat: NASHVILLE.lat, lon: NASHVILLE.lng }, radiusMeters: radius });
  });

  it("the circle plus the matcher's 50 m buffer is the edge: a 9-hole site matches at 295 m and not at 305 m", () => {
    const e = entryOf(facility({ courses: [{ id: "crs_a", holes: 9 }] }));
    expect(matchCourse(e, fixAt({ lat: north(295) })).kind).toBe("matched");
    expect(matchCourse(e, fixAt({ lat: north(305) }))).toMatchObject({ kind: "rejected", reason: "outside_polygon" });
  });
});

describe("candidateFor: only a facility the circle is defined for has geometry on the device", () => {
  it("listed-verified and play-verified with an exact coordinate: a candidate, with the tier and the shared-geometry flag", () => {
    expect(candidateFor(entryOf(facility({ status: "listed-verified" })))).toMatchObject({ id: "crs_x1", facilityId: "fac_x", verificationTier: "listed-verified", sharedGeometry: false });
    expect(candidateFor(entryOf(facility({ status: "play-verified", courses: [{ id: "crs_a" }, { id: "crs_b" }] }), 1))).toMatchObject({ id: "crs_b", verificationTier: "play-verified", sharedGeometry: true });
  });

  it("unverified, approximate or coordinate-less: NO candidate (a check-in there is refused, not matched against a guess)", () => {
    expect(candidateFor(entryOf(facility({ status: "unverified" })))).toBeNull();
    expect(candidateFor(entryOf(facility({ approx: true })))).toBeNull();
    expect(candidateFor(entryOf(facility({ lat: null, lng: null })))).toBeNull();
    expect(matchCourse(entryOf(facility({ status: "unverified" })), fixAt())).toMatchObject({ kind: "rejected", reason: "no_geometry" });
  });

  it("a POLYGON, when the device has one, is matched with `geometryKind: polygon` (the seam for a future polygon shard; the app passes none today)", () => {
    const e = entryOf(facility({ status: "unverified" })); // no circle for it, but a polygon is geometry
    const d = 0.001; // ~111 m
    const polygon = [
      { lat: NASHVILLE.lat - d, lon: NASHVILLE.lng - d },
      { lat: NASHVILLE.lat - d, lon: NASHVILLE.lng + d },
      { lat: NASHVILLE.lat + d, lon: NASHVILLE.lng + d },
      { lat: NASHVILLE.lat + d, lon: NASHVILLE.lng - d },
    ];
    expect(matchCourse(e, fixAt(), { polygon })).toEqual({ kind: "matched", geometryKind: "polygon", sharedGeometry: false });
    expect(matchCourse(e, fixAt({ lat: NASHVILLE.lat + d + 0.0003 }), { polygon }).kind).toBe("matched"); // ~33 m outside: inside the 50 m buffer
    expect(matchCourse(e, fixAt({ lat: NASHVILLE.lat + d + 0.001 }), { polygon })).toMatchObject({ kind: "rejected", reason: "outside_polygon" }); // ~111 m outside
  });
});

describe("matchCourse: the matcher's own rules are applied, not re-implemented", () => {
  const e = entryOf(facility());
  it("simulated, inaccurate (> 50 m) and malformed fixes are rejected with the matcher's reason", () => {
    expect(matchCourse(e, fixAt({ simulated: true }))).toMatchObject({ kind: "rejected", reason: "simulated" });
    expect(matchCourse(e, fixAt({ accuracyMeters: 51 }))).toMatchObject({ kind: "rejected", reason: "inaccurate" });
    expect(matchCourse(e, fixAt({ accuracyMeters: 50 })).kind).toBe("matched");
    expect(matchCourse(e, fixAt({ lat: Number.NaN }))).toMatchObject({ kind: "rejected", reason: "invalid_fix" });
  });

  it("a match says whether the geometry is shared (the user-pick case) and which kind it was", () => {
    expect(matchCourse(e, fixAt())).toEqual({ kind: "matched", geometryKind: "radius", sharedGeometry: false });
    expect(matchCourse(entryOf(facility({ courses: [{ id: "crs_a" }, { id: "crs_b" }] }), 1), fixAt())).toEqual({ kind: "matched", geometryKind: "radius", sharedGeometry: true });
  });

  it("distance to the facility is reported for the 'not here' message (null with no coordinate)", () => {
    expect(distanceToFacility(e, fixAt({ lat: north(1000) }))).toBeGreaterThan(995);
    expect(distanceToFacility(e, fixAt({ lat: north(1000) }))).toBeLessThan(1005);
    expect(distanceToFacility(entryOf(facility({ lat: null, lng: null })), fixAt())).toBeNull();
  });
});

describe("nearbyCourses: 'did you mean' for a player on the wrong course page", () => {
  const a = facility({ id: "fac_a", lat: NASHVILLE.lat, lng: NASHVILLE.lng });
  const b = facility({ id: "fac_b", lat: north(100), lng: NASHVILLE.lng, courses: [{ id: "crs_b1", holes: 18 }, { id: "crs_b2", holes: 18 }] });
  const c = facility({ id: "fac_c", lat: north(150), lng: NASHVILLE.lng });
  const far = facility({ id: "fac_far", lat: north(50_000), lng: NASHVILLE.lng });
  const unverified = facility({ id: "fac_u", lat: north(10), lng: NASHVILLE.lng, status: "unverified" });
  const idx = indexOf(a, b, c, far, unverified);

  it("lists the OTHER facilities whose circle contains the fix, nearest first, one course each, never the one being viewed, an unverified one or a far one", () => {
    const got = nearbyCourses(idx, fixAt({ lat: north(120) }), "fac_a");
    expect(got.map((n) => n.facilityId)).toEqual(["fac_b", "fac_c"]); // 20 m and 30 m away
    expect(got.map((n) => n.courseId)).toEqual(["crs_b1", "crs_x1"]); // the FIRST course of each facility (the player picks within a site on its page)
    expect(got.map((n) => n.distanceMeters)).toEqual([20, 30]);
    expect(nearbyCourses(idx, fixAt({ lat: north(120) }), "fac_b").map((n) => n.facilityId)).toEqual(["fac_c", "fac_a"]); // 30 m, then 120 m
  });

  it("is bounded by `max`", () => {
    expect(nearbyCourses(idx, fixAt({ lat: north(120) }), "fac_a", 1)).toHaveLength(1);
  });
});

describe("pickGuard (§4.3): one pick per facility per date, only where there is a pick to make", () => {
  const two = facility({ id: "fac_m", courses: [{ id: "crs_m1" }, { id: "crs_m2" }] });
  const picks = [{ facilityId: "fac_m", localDate: "2026-06-01", courseId: "crs_m1" }];
  it("refuses a different course on the same facility and date, naming the one already picked", () => {
    expect(pickGuard(picks, entryOf(two, 1), "2026-06-01")).toEqual({ ok: false, courseId: "crs_m1" });
  });
  it.each([
    ["the same course again", entryOf(two, 0), "2026-06-01"],
    ["another date", entryOf(two, 1), "2026-06-02"],
    ["another facility", entryOf(facility({ id: "fac_n", courses: [{ id: "crs_n1" }, { id: "crs_n2" }] }), 1), "2026-06-01"],
    ["a single-course facility", entryOf(facility({ id: "fac_m" })), "2026-06-01"],
  ])("allows %s", (_n, entry, date) => {
    expect(pickGuard(picks, entry, date)).toEqual({ ok: true });
  });
});

describe("localDateInTz: the facility-local date, compared with the SERVER's own function for the recorded instants", () => {
  it("agrees with the server on every recorded sample (DST edges, half-hour zones, both sides of local midnight)", () => {
    expect(VECTORS.localDate.samples.length).toBeGreaterThanOrEqual(20);
    for (const s of VECTORS.localDate.samples) expect(localDateInTz(s.epochMs, s.tz), `${s.tz} ${new Date(s.epochMs).toISOString()}`).toBe(s.localDate);
  });

  it("the recorded samples really straddle midnight (the vector is not vacuous): consecutive pairs differ by a day", () => {
    const s = VECTORS.localDate.samples;
    let differing = 0;
    for (let i = 0; i + 1 < s.length; i += 2) if (s[i]!.localDate !== s[i + 1]!.localDate) differing += 1;
    expect(differing).toBe(8); // the 2 DST pairs (01:59:59 -> 03:00:00, and the autumn repeat) stay on the same local date
  });

  it("refuses what it cannot compute: an unknown zone, an empty zone, a non-finite instant", () => {
    expect(localDateInTz(NOW0, "Not/AZone")).toBeNull();
    expect(localDateInTz(NOW0, "")).toBeNull();
    expect(localDateInTz(Number.NaN, "America/Chicago")).toBeNull();
  });
});
