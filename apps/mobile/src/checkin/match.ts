/**
 * Course matching for a foreground check-in (build plan §7.4 step 5, §4.2 radius fallback, §4.3 user pick), over `@golfraven/matching`'s `matchCheckIn`.
 *
 * WHAT THE DEVICE HAS. The signed catalog the app caches carries each facility's coordinate (`lat`, `lng`, `approx`) and each course's `geometry` REFERENCE (a file name), but no polygon
 * shard reaches the device today, so the only geometry a check-in can be matched against here is the §4.2 radius-fallback circle (9 holes 250 m, 18 holes 400 m, larger sites 550 m
 * `[inference; tuned by the P4 field test]`), and only for a facility the circle is defined for: `listed-verified` or better, with a non-approximate coordinate. A facility
 * without that has NO geometry on the device and a check-in there is refused (`no_geometry`); the server may still know a polygon, but the app cannot check against one it does not
 * have. `polygons` is the seam for the day a polygon shard exists (`candidateFor(entry, { polygon })`): it is exercised by tests, not passed by the app.
 *
 * THE USER PICK (§4.3). Every course at a multi-course site shares the facility's circle, so the geometry cannot say which course was played: the player picks (the course page they
 * are on, or a sibling in the card's course chips), and one pick is allowed per facility per date (`pickGuard`). The server derives `course_disambiguated_by` itself; nothing about
 * the pick is sent.
 *
 * The 50 m accuracy cap, the 50 m buffer and the "simulated is refused" rule are `matchCheckIn`'s own, not re-implemented here.
 */
import { haversineMeters, matchCheckIn, type CandidateCourse, type CheckInResult, type PolygonInput, type VerificationTier } from "@golfraven/matching";
import type { CatalogIndex, CourseEntry } from "../browse";

/** A validated fix, in the matcher's vocabulary plus what the evidence needs. */
export interface DeviceFix {
  lat: number;
  lng: number;
  accuracyMeters: number;
  /** Epoch ms: the fix's own time. */
  capturedAt: number;
  simulated: boolean;
}

/** §4.2: the synthetic circle's radius by the SITE's size (`[inference]`): every course at a site shares it. */
export function radiusMetersFor(entry: CourseEntry): number {
  const holes = entry.facility.courses.reduce((n, c) => n + (c.holes ?? 18), 0);
  if (holes <= 9) return 250;
  if (holes <= 18) return 400;
  return 550;
}

export interface CandidateOptions {
  /** A polygon for this course, when the device has one (no shard ships one yet). */
  polygon?: PolygonInput;
}

/** The matcher's candidate for a course, or `null` when the device has no geometry for it. */
export function candidateFor(entry: CourseEntry, opts: CandidateOptions = {}): CandidateCourse | null {
  const f = entry.facility;
  const tier: VerificationTier = f.verification.status;
  const sharedGeometry = f.courses.length > 1;
  const base = { id: entry.course.id, facilityId: f.id, verificationTier: tier, sharedGeometry, ...(entry.course.holes !== undefined ? { holes: entry.course.holes } : {}) };
  if (opts.polygon !== undefined) return { ...base, polygon: opts.polygon };
  if (tier === "unverified" || f.approx === true || f.lat === undefined || f.lng === undefined) return null;
  return { ...base, radiusFallback: { center: { lat: f.lat, lon: f.lng }, radiusMeters: radiusMetersFor(entry) } };
}

export type CourseMatch =
  | { kind: "matched"; geometryKind: "polygon" | "radius"; sharedGeometry: boolean }
  | { kind: "rejected"; reason: Extract<CheckInResult, { accepted: false }>["reason"]; distanceMeters: number | null };

/** Metres from the fix to the facility's coordinate, or `null` when it has none. */
export function distanceToFacility(entry: CourseEntry, fix: Pick<DeviceFix, "lat" | "lng">): number | null {
  const f = entry.facility;
  return f.lat === undefined || f.lng === undefined ? null : Math.round(haversineMeters({ lat: fix.lat, lon: fix.lng }, { lat: f.lat, lon: f.lng }));
}

export function matchCourse(entry: CourseEntry, fix: DeviceFix, opts: CandidateOptions = {}): CourseMatch {
  const candidate = candidateFor(entry, opts);
  if (candidate === null) return { kind: "rejected", reason: "no_geometry", distanceMeters: distanceToFacility(entry, fix) };
  const r = matchCheckIn({ point: { lat: fix.lat, lon: fix.lng }, accuracyMeters: fix.accuracyMeters, simulated: fix.simulated, timestamp: fix.capturedAt }, candidate);
  if (!r.accepted) return { kind: "rejected", reason: r.reason, distanceMeters: distanceToFacility(entry, fix) };
  return { kind: "matched", geometryKind: r.geometryKind, sharedGeometry: candidate.sharedGeometry === true };
}

export interface NearbyCourse {
  courseId: string;
  facilityId: string;
  distanceMeters: number;
}

/** Up to `max` OTHER facilities whose circle contains the fix, nearest first (one course each: the player picks within a site on its page). "Did you mean ...?" for a player on the wrong
 * course page. Pure and O(facilities). */
export function nearbyCourses(index: CatalogIndex, fix: DeviceFix, exceptFacilityId: string, max = 3): NearbyCourse[] {
  const out: NearbyCourse[] = [];
  for (const f of index.facilities.values()) {
    if (f.id === exceptFacilityId) continue;
    const first = f.courses[0];
    if (!first) continue;
    const entry: CourseEntry = { course: first, facility: f };
    if (matchCourse(entry, fix).kind !== "matched") continue;
    const d = distanceToFacility(entry, fix);
    if (d !== null) out.push({ courseId: first.id, facilityId: f.id, distanceMeters: d });
  }
  return out.sort((a, b) => a.distanceMeters - b.distanceMeters || (a.courseId < b.courseId ? -1 : 1)).slice(0, max);
}

/** One recorded play at a facility on a date, for the §4.3 one-pick guard. */
export interface FacilityPick {
  facilityId: string;
  localDate: string;
  courseId: string;
}

/** §4.3 "one pick per facility per date": at a MULTI-course facility a second pick of a DIFFERENT course on the same facility-local date is refused (`conflict` names the course
 * already picked); the same course again is not a second pick. A single-course facility has nothing to pick. */
export function pickGuard(picks: readonly FacilityPick[], entry: CourseEntry, localDate: string): { ok: true } | { ok: false; courseId: string } {
  if (entry.facility.courses.length < 2) return { ok: true };
  const clash = picks.find((p) => p.facilityId === entry.facility.id && p.localDate === localDate && p.courseId !== entry.course.id);
  return clash ? { ok: false, courseId: clash.courseId } : { ok: true };
}
