/**
 * Many-to-many trail membership, derived from `Trail.rosterVersions[].members`
 * only — never authored on `Facility`/`Course` (§4.3: "Membership lives only
 * in `Trail.rosterVersions[].members`. There is no `trails[]` field on
 * Facility or Course, so nothing can drift" — the SWC 1:1 `Winery.trail` fix,
 * `swc-analysis.md §0.6`). §5.1's file mapping rewrites SWC's `src/lib/trails.ts`
 * (a flat `Winery.trail === name` filter) into this file.
 *
 * Every lookup here is **unit-aware** (§4.3's `completionUnit`: `course` /
 * `facility` / `hole`) and operates on a trail's **latest** roster version —
 * the version the website shows (§5.1 `trails/*`: "Latest roster version").
 * Multi-version completion math (which version a given *player* is furthest
 * along on) is player-plane scope (§8.2, `packages/rules`), not this
 * site-facing package.
 */
import { resolveMergedId, type IdLedger } from "./ledger.js";
import type { CourseId, FacilityId, TrailId } from "./ids.js";
import type { Catalog } from "./load.js";
import type {
  Course,
  Facility,
  RosterMember,
  RosterVersion,
  Trail,
} from "./schema.js";

/** The roster member variants that carry `unit: 'course'` are told apart by
 * which of `courseId` / `anyOf` they carry (§4.1: not a `discriminatedUnion`
 * on `unit` alone, because two variants share it — see `schema.ts`). */
function courseMemberIds(member: RosterMember & { unit: "course" }): CourseId[] {
  return "courseId" in member ? [member.courseId] : member.anyOf;
}

/** The latest published roster version of a trail (max `.version`). Every
 * `Trail` carries at least one roster version (`rosterVersions.min(1)`), so
 * this is total over any schema-valid `Trail`. */
export function latestRosterVersion(trail: Trail): RosterVersion {
  return trail.rosterVersions.reduce((latest, v) =>
    v.version > latest.version ? v : latest,
  );
}

/** `courseId -> facilityId` for every course in the catalog — the join a
 * course/hole roster member needs to resolve "which facility is this
 * course at" (§4.3). Built once per call site; callers doing several
 * lookups should build it once and pass results around rather than calling
 * the `trailsOf*` functions in a tight loop. */
export function buildCourseFacilityIndex(
  catalog: Catalog,
): Map<CourseId, FacilityId> {
  const index = new Map<CourseId, FacilityId>();
  for (const facility of catalog.facilities) {
    for (const course of facility.courses) {
      index.set(course.id, facility.id);
    }
  }
  return index;
}

function resolveId(id: string, ledger?: IdLedger): string {
  return ledger ? resolveMergedId(ledger, id) : id;
}

function idEquals(a: string, b: string, ledger?: IdLedger): boolean {
  return resolveId(a, ledger) === resolveId(b, ledger);
}

/** Unit-aware: does this roster `member` cover the given course, whatever
 * its own `unit` is? A `facility` member covers EVERY course at that
 * facility (§4.3: "`facility`: **any** course at that facility has a
 * qualifying play"); a `hole` member covers the course that hole belongs
 * to. Ledger merges (A2-04) are resolved on both sides when `ledger` is
 * given. */
export function memberCoversCourse(
  member: RosterMember,
  courseId: CourseId,
  courseFacility: ReadonlyMap<CourseId, FacilityId>,
  ledger?: IdLedger,
): boolean {
  switch (member.unit) {
    case "course":
      return courseMemberIds(member).some((id) =>
        idEquals(id, courseId, ledger),
      );
    case "hole":
      return idEquals(member.courseId, courseId, ledger);
    case "facility": {
      const facilityId = courseFacility.get(
        resolveId(courseId, ledger) as CourseId,
      );
      return (
        facilityId !== undefined && idEquals(member.facilityId, facilityId, ledger)
      );
    }
  }
}

/** Unit-aware: does this roster `member` cover the given facility? A
 * `course`/`hole` member covers the facility that course belongs to. */
export function memberCoversFacility(
  member: RosterMember,
  facilityId: FacilityId,
  courseFacility: ReadonlyMap<CourseId, FacilityId>,
  ledger?: IdLedger,
): boolean {
  switch (member.unit) {
    case "facility":
      return idEquals(member.facilityId, facilityId, ledger);
    case "course":
      return courseMemberIds(member).some((courseId) => {
        const fid = courseFacility.get(resolveId(courseId, ledger) as CourseId);
        return fid !== undefined && idEquals(fid, facilityId, ledger);
      });
    case "hole": {
      const fid = courseFacility.get(
        resolveId(member.courseId, ledger) as CourseId,
      );
      return fid !== undefined && idEquals(fid, facilityId, ledger);
    }
  }
}

/** Derived, never authored (§4.3): every trail whose latest roster version
 * has a member covering `courseId`. */
export function trailsOfCourse(catalog: Catalog, courseId: CourseId): Trail[] {
  const courseFacility = buildCourseFacilityIndex(catalog);
  return catalog.trails.filter((trail) =>
    latestRosterVersion(trail).members.some((member) =>
      memberCoversCourse(member, courseId, courseFacility, catalog.idLedger),
    ),
  );
}

/** Derived, never authored (§4.3): every trail whose latest roster version
 * has a member covering `facilityId`. */
export function trailsOfFacility(
  catalog: Catalog,
  facilityId: FacilityId,
): Trail[] {
  const courseFacility = buildCourseFacilityIndex(catalog);
  return catalog.trails.filter((trail) =>
    latestRosterVersion(trail).members.some((member) =>
      memberCoversFacility(member, facilityId, courseFacility, catalog.idLedger),
    ),
  );
}

/** `primaryTrailOf(facility)`: "the smallest containing trail, tie-broken
 * by id, overridable only via `data/overrides/primary-trail.json`, which is
 * gated to real members" (§4.3). This function takes the override as a
 * plain map rather than reading the override file itself — `packages/catalog`
 * "Never does: Hold data or fetch" (§3.1 row A); the caller (a script, the
 * site's build) reads `data/overrides/primary-trail.json` (through
 * `loadCatalog`'s directory path or its own read) and passes the result in.
 * "Smallest" is read as fewest roster members in the LATEST version — the
 * tightest-knit trail a facility belongs to — ties broken by trail id
 * (`Trail.id`, ascending), matching "tie-broken by id" literally. */
export function primaryTrailOf(
  catalog: Catalog,
  facilityId: FacilityId,
  overrides?: ReadonlyMap<FacilityId, TrailId>,
): Trail | undefined {
  const overrideTrailId = overrides?.get(facilityId);
  if (overrideTrailId !== undefined) {
    const overridden = catalog.trails.find((t) => t.id === overrideTrailId);
    // "gated to real members": an override naming a trail the facility is
    // not actually on is ignored, not trusted blindly.
    if (
      overridden &&
      trailsOfFacility(catalog, facilityId).some((t) => t.id === overridden.id)
    ) {
      return overridden;
    }
  }
  const candidates = trailsOfFacility(catalog, facilityId);
  if (candidates.length === 0) return undefined;
  return candidates.reduce((best, candidate) => {
    const bestSize = latestRosterVersion(best).members.length;
    const candidateSize = latestRosterVersion(candidate).members.length;
    if (candidateSize < bestSize) return candidate;
    if (candidateSize === bestSize && candidate.id < best.id) return candidate;
    return best;
  });
}

/** One resolved roster stop, for rendering a trail page's stop list
 * (§5.1 `trails/*`: "stops"). `course` is set only when the member itself
 * names a specific course (`unit: 'course'` — the first id of an `anyOf`
 * group — or `unit: 'hole'`); a `facility`-unit member has no single
 * "the" course, by definition (§4.3). */
export interface RosterStop {
  member: RosterMember;
  facility: Facility;
  course?: Course;
}

/** Unit-aware resolution of every roster member in `version` (default: the
 * trail's latest) down to the `Facility` (and, where the member names one,
 * `Course`) it points at, sorted by `stopOrder` (members without one sort
 * after those with one, in encounter order). Members whose target id is not
 * in `catalog.facilities`/`.courses` (a dangling reference — a gate-rule
 * concern for `verify-catalog`, not this package) are skipped rather than
 * throwing. */
export function rosterStops(
  catalog: Catalog,
  trail: Trail,
  version: RosterVersion = latestRosterVersion(trail),
): RosterStop[] {
  const facilityById = new Map(catalog.facilities.map((f) => [f.id, f]));
  const courseById = new Map<CourseId, Course>();
  for (const facility of catalog.facilities) {
    for (const course of facility.courses) {
      courseById.set(course.id, course);
    }
  }
  const courseFacility = buildCourseFacilityIndex(catalog);

  interface InternalStop {
    member: RosterMember;
    facility: Facility;
    course: Course | undefined;
    stopOrder: number | undefined;
    seq: number;
  }

  const stops: InternalStop[] = [];
  version.members.forEach((member, seq) => {
    if (member.unit === "facility") {
      const facility = facilityById.get(member.facilityId);
      if (facility) {
        stops.push({ member, facility, course: undefined, stopOrder: member.stopOrder, seq });
      }
      return;
    }
    if (member.unit === "course") {
      const [firstId] = courseMemberIds(member);
      if (firstId === undefined) return;
      const facilityId = courseFacility.get(firstId);
      const facility = facilityId ? facilityById.get(facilityId) : undefined;
      const course = courseById.get(firstId);
      if (facility) {
        stops.push({ member, facility, course, stopOrder: member.stopOrder, seq });
      }
      return;
    }
    // unit === 'hole'
    const facilityId = courseFacility.get(member.courseId);
    const facility = facilityId ? facilityById.get(facilityId) : undefined;
    const course = courseById.get(member.courseId);
    if (facility) {
      stops.push({ member, facility, course, stopOrder: member.stopOrder, seq });
    }
  });

  return stops
    .sort((a, b) => {
      const aOrder = a.stopOrder ?? Number.MAX_SAFE_INTEGER;
      const bOrder = b.stopOrder ?? Number.MAX_SAFE_INTEGER;
      return aOrder - bOrder || a.seq - b.seq;
    })
    .map(
      ({ member, facility, course }): RosterStop =>
        course === undefined ? { member, facility } : { member, facility, course },
    );
}

/** How many resolved stops are private clubs (O8: "a trail with a private
 * member shows the private-stops note"). Counts distinct facilities, so a
 * course-unit trail with several members at one private facility counts
 * that facility once. */
export function privateStopCount(stops: readonly RosterStop[]): number {
  const privateFacilityIds = new Set(
    stops.filter((s) => s.facility.access === "private").map((s) => s.facility.id),
  );
  return privateFacilityIds.size;
}
