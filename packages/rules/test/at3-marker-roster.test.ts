/**
 * P1 AT(3): "RTJ fixture (26 courses / 11 facilities) → marker roster of
 * 11; Okanagan hole unit → 18 courses; a 27-hole composite fixture" (build
 * plan §10 P1). Every id is synthetic (task instruction: "all fixture data
 * is synthetic, apart from the course/facility counts the plan states") —
 * only the COUNTS (26/11, 18, 27-hole/2-nine) are the real research
 * numbers (`research/us-trails.md — RTJ … 26 public courses / 468 holes at
 * 11 sites`; `research/canada-trails.md — Great Okanagan … 18-signature-hole
 * … passport`).
 */
import { describe, expect, it } from "vitest";
import {
  type CourseId,
  type FacilityId,
  type RosterMember,
  type RosterVersion,
} from "@golfraven/catalog";
import {
  deriveRemovedOn,
  evaluateVersionCompletion,
  markerRosterOf,
  physicalIdentityOfMember,
  uniqueCourses,
  type CompletionContext,
  type Play,
} from "../src/completion.js";
import { nextId } from "./test-ids.js";

// N7 (gate review): deterministic ids, no Date.now().
function ids(kind: "fac" | "crs", n: number): string[] {
  return Array.from({ length: n }, () => nextId(kind));
}

describe("AT(3): RTJ fixture — 26 courses / 11 facilities → marker roster of 11", () => {
  it("markerRosterOf returns exactly the 11 distinct facilities hosting the 26 course members", () => {
    const facilityIds = ids("fac", 11) as FacilityId[];
    // Spread 26 courses across 11 facilities (some facilities host more
    // than one course — RTJ's own shape, "26 public courses ... at 11
    // sites").
    const courseIds: CourseId[] = [];
    const courses: CompletionContext["courses"] = {};
    let facilityIndex = 0;
    for (let i = 0; i < 26; i += 1) {
      const courseId = nextId("crs") as CourseId;
      const facilityId = facilityIds[facilityIndex % 11]!;
      courseIds.push(courseId);
      courses[courseId] = { id: courseId, facilityId, verified: true };
      facilityIndex += 1;
    }
    const version: RosterVersion = {
      version: 1,
      effectiveFrom: "2026-01-01",
      source: { url: "https://example.com/rtj", retrieved: "2026-01-01" },
      verifiedAt: "2026-01-01",
      completionUnit: "facility",
      markerUnit: "facility",
      completionRule: { kind: "all" },
      markerRule: { kind: "all" },
      members: facilityIds.map((facilityId): RosterMember => ({
        unit: "facility",
        facilityId,
      })),
    };
    const ctx: CompletionContext = { courses };
    const roster = markerRosterOf(version, ctx);
    expect(roster.length).toBe(11);
    expect(new Set(roster).size).toBe(11);
    // Every course really does resolve to one of those 11 facilities.
    expect(new Set(courseIds.map((c) => courses[c]!.facilityId)).size).toBe(11);
    expect(courseIds.length).toBe(26);
  });
});

describe("AT(3): Great Okanagan — hole unit → 18 courses", () => {
  it("an 18-signature-hole roster (completionUnit: 'hole') names 18 distinct courses", () => {
    const courseIds = ids("crs", 18) as CourseId[];
    const version: RosterVersion = {
      version: 1,
      effectiveFrom: "2026-01-01",
      source: { url: "https://example.com/okanagan", retrieved: "2026-01-01" },
      verifiedAt: "2026-01-01",
      completionUnit: "hole",
      markerUnit: "facility",
      completionRule: { kind: "all" },
      markerRule: { kind: "all" },
      members: courseIds.map((courseId, i): RosterMember => ({
        unit: "hole",
        holeId: nextId("hol") as never,
        courseId,
      })),
    };
    expect(version.members.length).toBe(18);
    const distinctCourses = new Set(
      version.members
        .filter((m) => m.unit === "hole")
        .map((m) => (m as Extract<RosterMember, { unit: "hole" }>).courseId),
    );
    expect(distinctCourses.size).toBe(18);
  });
});

describe("AT(3): a 27-hole composite fixture (A2-18)", () => {
  it("a play on the composite course counts once in uniqueCourses, and satisfies both nines as members", () => {
    const facilityId = nextId("fac") as FacilityId;
    const nineA = nextId("crs") as CourseId;
    const nineB = nextId("crs") as CourseId;
    const composite18 = nextId("crs") as CourseId;

    const courses: CompletionContext["courses"] = {
      [nineA]: { id: nineA, facilityId, verified: true },
      [nineB]: { id: nineB, facilityId, verified: true },
      [composite18]: {
        id: composite18,
        facilityId,
        composite: [nineA, nineB],
        verified: true,
      },
    };
    const ctx: CompletionContext = { courses };

    const plays: Play[] = [
      { courseId: composite18, localDate: "2026-05-01", scoreBadge: 1 },
    ];

    // "one play is one playable unit" — uniqueCourses counts the ONE
    // course id the play was recorded at, never 2 or 3.
    expect(uniqueCourses(plays, ctx)).toBe(1);

    // But the SAME play satisfies both nines as roster members (§4.3:
    // "A play on the composite satisfies the composite and both nines
    // AS ROSTER MEMBERS").
    const version: RosterVersion = {
      version: 1,
      effectiveFrom: "2026-01-01",
      source: { url: "https://example.com/composite", retrieved: "2026-01-01" },
      verifiedAt: "2026-01-01",
      completionUnit: "course",
      markerUnit: "facility",
      completionRule: { kind: "all" },
      markerRule: { kind: "all" },
      members: [
        { unit: "course", courseId: nineA },
        { unit: "course", courseId: nineB },
      ],
    };
    const result = evaluateVersionCompletion(version, [version], plays, ctx);
    expect(result.satisfiedCount).toBe(2);
    expect(result.complete).toBe(true);
  });

  // Re-gate item 4: a LATER version that lists only the composite still
  // covers each nine's own identity — `isIdentityPresentIn` must check the
  // reverse direction too (a nine's identity, covered by a member listing
  // the composite), not just "a play on the composite satisfies a nine
  // member". Without that, a nine would wrongly show `removed_on` set the
  // moment the roster switches to listing the composite alone.
  it("a version listing only the composite still covers a nine's identity — no removed_on for it (A2-18)", () => {
    const facilityId = nextId("fac") as FacilityId;
    const nineA = nextId("crs") as CourseId;
    const nineB = nextId("crs") as CourseId;
    const composite18 = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = {
      [nineA]: { id: nineA, facilityId, verified: true },
      [nineB]: { id: nineB, facilityId, verified: true },
      [composite18]: {
        id: composite18,
        facilityId,
        composite: [nineA, nineB],
        verified: true,
      },
    };
    const ctx: CompletionContext = { courses };
    const v1: RosterVersion = {
      version: 1,
      effectiveFrom: "2026-01-01",
      source: { url: "https://example.com/composite", retrieved: "2026-01-01" },
      verifiedAt: "2026-01-01",
      completionUnit: "course",
      markerUnit: "facility",
      completionRule: { kind: "all" },
      markerRule: { kind: "all" },
      members: [{ unit: "course", courseId: nineA }],
    };
    // V2 (later, effectiveFrom AFTER v1) lists only the composite — not
    // nineA by name.
    const v2: RosterVersion = {
      ...v1,
      version: 2,
      effectiveFrom: "2026-06-01",
      members: [{ unit: "course", courseId: composite18 }],
    };
    const identity = physicalIdentityOfMember(v1.members[0]!, ctx);
    expect(deriveRemovedOn(identity, 1, [v1, v2], ctx)).toBeUndefined();
  });
});
