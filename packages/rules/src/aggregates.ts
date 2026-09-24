/**
 * The `field`-keyed aggregates (§4.1 line 601-603, 608-611):
 * `countDistinct(field, where?)`, `maxCountBy(field)`, `countWhere(field,
 * value)`, plus `markerCredits(trailId)` (line 604, which needs the same
 * marker-roster crediting `completion.ts` already builds). Pure TS, no I/O.
 *
 * **`field: 'trail'` and cross-trail context.** "`trail` (every trail with
 * some roster version that contains the course)" (§4.1 line 609) is the
 * one field whose value for a course depends on trails OTHER than any
 * single trail the caller might be evaluating — so these three functions
 * take `trails: Record<TrailId, RosterVersion[]>` (every trail this
 * evaluation run knows about), not a single trail's roster versions the
 * way `completion.ts`'s trail-scoped functions do.
 */
import type { Field, RosterVersion, TrailId } from "@golfraven/catalog";
import {
  BADGE_THRESHOLD,
  isFacilityCreditedByPlay,
  markerRosterOf,
  memberCoversCourseId,
  type CompletionContext,
  type Play,
} from "./completion.js";

export interface AggregateContext extends CompletionContext {
  trails: Record<string, RosterVersion[]>;
}

function qualifyingCourseIds(plays: Play[], money: boolean): Set<string> {
  const set = new Set<string>();
  for (const p of plays) {
    if (money ? p.moneyQualifies !== true : p.scoreBadge < BADGE_THRESHOLD) continue;
    set.add(p.courseId);
  }
  return set;
}

function fieldValuesOfCourse(courseId: string, field: Field, ctx: AggregateContext): string[] {
  const meta = ctx.courses[courseId];
  switch (field) {
    case "region":
      return meta?.region ? [meta.region] : [];
    case "country":
      return meta?.country ? [meta.country] : [];
    case "designer":
      return meta?.designers ?? [];
    case "facility":
      return meta?.facilityId ? [meta.facilityId] : [];
    case "trail":
      return trailsContainingCourse(courseId, ctx);
  }
}

/** "every trail with some roster version that contains the course"
 * (§4.1 line 609) — scans every trail this evaluation run was given. */
function trailsContainingCourse(courseId: string, ctx: AggregateContext): TrailId[] {
  const out: TrailId[] = [];
  for (const [trailId, versions] of Object.entries(ctx.trails)) {
    const contains = versions.some((v) =>
      v.members.some((m) => memberCoversCourseId(courseId, m, v.completionUnit, ctx)),
    );
    if (contains) out.push(trailId as TrailId);
  }
  return out;
}

/** `countDistinct(field, where?)`: "Distinct values of `field` over
 * qualifying played courses. `where: { in: [...] }` restricts the values
 * that count" (§4.1 line 601). */
export function countDistinct(
  field: Field,
  ctx: AggregateContext,
  plays: Play[],
  money = false,
  where?: { in: string[] },
): number {
  const allowed = where ? new Set(where.in) : undefined;
  const values = new Set<string>();
  for (const courseId of qualifyingCourseIds(plays, money)) {
    for (const value of fieldValuesOfCourse(courseId, field, ctx)) {
      if (allowed && !allowed.has(value)) continue;
      values.add(value);
    }
  }
  return values.size;
}

/** `maxCountBy(field)`: "The largest number of distinct qualifying played
 * courses sharing one value of `field`" (§4.1 line 602). */
export function maxCountBy(field: Field, ctx: AggregateContext, plays: Play[], money = false): number {
  const countByValue = new Map<string, number>();
  for (const courseId of qualifyingCourseIds(plays, money)) {
    for (const value of fieldValuesOfCourse(courseId, field, ctx)) {
      countByValue.set(value, (countByValue.get(value) ?? 0) + 1);
    }
  }
  let best = 0;
  for (const count of countByValue.values()) {
    if (count > best) best = count;
  }
  return best;
}

/** `countWhere(field, value)`: "Distinct qualifying played courses whose
 * `field` includes `value`" (§4.1 line 603). */
export function countWhere(
  field: Field,
  value: string,
  ctx: AggregateContext,
  plays: Play[],
  money = false,
): number {
  let count = 0;
  for (const courseId of qualifyingCourseIds(plays, money)) {
    if (fieldValuesOfCourse(courseId, field, ctx).includes(value)) count += 1;
  }
  return count;
}

/** `markerCredits(trailId)`: "the maximum over V of credited facilities
 * that satisfy V's marker roster under the §4.6 membership rule" (§4.1
 * line 604) — the same crediting rule `markerSetComplete` (`completion.ts`)
 * uses, but counted rather than thresholded against `markerRule`. */
export function markerCredits(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  money = false,
): number {
  let best = 0;
  for (const v of allVersions) {
    const roster = markerRosterOf(v, ctx);
    const credited = roster.filter((f) => isFacilityCreditedByPlay(f, v, plays, ctx, money)).length;
    if (credited > best) best = credited;
  }
  return best;
}
