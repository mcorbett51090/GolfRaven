/**
 * The `field`-keyed aggregates (§4.1 line 601-603, 608-611):
 * `countDistinct(field, where?)`, `maxCountBy(field)`, `countWhere(field,
 * value)`, plus `markerCredits(trailId)` (line 604, which needs the same
 * marker-roster crediting `completion.ts` already builds). Pure TS, no I/O.
 *
 * **`field: 'trail'` and cross-trail context.** "`trail` (every trail with
 * some roster version that contains the course)" (§4.1 line 609) is the
 * one field whose value for a course depends on trails OTHER than any
 * single trail the caller might be evaluating — so these functions take
 * `trails: Record<TrailId, RosterVersion[]>` (every trail this evaluation
 * run knows about).
 *
 * **S3 (gate review): every id resolves through the ledger's `mergedInto`
 * closure first (A2-04, §4.1 line 590).** A play recorded against a
 * tombstoned course id counts for its SURVIVOR, and — because the
 * qualifying-course SET is built from resolved ids — never twice even if
 * two plays name the pre-merge id and the survivor id separately for the
 * "same" real course.
 */
import type { Field, IdLedger, RosterVersion, TrailId } from "@golfraven/catalog";
import { resolveMergedId } from "@golfraven/catalog";
import {
  isFacilityCreditedByPlay,
  markerRosterOf,
  memberCoversCourseId,
  playQualifies,
  type CompletionContext,
  type EvalOptions,
  type Play,
} from "./completion.js";

export interface AggregateContext extends CompletionContext {
  trails: Record<string, RosterVersion[]>;
}

function resolveId(ledger: IdLedger | undefined, id: string): string {
  return ledger ? resolveMergedId(ledger, id) : id;
}

/** S3: every qualifying play's course id, resolved through `mergedInto`
 * FIRST, then deduped — a `Set` of already-resolved ids, so a tombstoned
 * id's play and its survivor's own play collapse into one entry. */
function qualifyingCourseIds(plays: Play[], ctx: AggregateContext, opts: EvalOptions): Set<string> {
  const set = new Set<string>();
  for (const p of plays) {
    if (!playQualifies(p, ctx, opts, undefined)) continue;
    set.add(resolveId(ctx.ledger, p.courseId));
  }
  return set;
}

function fieldValuesOfCourse(resolvedCourseId: string, field: Field, ctx: AggregateContext): string[] {
  const meta = ctx.courses[resolvedCourseId];
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
      return trailsContainingCourse(resolvedCourseId, ctx);
  }
}

/** "every trail with some roster version that contains the course"
 * (§4.1 line 609) — scans every trail this evaluation run was given,
 * resolving each member's own course reference(s) through the ledger too
 * (S3), so a roster that still lists a since-tombstoned id correctly
 * covers the survivor. */
function trailsContainingCourse(resolvedCourseId: string, ctx: AggregateContext): TrailId[] {
  const out: TrailId[] = [];
  for (const [trailId, versions] of Object.entries(ctx.trails)) {
    const contains = versions.some((v) =>
      v.members.some((m) => memberCoversCourseId(resolvedCourseId, m, v.completionUnit, ctx)),
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
  opts: EvalOptions = {},
  where?: { in: string[] },
): number {
  const allowed = where ? new Set(where.in) : undefined;
  const values = new Set<string>();
  for (const courseId of qualifyingCourseIds(plays, ctx, opts)) {
    for (const value of fieldValuesOfCourse(courseId, field, ctx)) {
      if (allowed && !allowed.has(value)) continue;
      values.add(value);
    }
  }
  return values.size;
}

/** `maxCountBy(field)`: "The largest number of distinct qualifying played
 * courses sharing one value of `field`" (§4.1 line 602) — counts
 * COURSES, one per distinct qualifying course id, never plays (a player
 * who plays the same course twice must not inflate this). */
export function maxCountBy(
  field: Field,
  ctx: AggregateContext,
  plays: Play[],
  opts: EvalOptions = {},
): number {
  const countByValue = new Map<string, number>();
  for (const courseId of qualifyingCourseIds(plays, ctx, opts)) {
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
  opts: EvalOptions = {},
): number {
  let count = 0;
  for (const courseId of qualifyingCourseIds(plays, ctx, opts)) {
    if (fieldValuesOfCourse(courseId, field, ctx).includes(value)) count += 1;
  }
  return count;
}

/** `markerCredits(trailId)`: "the maximum over V of credited facilities
 * that satisfy V's marker roster under the §4.6 membership rule" (§4.1
 * line 604). */
export function markerCredits(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  opts: EvalOptions = {},
): number {
  let best = 0;
  for (const v of allVersions) {
    const roster = markerRosterOf(v, ctx);
    const credited = roster.filter((f) => isFacilityCreditedByPlay(f, v, allVersions, plays, ctx, opts)).length;
    if (credited > best) best = credited;
  }
  return best;
}
