/**
 * §8.2 completion + §4.3 marker-roster evaluation. Pure TS, no I/O (build
 * plan §3.1 row E) — every function here takes a trail's roster versions
 * and a player's plays as plain data and returns a plain result; nothing
 * fetches, nothing mutates its inputs.
 *
 * **Inputs, literally as the task states them ("course id, local_date,
 * evidence class and score"), plus the minimal extra the spec's own rules
 * cannot be computed without.** `Play.courseId` / `Play.localDate` /
 * `Play.courseDisambiguatedBy` (§4.3's "evidence class" — `geometry` /
 * `staff` / `user`, A2-01) / `Play.scoreBadge` map onto the task's four
 * named fields directly. Two things had to be added beyond that literal
 * four, both cited at the point they're used below:
 *
 * 1. `Play.moneyQualifies` — a boolean the (out-of-scope, P3) money-rule
 *    scorer would have already computed. §8.2's core completion rule only
 *    ever needs `score_badge ≥ 0.50` (line 1942) — but AT(6)'s own O19
 *    rows (plan lines 1985-1988) are written entirely in terms of "money-
 *    mode plays" vs "badge-level" plays for the special-marker entitlement,
 *    and "compute completion and marker eligibility... including every
 *    case listed in AT(6)" is the literal scope instruction. Since
 *    `scorePlay`/the money rule itself is explicitly out of scope (task's
 *    own "Out of scope" list), this field is taken as a pre-computed input,
 *    the same way `scoreBadge` already is.
 * 2. `MarkerPurchase` (a separate, much smaller input: `facilityId` +
 *    `localDate`) — the O19 fixtures need "a purchase at every marker-
 *    roster facility" as a distinct leg from "money-mode plays at every
 *    member" (plan lines 1985-1986 name both legs separately, and
 *    line 1984 ties `marker_requires_completion` to "counting purchase
 *    corroboration"). There is no way to model two independently-failing
 *    legs from one input stream, so a second, minimal input was necessary.
 *
 * **`trail_programme.starts_on` simplification (documented, not modelled).**
 * §4.6 dates a purchase leg against `trail_programme.starts_on` (a DB-side
 * concept, §4.4/§4.6 — no `TrailProgramme` record exists in this task's
 * catalog scope). `specialMarkerEntitlement` below uses the SAME
 * `trackingStartsOn`/`removedOn` bounds for both legs (purchases and
 * plays) rather than a separate programme-start date, since the plan's
 * own "marker vs completion parity" fixture (AT(6) row) explicitly wants
 * both legs judged under the SAME bounds when the two dates coincide, and
 * modelling a second, independent date source has no fixture driving its
 * shape. Flagged again at `specialMarkerEntitlement`'s own doc.
 */
import {
  resolveMergedId,
  type CourseId,
  type DesignerId,
  type FacilityId,
  type IdLedger,
  type IsoDate,
  type RegionCode,
  type RosterMember,
  type RosterVersion,
  type TrailId,
} from "@golfraven/catalog";

/** §8.2 line 1942: "any play at m with `score_badge ≥ 0.50`". */
export const BADGE_THRESHOLD = 0.5;

/* ------------------------------------------------------------------ */
/* Inputs                                                               */
/* ------------------------------------------------------------------ */

export type CourseDisambiguatedBy = "geometry" | "staff" | "user";

export interface Play {
  courseId: CourseId;
  /** Facility-local `play_date` (A2-17: date-only evidence — self-report,
   * a Health workout with no route, a file with no route — is already
   * resolved to a single date by the caller before it ever reaches this
   * package; a device's own time zone plays no part here, which is
   * exactly AT(6)'s "date-only `local_date`" fixture: this field is used
   * verbatim, never re-derived from anything device-side). */
  localDate: IsoDate;
  /** "evidence class" (task wording) — §4.3's `course_disambiguated_by`.
   * Defaults to `'geometry'` when omitted (the strongest, unambiguous
   * case) so a caller that has no multi-course-site ambiguity to report
   * need not always set it. */
  courseDisambiguatedBy?: CourseDisambiguatedBy;
  /** "score" (task wording) — `score_badge`, §8.2's only completion
   * threshold. */
  scoreBadge: number;
  /** Whether this SAME play also meets the §4.5 money rule (out of
   * scope — see module doc point 1). Defaults to `false`. */
  moneyQualifies?: boolean;
}

/** The §4.6/O19 purchase leg — see module doc point 2. */
export interface MarkerPurchase {
  facilityId: FacilityId;
  localDate: IsoDate;
}

export interface CourseMeta {
  id: CourseId;
  facilityId: FacilityId;
  region?: RegionCode;
  country?: "US" | "CA";
  designers?: DesignerId[];
  closed?: boolean;
  /** Mirrors `Course.composite` (§4.1): the two nines this course is
   * composed of, when this course IS an 18 formed from two nines. */
  composite?: [CourseId, CourseId];
}

/** The course metadata `packages/rules` needs (never fetched — supplied by
 * the caller, keyed by `CourseId`). `ledger` is optional; omitted, every id
 * is taken as already resolved (no merge to apply). */
export interface CompletionContext {
  courses: Record<string, CourseMeta>;
  ledger?: IdLedger;
}

function resolveId(ctx: CompletionContext, id: string): string {
  return ctx.ledger ? resolveMergedId(ctx.ledger, id) : id;
}

function courseMeta(ctx: CompletionContext, courseId: string): CourseMeta | undefined {
  const resolved = resolveId(ctx, courseId);
  return ctx.courses[resolved] ?? ctx.courses[courseId];
}

function facilityOfCourse(ctx: CompletionContext, courseId: string): FacilityId | undefined {
  return courseMeta(ctx, courseId)?.facilityId;
}

/* ------------------------------------------------------------------ */
/* A2-01: the user-pick one-per-facility-per-date guard                */
/* ------------------------------------------------------------------ */

/**
 * "A `user` pick yields at most one course per facility per facility-local
 * date. A second, different pick on the same date replaces the first
 * (audited)" (§4.3). Only `courseDisambiguatedBy: 'user'` plays are
 * subject to this — `geometry`/`staff` plays are never ambiguous and pass
 * through untouched. "Replaces" is read as last-write-wins on **input
 * order** (the caller's array order is the audit order; this function has
 * no other way to know which pick came later).
 */
export function applyUserPickGuard(plays: Play[], ctx: CompletionContext): Play[] {
  const latestUserPickIndex = new Map<string, number>();
  plays.forEach((play, i) => {
    if ((play.courseDisambiguatedBy ?? "geometry") !== "user") return;
    const facilityId = facilityOfCourse(ctx, play.courseId);
    if (!facilityId) return;
    latestUserPickIndex.set(`${facilityId}|${play.localDate}`, i);
  });
  return plays.filter((play, i) => {
    if ((play.courseDisambiguatedBy ?? "geometry") !== "user") return true;
    const facilityId = facilityOfCourse(ctx, play.courseId);
    if (!facilityId) return true;
    return latestUserPickIndex.get(`${facilityId}|${play.localDate}`) === i;
  });
}

/* ------------------------------------------------------------------ */
/* removedOn (§4.3: "the import derives each member's removed_on")     */
/* ------------------------------------------------------------------ */

/** A member's PHYSICAL identity, for cross-version "is this the same
 * stop" comparisons (§4.3: "re-typing is not a drop... a member counts as
 * dropped only when no member of the later version covers the same
 * physical unit"). Facility id is the common denominator every unit type
 * resolves to (a course belongs to one facility; a hole belongs to a
 * course which belongs to one facility). */
export function physicalFacilityIdOfMember(
  member: RosterMember,
  ctx: CompletionContext,
): FacilityId | undefined {
  switch (member.unit) {
    case "facility":
      return (resolveId(ctx, member.facilityId) as FacilityId) ?? member.facilityId;
    case "course":
      if ("courseId" in member) return facilityOfCourse(ctx, member.courseId);
      // anyOf: every listed course is, by construction, the same
      // multi-course site (A2-18), so the first resolvable one's facility
      // is authoritative.
      for (const courseId of member.anyOf) {
        const f = facilityOfCourse(ctx, courseId);
        if (f) return f;
      }
      return undefined;
    case "hole":
      return facilityOfCourse(ctx, member.courseId);
  }
}

/**
 * §4.3: "the import derives each member's `removed_on` (the
 * `effectiveFrom` of the first later version that drops it, reset to null
 * if a later version re-adds it)." Implemented as a single forward scan
 * (ascending version number) rather than literally "find first drop, then
 * separately reset" — the two are equivalent (a `removed_on` is only ever
 * READ when the member is absent from the *latest* version, §8.2 line
 * 1944: "if m has been dropped from the latest version"), and a forward
 * scan naturally lands on the correct final state either way: present in
 * latest ⇒ `undefined`; absent in latest ⇒ the `effectiveFrom` of the
 * start of the unbroken absence streak that reaches the latest version.
 */
export function deriveRemovedOn(
  memberFacilityId: FacilityId | undefined,
  fromVersion: number,
  allVersions: RosterVersion[],
  ctx: CompletionContext,
): IsoDate | undefined {
  if (!memberFacilityId) return undefined;
  const later = [...allVersions]
    .filter((v) => v.version > fromVersion)
    .sort((a, b) => a.version - b.version);
  let absentSince: IsoDate | undefined;
  for (const v of later) {
    const present = v.members.some(
      (m) => physicalFacilityIdOfMember(m, ctx) === memberFacilityId,
    );
    if (present) {
      absentSince = undefined;
    } else if (absentSince === undefined) {
      absentSince = v.effectiveFrom;
    }
  }
  return absentSince;
}

/* ------------------------------------------------------------------ */
/* Member satisfaction (§8.2 core rule)                                 */
/* ------------------------------------------------------------------ */

/**
 * Whether `courseId` (a bare course id — NOT tied to any particular play's
 * date/score) is the/a physical unit `member` names, under `unit`. Handles
 * the composite case (A2-18): the composite course id itself covers each
 * of its two nines' course-unit members. This is the shared core both
 * `playMatchesMember` (a real play, date/score already checked by the
 * caller) and `aggregates.ts`'s `field: 'trail'` lookup (no play at all,
 * just "does this trail's roster include this course anywhere") need —
 * factored out so the two never drift.
 */
export function memberCoversCourseId(
  courseId: string,
  member: RosterMember,
  unit: RosterVersion["completionUnit"],
  ctx: CompletionContext,
): boolean {
  const resolvedCourseId = resolveId(ctx, courseId);
  // A2-18: "a play on the composite satisfies the composite AND BOTH
  // NINES as roster members" — so the composite's `composite: [a, b]`
  // pair is read off the PLAY's own course (`resolvedCourseId`), and a
  // member naming either nine (`resolved`) matches it. (Not the other way
  // around — a nine's own `courseMeta` carries no `composite` field at
  // all; only the 18-hole composite course does.)
  const matchesAnyOf = (courseIds: string[]): boolean =>
    courseIds.some((id) => {
      const resolved = resolveId(ctx, id);
      if (resolved === resolvedCourseId) return true;
      const composite = courseMeta(ctx, resolvedCourseId)?.composite;
      return composite !== undefined && composite.includes(resolved as CourseId);
    });

  switch (unit) {
    case "facility": {
      if (member.unit !== "facility") return false;
      const memberFacility = resolveId(ctx, member.facilityId);
      return facilityOfCourse(ctx, resolvedCourseId) === memberFacility;
    }
    case "course": {
      if (member.unit !== "course") return false;
      if ("courseId" in member) return matchesAnyOf([member.courseId]);
      return matchesAnyOf(member.anyOf);
    }
    case "hole": {
      // "the course containing that signature hole has a qualifying play"
      // (§4.3) — the specific hole is cosmetic, so this is a course match.
      if (member.unit !== "hole") return false;
      return matchesAnyOf([member.courseId]);
    }
  }
}

/** Whether `play` (already ledger-resolved) is a play AT the physical unit
 * `member` names, under `version.completionUnit`. */
export function playMatchesMember(
  play: Play,
  member: RosterMember,
  unit: RosterVersion["completionUnit"],
  ctx: CompletionContext,
): boolean {
  return memberCoversCourseId(play.courseId, member, unit, ctx);
}

export interface MemberSatisfactionResult {
  satisfied: boolean;
  /** The earliest qualifying play date, when satisfied — used by
   * `trailCompleteWithin`/`inOrder` below. */
  earliestQualifyingDate?: IsoDate;
}

/**
 * §8.2's core per-member rule (line 1941-1946): a member m of version V is
 * satisfied by any play at m with `score_badge ≥ 0.50` whose facility-local
 * `play_date` (a) is on/after V's `trackingStartsOn` if set, and (b) is
 * before m's derived `removed_on`, if m has been dropped from the latest
 * version.
 */
export function isMemberSatisfied(
  member: RosterMember,
  version: RosterVersion,
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  /** `true` selects money-rule-qualifying plays instead of badge-level
   * ones — used only by the `RuleExpr` evaluator (`rule-expr-eval.ts`)
   * when this aggregate occurrence is POSITIVE in a money-mode rule
   * (§4.1 line 629-643: "the caller sets the evaluation mode... a positive
   * occurrence counts only money-rule plays"). §8.2's own completion rule
   * (a badge, never an offer) always calls this with the default `false`. */
  money = false,
): MemberSatisfactionResult {
  const memberFacilityId = physicalFacilityIdOfMember(member, ctx);
  const removedOn = deriveRemovedOn(memberFacilityId, version.version, allVersions, ctx);
  const qualifyingDates: IsoDate[] = [];
  for (const play of plays) {
    if (money ? play.moneyQualifies !== true : play.scoreBadge < BADGE_THRESHOLD) continue;
    if (version.trackingStartsOn && play.localDate < version.trackingStartsOn) continue;
    if (removedOn && !(play.localDate < removedOn)) continue;
    if (!playMatchesMember(play, member, version.completionUnit, ctx)) continue;
    qualifyingDates.push(play.localDate);
  }
  if (qualifyingDates.length === 0) return { satisfied: false };
  qualifyingDates.sort();
  return { satisfied: true, earliestQualifyingDate: qualifyingDates[0]! };
}

/* ------------------------------------------------------------------ */
/* Version / trail completion                                          */
/* ------------------------------------------------------------------ */

export interface VersionCompletionResult {
  complete: boolean;
  satisfiedCount: number;
  requiredCount: number;
  /** Per-member results, in `version.members` order — used by callers
   * that need to know WHICH members are still missing (e.g. a Wallet
   * "names the missing stop" UI, O19). */
  members: MemberSatisfactionResult[];
}

export function requiredCountOf(
  rule: RosterVersion["completionRule"],
  memberCount: number,
): number {
  return rule.kind === "all" ? memberCount : rule.n;
}

export function evaluateVersionCompletion(
  version: RosterVersion,
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  money = false,
): VersionCompletionResult {
  const members = version.members.map((m) =>
    isMemberSatisfied(m, version, allVersions, plays, ctx, money),
  );
  const satisfiedCount = members.filter((r) => r.satisfied).length;
  const requiredCount = requiredCountOf(version.completionRule, version.members.length);
  return { complete: satisfiedCount >= requiredCount, satisfiedCount, requiredCount, members };
}

/** `trailComplete(trailId)`: "∃V complete" (§4.1 line 597). */
export function isTrailComplete(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  money = false,
): boolean {
  return allVersions.some(
    (v) => evaluateVersionCompletion(v, allVersions, plays, ctx, money).complete,
  );
}

/**
 * `trailProgress(trailId)`: "the maximum over published roster versions V
 * of (members satisfied in V) ÷ (members V requires)... capped at 1"
 * (§4.1 line 596).
 */
export function trailProgress(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  money = false,
): number {
  let best = 0;
  for (const v of allVersions) {
    const result = evaluateVersionCompletion(v, allVersions, plays, ctx, money);
    const share = result.requiredCount === 0 ? 0 : result.satisfiedCount / result.requiredCount;
    if (share > best) best = share;
  }
  return Math.min(best, 1);
}

/**
 * `trailCompleteWithin(trailId, days)`: "∃V, and one qualifying play per
 * member V requires, whose facility-local dates all fall within `days` of
 * each other" (§4.1 line 598). Each member's EARLIEST qualifying play date
 * is its representative (the date most likely to fit inside any feasible
 * window); for `n-of-m`, a sliding window over the sorted representative
 * dates checks whether at least `n` of them fit within `days`.
 */
export function trailCompleteWithin(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  days: number,
  money = false,
): boolean {
  return allVersions.some((v) => {
    const result = evaluateVersionCompletion(v, allVersions, plays, ctx, money);
    if (!result.complete) return false;
    const dates = result.members
      .map((m) => m.earliestQualifyingDate)
      .filter((d): d is IsoDate => d !== undefined)
      .sort();
    if (dates.length < result.requiredCount) return false;
    for (let i = 0; i + result.requiredCount - 1 < dates.length; i += 1) {
      const windowStart = dates[i]!;
      const windowEnd = dates[i + result.requiredCount - 1]!;
      if (daysBetween(windowStart, windowEnd) <= days) return true;
    }
    return false;
  });
}

function daysBetween(a: IsoDate, b: IsoDate): number {
  const msPerDay = 24 * 60 * 60 * 1000;
  return Math.abs(Date.parse(b) - Date.parse(a)) / msPerDay;
}

/**
 * `inOrder(trailId)`: "∃V that has `stopOrder` and is complete, where the
 * first qualifying play at each stop falls on or after the first
 * qualifying play at the previous stop" (§4.1 line 599). A version whose
 * members don't ALL carry `stopOrder` cannot be evaluated for order and is
 * skipped (the aggregate is about versions that opt into ordering).
 */
export function inOrder(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  money = false,
): boolean {
  return allVersions.some((v) => {
    if (!v.members.every((m) => m.stopOrder !== undefined)) return false;
    const result = evaluateVersionCompletion(v, allVersions, plays, ctx, money);
    if (!result.complete) return false;
    const ordered = v.members
      .map((m, i) => ({ stopOrder: m.stopOrder!, result: result.members[i]! }))
      .sort((a, b) => a.stopOrder - b.stopOrder);
    for (let i = 1; i < ordered.length; i += 1) {
      const prevDate = ordered[i - 1]!.result.earliestQualifyingDate;
      const curDate = ordered[i]!.result.earliestQualifyingDate;
      if (!prevDate || !curDate) return false;
      if (curDate < prevDate) return false;
    }
    return true;
  });
}

/* ------------------------------------------------------------------ */
/* Marker roster (§4.3)                                                 */
/* ------------------------------------------------------------------ */

/**
 * "With `markerUnit: 'facility'`... the marker roster of version V is the
 * set of **distinct facilities** that host a member of V" (§4.3 line 738).
 * `markerUnit` is currently always `'facility'` (§4.1: "the default and,
 * in v1, the only value") so this does not branch on it.
 */
export function markerRosterOf(version: RosterVersion, ctx: CompletionContext): FacilityId[] {
  const seen = new Set<string>();
  const out: FacilityId[] = [];
  for (const member of version.members) {
    const facilityId = physicalFacilityIdOfMember(member, ctx);
    if (facilityId && !seen.has(facilityId)) {
      seen.add(facilityId);
      out.push(facilityId);
    }
  }
  return out;
}

/** Whether `facilityId` has a qualifying (badge-level, respecting the
 * version's `trackingStartsOn`) play at any of its courses — the same
 * date-bounding `isMemberSatisfied` applies, specialised to a bare
 * facility id (used for the marker roster, which is always facility-unit
 * regardless of the trail's own `completionUnit`). Exported for
 * `markerCredits` (`aggregates.ts`), which needs the identical rule. */
export function isFacilityCreditedByPlay(
  facilityId: FacilityId,
  version: RosterVersion,
  plays: Play[],
  ctx: CompletionContext,
  requireMoney: boolean,
): boolean {
  return plays.some((play) => {
    if (requireMoney ? play.moneyQualifies !== true : play.scoreBadge < BADGE_THRESHOLD) {
      return false;
    }
    if (version.trackingStartsOn && play.localDate < version.trackingStartsOn) return false;
    return facilityOfCourse(ctx, play.courseId) === facilityId;
  });
}

/**
 * `markerSetComplete(trailId)`: "∃V whose marker roster is covered under
 * V's `markerRule`" (§4.1 line 605). "Covered" is read as the same kind of
 * play-based crediting `isMemberSatisfied` uses for completion (§8.2's own
 * "the marker set (§4.6) and the badge reach the same verdict for the
 * same member set" fixture, AT(6)), not a purchase — purchases are the
 * SEPARATE O19 special-marker leg (`specialMarkerEntitlement` below).
 */
export function markerSetComplete(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  money = false,
): boolean {
  return allVersions.some((v) => {
    const roster = markerRosterOf(v, ctx);
    const creditedCount = roster.filter((f) =>
      isFacilityCreditedByPlay(f, v, plays, ctx, money),
    ).length;
    const required = requiredCountOf(v.markerRule, roster.length);
    return creditedCount >= required;
  });
}

/* ------------------------------------------------------------------ */
/* O19: the special-marker entitlement                                  */
/* ------------------------------------------------------------------ */

export interface SpecialMarkerEntitlementResult {
  entitled: boolean;
  /** The version the entitlement was (or would be) judged on — `undefined`
   * when no single version satisfies both legs (AT(6): "both legs must
   * hold on the SAME V"). */
  version?: number;
  missingPurchases: FacilityId[];
  missingMoneyPlays: FacilityId[];
}

/**
 * O19 (§4.6, default `true`): "The special marker needs a valid marker
 * purchase at every marker-roster facility **and** a qualifying (money-
 * mode) play at every member... both on the same roster version." With
 * `markerRequiresCompletion: false`, only the purchase leg is required
 * (§4.6's per-trail toggle).
 *
 * **Both legs are judged on ONE version** — this function tries every
 * published version and returns the first where both legs hold (or, with
 * the toggle off, where the purchase leg alone holds); a trail where leg 1
 * holds on V1 and leg 2 only on V2 is correctly NOT entitled (AT(6): "one
 * leg on V1 and the other only on V2 → No entitlement").
 *
 * See this module's doc for the `trail_programme.starts_on` simplification
 * (both legs use `version.trackingStartsOn`, not a separate programme
 * date).
 */
export function specialMarkerEntitlement(
  allVersions: RosterVersion[],
  plays: Play[],
  purchases: MarkerPurchase[],
  ctx: CompletionContext,
  markerRequiresCompletion = true,
): SpecialMarkerEntitlementResult {
  let bestMissingPurchases: FacilityId[] = [];
  let bestMissingMoneyPlays: FacilityId[] = [];
  for (const v of allVersions) {
    const roster = markerRosterOf(v, ctx);
    const missingPurchases = roster.filter(
      (f) => !hasPurchase(f, v, purchases),
    );
    const missingMoneyPlays = markerRequiresCompletion
      ? roster.filter((f) => !isFacilityCreditedByPlay(f, v, plays, ctx, true))
      : [];
    if (missingPurchases.length === 0 && missingMoneyPlays.length === 0) {
      return { entitled: true, version: v.version, missingPurchases: [], missingMoneyPlays: [] };
    }
    // Keep the best (fewest-missing) attempt across versions, purely for a
    // more useful "what's missing" report when nothing is entitled.
    if (
      bestMissingPurchases.length + bestMissingMoneyPlays.length === 0 ||
      missingPurchases.length + missingMoneyPlays.length <
        bestMissingPurchases.length + bestMissingMoneyPlays.length
    ) {
      bestMissingPurchases = missingPurchases;
      bestMissingMoneyPlays = missingMoneyPlays;
    }
  }
  return {
    entitled: false,
    missingPurchases: bestMissingPurchases,
    missingMoneyPlays: bestMissingMoneyPlays,
  };
}

function hasPurchase(
  facilityId: FacilityId,
  version: RosterVersion,
  purchases: MarkerPurchase[],
): boolean {
  return purchases.some((p) => {
    if (version.trackingStartsOn && p.localDate < version.trackingStartsOn) return false;
    return p.facilityId === facilityId;
  });
}

/* ------------------------------------------------------------------ */
/* played / uniqueCourses / monthlyStreak (simple, no roster needed)    */
/* ------------------------------------------------------------------ */

/** `played(courseId)`: "Qualifying plays at that course" (§4.1 line 595) —
 * badge-level (`scoreBadge >= 0.50`) unless `money` is true, in which case
 * only `moneyQualifies` plays count (§4.1 line 629-632, "the caller sets
 * the evaluation mode"). */
export function played(courseId: CourseId, plays: Play[], ctx: CompletionContext, money = false): number {
  const resolvedTarget = resolveId(ctx, courseId);
  return plays.filter((p) => {
    if (money ? p.moneyQualifies !== true : p.scoreBadge < BADGE_THRESHOLD) return false;
    return resolveId(ctx, p.courseId) === resolvedTarget;
  }).length;
}

/** `uniqueCourses`: "Distinct qualifying played courses; a composite play
 * counts once" (§4.1 line 600) — a composite play already only ever
 * carries ONE `courseId` (the composite's own), so "counts once" is
 * automatic here; the "also satisfies both nines as roster members" half
 * of A2-18 is `playMatchesMember`'s concern, not this aggregate's. */
export function uniqueCourses(plays: Play[], ctx: CompletionContext, money = false): number {
  const set = new Set<string>();
  for (const p of plays) {
    if (money ? p.moneyQualifies !== true : p.scoreBadge < BADGE_THRESHOLD) continue;
    set.add(resolveId(ctx, p.courseId));
  }
  return set.size;
}

/** `monthlyStreak`: "The longest run of consecutive calendar months, in
 * facility-local dates, with ≥ 1 qualifying play" (§4.1 line 606). */
export function monthlyStreak(plays: Play[], money = false): number {
  const months = new Set<string>();
  for (const p of plays) {
    if (money ? p.moneyQualifies !== true : p.scoreBadge < BADGE_THRESHOLD) continue;
    months.add(p.localDate.slice(0, 7)); // "YYYY-MM"
  }
  const sorted = [...months].sort();
  let best = 0;
  let current = 0;
  let prevKey: number | undefined;
  for (const ym of sorted) {
    const parts = ym.split("-");
    const y = Number(parts[0]);
    const m = Number(parts[1]);
    const key = y * 12 + (m - 1);
    if (prevKey !== undefined && key === prevKey + 1) {
      current += 1;
    } else {
      current = 1;
    }
    prevKey = key;
    if (current > best) best = current;
  }
  return best;
}
