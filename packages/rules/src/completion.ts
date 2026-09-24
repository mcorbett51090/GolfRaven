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
 * named fields directly. Beyond that literal four:
 *
 * 1. `Play.moneyQualifies` — a boolean the (out-of-scope, P3) money-rule
 *    scorer would have already computed.
 * 2. `MarkerPurchase` (a separate, much smaller input: `facilityId` +
 *    `localDate`) — the O19 fixtures need "a purchase at every marker-
 *    roster facility" as a distinct leg from "money-mode plays at every
 *    member".
 * 3. `EvalOptions.programmeStartsOn` (gate review B2) — §4.6's
 *    `trail_programme.starts_on`, a bound that governs ONLY money-mode
 *    qualification, kept strictly separate from `RosterVersion.trackingStartsOn`
 *    (the badge bound): "a backdated badge never backdates an offer or a
 *    marker" (§8.2 line ≈1956). Passed explicitly by the caller — never
 *    inferred from `trackingStartsOn`.
 * 4. `EvalOptions.badgeThreshold` (gate review S4) — `AchievementDef.minConfidence`
 *    ("thresholds are data", §4.5 line ≈1024). Defaults to `BADGE_THRESHOLD`
 *    (0.50, §8.2's own literal "score_badge ≥ 0.50") when the caller has no
 *    achievement-specific threshold to apply.
 *
 * **Qualification (S2, S4).** A play "qualifies" for a given `EvalOptions`
 * as follows:
 *   - money mode (`opts.money`): `play.moneyQualifies === true` AND the
 *     play's date clears BOTH `version.trackingStartsOn` (if set) AND
 *     `opts.programmeStartsOn` (if set) — both bounds apply together
 *     (point 3 above).
 *   - non-money mode (plain badge-mode evaluation, OR a NEGATIVE occurrence
 *     inside a money-mode `RuleExpr`, S2): `play.scoreBadge >= threshold OR
 *     play.moneyQualifies === true` — meeting the stricter money bar always
 *     counts as meeting the weaker badge one too, and the play's date only
 *     needs to clear `version.trackingStartsOn` (never `programmeStartsOn`,
 *     which is a money-only bound).
 *   - the course played must be `verified` (`CourseMeta.verified`, S4;
 *     §4.1 line ≈589: "Qualifying... at a verified course; stub-course
 *     plays qualify only after promotion", G3-01) — checked identically in
 *     both modes.
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
} from "@golfraven/catalog";

/** §8.2 line 1942: "any play at m with `score_badge ≥ 0.50`" — the DEFAULT
 * badge threshold, overridden per achievement by `EvalOptions.badgeThreshold`
 * (`AchievementDef.minConfidence`, S4). */
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
   * package; a device's own time zone plays no part here). */
  localDate: IsoDate;
  /** "evidence class" (task wording) — §4.3's `course_disambiguated_by`.
   * Defaults to `'geometry'` when omitted. */
  courseDisambiguatedBy?: CourseDisambiguatedBy;
  /** "score" (task wording) — `score_badge`. */
  scoreBadge: number;
  /** Whether this SAME play also meets the §4.5 money rule (out of
   * scope). Defaults to `false`. */
  moneyQualifies?: boolean;
}

/** The §4.6/O19 purchase leg. */
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
  /** Mirrors `Course.composite` (§4.1). */
  composite?: [CourseId, CourseId];
  /** S4 (gate review): "a qualifying play must be at a verified course"
   * (§4.1 line ≈589, G3-01). Defaults to `true` when omitted so existing
   * synthetic fixtures that predate this field (and any caller that
   * genuinely doesn't model verification) keep working — an explicit
   * `verified: false` is what opts a course OUT. */
  verified?: boolean;
}

/** The course metadata `packages/rules` needs (never fetched — supplied by
 * the caller, keyed by `CourseId`). `ledger` is optional; omitted, every id
 * is taken as already resolved (no merge to apply). */
export interface CompletionContext {
  courses: Record<string, CourseMeta>;
  ledger?: IdLedger;
}

/**
 * Shared knobs every completion/aggregate function below accepts (gate
 * review B2/S4 — see this module's doc for the full qualification rule).
 */
export interface EvalOptions {
  /** Use money-qualifying plays (and `programmeStartsOn`) instead of
   * badge-level ones. Default `false`. */
  money?: boolean;
  /** B2: an additional lower bound applied ONLY when `money` is true, in
   * ADDITION to (never instead of) each version's own `trackingStartsOn`.
   * Never applied in non-money mode. */
  programmeStartsOn?: IsoDate;
  /** S4: `AchievementDef.minConfidence` — the `score_badge` threshold a
   * play must meet to qualify in non-money mode. Defaults to
   * `BADGE_THRESHOLD` (0.50). Never applied in money mode (money mode
   * uses the already-thresholded `moneyQualifies` boolean directly). */
  badgeThreshold?: number;
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

function isCourseVerified(ctx: CompletionContext, courseId: string): boolean {
  const meta = courseMeta(ctx, courseId);
  return meta?.verified !== false;
}

/**
 * The single play-qualification predicate every function below (and
 * `aggregates.ts`'s field-keyed aggregates) shares (module doc
 * "Qualification"). `trackingStartsOn` is the version's own bound (always
 * consulted; pass `undefined` for a roster-agnostic global aggregate like
 * `uniqueCourses`); `opts.programmeStartsOn` is consulted ADDITIONALLY,
 * only in money mode. Exported so `aggregates.ts` never re-derives this
 * logic (S3/S4 both apply there too: merge resolution AND qualification
 * are orthogonal, but qualification itself must be identical everywhere).
 */
export function playQualifies(
  play: Play,
  ctx: CompletionContext,
  opts: EvalOptions,
  trackingStartsOn: IsoDate | undefined,
): boolean {
  if (!isCourseVerified(ctx, play.courseId)) return false;
  if (trackingStartsOn && play.localDate < trackingStartsOn) return false;
  if (opts.money) {
    if (play.moneyQualifies !== true) return false;
    if (opts.programmeStartsOn && play.localDate < opts.programmeStartsOn) return false;
    return true;
  }
  const threshold = opts.badgeThreshold ?? BADGE_THRESHOLD;
  // S2: a non-money query (plain badge mode, or a negative occurrence
  // inside a money-mode RuleExpr) counts scoreBadge >= threshold OR
  // moneyQualifies — meeting the stricter money bar always also meets the
  // weaker badge one.
  return play.scoreBadge >= threshold || play.moneyQualifies === true;
}

/* ------------------------------------------------------------------ */
/* A2-01: the user-pick one-per-facility-per-date guard                */
/* ------------------------------------------------------------------ */

/**
 * "A `user` pick yields at most one course per facility per facility-local
 * date. A second, different pick on the same date replaces the first
 * (audited)" (§4.3). Only `courseDisambiguatedBy: 'user'` plays are
 * subject to this. "Replaces" is read as last-write-wins on **input
 * order**.
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
/* Physical member identity + removedOn (§4.3)                          */
/* ------------------------------------------------------------------ */

/** A roster member's physical identity, for cross-version "is this the
 * same stop" comparisons (§4.3: "re-typing is not a drop... a member
 * counts as dropped only when no member of the later version covers the
 * same physical unit").
 *
 * S1 (gate review): keyed on the FACILITY only when the member itself is
 * facility-unit; a course (or hole) member's physical identity is the
 * COURSE — two different courses at the same facility are two different
 * physical stops, so swapping one for the other at a course-unit trail IS
 * a drop, even though the facility itself is unchanged. `anyOf`'s
 * identity is the whole listed course set (any one of them still being
 * coverable counts as "still present", mirroring how `anyOf` itself is
 * satisfied).
 */
export type PhysicalIdentity =
  | { kind: "facility"; facilityId: FacilityId }
  | { kind: "course"; courseIds: string[] };

export function physicalIdentityOfMember(
  member: RosterMember,
  ctx: CompletionContext,
): PhysicalIdentity | undefined {
  switch (member.unit) {
    case "facility": {
      const resolved = resolveId(ctx, member.facilityId) as FacilityId;
      return { kind: "facility", facilityId: resolved };
    }
    case "course": {
      if ("courseId" in member) return { kind: "course", courseIds: [resolveId(ctx, member.courseId)] };
      return { kind: "course", courseIds: member.anyOf.map((id) => resolveId(ctx, id)) };
    }
    case "hole":
      return { kind: "course", courseIds: [resolveId(ctx, member.courseId)] };
  }
}

/** Backward-compatible convenience: the FACILITY a member resolves to,
 * regardless of unit (used by the marker roster, which is always
 * facility-level per §4.3, and by `deriveRemovedOn`'s facility-identity
 * branch). */
export function physicalFacilityIdOfMember(
  member: RosterMember,
  ctx: CompletionContext,
): FacilityId | undefined {
  switch (member.unit) {
    case "facility":
      return (resolveId(ctx, member.facilityId) as FacilityId) ?? member.facilityId;
    case "course": {
      if ("courseId" in member) return facilityOfCourse(ctx, member.courseId);
      for (const courseId of member.anyOf) {
        const f = facilityOfCourse(ctx, courseId);
        if (f) return f;
      }
      return undefined;
    }
    case "hole":
      return facilityOfCourse(ctx, member.courseId);
  }
}

/** Whether `identity` is still covered by SOME member of `version` — the
 * shared presence test `deriveRemovedOn` walks forward with. */
function isIdentityPresentIn(
  identity: PhysicalIdentity,
  version: RosterVersion,
  ctx: CompletionContext,
): boolean {
  if (identity.kind === "facility") {
    return version.members.some((m) => physicalFacilityIdOfMember(m, ctx) === identity.facilityId);
  }
  return identity.courseIds.some((courseId) =>
    version.members.some((m) => memberCoversCourseId(courseId, m, version.completionUnit, ctx)),
  );
}

/**
 * §4.3: "the import derives each member's `removed_on` (the
 * `effectiveFrom` of the first later version that drops it, reset to null
 * if a later version re-adds it)." A single forward scan (ascending
 * version number) — equivalent to the plan's two-step description, since
 * `removed_on` is only ever READ when the member is absent from the
 * *latest* version (§8.2 line ≈1944).
 */
export function deriveRemovedOn(
  identity: PhysicalIdentity | undefined,
  fromVersion: number,
  allVersions: RosterVersion[],
  ctx: CompletionContext,
): IsoDate | undefined {
  if (!identity) return undefined;
  const later = [...allVersions]
    .filter((v) => v.version > fromVersion)
    .sort((a, b) => a.version - b.version);
  let absentSince: IsoDate | undefined;
  for (const v of later) {
    if (isIdentityPresentIn(identity, v, ctx)) {
      absentSince = undefined;
    } else if (absentSince === undefined) {
      absentSince = v.effectiveFrom;
    }
  }
  return absentSince;
}

/** `removed_on` for a bare FACILITY id (S1: "marker credit and purchases
 * must respect `removed_on` too", §4.6 line ≈1155) — the facility's own
 * `removed_on`, computed the identical way a facility-unit member's would
 * be. */
function deriveFacilityRemovedOn(
  facilityId: FacilityId,
  fromVersion: number,
  allVersions: RosterVersion[],
  ctx: CompletionContext,
): IsoDate | undefined {
  return deriveRemovedOn({ kind: "facility", facilityId }, fromVersion, allVersions, ctx);
}

/* ------------------------------------------------------------------ */
/* Member satisfaction (§8.2 core rule)                                 */
/* ------------------------------------------------------------------ */

/**
 * Whether `courseId` (a bare course id) is the/a physical unit `member`
 * names, under `unit`. Handles the composite case (A2-18): the composite
 * course id itself covers each of its two nines' course-unit members.
 */
export function memberCoversCourseId(
  courseId: string,
  member: RosterMember,
  unit: RosterVersion["completionUnit"],
  ctx: CompletionContext,
): boolean {
  const resolvedCourseId = resolveId(ctx, courseId);
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
      if (member.unit !== "hole") return false;
      return matchesAnyOf([member.courseId]);
    }
  }
}

/** Whether `play` is a play AT the physical unit `member` names, under
 * `version.completionUnit`. */
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
  /** Every qualifying play date, sorted ascending (B3: `trailCompleteWithin`
   * needs the FULL set, not just the earliest, to search candidate
   * windows correctly). Empty when not satisfied. */
  qualifyingDates: IsoDate[];
  /** The earliest qualifying play date, when satisfied — used by
   * `inOrder`. `undefined` when not satisfied. */
  earliestQualifyingDate?: IsoDate;
}

/**
 * §8.2's core per-member rule (line 1941-1946): a member m of version V is
 * satisfied by any QUALIFYING play at m (module doc's "Qualification")
 * whose facility-local `play_date` is before m's derived `removed_on`, if
 * m has been dropped from the latest version.
 */
export function isMemberSatisfied(
  member: RosterMember,
  version: RosterVersion,
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  opts: EvalOptions = {},
): MemberSatisfactionResult {
  const identity = physicalIdentityOfMember(member, ctx);
  const removedOn = deriveRemovedOn(identity, version.version, allVersions, ctx);
  const qualifyingDates: IsoDate[] = [];
  for (const play of plays) {
    if (!playQualifies(play, ctx, opts, version.trackingStartsOn)) continue;
    if (removedOn && !(play.localDate < removedOn)) continue;
    if (!playMatchesMember(play, member, version.completionUnit, ctx)) continue;
    qualifyingDates.push(play.localDate);
  }
  qualifyingDates.sort();
  if (qualifyingDates.length === 0) return { satisfied: false, qualifyingDates: [] };
  return { satisfied: true, qualifyingDates, earliestQualifyingDate: qualifyingDates[0]! };
}

/* ------------------------------------------------------------------ */
/* Version / trail completion                                          */
/* ------------------------------------------------------------------ */

export interface VersionCompletionResult {
  complete: boolean;
  satisfiedCount: number;
  requiredCount: number;
  /** Per-member results, in `version.members` order. */
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
  opts: EvalOptions = {},
): VersionCompletionResult {
  const members = version.members.map((m) => isMemberSatisfied(m, version, allVersions, plays, ctx, opts));
  const satisfiedCount = members.filter((r) => r.satisfied).length;
  const requiredCount = requiredCountOf(version.completionRule, version.members.length);
  return { complete: satisfiedCount >= requiredCount, satisfiedCount, requiredCount, members };
}

/** `trailComplete(trailId)`: "∃V complete" (§4.1 line 597). */
export function isTrailComplete(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  opts: EvalOptions = {},
): boolean {
  return allVersions.some((v) => evaluateVersionCompletion(v, allVersions, plays, ctx, opts).complete);
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
  opts: EvalOptions = {},
): number {
  let best = 0;
  for (const v of allVersions) {
    const result = evaluateVersionCompletion(v, allVersions, plays, ctx, opts);
    const share = result.requiredCount === 0 ? 0 : result.satisfiedCount / result.requiredCount;
    if (share > best) best = share;
  }
  return Math.min(best, 1);
}

/**
 * `trailCompleteWithin(trailId, days)`: "∃V, and one qualifying play per
 * member V requires, whose facility-local dates all fall within `days` of
 * each other" (§4.1 line 598).
 *
 * B3 (gate review): "SOME one qualifying play per member inside a window
 * of `days`, not each member's earliest play." Every candidate window is
 * searched — a classic minimum-window-covering-K-groups sliding window
 * over ALL (member, date) pairs (not just each member's earliest date):
 * sort every qualifying date across every member, slide a window, and
 * track how many DISTINCT members have at least one date currently inside
 * it. `n-of-m`'s sliding-window count check is kept (only `requiredCount`
 * distinct members need to be covered, not all of them).
 */
export function trailCompleteWithin(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  days: number,
  opts: EvalOptions = {},
): boolean {
  return allVersions.some((v) => {
    const result = evaluateVersionCompletion(v, allVersions, plays, ctx, opts);
    if (!result.complete) return false;
    const points: { memberIndex: number; date: IsoDate }[] = [];
    result.members.forEach((m, i) => {
      for (const date of m.qualifyingDates) points.push({ memberIndex: i, date });
    });
    points.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));

    const countByMember = new Map<number, number>();
    let distinctInWindow = 0;
    let left = 0;
    for (let right = 0; right < points.length; right += 1) {
      const p = points[right]!;
      const nextCount = (countByMember.get(p.memberIndex) ?? 0) + 1;
      countByMember.set(p.memberIndex, nextCount);
      if (nextCount === 1) distinctInWindow += 1;
      while (daysBetween(points[left]!.date, p.date) > days) {
        const lp = points[left]!;
        const c = countByMember.get(lp.memberIndex)! - 1;
        countByMember.set(lp.memberIndex, c);
        if (c === 0) distinctInWindow -= 1;
        left += 1;
      }
      if (distinctInWindow >= result.requiredCount) return true;
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
 * qualifying play at the previous stop" (§4.1 line 599).
 */
export function inOrder(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  opts: EvalOptions = {},
): boolean {
  return allVersions.some((v) => {
    if (!v.members.every((m) => m.stopOrder !== undefined)) return false;
    const result = evaluateVersionCompletion(v, allVersions, plays, ctx, opts);
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

/** "the marker roster of version V is the set of **distinct facilities**
 * that host a member of V" (§4.3 line 738). */
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

/** Whether `facilityId` has a qualifying play at any of its courses,
 * respecting `removed_on` for the FACILITY itself (S1). */
export function isFacilityCreditedByPlay(
  facilityId: FacilityId,
  version: RosterVersion,
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  opts: EvalOptions = {},
): boolean {
  const removedOn = deriveFacilityRemovedOn(facilityId, version.version, allVersions, ctx);
  return plays.some((play) => {
    if (!playQualifies(play, ctx, opts, version.trackingStartsOn)) return false;
    if (removedOn && !(play.localDate < removedOn)) return false;
    return facilityOfCourse(ctx, play.courseId) === facilityId;
  });
}

/**
 * `markerSetComplete(trailId)`: "∃V whose marker roster is covered under
 * V's `markerRule`" (§4.1 line 605).
 */
export function markerSetComplete(
  allVersions: RosterVersion[],
  plays: Play[],
  ctx: CompletionContext,
  opts: EvalOptions = {},
): boolean {
  return allVersions.some((v) => {
    const roster = markerRosterOf(v, ctx);
    const creditedCount = roster.filter((f) =>
      isFacilityCreditedByPlay(f, v, allVersions, plays, ctx, opts),
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
  /** The version the entitlement was (or would be) judged on. */
  version?: number;
  missingPurchases: FacilityId[];
  missingMoneyPlays: FacilityId[];
}

/**
 * O19 (§4.6, default `true`): "The special marker needs a valid marker
 * purchase at every marker-roster facility **and** a qualifying (money-
 * mode) play at every member... both on the same roster version."
 *
 * B1 (gate review): the money leg is judged PER COMPLETION MEMBER, under
 * V's own `completionRule` (`evaluateVersionCompletion(v, …, {money:
 * true, …}).complete`) — NOT per marker-roster facility. Two course
 * members sharing one facility, with a money play at only one of them,
 * must NOT be entitled just because "the facility" has some money play —
 * §4.6 (line ≈1142) says "a qualifying play at every MEMBER", and members
 * are completion-unit-typed, not always facility-grained. The FACILITY
 * report (`missingMoneyPlays`) is still facility-shaped for the Wallet UI
 * ("names the missing shop") — it's derived from which members failed,
 * mapped to their facilities, not from an independent facility-level
 * credit check.
 *
 * With `markerRequiresCompletion: false`, only the purchase leg is
 * required (§4.6's per-trail toggle).
 */
export function specialMarkerEntitlement(
  allVersions: RosterVersion[],
  plays: Play[],
  purchases: MarkerPurchase[],
  ctx: CompletionContext,
  markerRequiresCompletion = true,
  opts: Omit<EvalOptions, "money"> = {},
): SpecialMarkerEntitlementResult {
  let bestMissingPurchases: FacilityId[] = [];
  let bestMissingMoneyPlays: FacilityId[] = [];
  for (const v of allVersions) {
    const roster = markerRosterOf(v, ctx);
    const missingPurchases = roster.filter(
      (f) => !hasPurchase(f, v, allVersions, purchases, ctx, opts),
    );

    let missingMoneyPlays: FacilityId[] = [];
    if (markerRequiresCompletion) {
      const moneyResult = evaluateVersionCompletion(v, allVersions, plays, ctx, {
        ...opts,
        money: true,
      });
      const missingFacilities = new Set<string>();
      v.members.forEach((member, i) => {
        if (moneyResult.members[i]!.satisfied) return;
        const facilityId = physicalFacilityIdOfMember(member, ctx);
        if (facilityId) missingFacilities.add(facilityId);
      });
      missingMoneyPlays = [...missingFacilities] as FacilityId[];
      if (!moneyResult.complete && missingMoneyPlays.length === 0) {
        // n-of-m: every INDIVIDUAL member could show as "satisfied" while
        // the version is still short of `requiredCount` overall (e.g. one
        // member counted twice via a shared facility can't happen, but a
        // trail could require MORE satisfied members than are actually
        // satisfied even with none individually "missing" a facility of
        // its own — defensive fallback so the boolean and the report never
        // disagree: fall back to the whole roster when nothing more
        // specific can be named).
        missingMoneyPlays = roster;
      }
    }

    if (missingPurchases.length === 0 && missingMoneyPlays.length === 0) {
      return { entitled: true, version: v.version, missingPurchases: [], missingMoneyPlays: [] };
    }
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

/** A purchase leg check respecting `removed_on` (S1) and `programmeStartsOn`
 * (B2) for the facility, on top of the version's own `trackingStartsOn`. */
function hasPurchase(
  facilityId: FacilityId,
  version: RosterVersion,
  allVersions: RosterVersion[],
  purchases: MarkerPurchase[],
  ctx: CompletionContext,
  opts: Omit<EvalOptions, "money">,
): boolean {
  const removedOn = deriveFacilityRemovedOn(facilityId, version.version, allVersions, ctx);
  return purchases.some((p) => {
    if (version.trackingStartsOn && p.localDate < version.trackingStartsOn) return false;
    if (opts.programmeStartsOn && p.localDate < opts.programmeStartsOn) return false;
    if (removedOn && !(p.localDate < removedOn)) return false;
    return p.facilityId === facilityId;
  });
}

/* ------------------------------------------------------------------ */
/* played / uniqueCourses / monthlyStreak (simple, no roster needed)    */
/* ------------------------------------------------------------------ */

/** `played(courseId)`: "Qualifying plays at that course" (§4.1 line 595). */
export function played(
  courseId: CourseId,
  plays: Play[],
  ctx: CompletionContext,
  opts: EvalOptions = {},
): number {
  const resolvedTarget = resolveId(ctx, courseId);
  return plays.filter((p) => {
    if (!playQualifies(p, ctx, opts, undefined)) return false;
    return resolveId(ctx, p.courseId) === resolvedTarget;
  }).length;
}

/** `uniqueCourses`: "Distinct qualifying played courses; a composite play
 * counts once" (§4.1 line 600). */
export function uniqueCourses(plays: Play[], ctx: CompletionContext, opts: EvalOptions = {}): number {
  const set = new Set<string>();
  for (const p of plays) {
    if (!playQualifies(p, ctx, opts, undefined)) continue;
    set.add(resolveId(ctx, p.courseId));
  }
  return set.size;
}

/** `monthlyStreak`: "The longest run of consecutive calendar months, in
 * facility-local dates, with ≥ 1 qualifying play" (§4.1 line 606). */
export function monthlyStreak(plays: Play[], ctx: CompletionContext, opts: EvalOptions = {}): number {
  const months = new Set<string>();
  for (const p of plays) {
    if (!playQualifies(p, ctx, opts, undefined)) continue;
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
