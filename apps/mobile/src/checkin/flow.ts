/**
 * The foreground check-in (build plan §7.2 "I'm here", §7.4 step 5, §7.6 "Offline attestation"): from the player's tap to an outbox item.
 *
 * ORDER (each step can end the flow, and nothing is spent before it is needed):
 *   0. the build switch (`CHECKIN_UI_ENABLED`): off = refuse, nothing else runs, in particular NO permission prompt;
 *   1. signed in (a check-in is recorded for an account, never "for whoever signs in next"); a course the device has geometry for; a time zone for the facility's local date;
 *      the §4.3 one-pick guard at a multi-course site. All of this BEFORE the prompt: there is no point asking for location for a check-in that cannot be made;
 *   2. the permission: read without prompting, and only when the player has not decided is the system prompt shown (this function is only ever called from a button);
 *   3. a LIVE challenge, when online, taken BEFORE the fix with a short budget (see below); offline or slow, there is none and the fix is covered by a PREFETCHED one at enqueue;
 *   4. one foreground fix, validated: not simulated, accuracy present, its own time plausible and recent;
 *   5. matched to the course with `@golfraven/matching` (`match.ts`); outside = "not here" plus the nearby courses that do contain it;
 *   6. `enqueueEvidence`, which consumes ONE challenge for the fix (the live one when it covers the fix, else one prefetched, else none = the x0.6 penalty, visible in the result).
 *
 * WHY THE LIVE CHALLENGE COMES FIRST. The server accepts a fix as a co-signal for a challenge only when `challenge.issued_at <= fix.capturedAt <= challenge.expires_at`
 * (`consumeForFix`; recorded in the fixture's `vectors.checkinWindow`). A live challenge requested after the fix is issued after it and can never cover it. So: challenge, then fix, and the
 * live challenge is used only if the fix really lies inside its window (`liveCovers`); otherwise it is dropped (it expires unused after 120 s) and the pool is used.
 * Offline there is no live challenge by definition; `acquireForFix` then takes a prefetched one whose own window (`issuedAt <= capturedAt`, 24 h) contains the fix.
 *
 * `capturedAt` is the fix's own time, and `localDate` is derived from it in the facility's tz (`local-date.ts`), the same way the server derives it.
 *
 * Never throws: every failure is an outcome the screen has copy for.
 */
import { OutboxEnqueueError, type OutboxItem } from "../outbox";
import type { CatalogIndex, CourseEntry } from "../browse";
import type { LiveChallenge } from "../challenges";
import { parseEvidencePayload, type EvidenceEnqueued, type EvidenceInput, type EvidencePayload, type FixChallenge } from "../evidence";
import type { LocationPort } from "./location";
import { localDateInTz } from "./local-date";
import { ensureForegroundLocation } from "./permission";
import { candidateFor, matchCourse, nearbyCourses, pickGuard, type DeviceFix, type FacilityPick, type NearbyCourse } from "./match";

export interface CheckInTiming {
  liveBudgetMs: number;
  fixTimeoutMs: number;
  maxFixAgeMs: number;
  maxFixAheadMs: number;
}

export const CHECKIN_TIMING: Readonly<CheckInTiming> = {
  /** How long the live challenge (request + attested redemption) may take before the check-in carries on with the pool. */
  liveBudgetMs: 8_000,
  /** How long to wait for a fix. */
  fixTimeoutMs: 20_000,
  /** A fix whose own time is older than this when read is not "here and now" (a cached position). */
  maxFixAgeMs: 60_000,
  /** A fix stamped further in the future than this is a clock problem. */
  maxFixAheadMs: 5_000,
};

const MIN_EPOCH_MS = Date.UTC(2020, 0, 1);
const MAX_EPOCH_MS = Date.UTC(2100, 0, 1);
const SITE_VERSION = /^\d{8}-[0-9a-f]{7}$/;

export type CheckInOutcome =
  | { kind: "queued"; item: OutboxItem; penalty: boolean; challenge: "live" | "prefetched" | "none"; geometryKind: "polygon" | "radius"; capturedAt: number; accuracyMeters: number }
  | { kind: "disabled" }
  | { kind: "signed_out" }
  /** The signed-in account changed while the check-in ran (the fix can take seconds): nothing was recorded for either account (P4.2c-1). */
  | { kind: "account_changed" }
  | { kind: "no_geometry" }
  | { kind: "no_catalog" }
  | { kind: "no_timezone" }
  | { kind: "already_picked"; courseId: string }
  | { kind: "permission"; status: "denied" | "blocked" | "approximate" }
  | { kind: "services_off" }
  | { kind: "no_fix"; reason: "timeout" | "unavailable" | "invalid" }
  | { kind: "stale_fix" }
  | { kind: "simulated" }
  | { kind: "inaccurate"; accuracyMeters: number }
  | { kind: "not_here"; distanceMeters: number | null; nearby: NearbyCourse[] }
  | { kind: "failed"; message: string };

export interface CheckInDeps {
  /** `checkinUiAvailable()`: the build switch. */
  enabled: boolean;
  location: LocationPort;
  currentUserId: () => string | null;
  challenges: { acquireLive(owner: string, facilityId?: string): Promise<LiveChallenge | null> };
  enqueueEvidence: (input: EvidenceInput) => Promise<EvidenceEnqueued>;
  /** The signed-in user's recorded plays as `(facility, date, course)`, for the §4.3 one-pick guard. */
  existingPicks: (owner: string) => Promise<readonly FacilityPick[]>;
  /** The cached `manifest.sig.json` fields for `catalogVersion` (a catalog newer than the server's import is queued, not refused, only with it), or `null`. */
  manifestSig: (catalogVersion: string) => Promise<EvidencePayload["manifestSig"] | null>;
  newFixId: () => string;
  now: () => number;
  timing?: Partial<CheckInTiming>;
}

export interface CheckInInput {
  entry: CourseEntry;
  /** The site catalog version the screen is showing (the match is made against it). */
  catalogVersion: string;
  /** For the "did you mean" list when the fix is outside. */
  index?: CatalogIndex | null;
}

/** Resolves with `null` when `p` has not settled within `ms`. */
async function within<T>(p: Promise<T>, ms: number): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** True when a fix captured at `capturedAt` lies inside the window of a live challenge received at `receivedAt` and expiring at `expiresAt`: the server's
 * `issued_at <= capturedAt <= expires_at`, where `receivedAt` stands for `issued_at` (it is never earlier than it, so a fix at or after it is after the issue).
 *
 * CLOCK SKEW (known limit, behaviour kept): `receivedAt` is the DEVICE clock and the fix's `capturedAt` is the device clock too, while `issued_at` / `expires_at` are the SERVER's
 * clock. The comparison with `receivedAt` is therefore skew-free; the one against `expiresAt` (the server's clock, read from the response) is not: a device clock that runs fast
 * by more than the slack in the 120 s window would call a covered fix uncovered (the check-in then falls back to the pool, never to a wrong co-signal), and one that runs slow could call
 * an expired window open (the server then refuses the co-signal and the play counts without it). `IssuedChallenge` carries no `issuedAt` (id, nonce, expiresAt, kind), so there is no server
 * issue time to use instead of `receivedAt`; deriving one as `expiresAt - 120 s` would read the same skewed clock. */
export function liveCovers(live: Pick<LiveChallenge, "receivedAt" | "expiresAt">, capturedAt: number): boolean {
  return live.receivedAt <= capturedAt && capturedAt <= live.expiresAt;
}

/** The structural / timing validation of a fix as read at `now`: `null` when fine, else why not. */
export function fixProblem(f: { latitude: number; longitude: number; timestamp: number }, now: number, timing: Pick<CheckInTiming, "maxFixAgeMs" | "maxFixAheadMs"> = CHECKIN_TIMING): "invalid" | "stale" | null {
  if (!Number.isFinite(f.latitude) || !Number.isFinite(f.longitude) || f.latitude < -90 || f.latitude > 90 || f.longitude < -180 || f.longitude > 180) return "invalid";
  if (!Number.isFinite(f.timestamp) || f.timestamp < MIN_EPOCH_MS || f.timestamp >= MAX_EPOCH_MS) return "invalid";
  if (now - f.timestamp > timing.maxFixAgeMs || f.timestamp - now > timing.maxFixAheadMs) return "stale";
  return null;
}

/** The recorded plays of one owner as picks (a fix-bearing play carries its facility and local date in its payload; its course is the item's). */
export function picksFromItems(items: readonly OutboxItem[]): FacilityPick[] {
  const out: FacilityPick[] = [];
  for (const i of items) {
    if (i.courseId === null) continue;
    const p = parseEvidencePayload(i.payload);
    if (p.ok) out.push({ facilityId: p.payload.facilityId, localDate: p.payload.localDate, courseId: i.courseId });
  }
  return out;
}

function challengeKindOf(item: OutboxItem, fixId: string): "live" | "prefetched" | "none" {
  const p = parseEvidencePayload(item.payload);
  const c: FixChallenge | undefined = p.ok ? p.payload.challenges[fixId] : undefined;
  return c !== undefined && c.state !== "none" ? c.kind : "none";
}

/** Called from the "I'm here" button, never from startup. */
export async function runCheckIn(deps: CheckInDeps, input: CheckInInput): Promise<CheckInOutcome> {
  try {
    return await run(deps, input);
  } catch (e) {
    if (e instanceof OutboxEnqueueError) return { kind: e.code };
    return { kind: "failed", message: e instanceof Error ? e.message : String(e) };
  }
}

async function run(deps: CheckInDeps, input: CheckInInput): Promise<CheckInOutcome> {
  if (!deps.enabled) return { kind: "disabled" };
  const timing = { ...CHECKIN_TIMING, ...deps.timing };
  const { entry } = input;
  const owner = deps.currentUserId();
  if (owner === null || owner === "") return { kind: "signed_out" };
  if (!SITE_VERSION.test(input.catalogVersion)) return { kind: "no_catalog" };
  if (candidateFor(entry) === null) return { kind: "no_geometry" };
  const today = localDateInTz(deps.now(), entry.facility.tz);
  if (today === null) return { kind: "no_timezone" };
  const guard = pickGuard(await deps.existingPicks(owner), entry, today);
  if (!guard.ok) return { kind: "already_picked", courseId: guard.courseId };

  // The permission: read first, ask only when undecided (an explicit player action got us here).
  const gate = await ensureForegroundLocation(deps.location);
  if (!gate.ok) return gate.outcome;

  // A live challenge first, if we are online and it is quick; nothing here can fail the check-in.
  const live = await within(deps.challenges.acquireLive(owner, entry.facility.id), timing.liveBudgetMs).catch(() => null);

  const attempt = await deps.location.currentFix({ timeoutMs: timing.fixTimeoutMs });
  if (!attempt.ok) return { kind: "no_fix", reason: attempt.reason };
  const raw = attempt.fix;
  const problem = fixProblem(raw, deps.now(), timing);
  if (problem === "invalid") return { kind: "no_fix", reason: "invalid" };
  if (problem === "stale") return { kind: "stale_fix" };
  if (raw.accuracyMeters === null || !Number.isFinite(raw.accuracyMeters) || raw.accuracyMeters < 0) return { kind: "inaccurate", accuracyMeters: Number.POSITIVE_INFINITY };
  const fix: DeviceFix = { lat: raw.latitude, lng: raw.longitude, accuracyMeters: raw.accuracyMeters, capturedAt: raw.timestamp, simulated: raw.simulated };

  const match = matchCourse(entry, fix);
  if (match.kind === "rejected") {
    switch (match.reason) {
      case "simulated":
        return { kind: "simulated" };
      case "inaccurate":
        return { kind: "inaccurate", accuracyMeters: fix.accuracyMeters };
      case "no_geometry":
        return { kind: "no_geometry" };
      case "invalid_fix":
        return { kind: "no_fix", reason: "invalid" };
      case "outside_polygon":
        return { kind: "not_here", distanceMeters: match.distanceMeters, nearby: input.index ? nearbyCourses(input.index, fix, entry.facility.id) : [] };
    }
  }

  const localDate = localDateInTz(fix.capturedAt, entry.facility.tz);
  if (localDate === null) return { kind: "no_timezone" };
  const fixId = deps.newFixId();
  // The live challenge covers this fix only if the fix lies inside its window; otherwise it is dropped and the pool is used (`challenge` absent).
  const challenge = live !== null && liveCovers(live, fix.capturedAt) ? live.challenge : undefined;
  const manifestSig = await deps.manifestSig(input.catalogVersion).catch(() => null);
  // The owner is bound for the WHOLE run: a different account signed in during the fix gets nothing (and never A's live token).
  const now = deps.currentUserId();
  if (now !== owner) return { kind: now === null || now === "" ? "signed_out" : "account_changed" };
  const enqueued = await deps.enqueueEvidence({
    origin: "live",
    owner,
    facilityId: entry.facility.id,
    courseId: entry.course.id,
    catalogVersion: input.catalogVersion,
    localDate,
    ...(manifestSig ? { manifestSig } : {}),
    submission: { source: "foreground_checkin", fix: { fixId, lat: fix.lat, lng: fix.lng, accuracyMeters: fix.accuracyMeters, capturedAt: fix.capturedAt, simulated: false, foreground: true, fromApp: true } },
    ...(challenge && live ? { challenge, challengeFor: { ownerUserId: live.ownerUserId, deviceId: live.deviceId } } : {}),
  });
  return { kind: "queued", item: enqueued.item, penalty: enqueued.penalty, challenge: challengeKindOf(enqueued.item, fixId), geometryKind: match.geometryKind, capturedAt: fix.capturedAt, accuracyMeters: fix.accuracyMeters };
}
