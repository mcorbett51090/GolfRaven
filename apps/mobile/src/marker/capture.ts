/**
 * "Buying a marker" (build plan §7.6 "Offline marker purchase", G2-03, case 1: staff online, player offline): the player taps the button at the pro shop and the app captures a
 * co-signal, a foreground fix against a PREFETCHED challenge, and queues it.
 *
 * WHAT IS BUILT, AND WHAT IS NOT. The capture and the local queue (`marker/store.ts`) are built. The sending is NOT: no server path accepts a marker-purchase co-signal yet, so the record
 * stays on the device, behind `MARKER_COSIGNAL_UI_ENABLED` (and `CHECKIN_UI_ENABLED`), and no wire shape is invented. README, "Marker purchase: what the server does not have yet".
 *
 * Same discipline as the check-in: build switch first (no prompt while off), signed in, the facility has geometry on the device, the permission read-then-ask from this explicit tap,
 * one foreground fix validated the same way, matched to the FACILITY's circle (a pro shop is at the facility; "a fix outside polygon + 50 m: the row stays pending"), and then the challenge:
 * a prefetched one only (the whole point is the player may be offline), consumed with the fix's own time so its window contains the fix. A co-signal without a challenge is
 * worth nothing, so with none left the capture is refused (`no_challenge`) and nothing is stored.
 */
import type { CourseEntry } from "../browse";
import type { ChallengeManager } from "../challenges";
import { fixProblem, CHECKIN_TIMING, type CheckInTiming } from "../checkin/flow";
import type { LocationPort } from "../checkin/location";
import { matchCourse, type DeviceFix } from "../checkin/match";
import { ensureForegroundLocation } from "../checkin/permission";
import type { MarkerCosignal, MarkerCosignalStore } from "./store";

const SITE_VERSION = /^\d{8}-[0-9a-f]{7}$/;

export type MarkerCaptureOutcome =
  | { kind: "captured"; record: MarkerCosignal }
  | { kind: "disabled" }
  | { kind: "signed_out" }
  | { kind: "no_catalog" }
  | { kind: "no_geometry" }
  | { kind: "permission"; status: "denied" | "blocked" | "approximate" }
  | { kind: "services_off" }
  | { kind: "no_fix"; reason: "timeout" | "unavailable" | "invalid" }
  | { kind: "stale_fix" }
  | { kind: "simulated" }
  | { kind: "inaccurate"; accuracyMeters: number }
  | { kind: "not_here"; distanceMeters: number | null }
  /** No prefetched challenge was left for this fix (or none whose window contains it): a co-signal without one is worth nothing, so nothing is stored. */
  | { kind: "no_challenge" }
  | { kind: "failed"; message: string };

export interface MarkerCaptureDeps {
  /** `markerCosignalUiAvailable()`. */
  enabled: boolean;
  location: LocationPort;
  currentUserId: () => string | null;
  challenges: Pick<ChallengeManager, "acquireForFix">;
  store: MarkerCosignalStore;
  deviceId: () => Promise<string>;
  newId: () => string;
  newFixId: () => string;
  now: () => number;
  timing?: Partial<CheckInTiming>;
}

export interface MarkerCaptureInput {
  /** Any course of the facility: the circle is the facility's. */
  entry: CourseEntry;
  catalogVersion: string;
}

/** Called from the "Buying a marker" button, never from startup. Never throws. */
export async function captureMarkerCoSignal(deps: MarkerCaptureDeps, input: MarkerCaptureInput): Promise<MarkerCaptureOutcome> {
  try {
    if (!deps.enabled) return { kind: "disabled" };
    const timing = { ...CHECKIN_TIMING, ...deps.timing };
    const owner = deps.currentUserId();
    if (owner === null || owner === "") return { kind: "signed_out" };
    if (!SITE_VERSION.test(input.catalogVersion)) return { kind: "no_catalog" };

    const gate = await ensureForegroundLocation(deps.location);
    if (!gate.ok) return gate.outcome;

    const attempt = await deps.location.currentFix({ timeoutMs: timing.fixTimeoutMs });
    if (!attempt.ok) return { kind: "no_fix", reason: attempt.reason };
    const raw = attempt.fix;
    const problem = fixProblem(raw, deps.now(), timing);
    if (problem === "invalid") return { kind: "no_fix", reason: "invalid" };
    if (problem === "stale") return { kind: "stale_fix" };
    if (raw.accuracyMeters === null || !Number.isFinite(raw.accuracyMeters) || raw.accuracyMeters < 0) return { kind: "inaccurate", accuracyMeters: Number.POSITIVE_INFINITY };
    const fix: DeviceFix = { lat: raw.latitude, lng: raw.longitude, accuracyMeters: raw.accuracyMeters, capturedAt: raw.timestamp, simulated: raw.simulated };

    const match = matchCourse(input.entry, fix);
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
          return { kind: "not_here", distanceMeters: match.distanceMeters };
      }
    }

    // A prefetched challenge only (live: false): consumed with the fix's own time, so the one chosen was issued before the fix and expires after it.
    const challenge = await deps.challenges.acquireForFix(owner, fix.capturedAt, { live: false, facilityId: input.entry.facility.id });
    if (challenge.state === "none") return { kind: "no_challenge" };
    const record: MarkerCosignal = {
      id: deps.newId(),
      ownerUserId: owner,
      facilityId: input.entry.facility.id,
      catalogVersion: input.catalogVersion,
      deviceId: await deps.deviceId(),
      fix: { fixId: deps.newFixId(), lat: fix.lat, lng: fix.lng, accuracyMeters: fix.accuracyMeters, capturedAt: fix.capturedAt, simulated: false, foreground: true, fromApp: true },
      challenge,
      createdAt: deps.now(),
    };
    await deps.store.insert(record);
    return { kind: "captured", record };
  } catch (e) {
    return { kind: "failed", message: e instanceof Error ? e.message : String(e) };
  }
}
