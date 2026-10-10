/**
 * P5 §53: online shop-QR scan from a pasted link (rotating token or printed facility QR + PIN).
 * No CAMERA — paste / OS open-URL only. Captures a presence fix, redeems a challenge, POSTs
 * `marker-scan` with `qr` + `fix` + `jti`. Behind the same UI flags as capture (`MARKER_COSIGNAL_UI_ENABLED`
 * + `CHECKIN_UI_ENABLED`); both stay false in release builds.
 */
import { isApiError } from "../api/errors";
import type { CheckinTokenResult, MarkerScanApi, MarkerScanQr, MarkerScanResult } from "../api/types";
import { AttestationDeferred } from "../attest";
import type { CourseEntry } from "../browse";
import type { ChallengeManager } from "../challenges";
import { fixProblem, CHECKIN_TIMING, type CheckInTiming } from "../checkin/flow";
import type { LocationPort } from "../checkin/location";
import { candidateFor, matchCourse, type DeviceFix } from "../checkin/match";
import { ensureForegroundLocation } from "../checkin/permission";
import type { EvidenceCredentials } from "../outbox";
import { parseCourseQrLink } from "./link";

export type MarkerScanOutcome =
  | { kind: "scanned"; result: MarkerScanResult }
  | { kind: "disabled" }
  | { kind: "signed_out" }
  | { kind: "invalid_link" }
  | { kind: "need_pin" }
  | { kind: "invalid_pin" }
  | { kind: "wrong_facility" }
  | { kind: "no_geometry" }
  | { kind: "permission"; status: "denied" | "blocked" | "approximate" }
  | { kind: "services_off" }
  | { kind: "no_fix"; reason: "timeout" | "unavailable" | "invalid" }
  | { kind: "stale_fix" }
  | { kind: "simulated" }
  | { kind: "inaccurate"; accuracyMeters: number }
  | { kind: "not_here"; distanceMeters: number | null }
  | { kind: "no_challenge" }
  | { kind: "attestation_deferred"; message: string }
  | { kind: "rejected"; code: string | null; status: number | null }
  | { kind: "transport"; message: string }
  | { kind: "failed"; message: string };

export interface MarkerScanDeps {
  enabled: boolean;
  location: LocationPort;
  currentUserId: () => string | null;
  accessTokenFor: (userId: string) => Promise<string | null>;
  challenges: Pick<ChallengeManager, "acquireForFix">;
  redeem(req: { challengeId: string; nonce: string; deviceId: string }, credentials: EvidenceCredentials): Promise<CheckinTokenResult>;
  scan: Pick<MarkerScanApi, "scanMarker">;
  deviceId: () => Promise<string>;
  newFixId: () => string;
  now: () => number;
  timing?: Partial<CheckInTiming>;
}

export interface MarkerScanInput {
  entry: CourseEntry;
  /** Pasted universal link (`/q/m#…` or `/q/f/<slug>#kid.sig`). */
  link: string;
  /** Four-digit PIN for a printed facility QR; ignored for rotating tokens. */
  pin?: string;
}

function toQr(parsed: NonNullable<ReturnType<typeof parseCourseQrLink>>, pin: string | undefined): MarkerScanQr | { error: "need_pin" | "invalid_pin" } {
  if (parsed.kind === "rotating") return { variant: "rotating", token: parsed.token };
  const digits = (pin ?? "").trim();
  if (digits.length === 0) return { error: "need_pin" };
  if (!/^\d{4}$/.test(digits)) return { error: "invalid_pin" };
  return { variant: "static_pin", kid: parsed.kid, sig: parsed.sig, pin: digits };
}

/** Online paste scan. Never throws. */
export async function scanMarkerFromLink(deps: MarkerScanDeps, input: MarkerScanInput): Promise<MarkerScanOutcome> {
  try {
    if (!deps.enabled) return { kind: "disabled" };
    const owner = deps.currentUserId();
    if (owner === null || owner === "") return { kind: "signed_out" };
    const token = await deps.accessTokenFor(owner);
    if (token === null || token === "") return { kind: "signed_out" };
    const credentials = { userId: owner, accessToken: token };

    const parsed = parseCourseQrLink(input.link);
    if (parsed === null) return { kind: "invalid_link" };
    if (parsed.kind === "static_pin" && parsed.facilitySlug !== input.entry.facility.slug) return { kind: "wrong_facility" };
    const qrOrErr = toQr(parsed, input.pin);
    if ("error" in qrOrErr) return { kind: qrOrErr.error };

    if (candidateFor(input.entry) === null) return { kind: "no_geometry" };
    const timing = { ...CHECKIN_TIMING, ...deps.timing };
    const gate = await ensureForegroundLocation(deps.location);
    if (!gate.ok) return gate.outcome;

    const attempt = await deps.location.currentFix({ timeoutMs: timing.fixTimeoutMs });
    if (!attempt.ok) return { kind: "no_fix", reason: attempt.reason };
    const raw = attempt.fix;
    const problem = fixProblem(raw, deps.now(), timing);
    if (problem === "invalid") return { kind: "no_fix", reason: "invalid" };
    if (problem === "stale") return { kind: "stale_fix" };
    if (raw.accuracyMeters === null || !Number.isFinite(raw.accuracyMeters) || raw.accuracyMeters < 0) {
      return { kind: "inaccurate", accuracyMeters: Number.POSITIVE_INFINITY };
    }
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

    // Prefer a live challenge when online (shop has signal); fall back to prefetched.
    // `live: true` returns `redeemed` (tryLive already POSTed checkin-token); the pool returns `held`.
    let challenge = await deps.challenges.acquireForFix(owner, fix.capturedAt, { live: true, facilityId: input.entry.facility.id });
    if (challenge.state === "none") {
      challenge = await deps.challenges.acquireForFix(owner, fix.capturedAt, { live: false, facilityId: input.entry.facility.id });
    }

    const deviceId = await deps.deviceId();
    let jti: string;
    if (challenge.state === "redeemed") {
      jti = challenge.jti;
    } else if (challenge.state === "held") {
      try {
        const redeemed = await deps.redeem({ challengeId: challenge.challengeId, nonce: challenge.nonce, deviceId }, credentials);
        jti = redeemed.jti;
      } catch (e) {
        if (e instanceof AttestationDeferred) return { kind: "attestation_deferred", message: e.reason };
        if (isApiError(e) && (e.kind === "network" || e.kind === "unavailable" || e.kind === "server" || e.kind === "rate_limited" || e.kind === "unauthenticated")) {
          return { kind: "transport", message: e.message };
        }
        return { kind: "rejected", code: isApiError(e) ? e.code : null, status: isApiError(e) ? e.status : null };
      }
    } else {
      return { kind: "no_challenge" };
    }

    try {
      const result = await deps.scan.scanMarker(
        {
          facilityId: input.entry.facility.id,
          qr: qrOrErr,
          deviceId,
          fix: {
            fixId: deps.newFixId(),
            lat: fix.lat,
            lng: fix.lng,
            accuracyMeters: fix.accuracyMeters,
            capturedAt: fix.capturedAt,
            simulated: false,
            foreground: true,
            fromApp: true,
          },
          jti,
        },
        credentials,
      );
      return { kind: "scanned", result };
    } catch (e) {
      if (isApiError(e) && (e.kind === "network" || e.kind === "unavailable" || e.kind === "server" || e.kind === "rate_limited")) {
        return { kind: "transport", message: e.message };
      }
      return { kind: "rejected", code: isApiError(e) ? e.code : null, status: isApiError(e) ? e.status : null };
    }
  } catch (e) {
    return { kind: "failed", message: e instanceof Error ? e.message : String(e) };
  }
}
