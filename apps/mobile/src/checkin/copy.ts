/**
 * Which sentence each check-in / marker outcome gets. Pure (the screens pass `t`), so `test/checkin-copy.test.ts` can check that EVERY outcome kind has copy in both languages and
 * that the words are the honest ones (a refusal is never worded as a success).
 */
import type { MessageKey, Params } from "../i18n";
import type { CheckInOutcome } from "./flow";
import type { MarkerCaptureOutcome } from "../marker/capture";

export type Translate = (key: MessageKey, params?: Params) => string;

export type CheckInFailure = Exclude<CheckInOutcome, { kind: "queued" }>;
export type MarkerFailure = Exclude<MarkerCaptureOutcome, { kind: "captured" }>;

/** "850 m", "1.2 km": SI symbols, not translated. */
export function formatDistance(meters: number): string {
  return meters < 1000 ? `${Math.round(meters)} m` : `${(meters / 1000).toFixed(1)} km`;
}

export interface CheckInNames {
  /** The name of the course being checked in to. */
  course: string;
  /** The name of the course already picked at this facility today (for `already_picked`). */
  picked?: string;
}

export function checkInFailureText(o: CheckInFailure, t: Translate, names: CheckInNames): string {
  switch (o.kind) {
    case "disabled":
      return t("checkin.err.disabled");
    case "signed_out":
      return t("checkin.err.signed_out");
    case "no_geometry":
      return t("checkin.err.no_geometry");
    case "no_catalog":
      return t("checkin.err.no_catalog");
    case "no_timezone":
      return t("checkin.err.no_timezone");
    case "already_picked":
      return t("checkin.err.already_picked", { course: names.picked ?? names.course });
    case "permission":
      return t(o.status === "denied" ? "checkin.err.denied" : o.status === "blocked" ? "checkin.err.blocked" : "checkin.err.approximate");
    case "services_off":
      return t("checkin.err.services_off");
    case "no_fix":
      return t(o.reason === "timeout" ? "checkin.err.no_fix.timeout" : "checkin.err.no_fix.unavailable");
    case "stale_fix":
      return t("checkin.err.stale_fix");
    case "simulated":
      return t("checkin.err.simulated");
    case "inaccurate":
      return Number.isFinite(o.accuracyMeters) ? t("checkin.err.inaccurate", { meters: Math.round(o.accuracyMeters) }) : t("checkin.err.inaccurate.unknown");
    case "not_here":
      return o.distanceMeters === null ? t("checkin.err.not_here", { course: names.course }) : t("checkin.err.not_here.distance", { course: names.course, distance: formatDistance(o.distanceMeters) });
    case "failed":
      return t("checkin.err.failed");
  }
}

export function markerFailureText(o: MarkerFailure, t: Translate, facility: string): string {
  switch (o.kind) {
    case "not_here":
      return t("marker.err.not_here", { facility });
    case "no_challenge":
      return t("marker.err.no_challenge");
    case "signed_out":
      return t("marker.err.signed_out");
    case "disabled":
      return t("checkin.err.disabled");
    case "no_catalog":
      return t("checkin.err.no_catalog");
    case "no_geometry":
      return t("checkin.err.no_geometry");
    case "permission":
      return t(o.status === "denied" ? "checkin.err.denied" : o.status === "blocked" ? "checkin.err.blocked" : "checkin.err.approximate");
    case "services_off":
      return t("checkin.err.services_off");
    case "no_fix":
      return t(o.reason === "timeout" ? "checkin.err.no_fix.timeout" : "checkin.err.no_fix.unavailable");
    case "stale_fix":
      return t("checkin.err.stale_fix");
    case "simulated":
      return t("checkin.err.simulated");
    case "inaccurate":
      return Number.isFinite(o.accuracyMeters) ? t("checkin.err.inaccurate", { meters: Math.round(o.accuracyMeters) }) : t("checkin.err.inaccurate.unknown");
    case "failed":
      return t("checkin.err.failed");
  }
}

/** Outcomes whose fix is for the player to act on in Settings (the card then offers "Open Settings"). */
export function needsSettings(o: { kind: string; status?: string }): boolean {
  return o.kind === "permission" && (o.status === "blocked" || o.status === "approximate");
}
