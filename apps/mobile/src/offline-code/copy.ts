import type { MessageKey } from "../i18n";
import type { ProvisionOutcome } from "./manager";

/** `mm:ss` for a countdown (whole seconds, 0 to 600). Pure. */
export function formatCountdown(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Whole minutes of a clock offset, rounded, for the "your clock is off" line. */
export function skewMinutes(offsetMs: number): number {
  return Math.round(Math.abs(offsetMs) / 60_000);
}

/** The line a provisioning outcome gets (every `ProvisionOutcome` has one: the `switch` is exhaustive, so a new status is a compile error here). */
export function provisionMessage(o: ProvisionOutcome, rotated: boolean = false): MessageKey {
  switch (o.status) {
    case "ready":
      return rotated ? "offline.status.reset" : "offline.status.ready";
    case "signed_out":
      return "offline.status.signedOut";
    case "sign_in_required":
      return "offline.status.signIn";
    case "not_ready":
      return "offline.status.notReady";
    case "rate_limited":
      return "offline.status.rateLimited";
    case "unavailable":
      return "offline.status.unavailable";
    case "offline":
      return "offline.status.offline";
    case "failed":
      return o.reason === "not_configured" ? "offline.status.notConfigured" : "offline.status.failed";
  }
}
