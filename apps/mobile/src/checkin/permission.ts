import type { LocationPort } from "./location";

export type LocationGate = { ok: true } | { ok: false; outcome: { kind: "permission"; status: "denied" | "blocked" | "approximate" } | { kind: "services_off" } };

/**
 * The foreground location permission for an action the player just took: read WITHOUT prompting, and only when the player has not decided yet show the system prompt once.
 * Called by `runCheckIn` and `captureMarkerCoSignal`, which are only ever called from a button's `onPress`; nothing at launch reaches this (`test/checkin-no-prompt-at-launch.test.ts`).
 * Denied with the dialog still available is asked again on the next tap ("denied" is the answer when they decline again); denied for good is "blocked" (only Settings can change it); a coarse-only grant is "approximate"
 * (its accuracy can never reach the 50 m a check-in needs). Services off is its own outcome.
 */
export async function ensureForegroundLocation(location: LocationPort): Promise<LocationGate> {
  let permission = await location.permission();
  // The dialog is shown when the player has not decided, AND when they denied it once and the system will still show it (Android "Deny" without "don't ask again"): a tap on the button
  // is a new explicit request. Denied for good (`canAskAgain: false`) is never prompted: the system would not show it, and the player is sent to Settings instead.
  if (permission.status === "undetermined" || (permission.status === "denied" && permission.canAskAgain)) permission = await location.requestPermission();
  if (permission.status === "undetermined") return { ok: false, outcome: { kind: "permission", status: "denied" } };
  if (permission.status === "denied") return { ok: false, outcome: { kind: "permission", status: permission.canAskAgain ? "denied" : "blocked" } };
  if (permission.approximate) return { ok: false, outcome: { kind: "permission", status: "approximate" } };
  if (!(await location.servicesEnabled())) return { ok: false, outcome: { kind: "services_off" } };
  return { ok: true };
}
