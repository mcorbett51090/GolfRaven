import { CHECKIN_UI_ENABLED, MARKER_COSIGNAL_UI_ENABLED } from "../features";

/**
 * The ONLY question the screens and the services ask about the check-in switch: is the check-in UI part of this build? `enabled` is a parameter so tests can exercise both states;
 * the app never passes it. While it is false: the course page shows no check-in card (the old "not available" button), `runCheckIn` refuses, no permission prompt can be shown,
 * no challenge is prefetched (`challenges/prefetch-gate.ts` reads the same constant) and nothing builds evidence.
 */
export function checkinUiAvailable(enabled: boolean = CHECKIN_UI_ENABLED): boolean {
  return enabled;
}

/** "Buying a marker" needs BOTH switches: the check-in one (it spends a prefetched challenge, which exist only while prefetch is on) and its own (no server path accepts the record yet). */
export function markerCosignalUiAvailable(checkin: boolean = CHECKIN_UI_ENABLED, marker: boolean = MARKER_COSIGNAL_UI_ENABLED): boolean {
  return checkin && marker;
}
