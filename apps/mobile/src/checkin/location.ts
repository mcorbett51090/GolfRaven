/**
 * The location seam of the foreground check-in (build plan §7.1 "`expo-location` in foreground mode only", §7.4 step 5).
 *
 * `LocationPort` is everything the check-in needs from the device, and it deliberately has NO background / Always member: no `requestBackgroundPermissions`, no updates
 * subscription, no geofence. The only implementation that touches the native module is `expo-location.ts` (the one file that imports it); the flow and the tests use this
 * interface, so nothing here needs a device.
 *
 * THE PROMPT. `requestPermission()` shows the system dialog and so may be called only from an explicit player action (the "I'm here" / "Buying a marker" buttons, through
 * `runCheckIn` / `captureMarkerCoSignal`). `permission()` reads the current state and never prompts. `test/checkin-no-prompt-at-launch.test.ts` scans the sources for that.
 */

export type LocationPermission =
  /** `approximate`: the player granted only a coarse location (Android 12+ "Approximate"); its accuracy is far above the 50 m a check-in needs. */
  | { status: "granted"; approximate: boolean }
  /** `canAskAgain: false` is "blocked": the system will not show the dialog again, only Settings can change it. */
  | { status: "denied"; canAskAgain: boolean }
  /** Never asked. */
  | { status: "undetermined" };

/** One position fix as the device reported it, before any validation. `timestamp` is the fix's own time (epoch ms), not the time we read it. */
export interface RawFix {
  latitude: number;
  longitude: number;
  /** Horizontal accuracy in metres; `null` when the device did not report one (a fix with no accuracy is refused). */
  accuracyMeters: number | null;
  timestamp: number;
  /** A mock / simulated position. Android reports `isFromMockProvider` (read as `mocked !== false`: absent is NOT trusted there); iOS exposes no such flag through `expo-location`
   * (`[unverified: iOS 15+ CLLocationSourceInformation.isSimulatedBySoftware is not surfaced by expo-location 57.0.19]`), so it is `false` there. */
  simulated: boolean;
}

export type FixAttempt = { ok: true; fix: RawFix } | { ok: false; reason: "timeout" | "unavailable" };

export interface LocationPort {
  /** The current permission, read without prompting. */
  permission(): Promise<LocationPermission>;
  /** Shows the system prompt if the player has not decided. EXPLICIT PLAYER ACTION ONLY. Never throws: a failure is `denied`. */
  requestPermission(): Promise<LocationPermission>;
  /** False when the device's location services are switched off. */
  servicesEnabled(): Promise<boolean>;
  /** One foreground fix (high accuracy). Never throws; gives up after `timeoutMs`. */
  currentFix(opts: { timeoutMs: number }): Promise<FixAttempt>;
}

/** A port for a build that has no location module (web, a test, a build without the native module): everything refuses, nothing prompts. */
export function unavailableLocationPort(): LocationPort {
  return {
    permission: () => Promise.resolve({ status: "denied", canAskAgain: false }),
    requestPermission: () => Promise.resolve({ status: "denied", canAskAgain: false }),
    servicesEnabled: () => Promise.resolve(false),
    currentFix: () => Promise.resolve({ ok: false, reason: "unavailable" }),
  };
}
