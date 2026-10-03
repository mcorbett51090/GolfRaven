import type { CheckinApi } from "../api/types";
import { OFFLINE_CODE_UI_ENABLED } from "../features";
import type { OfflineCodeManagerDeps } from "./manager";

/**
 * The ONLY way the app provisions the offline seed on its own (launch, sign-in). Until a screen can SHOW the code (`OFFLINE_CODE_UI_ENABLED`, `src/features.ts`: the staff side that
 * accepts it is P5), a provisioning would only reveal a secret into the keychain for nothing and spend the server's 20-an-hour reveal limit: so while the flag is false this does
 * nothing at all (no request, no token fetch, no keychain read). `enabled` is a parameter so tests can exercise both states; the app never passes it.
 */
export async function provisionOfflineSeedOnLaunch(manager: { provisionIfMissing(): Promise<unknown> }, enabled: boolean = OFFLINE_CODE_UI_ENABLED): Promise<void> {
  if (!enabled) return;
  await manager.provisionIfMissing();
}

/**
 * The device-registration path the offline code needs before it can ever become ready (PR #44 gate NIT), switched on by the same flag as everything else here.
 *
 * `POST me-offline-seed` never creates a device: it answers 404 (`not_ready`) until THIS device is registered to the account, and nothing else in the app registers one yet (challenge
 * prefetch is gated off by `CHECKIN_UI_ENABLED`, and push is not installed, `unavailablePushAdapter`). So while `OFFLINE_CODE_UI_ENABLED` is true the manager, on a 404 from the seed
 * endpoint, registers the device through `POST checkin-challenge { deviceId }` (`device.ensureOwn`, platform left unknown) and asks again, once, at most once per
 * `AUTO_PROVISION_COOLDOWN_MS` per user (`OfflineCodeManager.registerDeviceOnce` has the reasoning and the cost: one live challenge of the account's 30 an hour). While the flag is false this
 * returns `undefined`: the manager is built with no registration path and a 404 stays "not ready". `enabled` is a parameter so tests can exercise both states; the app never passes it.
 */
export function deviceRegistrationFor(api: Pick<CheckinApi, "requestCheckinChallenges">, enabled: boolean = OFFLINE_CODE_UI_ENABLED): OfflineCodeManagerDeps["registerDevice"] {
  if (!enabled) return undefined;
  return async ({ deviceId, userId, accessToken }) => {
    await api.requestCheckinChallenges({ deviceId }, { userId, accessToken }); // no prefetchCount: ONE live challenge, which expires unused after 120 s
  };
}
