import { OFFLINE_CODE_UI_ENABLED } from "../features";

/**
 * The ONLY way the app provisions the offline seed on its own (launch, sign-in). Until a screen can SHOW the code (`OFFLINE_CODE_UI_ENABLED`, `src/features.ts`: the staff side that
 * accepts it is P5), a provisioning would only reveal a secret into the keychain for nothing and spend the server's 20-an-hour reveal limit: so while the flag is false this does
 * nothing at all (no request, no token fetch, no keychain read). `enabled` is a parameter so tests can exercise both states; the app never passes it.
 */
export async function provisionOfflineSeedOnLaunch(manager: { provisionIfMissing(): Promise<unknown> }, enabled: boolean = OFFLINE_CODE_UI_ENABLED): Promise<void> {
  if (!enabled) return;
  await manager.provisionIfMissing();
}
