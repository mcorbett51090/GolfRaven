/**
 * The reauth helper (docs/security/partner-auth-design.md 6.3, 18.2): a fresh passkey assertion by THE SESSION'S OWN person, which opens the
 * server's 5-minute `reauth_until` window. Exported for the screens that need it (adding a credential, A2 actions); S7a has no screen of its own
 * for it, and the Playwright suite drives it through a harness page that is built only for that suite.
 *
 * Steps: `POST reauth/options` (needs the session), `navigator.credentials.get` with the server's options, `POST reauth`.
 * A refused assertion is `PartnerApiError` kind `reauth_refused` (403): the session is still alive. A dead session is `unauthenticated` (401),
 * and by then the client has already wiped the token.
 */

import type { PartnerApi } from "../api/client";
import type { ReauthResult } from "../api/types";
import { getAssertion, type GetAssertionDeps } from "../webauthn/assertion";

export async function reauthWithPasskey(api: PartnerApi, webauthn: GetAssertionDeps, signal?: AbortSignal): Promise<ReauthResult> {
  const challenge = await api.reauthOptions();
  const credential = await getAssertion(webauthn, challenge.options, signal);
  return await api.reauth({ challengeToken: challenge.challengeToken, credential });
}
