/**
 * Passkey sign-in (docs/security/partner-auth-design.md 6.2, 18): `POST options`, `navigator.credentials.get` with the server's options,
 * `POST verify`. The session token stays inside the API client; this returns only what the page may know (`aal`, expiry).
 */

import type { PartnerApi } from "../api/client";
import type { SessionGrant } from "../api/types";
import { getAssertion, type GetAssertionDeps } from "../webauthn/assertion";

export async function signInWithPasskey(api: PartnerApi, webauthn: GetAssertionDeps, signal?: AbortSignal): Promise<SessionGrant> {
  const challenge = await api.signInOptions();
  const credential = await getAssertion(webauthn, challenge.options, signal);
  return await api.verify({ challengeToken: challenge.challengeToken, credential });
}
