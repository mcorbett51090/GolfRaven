// supabase/functions/_shared/signin/google-client.ts
//
// Google's token revocation for the sign-in grant (the Google half of the Apple 5.1.1(v) account-deletion requirement, build
// plan §7.8). Revocation is the CHEAP half: it takes only the token, no client secret.
//
// [unverified — training knowledge] POST https://oauth2.googleapis.com/revoke, form `token=<token>`; 200 on success; 400
// `{ "error": "invalid_token" }` when the token is already invalid or revoked (the state we want).
//
// ⚠ TODO(P4): the CAPTURE half is NOT built. Nothing stores a Google refresh token today: it needs Google's authorization-code
// exchange (a client secret and a redirect/`serverAuthCode` decision for the native flow), and `me-signin-methods` answers
// `link` for Google with 501 provider_not_supported until the P4 spike decides it. This revoker is generic over whatever the
// queue holds, so once capture exists nothing here changes.

import { VendorUnavailableError } from "./errors.ts";
import { parseJsonObject, type SafeFetcher } from "./safe-fetch.ts";

export const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
export const GOOGLE_HOST = "oauth2.googleapis.com";

export function createGoogleRevoker(fetcher: SafeFetcher) {
  return {
    async revokeToken(token: string): Promise<void> {
      const res = await fetcher(GOOGLE_REVOKE_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams({ token }).toString(),
      });
      if (res.status === 200) return;
      if (res.status === 400) {
        const e = parseJsonObject(res.text)?.error;
        if (e === "invalid_token") return; // already not valid at Google
        throw new VendorUnavailableError("revoke_400");
      }
      throw new VendorUnavailableError(res.status >= 500 ? "revoke_5xx" : `revoke_${res.status}`);
    },
  };
}
