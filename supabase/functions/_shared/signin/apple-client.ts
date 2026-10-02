// supabase/functions/_shared/signin/apple-client.ts
//
// Apple's token and revoke endpoints (server side only; the client secret never leaves this process).
//
// [unverified — training knowledge] endpoints and shapes, to be confirmed against a real service id in the P4 spike:
//   POST https://appleid.apple.com/auth/token   form: client_id, client_secret, code, grant_type=authorization_code
//        -> 200 { access_token, token_type, expires_in, refresh_token, id_token }
//        -> 400 { error: "invalid_grant" | "invalid_client" | "invalid_request" | ... }
//   POST https://appleid.apple.com/auth/revoke  form: client_id, client_secret, token, token_type_hint=refresh_token
//        -> 200 (empty body) on success; 400 { error } when the token is not valid (already revoked / unknown)
//
// Error discipline (the same as every vendor adapter here): the response BODY is never copied into an error; only a closed set
// of short codes leaves this file. `invalid_grant` on the token endpoint is the REQUEST being wrong (AppleGrantError);
// everything else that is not a success is the provider being unavailable (VendorUnavailableError), which is retryable.
//
// Revocation is idempotent by intent: "the token is not valid at Apple" is exactly the state we want, so a 400 whose error is
// invalid_grant / invalid_token / invalid_request is treated as already revoked. `invalid_client` (our own credentials are
// wrong) and 5xx are NOT: they leave the grant live at Apple, so the caller keeps retrying.

import { AppleGrantError, VendorUnavailableError } from "./errors.ts";
import { MAX_TOKEN_CHARS } from "./envelope.ts";
import { parseJsonObject, type SafeFetcher } from "./safe-fetch.ts";
import type { ClientSecretMinter } from "./apple-client-secret.ts";
import type { VerifiedAppleIdentity } from "./apple-id-token.ts";

export const APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token";
export const APPLE_REVOKE_URL = "https://appleid.apple.com/auth/revoke";

export interface AppleClientDeps {
  fetcher: SafeFetcher;
  secret: ClientSecretMinter;
  clientId: string;
  /** Verifies the id_token Apple returns from the token endpoint (signature, iss, aud, exp) WITHOUT a nonce check. */
  verifyReturnedIdToken(idToken: string): Promise<VerifiedAppleIdentity>;
}

const form = (fields: Record<string, string>) => new URLSearchParams(fields).toString();
const FORM_HEADERS = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };

function errorCode(text: string): string | null {
  const o = parseJsonObject(text);
  const e = o?.error;
  return typeof e === "string" && /^[a-z_]{1,40}$/.test(e) ? e : null;
}

export interface CodeExchangeResult {
  refreshToken: string;
  /** `sub` of the VERIFIED id_token Apple returned: the Apple user the authorization code actually belongs to. */
  subject: string;
}

export function createAppleClient(deps: AppleClientDeps) {
  return {
    async exchangeAuthorizationCode(code: string): Promise<CodeExchangeResult> {
      const clientSecret = await deps.secret.get(); // NotConfiguredError propagates: fail closed
      const res = await deps.fetcher(APPLE_TOKEN_URL, {
        method: "POST",
        headers: FORM_HEADERS,
        body: form({ client_id: deps.clientId, client_secret: clientSecret, code, grant_type: "authorization_code" }),
      });
      if (res.status === 400) {
        const e = errorCode(res.text);
        // invalid_grant: this authorization code is wrong / used / expired / for another client. The request is bad.
        if (e === "invalid_grant" || e === "invalid_request") throw new AppleGrantError(e);
        // invalid_client / unsupported_grant_type: OUR configuration is wrong, which is not the caller's fault.
        throw new VendorUnavailableError(`token_${e ?? "400"}`);
      }
      if (res.status !== 200) throw new VendorUnavailableError(res.status >= 500 ? "token_5xx" : `token_${res.status}`);
      const body = parseJsonObject(res.text);
      const refresh = body?.refresh_token;
      const idToken = body?.id_token;
      if (typeof refresh !== "string" || refresh.length === 0 || refresh.length > MAX_TOKEN_CHARS) throw new VendorUnavailableError("token_no_refresh_token");
      if (typeof idToken !== "string" || idToken.length === 0) throw new VendorUnavailableError("token_no_id_token");
      const identity = await deps.verifyReturnedIdToken(idToken);
      return { refreshToken: refresh, subject: identity.subject };
    },

    /** Revokes one refresh token. Resolves when the grant is no longer valid at Apple (revoked now, or already not valid). */
    async revokeRefreshToken(refreshToken: string): Promise<void> {
      const clientSecret = await deps.secret.get();
      const res = await deps.fetcher(APPLE_REVOKE_URL, {
        method: "POST",
        headers: FORM_HEADERS,
        body: form({ client_id: deps.clientId, client_secret: clientSecret, token: refreshToken, token_type_hint: "refresh_token" }),
      });
      if (res.status === 200) return;
      if (res.status === 400) {
        const e = errorCode(res.text);
        if (e === "invalid_grant" || e === "invalid_token" || e === "invalid_request") return; // already not valid at Apple
        throw new VendorUnavailableError(`revoke_${e ?? "400"}`);
      }
      throw new VendorUnavailableError(res.status >= 500 ? "revoke_5xx" : `revoke_${res.status}`);
    },
  };
}

