// supabase/functions/_shared/signin/production.ts
//
// Assembles the production sign-in ports from an already-parsed configuration (privileged.ts reads the environment; nothing here
// does). THE ONLY place that decides what "configured" means:
//
//   config === null (any of the four GR_APPLE_* values absent or blank)  ->  ports.apple === null
//                                                                         ->  every Apple operation answers 503, never a fallback.
//
// The Google port needs no configuration (revocation takes only the token), so it always exists; it is only ever called for a
// queue row that holds a Google grant, and none is created until the P4 capture work (google-client.ts, TODO).
//
// Every outbound call goes through a SafeFetcher with its own host allow-list (one host each), the per-call timeout and the size
// cap (safe-fetch.ts). The JWKS cache lives as long as the isolate.

import { APPLE_HOST, createJwksCache, verifyAppleIdentityToken } from "./apple-id-token.ts";
import { createAppleClient } from "./apple-client.ts";
import { createClientSecretMinter, isCompleteAppleSecretConfig, type AppleSecretConfig } from "./apple-client-secret.ts";
import { createGoogleRevoker, GOOGLE_HOST } from "./google-client.ts";
import { createSafeFetcher, SIGNIN_VENDOR_MAX_BYTES, SIGNIN_VENDOR_TIMEOUT_MS, type FetchLike } from "./safe-fetch.ts";
import type { AppleSigninPort, GoogleRevokePort } from "./types.ts";

export interface SigninPorts {
  apple: AppleSigninPort | null;
  google: GoogleRevokePort;
}

export interface ProductionEnv {
  fetch: FetchLike;
  nowMs(): number;
  timeoutMs?: number;
}

export function buildSigninPorts(config: AppleSecretConfig | null, env: ProductionEnv): SigninPorts {
  const timeoutMs = env.timeoutMs ?? SIGNIN_VENDOR_TIMEOUT_MS;
  const googleFetcher = createSafeFetcher({ fetch: env.fetch, allowedHosts: [GOOGLE_HOST], timeoutMs, maxBytes: SIGNIN_VENDOR_MAX_BYTES });
  const google = createGoogleRevoker(googleFetcher);
  if (!isCompleteAppleSecretConfig(config)) return { apple: null, google };

  const appleFetcher = createSafeFetcher({ fetch: env.fetch, allowedHosts: [APPLE_HOST], timeoutMs, maxBytes: SIGNIN_VENDOR_MAX_BYTES });
  const jwks = createJwksCache({ fetcher: appleFetcher, nowMs: env.nowMs });
  const verifyOpts = { jwks, nowMs: env.nowMs, clientId: config.clientId };
  const secret = createClientSecretMinter(config, env.nowMs);
  const client = createAppleClient({
    fetcher: appleFetcher,
    secret,
    clientId: config.clientId,
    verifyReturnedIdToken: (idToken) => verifyAppleIdentityToken(idToken, { rawNonce: null }, verifyOpts),
  });
  return {
    apple: {
      verifyIdentityToken: (token, rawNonce) => verifyAppleIdentityToken(token, { rawNonce }, verifyOpts),
      exchangeAuthorizationCode: (code) => client.exchangeAuthorizationCode(code),
      revokeRefreshToken: (token) => client.revokeRefreshToken(token),
    },
    google,
  };
}

/** The platform `fetch`, typed as the narrow shape safe-fetch.ts wants. */
export const platformFetch: FetchLike = (url, init) => fetch(url, init);
