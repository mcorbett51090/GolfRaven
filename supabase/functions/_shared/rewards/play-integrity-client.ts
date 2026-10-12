// supabase/functions/_shared/rewards/play-integrity-client.ts
//
// PRODUCTION adapter that turns a Play Integrity token into its decoded verdict
// payload (Google's `decodeIntegrityToken`), behind `IntegrityDecoder`. The
// verdict is then judged by the PURE `evaluateIntegrityPayload`
// (play-integrity.ts).
//
// ⚠ LIVE VENDOR VERIFICATION IS NOT EXERCISED. No Google Cloud project, service
// account or network route to Google exists in this environment; this is tested
// only against a scripted `fetch`. `[unverified — training knowledge]`:
//   - POST https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken
//     with body {"integrity_token": ...}, `Authorization: Bearer <OAuth token>`,
//     answer {"tokenPayloadExternal": {...}};
//   - the OAuth token comes from the service-account JWT-bearer flow (RS256
//     JWT -> POST https://oauth2.googleapis.com/token, scope
//     https://www.googleapis.com/auth/playintegrity);
//   - 400 = the token is not decodable; 401 = our credentials rejected;
//     429/5xx = try later;
//   - 403 on `decodeIntegrityToken` is AMBIGUOUS and not verified: it may mean our service account lacks access to
//     the app, or that the token was minted for ANOTHER app or project (a caller can send one; whether Google then
//     answers 400 or 403 was not checked). It is therefore a `VendorForbiddenError` (a `VendorNotConfiguredError`:
//     same 503, same non-grading) that the handlers log at warn level, rate-limited, instead of as "our credentials
//     are wrong"; and it does NOT discard the cached OAuth token (a fresh token would be refused the same way, and an
//     attacker could otherwise force an OAuth exchange per request). Grading is unchanged. A 403 on the OAuth
//     exchange itself (below) is still "our credentials".
//
// FAIL CLOSED: no/incomplete config, or an unusable key, throws
// `VendorNotConfiguredError` on every call.
//
// EGRESS GUARD (K11; the same protections as `devicecheck-client.ts` and the sign-in modules' `safe-fetch.ts`): the host of every call must be one
// of the two exact Google hosts, checked BEFORE a JWT is signed or an OAuth exchange is started; a redirect is REFUSED rather than followed (a
// 307/308 would replay the signed service-account assertion, or the integrity token, to whatever host it names); and every call carries a
// wall-clock bound (`http.timeoutMs`). A refusal is a retryable 503-class `VendorUnavailableError`, never a clean reading.

import { pemToDer, signJwtRs256, type VendorHttp } from "./vendor-http.ts";
import { VendorForbiddenError, VendorNotConfiguredError, VendorRejectedError, VendorUnavailableError } from "./types.ts";

export interface PlayIntegrityConfig {
  packageName: string;
  /** base64url (unpadded) SHA-256 digests of the allowed signing certificates. */
  certificateSha256Digests: string[];
  serviceAccountEmail: string;
  /** PKCS#8 PEM of the service-account key. A SECRET (read from the environment
   * by privileged.ts's config loader). */
  serviceAccountPrivateKeyPem: string;
}

export interface IntegrityDecoder {
  /** The decoded `tokenPayloadExternal` object, exactly as Google returned it. */
  decode(integrityToken: string): Promise<unknown>;
}

const SCOPE = "https://www.googleapis.com/auth/playintegrity";
const TOKEN_URL = "https://oauth2.googleapis.com/token";

export interface PlayIntegrityEndpoints {
  /** The OAuth token endpoint (the service-account JWT-bearer exchange). */
  tokenUrl: string;
  /** The Play Integrity API origin; the decode URL is `${apiBase}/v1/{package}:decodeIntegrityToken`. */
  apiBase: string;
}

const ENDPOINTS: PlayIntegrityEndpoints = { tokenUrl: TOKEN_URL, apiBase: "https://playintegrity.googleapis.com" };

/** The ONLY hosts a Play Integrity call may reach: Google's OAuth host and the Play Integrity API host, lowercase. */
export const PLAY_INTEGRITY_ALLOWED_HOSTS: readonly string[] = ["oauth2.googleapis.com", "playintegrity.googleapis.com"];

/** True only for an `https` URL with no userinfo and no explicit port whose HOSTNAME (parsed, never pattern-matched, so
 * `https://playintegrity.googleapis.com.evil.test/` and `https://evil.test/#@playintegrity.googleapis.com` are refused) is on the allow-list.
 * The same shape of check as `isAllowedDeviceCheckUrl` and the sign-in modules' `safe-fetch.ts`. */
export function isAllowedPlayIntegrityUrl(rawUrl: string): boolean {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.username === "" && url.password === "" && url.port === "" && PLAY_INTEGRITY_ALLOWED_HOSTS.includes(url.hostname.toLowerCase());
}

export function isCompletePlayIntegrityConfig(c: PlayIntegrityConfig | null): c is PlayIntegrityConfig {
  return (
    c !== null &&
    c.packageName.length > 0 &&
    c.certificateSha256Digests.length > 0 &&
    c.certificateSha256Digests.every((d) => d.length > 0) &&
    c.serviceAccountEmail.length > 0 &&
    c.serviceAccountPrivateKeyPem.length > 0
  );
}

/** `endpoints` exists ONLY so a test can prove the call-site allow-list check refuses a host that is not on the list; production wiring never
 * passes it (`play-integrity-egress.test.ts` pins that every call site in `supabase/functions` passes exactly two arguments). */
export function createIntegrityDecoder(config: PlayIntegrityConfig | null, http: VendorHttp, endpoints: PlayIntegrityEndpoints = ENDPOINTS): IntegrityDecoder {
  const notConfigured = (why: string) => new VendorNotConfiguredError(`Play Integrity is not configured: ${why}`);
  let cached: { token: string; expiresAtMs: number } | null = null;

  /** Refuses a URL that is not on the host allow-list; called BEFORE anything is signed or sent. */
  function requireAllowedHost(url: string, what: string): void {
    if (!isAllowedPlayIntegrityUrl(url)) throw new VendorUnavailableError(`${what}: host not allowed`);
  }

  /** One POST under the egress guard: a refused redirect (`redirect: "error"` rejects), a redirected response and our own timeout are all
   * unavailable. Never log the token, the assertion or the integrity token. */
  async function post(url: string, what: string, headers: Record<string, string>, body: string): Promise<Response> {
    let res: Response;
    try {
      res = await http.fetch(url, { method: "POST", headers, body, signal: AbortSignal.timeout(http.timeoutMs), redirect: "error" });
    } catch {
      throw new VendorUnavailableError(`${what} did not complete`);
    }
    if (res.redirected) {
      await res.body?.cancel().catch(() => {});
      throw new VendorUnavailableError(`${what} was redirected`);
    }
    return res;
  }

  async function accessToken(cfg: PlayIntegrityConfig): Promise<string> {
    if (cached && cached.expiresAtMs - 60_000 > http.nowMs()) return cached.token;
    requireAllowedHost(endpoints.tokenUrl, "Google OAuth token request");
    const der = pemToDer(cfg.serviceAccountPrivateKeyPem);
    if (!der) throw notConfigured("the service-account key is not a PKCS#8 PEM");
    const iat = Math.floor(http.nowMs() / 1000);
    let assertion: string;
    try {
      assertion = await signJwtRs256(der, { typ: "JWT" }, { iss: cfg.serviceAccountEmail, scope: SCOPE, aud: TOKEN_URL, iat, exp: iat + 3600 });
    } catch {
      throw notConfigured("the service-account key could not be used to sign (not an RSA key?)");
    }
    const res = await post(
      endpoints.tokenUrl,
      "Google OAuth token request",
      { "content-type": "application/x-www-form-urlencoded" },
      `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${encodeURIComponent(assertion)}`,
    );
    const text = await res.text().catch(() => "");
    if (res.status === 400 || res.status === 401 || res.status === 403) throw notConfigured(`Google rejected the service-account credentials (${res.status})`);
    if (res.status !== 200) throw new VendorUnavailableError(`Google OAuth token request answered ${res.status}`);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new VendorUnavailableError("Google OAuth token response was not JSON");
    }
    const o = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
    if (!o || typeof o.access_token !== "string" || o.access_token.length === 0 || typeof o.expires_in !== "number") {
      throw new VendorUnavailableError("Google OAuth token response was not recognised");
    }
    cached = { token: o.access_token, expiresAtMs: http.nowMs() + o.expires_in * 1000 };
    return o.access_token;
  }

  return {
    async decode(integrityToken) {
      if (!isCompletePlayIntegrityConfig(config)) {
        throw notConfigured("package name, certificate digests and service-account credentials are all required");
      }
      // the decode host is checked BEFORE the OAuth exchange: a refused host must not cost an OAuth round trip or sign anything
      const decodeUrl = `${endpoints.apiBase}/v1/${encodeURIComponent(config.packageName)}:decodeIntegrityToken`;
      requireAllowedHost(decodeUrl, "Play Integrity decodeIntegrityToken");
      const bearer = await accessToken(config);
      const res = await post(decodeUrl, "Play Integrity decodeIntegrityToken", { authorization: `Bearer ${bearer}`, "content-type": "application/json" }, JSON.stringify({ integrity_token: integrityToken }));
      const text = await res.text().catch(() => "");
      if (res.status === 400) throw new VendorRejectedError("Play Integrity could not decode the token");
      if (res.status === 401) {
        cached = null;
        throw notConfigured("Google rejected our credentials (401)");
      }
      if (res.status === 403) {
        throw new VendorForbiddenError(
          "Play Integrity decodeIntegrityToken answered 403: our service account lacks access to this app, OR the token was minted for another app or project [unverified which; a caller can send the latter]",
        );
      }
      if (res.status !== 200) throw new VendorUnavailableError(`Play Integrity decodeIntegrityToken answered ${res.status}`);
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new VendorUnavailableError("Play Integrity response was not JSON");
      }
      const payload = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>).tokenPayloadExternal : undefined;
      if (typeof payload !== "object" || payload === null) throw new VendorUnavailableError("Play Integrity response had no tokenPayloadExternal");
      return payload;
    },
  };
}
