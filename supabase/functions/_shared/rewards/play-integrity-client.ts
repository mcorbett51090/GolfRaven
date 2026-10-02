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
//   - 400 = the token is not decodable; 401/403 = our credentials rejected;
//     429/5xx = try later.
//
// FAIL CLOSED: no/incomplete config, or an unusable key, throws
// `VendorNotConfiguredError` on every call.

import { pemToDer, signJwtRs256, type VendorHttp } from "./vendor-http.ts";
import { VendorNotConfiguredError, VendorRejectedError, VendorUnavailableError } from "./types.ts";

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

export function createIntegrityDecoder(config: PlayIntegrityConfig | null, http: VendorHttp): IntegrityDecoder {
  const notConfigured = (why: string) => new VendorNotConfiguredError(`Play Integrity is not configured: ${why}`);
  let cached: { token: string; expiresAtMs: number } | null = null;

  async function accessToken(cfg: PlayIntegrityConfig): Promise<string> {
    if (cached && cached.expiresAtMs - 60_000 > http.nowMs()) return cached.token;
    const der = pemToDer(cfg.serviceAccountPrivateKeyPem);
    if (!der) throw notConfigured("the service-account key is not a PKCS#8 PEM");
    const iat = Math.floor(http.nowMs() / 1000);
    let assertion: string;
    try {
      assertion = await signJwtRs256(der, { typ: "JWT" }, { iss: cfg.serviceAccountEmail, scope: SCOPE, aud: TOKEN_URL, iat, exp: iat + 3600 });
    } catch {
      throw notConfigured("the service-account key could not be used to sign (not an RSA key?)");
    }
    let res: Response;
    try {
      res = await http.fetch(TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer")}&assertion=${encodeURIComponent(assertion)}`,
        signal: AbortSignal.timeout(http.timeoutMs),
      });
    } catch {
      throw new VendorUnavailableError("Google OAuth token request did not complete");
    }
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
      const bearer = await accessToken(config);
      let res: Response;
      try {
        res = await http.fetch(`https://playintegrity.googleapis.com/v1/${encodeURIComponent(config.packageName)}:decodeIntegrityToken`, {
          method: "POST",
          headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" },
          body: JSON.stringify({ integrity_token: integrityToken }),
          signal: AbortSignal.timeout(http.timeoutMs),
        });
      } catch {
        throw new VendorUnavailableError("Play Integrity decodeIntegrityToken did not complete");
      }
      const text = await res.text().catch(() => "");
      if (res.status === 400) throw new VendorRejectedError("Play Integrity could not decode the token");
      if (res.status === 401 || res.status === 403) {
        cached = null;
        throw notConfigured(`Google rejected our credentials (${res.status})`);
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
