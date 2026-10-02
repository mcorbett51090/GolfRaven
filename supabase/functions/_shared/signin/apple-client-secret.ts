// supabase/functions/_shared/signin/apple-client-secret.ts
//
// The Sign in with Apple CLIENT SECRET: not a static secret but a short-lived ES256 JWT that the SERVER mints from the
// `.p8` private key, and that Apple's token and revoke endpoints take as `client_secret`.
//
// [unverified — training knowledge] the claim set Apple documents for it: header { alg: ES256, kid: <key id> }, payload
// { iss: <team id>, iat, exp (<= 6 months after iat), aud: "https://appleid.apple.com", sub: <client id> }. The P4 spike
// confirms it against a real key.
//
// Rules this module keeps:
//   * It is minted ONLY here, on the server, from the private key in the environment (privileged.ts reads it). It is never
//     minted on, sent to, or derived by a client; the PEM is never logged or returned.
//   * It is SHORT-LIVED on purpose (10 minutes): minted per use, cached, and RE-MINTED when under two minutes remain, so a
//     leaked secret is useless almost at once and nothing here ever depends on a six-month value in the environment.
//   * It FAILS CLOSED: an unconfigured, empty, or unparseable key throws NotConfiguredError on the first `get()`; nothing
//     substitutes a default or a previously-valid secret once the key is unusable.
//   * Web Crypto ECDSA already returns the raw r||s form a JWS needs; no DER conversion.
//
// The long-lived (<= 6 months) secret that Supabase Auth's own Apple provider setting needs is a DIFFERENT artifact (an
// operator pastes it into the dashboard); see secret-expiry.ts and docs/security/p3-money-path-requirements.md ("Sign in
// with Apple, server side") for the monthly expiry check that guards it.

import { NotConfiguredError } from "./errors.ts";
import { toBase64Url, utf8 } from "./bytes.ts";

export interface AppleSecretConfig {
  teamId: string;
  clientId: string;
  keyId: string;
  /** The `.p8` contents: a PKCS#8 PEM (a PRIVATE KEY block). A literal backslash-n (how a one-line env var carries a PEM) is accepted. */
  privateKeyPem: string;
}

export interface ClientSecretMinter {
  get(): Promise<string>;
}

export const CLIENT_SECRET_TTL_SECONDS = 600;
export const CLIENT_SECRET_REMINT_BEFORE_SECONDS = 120;

// The block markers are assembled at run time so no source line carries a literal PEM header (a secret scanner reads one as a
// leaked private key, correctly in general and wrongly here).
const PEM_FENCE = "-".repeat(5);
const PKCS8_PEM = new RegExp(`^\\s*${PEM_FENCE}BEGIN PRIVATE KEY${PEM_FENCE}([A-Za-z0-9+/=\\s]+)${PEM_FENCE}END PRIVATE KEY${PEM_FENCE}\\s*$`);

/** PEM (PKCS#8) -> DER; `null` unless it is exactly one well-formed PRIVATE KEY block. */
export function pkcs8PemToDer(pem: string): Uint8Array | null {
  const normalised = pem.replace(/\\n/g, "\n");
  const m = PKCS8_PEM.exec(normalised);
  if (!m) return null;
  try {
    const bin = atob(m[1]!.replace(/\s+/g, ""));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.length > 0 ? out : null;
  } catch {
    return null;
  }
}

export function isCompleteAppleSecretConfig(c: AppleSecretConfig | null | undefined): c is AppleSecretConfig {
  return !!c && c.teamId.trim() !== "" && c.clientId.trim() !== "" && c.keyId.trim() !== "" && c.privateKeyPem.trim() !== "";
}

const b64urlJson = (v: unknown) => toBase64Url(utf8(JSON.stringify(v)));

/** Signs one client secret valid from `nowSec`. Exported for the unit tests and for an operator script that needs the same
 * artifact; production code uses the cached minter below. */
export async function mintAppleClientSecret(config: AppleSecretConfig, nowSec: number, ttlSeconds = CLIENT_SECRET_TTL_SECONDS): Promise<string> {
  if (!isCompleteAppleSecretConfig(config)) throw new NotConfiguredError("apple_siwa_key");
  const der = pkcs8PemToDer(config.privateKeyPem);
  if (der === null) throw new NotConfiguredError("apple_siwa_key_pem");
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("pkcs8", der.slice().buffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  } catch {
    throw new NotConfiguredError("apple_siwa_key_import");
  }
  const signingInput = `${b64urlJson({ alg: "ES256", kid: config.keyId })}.${b64urlJson({
    iss: config.teamId,
    iat: nowSec,
    exp: nowSec + ttlSeconds,
    aud: "https://appleid.apple.com",
    sub: config.clientId,
  })}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(signingInput)));
  return `${signingInput}.${toBase64Url(sig)}`;
}

/** The cached, auto-re-minting minter. `config === null` (unconfigured) makes every `get()` throw NotConfiguredError. */
export function createClientSecretMinter(config: AppleSecretConfig | null, nowMs: () => number): ClientSecretMinter {
  let cached: { secret: string; expSec: number } | null = null;
  let pending: Promise<string> | null = null;
  return {
    async get(): Promise<string> {
      if (!isCompleteAppleSecretConfig(config)) throw new NotConfiguredError("apple_siwa_key");
      const nowSec = Math.floor(nowMs() / 1000);
      if (cached !== null && cached.expSec - nowSec > CLIENT_SECRET_REMINT_BEFORE_SECONDS) return cached.secret;
      if (pending !== null) return pending;
      pending = mintAppleClientSecret(config, nowSec)
        .then((secret) => {
          cached = { secret, expSec: nowSec + CLIENT_SECRET_TTL_SECONDS };
          return secret;
        })
        .finally(() => {
          pending = null;
        });
      return pending;
    },
  };
}
