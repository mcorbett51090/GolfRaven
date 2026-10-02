// supabase/functions/_shared/rewards/devicecheck-client.ts
//
// PRODUCTION adapter for Apple DeviceCheck's two persistent bits (build plan
// §7.5: bit0 = "an account that received a monetary reward has used this
// device", bit1 = "an account later voided for fraud has used this device").
//
// ⚠ LIVE VENDOR VERIFICATION IS NOT EXERCISED. This environment has no Apple
// Developer account, no DeviceCheck key and no network route to Apple. This
// module is tested only against a scripted `fetch` (supabase/tests/unit/
// devicecheck-client.test.ts). Everything about Apple's wire contract below is
// `[unverified — training knowledge]`:
//   - hosts api.devicecheck.apple.com / api.development.devicecheck.apple.com,
//     paths /v1/query_two_bits and /v1/update_two_bits;
//   - `Authorization: Bearer <ES256 JWT>` with header {alg, kid} and claims
//     {iss: <team id>, iat};
//   - request body {device_token, transaction_id, timestamp(ms)} (+ bit0/bit1
//     for update);
//   - query response: 200 JSON {bit0, bit1, last_update_time:"YYYY-MM"}, or 200
//     with the text "Failed to find bit state" when the bits were never set;
//   - 400 = bad/missing device token; 401/403 = our JWT/credentials rejected;
//     429/5xx = try later.
//
// FAIL CLOSED. With no config, an incomplete config, or an unusable private
// key, every call throws `VendorNotConfiguredError` — the handler turns that
// into a 503, never into a clean reading. An unrecognised 200 body is
// `VendorUnavailableError`, NOT "bits clear": the only text accepted as "never
// set" is the one documented phrase.

import { pemToDer, signJwtEs256, type VendorHttp } from "./vendor-http.ts";
import { type DeviceBits, VendorNotConfiguredError, VendorRejectedError, VendorUnavailableError } from "./types.ts";

export interface DeviceCheckConfig {
  teamId: string;
  keyId: string;
  /** PKCS#8 PEM of the DeviceCheck private key (.p8). A SECRET: read from the
   * environment by privileged.ts's config loader, never from the repo. */
  privateKeyPem: string;
  environment: "production" | "development";
}

export interface DeviceCheckClient {
  queryTwoBits(deviceTokenB64: string): Promise<DeviceBits>;
  updateTwoBits(deviceTokenB64: string, bits: { bit0: boolean; bit1: boolean }): Promise<void>;
}

const HOSTS: Record<DeviceCheckConfig["environment"], string> = {
  production: "https://api.devicecheck.apple.com",
  development: "https://api.development.devicecheck.apple.com",
};

const NEVER_SET_RE = /^\s*failed to find bit state\.?\s*$/i;
const LAST_UPDATE_RE = /^\d{4}-(0[1-9]|1[0-2])$/;

export function isCompleteDeviceCheckConfig(c: DeviceCheckConfig | null): c is DeviceCheckConfig {
  return (
    c !== null &&
    c.teamId.length > 0 &&
    c.keyId.length > 0 &&
    c.privateKeyPem.length > 0 &&
    (c.environment === "production" || c.environment === "development")
  );
}

export function createDeviceCheckClient(config: DeviceCheckConfig | null, http: VendorHttp): DeviceCheckClient {
  const notConfigured = (why: string) => new VendorNotConfiguredError(`DeviceCheck is not configured: ${why}`);

  async function call(path: "/v1/query_two_bits" | "/v1/update_two_bits", payload: Record<string, unknown>): Promise<string> {
    if (!isCompleteDeviceCheckConfig(config)) throw notConfigured("team id, key id, private key and environment are all required");
    const der = pemToDer(config.privateKeyPem);
    if (!der) throw notConfigured("the private key is not a PKCS#8 PEM");
    let jwt: string;
    try {
      jwt = await signJwtEs256(der, { kid: config.keyId, typ: "JWT" }, { iss: config.teamId, iat: Math.floor(http.nowMs() / 1000) });
    } catch {
      throw notConfigured("the private key could not be used to sign (not a P-256 key?)");
    }
    let res: Response;
    try {
      res = await http.fetch(`${HOSTS[config.environment]}${path}`, {
        method: "POST",
        headers: { authorization: `Bearer ${jwt}`, "content-type": "application/json" },
        body: JSON.stringify({ ...payload, transaction_id: http.randomUuid(), timestamp: http.nowMs() }),
        signal: AbortSignal.timeout(http.timeoutMs),
      });
    } catch {
      // Network failure or our own timeout. Never log the token or the JWT.
      throw new VendorUnavailableError(`DeviceCheck ${path} did not complete`);
    }
    const text = await res.text().catch(() => "");
    if (res.status === 200) return text;
    if (res.status === 400) throw new VendorRejectedError(`DeviceCheck ${path} rejected the device token`);
    if (res.status === 401 || res.status === 403) throw notConfigured(`Apple rejected our credentials (${res.status})`);
    throw new VendorUnavailableError(`DeviceCheck ${path} answered ${res.status}`);
  }

  return {
    async queryTwoBits(deviceTokenB64) {
      const text = await call("/v1/query_two_bits", { device_token: deviceTokenB64 });
      if (NEVER_SET_RE.test(text)) return { bit0: false, bit1: false, lastUpdateMonth: null };
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new VendorUnavailableError("DeviceCheck query_two_bits returned an unrecognised body");
      }
      const o = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
      if (!o || typeof o.bit0 !== "boolean" || typeof o.bit1 !== "boolean") {
        throw new VendorUnavailableError("DeviceCheck query_two_bits returned an unrecognised body");
      }
      const last = typeof o.last_update_time === "string" && LAST_UPDATE_RE.test(o.last_update_time) ? o.last_update_time : null;
      return { bit0: o.bit0, bit1: o.bit1, lastUpdateMonth: last };
    },
    async updateTwoBits(deviceTokenB64, bits) {
      await call("/v1/update_two_bits", { device_token: deviceTokenB64, bit0: bits.bit0, bit1: bits.bit1 });
    },
  };
}
