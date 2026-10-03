// supabase/functions/_shared/me/offline-seed-handler.ts
//
// Pure, DI'd core of the `me-offline-seed` Edge Function (`POST /v1/me/offline-seed`; build plan §7.6 "Offline staff path (G-P1-07)": "a per-(account,
// device) seed provisioned by the server while online and held in the secure store"). Returns the caller's OWN device's TOTP seed so the device can
// compute the offline staff code without a network.
//
// WHERE THE SEED COMES FROM. Nothing per-device is stored. The seed is `HMAC-SHA256(K, label || user_id || device_id || seed_version)`, computed INSIDE
// Postgres by `private.offline_seed_for_actor` (migration 0045) with K read from Vault by a SECURITY DEFINER function owned by `private_definer`: K is
// never returned to any role and never reaches this runtime. Only the derived, per-(account, device, version) seed crosses the wire, and only to the
// device it belongs to. Re-provisioning therefore returns the SAME seed (a reinstall that lost the secure store recovers); `rotate: true` increments
// the device's seed version, which gives a different seed and invalidates every code from the old one.

import type { Repo } from "../types.ts";
import { Errors } from "../http.ts";
import { OFFLINE_CODE_ALGORITHM, OFFLINE_CODE_DIGITS, OFFLINE_CODE_STEP_SECONDS } from "../offline-code/params.ts";
import { base32Encode } from "../offline-code/totp.ts";

// Same UUID pattern the other me-* endpoints pin a deviceId to.
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export interface OfflineSeedRequest {
  deviceId: string;
  rotate?: boolean;
}

/** The response body (inside the usual `{ "data": ... }` envelope). The mobile client implements exactly this: `seed` is the RFC 4648 base32 (upper
 * case, no padding) encoding of 32 bytes; the code at a unix time `t` is HOTP-HMAC-SHA-256(seed bytes, floor(t / stepSeconds)) to `digits` digits. */
export interface OfflineSeedResponse {
  seed: string;
  stepSeconds: typeof OFFLINE_CODE_STEP_SECONDS;
  digits: typeof OFFLINE_CODE_DIGITS;
  algorithm: typeof OFFLINE_CODE_ALGORITHM;
  seedVersion: number;
  /** The server's clock when the seed was issued (ISO-8601), so the client can estimate its own clock offset. */
  issuedAt: string;
}

const KEYS = new Set(["deviceId", "rotate"]);

/** STRICT body validation: a JSON object whose only keys are `deviceId` (a UUID) and, optionally, `rotate` (a boolean). An unknown key, a wrong type or
 * a non-object is a 400 (the same strictness as the evidence body: a typo in a field name must not silently mean "no rotation"). */
export function parseOfflineSeedRequest(body: unknown): OfflineSeedRequest {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw Errors.badRequest('body must be {"deviceId": string (UUID), "rotate"?: boolean}');
  }
  const o = body as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!KEYS.has(k)) throw Errors.badRequest(`unknown field "${k.slice(0, 40)}"`);
  }
  if (typeof o.deviceId !== "string" || !UUID_RE.test(o.deviceId)) throw Errors.badRequest("deviceId must be a UUID");
  if (o.rotate !== undefined && typeof o.rotate !== "boolean") throw Errors.badRequest("rotate must be a boolean");
  return o.rotate === undefined ? { deviceId: o.deviceId } : { deviceId: o.deviceId, rotate: o.rotate };
}

export async function handleOfflineSeedRequest(body: OfflineSeedRequest, repo: Repo): Promise<OfflineSeedResponse> {
  const provisioned = await repo.offlineCode.provisionSeed(body.deviceId, body.rotate === true);
  // null = not the caller's device: another account's device, or one that does not exist, are the same answer (no oracle on device ids). The
  // endpoint never creates a device; the app registers it first (push-token, checkin-challenge prefetch, ...).
  if (provisioned === null) throw Errors.notFound("no such device on this account");
  try {
    return {
      seed: base32Encode(provisioned.seed),
      stepSeconds: OFFLINE_CODE_STEP_SECONDS,
      digits: OFFLINE_CODE_DIGITS,
      algorithm: OFFLINE_CODE_ALGORITHM,
      seedVersion: provisioned.seedVersion,
      issuedAt: provisioned.issuedAt,
    };
  } finally {
    provisioned.seed.fill(0); // best effort: the raw bytes do not outlive the response being built
  }
}
