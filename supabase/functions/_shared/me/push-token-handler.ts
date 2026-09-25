// supabase/functions/_shared/me/push-token-handler.ts
//
// Pure, DI'd core of the `me-push-token` Edge Function (`POST
// /v1/me/push-token`, build plan §4.7.1a inventory: "me-push-token";
// line 832: "push_token — replaced on reinstall, deleted by DELETE
// /v1/me"). Registers/updates the caller's OWN push token for their OWN
// device.

import type { Repo } from "../types.ts";
import { Errors } from "../http.ts";

// Same accepted-follow-up constant `evidence/handler.ts` and `checkin/
// challenge-handler.ts` already use (no plan-stated number — both of
// those files' own footnotes say so; not yet centralized, per their own
// comments). `app.push_token`'s own PRIMARY KEY is `(user_id, device_id)`
// (0003_player_core.sql) — a device can hold at most ONE token by
// construction, so "cap the number of tokens per user" (task
// instruction) reduces to capping the number of DEVICES a user can
// register at all, which is exactly this constant, checked the same way
// evidence/handler.ts and challenge-handler.ts already check it (BEFORE
// creating a new device row, never after). Reusing the SAME number
// rather than inventing a second, independent push-token-specific cap
// keeps "how many devices/tokens can one account have" one answer, not
// two that could drift.
const MAX_DEVICES_PER_USER = 20;

// Expo push tokens are typically `ExponentPushToken[xxxxxxxxxxxxxxxxxxxx]`
// (and FCM/APNs-native tokens are a differently-shaped opaque string on
// some SDK/config combinations) `[unverified — training knowledge on the
// exact Expo/FCM/APNs token grammar]`. Validated loosely here — non-
// empty, printable ASCII, bounded length — rather than pinned to one
// exact regex, so a legitimate token shape this session has not seen
// (a newer SDK version, a different push provider) is never rejected on
// a guess; the bound exists to reject an obviously-wrong payload (empty,
// binary garbage, an absurdly long string) cheaply, before it is ever
// written to the database.
const MAX_TOKEN_LENGTH = 512;

function isValidExpoToken(token: string): boolean {
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) return false;
  return /^[\x20-\x7e]+$/.test(token); // printable ASCII only, no control/binary bytes
}

export interface PushTokenRequest {
  deviceId: string;
  expoToken: string;
  platform?: "ios" | "android";
}

export interface PushTokenResult {
  deviceId: string;
  updatedAt: string;
}

export async function handlePushTokenRequest(body: PushTokenRequest, repo: Repo): Promise<PushTokenResult> {
  if (!isValidExpoToken(body.expoToken)) {
    throw Errors.badRequest(`expoToken must be a non-empty, printable-ASCII string of at most ${MAX_TOKEN_LENGTH} characters`);
  }

  // Resolve/cap the device BEFORE writing a token for it — the SAME
  // ordering evidence/handler.ts and checkin/challenge-handler.ts already
  // use: check the cap against a device that does NOT yet exist, so a
  // request that will be rejected for being over-cap never creates the
  // device row it's about to reject (Repo#device.findOwn's own doc,
  // types.ts).
  const existingDevice = await repo.device.findOwn(body.deviceId);
  if (!existingDevice) {
    const deviceCount = await repo.device.countForUser();
    if (deviceCount >= MAX_DEVICES_PER_USER) {
      throw Errors.unprocessable("device_limit_exceeded", `this account already has ${MAX_DEVICES_PER_USER} devices on record`);
    }
  }
  const device = await repo.device.ensureOwn(body.deviceId, body.platform ?? null);

  // "Register or update" (task instruction): app.push_token's own
  // ON CONFLICT (user_id, device_id) DO UPDATE (privileged.ts) means a
  // reinstall on the SAME device id naturally replaces the old token,
  // matching line 832's own "replaced on reinstall."
  return repo.pushToken.upsert(device.id, body.expoToken);
}
