// supabase/functions/_shared/checkin/challenge-handler.ts
//
// Pure, DI'd core of POST /v1/checkin/challenge (build plan §4.4 line
// 829: "up to 10 prefetched per player device... 24h TTL for offline
// sites"; §4.7 item 8: "Check-in token / challenge: 30/user/h; at most 10
// unused prefetched challenges per device"). Issues one or more
// single-use `app.checkin_challenge` rows: a live challenge (short TTL)
// or, when `prefetchCount` is given, up to that many offline-prefetch
// challenges (24h TTL), bounded so a device never holds more than 10
// unused ones at once.
//
// The nonce itself: a fresh cryptographically random value, hashed
// (SHA-256) before it is ever handed to `Repo#challenge.insert` — only
// the hash is ever persisted (§4.4: "the table only its hash"), matching
// `course_qr_token`'s own pattern. The RAW nonce is returned to the
// caller once, in the response, and never stored server-side at all.
//
// P3c gate round 2 fixes: device cap (item 7) checked before any device
// row is created; the prefetch-cap count-then-insert race (item 8) is
// closed inside `Repo#challenge.countOpenPrefetched` itself (an advisory
// lock, privileged.ts); `kind` ("live"/"prefetched") is now a real
// column (should-fix), passed straight through rather than inferred
// downstream from TTL width.

import type { Repo } from "../types.ts";
import { Errors } from "../http.ts";

// P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock the
// pool"): exported so checkin-challenge/index.ts can hit this bucket via
// `privileged.ts#hitRateLimitForActor` BEFORE calling `withOwnership` —
// see this file's own `handleChallengeRequest` for why the hit no longer
// happens in here.
export const RATE_LIMIT_PER_USER_HOUR = 30; // build plan §4.7 item 8
const MAX_OPEN_PREFETCHED_PER_DEVICE = 10;
const LIVE_TTL_SECONDS = 120; // matches the rotating-course-QR ≤120s window's order of magnitude for a live in-session challenge
const PREFETCH_TTL_SECONDS = 24 * 60 * 60;
const MAX_PREFETCH_COUNT = 10;
const MAX_DEVICES_PER_USER = 20; // same cap as evidence/handler.ts — one accepted-follow-up constant, not yet centralized

export interface ChallengeRequest {
  deviceId: string;
  facilityId?: string;
  /** Absent/0 -> issue one LIVE challenge. >0 -> issue that many
   * PREFETCHED (offline-TTL) challenges instead (§7.6). */
  prefetchCount?: number;
}

export interface IssuedChallenge {
  id: string;
  nonce: string;
  expiresAt: string;
  kind: "live" | "prefetched";
}

export interface RandomBytesFn {
  (length: number): Uint8Array;
}
export interface DigestHexFn {
  (bytes: Uint8Array): Promise<string>;
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function handleChallengeRequest(body: ChallengeRequest, repo: Repo, randomBytes: RandomBytesFn, digestHex: DigestHexFn): Promise<IssuedChallenge[]> {
  // ⛔ P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock
  // the pool"): the rate-limit hit used to happen HERE, via
  // `repo.rateLimit.hit` — removed. `Repo` no longer has a `rateLimit`
  // member at all (types.ts). checkin-challenge/index.ts now hits
  // `checkin-challenge:user` via `hitRateLimitForActor` BEFORE calling
  // `withOwnership`, so this function is only ever reached once that has
  // already succeeded — see privileged.ts#hitRateLimitForActor's own doc
  // for the full reasoning.
  const knownDevice = await repo.device.findOwn(body.deviceId);
  if (!knownDevice) {
    const existingDeviceCount = await repo.device.countForUser();
    if (existingDeviceCount >= MAX_DEVICES_PER_USER) {
      throw Errors.unprocessable("device_limit_exceeded", `this account already has ${MAX_DEVICES_PER_USER} devices on record`);
    }
  }
  const device = knownDevice ?? (await repo.device.ensureOwn(body.deviceId, null));
  const prefetchCount = body.prefetchCount ?? 0;

  if (prefetchCount === 0) {
    const nonce = randomBytes(32);
    const nonceHash = await digestHex(nonce);
    const expiresAt = new Date(repo.now().getTime() + LIVE_TTL_SECONDS * 1000).toISOString();
    const inserted = await repo.challenge.insert({ deviceId: device.id, facilityId: body.facilityId ?? null, nonceHash, kind: "live", expiresAt });
    return [{ id: inserted.id, nonce: toBase64Url(nonce), expiresAt: inserted.expiresAt, kind: "live" }];
  }

  if (prefetchCount < 0 || prefetchCount > MAX_PREFETCH_COUNT) {
    throw Errors.badRequest(`prefetchCount must be between 1 and ${MAX_PREFETCH_COUNT}`);
  }
  const openCount = await repo.challenge.countOpenPrefetched(device.id);
  const room = MAX_OPEN_PREFETCHED_PER_DEVICE - openCount;
  if (room <= 0) {
    throw Errors.tooManyRequests(`device already holds ${MAX_OPEN_PREFETCHED_PER_DEVICE} unused prefetched challenges`);
  }
  const toIssue = Math.min(prefetchCount, room);
  const issued: IssuedChallenge[] = [];
  const expiresAt = new Date(repo.now().getTime() + PREFETCH_TTL_SECONDS * 1000).toISOString();
  for (let i = 0; i < toIssue; i++) {
    const nonce = randomBytes(32);
    const nonceHash = await digestHex(nonce);
    const inserted = await repo.challenge.insert({ deviceId: device.id, facilityId: body.facilityId ?? null, nonceHash, kind: "prefetched", expiresAt });
    issued.push({ id: inserted.id, nonce: toBase64Url(nonce), expiresAt: inserted.expiresAt, kind: "prefetched" });
  }
  return issued;
}
