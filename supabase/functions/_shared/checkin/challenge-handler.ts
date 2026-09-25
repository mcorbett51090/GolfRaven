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
// (SHA-256) before it is ever handed to `Repo#insertChallenge` — only the
// hash is ever persisted (§4.4: "the table only its hash"), matching
// `course_qr_token`'s own pattern. The RAW nonce is returned to the
// caller once, in the response, and never stored server-side at all.

import type { Repo } from "../types.ts";
import { Errors } from "../http.ts";

const RATE_LIMIT_PER_USER_HOUR = 30; // build plan §4.7 item 8
const MAX_OPEN_PREFETCHED_PER_DEVICE = 10;
const LIVE_TTL_SECONDS = 120; // matches the rotating-course-QR ≤120s window's order of magnitude for a live in-session challenge
const PREFETCH_TTL_SECONDS = 24 * 60 * 60;
const MAX_PREFETCH_COUNT = 10;

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

export async function handleChallengeRequest(actorUid: string, body: ChallengeRequest, repo: Repo, randomBytes: RandomBytesFn, digestHex: DigestHexFn): Promise<IssuedChallenge[]> {
  const rateLimit = await repo.hitRateLimit(`checkin-challenge:user:${actorUid}`, 3600, RATE_LIMIT_PER_USER_HOUR);
  if (!rateLimit.ok) throw Errors.tooManyRequests("checkin-challenge rate limit exceeded", rateLimit.retryAfterSeconds);

  const device = await repo.ensureOwnDevice(actorUid, body.deviceId, null);
  const prefetchCount = body.prefetchCount ?? 0;

  if (prefetchCount === 0) {
    const nonce = randomBytes(32);
    const nonceHash = await digestHex(nonce);
    const expiresAt = new Date(repo.now().getTime() + LIVE_TTL_SECONDS * 1000).toISOString();
    const inserted = await repo.insertChallenge({ userId: actorUid, staffUserId: null, deviceId: device.id, facilityId: body.facilityId ?? null, nonceHash, expiresAt });
    return [{ id: inserted.id, nonce: toBase64Url(nonce), expiresAt, kind: "live" }];
  }

  if (prefetchCount < 0 || prefetchCount > MAX_PREFETCH_COUNT) {
    throw Errors.badRequest(`prefetchCount must be between 1 and ${MAX_PREFETCH_COUNT}`);
  }
  const openCount = await repo.countOpenPrefetchedChallenges(device.id);
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
    const inserted = await repo.insertChallenge({ userId: actorUid, staffUserId: null, deviceId: device.id, facilityId: body.facilityId ?? null, nonceHash, expiresAt });
    issued.push({ id: inserted.id, nonce: toBase64Url(nonce), expiresAt, kind: "prefetched" });
  }
  return issued;
}
