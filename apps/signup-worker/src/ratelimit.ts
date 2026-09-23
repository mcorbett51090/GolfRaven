/**
 * Abuse controls: per-IP-key and per-email daily caps (gate-review S6).
 *
 * Adapted from the owner's production Worker
 * (raven-site-kit/secure-upload/worker/src/ratelimit.ts) — same KV
 * get-then-put counter shape and the same documented limitation: Workers
 * KV is eventually consistent with no atomic increment, so this is an
 * approximate, defense-in-depth limiter, not a hard ceiling. That's
 * accepted here (unlike the reference Worker's site-wide spend cap, which
 * layers a Durable Object on top): this endpoint only ever sends a small
 * confirmation email, so the worst case of a missed race is a handful of
 * extra emails, not the R2/Workers cost-exhaustion risk the DO exists for
 * there — per this task's scope, "rate limiting uses KV ... and TTL only".
 *
 * Per the task's privacy requirement, the IP address itself is NEVER
 * stored — only `sha256(pepper + ":ip:" + ip)` is used as the KV key.
 */

import type { Env } from "./config";
import { hashWithPepper } from "./tokens";

const DAY_SECONDS = 24 * 60 * 60;

function utcDateKey(): string {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

async function readCount(kv: Env["RATE_LIMIT_KV"], key: string): Promise<number> {
  const raw = await kv.get(key);
  const n = raw ? parseInt(raw, 10) : 0;
  return Number.isFinite(n) ? n : 0;
}

async function bumpCount(kv: Env["RATE_LIMIT_KV"], key: string, current: number): Promise<void> {
  // expirationTtl resets on every write; the key is always scoped to
  // today's UTC date, so a stale TTL just means it survives a little past
  // midnight before the next day's key takes over.
  await kv.put(key, String(current + 1), { expirationTtl: DAY_SECONDS * 2 });
}

export interface RateLimitResult {
  allowed: boolean;
  reason?: "ip-daily-cap" | "email-daily-cap";
}

/**
 * Checks-and-consumes one slot against BOTH the per-IP-key and per-email
 * daily caps. Callers should treat a `false` `allowed` as "stop here,
 * return 429" — do not do the Turnstile/Resend work first.
 */
export async function checkAndConsumeRateLimit(
  env: Env,
  ip: string,
  emailLc: string,
  ipDailyCap: number,
  emailDailyCap: number,
): Promise<RateLimitResult> {
  const day = utcDateKey();
  const ipHash = await hashWithPepper(env.TOKEN_PEPPER, `ip:${ip}`);
  const emailHash = await hashWithPepper(env.TOKEN_PEPPER, `email:${emailLc}`);
  const ipKey = `rl:ip:${day}:${ipHash}`;
  const emailKey = `rl:email:${day}:${emailHash}`;

  const ipCount = await readCount(env.RATE_LIMIT_KV, ipKey);
  if (ipCount >= ipDailyCap) {
    return { allowed: false, reason: "ip-daily-cap" };
  }
  const emailCount = await readCount(env.RATE_LIMIT_KV, emailKey);
  if (emailCount >= emailDailyCap) {
    return { allowed: false, reason: "email-daily-cap" };
  }

  await bumpCount(env.RATE_LIMIT_KV, ipKey, ipCount);
  await bumpCount(env.RATE_LIMIT_KV, emailKey, emailCount);
  return { allowed: true };
}
