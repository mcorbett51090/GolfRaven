/**
 * Abuse controls: per-IP-key and per-email daily caps (gate-review S6),
 * plus the confirmation-email send limits added for gate findings F5/F6.
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
 * stored — only a peppered hash is used as the KV key.
 *
 * Gate finding F5 (order of checks): the per-IP cap and the per-EMAIL cap
 * are now two SEPARATE functions rather than one combined check, so
 * index.ts can check/consume the IP cap first, verify Turnstile, and only
 * THEN check/consume the per-email cap — otherwise an attacker holding a
 * junk turnstileToken could burn a victim's per-email slot without ever
 * solving a challenge.
 *
 * Gate finding F5/F6 (IPv6): the per-IP key is now the requester's IPv6
 * /64 rather than the full address, so rotating within one /64 (which an
 * attacker fully controls) no longer resets the cap.
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

async function bumpCount(kv: Env["RATE_LIMIT_KV"], key: string, current: number, ttlSeconds: number): Promise<void> {
  // expirationTtl resets on every write; callers scope the key to today's
  // UTC date (or a fixed window), so a stale TTL just means it survives a
  // little past the window boundary before the next key takes over.
  await kv.put(key, String(current + 1), { expirationTtl: ttlSeconds });
}

/**
 * Gate finding F5/F6: groups an IPv6 address to its /64 so an attacker who
 * controls a whole /64 (common with residential/VPS IPv6 allocations)
 * can't bypass the cap by rotating the low 64 bits. Best-effort: handles
 * the full 8-hextet form and the single "::" shorthand, which covers the
 * addresses CF-Connecting-IP actually sends. IPv4 addresses (and the
 * "unknown" fallback) pass through unchanged.
 */
export function rateLimitIpKeyMaterial(ip: string): string {
  if (!ip.includes(":")) return ip; // IPv4 or "unknown"
  const withoutZone = ip.split("%")[0] ?? ip;
  const parts = withoutZone.split(":");
  let hextets = parts;
  const collapseIdx = parts.indexOf("");
  if (collapseIdx !== -1) {
    const nonEmpty = parts.filter((p) => p !== "");
    const zerosNeeded = Math.max(8 - nonEmpty.length, 0);
    hextets = [...parts.slice(0, collapseIdx), ...Array(zerosNeeded).fill("0"), ...parts.slice(collapseIdx + 1)].filter(
      (p) => p !== "",
    );
  }
  return `${hextets.slice(0, 4).join(":")}::/64`;
}

export interface RateLimitResult {
  allowed: boolean;
  reason?: "ip-daily-cap" | "email-daily-cap";
}

/** Checks-and-consumes one slot against the per-IP-key (IPv6 /64-scoped) daily cap. */
export async function checkAndConsumeIpRateLimit(env: Env, ip: string, ipDailyCap: number): Promise<RateLimitResult> {
  const day = utcDateKey();
  const ipHash = await hashWithPepper(env.TOKEN_PEPPER, `ip:${rateLimitIpKeyMaterial(ip)}`);
  const ipKey = `rl:ip:${day}:${ipHash}`;

  const ipCount = await readCount(env.RATE_LIMIT_KV, ipKey);
  if (ipCount >= ipDailyCap) {
    return { allowed: false, reason: "ip-daily-cap" };
  }
  await bumpCount(env.RATE_LIMIT_KV, ipKey, ipCount, DAY_SECONDS * 2);
  return { allowed: true };
}

/** Checks-and-consumes one slot against the per-email daily cap. Call ONLY after Turnstile succeeds (F5). */
export async function checkAndConsumeEmailRateLimit(env: Env, emailLc: string, emailDailyCap: number): Promise<RateLimitResult> {
  const day = utcDateKey();
  const emailHash = await hashWithPepper(env.TOKEN_PEPPER, `email:${emailLc}`);
  const emailKey = `rl:email:${day}:${emailHash}`;

  const emailCount = await readCount(env.RATE_LIMIT_KV, emailKey);
  if (emailCount >= emailDailyCap) {
    return { allowed: false, reason: "email-daily-cap" };
  }
  await bumpCount(env.RATE_LIMIT_KV, emailKey, emailCount, DAY_SECONDS * 2);
  return { allowed: true };
}

export interface SendLimitResult {
  allowed: boolean;
  reason?: "resend-cooldown" | "email-send-daily-cap" | "global-send-daily-cap";
}

/**
 * Gate finding F6: governs whether a confirmation email may actually be
 * SENT (separate from the per-email signup-attempt cap above, which
 * governs API requests, not emails). Three independent limits, all
 * checked-and-consumed together so a caller gets one allow/deny:
 *
 *   - a per-email cooldown (default 10 min) between sends,
 *   - a per-email daily cap on emails sent (default 3/day),
 *   - a global daily cap on emails sent across all addresses (configurable,
 *     default 500/day — Env.GLOBAL_DAILY_SEND_CAP).
 *
 * On denial, the caller must still return the generic 202 (no enumeration
 * signal) but skip the send and log an error (see index.ts).
 */
export async function checkAndConsumeResendSendLimits(
  env: Env,
  emailLc: string,
  opts: { cooldownSeconds: number; emailDailyCap: number; globalDailyCap: number },
): Promise<SendLimitResult> {
  const day = utcDateKey();
  const emailHash = await hashWithPepper(env.TOKEN_PEPPER, `email:${emailLc}`);

  const cooldownKey = `rl:send-cooldown:${emailHash}`;
  const onCooldown = await env.RATE_LIMIT_KV.get(cooldownKey);
  if (onCooldown) {
    return { allowed: false, reason: "resend-cooldown" };
  }

  const emailDailyKey = `rl:send-email-daily:${day}:${emailHash}`;
  const emailDailyCount = await readCount(env.RATE_LIMIT_KV, emailDailyKey);
  if (emailDailyCount >= opts.emailDailyCap) {
    return { allowed: false, reason: "email-send-daily-cap" };
  }

  const globalDailyKey = `rl:send-global-daily:${day}`;
  const globalDailyCount = await readCount(env.RATE_LIMIT_KV, globalDailyKey);
  if (globalDailyCount >= opts.globalDailyCap) {
    return { allowed: false, reason: "global-send-daily-cap" };
  }

  await env.RATE_LIMIT_KV.put(cooldownKey, "1", { expirationTtl: opts.cooldownSeconds });
  await bumpCount(env.RATE_LIMIT_KV, emailDailyKey, emailDailyCount, DAY_SECONDS * 2);
  await bumpCount(env.RATE_LIMIT_KV, globalDailyKey, globalDailyCount, DAY_SECONDS * 2);
  return { allowed: true };
}
