/**
 * Env bindings, structural storage interfaces, and the fixed policy
 * constants for the K2 signup backend (build plan §10 P0, K2; decision
 * 0001 Addendum D R3; docs/p0/gate-review.md S5/S6).
 *
 * `D1Like`/`KVLike` are deliberately our OWN narrow interfaces rather than
 * the `@cloudflare/workers-types` `D1Database`/`KVNamespace` types directly.
 * The real bindings satisfy them structurally (they're a superset), so
 * nothing changes for the deployed Worker — but it lets tests pass in a
 * tiny in-memory fake without fighting the full Cloudflare type surface
 * (see test/fakes.ts).
 */

export interface D1PreparedLike {
  bind(...values: unknown[]): D1PreparedLike;
  run(): Promise<unknown>;
  first<T = unknown>(): Promise<T | null>;
  all<T = unknown>(): Promise<{ results: T[] }>;
}

export interface D1Like {
  prepare(query: string): D1PreparedLike;
}

export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
}

export interface Env {
  /** D1 binding holding the `signups` table (migrations/0001_create_signups.sql). */
  DB: D1Like;
  /** KV binding used ONLY for rate-limit counters (hashed IP key + TTL). No PII stored here. */
  RATE_LIMIT_KV: KVLike;

  /** Resend API key. Secret — set with `wrangler secret put RESEND_API_KEY`. */
  RESEND_API_KEY: string;
  /** Cloudflare Turnstile secret key. Secret — `wrangler secret put TURNSTILE_SECRET`. */
  TURNSTILE_SECRET: string;
  /**
   * Server-side pepper mixed into every token/IP hash before it's stored.
   * Secret — `wrangler secret put TOKEN_PEPPER`. Defense-in-depth: tokens
   * are already 256-bit random values, so this mainly guards the per-IP
   * rate-limit KV keys (otherwise a raw-IP hash) and gives a rotation
   * lever if the hashing scheme ever needs to change.
   */
  TOKEN_PEPPER: string;

  /** e.g. `"GolfRaven <hello@golfraven.example>"` — must be on a Resend-verified sending domain. */
  RESEND_FROM_EMAIL: string;
  /** e.g. `"https://golfraven.example"` — used to build confirm/unsubscribe links. No trailing slash. */
  PUBLIC_BASE_URL: string;
  /**
   * Optional CSV of origins allowed to call this API cross-origin, for local
   * dev only (e.g. `http://localhost:8788`). Empty by default: the Worker
   * is served same-origin under `golfraven.<tld>/api/*`, so the landing
   * page needs no CORS at all in production. See responses.ts corsHeaders().
   */
  ALLOWED_DEV_ORIGINS?: string;
  /**
   * Global daily cap on confirmation emails actually SENT (gate finding F6)
   * — a send-volume backstop on top of the per-IP/per-email attempt caps in
   * ratelimit.ts. Configurable so the owner can raise/lower it without a
   * code change. Optional; defaults to DEFAULT_GLOBAL_DAILY_SEND_CAP below
   * when unset or blank.
   */
  GLOBAL_DAILY_SEND_CAP?: string;
  /**
   * ISO-8601 date/time the K2 gate closes (day 0 + 42 days) — set by the
   * owner once day 0 is logged in docs/p0/K2.md. Used ONLY by the retention
   * cron (gate finding F11) to decide when it's safe to delete a row that
   * was unsubscribed >30 days ago: never before this date, so a K2 verdict
   * can always be reconstructed from confirmed_at. Leave unset/blank until
   * day 0 is known — the cron skips that deletion class entirely until then.
   */
  K2_GATE_CLOSES_AT?: string;
}

/**
 * Consent-copy versions the backend will accept. Bump apps/landing's
 * `CONSENT_VERSION` (main.js) alongside adding the new value here whenever
 * the privacy/consent copy changes materially — an unrecognized version is
 * rejected (400), never silently accepted, so a stored `consent_version`
 * always matches wording that was actually reviewed.
 */
export const ALLOWED_CONSENT_VERSIONS: readonly string[] = ["2026-09-23"];

/** Single-use confirmation token lifetime (README "How signups work" / gate-review S6). */
export const CONFIRM_TOKEN_TTL_SECONDS = 48 * 60 * 60;

/** Per-IP-key signup attempts allowed per UTC day (abuse control, gate-review S6). */
export const SIGNUP_IP_DAILY_CAP = 20;
/** Per-email signup attempts allowed per UTC day (bounds resend-token spam to one address). */
export const SIGNUP_EMAIL_DAILY_CAP = 5;

export const MAX_EMAIL_LENGTH = 254;
/**
 * `source` is a free-text attribution tag — apps/landing sends the
 * visitor's trail-preference radio value here (there's no dedicated
 * `trail` column in the `signups` table; this is where that signal is
 * kept), and a promo-channel tag is an equally valid use.
 */
export const MAX_SOURCE_LENGTH = 64;
export const MAX_TURNSTILE_TOKEN_LENGTH = 4096;

/** Gate finding F10: reject an oversized/absent Content-Length before parsing. */
export const MAX_SIGNUP_BODY_BYTES = 8 * 1024;

/** Gate finding F6: minimum time between confirmation emails to the same address. */
export const RESEND_COOLDOWN_SECONDS = 10 * 60;
/** Gate finding F6: confirmation emails actually sent to one address per UTC day. */
export const RESEND_EMAIL_DAILY_CAP = 3;
/** Gate finding F6: fallback for Env.GLOBAL_DAILY_SEND_CAP when unset/blank. */
export const DEFAULT_GLOBAL_DAILY_SEND_CAP = 500;

/** Gate finding F11: unconfirmed rows are purged after this many days. */
export const UNCONFIRMED_RETENTION_DAYS = 30;
/** Gate finding F11: unsubscribed (and confirmed) rows are purged this long after unsubscribe. */
export const UNSUBSCRIBED_RETENTION_DAYS = 30;

/**
 * N2: the earliest `K2_GATE_CLOSES_AT` could ever legitimately be — plan P0
 * start (2026-10-05) + the 42-day gate window. Any configured value earlier
 * than this is necessarily wrong (either a typo, or day 0 itself typed into
 * this var by mistake — exactly the gate-review probe that caught this),
 * so it is rejected the same as a malformed value.
 */
export const K2_GATE_CLOSES_AT_FLOOR = "2026-11-16T00:00:00Z";
/**
 * N2: once the gate closes, retention still waits this many additional
 * days before it's allowed to delete a confirmed-then-unsubscribed row —
 * the same margin as UNSUBSCRIBED_RETENTION_DAYS, but a DISTINCT knob: this
 * one gates *whether* deletion may run at all (a grace period after the
 * verdict window), the other gates *which* rows within that run are old
 * enough to delete.
 */
export const K2_VERDICT_GRACE_DAYS = 30;

const K2_GATE_CLOSES_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export type K2GateCheckResult = { ok: true; gateCloses: Date } | { ok: false; reason: string };

/**
 * N2: validates `Env.K2_GATE_CLOSES_AT` strictly — a strict full ISO-8601
 * UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`), not earlier than
 * K2_GATE_CLOSES_AT_FLOOR. Anything else (unset, malformed, a bare year
 * like `"2026"`, a bare `"1"`, a date-only string, or a date earlier than
 * the floor) is rejected — the retention cron (index.ts runRetentionCron)
 * must NOT delete any confirmed-then-unsubscribed row unless this returns
 * `ok: true`, and even then only once `now >= gateCloses + K2_VERDICT_GRACE_DAYS`.
 */
export function checkK2GateClosesAt(raw: string | undefined): K2GateCheckResult {
  if (!raw || raw.trim() === "") {
    return { ok: false, reason: "unset" };
  }
  if (!K2_GATE_CLOSES_AT_RE.test(raw)) {
    return { ok: false, reason: "malformed (must match YYYY-MM-DDTHH:MM:SSZ)" };
  }
  const gateCloses = new Date(raw);
  if (Number.isNaN(gateCloses.getTime())) {
    return { ok: false, reason: "not a valid calendar date/time" };
  }
  const floor = new Date(K2_GATE_CLOSES_AT_FLOOR);
  if (gateCloses.getTime() < floor.getTime()) {
    return { ok: false, reason: `earlier than the earliest possible K2 gate close (${K2_GATE_CLOSES_AT_FLOOR})` };
  }
  return { ok: true, gateCloses };
}

const MIN_SECRET_LENGTH = 16;

export type SecretsCheckResult = { ok: true } | { ok: false; error: string };

/**
 * Gate finding F13: a missing secret must not silently degrade into
 * hashing over `"undefined:..."` or a brute-forceable plain-IP hash — fail
 * loudly with a 500 instead. Checked once per request at the top of
 * `fetch` (see index.ts).
 */
export function assertRequiredSecretsPresent(env: Env): SecretsCheckResult {
  const required: Array<[string, string | undefined]> = [
    ["TOKEN_PEPPER", env.TOKEN_PEPPER],
    ["TURNSTILE_SECRET", env.TURNSTILE_SECRET],
    ["RESEND_API_KEY", env.RESEND_API_KEY],
    ["RESEND_FROM_EMAIL", env.RESEND_FROM_EMAIL],
    ["PUBLIC_BASE_URL", env.PUBLIC_BASE_URL],
  ];
  for (const [name, value] of required) {
    if (typeof value !== "string" || value.length === 0) {
      return { ok: false, error: `missing required secret/config: ${name}` };
    }
  }
  if (env.TOKEN_PEPPER.length < MIN_SECRET_LENGTH) {
    return { ok: false, error: `TOKEN_PEPPER is too short (minimum ${MIN_SECRET_LENGTH} characters)` };
  }
  return { ok: true };
}

/** Gate finding F6: resolves the effective global daily send cap. */
export function globalDailySendCap(env: Env): number {
  const raw = env.GLOBAL_DAILY_SEND_CAP;
  const parsed = raw ? parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_GLOBAL_DAILY_SEND_CAP;
}
