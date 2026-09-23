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
  /**
   * Optional PREVIOUS value of `TOKEN_PEPPER`, set only during a pepper
   * rotation. The unsubscribe token is derived deterministically from
   * `TOKEN_PEPPER` + the address (see `src/tokens.ts`'s
   * `deriveUnsubscribeToken`), so rotating `TOKEN_PEPPER` alone would
   * invalidate every unsubscribe link already sent. While this is set,
   * `handleUnsubscribeSubmit` (src/index.ts) tries a lookup under the
   * CURRENT pepper first and falls back to this PREVIOUS one, so old
   * links keep working during the transition — see README.md "Rotating
   * TOKEN_PEPPER" for the full runbook. Unset it once the previous
   * pepper's unsubscribe links have all aged out (>= the confirm-token
   * TTL plus a safety margin is not enough on its own — see that README
   * section for the actual retention-driven cutover point).
   */
  TOKEN_PEPPER_PREVIOUS?: string;

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
  /**
   * Gate finding A-3: bare `YYYY-MM-DD` day 0, copied VERBATIM from
   * `docs/p0/K2.md`'s "## Day 0" section — set alongside `K2_GATE_CLOSES_AT`
   * (never instead of it). The retention cron additionally requires
   * `K2_GATE_CLOSES_AT` to equal EXACTLY this date + 42 days at
   * `00:00:00Z` (`checkK2GateMatchesDay0`) before it will delete a
   * confirmed-then-unsubscribed row — see that function's doc for why
   * `K2_GATE_CLOSES_AT`'s own floor check alone isn't enough once day 0
   * itself lands late.
   */
  K2_DAY0?: string;
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
  // A-4: round-trip the value — `new Date("2026-11-31T00:00:00Z")` etc.
  // don't throw; V8 rolls a nonexistent calendar date FORWARD (e.g. to
  // 2026-12-01), which the regex + NaN checks above don't catch. Harmless
  // direction (it only pushes gateCloses later), but it's not the strict
  // calendar check the format implies, so reject it outright instead.
  if (gateCloses.toISOString().replace(".000Z", "Z") !== raw) {
    return { ok: false, reason: "not a valid calendar date (round-trip mismatch, e.g. a day-of-month rollover)" };
  }
  const floor = new Date(K2_GATE_CLOSES_AT_FLOOR);
  if (gateCloses.getTime() < floor.getTime()) {
    return { ok: false, reason: `earlier than the earliest possible K2 gate close (${K2_GATE_CLOSES_AT_FLOOR})` };
  }
  return { ok: true, gateCloses };
}

const K2_DAY0_RE = /^\d{4}-\d{2}-\d{2}$/;

export type K2Day0CheckResult = { ok: true; day0: Date } | { ok: false; reason: string };

/**
 * Gate finding A-3: validates `Env.K2_DAY0` — a strict, bare `YYYY-MM-DD`
 * date (the same value Matt copies verbatim into `docs/p0/K2.md`'s
 * "## Day 0"), interpreted as 00:00:00Z. Anything else (unset, malformed,
 * or a calendar-rollover date like "2026-11-31") is rejected the same way
 * `checkK2GateClosesAt` rejects a bad `K2_GATE_CLOSES_AT`.
 */
export function checkK2Day0(raw: string | undefined): K2Day0CheckResult {
  if (!raw || raw.trim() === "") {
    return { ok: false, reason: "unset" };
  }
  if (!K2_DAY0_RE.test(raw)) {
    return { ok: false, reason: "malformed (must be a bare YYYY-MM-DD date)" };
  }
  const day0 = new Date(`${raw}T00:00:00Z`);
  if (Number.isNaN(day0.getTime()) || day0.toISOString().slice(0, 10) !== raw) {
    return { ok: false, reason: "not a valid calendar date" };
  }
  return { ok: true, day0 };
}

const K2_GATE_WINDOW_DAYS = 42;

export type K2GateMatchesDay0Result = { ok: true } | { ok: false; reason: string };

/**
 * Gate finding A-3 (BLOCKING-adjacent SHOULD-FIX): `checkK2GateClosesAt`'s
 * floor only catches "day 0 typed into `K2_GATE_CLOSES_AT` by mistake"
 * while day 0 itself is earlier than `K2_GATE_CLOSES_AT_FLOOR`
 * (2026-11-16). If day 0 slips past that date — plausible, since it
 * depends on owner-side domain/SMTP setup — the exact same mistake passes
 * the floor check and deletion of confirmed-then-unsubscribed rows could
 * start at day 0 + 30, BEFORE the real gate closes at day 0 + 42.
 *
 * This closes that gap directly: deletion additionally requires
 * `K2_GATE_CLOSES_AT` to equal EXACTLY `K2_DAY0 + 42 days` at
 * `00:00:00Z` — not merely "parses and clears the floor". Any mismatch
 * (including the "day 0 typed into the gate var" case, at ANY day 0)
 * refuses deletion outright; see `runRetentionCron` in index.ts for the
 * single PII-free warning this produces.
 */
export function checkK2GateMatchesDay0(gateCloses: Date, day0: Date): K2GateMatchesDay0Result {
  const expectedMs = day0.getTime() + K2_GATE_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  if (gateCloses.getTime() !== expectedMs) {
    return {
      ok: false,
      reason: `K2_GATE_CLOSES_AT does not equal K2_DAY0 + ${K2_GATE_WINDOW_DAYS} days at 00:00:00Z`,
    };
  }
  return { ok: true };
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
