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
