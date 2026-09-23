/**
 * K2 double-opt-in signup backend — router + handlers.
 *
 * Routes:
 *   POST /api/signup       — validate, rate-limit, Turnstile-verify, upsert
 *                             pending row, send confirmation email. ALWAYS
 *                             the same generic 202 (enumeration-safe): the
 *                             response is sent after validation + rate
 *                             limit + Turnstile + the existence SELECT
 *                             (identical cost for every case), and every
 *                             case-dependent write plus the email send runs
 *                             in the background via `ctx.waitUntil` (gate
 *                             finding F2 — the response must never depend
 *                             on whether the address exists/confirmed).
 *   GET  /api/confirm       — read-only confirm page (a GET never confirms).
 *   POST /api/confirm       — performs the confirmation. Single-use: the
 *                             confirm token is cleared on success (F4).
 *   GET  /api/unsubscribe   — read-only unsubscribe page.
 *   POST /api/unsubscribe   — performs the unsubscribe (RFC 8058 one-click:
 *                             a mail client's automated POST works with no
 *                             further interaction — see email.ts headers).
 *
 * Also exports `scheduled`, a cron handler that purges stale rows
 * (gate finding F11) — see wrangler.toml's `[triggers]`.
 *
 * Every handler is exported individually so tests can call it directly
 * with a fake Env (see test/fakes.ts), without needing a Workers runtime.
 */

import {
  ALLOWED_CONSENT_VERSIONS,
  assertRequiredSecretsPresent,
  CONFIRM_TOKEN_TTL_SECONDS,
  globalDailySendCap,
  MAX_SIGNUP_BODY_BYTES,
  RESEND_COOLDOWN_SECONDS,
  RESEND_EMAIL_DAILY_CAP,
  SIGNUP_EMAIL_DAILY_CAP,
  SIGNUP_IP_DAILY_CAP,
  UNCONFIRMED_RETENTION_DAYS,
  UNSUBSCRIBED_RETENTION_DAYS,
  type Env,
} from "./config";
import {
  createPendingSignup,
  deleteStaleUnconfirmed,
  deleteStaleUnsubscribed,
  findByConfirmTokenHash,
  findByEmailLc,
  findByUnsubscribeTokenHash,
  markUnsubscribed,
  recordConfirmation,
  rotateConfirmToken,
  type SignupRow,
} from "./db";
import { sendConfirmationEmail } from "./email";
import {
  confirmInvalidPage,
  confirmPromptPage,
  confirmSuccessPage,
  unsubscribeInvalidPage,
  unsubscribePromptPage,
  unsubscribeSuccessPage,
} from "./html";
import {
  checkAndConsumeEmailRateLimit,
  checkAndConsumeIpRateLimit,
  checkAndConsumeResendSendLimits,
} from "./ratelimit";
import { corsHeadersFor, genericSignupAccepted, htmlResponse, jsonResponse } from "./responses";
import { generateToken, hashWithPepper, isExpired, isoTimeFromNow } from "./tokens";
import { verifyTurnstileToken } from "./turnstile";
import { validateSignupPayload } from "./validate";

/** The subset of ExecutionContext every handler that defers work actually needs. */
type WaitUntilCtx = { waitUntil(promise: Promise<unknown>): void };

function clientIp(request: Request): string {
  // Cloudflare-set header with the real client IP. In dev/tests this may
  // be absent; fall back to a constant so rate limiting still functions
  // (against a shared bucket) rather than throwing.
  return request.headers.get("CF-Connecting-IP") ?? "unknown";
}

function confirmUrl(env: Env, token: string): string {
  return `${env.PUBLIC_BASE_URL}/api/confirm?token=${encodeURIComponent(token)}`;
}

function unsubscribeUrl(env: Env, token: string): string {
  return `${env.PUBLIC_BASE_URL}/api/unsubscribe?token=${encodeURIComponent(token)}`;
}

function expectedTurnstileHostname(env: Env): string | undefined {
  try {
    return new URL(env.PUBLIC_BASE_URL).hostname;
  } catch {
    return undefined;
  }
}

type BodyReadResult = { ok: true; value: unknown } | { ok: false; response: Response };

/**
 * Gate finding F10: caps the request body at MAX_SIGNUP_BODY_BYTES and
 * requires `Content-Type: application/json` BEFORE `JSON.parse` ever runs,
 * so an oversized or wrong-Content-Type body (e.g. a cross-site "simple"
 * request with `text/plain`) is rejected cheaply.
 */
async function readSignupBody(request: Request): Promise<BodyReadResult> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return {
      ok: false,
      response: jsonResponse(415, { status: "error", error: "Content-Type must be application/json" }),
    };
  }

  const contentLengthHeader = request.headers.get("Content-Length");
  const contentLength = contentLengthHeader ? parseInt(contentLengthHeader, 10) : NaN;
  if (!Number.isFinite(contentLength)) {
    return {
      ok: false,
      response: jsonResponse(411, { status: "error", error: "Content-Length header is required" }),
    };
  }
  if (contentLength > MAX_SIGNUP_BODY_BYTES) {
    return { ok: false, response: jsonResponse(413, { status: "error", error: "request body too large" }) };
  }

  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_SIGNUP_BODY_BYTES) {
    return { ok: false, response: jsonResponse(413, { status: "error", error: "request body too large" }) };
  }

  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, response: jsonResponse(400, { status: "error", error: "request body must be valid JSON" }) };
  }
}

export async function handleSignupOptions(request: Request, env: Env): Promise<Response> {
  return new Response(null, { status: 204, headers: corsHeadersFor(request, env) });
}

/**
 * Re-signup of an existing row (cases C: still pending, or D: previously
 * unsubscribed): mints a fresh confirm token AND a fresh unsubscribe
 * token, returning the raw unsubscribe token for the email link. Shared by
 * the normal path and the F3 concurrent-insert-race fallback below.
 */
async function rotateAndGetUnsubscribeToken(
  env: Env,
  row: SignupRow,
  consentVersion: string,
  source: string | undefined,
  confirmTokenHash: string,
  confirmExpiresAt: string,
): Promise<string> {
  await rotateConfirmToken(env.DB, {
    id: row.id,
    consentVersion,
    source: source ?? row.source,
    confirmTokenHash,
    confirmExpiresAt,
  });
  const rawUnsubscribeToken = generateToken();
  const unsubscribeTokenHash = await hashWithPepper(env.TOKEN_PEPPER, rawUnsubscribeToken);
  await env.DB
    .prepare("UPDATE signups SET unsubscribe_token_hash = ?2 WHERE id = ?1")
    .bind(row.id, unsubscribeTokenHash)
    .run();
  return rawUnsubscribeToken;
}

/**
 * Gate finding F6: sends the confirmation email only if the per-email
 * cooldown, per-email daily cap, and global daily cap all allow it. A
 * denial is NOT an error — the HTTP response is already the generic 202
 * either way — it just means this particular send is skipped, and that is
 * logged (no PII beyond the fixed reason code / HTTP status — F14).
 */
async function maybeSendConfirmationEmail(
  env: Env,
  emailLc: string,
  rawConfirmToken: string,
  rawUnsubscribeToken: string,
): Promise<void> {
  const sendLimit = await checkAndConsumeResendSendLimits(env, emailLc, {
    cooldownSeconds: RESEND_COOLDOWN_SECONDS,
    emailDailyCap: RESEND_EMAIL_DAILY_CAP,
    globalDailyCap: globalDailySendCap(env),
  });
  if (!sendLimit.allowed) {
    console.error("confirmation email skipped by send limit", { reason: sendLimit.reason });
    return;
  }

  const sendResult = await sendConfirmationEmail(env, {
    to: emailLc,
    confirmUrl: confirmUrl(env, rawConfirmToken),
    unsubscribeUrl: unsubscribeUrl(env, rawUnsubscribeToken),
  });
  if (!sendResult.ok) {
    // F14: log the fixed HTTP status / transport code, never Resend's
    // free-text message (which may echo the recipient address).
    console.error("confirmation email send failed", { status: sendResult.status });
  }
}

/**
 * Everything about a signup that depends on WHICH case applied (case
 * A/B/C/D) — this is deliberately run from `ctx.waitUntil`, never awaited
 * by the HTTP response (gate finding F2: response timing must not depend
 * on this).
 */
async function runSignupSideEffects(
  env: Env,
  params: { emailLc: string; consentVersion: string; source?: string | undefined; existing: SignupRow | null },
): Promise<void> {
  const { emailLc, consentVersion, source, existing } = params;

  // Case B: an ACTIVE confirmed subscriber (confirmed AND not currently
  // unsubscribed) — nothing to do. A confirmed-but-unsubscribed address
  // does NOT take this branch (task requirement: "Re-signup of an
  // unsubscribed address may re-open only via a fresh confirmation"), so
  // it falls through to the rotate-and-resend path below (case D).
  if (existing && existing.confirmed_at && !existing.unsubscribed_at) {
    return;
  }

  const rawConfirmToken = generateToken();
  const confirmTokenHash = await hashWithPepper(env.TOKEN_PEPPER, rawConfirmToken);
  const confirmExpiresAt = isoTimeFromNow(CONFIRM_TOKEN_TTL_SECONDS);

  let unsubscribeTokenForEmail: string;

  if (!existing) {
    // Case A: brand new address. Race-safe insert (F3): ON CONFLICT DO
    // NOTHING means a concurrent signup for the same address never 500s.
    const rawUnsubscribeToken = generateToken();
    const unsubscribeTokenHash = await hashWithPepper(env.TOKEN_PEPPER, rawUnsubscribeToken);
    const { inserted } = await createPendingSignup(env.DB, {
      id: crypto.randomUUID(),
      emailLc,
      consentVersion,
      source: source ?? null,
      createdAt: new Date().toISOString(),
      confirmTokenHash,
      confirmExpiresAt,
      unsubscribeTokenHash,
    });

    if (inserted) {
      unsubscribeTokenForEmail = rawUnsubscribeToken;
    } else {
      // Lost the race: another request inserted this address first. Re-read
      // and fall through to the rotate path instead of doing nothing.
      const raced = await findByEmailLc(env.DB, emailLc);
      if (!raced) {
        console.error("signup insert race: row missing after ON CONFLICT DO NOTHING");
        return;
      }
      if (raced.confirmed_at && !raced.unsubscribed_at) return; // became case B meanwhile
      unsubscribeTokenForEmail = await rotateAndGetUnsubscribeToken(
        env,
        raced,
        consentVersion,
        source,
        confirmTokenHash,
        confirmExpiresAt,
      );
    }
  } else {
    // Case C (still pending) or D (previously unsubscribed).
    unsubscribeTokenForEmail = await rotateAndGetUnsubscribeToken(
      env,
      existing,
      consentVersion,
      source,
      confirmTokenHash,
      confirmExpiresAt,
    );
  }

  await maybeSendConfirmationEmail(env, emailLc, rawConfirmToken, unsubscribeTokenForEmail);
}

export async function handleSignup(request: Request, env: Env, ctx: WaitUntilCtx): Promise<Response> {
  const bodyResult = await readSignupBody(request);
  if (!bodyResult.ok) return bodyResult.response;

  const validation = validateSignupPayload(bodyResult.value);
  if (!validation.ok) {
    return jsonResponse(400, { status: "error", error: validation.error });
  }
  const { emailLc, consentVersion, source, turnstileToken } = validation.value;

  const ip = clientIp(request);

  // F5: per-IP cap is checked (and consumed) FIRST — this bounds request
  // volume from one source regardless of whether Turnstile ultimately
  // passes, so it's fine to spend before Turnstile runs.
  const ipLimit = await checkAndConsumeIpRateLimit(env, ip, SIGNUP_IP_DAILY_CAP);
  if (!ipLimit.allowed) {
    return jsonResponse(429, { status: "error", error: "too many requests, try again later" });
  }

  // F5: Turnstile BEFORE the per-EMAIL slot is ever touched. Otherwise
  // anyone could send a junk turnstileToken for a victim's address and
  // burn that address's per-email cap without solving a challenge.
  const turnstile = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET, ip === "unknown" ? null : ip, {
    hostname: expectedTurnstileHostname(env),
    action: "signup",
  });
  if (!turnstile.success) {
    return jsonResponse(400, { status: "error", error: "turnstile verification failed" });
  }

  const emailLimit = await checkAndConsumeEmailRateLimit(env, emailLc, SIGNUP_EMAIL_DAILY_CAP);
  if (!emailLimit.allowed) {
    return jsonResponse(429, { status: "error", error: "too many requests, try again later" });
  }

  // Same SELECT for every case — this is NOT a timing discriminator (F2):
  // every request pays for it identically, only what happens AFTER it
  // (backgrounded below) differs by case.
  const existing = await findByEmailLc(env.DB, emailLc);

  ctx.waitUntil(
    runSignupSideEffects(env, { emailLc, consentVersion, source, existing }).catch((err) => {
      console.error("signup side effects failed", err instanceof Error ? err.message : String(err));
    }),
  );

  return genericSignupAccepted(request, env);
}

export async function handleConfirmPage(request: Request, _env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!token) {
    return htmlResponse(400, confirmInvalidPage());
  }
  // GET never touches the database and never confirms — it just renders
  // the button. The actual validity check happens on POST.
  return htmlResponse(200, confirmPromptPage(`/api/confirm?token=${encodeURIComponent(token)}`));
}

export async function handleConfirmSubmit(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!token) {
    return htmlResponse(400, confirmInvalidPage());
  }

  const hash = await hashWithPepper(env.TOKEN_PEPPER, token);
  const row = await findByConfirmTokenHash(env.DB, hash);

  if (!row) {
    // Gate finding F4: this is also what a REUSED (already-confirmed) or
    // superseded (rotated by a later re-signup) link looks like now, since
    // recordConfirmation() clears confirm_token_hash on success — the
    // generic "expired or already used" page covers both cases uniformly.
    return htmlResponse(400, confirmInvalidPage());
  }
  if (!row.confirm_expires_at || isExpired(row.confirm_expires_at)) {
    return htmlResponse(400, confirmInvalidPage());
  }

  // Single-use (F4): recordConfirmation() clears confirm_token_hash /
  // confirm_expires_at on success, so a second POST with the same raw
  // token no longer finds a row above and shows the invalid/used page.
  await recordConfirmation(env.DB, row.id, new Date().toISOString());
  return htmlResponse(200, confirmSuccessPage());
}

export async function handleUnsubscribePage(request: Request, _env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!token) {
    return htmlResponse(400, unsubscribeInvalidPage());
  }
  return htmlResponse(200, unsubscribePromptPage(`/api/unsubscribe?token=${encodeURIComponent(token)}`));
}

export async function handleUnsubscribeSubmit(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!token) {
    return htmlResponse(400, unsubscribeInvalidPage());
  }

  const hash = await hashWithPepper(env.TOKEN_PEPPER, token);
  const row = await findByUnsubscribeTokenHash(env.DB, hash);
  if (!row) {
    return htmlResponse(400, unsubscribeInvalidPage());
  }

  // Idempotent: already-unsubscribed just re-shows success, no re-write.
  if (!row.unsubscribed_at) {
    await markUnsubscribed(env.DB, row.id, new Date().toISOString());
  }
  return htmlResponse(200, unsubscribeSuccessPage());
}

function notFound(): Response {
  return jsonResponse(404, { status: "error", error: "not found" });
}

/**
 * Gate finding F11 (retention cron): deletes rows that were never
 * confirmed and are older than UNCONFIRMED_RETENTION_DAYS. Unconfirmed
 * rows never count toward K2 (src/k2-count.ts only ever reads rows with a
 * non-null confirmed_at — see its header comment), so this deletion can
 * never change a K2 count.
 *
 * Also deletes confirmed-but-unsubscribed rows more than
 * UNSUBSCRIBED_RETENTION_DAYS past their unsubscribe date — but ONLY once
 * `Env.K2_GATE_CLOSES_AT` (day 0 + 42 days) has passed, so a K2 recount
 * always remains reconstructable from confirmed_at until the verdict is
 * safely recorded. Until the owner sets that var, this half is skipped
 * entirely (see README.md "Data retention").
 */
export async function runRetentionCron(
  env: Env,
): Promise<{ deletedUnconfirmed: number; deletedUnsubscribed: number }> {
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;

  const unconfirmedCutoff = new Date(now - UNCONFIRMED_RETENTION_DAYS * dayMs).toISOString();
  const deletedUnconfirmed = await deleteStaleUnconfirmed(env.DB, unconfirmedCutoff);

  let deletedUnsubscribed = 0;
  if (env.K2_GATE_CLOSES_AT) {
    const gateCloses = new Date(env.K2_GATE_CLOSES_AT);
    if (!Number.isNaN(gateCloses.getTime()) && now >= gateCloses.getTime()) {
      const unsubscribedCutoff = new Date(now - UNSUBSCRIBED_RETENTION_DAYS * dayMs).toISOString();
      deletedUnsubscribed = await deleteStaleUnsubscribed(env.DB, unsubscribedCutoff);
    }
  }

  return { deletedUnconfirmed, deletedUnsubscribed };
}

export default {
  async fetch(request: Request, env: Env, ctx: WaitUntilCtx): Promise<Response> {
    // F13: a missing/short secret must fail loudly, not silently hash
    // over "undefined:..." or a brute-forceable plain-IP hash.
    const secretsCheck = assertRequiredSecretsPresent(env);
    if (!secretsCheck.ok) {
      console.error("misconfigured environment", secretsCheck.error);
      return jsonResponse(500, { status: "error", error: "internal error" });
    }

    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/signup") {
        if (request.method === "POST") return await handleSignup(request, env, ctx);
        if (request.method === "OPTIONS") return await handleSignupOptions(request, env);
      } else if (url.pathname === "/api/confirm") {
        if (request.method === "GET") return await handleConfirmPage(request, env);
        if (request.method === "POST") return await handleConfirmSubmit(request, env);
      } else if (url.pathname === "/api/unsubscribe") {
        if (request.method === "GET") return await handleUnsubscribePage(request, env);
        if (request.method === "POST") return await handleUnsubscribeSubmit(request, env);
      }
      return notFound();
    } catch (err) {
      // F3: `return await` above ensures a rejected handler promise is
      // actually caught here instead of escaping as an uncaught exception.
      console.error("unhandled error", err);
      return jsonResponse(500, { status: "error", error: "internal error" });
    }
  },

  /** Cron entry point (see wrangler.toml `[triggers]`) — gate finding F11. */
  async scheduled(_event: unknown, env: Env, ctx: WaitUntilCtx): Promise<void> {
    ctx.waitUntil(
      runRetentionCron(env)
        .then((result) => {
          console.log("retention cron completed", result);
        })
        .catch((err) => {
          console.error("retention cron failed", err instanceof Error ? err.message : String(err));
        }),
    );
  },
};

export { ALLOWED_CONSENT_VERSIONS };
