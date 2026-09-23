/**
 * K2 double-opt-in signup backend — router + handlers.
 *
 * Routes:
 *   POST /api/signup       — validate, rate-limit, Turnstile-verify, upsert
 *                             pending row, send confirmation email. ALWAYS
 *                             the same generic 202 (enumeration-safe).
 *   GET  /api/confirm       — read-only confirm page (a GET never confirms).
 *   POST /api/confirm       — performs the confirmation. Idempotent.
 *   GET  /api/unsubscribe   — read-only unsubscribe page.
 *   POST /api/unsubscribe   — performs the unsubscribe (RFC 8058 one-click:
 *                             a mail client's automated POST works with no
 *                             further interaction — see email.ts headers).
 *
 * Every handler is exported individually so tests can call it directly
 * with a fake Env (see test/fakes.ts), without needing a Workers runtime.
 */

import {
  ALLOWED_CONSENT_VERSIONS,
  CONFIRM_TOKEN_TTL_SECONDS,
  SIGNUP_EMAIL_DAILY_CAP,
  SIGNUP_IP_DAILY_CAP,
  type Env,
} from "./config";
import {
  createPendingSignup,
  findByConfirmTokenHash,
  findByEmailLc,
  findByUnsubscribeTokenHash,
  markUnsubscribed,
  recordConfirmation,
  rotateConfirmToken,
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
import { checkAndConsumeRateLimit } from "./ratelimit";
import { corsHeadersFor, genericSignupAccepted, htmlResponse, jsonResponse } from "./responses";
import { generateToken, hashWithPepper, isExpired, isoTimeFromNow } from "./tokens";
import { verifyTurnstileToken } from "./turnstile";
import { validateSignupPayload } from "./validate";

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

export async function handleSignupOptions(request: Request, env: Env): Promise<Response> {
  return new Response(null, { status: 204, headers: corsHeadersFor(request, env) });
}

export async function handleSignup(request: Request, env: Env): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(400, { status: "error", error: "request body must be valid JSON" });
  }

  const validation = validateSignupPayload(body);
  if (!validation.ok) {
    return jsonResponse(400, { status: "error", error: validation.error });
  }
  const { emailLc, consentVersion, source, turnstileToken } = validation.value;

  const ip = clientIp(request);
  const rateLimit = await checkAndConsumeRateLimit(env, ip, emailLc, SIGNUP_IP_DAILY_CAP, SIGNUP_EMAIL_DAILY_CAP);
  if (!rateLimit.allowed) {
    return jsonResponse(429, { status: "error", error: "too many requests, try again later" });
  }

  const turnstile = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET, ip === "unknown" ? null : ip);
  if (!turnstile.success) {
    return jsonResponse(400, { status: "error", error: "turnstile verification failed" });
  }

  const existing = await findByEmailLc(env.DB, emailLc);

  // Case B: an ACTIVE confirmed subscriber (confirmed AND not currently
  // unsubscribed) — send nothing new. The response below is byte-identical
  // to every other case (enumeration-safe). A confirmed-but-unsubscribed
  // address does NOT take this branch — task requirement: "Re-signup of an
  // unsubscribed address may re-open only via a fresh confirmation", so it
  // falls through to the rotate-and-resend path below (case D).
  if (existing && existing.confirmed_at && !existing.unsubscribed_at) {
    return genericSignupAccepted(request, env);
  }

  const rawConfirmToken = generateToken();
  const confirmTokenHash = await hashWithPepper(env.TOKEN_PEPPER, rawConfirmToken);
  const confirmExpiresAt = isoTimeFromNow(CONFIRM_TOKEN_TTL_SECONDS);

  let unsubscribeTokenForEmail: string;

  if (!existing) {
    // Case A: brand new address.
    const rawUnsubscribeToken = generateToken();
    const unsubscribeTokenHash = await hashWithPepper(env.TOKEN_PEPPER, rawUnsubscribeToken);
    await createPendingSignup(env.DB, {
      id: crypto.randomUUID(),
      emailLc,
      consentVersion,
      source: source ?? null,
      createdAt: new Date().toISOString(),
      confirmTokenHash,
      confirmExpiresAt,
      unsubscribeTokenHash,
    });
    unsubscribeTokenForEmail = rawUnsubscribeToken;
  } else {
    // Case C (still pending) or D (previously unsubscribed): rotate the
    // confirm token and resend. We only ever store the unsubscribe
    // token's HASH, so a re-signup also mints a fresh raw unsubscribe
    // token (one extra UPDATE) rather than trying to reuse a raw value we
    // don't hold — this keeps "every confirmation email includes a
    // working unsubscribe link" true in every case, including a re-signup
    // before a prior confirmation email was ever read.
    await rotateConfirmToken(env.DB, {
      id: existing.id,
      consentVersion,
      source: source ?? existing.source,
      confirmTokenHash,
      confirmExpiresAt,
    });
    const rawUnsubscribeToken = generateToken();
    const unsubscribeTokenHash = await hashWithPepper(env.TOKEN_PEPPER, rawUnsubscribeToken);
    await env.DB
      .prepare("UPDATE signups SET unsubscribe_token_hash = ?2 WHERE id = ?1")
      .bind(existing.id, unsubscribeTokenHash)
      .run();
    unsubscribeTokenForEmail = rawUnsubscribeToken;
  }

  const sendResult = await sendConfirmationEmail(env, {
    to: emailLc,
    confirmUrl: confirmUrl(env, rawConfirmToken),
    unsubscribeUrl: unsubscribeUrl(env, unsubscribeTokenForEmail),
  });
  if (!sendResult.ok) {
    // "success only after Resend accepts" (task requirement): we do NOT
    // claim the email was sent anywhere internally. The row stays pending
    // with a valid (unexpired) confirm token, so a later /api/signup retry
    // for the same address will rotate-and-resend rather than being stuck.
    // The HTTP response is still the generic 202 — a transient Resend
    // outage must not become an oracle for "does this email exist"
    // (a real signup and a probe of an unrelated address look identical
    // to an external caller either way; see README "How signups work").
    console.error("confirmation email send failed", { reason: sendResult.error });
  }

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
    return htmlResponse(400, confirmInvalidPage());
  }
  if (!row.confirm_expires_at || isExpired(row.confirm_expires_at)) {
    return htmlResponse(400, confirmInvalidPage());
  }

  // Idempotent by construction: recordConfirmation() is safe to run more
  // than once for the same row (see its doc comment — confirmed_at is set
  // via COALESCE, so a second POST with the same still-unexpired token
  // reaches the exact same state and the same success page, never a
  // second confirmation timestamp and never an error).
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/signup") {
        if (request.method === "POST") return handleSignup(request, env);
        if (request.method === "OPTIONS") return handleSignupOptions(request, env);
      } else if (url.pathname === "/api/confirm") {
        if (request.method === "GET") return handleConfirmPage(request, env);
        if (request.method === "POST") return handleConfirmSubmit(request, env);
      } else if (url.pathname === "/api/unsubscribe") {
        if (request.method === "GET") return handleUnsubscribePage(request, env);
        if (request.method === "POST") return handleUnsubscribeSubmit(request, env);
      }
      return notFound();
    } catch (err) {
      console.error("unhandled error", err);
      return jsonResponse(500, { status: "error", error: "internal error" });
    }
  },
};

export { ALLOWED_CONSENT_VERSIONS };
