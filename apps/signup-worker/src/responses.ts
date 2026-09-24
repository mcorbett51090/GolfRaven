/**
 * Response helpers: security headers (task requirement — tight CSP,
 * no-store caching) and the allow-listed dev-only CORS helper (production
 * is same-origin under `golfraven.<tld>/api/*`, so no CORS headers are
 * needed there at all).
 */

import type { Env } from "./config";

const BASE_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

export function corsHeadersFor(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get("Origin");
  if (!origin) return {};
  const allowed = (env.ALLOWED_DEV_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!allowed.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export function jsonResponse(
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'",
      ...BASE_HEADERS,
      ...extraHeaders,
    },
  });
}

export function htmlResponse(
  status: number,
  html: string,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'; form-action 'self'; base-uri 'none'",
      "X-Frame-Options": "DENY",
      ...BASE_HEADERS,
      ...extraHeaders,
    },
  });
}

/**
 * The ONE response `POST /api/signup` ever returns for a well-formed,
 * non-rate-limited, Turnstile-passing request — identical whether the
 * email is new, already pending, already confirmed, or previously
 * unsubscribed. This is what makes the endpoint enumeration-safe (task
 * requirement): nothing about the response reveals which case applied.
 */
export function genericSignupAccepted(request: Request, env: Env): Response {
  return jsonResponse(
    202,
    { status: "ok", message: "If that address isn't already confirmed, check your inbox for a confirmation email." },
    corsHeadersFor(request, env),
  );
}
