// supabase/functions/_shared/partner/http.ts
//
// The partner lane's HTTP helpers (docs/security/partner-auth-design.md 4.6, PA-10, PA-11). Pure: no environment, no database, no logging (PA-11: there is no `console` anywhere in the partner modules,
// and the source scan in supabase/tests/unit/partner-no-console.test.ts keeps it so).
//
//   * `readPartnerJsonBody`: the media type must be EXACTLY `application/json` (a `charset=utf-8` parameter allowed), anything else 415, BEFORE the body is read. The existing `readJsonBody` accepts any content
//     type that merely CONTAINS `application/json` (`text/plain; x=application/json` is a CORS "simple" request that needs no preflight); it is left alone and the partner lane never calls it.
//   * every response is `Cache-Control: no-store` and varies by Origin.
//   * `UNAUTHENTICATED`: the ONE `401` body. Every refused sign-in, every unknown / expired / revoked session and every foreign bearer answers these exact bytes, so nothing tells them apart.

import { Errors, HttpError, readCappedJsonBody, withTimeout } from "../http.ts";
import { baseHeaders, type OriginDecision } from "./cors.ts";

/** Is this `Content-Type` exactly `application/json`, optionally with the single parameter `charset=utf-8` (case-insensitive, optionally quoted)? Any other type or parameter is false. */
export function isExactJsonMediaType(contentType: string | null): boolean {
  if (contentType === null) return false;
  const parts = contentType.split(";");
  if (parts[0]!.trim().toLowerCase() !== "application/json") return false;
  if (parts.length === 1) return true;
  if (parts.length > 2) return false;
  const m = /^\s*charset\s*=\s*(?:"utf-8"|utf-8)\s*$/i.exec(parts[1]!);
  return m !== null;
}

/** Reads a partner request's JSON body. 415 on any media type but the exact one (before the body is read), 413 over 64 KB, 400 for invalid UTF-8 or JSON. */
export async function readPartnerJsonBody(req: Request): Promise<unknown> {
  if (!isExactJsonMediaType(req.headers.get("content-type"))) throw Errors.unsupportedMediaType("expected exactly application/json");
  return await readCappedJsonBody(req);
}

/** A JSON response with the partner lane's headers (no-store, Vary: Origin, nosniff and, for the allowed origin, its CORS headers). */
export function partnerJson(decision: OriginDecision, status: number, body: unknown, extra?: Record<string, string>): Response {
  const h = baseHeaders(decision);
  h.set("content-type", "application/json; charset=utf-8");
  if (extra) for (const [k, v] of Object.entries(extra)) h.set(k, v);
  return new Response(JSON.stringify(body), { status, headers: h });
}

export function partnerOk<T>(decision: OriginDecision, status: number, data: T): Response {
  return partnerJson(decision, status, { data });
}

/** The ONE 401: a constant body, so a refused sign-in, a dead session and a foreign bearer are indistinguishable. */
export const UNAUTHENTICATED_BODY = Object.freeze({ error: { code: "unauthenticated", message: "authentication failed" } });

export function unauthenticated(decision: OriginDecision): Response {
  return partnerJson(decision, 401, UNAUTHENTICATED_BODY);
}

export function partnerError(decision: OriginDecision, status: number, code: string, message: string, extra?: Record<string, string>): Response {
  return partnerJson(decision, status, { error: { code, message } }, extra);
}

/** An `HttpError` as a partner response (its status, code and message; its `details` are never sent). */
export function httpErrorResponse(decision: OriginDecision, err: HttpError): Response {
  return partnerError(decision, err.status, err.code, err.message);
}

const DEFAULT_PARTNER_TIMEOUT_MS = 15_000;

/**
 * Runs a partner handler under the request timeout. An `HttpError` is its own response; ANY other error is a constant 500 with no detail (never a stack, never database text) and,
 * unlike `handleRequest`, nothing is logged: the partner lane writes no log line at all (PA-11), because a log is where a token or a challenge would end up.
 */
export async function runPartnerHandler(decision: OriginDecision, fn: () => Promise<Response>, timeoutMs: number = DEFAULT_PARTNER_TIMEOUT_MS): Promise<Response> {
  try {
    return await withTimeout(fn(), timeoutMs);
  } catch (err) {
    if (err instanceof HttpError) return httpErrorResponse(decision, err);
    return partnerError(decision, 500, "internal_error", "internal error");
  }
}
