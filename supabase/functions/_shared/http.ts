// supabase/functions/_shared/http.ts
//
// Pure helpers: the JSON response envelope every Edge Function in this
// round uses, plus the P3 AT 8 request-body size cap (64 KB). No Deno/
// Node-specific globals beyond the standard `Request`/`Response`/
// `TextEncoder` objects every modern JS runtime (Deno, Node >=18, a
// vitest/jsdom-less Node test) provides — kept dependency-free so it is
// importable unmodified from supabase/tests/unit/*.test.ts.

export interface ErrorBody {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export interface OkBody<T> {
  data: T;
}

/** The one request-body size cap every write Edge Function enforces (P3
 * AT 8: "bodies > 64 KB are rejected"). Checked from `Content-Length`
 * when present (cheap, no body read), and re-checked against the actual
 * decoded byte length after reading — a client can lie about or omit
 * Content-Length, so the second check is the real enforcement; the first
 * is a fast-reject when available. */
export const MAX_BODY_BYTES = 64 * 1024;

export function jsonResponse(status: number, body: unknown, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

export function okResponse<T>(status: number, data: T, extraHeaders?: HeadersInit): Response {
  return jsonResponse(status, { data } satisfies OkBody<T>, extraHeaders);
}

export function errorResponse(status: number, code: string, message: string, details?: unknown): Response {
  return jsonResponse(status, { error: { code, message, details } } satisfies ErrorBody, undefined);
}

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
  toResponse(): Response {
    return errorResponse(this.status, this.code, this.message, this.details);
  }
}

export const Errors = {
  unauthorized: () => new HttpError(401, "unauthorized", "missing or invalid Authorization token"),
  forbidden: (message = "forbidden") => new HttpError(403, "forbidden", message),
  notFound: (message = "not found") => new HttpError(404, "not_found", message),
  badRequest: (message: string, details?: unknown) => new HttpError(400, "bad_request", message, details),
  payloadTooLarge: () => new HttpError(413, "payload_too_large", `request body exceeds ${MAX_BODY_BYTES} bytes`),
  unsupportedMediaType: (message = "expected application/json") => new HttpError(415, "unsupported_media_type", message),
  unprocessable: (code: string, message: string, details?: unknown) => new HttpError(422, code, message, details),
  /** P3c gate round 3, blocking HIGH 1+2 ("Fix Errors to have a 409"): a
   * changed-replay (same (user, source, source_ref), different content —
   * evidence/handler.ts's own `computeInputHash` mismatches the stored
   * `input_hash`) is a genuine conflict, distinct from a validation
   * failure (422) or an auth failure (401/403) — the client is telling
   * the server two different things happened under the one identity that
   * must be unique. Also used for a cross-user device-id conflict
   * (privileged.ts#device.ensureOwn, should-fix). */
  conflict: (code: string, message: string, details?: unknown) => new HttpError(409, code, message, details),
  tooManyRequests: (message: string, retryAfterSeconds?: number) =>
    new HttpError(429, "rate_limited", message, retryAfterSeconds !== undefined ? { retryAfterSeconds } : undefined),
  internal: (message = "internal error") => new HttpError(500, "internal_error", message),
  /** P3c gate round 4, blocking HIGH's own fix list: "a request-level
   * timeout that returns 503." Used by `handleRequest`'s own timeout
   * backstop below — see its doc for what this is and, just as
   * importantly, what it is NOT a substitute for. */
  serviceUnavailable: (message = "request timed out") => new HttpError(503, "service_unavailable", message),
};

/** Reads a `Request` body, enforcing MAX_BODY_BYTES with a RUNNING byte
 * count over the stream itself (P3c gate round 2, item 10) — the prior
 * version called `req.arrayBuffer()` unconditionally, which buffers the
 * ENTIRE body in memory before the size check ever runs whenever
 * `Content-Length` is absent or understated (a client can omit or lie
 * about it; the size check must not depend on it). This version reads
 * `req.body` chunk by chunk, cancels the stream and throws the instant
 * the running total exceeds the cap — a body ten times the cap is never
 * more than ~`MAX_BODY_BYTES` resident at once. `Content-Length` is still
 * checked first as a cheap fast-reject when present (never even opens
 * the stream for an up-front-oversized body), but is never trusted
 * alone. Throws `HttpError` (413/415/400) rather than returning a
 * discriminated result — every caller in this codebase wants exactly one
 * of "parsed JSON value" or "the request is rejected", never a third
 * state to forget to check. Invalid UTF-8 -> 400 (P3c gate round 2, item
 * 10), not an uncaught exception surfacing as a generic 500. */
export async function readJsonBody(req: Request): Promise<unknown> {
  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw Errors.unsupportedMediaType();
  }
  const declaredLength = req.headers.get("content-length");
  if (declaredLength !== null) {
    const n = Number(declaredLength);
    if (Number.isFinite(n) && n > MAX_BODY_BYTES) {
      throw Errors.payloadTooLarge();
    }
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  if (req.body) {
    const reader = req.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => {});
        throw Errors.payloadTooLarge();
      }
      chunks.push(value);
    }
  }

  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
  } catch {
    throw Errors.badRequest("request body is not valid UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw Errors.badRequest("request body is not valid JSON");
  }
  return parsed;
}

// P3c gate round 4, blocking HIGH's own fix list: "Set a connect/acquire
// timeout... plus a request-level timeout that returns 503." Bounds an
// Edge Function's own wall-clock time as the LAST line of defense — not
// the fix for the pool deadlock itself (privileged.ts#
// hitRateLimitForActor's own doc has that: rate-limit hits BEFORE the
// request transaction opens, so no request holds two pooled connections
// at once and there's nothing left to hang on under normal operation).
// This is what turns an UNEXPECTED future hang (a regression that
// reintroduces contention, a slow/wedged database, anything else that
// can make a request wait indefinitely) into a clean 503 instead of a
// connection the CLIENT waits on forever. 15s is comfortably above this
// round's own real numbers (25 concurrent requests in ~200ms once
// ordered correctly; the reviewer's own repro hung past 20s specifically
// BECAUSE of the deadlock this round fixes) while still bounding the
// worst case to something a caller can reasonably retry against.
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

/** Races `promise` against a timer that rejects with `Errors.
 * serviceUnavailable()` after `ms`. Honest limitation, stated once here
 * rather than at every call site: this does NOT cancel `promise` itself
 * (JS/Deno has no general-purpose promise cancellation) — if the
 * underlying operation is, say, a DB write that is genuinely still
 * running when the timer fires, that write keeps running in the
 * background and may still complete (or fail) AFTER the client has
 * already been told 503. That's an inherent property of a race-based
 * timeout, not a bug in this one; the client's own 503-triggered retry
 * is itself made SAFE by this round's other fix (rate-limit hits happen
 * before the transaction, and replays are read-only), not by this
 * timeout pretending to cancel anything. */
async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(Errors.serviceUnavailable(`request exceeded ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Runs an async handler and turns a thrown `HttpError` (or any other
 * error, mapped to 500 with no leaked internals) into the right
 * `Response`. Every Edge Function entrypoint's `Deno.serve` callback is a
 * one-line call to this, so the error-shape discipline lives in one
 * place, not copy-pasted per function. Also the ONE place the
 * request-level timeout backstop (above) is wired in, uniformly, rather
 * than per endpoint. */
export async function handleRequest(fn: () => Promise<Response>, timeoutMs: number = DEFAULT_REQUEST_TIMEOUT_MS): Promise<Response> {
  try {
    return await withTimeout(fn(), timeoutMs);
  } catch (err) {
    if (err instanceof HttpError) return err.toResponse();
    // Never leak internals (stack traces, DB error text) to the client —
    // security-doc discipline applied uniformly, not just on the money
    // -path fields it names explicitly.
    console.error("unhandled error in Edge Function handler:", err);
    return errorResponse(500, "internal_error", "internal error");
  }
}
