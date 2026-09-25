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
  tooManyRequests: (message: string, retryAfterSeconds?: number) =>
    new HttpError(429, "rate_limited", message, retryAfterSeconds !== undefined ? { retryAfterSeconds } : undefined),
  internal: (message = "internal error") => new HttpError(500, "internal_error", message),
};

/** Reads a `Request` body, enforcing MAX_BODY_BYTES on both the declared
 * `Content-Length` (fast path — never reads a body known up front to be
 * too large) and the actual decoded byte length (the real enforcement;
 * `Content-Length` is client-supplied and not trustworthy alone). Throws
 * `HttpError` (413/415/400) rather than returning a discriminated result —
 * every caller in this codebase wants exactly one of "parsed JSON value"
 * or "the request is rejected", never a third state to forget to check. */
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
  const buf = await req.arrayBuffer();
  if (buf.byteLength > MAX_BODY_BYTES) {
    throw Errors.payloadTooLarge();
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw Errors.badRequest("request body is not valid JSON");
  }
  return parsed;
}

/** Runs an async handler and turns a thrown `HttpError` (or any other
 * error, mapped to 500 with no leaked internals) into the right
 * `Response`. Every Edge Function entrypoint's `Deno.serve` callback is a
 * one-line call to this, so the error-shape discipline lives in one
 * place, not copy-pasted per function. */
export async function handleRequest(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof HttpError) return err.toResponse();
    // Never leak internals (stack traces, DB error text) to the client —
    // security-doc discipline applied uniformly, not just on the money
    // -path fields it names explicitly.
    console.error("unhandled error in Edge Function handler:", err);
    return errorResponse(500, "internal_error", "internal error");
  }
}
