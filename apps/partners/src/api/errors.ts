/**
 * Typed errors of the partner API client. The mapping is the uniform one the server promises
 * (docs/security/partner-auth-design.md 4.5, 18.2): a dead or unknown session, a refused sign-in and a foreign bearer
 * are ONE `401`; `403` is a refusal of authority (or, on `POST reauth`, `reauth_refused`: the session is fine, the
 * assertion was wrong); `415` is a media-type refusal; `429` is a rate limit.
 *
 * An error carries the HTTP status, the server's short `code` and (for a 429) `retryAfterSeconds` ONLY when the browser
 * could read the `Retry-After` header. It never carries a token, a header value, a request body or a response body.
 */

export type ApiErrorKind =
  /** 401: no session, a dead session, or a refused sign-in. One answer by design. */
  | "unauthenticated"
  /** 403 `reauth_refused` on `POST reauth`: the session is alive, the assertion was not accepted. */
  | "reauth_refused"
  /** 403 any other code: the session lacks authority for this call, or the origin is refused. */
  | "forbidden"
  /** 415: the media type was not exactly `application/json` (a client bug: the client always sends it). */
  | "unsupported_media_type"
  /** 429: a rate limit. */
  | "rate_limited"
  /** 400, 413: the server refused the request body. */
  | "bad_request"
  /** 404, 405: a route the server does not have. */
  | "not_found"
  /** 503: the partner lane is not configured or not available. */
  | "unavailable"
  /** Any other 5xx. */
  | "server"
  /** The request never produced a response (offline, DNS, CORS refusal, aborted). */
  | "network"
  /** A response that is not the documented shape (a server or deployment fault). */
  | "malformed_response";

export class PartnerApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;
  readonly code: string | null;
  readonly retryAfterSeconds: number | null;

  constructor(kind: ApiErrorKind, init: { status?: number | null; code?: string | null; retryAfterSeconds?: number | null } = {}) {
    super(`partner api: ${kind}`);
    this.name = "PartnerApiError";
    this.kind = kind;
    this.status = init.status ?? null;
    this.code = init.code ?? null;
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
  }
}

export function isPartnerApiError(e: unknown): e is PartnerApiError {
  return e instanceof PartnerApiError;
}

/** The kind for an HTTP status and the server's error code. */
export function kindForStatus(status: number, code: string | null): ApiErrorKind {
  if (status === 401) return "unauthenticated";
  if (status === 403) return code === "reauth_refused" ? "reauth_refused" : "forbidden";
  if (status === 415) return "unsupported_media_type";
  if (status === 429) return "rate_limited";
  if (status === 400 || status === 413) return "bad_request";
  if (status === 404 || status === 405) return "not_found";
  if (status === 503) return "unavailable";
  if (status >= 500) return "server";
  return "malformed_response";
}

/**
 * `Retry-After` as whole seconds: delta-seconds, or an HTTP date (RFC 9110 10.2.3) measured from `nowMs`. `null` when absent
 * or unparseable. NOTE: across origins the browser hides this header unless the server lists it in
 * `Access-Control-Expose-Headers`; the S1.2 server does not (design doc 'As built: S7a'), so on the real deployment this is
 * `null` and the UI shows a generic wait message.
 */
export function parseRetryAfter(value: string | null, nowMs: number): number | null {
  if (value === null) return null;
  const v = value.trim();
  if (/^[0-9]{1,9}$/.test(v)) return Number(v);
  // an HTTP-date always carries day and month names; without letters it is not one (Date.parse would read "-5" or "1.5" as some year)
  if (!/[A-Za-z]{3}/.test(v)) return null;
  const at = Date.parse(v);
  if (Number.isNaN(at)) return null;
  return Math.max(0, Math.ceil((at - nowMs) / 1000));
}
