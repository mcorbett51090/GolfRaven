/**
 * The app's error type for a failed `api.*` call. One class, a small closed `kind` the UI switches on, and the server's own machine `code`
 * kept verbatim (it selects the copy for the specific cases: `email_proof_required`, `last_sign_in_method`, ...).
 *
 * Mapping (server shapes from `supabase/functions/_shared/http.ts`: `{ "error": { "code", "message", "details"? } }`):
 *
 * | situation                                   | `kind`            |
 * |---------------------------------------------|-------------------|
 * | no network, timeout, aborted                | `network`         |
 * | 2xx whose body fails the zod schema         | `bad_response`    |
 * | no token to send / 401 after one refresh    | `unauthenticated` |
 * | 403                                         | `forbidden`       |
 * | 404                                         | `not_found`       |
 * | 409                                         | `conflict`        |
 * | 429                                         | `rate_limited`    |
 * | 501                                         | `not_supported`   |
 * | 502 / 503 / 504                             | `unavailable`     |
 * | other 5xx                                   | `server`          |
 * | any other 4xx (400, 413, 415, 422, ...)     | `rejected`        |
 * | no API configured in this build             | `not_configured`  |
 */
export type ApiErrorKind =
  | "network"
  | "bad_response"
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "not_supported"
  | "unavailable"
  | "server"
  | "rejected"
  | "not_configured";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  /** HTTP status; `null` when no response was received or understood. */
  readonly status: number | null;
  /** The server's machine code, verbatim (`null` when the body carried none, e.g. a gateway's HTML 502). */
  readonly code: string | null;
  /** The server's `details`, untrusted and unvalidated: read through a schema before use. */
  readonly details: unknown;
  /** From the server's `details.retryAfterSeconds` or a `Retry-After` header; `null` when absent. */
  readonly retryAfterSeconds: number | null;

  constructor(init: { kind: ApiErrorKind; status?: number | null; code?: string | null; message?: string; details?: unknown; retryAfterSeconds?: number | null }) {
    super(init.message ?? `${init.kind}${init.code ? `: ${init.code}` : ""}`);
    this.name = "ApiError";
    this.kind = init.kind;
    this.status = init.status ?? null;
    this.code = init.code ?? null;
    this.details = init.details;
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

export function kindForStatus(status: number): ApiErrorKind {
  if (status === 401) return "unauthenticated";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 429) return "rate_limited";
  if (status === 501) return "not_supported";
  if (status === 502 || status === 503 || status === 504) return "unavailable";
  if (status >= 500) return "server";
  return "rejected";
}
