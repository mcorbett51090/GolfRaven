// supabase/functions/_shared/evidence/batch-item-result.ts
//
// The per-item result shape of `POST /v1/evidence/batch` and its error builders — pure (no database, no environment), so they are unit-testable
// without privileged.ts. A rate-limited item carries `error.details.retryAfterSeconds`, the same shape as the single endpoint's 429
// (`Errors.tooManyRequests` -> `error.details.retryAfterSeconds`), so a client can back off per item exactly as it does per request.

import { HttpError } from "../http.ts";

export interface ItemResult {
  index: number;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string; details?: { retryAfterSeconds: number } };
}

/** `{ details: { retryAfterSeconds } }` when the limiter named one (it always does when it refuses), else nothing. */
function retryDetails(retryAfterSeconds: unknown): { details?: { retryAfterSeconds: number } } {
  return typeof retryAfterSeconds === "number" && Number.isFinite(retryAfterSeconds) ? { details: { retryAfterSeconds } } : {};
}

/** An item the rate limiter refused (the daily batch cap, or a device bucket). */
export function rateLimitedItem(index: number, message: string, retryAfterSeconds: number | undefined): ItemResult {
  return { index, ok: false, error: { code: "rate_limited", message, ...retryDetails(retryAfterSeconds) } };
}

export function toErrorResult(index: number, err: unknown): ItemResult {
  if (err instanceof HttpError) {
    // A 429 raised inside the item (HttpError with details.retryAfterSeconds) keeps its hint; no other error carries details here.
    const hint = err.status === 429 && typeof err.details === "object" && err.details !== null ? (err.details as { retryAfterSeconds?: unknown }).retryAfterSeconds : undefined;
    return { index, ok: false, error: { code: err.code, message: err.message, ...retryDetails(hint) } };
  }
  console.error(`evidence-batch: item ${index} failed unexpectedly`, err);
  return { index, ok: false, error: { code: "internal_error", message: "internal error" } };
}
