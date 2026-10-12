// supabase/functions/_shared/receipts/purge-handler.ts
//
// The pure, DI'd core of `receipts-purge` (docs/security/partner-auth-design.md §40.3 / §42; build plan A66 / 0012 TODO):
// delete objects in the private `receipts` bucket older than 90 days.
// Mirrors exports-purge auth / rate-limit order: nothing here touches a connection or the environment.
//
//   Authentication   the scheduler's bearer is the project's service-role key (`isServiceRoleBearer`). Wrong/missing → 401 before rate limit and storage.
//   Rate limit       one coarse system bucket (`receipts-purge`, 12 per hour).
//   Retention        90 days; the cutoff is `nowMs - RECEIPTS_RETENTION_MS`.

import { Errors, errorResponse, okResponse } from "../http.ts";
import type { RateLimitResult } from "../types.ts";
import type { ReceiptsStoragePort } from "./ports.ts";

export const RECEIPTS_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
export const RECEIPTS_PURGE_RATE_BUCKET = "receipts-purge";
export const RECEIPTS_PURGE_RATE_WINDOW_SECONDS = 3600;
export const RECEIPTS_PURGE_RATE_MAX_PER_WINDOW = 12;
export const RECEIPTS_PURGE_REQUEST_TIMEOUT_MS = 55_000;

export interface ReceiptsPurgeDeps {
  isAuthorized(req: Request): boolean;
  hitRateLimit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult>;
  storage: Pick<ReceiptsStoragePort, "purgeOlderThan">;
  nowMs(): number;
  log(event: Record<string, unknown>): void;
}

export async function handleReceiptsPurgeRequest(req: Request, deps: ReceiptsPurgeDeps): Promise<Response> {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");
  if (!deps.isAuthorized(req)) return Errors.unauthorized().toResponse();

  const limit = await deps.hitRateLimit(
    RECEIPTS_PURGE_RATE_BUCKET,
    RECEIPTS_PURGE_RATE_WINDOW_SECONDS,
    RECEIPTS_PURGE_RATE_MAX_PER_WINDOW,
  );
  if (!limit.ok) return Errors.tooManyRequests("receipts-purge rate limit exceeded", limit.retryAfterSeconds).toResponse();

  const olderThanMs = deps.nowMs() - RECEIPTS_RETENTION_MS;
  try {
    const purged = await deps.storage.purgeOlderThan(olderThanMs);
    deps.log({ event: "receipts_purge", purged, olderThanMs });
    return okResponse(200, { purged, complete: true });
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    const short = typeof code === "string" && /^[0-9A-Z_]{1,32}$/.test(code) ? code : "error";
    console.error("receipts-purge: storage purge failed", err);
    deps.log({ event: "receipts_purge", purged: 0, complete: false, error: short });
    return errorResponse(500, "receipts_purge_failed", "receipts purge failed", { purged: 0, complete: false, error: short });
  }
}
