// supabase/functions/_shared/exports/purge-handler.ts
//
// The pure, DI'd core of `exports-purge` (docs/security/partner-auth-design.md 32; AT(17); P5.1b): delete objects in the private `exports` bucket older than 7 days.
// Mirrors retention-purge's auth / rate-limit order: nothing here touches a connection or the environment; the storage port, authorisation check, rate limit and clock arrive through deps.
//
//   Authentication   the scheduler's bearer is the project's service-role key (`isServiceRoleBearer`). A wrong or missing bearer is 401 BEFORE the rate limit and before any storage access.
//   Rate limit       one coarse system bucket (`exports-purge`, 12 per hour).
//   Retention        7 days (AT(17) / 0012 TODO); the cutoff is `nowMs - EXPORTS_RETENTION_MS`.

import { Errors, errorResponse, okResponse } from "../http.ts";
import type { ExportsStoragePort } from "../partner/ports.ts";
import type { RateLimitResult } from "../types.ts";

export const EXPORTS_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
export const EXPORTS_PURGE_RATE_BUCKET = "exports-purge";
export const EXPORTS_PURGE_RATE_WINDOW_SECONDS = 3600;
export const EXPORTS_PURGE_RATE_MAX_PER_WINDOW = 12;
export const EXPORTS_PURGE_REQUEST_TIMEOUT_MS = 55_000;

export interface ExportsPurgeDeps {
  isAuthorized(req: Request): boolean;
  hitRateLimit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult>;
  storage: ExportsStoragePort;
  nowMs(): number;
  log(event: Record<string, unknown>): void;
}

export async function handleExportsPurgeRequest(req: Request, deps: ExportsPurgeDeps): Promise<Response> {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");
  if (!deps.isAuthorized(req)) return Errors.unauthorized().toResponse();

  const limit = await deps.hitRateLimit(EXPORTS_PURGE_RATE_BUCKET, EXPORTS_PURGE_RATE_WINDOW_SECONDS, EXPORTS_PURGE_RATE_MAX_PER_WINDOW);
  if (!limit.ok) return Errors.tooManyRequests("exports-purge rate limit exceeded", limit.retryAfterSeconds).toResponse();

  const olderThanMs = deps.nowMs() - EXPORTS_RETENTION_MS;
  try {
    const purged = await deps.storage.purgeOlderThan(olderThanMs);
    deps.log({ event: "exports_purge", purged, olderThanMs });
    return okResponse(200, { purged, complete: true });
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    const short = typeof code === "string" && /^[0-9A-Z_]{1,32}$/.test(code) ? code : "error";
    console.error("exports-purge: storage purge failed", err);
    deps.log({ event: "exports_purge", purged: 0, complete: false, error: short });
    return errorResponse(500, "exports_purge_failed", "exports purge failed", { purged: 0, complete: false, error: short });
  }
}
