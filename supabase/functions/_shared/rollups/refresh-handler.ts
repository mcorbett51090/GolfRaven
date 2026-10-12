// supabase/functions/_shared/rollups/refresh-handler.ts
//
// The pure, DI'd core of `rollups-refresh` (docs/security/partner-auth-design.md §30.3 / §41; plan §4.7.3):
// recompute operator_rollup.completions and sponsor_rollup.markers_earned for a UTC month via private.refresh_rollups.
// Mirrors retention-purge / exports-purge auth order: nothing here touches a connection or the environment.
//
//   Authentication   the scheduler's bearer is the project's service-role key (`isServiceRoleBearer`). Wrong/missing → 401 before rate limit and DB.
//   Rate limit       one coarse system bucket (`rollups-refresh`, 12 per hour).
//   Body             empty POST, or JSON `{ "month": "YYYY-MM-01" }` (first-of-month UTC). Other shapes → 400.

import { Errors, errorResponse, okResponse } from "../http.ts";
import type { RateLimitResult } from "../types.ts";

export const ROLLUPS_REFRESH_RATE_BUCKET = "rollups-refresh";
export const ROLLUPS_REFRESH_RATE_WINDOW_SECONDS = 3600;
export const ROLLUPS_REFRESH_RATE_MAX_PER_WINDOW = 12;
export const ROLLUPS_REFRESH_REQUEST_TIMEOUT_MS = 55_000;

export interface RollupsRefreshResult {
  readonly operatorWritten: number;
  readonly operatorRemoved: number;
  readonly sponsorWritten: number;
  readonly sponsorRemoved: number;
  readonly month: string;
}

export interface RollupsRefreshDeps {
  isAuthorized(req: Request): boolean;
  hitRateLimit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult>;
  refresh(month: string | null): Promise<RollupsRefreshResult>;
  log(event: Record<string, unknown>): void;
}

const MONTH_RE = /^\d{4}-\d{2}-01$/;

async function parseMonth(req: Request): Promise<{ ok: true; month: string | null } | { ok: false; response: Response }> {
  const raw = await req.text();
  if (raw.trim() === "") return { ok: true, month: null };
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return { ok: false, response: Errors.badRequest("invalid request", ["body must be JSON or empty"]).toResponse() };
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, response: Errors.badRequest("invalid request", ["body must be an object"]).toResponse() };
  }
  const keys = Object.keys(body as Record<string, unknown>);
  if (keys.length === 0) return { ok: true, month: null };
  if (keys.length !== 1 || keys[0] !== "month") {
    return { ok: false, response: Errors.badRequest("invalid request", ["only month is allowed"]).toResponse() };
  }
  const month = (body as { month?: unknown }).month;
  if (typeof month !== "string" || !MONTH_RE.test(month)) {
    return { ok: false, response: Errors.badRequest("invalid request", ["month must be YYYY-MM-01"]).toResponse() };
  }
  return { ok: true, month };
}

export async function handleRollupsRefreshRequest(req: Request, deps: RollupsRefreshDeps): Promise<Response> {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");
  if (!deps.isAuthorized(req)) return Errors.unauthorized().toResponse();

  const limit = await deps.hitRateLimit(
    ROLLUPS_REFRESH_RATE_BUCKET,
    ROLLUPS_REFRESH_RATE_WINDOW_SECONDS,
    ROLLUPS_REFRESH_RATE_MAX_PER_WINDOW,
  );
  if (!limit.ok) return Errors.tooManyRequests("rollups-refresh rate limit exceeded", limit.retryAfterSeconds).toResponse();

  const parsed = await parseMonth(req);
  if (!parsed.ok) return parsed.response;

  try {
    const result = await deps.refresh(parsed.month);
    deps.log({
      event: "rollups_refresh",
      month: result.month,
      operatorWritten: result.operatorWritten,
      operatorRemoved: result.operatorRemoved,
      sponsorWritten: result.sponsorWritten,
      sponsorRemoved: result.sponsorRemoved,
    });
    return okResponse(200, {
      month: result.month,
      operatorWritten: result.operatorWritten,
      operatorRemoved: result.operatorRemoved,
      sponsorWritten: result.sponsorWritten,
      sponsorRemoved: result.sponsorRemoved,
      complete: true,
    });
  } catch (err) {
    const code = (err as { code?: unknown } | null)?.code;
    const short = typeof code === "string" && /^[0-9A-Z_]{1,32}$/.test(code) ? code : "error";
    console.error("rollups-refresh: refresh_rollups failed", err);
    deps.log({ event: "rollups_refresh", complete: false, error: short });
    return errorResponse(500, "rollups_refresh_failed", "rollups refresh failed", { complete: false, error: short });
  }
}
