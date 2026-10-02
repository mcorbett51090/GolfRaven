// supabase/functions/_shared/retention/purge-handler.ts
//
// The pure, DI'd core of `retention-purge` (edge role PR4b, E5, launch-blocking): the retention schedule that runs INDEPENDENTLY of a catalog
// import and of the sign-in revocation drain. Nothing here touches a connection or the environment: the steps, the authorisation check, the rate
// limit and the clock arrive through `RetentionDeps`, wired by `retention-purge/index.ts` from privileged.ts.
//
//   Authentication   the scheduler's bearer token is the project's service-role key, compared in constant time (`isServiceRoleBearer`, the same
//                    check `signin-revocation-drain` makes). A wrong or missing bearer is a 401 BEFORE the rate limit and before any database access:
//                    an unauthenticated caller opens no connection and spends nothing.
//   Rate limit       one coarse system bucket (`retention-purge`, 12 per hour). A scheduler that runs hourly uses 1; the rest is headroom for a manual
//                    run or a retry, and a runaway scheduler is answered 429 instead of hammering the database.
//   Bounded          each step removes at most `batchLimit` rows per batch (the definer's own limit) and a run repeats a step at most
//                    MAX_BATCHES_PER_STEP times, and starts no new batch after RUN_BUDGET_MS. What is left is reported as `truncated` and is picked up by
//                    the next run (every purge is oldest-first, so the next run continues where this one stopped).
//   Idempotent       each purge deletes only what is already past its retention; running it twice removes nothing the first did not.
//   Concurrent       a step's batch takes a try-lock first (privileged.ts#retentionPurgeSteps): a concurrent run reports `busy` for that step instead of
//                    waiting on, or deadlocking over, the same rows.
//   Failure          one step failing does not stop the others (each class is independent retention): the run reports every step and answers 500
//                    if any failed, so a scheduler's monitoring sees it. Only a short code is reported, never database text.

import { Errors, errorResponse, okResponse } from "../http.ts";
import type { RateLimitResult, RetentionStep } from "../types.ts";

/** The most batches one step runs in one request. With 5000 rows per batch this bounds a run at 50 000 rows per step. */
export const MAX_BATCHES_PER_STEP = 10;
/** No new batch is STARTED after this much of the run has elapsed (a batch is itself bounded by the 10 s statement timeout, 12 s transaction timeout). */
export const RUN_BUDGET_MS = 30_000;
/** The whole-request race (http.ts#handleRequest); above RUN_BUDGET_MS plus one batch plus the rate-limit transaction. */
export const RETENTION_REQUEST_TIMEOUT_MS = 55_000;
export const RETENTION_RATE_BUCKET = "retention-purge";
export const RETENTION_RATE_WINDOW_SECONDS = 3600;
export const RETENTION_RATE_MAX_PER_WINDOW = 12;

export interface RetentionDeps {
  /** True only for the scheduler's bearer (constant-time). */
  isAuthorized(req: Request): boolean;
  hitRateLimit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult>;
  steps: RetentionStep[];
  nowMs(): number;
  log(event: Record<string, unknown>): void;
}

export type StepStatus = "done" | "truncated" | "busy" | "failed";

export interface StepResult {
  name: RetentionStep["name"];
  status: StepStatus;
  /** Rows removed across this run's batches. */
  purged: number;
  batches: number;
  /** Only on `failed`: a short machine code (an SQLSTATE or `error`), never the message. */
  error?: string;
}

export interface RetentionResult {
  steps: StepResult[];
  /** true when every step ran to the end of what is past retention (no step was truncated, busy or failed). */
  complete: boolean;
}

/** A short, non-sensitive code for a failed step: the SQLSTATE when there is one, else `error`. */
function errorCode(err: unknown): string {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[0-9A-Z_]{1,32}$/.test(code) ? code : "error";
}

async function runStep(step: RetentionStep, deps: RetentionDeps, startedAt: number): Promise<StepResult> {
  const out: StepResult = { name: step.name, status: "done", purged: 0, batches: 0 };
  const maxBatches = step.batchLimit === null ? 1 : MAX_BATCHES_PER_STEP;
  try {
    for (;;) {
      if (out.batches > 0 && deps.nowMs() - startedAt >= RUN_BUDGET_MS) {
        out.status = "truncated";
        return out;
      }
      const n = await step.runBatch();
      if (n === null) {
        out.status = "busy"; // another run holds this step right now: it is doing this work
        return out;
      }
      out.batches += 1;
      out.purged += n;
      // An unbatched step is one pass; a batched step is finished when a batch comes back short of its limit.
      if (step.batchLimit === null || n < step.batchLimit) return out;
      if (out.batches >= maxBatches) {
        out.status = "truncated"; // the last batch was full: more is (probably) waiting; the next run continues
        return out;
      }
    }
  } catch (err) {
    out.status = "failed";
    out.error = errorCode(err);
    // The error itself goes to the server log only (it may carry database text); the response carries the code.
    console.error(`retention-purge: step ${step.name} failed`, err);
    return out;
  }
}

export async function handleRetentionPurgeRequest(req: Request, deps: RetentionDeps): Promise<Response> {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");
  // Authentication first: nothing below runs, and no connection is opened, for a caller that is not the scheduler.
  if (!deps.isAuthorized(req)) return Errors.unauthorized().toResponse();

  const limit = await deps.hitRateLimit(RETENTION_RATE_BUCKET, RETENTION_RATE_WINDOW_SECONDS, RETENTION_RATE_MAX_PER_WINDOW);
  if (!limit.ok) return Errors.tooManyRequests("retention-purge rate limit exceeded", limit.retryAfterSeconds).toResponse();

  const startedAt = deps.nowMs();
  const steps: StepResult[] = [];
  // Sequential, in a fixed order: each step is its own short transaction, and a failure in one never stops the next.
  for (const step of deps.steps) steps.push(await runStep(step, deps, startedAt));

  const result: RetentionResult = { steps, complete: steps.every((s) => s.status === "done") };
  deps.log({ event: "retention_purge", complete: result.complete, steps: steps.map((s) => ({ name: s.name, status: s.status, purged: s.purged, batches: s.batches, error: s.error })) });
  if (steps.some((s) => s.status === "failed")) {
    return errorResponse(500, "retention_step_failed", "one or more retention steps failed; the others ran", result);
  }
  return okResponse(200, result);
}
