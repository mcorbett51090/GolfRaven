// supabase/functions/_shared/catalog/import-endpoint.ts
//
// The pure, dependency-injected request handler behind
// `import-catalog/index.ts` (P3e round 2 gate, M5: "Entrypoint must-fail
// cells for import-catalog/index.ts: anon JWT -> 401, player JWT -> 401,
// wrong method -> 405, oversize body -> 413, rate limit -> 429"). Moving
// the sequencing out of the Deno `serve(...)` entrypoint into a function
// with injected I/O makes every one of those cells unit-testable
// (supabase/tests/unit/import-endpoint.test.ts) without a running server;
// index.ts only wires the REAL dependencies.
//
// AUTH: HMAC-only (webhook-auth.ts) — no JWT path exists, so an anon
// key, a player JWT, or any `Authorization: Bearer ...` header is simply
// "no valid X-GolfRaven-Catalog-Signature" -> 401.
//
// SEQUENCING (H4: "Run the drain even when the import fails (422/500),
// in its own transaction"): auth -> rate limit -> import (own phases/
// transactions) -> drain ALWAYS (its own `withSystemCatalogImport`,
// independent of the import's), then the response reflects both.

import { errorResponse, Errors, HttpError, okResponse } from "../http.ts";
import { isAcceptableWebhookSecret, verifyWebhookSignature } from "./webhook-auth.ts";
import type { CatalogImportOutcome, RejectedArtifact } from "./import-handler.ts";
import type { DrainQueuedCatalogResult } from "./drain-orchestrator.ts";
import type { RescoreBacklogResult } from "./rescore-orchestrator.ts";
import type { CatalogImportEnvConfig, RateLimitResult } from "../types.ts";
import { type Deadline, makeImportBudget } from "./time-budget.ts";

/** This endpoint's own, small body cap — the webhook payload is a couple
 * of fields or empty; far below http.ts's 64 KB evidence cap. */
export const MAX_IMPORT_REQUEST_BODY_BYTES = 4 * 1024;
export const IMPORT_RATE_LIMIT_MAX_PER_HOUR = 60;

export interface ImportEndpointDeps {
  getConfig(): CatalogImportEnvConfig | null;
  hitRateLimit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult>;
  /** Phase 1 (network + crypto, no transaction) then phase 2 (atomic DB
   * apply) — see import-handler.ts. */
  runImport(config: CatalogImportEnvConfig, fetchDeadline: Deadline): Promise<CatalogImportOutcome | RejectedArtifact>;
  /** Drains queued_catalog in its OWN transaction(s), time-boxed by `deadline`. */
  runDrain(deadline: Deadline): Promise<DrainQueuedCatalogResult>;
  /** AT 18: works the stub->verified / split re-score backlog, a bounded
   * batch per pass, each play in its own user's transaction. Optional so
   * existing callers/tests keep working; failures never mask the others. */
  runRescore?(deadline: Deadline): Promise<RescoreBacklogResult>;
  now(): Date;
}

async function readBoundedBody(req: Request): Promise<Uint8Array> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    const n = Number(declared);
    if (Number.isFinite(n) && n > MAX_IMPORT_REQUEST_BODY_BYTES) throw tooLarge();
  }
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_IMPORT_REQUEST_BODY_BYTES) {
      await reader.cancel().catch(() => {});
      throw tooLarge();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

function tooLarge(): HttpError {
  return new HttpError(413, "payload_too_large", `request body exceeds ${MAX_IMPORT_REQUEST_BODY_BYTES} bytes`);
}

export async function handleImportCatalogRequest(req: Request, deps: ImportEndpointDeps): Promise<Response> {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

  const rawBody = await readBoundedBody(req);

  // NIT (P3e round 2 gate): an unconfigured environment answers EXACTLY
  // like a bad signature (same opaque 401) — the detail is logged
  // server-side only, so an unauthenticated caller cannot probe whether
  // this deployment is configured. A weak/blank secret counts as
  // unconfigured.
  const config = deps.getConfig();
  if (!config || !isAcceptableWebhookSecret(config.webhookHmacSecret)) {
    console.error("import-catalog: CATALOG_ARTIFACT_BASE_URL / CATALOG_ARTIFACT_ALLOWED_HOSTS / CATALOG_IMPORT_HMAC_SECRET not fully (or acceptably) configured in this environment");
    return Errors.unauthorized().toResponse();
  }

  const auth = await verifyWebhookSignature({ secret: config.webhookHmacSecret, headerValue: req.headers.get("x-golfraven-catalog-signature"), rawBody, now: deps.now() });
  if (!auth.ok) {
    console.error(`import-catalog: webhook auth rejected (${auth.reason ?? "unknown"})`);
    return Errors.unauthorized().toResponse();
  }

  const rateLimit = await deps.hitRateLimit("import-catalog:system", 3600, IMPORT_RATE_LIMIT_MAX_PER_HOUR);
  if (!rateLimit.ok) return Errors.tooManyRequests("import-catalog rate limit exceeded", rateLimit.retryAfterSeconds).toResponse();

  // Per-PHASE deadlines (time-budget.ts) — measured from here, after auth.
  const budget = makeImportBudget(() => deps.now().getTime());

  // ---- import (never allowed to prevent the drain below) ----
  let importOutcome: CatalogImportOutcome | RejectedArtifact | null = null;
  let importError: unknown = null;
  try {
    importOutcome = await deps.runImport(config, budget.fetch);
  } catch (err) {
    importError = err;
    console.error("import-catalog: unhandled error during import", err);
  }

  // ---- H4: ALWAYS drain, in its own transaction(s) ----
  // Whatever the import left of the budget is split between the two drains
  // (queued first, then the re-score); each stops STARTING work it cannot
  // finish and leaves the rest for the next run.
  const { drain: drainDeadline, rescore: rescoreDeadline } = budget.splitRemaining();
  let drained: DrainQueuedCatalogResult | null = null;
  try {
    drained = await deps.runDrain(drainDeadline);
  } catch (err) {
    console.error("import-catalog: unhandled error during drain", err);
  }

  // AT 18: ALSO always — a failed import must not strand a backlog an
  // EARLIER import already queued.
  let rescored: RescoreBacklogResult | null = null;
  if (deps.runRescore) {
    try {
      rescored = await deps.runRescore(rescoreDeadline);
    } catch (err) {
      console.error("import-catalog: unhandled error during rescore", err);
    }
  }

  if (importError !== null) {
    if (importError instanceof HttpError) return new HttpError(importError.status, importError.code, importError.message, { drained, rescored }).toResponse();
    return new HttpError(500, "internal_error", "internal error", { drained, rescored }).toResponse();
  }
  if (importOutcome === null || !importOutcome.ok) {
    const reason = importOutcome?.reason ?? "unknown";
    console.error(`import-catalog: import rejected (${reason})`);
    return errorResponse(422, "catalog_import_rejected", "the fetched catalog artifact failed verification", { reason, drained, rescored });
  }
  if (drained === null) {
    return new HttpError(500, "internal_error", "internal error", { imported: importOutcome }).toResponse();
  }
  // `truncated`: the budget (not an error) cut a drain short — the rest is
  // still queued / still in the backlog and the next run continues it.
  const truncated = drained.truncated || (rescored?.truncated ?? false);
  return okResponse(200, { imported: importOutcome, drained, rescored, truncated });
}
