// supabase/functions/import-catalog/index.ts
//
// The Edge Function entrypoint for `import-catalog` (build plan §3.3 /
// P1 scope / P3 scope: "the import-catalog Edge Function (pull + verify
// + ledger import)... and queued_catalog draining"). Deliberately thin:
// every decision lives in `_shared/catalog/import-endpoint.ts` (pure,
// dependency-injected, unit-tested — M5's entrypoint must-fail cells),
// `import-handler.ts` (pull+verify, then atomic apply) and
// `drain-orchestrator.ts`. This file only wires the REAL I/O in.
//
// AUTH: HMAC-only, no JWT path at all — see import-endpoint.ts /
// webhook-auth.ts.
//
// EDGE ROLE: every database call below runs through GOLFRAVEN_EDGE_DB_URL (there is no other database path since PR4b):
// the importer repo, the drain's list reads and both purges are `edge_system` (`withSystemCatalogImport`); the drains' per-row USER
// transactions are `withDelegatedActor` (edge_system binds the row's owner through a delegate binder, then acts as edge_actor); the rate
// limit is `hitSystemRateLimit` (edge_system). So this function needs ONE connection string, not two.
//
// M4 (fetch safety): every artifact is fetched and verified BEFORE the
// write transaction opens (`fetchAndVerifyArtifact`), with
// `AbortSignal.timeout`, `redirect: "error"` and a streamed byte cap on
// every fetch; the signing-key lookup it needs is its own short,
// already-committed read.

import { getCatalogImportEnvConfig, hitSystemRateLimit, withDelegatedActor, withSystemCatalogImport } from "../_shared/privileged.ts";
import { handleRequest } from "../_shared/http.ts";
import { applyImportPlanAtomically, fetchAndVerifyArtifact, type FetchBytes } from "../_shared/catalog/import-handler.ts";
import { drainQueuedCatalog } from "../_shared/catalog/drain-orchestrator.ts";
import { drainRescoreBacklog } from "../_shared/catalog/rescore-orchestrator.ts";
import { handleImportCatalogRequest } from "../_shared/catalog/import-endpoint.ts";
import { makeDrainReadRepo } from "../_shared/catalog/drain-read-repo.ts";
import { PER_FETCH_MS, TOTAL_BUDGET_MS, type Deadline } from "../_shared/catalog/time-budget.ts";
import { serve } from "std/http/server";


/** The Edge Runtime's own outbound fetch, bounded by (a) a hard deadline
 * (`AbortSignal.timeout`), (b) `redirect: "error"` — a redirect (e.g.
 * an allow-listed host bouncing to an attacker's) is a failure, never
 * followed — and (c) a RUNNING byte count over the response stream, the
 * same "never buffer past the cap before checking size" discipline
 * http.ts#readJsonBody uses for a request body. A missing/lying
 * `Content-Length` on the RESPONSE is as untrustworthy as one on a
 * request, so the streamed check is the real enforcement. */
const makeFetchBytes = (fetchDeadline: Deadline): FetchBytes => async (url, maxBytes) => {
  // Per-fetch hard deadline (M4), never past the whole fetch PHASE's own
  // deadline (time-budget.ts) — sequential fetches cannot add up past it.
  const allowedMs = Math.min(PER_FETCH_MS, fetchDeadline.remainingMs());
  if (allowedMs <= 0) throw new Error(`import-catalog: fetch phase budget exhausted before ${url}`);
  const res = await fetch(url, { signal: AbortSignal.timeout(allowedMs), redirect: "error" });
  if (!res.ok) throw new Error(`import-catalog: fetch ${url} -> HTTP ${res.status}`);
  const declared = res.headers.get("content-length");
  if (declared !== null) {
    const n = Number(declared);
    if (Number.isFinite(n) && n > maxBytes) throw new Error(`import-catalog: ${url} declares ${n} bytes, over the ${maxBytes}-byte cap`);
  }
  if (!res.body) return new Uint8Array(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error(`import-catalog: ${url} exceeded the ${maxBytes}-byte cap`);
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
};

/** A short, SEPARATE, already-committed read — never inside the import's
 * write transaction (M4). */
const getSigningKeyReadOnly = (kid: string) => withSystemCatalogImport((repo) => repo.catalog.getSigningKey(kid));

/** A cap per run — the real bound is the time budget (time-budget.ts):
 * each row is its own per-user transaction, a new one is only started
 * while the phase deadline leaves room, and whatever is left stays queued
 * for the next run. */
const DRAIN_BATCH_LIMIT = 200;

/** Each drain read/advance is its own short system transaction — see
 * drain-read-repo.ts. */
const drainReadRepo = makeDrainReadRepo(withSystemCatalogImport);

serve((req) =>
  handleRequest(
    () =>
      handleImportCatalogRequest(req, {
        getConfig: getCatalogImportEnvConfig,
        hitRateLimit: hitSystemRateLimit,
        now: () => new Date(),
        runImport: async (config, fetchDeadline) => {
          const plan = await fetchAndVerifyArtifact({ artifactBaseUrl: config.artifactBaseUrl, allowedHosts: config.allowedHosts }, makeFetchBytes(fetchDeadline), getSigningKeyReadOnly);
          if (!plan.ok) return plan;
          return applyImportPlanAtomically(plan, withSystemCatalogImport);
        },
        // H4: its own transaction(s) — independent of whatever the import did.
        runDrain: (deadline) => drainQueuedCatalog(drainReadRepo, withDelegatedActor, DRAIN_BATCH_LIMIT, deadline),
        runRescore: (deadline) => drainRescoreBacklog(drainReadRepo, withDelegatedActor, undefined, deadline),
      }),
    // The per-PHASE deadlines above are the mechanism; this race (the
    // whole-request budget) is only the backstop for a phase that blows
    // through its own bound.
    TOTAL_BUDGET_MS,
  ),
);
