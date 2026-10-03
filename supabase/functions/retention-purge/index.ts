// supabase/functions/retention-purge/index.ts
//
// POST (no body) — the independent retention schedule (edge role PR4b, E5, launch-blocking). System work, not a user endpoint: it is meant to
// be called on a schedule (hourly; see docs/security/edge-role-design.md, "Deploy runbook (edge role)") by a scheduler that holds the project's
// service-role key as its bearer token. Anything else is 401. One run purges, as `edge_system`, each class of data that is past its retention:
// fix coordinates (30 days), install-link tombstones (24 months), sign-in email proofs (an hour past expiry), finished sign-in revocation rows
// (30 days) and, since 0040 (owner decision 2026-10-02), the two TTL hygiene classes: consumed-nonce tombstones (7 days past expiry) and rate-limit
// windows (older than 2 days). Bounded, idempotent, rate-limited, safe to run concurrently; see _shared/retention/purge-handler.ts for the contract.
//
// Deploy step, not code: schedule it. Nothing in this repository schedules it.

import { hitSystemRateLimit, isServiceRoleBearer, retentionPurgeSteps } from "../_shared/privileged.ts";
import { handleRequest } from "../_shared/http.ts";
import { handleRetentionPurgeRequest, RETENTION_REQUEST_TIMEOUT_MS } from "../_shared/retention/purge-handler.ts";
import { serve } from "std/http/server";

const log = (event: Record<string, unknown>) => console.log(JSON.stringify(event));

serve((req) =>
  handleRequest(
    () =>
      handleRetentionPurgeRequest(req, {
        isAuthorized: isServiceRoleBearer,
        hitRateLimit: hitSystemRateLimit,
        steps: retentionPurgeSteps(),
        nowMs: () => Date.now(),
        log,
      }),
    RETENTION_REQUEST_TIMEOUT_MS,
  ),
);
