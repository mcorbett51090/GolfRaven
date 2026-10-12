// supabase/functions/receipts-purge/index.ts
//
// POST (no body) — delete objects in the private `receipts` bucket older than 90 days
// (docs/security/partner-auth-design.md §42; build plan A66 / 0012 TODO). System work, not a user
// endpoint: called on a schedule by a scheduler that holds the project's service-role key as its
// bearer token. Anything else is 401. Mirrors exports-purge / retention-purge auth / rate-limit order.
//
// Deploy step, not code: schedule it. Nothing in this repository schedules it.

import { hitSystemRateLimit, isServiceRoleBearer, receiptsStorage } from "../_shared/privileged.ts";
import { handleRequest } from "../_shared/http.ts";
import { handleReceiptsPurgeRequest, RECEIPTS_PURGE_REQUEST_TIMEOUT_MS } from "../_shared/receipts/purge-handler.ts";
import { serve } from "std/http/server";

const log = (event: Record<string, unknown>) => console.log(JSON.stringify(event));

serve((req) =>
  handleRequest(
    () =>
      handleReceiptsPurgeRequest(req, {
        isAuthorized: isServiceRoleBearer,
        hitRateLimit: hitSystemRateLimit,
        storage: receiptsStorage,
        nowMs: () => Date.now(),
        log,
      }),
    RECEIPTS_PURGE_REQUEST_TIMEOUT_MS,
  ),
);
