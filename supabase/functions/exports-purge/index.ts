// supabase/functions/exports-purge/index.ts
//
// POST (no body) — delete objects in the private `exports` bucket older than 7 days (AT(17); docs/security/partner-auth-design.md 32; P5.1b). System work, not a user endpoint: called on a
// schedule by a scheduler that holds the project's service-role key as its bearer token. Anything else is 401. Mirrors retention-purge's auth / rate-limit order.
//
// Deploy step, not code: schedule it. Nothing in this repository schedules it.

import { exportsStorage, hitSystemRateLimit, isServiceRoleBearer } from "../_shared/privileged.ts";
import { handleRequest } from "../_shared/http.ts";
import { EXPORTS_PURGE_REQUEST_TIMEOUT_MS, handleExportsPurgeRequest } from "../_shared/exports/purge-handler.ts";
import { serve } from "std/http/server";

const log = (event: Record<string, unknown>) => console.log(JSON.stringify(event));

serve((req) =>
  handleRequest(
    () =>
      handleExportsPurgeRequest(req, {
        isAuthorized: isServiceRoleBearer,
        hitRateLimit: hitSystemRateLimit,
        storage: exportsStorage,
        nowMs: () => Date.now(),
        log,
      }),
    EXPORTS_PURGE_REQUEST_TIMEOUT_MS,
  ),
);
