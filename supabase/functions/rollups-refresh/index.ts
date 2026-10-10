// supabase/functions/rollups-refresh/index.ts
//
// POST (empty or `{ "month": "YYYY-MM-01" }`) — recompute operator_rollup.completions and sponsor_rollup.markers_earned
// for a UTC month (docs/security/partner-auth-design.md §41; plan §4.7.3). System work, not a user endpoint: called on a
// schedule by a scheduler that holds the project's service-role key as its bearer token. Anything else is 401. Mirrors
// retention-purge / exports-purge auth / rate-limit order.
//
// Deploy step, not code: schedule it. Nothing in this repository schedules it.

import { hitSystemRateLimit, isServiceRoleBearer, refreshRollups } from "../_shared/privileged.ts";
import { handleRequest } from "../_shared/http.ts";
import { handleRollupsRefreshRequest, ROLLUPS_REFRESH_REQUEST_TIMEOUT_MS } from "../_shared/rollups/refresh-handler.ts";
import { serve } from "std/http/server";

const log = (event: Record<string, unknown>) => console.log(JSON.stringify(event));

serve((req) =>
  handleRequest(
    () =>
      handleRollupsRefreshRequest(req, {
        isAuthorized: isServiceRoleBearer,
        hitRateLimit: hitSystemRateLimit,
        refresh: refreshRollups,
        log,
      }),
    ROLLUPS_REFRESH_REQUEST_TIMEOUT_MS,
  ),
);
