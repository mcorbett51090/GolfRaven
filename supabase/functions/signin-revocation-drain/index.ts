// supabase/functions/signin-revocation-drain/index.ts
//
// POST (no body) — the retry loop behind "a revocation that fails is retried for 72 h and logged" (build plan §7.8, Apple
// 5.1.1(v)). System work, not a user endpoint: it is meant to be called every few minutes by a scheduler (Supabase cron / pg_net)
// that holds the project's service-role key as its bearer token. Anything else is 401: the gateway's JWT check alone would also
// admit an anon key. One run: expire what ran out its 72 h (the database logs each give-up), attempt up to 25 due rows, and once
// per run delete finished rows older than 30 days. Idempotent and safe to run concurrently (rows are leased).
//
// Deploy step, not code: schedule it, e.g. every 5 minutes. See docs/security/p3-money-path-requirements.md ("Sign in with Apple,
// server side").

import { isServiceRoleBearer, loadAppleSiwaConfig, purgeSigninEmailProofs, signinRevocationDb } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, Errors } from "../_shared/http.ts";
import { buildSigninPorts, platformFetch } from "../_shared/signin/production.ts";
import { runRevocations } from "../_shared/signin/revocation.ts";
import { serve } from "std/http/server";

const ports = buildSigninPorts(loadAppleSiwaConfig(), { fetch: platformFetch, nowMs: () => Date.now() });
const log = (event: Record<string, unknown>) => console.log(JSON.stringify(event));

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");
    if (!isServiceRoleBearer(req)) return Errors.unauthorized().toResponse();

    const outcomes = await runRevocations({ db: signinRevocationDb, apple: ports.apple, google: ports.google, log }, { limit: 25 });
    const purged = await signinRevocationDb.purge(30);
    const purgedEmailProofs = await purgeSigninEmailProofs();
    return okResponse(200, {
      attempted: outcomes.length,
      revoked: outcomes.filter((o) => o.status === "revoked").length,
      queuedForRetry: outcomes.filter((o) => o.status === "queued_for_retry").length,
      purgedFinishedRows: purged,
      purgedEmailProofs,
    });
  }),
);
