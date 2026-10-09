// supabase/functions/partner-attest/index.ts
//
// The partner attest function (docs/security/partner-auth-design.md 4.5, 6.5, 6.7, 12, 26; slice S3). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   POST attest           { facilityId, kind, token }          the ONLINE attest: the player's check-in token (class A1, one PIN per action)
//   POST attest/offline   { facilityId, kind, handle, code }   the offline code, verified and recorded IN THE DATABASE (class A1); the Edge never holds a seed or an expected code
//   GET  shift-log        ?facilityId=                         the facility's shift log (class A0, staff or manager)
//   GET  staff-activity   ?facilityId=&days=                   counts and anomaly markers per staff member and day (class A0, manager or operator)
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. A partner token is NEVER a Supabase identity: this function never calls
// `getActorFromRequest`. Thin entrypoint: every rule lives in _shared/partner/attest-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerAttestRequest } from "../_shared/partner/attest-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

// Built once per cold start. A malformed GR_PARTNER_ORIGIN throws here, at boot: a function that cannot say which origin it serves must not serve.
const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerAttestRequest(req, { db: partnerDb, allowedOrigin }));
