// supabase/functions/programme-config/index.ts
//
// The programme-config function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30; slice S6). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  programme              ?trailId=                                 class A0 (operator of the trail)
//   POST programme/trail        { trailId, status, markerSource, ... }    class A3
//   POST programme/facility     { trailId, facilityId, participation, ... } class A3
//   GET  rollups/operator       ?trailId=                                 class A0
//   GET  rollups/sponsor        ?sponsorshipId=                           class A0
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. Thin entrypoint: every rule lives in
// _shared/partner/programme-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerProgrammeRequest } from "../_shared/partner/programme-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerProgrammeRequest(req, { db: partnerDb, allowedOrigin }));
