// supabase/functions/sponsorships-admin/index.ts
//
// The sponsorships-admin function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30; slice S6). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  sponsorships           ?trailId=     class A0 (operator of the trail)
//   POST sponsorships           { ... }       class A3: draft upsert
//   POST sponsorships/approve   { id }        class A3: draft → live; stock_short (AT(20)) → 422
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. Thin entrypoint: every rule lives in
// _shared/partner/sponsorships-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerSponsorshipsRequest } from "../_shared/partner/sponsorships-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerSponsorshipsRequest(req, { db: partnerDb, allowedOrigin }));
