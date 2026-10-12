// supabase/functions/offers-admin/index.ts
//
// The offers-admin function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30; slice S6). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  offers           ?trailId=     class A0 (operator of the trail): full offer columns
//   POST offers           { ... }       class A3: draft upsert; eligibility validated with validateOfferEligibility (AT(14)) before the database
//   POST offers/approve   { id }        class A3: admin only, draft → live
//   POST offers/end       { id }        class A3: live → ended
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. Thin entrypoint: every rule lives in
// _shared/partner/offers-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerOffersAdminRequest } from "../_shared/partner/offers-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerOffersAdminRequest(req, { db: partnerDb, allowedOrigin }));
