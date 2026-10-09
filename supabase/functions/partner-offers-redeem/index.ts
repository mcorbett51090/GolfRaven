// supabase/functions/partner-offers-redeem/index.ts
//
// The partner-offers-redeem function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 32; P5.1b). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  queue    ?facilityId=
//   POST redeem   { facilityId, offerCodeId, method, credential }
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. Thin entrypoint: every rule lives in
// _shared/partner/offers-redeem-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerOffersRedeemRequest } from "../_shared/partner/offers-redeem-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerOffersRedeemRequest(req, { db: partnerDb, allowedOrigin }));
