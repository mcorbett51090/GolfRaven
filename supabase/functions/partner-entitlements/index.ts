// supabase/functions/partner-entitlements/index.ts
//
// The partner-entitlements function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 28; slice S5). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  collect          ?facilityId=
//   POST handover/mint    { facilityId, entitlementId }
//   POST redeem           { facilityId, entitlementId, method, credential }
//   POST voucher          { facilityId, entitlementId }
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. Thin entrypoint: every rule lives in
// _shared/partner/entitlements-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerEntitlementsRequest } from "../_shared/partner/entitlements-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerEntitlementsRequest(req, { db: partnerDb, allowedOrigin }));
