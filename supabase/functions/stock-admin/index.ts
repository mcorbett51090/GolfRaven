// supabase/functions/stock-admin/index.ts
//
// The stock-admin function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 28; slice S5). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  stock          ?facilityId=                                 class A0 (staff or manager)
//   POST stock/move     { facilityId, trailId, kind, qty, note? }    class A1
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. Thin entrypoint: every rule lives in
// _shared/partner/stock-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerStockRequest } from "../_shared/partner/stock-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerStockRequest(req, { db: partnerDb, allowedOrigin }));
