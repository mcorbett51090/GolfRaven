// supabase/functions/settlement-export/index.ts
//
// The settlement-export function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 32; AT(17), AT(20); P5.1b). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   POST export   { trailId, month }
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. Thin entrypoint: every rule lives in
// _shared/partner/settlement-handler.ts (pure, unit-tested). Storage upload + signed URL is wired from privileged.ts (`exportsStorage`). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handleSettlementExportRequest } from "../_shared/partner/settlement-handler.ts";
import { exportsStorage, loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handleSettlementExportRequest(req, { db: partnerDb, storage: exportsStorage, allowedOrigin }));
