// supabase/functions/partner-review/index.ts
//
// The partner review function (docs/security/partner-auth-design.md 4.5, 6.3, 12, 27; slice S4). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  queue                         the open held_review rewards and open review_items (class A0, admin)
//   GET  sla                           counts for the ops alert surface (class A0, admin)
//   POST resolve/offer-code            { id, approve }   wraps app.resolve_held_offer_code (class A3, admin; E20)
//   POST resolve/entitlement           { id, approve }   wraps app.resolve_held_entitlement (class A3, admin)
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. A partner token is NEVER a Supabase identity: this function never calls
// `getActorFromRequest`. Thin entrypoint: every rule lives in _shared/partner/review-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerReviewRequest } from "../_shared/partner/review-handler.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

const allowedOrigin = loadPartnerCorsOrigin();

serve((req) => handlePartnerReviewRequest(req, { db: partnerDb, allowedOrigin }));
