// supabase/functions/qr-print/index.ts
//
// Sign and register a facility's PRINTED QR (docs/security/partner-auth-design.md 6.3 "qr-print", S2b; migration 0055). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  ?facilityId=       the registered printed QR of a facility (class A0, operator or admin)
//   POST { facilityId }     sign it with the Vault printed-QR key and register it (class A3: aal 2 and a TOTP in the last 5 minutes)
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. A partner token is NEVER a Supabase identity: this function never calls
// `getActorFromRequest`. Thin entrypoint: every rule lives in _shared/partner/qr-print-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handleQrPrintRequest } from "../_shared/partner/qr-print-handler.ts";
import { courseQrDb, loadCourseQrLinkOrigin, loadPartnerCorsOrigin } from "../_shared/privileged.ts";

// Built once per cold start. A malformed GR_PARTNER_ORIGIN or GR_COURSE_QR_LINK_ORIGIN throws here, at boot: a function that cannot say which origin it serves must not serve.
const allowedOrigin = loadPartnerCorsOrigin();
const linkOrigin = loadCourseQrLinkOrigin();

serve((req) => handleQrPrintRequest(req, { db: courseQrDb, allowedOrigin, linkOrigin }));
