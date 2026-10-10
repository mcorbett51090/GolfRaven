// supabase/functions/course-qr/index.ts
//
// The STAFF lane of the course QR (docs/security/partner-auth-design.md 4.2, 6.3, S2b; migration 0055). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   GET  pin?facilityId=                 today's PIN, from the database's own derivation (class A0)
//   POST pin/rotate    { facilityId }    "Rotate PIN": pin_epoch + 1 (class A2)
//   POST tokens        { facilityId }    "Marker sold": a rotating token signed with the Vault key (class A1: consumes the single-use PIN grant)
//   POST tokens/refresh { facilityId, nonceHash }   the sale screen's 30 s heartbeat for one's own token (class A0_KEEPALIVE: never advances idle, creates nothing)
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. A partner token is NEVER a Supabase identity: this function never calls
// `getActorFromRequest`. Thin entrypoint: every rule lives in _shared/partner/course-qr-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handleCourseQrRequest } from "../_shared/partner/course-qr-handler.ts";
import { courseQrDb, loadCourseQrLinkOrigin, loadPartnerCorsOrigin } from "../_shared/privileged.ts";

// Built once per cold start. A malformed GR_PARTNER_ORIGIN or GR_COURSE_QR_LINK_ORIGIN throws here, at boot: a function that cannot say which origin it serves must not serve.
const allowedOrigin = loadPartnerCorsOrigin();
const linkOrigin = loadCourseQrLinkOrigin();

serve((req) =>
  handleCourseQrRequest(req, {
    db: courseQrDb,
    allowedOrigin,
    linkOrigin,
    randomNonce: () => crypto.getRandomValues(new Uint8Array(16)),
  }),
);
