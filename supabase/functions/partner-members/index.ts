// supabase/functions/partner-members/index.ts
//
// The partner member and credential administration function (docs/security/partner-auth-design.md 4.5, 6.4, 6.5, 22.4, slice S1.5). Every route is a session route (`Authorization: Bearer gr_ps_...`):
//
//   POST   members/{id}/revoke            { orgId }: revoke one membership (class A2, the reach rule)
//   POST   members/{id}/recover           revoke every credential and session, PIN must change, issue a recovery token (class A2); the `gr_enr_` token comes back once
//   POST   members/{id}/pin-reset         clear the lock and the failure counters, PIN must change (class A2)
//   POST   members/{id}/totp-reset        reset an operator's or admin's TOTP (class A3)
//   POST   orgs/{id}/sessions/revoke-all  { createdAfter? }: the stolen-iPad button (class A2)
//   POST   admin/enrolments               { userId }: an admin issues an enrolment token for another admin (class A3)
//   GET    credentials                    the signed-in person's credentials (class A0)
//   POST   credentials/options            create options for a second credential (class A2 + reauth)
//   POST   credentials                    { challengeToken, credential }: register a second credential (class A2 + reauth)
//   DELETE credentials/{id}               revoke a credential (class A2)
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. A partner token is NEVER a Supabase identity: this function never calls
// `getActorFromRequest`. Thin entrypoint: every rule lives in _shared/partner/members-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here.

import { serve } from "std/http/server";
import { handlePartnerMembersRequest } from "../_shared/partner/members-handler.ts";
import { newPartnerEnrolmentToken } from "../_shared/partner/token.ts";
import { registrationVerifier } from "../_shared/partner/webauthn-port.ts";
import { loadPartnerCorsOrigin, partnerDb } from "../_shared/privileged.ts";

// Built once per cold start. A malformed GR_PARTNER_ORIGIN throws here, at boot: a function that cannot say which origin it serves must not serve.
const allowedOrigin = loadPartnerCorsOrigin();

serve((req) =>
  handlePartnerMembersRequest(req, {
    db: partnerDb,
    allowedOrigin,
    registration: registrationVerifier,
    nowMs: () => Date.now(),
    newEnrolmentToken: newPartnerEnrolmentToken,
  }),
);
