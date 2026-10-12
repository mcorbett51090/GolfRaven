// supabase/functions/partner-invites/index.ts
//
// The partner invite, enrolment and first-credential function (docs/security/partner-auth-design.md 4.5, 6.1, 22.4, slice S1.5):
//
//   POST   invites                    { orgId, role, email }: create an invite (session, class A2); the `gr_inv_` token comes back once
//   GET    invites                    list the invites the actor's scope covers (session)
//   DELETE invites/{id}               revoke an unaccepted invite (session, class A2)
//   POST   invites/accept/start       { token }: mail a one-time code to the address on the invite (a constant answer)
//   POST   invites/accept/verify      { token, code }: branch N: the code, then the acceptance; the register challenge and the create options
//   POST   invites/accept             { token }: branch E (session, class A2): an existing member joins another organisation
//   POST   enrolments/accept/start    { token }: the same, for a recovery or admin enrolment token
//   POST   enrolments/accept/verify   { token, code }
//   POST   credentials                { userId, refKind, refId, challengeToken, credential }: the FIRST credential, and the first session (the `gr_ps_` token comes back once)
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies, and most routes carry no bearer at all. A partner token is NEVER a Supabase
// identity: this function never calls `getActorFromRequest`. Thin entrypoint: every rule lives in _shared/partner/invites-handler.ts (pure, unit-tested). No `console`, no log line, no environment read here:
// the one environment value (GR_PARTNER_ORIGIN) is read by privileged.ts, the only module that may.

import { serve } from "std/http/server";
import { handlePartnerInvitesRequest } from "../_shared/partner/invites-handler.ts";
import { newPartnerInviteToken, newPartnerSessionToken } from "../_shared/partner/token.ts";
import { registrationVerifier } from "../_shared/partner/webauthn-port.ts";
import { loadPartnerCorsOrigin, partnerDb, partnerEmailOtp, partnerInviteEmailOtp } from "../_shared/privileged.ts";

// Built once per cold start. A malformed GR_PARTNER_ORIGIN throws here, at boot: a function that cannot say which origin it serves must not serve.
const allowedOrigin = loadPartnerCorsOrigin();

serve((req) =>
  handlePartnerInvitesRequest(req, {
    db: partnerDb,
    allowedOrigin,
    registration: registrationVerifier,
    inviteOtp: partnerInviteEmailOtp,
    enrolmentOtp: partnerEmailOtp,
    nowMs: () => Date.now(),
    newSessionToken: newPartnerSessionToken,
    newInviteToken: newPartnerInviteToken,
  }),
);
