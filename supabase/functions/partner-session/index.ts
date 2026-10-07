// supabase/functions/partner-session/index.ts
//
// The partner (staff) sign-in and session function (docs/security/partner-auth-design.md 4.5, slice S1.2): the first Edge Function a staff member's browser talks to.
//
//   POST options          a stateless sign-in challenge
//   POST verify           { challengeToken, credential }: the passkey assertion -> the opaque `gr_ps_` session token (once)
//   GET  session          who am I (never extends the idle timer)
//   POST sign-out         revoke this session
//   POST lock             clear every step-up grant now
//   POST reauth/options   a reauth challenge bound to the session
//   POST reauth           { challengeToken, credential }: a fresh passkey assertion by the SESSION'S OWN person
//   GET  pin              the PBKDF2 inputs (salt, iterations) for the browser-side PIN derivation (S1.3)
//   POST step-up/pin      { derived }: the browser-derived PIN key -> a single-use PIN grant
//   POST pin/set          { derived, salt, iterations }: set the PIN (inside an enrolment window or after an email proof)
//   POST pin/change       { currentDerived, derived, salt, iterations }: change the PIN
//   POST otp-proof/start  mail a one-time code to the member's own address
//   POST otp-proof/verify { code }: record the email proof
//
// `verify_jwt = false` (supabase/config.toml): the gateway must not demand a Supabase JWT in the header the partner token occupies. A partner token is NEVER a Supabase identity: this function never
// calls `getActorFromRequest`, and `getActorFromRequest` refuses a `gr_ps_` bearer before it reaches GoTrue. Thin entrypoint: every rule lives in _shared/partner/session-handler.ts (pure, unit-tested).
// No `console`, no log line, no environment read here: the one environment value (GR_PARTNER_ORIGIN) is read by privileged.ts, the only module that may.

import { serve } from "std/http/server";
import { handlePartnerSessionRequest } from "../_shared/partner/session-handler.ts";
import { newPartnerSessionToken } from "../_shared/partner/token.ts";
import { assertionVerifier } from "../_shared/partner/webauthn-port.ts";
import { loadPartnerCorsOrigin, partnerDb, partnerEmailOtp } from "../_shared/privileged.ts";

// Built once per cold start. A malformed GR_PARTNER_ORIGIN throws here, at boot: a function that cannot say which origin it serves must not serve.
const allowedOrigin = loadPartnerCorsOrigin();

serve((req) =>
  handlePartnerSessionRequest(req, {
    db: partnerDb,
    allowedOrigin,
    webauthn: assertionVerifier,
    otp: partnerEmailOtp,
    nowMs: () => Date.now(),
    newSessionToken: newPartnerSessionToken,
  }),
);
