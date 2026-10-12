// supabase/functions/_shared/partner/webauthn-port.ts
//
// The adapter between the sign-in handler's `AssertionVerifier` port (`ports.ts`) and the S0 wrapper (`webauthn.ts`, the ONE module that touches @simplewebauthn/server).
// docs/security/partner-auth-design.md 6.1, 6.2 and PA-12. Deno only (the wrapper imports the library through the import map); the handler itself never imports it, which is what keeps the handler
// unit-testable under vitest.
//
// What it does beyond forwarding: it turns a wrapper refusal into a plain `{ ok: false }` (the closed code and the library's message, which can quote a challenge or a counter, stay in this file and
// are never returned, logged or sent), and it isolates the COUNTER. A non-zero counter that does not strictly rise is refused by the library like any other fault, but it is not a guess: it is the
// clone indicator of 6.2 step 4, and the database must see it so it writes the audit_log and alarm rows. So a refusal with the library's own `verification_failed` code is verified AGAIN with the stored
// counter forgotten (0): if THAT passes, the signature, origin, RP ID, challenge and user verification were all fine and the counter was the only fault (`counterOnly`). The handler then passes the
// assertion to the mint, which re-verifies everything (and writes the alarm); a forged assertion never gets that far because its second verification fails too.

import type { AssertionVerifier, CreationOptionsRequest, RegistrationOutcome, RegistrationVerifier, RpConfig, VerifyAssertionRequest, VerifyOutcome, VerifyRegistrationRequest } from "./ports.ts";
import { fromB64u, toB64u } from "./token.ts";
import { authenticationOptions, registrationOptions, verifyAssertion, verifyRegistration, WebAuthnRefusal } from "./webauthn.ts";

async function verifyOnce(input: VerifyAssertionRequest, signCount: number): Promise<VerifyOutcome | "refused_by_library"> {
  try {
    await verifyAssertion({
      rp: input.rp,
      // the library's type is structural and identical to AssertionJson (the handler built it from a strictly validated body)
      response: input.response as Parameters<typeof verifyAssertion>[0]["response"],
      expectedChallenge: input.expectedChallenge,
      credential: { id: input.credential.id, publicKey: input.credential.publicKey, signCount },
      expectedUserHandle: input.expectedUserHandle,
    });
    return { ok: true };
  } catch (e) {
    if (!(e instanceof WebAuthnRefusal)) throw e; // a configuration fault (RpConfigError ...) is not a client refusal: it surfaces as a 500 and rolls back
    return e.code === "verification_failed" || e.code === "not_verified" ? "refused_by_library" : { ok: false, counterOnly: false };
  }
}

export const assertionVerifier: AssertionVerifier = {
  options(rp: RpConfig, challenge: Uint8Array) {
    return authenticationOptions({ rp, challenge });
  },
  async verify(input: VerifyAssertionRequest): Promise<VerifyOutcome> {
    const first = await verifyOnce(input, input.credential.signCount);
    if (first !== "refused_by_library") return first;
    // the counter is the only thing that differs between the stored counter and 0: if the assertion verifies against 0, it was the counter
    if (input.credential.signCount > 0) {
      const second = await verifyOnce(input, 0);
      if (second !== "refused_by_library" && second.ok) return { ok: false, counterOnly: true };
    }
    return { ok: false, counterOnly: false };
  },
};

/** What an authenticator shows next to the relying party; not an identifier. */
const RP_DISPLAY_NAME = "GolfRaven";

/**
 * The create ceremony (6.1 step 4, S1.5). A wrapper refusal (a wrong format, a cross-origin ceremony, a mismatched challenge, a key outside the allowed algorithms) is a plain `{ ok: false }`: the closed code and the
 * library's message stay in this file. A configuration fault is not a client refusal and propagates (a 500, a rollback). The id and the key are returned as bytes: they are what the database parses and stores.
 */
export const registrationVerifier: RegistrationVerifier = {
  options(req: CreationOptionsRequest) {
    return registrationOptions({
      rp: req.rp,
      rpName: RP_DISPLAY_NAME,
      userHandle: req.userHandle,
      userName: req.userName,
      userDisplayName: req.userName,
      challenge: req.challenge,
      excludeCredentialIds: req.excludeCredentialIds.map(toB64u),
    });
  },
  async verify(req: VerifyRegistrationRequest): Promise<RegistrationOutcome> {
    try {
      const v = await verifyRegistration({
        rp: req.rp,
        // the library's type is structural and identical to RegistrationJson (the handler built it from a strictly validated body)
        response: req.response as Parameters<typeof verifyRegistration>[0]["response"],
        expectedChallenge: req.expectedChallenge,
      });
      const credentialId = fromB64u(v.credentialId);
      if (credentialId === null) return { ok: false };
      return { ok: true, credentialId, publicKey: v.publicKey, transports: v.transports };
    } catch (e) {
      if (!(e instanceof WebAuthnRefusal)) throw e;
      return { ok: false };
    }
  },
};
