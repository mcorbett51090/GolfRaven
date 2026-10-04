// MUST-FAIL (partner auth S1.1b, S0-L3): a second importer of the WebAuthn library. Only supabase/functions/_shared/partner/webauthn.ts may import
// @simplewebauthn/* (that wrapper is where the 14.0.3 gaps of design 6.1 L7 are closed: cross-origin, attestation format, response.id, algorithms,
// key shape, transports). A handler that verifies a ceremony through the library directly would be an unwrapped way in, so the import is the finding,
// wherever it appears and however it is spelled. The specifiers below are exact keys of supabase/functions/deno.json, so they are otherwise LEGAL
// imports (a pinned target on the allow-list): the site is what makes them wrong.
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";

export const verify = verifyAuthenticationResponse;
export const decode = decodeClientDataJSON;
