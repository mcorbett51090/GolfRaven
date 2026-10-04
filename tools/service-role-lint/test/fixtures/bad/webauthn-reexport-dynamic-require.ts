// MUST-FAIL (partner auth S1.1b, S0-L3): the other three ways to reach the WebAuthn library from a module that is not the wrapper: a re-export, a
// dynamic import() and a require(). Each names the library by an exact import-map key.
export { verifyRegistrationResponse } from "@simplewebauthn/server";

export async function lazy() {
  return await import("@simplewebauthn/server/helpers");
}

declare function require(spec: string): unknown;
export const cjs = require("@simplewebauthn/server");
