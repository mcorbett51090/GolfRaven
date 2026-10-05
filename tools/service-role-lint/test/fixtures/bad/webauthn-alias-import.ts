// MUST-FAIL (partner auth S1.1b, S0-L3): the library behind an ALIAS. "webauthn" is not itself a banned name; a deno.json entry that maps it to
// npm:@simplewebauthn/server@14.0.3 makes it the library. A check that reads only the literal specifier would pass this file.
import { generateAuthenticationOptions } from "webauthn";

export const options = generateAuthenticationOptions;
