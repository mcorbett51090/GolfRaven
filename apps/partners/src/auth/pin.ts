/**
 * The browser half of the step-up PIN (docs/security/partner-auth-design.md 6.3, 19.4). The PIN is four digits typed on this page; it is turned into
 * 32 derived bytes HERE, and only those bytes (plus, for a set or change, the salt and iteration count the page chose) ever leave it.
 *
 * The derivation, the PIN's shape and the deny-list are the SHARED modules the Edge and the database tests also run (`_shared/partner/pin-contract.ts`,
 * `pin-deny-list.ts`: Web Crypto only), imported by relative path so the browser cannot drift from the contract. `test/pin.test.ts` pins them to
 * `pin-vectors.ts` (four vectors computed outside the code, at the floor, the default and the ceiling of the iteration range).
 *
 * WHERE THE RULES BITE. The server sees only derived bytes, so it cannot tell a denied PIN from any other: the shape rule and the deny-list are enforced
 * here, before anything is derived or sent. At a SET the page refuses a rejected PIN and tells the person why. At a VERIFY a rejected PIN cannot be a
 * PIN this page ever set, so it is refused the same way: no derivation and no request, and no failure is counted against the member's lockout.
 */

import {
  DEFAULT_ITERATIONS,
  derivePinKeyB64u,
  newPinSalt,
  parseIterations,
  parsePinSalt,
} from "../../../../supabase/functions/_shared/partner/pin-contract.ts";
import { type PinRejection, pinRejection } from "../../../../supabase/functions/_shared/partner/pin-deny-list.ts";
import { toB64u } from "../../../../supabase/functions/_shared/partner/token.ts";

export type { PinRejection };

/** A PIN the rules refuse (`reason`), or server parameters the contract refuses (`params`): a derivation was NOT attempted. */
export class PinError extends Error {
  readonly kind: "rejected" | "params";
  readonly reason: PinRejection | null;

  constructor(kind: "rejected" | "params", reason: PinRejection | null = null) {
    super(`pin: ${kind}${reason === null ? "" : ` (${reason})`}`);
    this.name = "PinError";
    this.kind = kind;
    this.reason = reason;
  }
}

/** The salt and iteration count `GET pin` returned, as they travel. */
export interface StoredPinParams {
  readonly salt: string;
  readonly iterations: number;
}

/** What `POST pin/set` and `POST pin/change` carry besides the derived bytes: the browser's own salt and iteration count. */
export interface NewPinMaterial {
  readonly derived: string;
  readonly salt: string;
  readonly iterations: number;
}

/** The first rule that refuses this PIN, or null. Re-exported so the UI and the flows share one call. */
export function rejectionOf(pin: string): PinRejection | null {
  return pinRejection(pin);
}

/** The derived bytes of a PIN under the member's STORED salt and iteration count. Throws `PinError` for a refused PIN or for parameters outside the contract. */
export async function deriveForVerify(pin: string, stored: StoredPinParams): Promise<string> {
  const reason = pinRejection(pin);
  if (reason !== null) throw new PinError("rejected", reason);
  // a hostile or broken server must not choose the work factor: below the floor weakens the verifier, above the ceiling is a denial of service on this page
  const salt = parsePinSalt(stored.salt);
  const iterations = parseIterations(stored.iterations);
  if (salt === null || iterations === null) throw new PinError("params");
  return await derivePinKeyB64u(pin, salt, iterations);
}

/** A fresh salt (16 CSPRNG bytes) and the default iteration count, and the derived bytes under them. Throws `PinError("rejected")` for a PIN the rules refuse. */
export async function deriveForSet(pin: string): Promise<NewPinMaterial> {
  const reason = pinRejection(pin);
  if (reason !== null) throw new PinError("rejected", reason);
  const salt = newPinSalt();
  return { derived: await derivePinKeyB64u(pin, salt, DEFAULT_ITERATIONS), salt: toB64u(salt), iterations: DEFAULT_ITERATIONS };
}
