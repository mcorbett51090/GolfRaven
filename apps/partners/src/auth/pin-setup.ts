/**
 * Setting, changing and proving the right to set a PIN (docs/security/partner-auth-design.md 6.3, 19.4).
 *
 * A PIN is set or changed only inside the session's `enrolment_until` window (the first session of an enrolment, 15 minutes) or `otp_proof_until` (a fresh
 * emailed code to the member's own address, 10 minutes); a passkey alone is not enough (H2: on a shared iPad anyone with the passcode holds one). A change
 * also needs the CURRENT PIN. The page never stores the PIN: `setPin` and `changePin` take the digits as an argument, derive, send the derived bytes and
 * return.
 */

import type { PartnerApi } from "../api/client";
import { getPinParams, postOtpProofStart, postOtpProofVerify, postPinChange, postPinSet } from "../api/session-routes";
import type { WhoAmI } from "../api/types";
import { deriveForSet, deriveForVerify, PinError } from "./pin";

/** What the PIN screen should offer for this member: a first PIN (or a new one after a reset), a change, or nothing (locked). */
export type PinSetupMode = "set" | "change" | "locked";

export async function pinSetupMode(api: PartnerApi): Promise<PinSetupMode> {
  const p = await getPinParams(api);
  if (p.state === "locked") return "locked";
  return p.state === "ok" ? "change" : "set";
}

/** True while the session may set or change a PIN without a fresh email proof: an unexpired enrolment window or OTP proof. */
export function proofActive(session: WhoAmI, nowMs: number): boolean {
  const live = (iso: string | null) => iso !== null && Date.parse(iso) > nowMs;
  return live(session.stepUp.enrolmentUntil) || live(session.stepUp.otpProofUntil);
}

/** `POST pin/set`. Throws `PinError("rejected")` (nothing sent) for a PIN the rules refuse. */
export async function setPin(api: PartnerApi, pin: string): Promise<void> {
  await postPinSet(api, await deriveForSet(pin));
}

/** `POST pin/change`: derives the current PIN under the stored salt and the new one under a fresh salt. Throws `PinError` (nothing sent) for either PIN the rules refuse. */
export async function changePin(api: PartnerApi, currentPin: string, newPin: string): Promise<void> {
  const params = await getPinParams(api);
  if (params.state !== "ok") throw new PinError("params");
  const currentDerived = await deriveForVerify(currentPin, params);
  const next = await deriveForSet(newPin);
  await postPinChange(api, { currentDerived, ...next });
}

export const startEmailProof = (api: PartnerApi): Promise<void> => postOtpProofStart(api);
export const verifyEmailProof = (api: PartnerApi, code: string): Promise<{ readonly otpProofUntil: string }> => postOtpProofVerify(api, code);
