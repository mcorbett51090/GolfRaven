/**
 * Typed wrappers for the step-up routes of `partner-session` (docs/security/partner-auth-design.md 4.5, 6.3, 6.4, 19.4), over the client's `call()`:
 * the bearer, the headers, the error mapping and the 401 handling are all the client's. This file only builds the closed request bodies and checks the
 * documented response shapes, so a screen never handles a loose `unknown`.
 *
 * NOTHING HERE TAKES A PIN. The PIN-bearing routes take the BROWSER-DERIVED bytes (`derived`, 43 base64url characters) and, for a set or change, the salt
 * and iteration count the browser chose: the digits themselves never reach this module (the derivation is `src/auth/pin.ts`).
 */

import type { PartnerApi } from "./client";
import { PartnerApiError } from "./errors";
import type { PinParams, TotpEnrolment } from "./types";

const FN = "partner-session";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const malformed = () => new PartnerApiError("malformed_response");

/** `GET pin`: the stored salt and iteration count (state `ok`), or the state that has none (unset, must_change, locked). */
export async function getPinParams(api: PartnerApi): Promise<PinParams> {
  const d = await api.call("GET", FN, "pin");
  if (!isObject(d)) throw malformed();
  const state = d["state"];
  if (state === "unset" || state === "must_change" || state === "locked") return { state };
  if (state !== "ok" || typeof d["salt"] !== "string" || typeof d["iterations"] !== "number" || typeof d["retryAfterSeconds"] !== "number") throw malformed();
  return { state: "ok", salt: d["salt"], iterations: d["iterations"], retryAfterSeconds: d["retryAfterSeconds"] };
}

/** `POST step-up/pin { derived }`: on success the session holds a single-use PIN grant until `grantExpiresAt`. */
export async function postPinVerify(api: PartnerApi, derived: string): Promise<{ readonly grantExpiresAt: string }> {
  const d = await api.call("POST", FN, "step-up/pin", { derived });
  if (!isObject(d) || typeof d["grantExpiresAt"] !== "string") throw malformed();
  return { grantExpiresAt: d["grantExpiresAt"] };
}

export interface PinSetBody {
  readonly derived: string;
  readonly salt: string;
  readonly iterations: number;
}
export interface PinChangeBody extends PinSetBody {
  readonly currentDerived: string;
}

/** `POST pin/set`: the first PIN, or a new one after a reset (needs `enrolment_until` or an email proof on the session). */
export async function postPinSet(api: PartnerApi, body: PinSetBody): Promise<void> {
  const d = await api.call("POST", FN, "pin/set", { derived: body.derived, salt: body.salt, iterations: body.iterations });
  if (!isObject(d) || d["set"] !== true) throw malformed();
}

/** `POST pin/change`: the current PIN's derived bytes and the new PIN's (needs the same proof as a set). */
export async function postPinChange(api: PartnerApi, body: PinChangeBody): Promise<void> {
  const d = await api.call("POST", FN, "pin/change", { currentDerived: body.currentDerived, derived: body.derived, salt: body.salt, iterations: body.iterations });
  if (!isObject(d) || d["changed"] !== true) throw malformed();
}

/** `POST otp-proof/start`: mails a one-time code to the member's OWN address. */
export async function postOtpProofStart(api: PartnerApi): Promise<void> {
  const d = await api.call("POST", FN, "otp-proof/start", {});
  if (!isObject(d) || d["sent"] !== true) throw malformed();
}

/** `POST otp-proof/verify { code }`: records the proof on the session; it lasts until `otpProofUntil`. */
export async function postOtpProofVerify(api: PartnerApi, code: string): Promise<{ readonly otpProofUntil: string }> {
  const d = await api.call("POST", FN, "otp-proof/verify", { code });
  if (!isObject(d) || typeof d["otpProofUntil"] !== "string") throw malformed();
  return { otpProofUntil: d["otpProofUntil"] };
}

/** `POST totp/enrol`: the seed, shown once. */
export async function postTotpEnrol(api: PartnerApi): Promise<TotpEnrolment> {
  const d = await api.call("POST", FN, "totp/enrol", {});
  if (
    !isObject(d) || typeof d["seed"] !== "string" || typeof d["otpauthUrl"] !== "string" || typeof d["issuer"] !== "string" ||
    typeof d["period"] !== "number" || typeof d["digits"] !== "number" || typeof d["algo"] !== "string"
  ) throw malformed();
  return { seed: d["seed"], otpauthUrl: d["otpauthUrl"], issuer: d["issuer"], period: d["period"], digits: d["digits"], algo: d["algo"] };
}

/** `POST totp/confirm { code }`: confirms the seed in the session that enrolled it. */
export async function postTotpConfirm(api: PartnerApi, code: string): Promise<void> {
  const d = await api.call("POST", FN, "totp/confirm", { code });
  if (!isObject(d) || d["confirmed"] !== true) throw malformed();
}

/** `POST step-up/totp { code }`: raises the session to aal 2 for the MFA window. */
export async function postTotpVerify(api: PartnerApi, code: string): Promise<{ readonly mfaUntil: string; readonly aal: number }> {
  const d = await api.call("POST", FN, "step-up/totp", { code });
  if (!isObject(d) || typeof d["mfaUntil"] !== "string" || typeof d["aal"] !== "number") throw malformed();
  return { mfaUntil: d["mfaUntil"], aal: d["aal"] };
}
