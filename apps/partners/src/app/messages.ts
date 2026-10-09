/** Maps a failure to the catalogue key (and parameters) the UI shows. Pure: no DOM, no locale. A message never contains a server string. */

import { isPartnerApiError } from "../api/errors";
import type { MessageKey, Params } from "../i18n";
import type { PinRejection } from "../auth/pin";
import { WebAuthnFailure } from "../webauthn/assertion";

export interface UiMessage {
  readonly key: MessageKey;
  readonly params?: Params;
}

export type ErrorContext =
  | "sign-in"
  | "session"
  | "enrol"
  | "pin"
  | "proof"
  | "totp"
  | "attest"
  | "course-qr"
  | "stock"
  | "handover"
  | "programme"
  | "offers"
  | "sponsorships"
  | "review"
  | "rollups";

/** Code-specific answers of the step-up routes (`partner-session`: pin_*, otp_refused, totp_*). A code is a closed lower-case token (ERROR_CODE_RE), never server prose. */
function messageForCode(kind: string, code: string | null, context: ErrorContext, retryAfterSeconds: number | null): UiMessage | null {
  const wait = (key: MessageKey, waitKey: MessageKey): UiMessage => (retryAfterSeconds !== null ? { key: waitKey, params: { seconds: retryAfterSeconds } } : { key });
  if (context === "pin") {
    if (code === "pin_wrong") return { key: "pin.wrong" };
    if (code === "pin_locked") return { key: "pin.locked" };
    if (code === "pin_backoff") return wait("pin.backoff", "pin.backoff.wait");
    if (code === "pin_already_set") return { key: "pin.alreadySet" };
    if (code === "pin_not_set") return { key: "pin.notSet" };
    if (code === "pin_must_change") return { key: "pin.mustChange" };
  }
  if (context === "proof") {
    if (code === "otp_refused") return { key: "proof.refused" };
    if (code === "otp_unavailable") return { key: "proof.unavailable" };
  }
  if (context === "totp") {
    if (code === "totp_wrong") return { key: "totp.wrong" };
    if (code === "totp_locked") return { key: "totp.locked" };
    if (code === "totp_backoff") return wait("totp.backoff", "totp.backoff.wait");
    if (code === "totp_not_set") return { key: "totp.notSet" };
    if (code === "totp_unconfirmed") return { key: "totp.unconfirmed" };
    if (code === "totp_already_confirmed") return { key: "totp.alreadyConfirmed" };
    if (code === "totp_wrong_session") return { key: "totp.wrongSession" };
  }
  if (context === "enrol") {
    if (kind === "forbidden") return { key: "enrol.refused" };
    if (kind === "gone") return { key: "enrol.expired" };
    if (kind === "conflict") return { key: "enrol.conflict" };
  }
  if (context === "attest") {
    if (code === "self_attestation_refused") return { key: "attest.self" };
    if (code === "token_invalid") return { key: "attest.tokenBad" };
    if (code === "verification_failed") return { key: "attest.verifyFailed" };
    if (code === "replayed") return { key: "attest.replayed" };
    if (code === "no_programme") return { key: "attest.noProgramme" };
    if (code === "cold_start_cap") return { key: "attest.coldStart" };
    if (kind === "conflict") return { key: "attest.replayed" };
    if (kind === "unprocessable") return { key: "attest.verifyFailed" };
  }
  if (context === "course-qr") {
    if (code === "no_programme") return { key: "courseQr.noProgramme" };
    if (code === "not_printed") return { key: "courseQr.notPrinted" };
  }
  if (context === "stock") {
    if (code === "no_stock_row") return { key: "stock.noRow" };
    if (code === "short") return { key: "stock.short" };
    if (code === "over_cap") return { key: "stock.overCap" };
    if (kind === "unprocessable") return { key: "stock.moveFailed" };
  }
  if (context === "handover") {
    if (code === "out_of_stock") return { key: "handover.outOfStock" };
    if (code === "replayed") return { key: "handover.replayed" };
    if (code === "token_invalid") return { key: "handover.tokenInvalid" };
    if (code === "not_redeemable") return { key: "handover.notRedeemable" };
    if (code === "wrong_facility") return { key: "handover.wrongFacility" };
    if (code === "no_stock_row") return { key: "stock.noRow" };
    if (code === "no_programme") return { key: "handover.noProgramme" };
    if (code === "token_exists") return { key: "handover.tokenExists" };
    if (code === "cold_start_cap") return { key: "handover.coldStart" };
    if (kind === "conflict") return { key: "handover.outOfStock" };
    if (kind === "unprocessable") return { key: "handover.failed" };
  }
  if (context === "programme" || context === "offers" || context === "sponsorships" || context === "review" || context === "rollups") {
    if (code === "not_draft") return { key: "admin.notDraft" };
    if (code === "not_live") return { key: "admin.notLive" };
    if (code === "bad_funder") return { key: "admin.badFunder" };
    if (code === "bad_sponsor") return { key: "admin.badSponsor" };
    if (code === "stock_short") return { key: "admin.stockShort" };
    if (code === "budget_short") return { key: "admin.budgetShort" };
    if (code === "no_trail") return { key: "admin.noTrailRow" };
    if (code === "invalid_eligibility") return { key: "admin.invalidEligibility" };
    if (code === "not_held") return { key: "admin.notHeld" };
    if (code === "not_found") return { key: "admin.notFound" };
    if (kind === "unprocessable") return { key: "admin.failed" };
  }
  return null;
}

/** `context`: a 401 means "that sign-in failed" while signing in, and "your session ended" anywhere else; the step-up and enrolment contexts also read the server's closed error code. */
export function messageForError(e: unknown, context: ErrorContext): UiMessage {
  if (e instanceof WebAuthnFailure) {
    switch (e.kind) {
      case "unsupported":
        return { key: "error.webauthnUnsupported" };
      case "cancelled":
        return { key: "error.cancelled" };
      case "bad_options":
        return { key: "error.badOptions" };
      default:
        return { key: "error.webauthnFailed" };
    }
  }
  if (isPartnerApiError(e)) {
    const specific = messageForCode(e.kind, e.code, context, e.retryAfterSeconds);
    if (specific !== null) return specific;
    switch (e.kind) {
      case "unauthenticated":
        return { key: context === "sign-in" ? "error.signInFailed" : "error.sessionEnded" };
      case "forbidden":
      case "reauth_refused":
        return { key: "error.forbidden" };
      case "rate_limited":
        return e.retryAfterSeconds !== null ? { key: "error.rateLimited.wait", params: { seconds: e.retryAfterSeconds } } : { key: "error.rateLimited" };
      case "unavailable":
        return { key: "error.unavailable" };
      case "network":
        return { key: "error.network" };
      default:
        return { key: "error.generic" };
    }
  }
  return { key: "error.generic" };
}

/** Why the page itself refused a PIN (before deriving anything). Closed set: `PinRejection`. */
export function messageForPinRejection(reason: PinRejection): UiMessage {
  return { key: `pin.rejected.${reason}` };
}
