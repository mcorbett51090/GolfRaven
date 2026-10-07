/** Maps a failure to the catalogue key (and parameters) the UI shows. Pure: no DOM, no locale. A message never contains a server string. */

import { isPartnerApiError } from "../api/errors";
import type { MessageKey, Params } from "../i18n";
import { WebAuthnFailure } from "../webauthn/assertion";

export interface UiMessage {
  readonly key: MessageKey;
  readonly params?: Params;
}

/** `context`: a 401 means "that sign-in failed" while signing in, and "your session ended" anywhere else. */
export function messageForError(e: unknown, context: "sign-in" | "session"): UiMessage {
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
