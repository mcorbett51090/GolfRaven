import type { MessageKey, Params } from "../i18n";
import type { ActivationOutcome } from "./outcome";

/** The line an activation outcome gets, with its parameters. EVERY status has one (the `switch` is exhaustive: a new status is a compile error here). `held_review` is
 * "under review", never an error; the idempotent "already" answers say so. */
export function activationMessage(o: ActivationOutcome): { key: MessageKey; params?: Params } {
  switch (o.status) {
    case "activated":
      return { key: o.alreadyActive ? "wallet.activate.outcome.activated.already" : "wallet.activate.outcome.activated" };
    case "held_review":
      return { key: o.alreadyHeld ? "wallet.activate.outcome.held_review.already" : "wallet.activate.outcome.held_review" };
    case "rate_limited": {
      // Three limits, three lines: the activation's own, and (BEFORE the activation was sent) the live challenge's and the key registration's (`outcome.ts`, `source`).
      const minutes = o.retryAfterSeconds === null ? null : Math.max(1, Math.ceil(o.retryAfterSeconds / 60));
      const keys = {
        activation: ["wallet.activate.outcome.rate_limited", "wallet.activate.outcome.rate_limited.later"],
        challenge: ["wallet.activate.outcome.rate_limited.challenge", "wallet.activate.outcome.rate_limited.challenge.later"],
        registration: ["wallet.activate.outcome.rate_limited.registration", "wallet.activate.outcome.rate_limited.registration.later"],
      } as const;
      const [withMinutes, later] = keys[o.source ?? "activation"];
      return minutes === null ? { key: later } : { key: withMinutes, params: { minutes } };
    }
    case "unexpected_state":
      return { key: "wallet.activate.outcome.unexpected_state" };
    case "not_activatable":
      return { key: "wallet.activate.outcome.not_activatable" };
    case "expired":
      return { key: "wallet.activate.outcome.expired" };
    case "conflict":
      return { key: "wallet.activate.outcome.conflict" };
    case "not_found":
      return { key: "wallet.activate.outcome.not_found" };
    case "not_allowed":
      return { key: "wallet.activate.outcome.not_allowed" };
    case "platform_mismatch":
      return { key: "wallet.activate.outcome.platform_mismatch" };
    case "device_limit":
      return { key: "wallet.activate.outcome.device_limit" };
    case "challenge_expired":
      return { key: "wallet.activate.outcome.challenge_expired" };
    case "vendor_unavailable":
      return { key: "wallet.activate.outcome.vendor_unavailable" };
    case "not_available":
      return { key: "wallet.activate.outcome.not_available" };
    case "sign_in_required":
      return { key: "wallet.activate.outcome.sign_in_required" };
    case "signed_out":
      return { key: "wallet.activate.outcome.signed_out" };
    case "rejected":
      return { key: "wallet.activate.outcome.rejected" };
    case "unknown_outcome":
      return { key: "wallet.activate.outcome.unknown_outcome" };
    case "deferred":
      return { key: "wallet.activate.outcome.deferred" };
    case "offline":
      return { key: "wallet.activate.outcome.offline" };
    case "not_configured":
      return { key: "wallet.activate.outcome.not_configured" };
    case "unsupported_platform":
      return { key: "wallet.activate.outcome.unsupported_platform" };
    case "failed":
      return { key: "wallet.activate.outcome.failed" };
  }
}
