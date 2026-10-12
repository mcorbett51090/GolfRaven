import type { MessageKey } from "../i18n";
import type { ReceiptUploadOutcome } from "./outcome";

/** Exhaustive copy for every upload outcome. */
export function receiptOutcomeMessage(o: ReceiptUploadOutcome): { key: MessageKey; params?: Record<string, string | number> } {
  switch (o.status) {
    case "ok":
      return { key: "receipt.outcome.ok" };
    case "duplicate":
      return { key: "receipt.outcome.duplicate" };
    case "review":
      return { key: "receipt.outcome.review" };
    case "disabled":
      return { key: "receipt.outcome.disabled" };
    case "cancelled":
      return { key: "receipt.outcome.cancelled" };
    case "denied":
      return { key: o.canAskAgain ? "receipt.err.denied" : "receipt.err.denied.blocked" };
    case "picker_unavailable":
      return { key: "receipt.err.picker" };
    case "signed_out":
      return { key: "receipt.err.signed_out" };
    case "sign_in_required":
      return { key: "receipt.err.sign_in" };
    case "not_found":
      return { key: "receipt.err.not_found" };
    case "no_programme":
      return { key: "receipt.err.no_programme" };
    case "unsupported_media":
      return { key: "receipt.err.unsupported_media" };
    case "payload_too_large":
      return { key: "receipt.err.payload_too_large" };
    case "forbidden":
      return { key: "receipt.err.forbidden" };
    case "rate_limited":
      return o.retryAfterSeconds !== null && o.retryAfterSeconds > 0
        ? { key: "receipt.err.rate_limited.later", params: { minutes: Math.max(1, Math.ceil(o.retryAfterSeconds / 60)) } }
        : { key: "receipt.err.rate_limited" };
    case "offline":
      return { key: "receipt.err.offline" };
    case "not_configured":
      return { key: "receipt.err.not_configured" };
    case "rejected":
      return { key: "receipt.err.rejected" };
    case "failed":
      return { key: "receipt.err.failed" };
  }
}
