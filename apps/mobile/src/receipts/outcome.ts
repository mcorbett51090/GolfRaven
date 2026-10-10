/**
 * What a receipt upload ended in, as the facility card shows it (P5 §40 / §50).
 * Never throws; maps every `ApiError` kind the wire test covers.
 */
import { isApiError } from "../api/errors";
import type { ReceiptUploadResult } from "../api/types";

export type ReceiptUploadOutcome =
  | { status: "ok"; localDate: string | null; purchaseCount: number }
  | { status: "duplicate"; localDate: string | null }
  | { status: "review"; localDate: string | null }
  | { status: "disabled" }
  | { status: "cancelled" }
  | { status: "denied"; canAskAgain: boolean }
  | { status: "picker_unavailable" }
  | { status: "signed_out" }
  | { status: "sign_in_required" }
  | { status: "not_found" }
  | { status: "no_programme" }
  | { status: "unsupported_media" }
  | { status: "payload_too_large" }
  | { status: "forbidden" }
  | { status: "rate_limited"; retryAfterSeconds: number | null }
  | { status: "offline" }
  | { status: "not_configured" }
  | { status: "rejected"; code: string | null }
  | { status: "failed" };

export function outcomeFromAnswer(a: ReceiptUploadResult): ReceiptUploadOutcome {
  if (a.status === "duplicate") return { status: "duplicate", localDate: a.localDate };
  if (a.status === "review") return { status: "review", localDate: a.localDate };
  return { status: "ok", localDate: a.localDate, purchaseCount: a.purchases.length };
}

export function outcomeFromError(e: unknown): ReceiptUploadOutcome {
  if (!isApiError(e)) return { status: "failed" };
  switch (e.kind) {
    case "unauthenticated":
      return { status: "sign_in_required" };
    case "forbidden":
      return { status: "forbidden" };
    case "not_found":
      return { status: "not_found" };
    case "rate_limited":
      return { status: "rate_limited", retryAfterSeconds: e.retryAfterSeconds };
    case "network":
      return { status: "offline" };
    case "not_configured":
      return { status: "not_configured" };
    case "rejected":
      if (e.code === "no_programme") return { status: "no_programme" };
      if (e.code === "unsupported_media_type" || e.status === 415) return { status: "unsupported_media" };
      if (e.code === "payload_too_large" || e.status === 413) return { status: "payload_too_large" };
      return { status: "rejected", code: e.code };
    default:
      return { status: "failed" };
  }
}

export function needsSettings(o: ReceiptUploadOutcome): boolean {
  return o.status === "denied" && !o.canAskAgain;
}
