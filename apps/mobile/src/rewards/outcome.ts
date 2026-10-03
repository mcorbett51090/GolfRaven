/**
 * What a reward activation ended in, as the Wallet shows it (build plan §7.5; the server is `supabase/functions/_shared/rewards/activate-handler.ts`). EVERY answer the handler (and the
 * entrypoint around it) can give is mapped here, explicitly; nothing falls into a generic "error" that hides what the player can do about it:
 *
 * | server answer                                                        | outcome                  | the player sees                                   |
 * |----------------------------------------------------------------------|--------------------------|---------------------------------------------------|
 * | 200 `issued` / `redeemable`, `replay: false`                         | `activated`              | "Activated"                                       |
 * | 200 `issued` / `redeemable`, `replay: true` (already active here)    | `activated` + `alreadyActive` | "Already activated" (idempotent, NOT an error) |
 * | 200 `held_review` (any `replay`)                                     | `held_review`            | "Under review" (a person looks at it; NOT an error) |
 * | 200 any other state                                                  | `unexpected_state`       | "Refresh and look again"                          |
 * | 409 `reward_not_activatable` (redeemed, void, vouchered, ...)        | `not_activatable`        | "Can no longer be activated"                      |
 * | 409 `reward_expired`                                                 | `expired`                | "Expired"                                         |
 * | any other 409                                                        | `conflict`               | "Changed: refresh"                                |
 * | 404 (unknown id, or not the caller's: the same answer)               | `not_found`              | "Not found"                                       |
 * | 403 (the app-review demo account)                                    | `not_allowed`            | "This account can't activate rewards"             |
 * | 422 `platform_mismatch`                                              | `platform_mismatch`      | "This device is registered under another platform" |
 * | 422 `device_limit_exceeded`                                          | `device_limit`           | "Too many devices on this account"                |
 * | 422 `challenge_not_consumable` (a live challenge lasts 120 s)        | `challenge_expired`      | "Took too long: try again"                        |
 * | 429 (10 an hour per account, 20 a day per device)                    | `rate_limited`           | "Try again in N minutes"                          |
 * | 503 `attestation_unavailable` (Apple / Google unreachable)           | `vendor_unavailable`     | "Try again later" (nothing changed)               |
 * | 503 `attestation_not_configured`, 501                                | `not_available`          | "Activation isn't available right now"            |
 * | 401, or no session / no token                                        | `sign_in_required`       | "Sign in again"                                   |
 * | 400 and any other 4xx                                                | `rejected`               | "Couldn't activate" (a client / server mismatch)  |
 * | network, 5xx, 502 / 504, a 2xx that could not be read (AFTER a send) | `unknown_outcome`        | "Couldn't confirm: try again" (a retry is safe)   |
 * | the client could not produce the attestation now (local)             | `deferred`               | "Try again in a moment" (nothing was sent)        |
 * | no token could be fetched / no network before anything was sent      | `offline`                | "No connection"                                   |
 * | this build has no API                                                | `not_configured`         | "Not available in this build"                     |
 * | not iOS / Android                                                    | `unsupported_platform`   | "Needs a phone"                                   |
 *
 * Two corrections to the task's wording, both found in the handler: (1) the idempotent "already activated" answer is a 200 with `replay: true`, not a 409 (`handleActivation` step 2: "a held
 * reward waits for a human", "already active on THIS device"); a 409 means the reward can no longer be activated. (2) The answer carries NO attestation grade: `held_review` may come from the
 * bits, the account, or the grade, and the client cannot tell which, so it is never shown as a failure of the device.
 */
import { isApiError } from "../api/errors";
import type { ActivationAnswer, RewardKind } from "../api/types";
import { ActivationUnsupportedPlatform } from "../attest/activator";
import { AttestationDeferred } from "../attest/redeemer";

export type ActivationOutcome =
  | { status: "activated"; kind: RewardKind; state: "issued" | "redeemable"; alreadyActive: boolean }
  | { status: "held_review"; kind: RewardKind; alreadyHeld: boolean }
  | { status: "unexpected_state"; state: string }
  | { status: "not_activatable" }
  | { status: "expired" }
  | { status: "conflict" }
  | { status: "not_found" }
  | { status: "not_allowed" }
  | { status: "platform_mismatch" }
  | { status: "device_limit" }
  | { status: "challenge_expired" }
  | { status: "rate_limited"; retryAfterSeconds: number | null }
  | { status: "vendor_unavailable" }
  | { status: "not_available" }
  | { status: "sign_in_required" }
  | { status: "signed_out" }
  | { status: "rejected"; code: string | null }
  | { status: "unknown_outcome" }
  | { status: "deferred"; reason: string }
  | { status: "offline" }
  | { status: "not_configured" }
  | { status: "unsupported_platform" }
  | { status: "failed" };

export type ActivationOutcomeStatus = ActivationOutcome["status"];

/** The statuses worth offering "try again" for: nothing was changed, or a retry is safe at the server (`replay: true`). */
const RETRYABLE: ReadonlySet<ActivationOutcomeStatus> = new Set(["challenge_expired", "rate_limited", "vendor_unavailable", "unknown_outcome", "deferred", "offline", "unexpected_state", "conflict"]);
export const isRetryableActivation = (o: ActivationOutcome): boolean => RETRYABLE.has(o.status);

/** A 200 answer. `held` is the server's word; the two active states are `issued` (an offer code) and `redeemable` (a special marker). */
export function outcomeFromAnswer(a: ActivationAnswer): ActivationOutcome {
  if (a.held || a.state === "held_review") return { status: "held_review", kind: a.kind, alreadyHeld: a.replay };
  if (a.state === "issued" || a.state === "redeemable") return { status: "activated", kind: a.kind, state: a.state, alreadyActive: a.replay };
  return { status: "unexpected_state", state: a.state };
}

/** A thrown error, from the activator (a local failure, nothing sent) or the API client (an `ApiError`). */
export function outcomeFromError(e: unknown): ActivationOutcome {
  if (e instanceof AttestationDeferred) return { status: "deferred", reason: e.reason };
  if (e instanceof ActivationUnsupportedPlatform) return { status: "unsupported_platform" };
  if (!isApiError(e)) return { status: "failed" };
  switch (e.kind) {
    case "unauthenticated":
      return { status: "sign_in_required" };
    case "forbidden":
      return { status: "not_allowed" };
    case "not_found":
      return { status: "not_found" };
    case "conflict":
      return e.code === "reward_not_activatable" ? { status: "not_activatable" } : e.code === "reward_expired" ? { status: "expired" } : { status: "conflict" };
    case "rate_limited":
      return { status: "rate_limited", retryAfterSeconds: e.retryAfterSeconds };
    case "not_supported":
      return { status: "not_available" };
    case "unavailable":
      if (e.status === 503 && e.code === "attestation_unavailable") return { status: "vendor_unavailable" };
      if (e.status === 503 && e.code === "attestation_not_configured") return { status: "not_available" };
      return { status: "unknown_outcome" }; // a gateway's 502 / 504, or a bare 503: the request may have been applied
    case "server":
    case "network":
    case "bad_response":
      return { status: "unknown_outcome" };
    case "not_configured":
      return { status: "not_configured" };
    case "rejected":
      if (e.status === 422 && e.code === "platform_mismatch") return { status: "platform_mismatch" };
      if (e.status === 422 && e.code === "device_limit_exceeded") return { status: "device_limit" };
      if (e.status === 422 && e.code === "challenge_not_consumable") return { status: "challenge_expired" };
      return { status: "rejected", code: e.code };
  }
}
