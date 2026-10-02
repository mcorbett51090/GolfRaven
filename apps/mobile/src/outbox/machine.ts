/**
 * The §7.6 outbox state machine, PURE: every function takes an item and
 * returns a new one (or throws `InvalidTransition`); time and randomness are
 * arguments. Persistence lives behind `OutboxStore` (`store.ts`), the
 * orchestration in `runner.ts`.
 *
 * | Server answer (§7.6)                       | Outbox action                                   |
 * |--------------------------------------------|-------------------------------------------------|
 * | `201` / `409 duplicate`                    | `accepted`                                      |
 * | `202 queued_catalog`                       | `queued`                                        |
 * | `422 catalog_stale`                        | `pending` + `rematch`: refresh, re-match, resubmit |
 * | `429` / `5xx` / network                    | `retry`: exponential backoff + jitter, Retry-After |
 * | any other 4xx, or re-match fails           | `needs_attention` (dead letter kept 90 days)    |
 *
 * Interpretation notes (the spec table is exhaustive only for the rows
 * above; these are the judgement calls, each one conservative):
 *  - `409` WITHOUT `code: "duplicate"` is "any other 4xx", not `accepted`.
 *  - `202` WITHOUT `code: "queued_catalog"` and any other 2xx/3xx are
 *    `needs_attention` (`unexpected_status`): a state the contract does not
 *    define must be visible, never silently treated as success.
 *  - `401`/`403` are "any other 4xx" and therefore dead-letter. The token
 *    refresh that should make a `401` unreachable is the P4.2 auth client's
 *    job (§7.8 "unauthenticated body is a final 4xx"); this slice does not
 *    pretend to cover it. `[owner/P4.2 decision if a 401 should instead retry]`
 *  - `408` is "any other 4xx" (the spec lists only 429/5xx/network as retry).
 */
import type { NeedsAttentionReason, NewOutboxItem, OutboxItem, OutboxStatus, ServerAnswer } from "./types";

export const OUTBOX_POLICY = {
  /** First retry delay before jitter. */
  backoffBaseMs: 15_000,
  backoffFactor: 2,
  /** Ceiling of the exponential part, before jitter. */
  backoffCapMs: 60 * 60_000,
  /** A server `Retry-After` is honoured up to this ceiling (a hostile or
   * buggy header must not park an item for a year). */
  retryAfterCapMs: 24 * 60 * 60_000,
  /** §7.6: "Waiting to sync" is shown after 24 h of not being accepted. */
  waitingToSyncAfterMs: 24 * 60 * 60_000,
  /** §7.6: a dead letter is kept 90 days. */
  deadLetterRetentionMs: 90 * 24 * 60 * 60_000,
  /** A `sent` item with no recorded answer this long after is presumed
   * interrupted (process killed mid-request) and returns to `retry`. */
  sentStaleMs: 2 * 60_000,
} as const;

export class InvalidTransition extends Error {
  constructor(from: OutboxStatus, action: string) {
    super(`outbox: cannot ${action} an item in state "${from}"`);
  }
}

function assertStatus(item: OutboxItem, action: string, ...allowed: OutboxStatus[]): void {
  if (!allowed.includes(item.status)) throw new InvalidTransition(item.status, action);
}

export function createItem(draft: NewOutboxItem, now: number): OutboxItem {
  return {
    id: draft.id,
    sourceRef: draft.sourceRef,
    courseId: draft.courseId,
    catalogVersion: draft.catalogVersion,
    payload: draft.payload,
    status: "pending",
    createdAt: now,
    updatedAt: now,
    attempts: 0,
    nextAttemptAt: null,
    rematch: false,
    lastHttpStatus: null,
    lastServerCode: null,
    reason: null,
    reported: false,
    deadLetteredAt: null,
  };
}

/** An item the runner may send now. An item with no course id is NEVER
 * sendable (§7.6 "Unlisted course … is not sent until a catalog carrying
 * that course arrives"). */
export function isDue(item: OutboxItem, now: number): boolean {
  if (item.status !== "pending" && item.status !== "retry") return false;
  if (item.courseId === null) return false;
  return item.nextAttemptAt === null || item.nextAttemptAt <= now;
}

export function beginSend(item: OutboxItem, now: number): OutboxItem {
  assertStatus(item, "send", "pending", "retry");
  if (item.courseId === null) throw new InvalidTransition(item.status, "send an unlisted-course item");
  if (item.rematch) throw new InvalidTransition(item.status, "send before re-matching");
  return { ...item, status: "sent", attempts: item.attempts + 1, nextAttemptAt: null, updatedAt: now };
}

/** Full-jitter-ish exponential backoff: the delay is uniform in
 * [d/2, d] where d = min(cap, base * factor^(attempt-1)); a server
 * `Retry-After` is a floor on the result (capped). */
export function retryDelayMs(attempt: number, rng: () => number, retryAfterSeconds?: number): number {
  const p = OUTBOX_POLICY;
  const exp = Math.min(p.backoffCapMs, p.backoffBaseMs * p.backoffFactor ** Math.max(0, attempt - 1));
  const jittered = Math.floor(exp / 2 + rng() * (exp / 2));
  const retryAfter =
    retryAfterSeconds !== undefined && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
      ? Math.min(p.retryAfterCapMs, Math.ceil(retryAfterSeconds * 1000))
      : 0;
  return Math.max(jittered, retryAfter);
}

type Classified =
  | { to: "accepted" }
  | { to: "queued" }
  | { to: "rematch" }
  | { to: "retry"; retryAfterSeconds?: number | undefined }
  | { to: "needs_attention"; reason: NeedsAttentionReason };

export function classifyAnswer(answer: ServerAnswer): Classified {
  if (answer.kind === "network_error") return { to: "retry" };
  const { status, code } = answer;
  if (status === 201) return { to: "accepted" };
  if (status === 409 && code === "duplicate") return { to: "accepted" };
  if (status === 202 && code === "queued_catalog") return { to: "queued" };
  if (status === 422 && code === "catalog_stale") return { to: "rematch" };
  if (status === 429 || (status >= 500 && status <= 599)) return { to: "retry", retryAfterSeconds: answer.retryAfterSeconds };
  if (status >= 400 && status <= 499) return { to: "needs_attention", reason: "rejected" };
  return { to: "needs_attention", reason: "unexpected_status" };
}

function toNeedsAttention(item: OutboxItem, reason: NeedsAttentionReason, now: number): OutboxItem {
  return { ...item, status: "needs_attention", reason, rematch: false, nextAttemptAt: null, deadLetteredAt: now, updatedAt: now };
}

/** Records the server's answer for a `sent` item. */
export function applyAnswer(item: OutboxItem, answer: ServerAnswer, now: number, rng: () => number): OutboxItem {
  assertStatus(item, "answer", "sent");
  const base: OutboxItem = {
    ...item,
    lastHttpStatus: answer.kind === "response" ? answer.status : null,
    lastServerCode: answer.kind === "response" ? (answer.code ?? null) : null,
    updatedAt: now,
  };
  const c = classifyAnswer(answer);
  switch (c.to) {
    case "accepted":
      return { ...base, status: "accepted", rematch: false, nextAttemptAt: null, reason: null };
    case "queued":
      return { ...base, status: "queued", rematch: false, nextAttemptAt: null, reason: null };
    case "rematch":
      // Nothing is shown unless the re-match fails; the item goes back to
      // `pending`, due immediately, flagged for the runner to re-match.
      return { ...base, status: "pending", rematch: true, nextAttemptAt: null, reason: null };
    case "retry":
      return { ...base, status: "retry", rematch: false, nextAttemptAt: now + retryDelayMs(item.attempts, rng, c.retryAfterSeconds), reason: null };
    case "needs_attention":
      return toNeedsAttention(base, c.reason, now);
  }
}

/** The result of re-matching a stored summary against the refreshed catalog. */
export type RematchResult =
  | { ok: true; courseId: string | null; catalogVersion: string; payload: OutboxItem["payload"] }
  | { ok: false };

/** Applies a re-match to a `pending` item flagged `rematch`. A re-match that
 * resolves to NO course is not a failure: the item becomes an unlisted-course
 * item and waits (§7.6, G3-01). Only a summary that can no longer be
 * re-matched at all dead-letters. */
export function completeRematch(item: OutboxItem, result: RematchResult, now: number): OutboxItem {
  assertStatus(item, "complete a re-match of", "pending");
  if (!item.rematch) throw new InvalidTransition(item.status, "complete a re-match that was not requested for");
  if (!result.ok) return toNeedsAttention(item, "rematch_failed", now);
  return { ...item, courseId: result.courseId, catalogVersion: result.catalogVersion, payload: result.payload, rematch: false, nextAttemptAt: null, updatedAt: now };
}

/** A catalog carrying the course has arrived for an "Unlisted course" item:
 * it re-matches and becomes sendable like any other (G3-01). */
export function resolveUnlisted(item: OutboxItem, courseId: string, catalogVersion: string, now: number): OutboxItem {
  assertStatus(item, "resolve", "pending");
  if (item.courseId !== null) throw new InvalidTransition(item.status, "resolve an already-listed item");
  return { ...item, courseId, catalogVersion, nextAttemptAt: null, updatedAt: now };
}

/** The process died between `sent` and the answer. Replaying is harmless
 * (`unique(user_id, source, source_ref)`), so the item simply retries. */
export function isStaleSent(item: OutboxItem, now: number): boolean {
  return item.status === "sent" && now - item.updatedAt >= OUTBOX_POLICY.sentStaleMs;
}
export function recoverInterrupted(item: OutboxItem, now: number): OutboxItem {
  assertStatus(item, "recover", "sent");
  return { ...item, status: "retry", nextAttemptAt: now, updatedAt: now };
}

/** The server resolved a `queued_catalog` item (observed through the
 * player's plays view / a status refresh — the device does not poll
 * `/v1/evidence`). `queue_expired` = unresolved after 7 days (§3.3). */
export function resolveQueued(item: OutboxItem, outcome: "accepted" | "queue_expired", now: number): OutboxItem {
  assertStatus(item, "resolve", "queued");
  return outcome === "accepted"
    ? { ...item, status: "accepted", updatedAt: now }
    : toNeedsAttention(item, "queue_expired", now);
}

/** "Report a problem" on a dead letter: attaches the summary to a
 * `review_item` (server side); locally, just remembered so it is not
 * offered twice. */
export function markReported(item: OutboxItem, now: number): OutboxItem {
  assertStatus(item, "report", "needs_attention");
  return item.reported ? item : { ...item, reported: true, updatedAt: now };
}

export function isExpiredDeadLetter(item: OutboxItem, now: number): boolean {
  return item.status === "needs_attention" && item.deadLetteredAt !== null && now - item.deadLetteredAt >= OUTBOX_POLICY.deadLetterRetentionMs;
}

/** What the player sees in Played for an item (§7.6 right-hand column).
 * `null` copy = shown as an ordinary entry with no status line. */
export type PlayedStatusKey =
  | "accepted" // "the play"
  | "queued" // "Syncing — new course data on its way"
  | "waiting_to_sync" // "Waiting to sync" (retry, after 24 h)
  | "unlisted_course" // §7.4 "Unlisted course", pending a catalog
  | "needs_attention" // a card with the reason and "Report a problem"
  | "saving"; // pending / sent / early retry: in flight, nothing alarming

export function playedStatus(item: OutboxItem, now: number): PlayedStatusKey {
  switch (item.status) {
    case "accepted":
      return "accepted";
    case "queued":
      return "queued";
    case "needs_attention":
      return "needs_attention";
    case "retry":
      return now - item.createdAt >= OUTBOX_POLICY.waitingToSyncAfterMs ? "waiting_to_sync" : "saving";
    case "pending":
      return item.courseId === null ? "unlisted_course" : "saving";
    case "sent":
      return "saving";
  }
}
