/**
 * The evidence outbox's data model (build plan §7.6 "Offline behaviour").
 *
 * The outbox is APPEND-ONLY with an idempotent `source_ref`: an item is
 * identified by `sourceRef` for life, replays are harmless because the
 * server's `unique(user_id, source, source_ref)` dedupes them (§3.3), and no
 * item is ever dropped silently (FM-03) — the only ways an item leaves the
 * outbox are `accepted` (kept as the player's record) and the 90-day expiry
 * of an already-visible `needs_attention` dead letter.
 */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/** `pending → sent → accepted | queued | retry | needs_attention` (§7.6). */
export const OUTBOX_STATUSES = ["pending", "sent", "accepted", "queued", "retry", "needs_attention"] as const;
export type OutboxStatus = (typeof OUTBOX_STATUSES)[number];

/** Why an item is in `needs_attention`. Machine codes; the UI maps them to
 * copy. Never lose the server's own code: it is what "Report a problem"
 * attaches to the `review_item`. */
export type NeedsAttentionReason =
  | "rejected" // any other 4xx
  | "unexpected_status" // a status the contract does not define for this call
  | "rematch_failed" // 422 catalog_stale, and the stored summary no longer matches the new catalog
  | "queue_expired" // queued_catalog unresolved after 7 days (server-side decision, mirrored)
  | "unsendable" // the stored payload cannot be turned into a request (a local defect: nothing was sent)
  | "owner_unknown"; // a row from before P4.2b-0: it has no owner, so it can never be sent (`db/sql.ts` v2)

/** The owner stored on a row that predates owner binding (`db/sql.ts` v2). It is the empty string, which is never a user id, so no signed-in
 * user ever matches it: such a row is neither sent nor shown. */
export const UNOWNED = "";

export interface OutboxItem {
  /** Local id (uuid). */
  readonly id: string;
  /** The idempotency key. UNIQUE per owner (the server's key is `(user_id, source, source_ref)`); never changes. */
  readonly sourceRef: string;
  /** The Supabase user (`auth.users.id`) whose session created the item. Set once, from the auth session and never from a screen
   * (`enqueueOutboxItem`); only that user's session may send or see the item. Immutable. */
  readonly ownerUserId: string;
  /** `null` = "Unlisted course" (§7.4): stays `pending`, never sent, until a
   * catalog carrying that course arrives (G3-01). */
  courseId: string | null;
  /** The `catalogVersion` the stored summary was matched against. */
  catalogVersion: string | null;
  /** The stored `MatchSummary` (kept so 422 `catalog_stale` can re-match it). */
  payload: JsonValue;
  status: OutboxStatus;
  readonly createdAt: number;
  updatedAt: number;
  /** Sends attempted (a crash between `sent` and the answer counts). */
  attempts: number;
  /** When a `retry` (or a deferred `pending`) next becomes due; null = now. */
  nextAttemptAt: number | null;
  /** 422 `catalog_stale`: refresh the catalog, re-match the stored summary, resubmit. */
  rematch: boolean;
  lastHttpStatus: number | null;
  /** The server's error `code`, verbatim, if it sent one. */
  lastServerCode: string | null;
  reason: NeedsAttentionReason | null;
  /** The player tapped "Report a problem" (attaches the summary to a `review_item`). */
  reported: boolean;
  /** Set when the item entered `needs_attention`; starts the 90-day clock. */
  deadLetteredAt: number | null;
}

/** What one send attempt produced. `payload`, when present, REPLACES the item's stored payload together with the answer (the send step records
 * what it learned, e.g. the check-in token it redeemed, `evidence/send.ts`); absent = unchanged. */
export type ServerAnswer =
  | { kind: "response"; status: number; code?: string | undefined; retryAfterSeconds?: number | undefined; payload?: JsonValue | undefined }
  | { kind: "network_error"; message?: string | undefined; payload?: JsonValue | undefined }
  /** The item itself cannot be sent (its payload is not a valid evidence submission): no request was made. It is a dead letter, never a retry. */
  | { kind: "unsendable"; code: string; message?: string | undefined };

export interface NewOutboxItem {
  id: string;
  sourceRef: string;
  /** Non-empty. Callers outside the outbox module never choose it: `enqueueOutboxItem` takes it from the auth session. */
  ownerUserId: string;
  courseId: string | null;
  catalogVersion: string | null;
  payload: JsonValue;
}
