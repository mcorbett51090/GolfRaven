// supabase/functions/_shared/evidence/batch-handler.ts
//
// Pure(ish), DI'd core of the `evidence-batch` Edge Function (`POST
// /v1/evidence/batch`, build plan §4.7.1a inventory: "evidence-batch").
// Extracted from `evidence-batch/index.ts` (P3d should-fix 1) so it can
// be exercised directly by an integration test — the SAME "pure,
// dependency-injected modules unit-testable without a live Supabase"
// discipline `evidence/handler.ts`/`checkin/*.ts` already follow.
//
// Runs each item through the same pure `handleEvidenceIntake` core as a
// single `POST /v1/evidence` call, catching a per-item failure (security
// doc §3: "Catch scorer exceptions per play, so one bad row cannot block
// a re-score batch") — one bad item in a batch never fails the others.
//
// P3c gate round 2, should-fix "batch limits":
//   - the daily cap is counted PER ITEM (one `hitRateLimitForActor` call
//     per item, not once per whole request).
//   - each item explicitly skips the LIVE rate-limit bucket
//     (`skipLiveRateLimit`) — historic/batch import must not compete
//     with real-time submissions for the same budget.
//
// ⛔ FIX (P3c gate round 3, blocking MEDIUM 4: "one failing item aborts
// the whole transaction"). `withOwnershipBatch` (privileged.ts): each
// item runs inside its OWN `trx.savepoint(...)` of the same outer
// transaction.
//
// ⛔ FIX (P3c gate round 4, blocking HIGH: "5 concurrent requests
// deadlock the pool"). Rate-limiting is a SEPARATE, PRE-TRANSACTION phase
// (phase 1 below), never from inside `withOwnershipBatch`.
//
// ⛔ FIX (P3d should-fix 1, "score each play once per batch, after all
// items for that play, instead of once per item — rescoring is O(n^2)
// and held the advisory lock for over 15s").
//
// ⛔ REWRITE, same should-fix (found by THIS round's own new test — "an
// identical item submitted TWICE in one batch"): the FIRST version of
// this fix picked ONE item per (courseId, localDate) group — the group's
// LAST member, by original request order — to run the real scoring tail
// (`deferScoring: false`) while every earlier member deferred. That
// assumed the last item would always be a GENUINELY NEW submission. It
// broke the moment the last item was itself a byte-for-byte REPLAY of an
// EARLIER group member: a replay never reaches the scoring tail at all
// (`handleEvidenceIntake`'s replay check returns early, before
// `deferScoring` is ever consulted) — `deferScoring: false` on a replay
// item is simply ignored, so NOTHING in the group ever actually scored.
//
// THIS version never relies on any ONE item to trigger scoring. EVERY
// ready item runs with `deferScoring: true` (always insert-only — a
// replay of a not-yet-scored sibling now defers too, via
// `handler.ts#buildReplayResult`'s own `batchMode` branch, rather than
// failing closed on "no play row found yet"). A SEPARATE, DEDICATED
// finalization pass then runs `finalizeScoringForKey` exactly ONCE per
// DISTINCT group — its own savepoint, decoupled from any specific item —
// using ONLY already-persisted rows (`handler.ts`'s own
// `reconstructEvidenceFromStoredRows`, the same one the replay path
// already trusts). Every item in a group (deferred either way) is then
// backfilled with that group's single, shared `play` outcome. A group of
// size 1 (the common case — most batches don't repeat a play) still does
// exactly one insert savepoint + one finalize savepoint, matching what a
// single, un-batched submission already does.

import { hitRateLimitForActor, withOwnershipBatch } from "../privileged.ts";
import { HttpError } from "../http.ts";
import { finalizeScoringForKey, handleEvidenceIntake, planEvidenceRateLimitChecks, type EvidenceIntakeSuccess } from "./handler.ts";
import type { Actor } from "../types.ts";
import type { Repo } from "../types.ts";

export const MAX_BATCH_ITEMS_PER_REQUEST = 100;
export const RATE_LIMIT_PER_USER_DAY = 2000;

export interface ItemResult {
  index: number;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string };
}

function toErrorResult(index: number, err: unknown): ItemResult {
  if (err instanceof HttpError) return { index, ok: false, error: { code: err.code, message: err.message } };
  console.error(`evidence-batch: item ${index} failed unexpectedly`, err);
  return { index, ok: false, error: { code: "internal_error", message: "internal error" } };
}

export async function handleEvidenceBatchIntake(actor: Actor, items: unknown[]): Promise<{ results: ItemResult[] }> {
  // ---- Phase 1: pre-transaction rate limiting, for EVERY item, in
  // order — no transaction open at all yet. ----
  const results: ItemResult[] = new Array(items.length);
  const readyIndices: number[] = [];
  for (let i = 0; i < items.length; i++) {
    // The daily batch cap is hit FIRST, unconditionally, per item slot —
    // even a structurally-invalid item still consumes one unit of it.
    const batchRateLimit = await hitRateLimitForActor(actor, `evidence-batch:user`, 86400, RATE_LIMIT_PER_USER_DAY);
    if (!batchRateLimit.ok) {
      results[i] = { index: i, ok: false, error: { code: "rate_limited", message: "evidence-batch daily rate limit exceeded" } };
      continue;
    }
    let planned: ReturnType<typeof planEvidenceRateLimitChecks>;
    try {
      planned = planEvidenceRateLimitChecks(items[i], { skipLiveRateLimit: true });
    } catch (err) {
      results[i] = toErrorResult(i, err);
      continue;
    }
    let deviceRateLimitOk = true;
    for (const check of planned.checks) {
      const r = await hitRateLimitForActor(actor, check.bucketKey, check.windowSeconds, check.max);
      if (!r.ok) {
        deviceRateLimitOk = false;
        break;
      }
    }
    if (!deviceRateLimitOk) {
      results[i] = { index: i, ok: false, error: { code: "rate_limited", message: "evidence rate limit exceeded for this device" } };
      continue;
    }
    readyIndices.push(i);
  }

  if (readyIndices.length === 0) return { results };

  // ---- Phase 2: transactional work — one outer transaction. Every
  // ready item gets its own savepoint (P3c gate round 3, blocking MEDIUM
  // 4), ALWAYS deferring its own scoring (P3d should-fix 1, rewritten —
  // see this file's own header for why no item is ever relied on to
  // trigger scoring itself). A SECOND set of savepoints — one per
  // DISTINCT (facilityId, courseId, localDate) group actually produced —
  // runs immediately after, each calling `finalizeScoringForKey` exactly
  // once. `withOwnershipBatch`'s own `itemCount` covers BOTH passes
  // (items first, then finalize steps), so both stay inside the SAME
  // outer transaction/timeout budget. The number of finalize steps isn't
  // known until phase-2a's own results are in (a course/date pair only
  // becomes a "group" once resolved, inside the transaction) — so this
  // runs phase 2a and 2b as two SEPARATE `withOwnershipBatch` calls
  // rather than one. That does mean a phase-2b failure cannot roll back
  // phase-2a's own (separately committed) transaction — accepted
  // deliberately: each item's own insert is already independently
  // idempotent (a later retry/resubmission finds its row via
  // `findExisting` and replays cleanly, never double-inserts), so a
  // finalize-step failure leaves, at worst, evidence rows temporarily
  // unscored — recoverable by the client's own natural retry (which
  // hits the SAME idempotent path and defers again, into a FRESH
  // finalize attempt), never data loss or a double-count.
  const itemOutcomes = await withOwnershipBatch(actor, readyIndices.length, async (repo, j) => {
    const i = readyIndices[j];
    return handleEvidenceIntake(items[i], repo, { deferScoring: true, batchMode: true });
  });

  // Group DEFERRED items by their (facilityId, courseId, localDate) —
  // both ids ALREADY RESOLVED (survivor) ids, straight from the deferred
  // result itself (see `finalizeScoringForKey`'s own doc for why no
  // re-resolution is needed).
  const groupKeyOf = (facilityId: string, courseId: string, localDate: string) => `${facilityId}\u0000${courseId}\u0000${localDate}`;
  interface PendingGroup {
    facilityId: string;
    courseId: string;
    localDate: string;
    // (item index, that item's OWN evidenceId/replay flag) — both
    // differ per member even though they share one final play: a
    // replayed member must keep reporting `replay: true` to ITS OWN
    // caller, even though the actual scoring happened via the shared
    // finalize step, not by re-deriving anything from this member a
    // second time (handler.ts's own `EvidenceIntakeDeferred` doc).
    members: Array<{ index: number; evidenceId: string; replay: boolean }>;
  }
  const groups = new Map<string, PendingGroup>();
  for (let j = 0; j < readyIndices.length; j++) {
    const i = readyIndices[j];
    const outcome = itemOutcomes[j];
    if (!outcome.ok) {
      results[i] = toErrorResult(i, outcome.error);
      continue;
    }
    const value = outcome.value;
    if (value.status !== "deferred") {
      results[i] = { index: i, ok: true, result: value };
      continue;
    }
    const key = groupKeyOf(value.facilityId, value.courseId, value.localDate);
    let group = groups.get(key);
    if (!group) {
      group = { facilityId: value.facilityId, courseId: value.courseId, localDate: value.localDate, members: [] };
      groups.set(key, group);
    }
    group.members.push({ index: i, evidenceId: value.evidenceId, replay: value.replay });
  }

  if (groups.size > 0) {
    const groupList = [...groups.values()];
    const finalizeOutcomes = await withOwnershipBatch(actor, groupList.length, async (repo: Repo, k) => {
      const g = groupList[k];
      return finalizeScoringForKey(repo, g.facilityId, g.courseId, g.localDate);
    });
    for (let k = 0; k < groupList.length; k++) {
      const g = groupList[k];
      const outcome = finalizeOutcomes[k];
      for (const member of g.members) {
        if (!outcome.ok) {
          // Every member of this group already has its OWN evidence row
          // safely committed (phase 2a's own, already-closed savepoints)
          // — only the SCORING failed. Reported the same way a
          // same-cause SINGLE submission's own scoring failure already
          // would be (handler.ts's own tail: "our own row assembly...
          // not a client attack"): an internal error, never silently
          // "accepted" with no play. A later resubmission/rescore still
          // picks every row up.
          results[member.index] = toErrorResult(member.index, outcome.error);
          continue;
        }
        const value: EvidenceIntakeSuccess = { status: "accepted", evidenceId: member.evidenceId, replay: member.replay, play: outcome.value.play };
        results[member.index] = { index: member.index, ok: true, result: value };
      }
    }
  }

  return { results };
}
