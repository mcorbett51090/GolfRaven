/**
 * Drives the outbox: one `run()` pass takes every due item through the §7.6
 * state machine against the (mock or real) `api.*` evidence endpoint.
 *
 * Crash safety: an item is persisted as `sent` BEFORE the request and the
 * answer is persisted AFTER, so a process killed in between leaves a `sent`
 * item that `recoverInterrupted` returns to `retry`; replaying it is harmless
 * because of the server's unique `source_ref` key.
 */
import {
  applyAnswer,
  beginSend,
  completeRematch,
  isDue,
  isExpiredDeadLetter,
  isStaleSent,
  recoverInterrupted,
  resolveUnlisted,
  type RematchResult,
} from "./machine";
import type { OutboxStore } from "./store";
import type { OutboxItem, ServerAnswer } from "./types";

/** The slice of `api.*` the outbox uses: `POST /v1/evidence`. Never throws
 * for an HTTP outcome; a transport failure is `{ kind: "network_error" }`. */
export interface EvidenceSubmitter {
  submitEvidence(item: OutboxItem): Promise<ServerAnswer>;
}

export interface OutboxRunnerDeps {
  store: OutboxStore;
  api: EvidenceSubmitter;
  now: () => number;
  rng: () => number;
  /** Refresh the signed catalog (422 `catalog_stale` step 1). Called at most
   * once per run, and only if some item needs it. */
  refreshCatalog: () => Promise<void>;
  /** Re-match a stored summary against the CURRENT catalog (step 2). */
  rematch: (item: OutboxItem) => Promise<RematchResult>;
  /** For an "Unlisted course" item: the course id the current catalog now
   * carries for it, or null if it still has none. */
  findCourseForUnlisted: (item: OutboxItem) => Promise<{ courseId: string; catalogVersion: string } | null>;
}

export interface RunReport {
  sent: number;
  accepted: number;
  queued: number;
  retry: number;
  needsAttention: number;
  rematched: number;
  resolvedUnlisted: number;
  recovered: number;
  expired: number;
}

export class OutboxRunner {
  private inFlight: Promise<RunReport> | null = null;

  constructor(private readonly deps: OutboxRunnerDeps) {}

  /** Single-flight: a call made while a pass is running joins it. */
  run(): Promise<RunReport> {
    if (!this.inFlight) {
      this.inFlight = this.pass().finally(() => {
        this.inFlight = null;
      });
    }
    return this.inFlight;
  }

  private async pass(): Promise<RunReport> {
    const { store, api, now, rng } = this.deps;
    const report: RunReport = { sent: 0, accepted: 0, queued: 0, retry: 0, needsAttention: 0, rematched: 0, resolvedUnlisted: 0, recovered: 0, expired: 0 };

    // 1. Housekeeping: 90-day dead-letter expiry, and interrupted sends.
    for (const item of await store.list()) {
      if (isExpiredDeadLetter(item, now())) {
        await store.delete(item.id);
        report.expired += 1;
      } else if (isStaleSent(item, now())) {
        await store.update(recoverInterrupted(item, now()));
        report.recovered += 1;
      }
    }

    // 2. "Unlisted course" items become sendable once a catalog carries the course.
    for (const item of await store.list()) {
      if (item.status === "pending" && item.courseId === null && !item.rematch) {
        const found = await this.deps.findCourseForUnlisted(item);
        if (found) {
          await store.update(resolveUnlisted(item, found.courseId, found.catalogVersion, now()));
          report.resolvedUnlisted += 1;
        }
      }
    }

    // 3. Send everything due, oldest event first. A 422 `catalog_stale`
    //    answer is followed, within the same pass, by one refresh + re-match
    //    + resubmit (§7.6); a second stale answer waits for the next pass so
    //    a misbehaving server cannot make this loop spin.
    let refreshed = false;
    for (const listed of await store.list()) {
      let item = listed;
      for (let round = 0; round < 2; round += 1) {
        if (item.status === "pending" && item.rematch) {
          if (!refreshed) {
            await this.deps.refreshCatalog();
            refreshed = true;
          }
          item = completeRematch(item, await this.deps.rematch(item), now());
          await store.update(item);
          report.rematched += 1;
          if (item.status === "needs_attention") {
            report.needsAttention += 1;
            break;
          }
        }
        if (!isDue(item, now())) break;

        item = beginSend(item, now());
        await store.update(item); // durable BEFORE the request
        report.sent += 1;
        const answer = await api.submitEvidence(item).catch(
          (err: unknown): ServerAnswer => ({ kind: "network_error", message: err instanceof Error ? err.message : String(err) }),
        );
        item = applyAnswer(item, answer, now(), rng);
        await store.update(item);

        if (item.status === "accepted") report.accepted += 1;
        else if (item.status === "queued") report.queued += 1;
        else if (item.status === "retry") report.retry += 1;
        else if (item.status === "needs_attention") report.needsAttention += 1;
        if (!(item.status === "pending" && item.rematch)) break;
      }
    }
    return report;
  }
}
