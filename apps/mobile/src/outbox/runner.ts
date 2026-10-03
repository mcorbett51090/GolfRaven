/**
 * Drives the outbox: one `run()` pass takes every due item through the §7.6
 * state machine against the (mock or real) `api.*` evidence endpoint.
 *
 * OWNERSHIP (P4.2b-0). Every item belongs to the user whose session created it (`ownerUserId`). A pass belongs to ONE user, the one signed in
 * when it starts: it only selects that user's items (`listByOwner`), sends nothing at all when signed out, and checks again, synchronously,
 * immediately before each HTTP call that the signed-in user still owns the item it is about to send. The bearer token is requested for that
 * same owner (`session.accessTokenFor`) and handed to the submitter, so a request can never carry user B's token for user A's play or the
 * reverse. If the signed-in user changes at any point, the pass ABORTS (`report.aborted`); the items it did not reach stay as they were.
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
  isOwnedBy,
  isStaleSent,
  recoverInterrupted,
  resolveUnlisted,
  type RematchResult,
} from "./machine";
import type { OutboxStore } from "./store";
import { UNOWNED, type OutboxItem, type ServerAnswer } from "./types";

/** Who a request is sent as. `accessToken` is the bearer of `userId`'s session (`OutboxSession.accessTokenFor`); a submitter must use exactly
 * this token and never fetch its own (it could belong to whoever is signed in by then). */
export interface EvidenceCredentials {
  userId: string;
  accessToken: string;
}

/** The slice of `api.*` the outbox uses: `POST /v1/evidence`. Never throws
 * for an HTTP outcome; a transport failure is `{ kind: "network_error" }`. */
export interface EvidenceSubmitter {
  submitEvidence(item: OutboxItem, credentials: EvidenceCredentials): Promise<ServerAnswer>;
}

/** The runner's view of the auth session (`AuthService`, wired in `runtime/services.ts`). */
export interface OutboxSession {
  /** The signed-in user's id, or `null` when signed out. Read fresh each time, never cached. */
  currentUserId(): string | null;
  /** The access token of `userId`'s session, or `null` if that user is not the one signed in (or nobody is). May throw (a refresh that could not reach the server). */
  accessTokenFor(userId: string): Promise<string | null>;
}

export interface OutboxRunnerDeps {
  store: OutboxStore;
  api: EvidenceSubmitter;
  session: OutboxSession;
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

/** Why a pass stopped early: nobody is signed in (nothing was sent), the signed-in user changed during the pass, or the owner's token could not be had. */
export type RunAborted = "signed_out" | "user_changed" | "no_token";

export interface RunReport {
  /** `null` = the pass ran to the end. */
  aborted: RunAborted | null;
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
  private inFlight: { user: string | null; promise: Promise<RunReport> } | null = null;

  constructor(private readonly deps: OutboxRunnerDeps) {}

  /** Single-flight PER USER: a call made while a pass for the same signed-in user is running joins it. A call made by a different user
   * (or after a sign-out) waits for the running pass, which aborts as soon as it sees the change, and then runs its own. */
  run(): Promise<RunReport> {
    const user = this.deps.session.currentUserId();
    const running = this.inFlight;
    if (running && running.user === user) return running.promise;
    const after = running ? running.promise.then(noop, noop) : Promise.resolve();
    const entry = { user, promise: after.then(() => this.pass(user)) };
    entry.promise = entry.promise.finally(() => {
      if (this.inFlight === entry) this.inFlight = null;
    });
    this.inFlight = entry;
    return entry.promise;
  }

  /** `runUser` is the user who was signed in when `run()` was CALLED (a pass may start a moment later, after waiting for another user's pass). */
  private async pass(runUser: string | null): Promise<RunReport> {
    const { store, api, session, now, rng } = this.deps;
    const report: RunReport = { aborted: null, sent: 0, accepted: 0, queued: 0, retry: 0, needsAttention: 0, rematched: 0, resolvedUnlisted: 0, recovered: 0, expired: 0 };
    const abort = (why: RunAborted): RunReport => {
      report.aborted = why;
      return report;
    };

    // 1a. The 90-day dead-letter expiry. It runs for every owner (it only DELETES rows that are already past retention; it sends nothing)
    //     and even when signed out.
    for (const item of await store.list()) {
      if (isExpiredDeadLetter(item, now())) {
        await store.delete(item.id);
        report.expired += 1;
      }
    }

    // The pass's user. Signed out (or the unowned sentinel): nothing is selected and nothing is sent.
    if (runUser === null || runUser === UNOWNED) return abort("signed_out");
    const userChanged = (): boolean => session.currentUserId() !== runUser;
    if (userChanged()) return abort(session.currentUserId() === null ? "signed_out" : "user_changed");

    // 1b. Interrupted sends, for THIS user's items only (another user's stay as they are until that user signs back in).
    for (const item of await store.listByOwner(runUser)) {
      if (isStaleSent(item, now())) {
        await store.update(recoverInterrupted(item, now()));
        report.recovered += 1;
      }
    }

    // 2. "Unlisted course" items become sendable once a catalog carries the course.
    for (const item of await store.listByOwner(runUser)) {
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
    for (const listed of await store.listByOwner(runUser)) {
      let item = listed;
      for (let round = 0; round < 2; round += 1) {
        if (userChanged()) return abort("user_changed");
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

        // The owner's token, requested for the ITEM's owner (not for "whoever is signed in"). Checked first, so a sign-out never costs a refresh.
        if (!isOwnedBy(item, session.currentUserId())) return abort(session.currentUserId() === null ? "signed_out" : "user_changed");
        let accessToken: string | null;
        try {
          accessToken = await session.accessTokenFor(item.ownerUserId);
        } catch {
          accessToken = null;
        }
        if (accessToken === null) return abort(userChanged() ? "user_changed" : "no_token");

        const before = item;
        item = beginSend(item, now());
        await store.update(item); // durable BEFORE the request
        // The last check, with no await between it and the call: the item is still the signed-in user's. If not, undo the `sent` mark (the
        // request never started, so it must not count as an attempt) and stop.
        if (!isOwnedBy(item, session.currentUserId())) {
          await store.update({ ...before, updatedAt: now() });
          return abort(session.currentUserId() === null ? "signed_out" : "user_changed");
        }
        report.sent += 1;
        const answer = await api.submitEvidence(item, { userId: item.ownerUserId, accessToken }).catch(
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

function noop(): void {}
