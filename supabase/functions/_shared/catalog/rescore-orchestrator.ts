// supabase/functions/_shared/catalog/rescore-orchestrator.ts
//
// AT 18 (P3e round 3, R2): works the re-score backlog the importer filled
// (migration 0026, `ImporterRepo#rescoreBacklog`) a BOUNDED amount per
// pass. The import transaction only INSERTS backlog rows (set-based, one
// per promoted / newly-split course); everything per-play happens here, one
// short `withDelegatedActor` transaction per play (the play's own user), so a
// promotion that touches thousands of plays can never blow the 12 s
// transaction_timeout — it just takes several passes. The cursor
// (a stable (created_at, id) keyset) advances ONLY past plays that
// were actually processed: a failing play stops its course for this pass
// and is retried next pass, never skipped.

import { FIX_COORDS_RETENTION_DAYS, labelSplitPlayAsUserPick, rescorePlayAfterPromotion } from "../evidence/handler.ts";
import type { Actor, ImporterRepo, WithDelegatedActorFn } from "../types.ts";
import type { Deadline } from "./time-budget.ts";

export interface RescoreBacklogResult {
  backlogRows: number;
  playsProcessed: number;
  coursesCompleted: number;
  failures: number;
  /** True when the time budget stopped the pass early (the cursor persists; the next run resumes). */
  truncated: boolean;
  /** §8.6: evidence rows whose raw fix coordinates this pass cleared. */
  coordsPurged: number;
  /** F19 retention: install-link tombstones older than 24 months this pass deleted. */
  tombstonesPurged: number;
}

/** Edge role PR3: per-play transactions go through `privileged.ts#withDelegatedActor` (injected, so this module stays privileged.ts-free).
 * In `edge` mode it binds the play's owner with `private.bind_delegate_for_rescore(backlogId, playId)` (valid only while the backlog
 * row is open and the play is at its course); in `legacy` mode it is `withOwnership(actor, op)`. */
export type { WithDelegatedActorFn };

/** The most plays one `list_rescore_plays` page can return (the database definer clamps its limit to this). A page is full when it
 * holds exactly the requested count, so the request itself never exceeds it: a clamp the caller did not know about would read a full
 * page as a short one and close the course early. */
export const MAX_RESCORE_PAGE = 500;

export const DEFAULT_RESCORE_MAX_PLAYS = 50;
const DEFAULT_RESCORE_MAX_COURSES = 5;

/** Straggler grace. `app.play.created_at` is the START of the inserting
 * transaction (now()), and a write transaction can live for at most
 * `transaction_timeout` = 12 s (privileged.ts) — so a play whose
 * transaction began before the cursor's timestamp can still COMMIT after the
 * drain has passed that timestamp and be skipped by the keyset. A course is
 * therefore not closed the first time a page comes back short: it waits
 * `RESCORE_SWEEP_DELAY_SECONDS` (> 12 s, so every such transaction has
 * committed or died), rewinds the cursor by `RESCORE_SWEEP_OVERLAP_SECONDS`
 * (> 12 s) and scans to the end once more. Re-scoring is idempotent. */
export const RESCORE_SWEEP_DELAY_SECONDS = 15;
export const RESCORE_SWEEP_OVERLAP_SECONDS = 15;

/** §8.6: raw fix coordinates are kept only while a re-pick can happen; 30 days
 * is the most they can outlive the play. Why 30: a client can only submit
 * against a catalog within the 30-day skew window (build plan §3.3), so a
 * split that matters to a play is announced by a catalog release within about
 * that long; keeping them longer buys nothing, and a re-pick after that
 * fails closed (`cannot_rederive`). Named here, enforced by `purgeFixCoords`. */
export { FIX_COORDS_RETENTION_DAYS };
const PURGE_BATCH = 5000;
/** Bound per call of the install-link tombstone retention purge (the 24 months themselves live in the database function). */
const TOMBSTONE_PURGE_BATCH = 5000;

export interface RescoreOptions {
  /** Tests only: shorten the straggler grace (default RESCORE_SWEEP_DELAY_SECONDS). */
  sweepDelaySeconds?: number;
}

export async function drainRescoreBacklog(importerRepo: ImporterRepo, withDelegatedActor: WithDelegatedActorFn, maxPlays: number = DEFAULT_RESCORE_MAX_PLAYS, deadline?: Deadline, opts: RescoreOptions = {}): Promise<RescoreBacklogResult> {
  const sweepDelay = opts.sweepDelaySeconds ?? RESCORE_SWEEP_DELAY_SECONDS;
  const rows = await importerRepo.rescoreBacklog.listOpen(DEFAULT_RESCORE_MAX_COURSES, sweepDelay);
  const result: RescoreBacklogResult = { backlogRows: rows.length, playsProcessed: 0, coursesCompleted: 0, failures: 0, truncated: false, coordsPurged: 0, tombstonesPurged: 0 };
  let budget = maxPlays;

  outer: for (const initial of rows) {
    let row = initial;
    // One row can take several steps in a pass (pages, finish, sweep start,
    // sweep pages) when the grace is zero; the budget bounds the work.
    for (;;) {
      if (budget <= 0) break outer;
      if (deadline && !deadline.canStartUnit()) {
        result.truncated = true;
        break outer;
      }
      const requested = Math.min(budget, MAX_RESCORE_PAGE);
      const plays = await importerRepo.rescoreBacklog.nextPlays(row.courseId, row.cursor, requested);
      let cursor = row.cursor;
      let failed = false;
      let outOfTime = false;
      for (const p of plays) {
        if (deadline && !deadline.canStartUnit()) {
          outOfTime = true;
          result.truncated = true;
          break;
        }
        const actor: Actor = { uid: p.userId, role: "authenticated" };
        try {
          await withDelegatedActor({ kind: "rescore", backlogId: row.id, playId: p.playId }, actor, async (repo) => {
            if (row.reason === "promotion") await rescorePlayAfterPromotion(repo, { facilityId: p.facilityId, courseId: p.courseId, playDate: p.playDate });
            else await labelSplitPlayAsUserPick(repo, { playId: p.playId, facilityId: p.facilityId, courseId: p.courseId, playDate: p.playDate });
          });
        } catch (err) {
          console.error(`drainRescoreBacklog: play ${p.playId} (${row.reason}) failed; will retry next pass`, err);
          result.failures += 1;
          failed = true;
          break;
        }
        cursor = { playId: p.playId, createdAt: p.createdAt };
        result.playsProcessed += 1;
        budget -= 1;
      }
      const lastPage = !failed && !outOfTime && plays.length < requested;
      if (!lastPage) {
        await importerRepo.rescoreBacklog.advance(row.id, cursor, false);
        if (failed || outOfTime) break outer;
        // a full page: loop for the next one
        row = { ...row, cursor };
        continue;
      }
      // A short page: the end of the course AS OF NOW.
      if (row.swept) {
        await importerRepo.rescoreBacklog.advance(row.id, cursor, true);
        result.coursesCompleted += 1;
        break;
      }
      if (row.finishedAt === null) {
        await importerRepo.rescoreBacklog.markFinished(row.id, cursor);
        row = { ...row, cursor, finishedAt: "now", sweepReady: sweepDelay <= 0 };
      } else {
        await importerRepo.rescoreBacklog.advance(row.id, cursor, false);
        row = { ...row, cursor };
      }
      if (!row.sweepReady) break; // still inside the straggler grace: the next run sweeps
      const rewound = await importerRepo.rescoreBacklog.beginSweep(row.id, cursor, RESCORE_SWEEP_OVERLAP_SECONDS);
      row = { ...row, cursor: rewound, swept: true };
    }
  }

  // §8.6 minimisation: clear raw fix coordinates that can no longer be used
  // (course no longer re-pickable, or past the retention window) — one
  // set-based statement per pass, bounded, regardless of the backlog above.
  try {
    result.coordsPurged = await importerRepo.rescoreBacklog.purgeFixCoords(FIX_COORDS_RETENTION_DAYS, PURGE_BATCH);
  } catch (err) {
    console.error("drainRescoreBacklog: fixCoords purge failed; will retry next pass", err);
  }
  // F19 (owner decision 2026-10-02): the install-link fraud tombstone is kept 24 months from first_seen_at. Run here, next to the
  // fix-coordinate purge, because this is the one recurring system pass there is. SCHEDULING both purges independently of an
  // import is a launch-blocking follow-up (docs/security/p3-money-path-requirements.md, "Owner decisions (2026-10-02)").
  try {
    result.tombstonesPurged = await importerRepo.rescoreBacklog.purgeInstallLinkTombstones(TOMBSTONE_PURGE_BATCH);
  } catch (err) {
    console.error("drainRescoreBacklog: install-link tombstone purge failed; will retry next pass", err);
  }
  return result;
}
