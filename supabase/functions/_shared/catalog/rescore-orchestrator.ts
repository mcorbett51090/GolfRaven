// supabase/functions/_shared/catalog/rescore-orchestrator.ts
//
// AT 18 (P3e round 3, R2): works the re-score backlog the importer filled
// (migration 0026, `ImporterRepo#rescoreBacklog`) a BOUNDED amount per
// pass. The import transaction only INSERTS backlog rows (set-based, one
// per promoted / newly-split course); everything per-play happens here, one
// short `withOwnership` transaction per play (the play's own user), so a
// promotion that touches thousands of plays can never blow the 12 s
// transaction_timeout — it just takes several passes. The cursor
// (`cursor_play_id`, keyset over play ids) advances ONLY past plays that
// were actually processed: a failing play stops its course for this pass
// and is retried next pass, never skipped.

import { labelSplitPlayAsUserPick, rescorePlayAfterPromotion } from "../evidence/handler.ts";
import type { Actor, ImporterRepo, Repo } from "../types.ts";

export interface RescoreBacklogResult {
  backlogRows: number;
  playsProcessed: number;
  coursesCompleted: number;
  failures: number;
}

export type WithOwnershipFn = <T>(actor: Actor, op: (repo: Repo) => Promise<T>) => Promise<T>;

export const DEFAULT_RESCORE_MAX_PLAYS = 50;
const DEFAULT_RESCORE_MAX_COURSES = 5;

export async function drainRescoreBacklog(importerRepo: ImporterRepo, withOwnership: WithOwnershipFn, maxPlays: number = DEFAULT_RESCORE_MAX_PLAYS): Promise<RescoreBacklogResult> {
  const rows = await importerRepo.rescoreBacklog.listOpen(DEFAULT_RESCORE_MAX_COURSES);
  const result: RescoreBacklogResult = { backlogRows: rows.length, playsProcessed: 0, coursesCompleted: 0, failures: 0 };
  let budget = maxPlays;

  for (const row of rows) {
    if (budget <= 0) break;
    const requested = budget;
    const plays = await importerRepo.rescoreBacklog.nextPlays(row.courseId, row.cursorPlayId, requested);
    let cursor = row.cursorPlayId;
    let failed = false;
    for (const p of plays) {
      const actor: Actor = { uid: p.userId, role: "authenticated" };
      try {
        await withOwnership(actor, async (repo) => {
          if (row.reason === "promotion") await rescorePlayAfterPromotion(repo, { facilityId: p.facilityId, courseId: p.courseId, playDate: p.playDate });
          else await labelSplitPlayAsUserPick(repo, p.playId);
        });
      } catch (err) {
        console.error(`drainRescoreBacklog: play ${p.playId} (${row.reason}) failed; will retry next pass`, err);
        result.failures += 1;
        failed = true;
        break;
      }
      cursor = p.playId;
      result.playsProcessed += 1;
      budget -= 1;
    }
    // The LAST page is exactly one that returned fewer plays than requested.
    const done = !failed && plays.length < requested;
    await importerRepo.rescoreBacklog.advance(row.id, cursor, done);
    if (done) result.coursesCompleted += 1;
  }
  return result;
}
