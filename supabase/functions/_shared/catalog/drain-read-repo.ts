// supabase/functions/_shared/catalog/drain-read-repo.ts
//
// The importer-repo view the two drain passes (queued_catalog and the AT 18
// re-score backlog) read through: every cross-user read/advance runs in its
// OWN short system transaction, so the per-row actor-scoped `withOwnership`
// transactions that follow are NEVER nested inside a still-open system
// transaction (the P3c "pool deadlock" lesson, privileged.ts#
// hitRateLimitForActor's own doc). Takes `withSystem` as a parameter so
// this module stays free of privileged.ts (the only allow-listed
// service-role construction site); import-catalog/index.ts and the
// integration tests both pass the real `withSystemCatalogImport`.
import type { ImporterRepo } from "../types.ts";

export function makeDrainReadRepo(withSystem: <T>(op: (repo: ImporterRepo) => Promise<T>) => Promise<T>): ImporterRepo {
  return {
    now: () => new Date(),
    catalog: undefined as unknown as ImporterRepo["catalog"], // the drains never touch it
    queuedCatalog: {
      listOpen: (limit) => withSystem((repo) => repo.queuedCatalog.listOpen(limit)),
      currentSiteVersion: () => withSystem((repo) => repo.queuedCatalog.currentSiteVersion()),
    },
    rescoreBacklog: {
      listOpen: (limit, sweepDelaySeconds) => withSystem((repo) => repo.rescoreBacklog.listOpen(limit, sweepDelaySeconds)),
      markFinished: (id, cursor) => withSystem((repo) => repo.rescoreBacklog.markFinished(id, cursor)),
      beginSweep: (id, cursor, overlap) => withSystem((repo) => repo.rescoreBacklog.beginSweep(id, cursor, overlap)),
      purgeFixCoords: (days, limit) => withSystem((repo) => repo.rescoreBacklog.purgeFixCoords(days, limit)),
      purgeInstallLinkTombstones: (maxRows) => withSystem((repo) => repo.rescoreBacklog.purgeInstallLinkTombstones(maxRows)),
      nextPlays: (courseId, after, limit) => withSystem((repo) => repo.rescoreBacklog.nextPlays(courseId, after, limit)),
      advance: (id, cursor, done) => withSystem((repo) => repo.rescoreBacklog.advance(id, cursor, done)),
    },
  };
}
