/**
 * The `health_route` ↔ `file_import` correlation key (build plan §4.5:
 * "a `health_route` and a `file_import` of the same round (same start
 * ± 15 min at the same facility)" combine by `max`, not noisy-OR). The
 * actual combination logic lives server-side (P3, out of this package's
 * scope, per the build task's own framing) — this just gives it a
 * deterministic bucket key to group candidate pairs by.
 *
 * **Known approximation**, documented rather than hidden (same spirit as
 * `@golfraven/matching`'s own README ambiguity list): this buckets by
 * rounding `startedAt` to the nearest 15-minute mark, so two evidence
 * rows within about ±7.5 minutes of the same grid mark always share a
 * key, but a pair that straddles a grid boundary (e.g. 10:07 and 09:53 —
 * 14 minutes apart, nominally inside the ±15 min window) can round to
 * *different* marks and miss. P3's own correlation query isn't
 * constrained to trust only this key — it can always fall back to a
 * direct ±15 min timestamp comparison at the same facility when this
 * bucket alone doesn't produce a match; this function exists to make the
 * common case a cheap index lookup, not to be the sole source of truth
 * for the ±15 min rule.
 */
import type { ImportedRound } from "./types.js";

const BUCKET_MS = 15 * 60 * 1000;

/** Returns the correlation bucket key for a round at `facilityId`, or
 * `undefined` when the round has no `startedAt` to bucket (a date-only
 * import has nothing to correlate by start time against). */
export function correlationKey(round: ImportedRound, facilityId: string): string | undefined {
  if (round.startedAt === undefined || !Number.isFinite(round.startedAt)) return undefined;
  const bucket = Math.round(round.startedAt / BUCKET_MS);
  return `${facilityId}:${bucket}`;
}
