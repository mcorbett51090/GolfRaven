/**
 * The `health_route` ↔ `file_import` correlation key (build plan §4.5:
 * "a `health_route` and a `file_import` of the same round (same start
 * ± 15 min at the same facility)" combine by `max`, not noisy-OR). The
 * actual combination logic lives server-side (P3, out of this package's
 * scope, per the build task's own framing) — this just gives it a
 * deterministic set of bucket keys to group candidate pairs by.
 *
 * **Returns the current bucket plus its two neighbors**, not a single
 * key: `startedAt` is bucketed on a 15-minute grid (`floor(t / 15min)`),
 * and this returns `{floor-1, floor, floor+1}` as three keys. That's
 * deliberate, not decorative — for any two timestamps at most 15 minutes
 * apart, their floor-bucket indices differ by at most 1 (a 2-bucket gap
 * would require the earlier timestamp to sit below one boundary and the
 * later one at or past the *next* boundary, which needs a gap strictly
 * greater than the 15-minute bucket width). So the two rounds' 3-key
 * neighbor sets are guaranteed to share at least one key whenever they're
 * within the nominal ±15 min window, including exactly at 15 minutes and
 * right across a grid boundary — see `test/correlation.test.ts`'s
 * boundary cases (10:07:29 vs 10:07:31, and exactly ±15 minutes) for the
 * proof in practice. An earlier version returned a single rounded-to-
 * nearest bucket, which could miss a boundary-straddling pair; this
 * replaces it rather than layering a second key scheme on top.
 *
 * P3's own correlation query isn't constrained to trust only this key —
 * it can always fall back to a direct ±15 min timestamp comparison at the
 * same facility if it wants exact confirmation; this function exists to
 * make the common case a cheap, correct index lookup (`WHERE key IN
 * (...)`), not to be the sole source of truth for the ±15 min rule.
 */
import type { ImportedRound } from "./types.js";

const BUCKET_MS = 15 * 60 * 1000;

/**
 * Returns the three correlation bucket keys (previous, current, next) for
 * a round at `facilityId`, or `undefined` when there's nothing to
 * correlate by start time: a routeless import (no fixes) never carries
 * `startedAt` (build plan A2-17 — it's `localDate`-only evidence), so it
 * always returns `undefined` here too.
 */
export function correlationKey(round: ImportedRound, facilityId: string): string[] | undefined {
  if (round.fixes.length === 0) return undefined;
  if (round.startedAt === undefined || !Number.isFinite(round.startedAt)) return undefined;

  const floor = Math.floor(round.startedAt / BUCKET_MS);
  return [floor - 1, floor, floor + 1].map((bucket) => `${facilityId}:${bucket}`);
}
