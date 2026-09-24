# 0005 — Historical rounds on devices count toward the X1 verdict

- **Status:** Accepted
- **Date:** 2026-09-24
- **Decider:** Matt (owner): "I want historical rounds on devices to count toward the checks verdict."
  Context: Matt owns a Garmin Approach S62 and has already played several courses with it.
- **Amends:** decision 0001, Addendum F, "X1 round window". Nothing is read under the old rule first: no X1
  export has been read yet.

## Decision

**X1 counts every golf workout in the Health data, whenever it was played.** A golf workout from one of X1's
three sources counts toward the verdict whether it came from a planned test round or a round played before
today. Its route must be present, exactly as before.

- **Round windows become labels, not a filter.** A window logged in `docs/p0/X1.md` marks the workouts inside it
  as test rounds in the output. No workout is excluded because it falls outside one, and the tools no longer
  refuse to run when no window is logged.
- **Unchanged:**
  - the pass bar: ≥ 2 of 3 sources write golf workouts **with routes**;
  - the same-OS rule (Addendum F, "on ≥ 1 OS");
  - the source allow-list (plan §7.3 lane 5);
  - the per-source verdict (A2-14).

## Integrity rules (fixed now, before any export is read)

- **The first export read is the recorded one.** Matt logs the export's date in `docs/p0/X1.md` before it is
  read. A later export can be read for information, but it never replaces the recorded result. This stops a
  better-looking export from being chosen after the fact. The same rule applies separately to each OS.
- **Every counted workout is listed with its date and source.** This means the source bundle id, and the
  source version and device when the export records them. The memo shows, per source, the newest counted
  workout's date.
- **No recency limit.** An old round counts the same as a new one. The known limit is stated here once: an old
  round shows what the source app did **then**, and a source may have changed since. The newest-date column is
  there so a verdict resting only on old rounds is visible. Matt can add a recency limit before the export is
  read if he wants one.

## Where historical rounds do NOT apply

- **K4b.** Its bar is that **our** Connect IQ component records fixes while Garmin's native Golf activity runs.
  No round played before that component exists can show this, so historical rounds cannot count toward K4b.
  **K4 = X1 or K4b**, so K4 can still pass through X1 on historical rounds.
- **FIT files taken off the watch** (e.g. `GARMIN/SCORE/SCORECARD`) are the file-import lane (plan §7.3 lane 2),
  not Health data. They are not X1 evidence. They are used as real test fixtures for the "Import a round" flow,
  and for Matt's own played-course history.
- **Android history.** Health Connect may limit how far back an app can read data written before its permission
  was granted `[unverified — training knowledge]`. Whatever history the reader actually returns is what counts.
  Nothing is inferred beyond it.
