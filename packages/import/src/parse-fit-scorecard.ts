/**
 * Garmin golf-scorecard FIT extraction (build plan §7.3 lane 2).
 *
 * The Approach S62 (and similar Garmin golf watches) writes a scorecard
 * FIT file distinct from the GPS-track activity FIT, stored on-device
 * under `GARMIN/SCORE/SCORECARD`. **Its message layout is
 * `[unverified]`** — no real sample has been available to reverse-
 * engineer against, and this package no longer even asks
 * `fit-file-parser` for its full profile-based "unmapped message" list
 * (`includeUnmappedMessages`), because that option retains full raw
 * field data for every such message — exactly the kind of per-message
 * allocation the Opus security gate flagged. Instead, `parse-fit.ts`'s
 * own cheap header walk (`fit-prescan.ts`) tallies which global message
 * numbers occur, against a small curated "known" list
 * (`KNOWN_FIT_MESSAGE_NUMBERS`), and this function turns that tally into
 * warnings.
 *
 * This function is deliberately small and isolated, per the build plan's
 * own instruction ("design the scorecard extraction as a small isolated
 * function that is easy to update against real files"): it is the *only*
 * place that needs to change once the owner supplies real S62 scorecard
 * files (`test/fixtures/real/README.md`). Today it does the one thing the
 * build plan requires even without real fixtures — reporting, never
 * silently dropping, every FIT message number this package doesn't
 * recognize, so a scorecard file at least produces visible evidence that
 * *something* undecoded is in there instead of an empty-looking import.
 */
import type { ImportedScoreHole } from "./types.js";
import { KNOWN_FIT_MESSAGE_NUMBERS } from "./fit-prescan.js";
import { truncateEcho } from "./safety.js";

export interface FitScorecardData {
  courseNameHint?: string;
  localDate?: string;
  holes?: number;
  scores?: ImportedScoreHole[];
  totalScore?: number;
  warnings: string[];
}

/** `counts` is the prescan's tally of global message number → occurrence
 * count (`FitPrescanSuccess.globalMessageCounts`). */
export function extractGolfScorecard(
  counts: ReadonlyMap<number, number>,
): FitScorecardData {
  const warnings: string[] = [];

  const unknown = [...counts.entries()]
    .filter(
      ([globalMessageNumber]) =>
        !KNOWN_FIT_MESSAGE_NUMBERS.has(globalMessageNumber),
    )
    .sort((a, b) => a[0] - b[0]);

  for (const [globalMessageNumber, count] of unknown) {
    warnings.push(
      truncateEcho(
        `FIT message ${globalMessageNumber} (${count}x) isn't recognized by this package — ` +
          `possibly Garmin golf scorecard data (GARMIN/SCORE/SCORECARD on the Approach S62, ` +
          `[unverified]); not extracted. See parse-fit-scorecard.ts.`,
        200,
      ),
    );
  }

  // Nothing decoded yet — see the doc comment above. Update this function
  // once a real scorecard FIT is available: extend `fit-prescan.ts`'s
  // walk (or a small dedicated follow-up scan) to read the confirmed
  // field layout for the relevant global message number(s), and populate
  // `courseNameHint`/`localDate`/`scores`/`totalScore` from it here.
  return { warnings };
}
