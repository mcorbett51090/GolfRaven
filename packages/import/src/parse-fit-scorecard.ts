/**
 * Garmin golf-scorecard FIT extraction (build plan §7.3 lane 2).
 *
 * The Approach S62 (and similar Garmin golf watches) writes a scorecard
 * FIT file distinct from the GPS-track activity FIT, stored on-device
 * under `GARMIN/SCORE/SCORECARD`. **Its message layout is
 * `[unverified]`** — `fit-file-parser`'s bundled profile (the same public
 * FIT SDK profile tables every FIT decoder ships) has no entries for it,
 * and no real sample has been available to reverse-engineer against.
 *
 * This function is deliberately small and isolated, per the build plan's
 * own instruction ("design the scorecard extraction as a small isolated
 * function that is easy to update against real files"): it is the *only*
 * place that needs to change once the owner supplies real S62 scorecard
 * files (`test/fixtures/real/README.md`). Today it does the one thing the
 * build plan requires even without real fixtures — reporting, never
 * silently dropping, every FIT message number the decoder's profile
 * didn't recognize, so a scorecard file at least produces visible
 * evidence that *something* undecoded is in there instead of an
 * empty-looking import.
 */
import type { ParsedFit } from "fit-file-parser";
import type { ImportedScoreHole } from "./types.js";

export interface FitScorecardData {
  courseNameHint?: string;
  localDate?: string;
  holes?: number;
  scores?: ImportedScoreHole[];
  totalScore?: number;
  warnings: string[];
}

export function extractGolfScorecard(parsed: ParsedFit): FitScorecardData {
  const warnings: string[] = [];
  const countByGlobalNumber = new Map<number, number>();

  for (const msg of parsed.unmapped_messages ?? []) {
    countByGlobalNumber.set(
      msg.global_message_number,
      (countByGlobalNumber.get(msg.global_message_number) ?? 0) + 1,
    );
  }

  for (const [globalMessageNumber, count] of [...countByGlobalNumber.entries()].sort((a, b) => a[0] - b[0])) {
    warnings.push(
      `FIT message ${globalMessageNumber} (${count}x) isn't decoded by this parser's profile — ` +
        `possibly Garmin golf scorecard data (GARMIN/SCORE/SCORECARD on the Approach S62, ` +
        `[unverified]); not extracted. See parse-fit-scorecard.ts.`,
    );
  }

  // Nothing decoded yet — see the doc comment above. Update this function
  // once a real scorecard FIT is available: read its message layout with
  // `readFitMessages`/`includeUnmappedMessages`, add the confirmed field
  // mapping here, and populate `courseNameHint`/`localDate`/`scores`/
  // `totalScore` from it.
  return { warnings };
}
