/**
 * The facility-local calendar date of an instant, the `localDate` of a fix-bearing evidence submission.
 *
 * The server does not trust the client's label: `assertServerDerivableLocalDate` (evidence/handler.ts) recomputes the date from the ANCHOR fix's own `capturedAt` in the
 * FACILITY's time zone (`Facility.tz`) and answers 422 `local_date_mismatch` (a dead letter here) for any other value. So the date is derived the same way, from the fix's
 * timestamp (not from "now": a check-in queued offline just after midnight keeps the date of the moment it was taken) and the facility's tz (not the phone's).
 * `test/checkin-wire.test.ts` compares this with the server's own `localDateInTz` for the vectors the recorder produced.
 *
 * `Intl.DateTimeFormat` with a `timeZone` is Hermes' on both platforms `[unverified: on a device]`. When it is missing or throws (an unknown zone) the answer is `null`
 * and the check-in is refused with "no time zone" rather than guessed: a guessed date is a `local_date_mismatch` after the player has left.
 */
export function localDateInTz(epochMs: number, tz: string): string | null {
  if (!Number.isFinite(epochMs) || tz.length === 0) return null;
  try {
    const parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(new Date(epochMs));
    const get = (type: string): string | undefined => parts.find((p) => p.type === type)?.value;
    const y = get("year");
    const m = get("month");
    const d = get("day");
    if (y === undefined || m === undefined || d === undefined) return null;
    const out = `${y.padStart(4, "0")}-${m}-${d}`;
    return /^\d{4}-\d{2}-\d{2}$/.test(out) ? out : null;
  } catch {
    return null;
  }
}
