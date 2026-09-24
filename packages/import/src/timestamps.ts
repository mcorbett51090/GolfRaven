/**
 * Strict timestamp parsing shared by the GPX and CSV parsers (build plan
 * §7.3 lane 2 security follow-up). A file-supplied timestamp is untrusted
 * input, and JS's `Date.parse` is far too permissive for it: it accepts
 * naive (no zone) strings, applies the *host's* local timezone to them
 * (nondeterministic across devices/servers), and — for its
 * "implementation-defined" fallback branch — a pile of non-ISO formats
 * that vary by engine. None of that belongs in evidence parsing.
 *
 * `parseStrictTimestamp` requires the ISO 8601 extended date-time form
 * with a mandatory `Z` or a numeric UTC offset, and rejects anything
 * before the year 2000 (a device/file clearly has a wrong clock, or this
 * isn't really a timestamp). It never falls back to loose parsing.
 */

const ISO_STRICT_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$/;

const MIN_YEAR = 2000;

export interface StrictTimestamp {
  /** Epoch milliseconds. */
  ms: number;
  /** The literal `YYYY-MM-DD` exactly as written in the source string —
   * i.e. the wall-clock date implied by *that string's own* offset, not
   * reprojected through UTC or any other timezone. */
  literalDate: string;
  /** True when the source carried a real numeric offset (`+02:00`), not
   * just `Z`. `Z` means "normalized to UTC", which is not the same claim
   * as "this is the facility-local date" — a caller that wants a
   * facility-local date from a bare-`Z` timestamp should convert `ms`
   * through an explicit `tz`, not trust `literalDate`. */
  hasExplicitOffset: boolean;
}

/** Parses a strict ISO 8601 timestamp with a mandatory `Z`/offset, or
 * returns `undefined` for anything else (naive time, a US-style date, a
 * bare epoch number, a non-ISO string, or a year before 2000). */
export function parseStrictTimestamp(raw: string): StrictTimestamp | undefined {
  const trimmed = raw.trim();
  const m = ISO_STRICT_RE.exec(trimmed);
  if (!m) return undefined;
  const [, year, month, day, , , , offset] = m;
  if (Number(year) < MIN_YEAR) return undefined;
  if (Number(month) < 1 || Number(month) > 12) return undefined;
  if (Number(day) < 1 || Number(day) > 31) return undefined;

  const ms = Date.parse(trimmed);
  if (!Number.isFinite(ms)) return undefined;

  const hasExplicitOffset = offset !== "Z" && offset !== "z";
  return { ms, literalDate: `${year}-${month}-${day}`, hasExplicitOffset };
}

/** Converts an epoch-millisecond instant into an IANA timezone's local
 * calendar date (`YYYY-MM-DD`), or `undefined` if `tz` isn't a timezone
 * `Intl` recognizes. */
export function localDateForTz(ms: number, tz: string): string | undefined {
  try {
    const formatted = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date(ms));
    return /^\d{4}-\d{2}-\d{2}$/.test(formatted) ? formatted : undefined;
  } catch {
    return undefined;
  }
}
