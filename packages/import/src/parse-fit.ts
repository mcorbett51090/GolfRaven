/**
 * FIT import (build plan §7.3 lane 2). Uses `fit-file-parser` (MIT) — see
 * `README.md` "Why `fit-file-parser`" for why it was chosen over Garmin's
 * own `@garmin/fitsdk`.
 *
 * Record messages become fixes: `position_lat`/`position_long` are
 * already converted from semicircles to degrees by the decoder (its
 * `fit.js` applies the standard `180 / 2^31` constant), and `timestamp`
 * is already a `Date`. Session/activity start/end and sport come from the
 * first `session` message; golf is sport id 25, confirmed against this
 * decoder's own bundled profile table (`profile-lookup-data.js`) —
 * `[unverified against a real Garmin device capture]`, since no live S62
 * file was available to confirm end-to-end, but the id itself is the
 * standard public FIT SDK profile value the decoder ships, not a guess.
 *
 * **Security note (Opus gate follow-up).** A 19 MB crafted FIT file
 * (millions of tiny messages, or a handful of enormous definitions) drove
 * `fit-file-parser` to multi-GB peak RSS and tens of seconds of CPU. Two
 * layers now guard against that, checked in order, *before* the real
 * decode ever runs: (1) `MAX_FIT_INPUT_BYTES` (5 MB, down from the
 * general 20 MB cap), and (2) `fit-prescan.ts`'s cheap header-only walk,
 * which refuses a file with too many messages or too many cumulative
 * definition fields without allocating anything per message. Only a file
 * that survives both is handed to `fit-file-parser`, and even then
 * without `includeUnmappedMessages` (which itself retains full raw field
 * data per unmapped message — see `parse-fit-scorecard.ts`).
 */
import FitParser from "fit-file-parser";
import type { ParsedFit } from "fit-file-parser";
import type { ImportedFix, ImportedRound, ImportResult } from "./types.js";
import {
  checkInputSize,
  capAndSortFixes,
  isValidLat,
  isValidLon,
  sanitizeAccuracy,
  sanitizeText,
  finalizeWarnings,
  finalizeError,
  truncateEcho,
  MAX_FIT_INPUT_BYTES,
} from "./safety.js";
import { prescanFit } from "./fit-prescan.js";
import { extractGolfScorecard } from "./parse-fit-scorecard.js";
import { localDateForTz } from "./timestamps.js";

const GOLF_SPORT = "golf";

// `fit-file-parser`'s package exports only re-export `ParsedFit` itself
// (plus the raw-message types) from its root entry, not every nested
// message type — derive `ParsedSession` from it instead of reaching into
// an unexported subpath.
type ParsedSession = NonNullable<ParsedFit["sessions"]>[number];

export interface ParseFitOptions {
  /** An IANA timezone (e.g. `"America/Toronto"`) — the facility's `tz`
   * (build plan §4.1). Used only as a fallback to derive `localDate` for
   * a routeless import when the FIT file itself carries no
   * `activity.local_timestamp` (build plan A2-17, §4.5). Never applied
   * when the file has usable fixes — those get real timestamps, never a
   * derived date. */
  tz?: string;
  signal?: AbortSignal;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  // `bytes` may be a view over a larger buffer (e.g. a slice from a
  // multipart upload) — copy out exactly its own range so the parser
  // never reads bytes that aren't part of this file.
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function deviceStringFrom(parsed: ParsedFit): string | undefined {
  const fileId = parsed.file_ids?.[0];
  if (!fileId) return undefined;
  const manufacturer = typeof fileId.manufacturer === "string" ? fileId.manufacturer : undefined;
  const product =
    fileId.product_name && fileId.product_name.length > 0
      ? fileId.product_name
      : fileId.product !== undefined
        ? String(fileId.product)
        : undefined;
  const parts = [manufacturer, product].filter((v): v is string => v !== undefined && v.length > 0);
  return parts.length > 0 ? sanitizeText(parts.join(" ")) : undefined;
}

/** `local_date_time`-typed FIT fields (like `activity.local_timestamp`)
 * store a value that's already the device's local wall time — the raw
 * seconds are never adjusted for a real-world UTC offset by the decoder,
 * so reading the resulting `Date`'s *UTC* calendar fields back out gives
 * the intended local calendar date, not a re-shifted one. */
function localDateFromLocalTimestamp(date: Date | undefined): string | undefined {
  return date && Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 10) : undefined;
}

/** Parses a FIT file's bytes. Pure aside from the decode itself (no
 * filesystem or network access) — `fit-file-parser` reads only the
 * `ArrayBuffer` handed to it. Honors `options.signal` where feasible: a
 * synchronous CPU-bound walk (the prescan) can only be interrupted
 * between messages, not mid-instruction, and the real decode inside
 * `fit-file-parser` isn't itself abortable at all — the size cap and the
 * prescan are what actually bound its worst case. The app is expected to
 * run this inside a worker with its own hard timeout as the outermost
 * layer; `signal` support here is a cooperative fast-exit, not a
 * substitute for that. */
export async function parseFitFile(bytes: Uint8Array, options: ParseFitOptions = {}): Promise<ImportResult> {
  const sizeError = checkInputSize(bytes.byteLength, MAX_FIT_INPUT_BYTES);
  if (sizeError) return { ok: false, error: finalizeError(sizeError) };
  if (options.signal?.aborted) return { ok: false, error: "aborted" };

  const scan = prescanFit(bytes, options.signal !== undefined ? { signal: options.signal } : {});
  if (!scan.ok) {
    return { ok: false, error: finalizeError(scan.error) };
  }
  if (options.signal?.aborted) return { ok: false, error: "aborted" };

  const parser = new FitParser({
    force: true,
    mode: "list",
    includeUnmappedMessages: false,
  });

  let parsed: ParsedFit;
  try {
    parsed = await parser.parseAsync(toArrayBuffer(bytes));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: finalizeError(`FIT parse error: ${message}`) };
  }

  const warnings: string[] = [];

  if (scan.headerCrcOk === false) {
    warnings.push("FIT header CRC mismatch (parsed anyway)");
  }
  if (scan.fileCrcOk === false) {
    warnings.push("FIT file CRC mismatch (parsed anyway)");
  }

  const sessions = parsed.sessions ?? [];
  if (sessions.length > 1) {
    warnings.push(`FIT file has ${sessions.length} sessions; only the first is used`);
  }
  const session: ParsedSession | undefined = sessions[0];

  if (session?.sport !== undefined && session.sport !== GOLF_SPORT) {
    warnings.push(`FIT session sport is "${truncateEcho(String(session.sport))}", not golf — imported anyway`);
  }

  const fixesRaw: ImportedFix[] = [];
  for (const rec of parsed.records ?? []) {
    if (rec.position_lat === undefined || rec.position_long === undefined || !rec.timestamp) {
      continue;
    }
    const lat = rec.position_lat;
    const lon = rec.position_long;
    const timestamp = rec.timestamp.getTime();
    if (!isValidLat(lat) || !isValidLon(lon) || !Number.isFinite(timestamp)) {
      warnings.push("a FIT record had an invalid lat/lon/timestamp and was dropped");
      continue;
    }
    const accuracyMeters = sanitizeAccuracy(rec.gps_accuracy);
    fixesRaw.push({
      lat,
      lon,
      timestamp,
      ...(accuracyMeters !== undefined ? { accuracyMeters } : {}),
    });
  }
  const { fixes, warnings: capWarnings } = capAndSortFixes(fixesRaw);
  warnings.push(...capWarnings);

  const scorecard = extractGolfScorecard(scan.globalMessageCounts);
  warnings.push(...scorecard.warnings);

  const device = deviceStringFrom(parsed);
  const courseNameHint = scorecard.courseNameHint !== undefined ? sanitizeText(scorecard.courseNameHint) : undefined;

  const round: ImportedRound = {
    source: "file_import",
    format: "fit",
    fixes,
    warnings,
    ...(device !== undefined ? { device } : {}),
    ...(courseNameHint !== undefined ? { courseNameHint } : {}),
    ...(scorecard.holes !== undefined ? { holes: scorecard.holes } : {}),
    ...(scorecard.scores !== undefined ? { scores: scorecard.scores } : {}),
    ...(scorecard.totalScore !== undefined ? { totalScore: scorecard.totalScore } : {}),
  };

  if (fixes.length > 0) {
    // A routed import gets real timestamps, never a derived date (build
    // plan A2-17: `localDate` is for date-only evidence specifically).
    round.startedAt = fixes[0]!.timestamp;
    round.endedAt = fixes[fixes.length - 1]!.timestamp;
  } else {
    // Routeless: `localDate` only, per build plan A2-17/§4.5 — never
    // `startedAt`/`endedAt` here, even when the file's `session` message
    // carries start/end times, so this can never look like route
    // evidence downstream.
    const fromLocalTimestamp =
      scorecard.localDate ?? localDateFromLocalTimestamp(parsed.activity?.local_timestamp);
    if (fromLocalTimestamp !== undefined) {
      round.localDate = fromLocalTimestamp;
    } else if (options.tz !== undefined) {
      const anyInstant =
        session?.timestamp ?? session?.start_time ?? parsed.activity?.timestamp ?? parsed.file_ids?.[0]?.time_created;
      const tzDate = anyInstant ? localDateForTz(anyInstant.getTime(), options.tz) : undefined;
      if (tzDate !== undefined) {
        round.localDate = tzDate;
      } else {
        warnings.push(`could not derive a local date using tz "${truncateEcho(options.tz)}"`);
      }
    } else {
      warnings.push(
        "no route, no FIT activity.local_timestamp, and no facility tz option provided; local date left undefined",
      );
    }
  }

  round.warnings = finalizeWarnings(warnings);
  return { ok: true, round };
}
