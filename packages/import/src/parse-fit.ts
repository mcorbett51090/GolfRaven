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
 */
import FitParser from "fit-file-parser";
import type { ParsedFit } from "fit-file-parser";

// `fit-file-parser`'s package exports only re-export `ParsedFit` itself
// (plus the raw-message types) from its root entry, not every nested
// message type — derive `ParsedSession` from it instead of reaching into
// an unexported subpath.
type ParsedSession = NonNullable<ParsedFit["sessions"]>[number];
import type { ImportedFix, ImportedRound, ImportResult } from "./types.js";
import { checkInputSize, capAndSortFixes, isValidLat, isValidLon } from "./safety.js";
import { extractGolfScorecard } from "./parse-fit-scorecard.js";

const GOLF_SPORT = "golf";

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
  return parts.length > 0 ? parts.join(" ") : undefined;
}

function localDateFrom(date: Date | undefined): string | undefined {
  return date && Number.isFinite(date.getTime()) ? date.toISOString().slice(0, 10) : undefined;
}

/** Parses a FIT file's bytes. Pure aside from the decode itself (no
 * filesystem or network access) — `fit-file-parser` reads only the
 * `ArrayBuffer` handed to it. */
export async function parseFitFile(bytes: Uint8Array): Promise<ImportResult> {
  const sizeError = checkInputSize(bytes.byteLength);
  if (sizeError) return { ok: false, error: sizeError };

  const parser = new FitParser({
    force: true,
    mode: "list",
    includeUnmappedMessages: true,
  });

  let parsed: ParsedFit;
  try {
    parsed = await parser.parseAsync(toArrayBuffer(bytes));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: `FIT parse error: ${message}` };
  }

  const warnings: string[] = [];

  const sessions = parsed.sessions ?? [];
  if (sessions.length > 1) {
    warnings.push(`FIT file has ${sessions.length} sessions; only the first is used`);
  }
  const session: ParsedSession | undefined = sessions[0];

  if (session?.sport !== undefined && session.sport !== GOLF_SPORT) {
    warnings.push(`FIT session sport is "${String(session.sport)}", not golf — imported anyway`);
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
    fixesRaw.push({
      lat,
      lon,
      timestamp,
      ...(rec.gps_accuracy !== undefined ? { accuracyMeters: rec.gps_accuracy } : {}),
    });
  }
  const { fixes, warnings: capWarnings } = capAndSortFixes(fixesRaw);
  warnings.push(...capWarnings);

  const scorecard = extractGolfScorecard(parsed);
  warnings.push(...scorecard.warnings);

  const device = deviceStringFrom(parsed);

  const round: ImportedRound = {
    source: "file_import",
    format: "fit",
    fixes,
    warnings,
    ...(device !== undefined ? { device } : {}),
    ...(scorecard.courseNameHint !== undefined ? { courseNameHint: scorecard.courseNameHint } : {}),
    ...(scorecard.holes !== undefined ? { holes: scorecard.holes } : {}),
    ...(scorecard.scores !== undefined ? { scores: scorecard.scores } : {}),
    ...(scorecard.totalScore !== undefined ? { totalScore: scorecard.totalScore } : {}),
  };

  if (fixes.length > 0) {
    round.startedAt = fixes[0]!.timestamp;
    round.endedAt = fixes[fixes.length - 1]!.timestamp;
  } else if (session !== undefined && (session.start_time !== undefined || session.timestamp !== undefined)) {
    const startedAt = session.start_time?.getTime();
    const endedAt = session.timestamp?.getTime();
    if (startedAt !== undefined && Number.isFinite(startedAt)) round.startedAt = startedAt;
    if (endedAt !== undefined && Number.isFinite(endedAt)) round.endedAt = endedAt;
    if (round.startedAt === undefined && round.endedAt === undefined) {
      const fallback = scorecard.localDate ?? localDateFrom(session.start_time ?? session.timestamp);
      if (fallback !== undefined) round.localDate = fallback;
    }
  } else {
    const fallback =
      scorecard.localDate ??
      localDateFrom(parsed.activity?.timestamp) ??
      localDateFrom(parsed.file_ids?.[0]?.time_created);
    if (fallback !== undefined) {
      round.localDate = fallback;
    } else {
      warnings.push("no route and no timestamp of any kind found in this FIT file");
    }
  }

  return { ok: true, round };
}
