/**
 * GPX 1.0/1.1 track and route import (build plan §7.3 lane 2). Reads
 * `trkpt`/`rtept` `lat`/`lon` attributes and `time`; `ele` is read but not
 * carried into `ImportedFix` (the matcher has no use for elevation).
 *
 * Parsed with `sax` in strict mode — same pinned version (`1.4.1`) as
 * `tools/p0`, imported the same way (`import sax from "sax"`, per
 * `tools/p0/src/health-export-xml.ts`). `sax` never performs any I/O of
 * its own (it's a pure string tokenizer), but a `<!DOCTYPE`/external-
 * entity declaration is refused outright before the file is handed to
 * the parser at all, and again if `sax` itself reports a doctype — belt
 * and suspenders against XXE, and "no DTD fetch" is trivially true
 * because nothing in this package ever makes a network or filesystem
 * call.
 *
 * Timestamps use `timestamps.ts`'s strict ISO 8601 (`Z`/offset required)
 * parser, not `Date.parse` — see that module's doc comment for why.
 * Lat/lon attributes are validated with a decimal-only regex
 * (`safety.ts`'s `parseStrictDecimal`) before ever calling `Number()`, so
 * an empty `lat=""` can never silently become `0`.
 */
import sax from "sax";
import type { Tag, QualifiedTag } from "sax";
import type { ImportedFix, ImportedRound, ImportResult } from "./types.js";
import {
  checkInputSize,
  capAndSortFixes,
  isValidLat,
  isValidLon,
  parseStrictDecimal,
  sanitizeText,
  finalizeWarnings,
  finalizeError,
  truncateEcho,
  MAX_INPUT_BYTES,
} from "./safety.js";
import {
  parseStrictTimestamp,
  localDateForTz,
  type StrictTimestamp,
} from "./timestamps.js";

const DOCTYPE_RE = /<!DOCTYPE|<!ENTITY/i;

export interface ParseGpxOptions {
  /** An IANA timezone — the facility's `tz` (build plan §4.1). Used only
   * to derive `localDate` for a routeless import when no per-point or
   * file-level timestamp carried its own explicit UTC offset. */
  tz?: string;
}

function localName(tagName: string): string {
  const i = tagName.indexOf(":");
  return i === -1 ? tagName : tagName.slice(i + 1);
}

interface RawPoint {
  lat: number;
  lon: number;
  timestamp?: number;
}

export function parseGpxFile(
  bytes: Uint8Array,
  options: ParseGpxOptions = {},
): ImportResult {
  const sizeError = checkInputSize(bytes.byteLength, MAX_INPUT_BYTES);
  if (sizeError) return { ok: false, error: finalizeError(sizeError) };

  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  if (DOCTYPE_RE.test(text)) {
    return {
      ok: false,
      error: "GPX file declares a DOCTYPE/ENTITY; refused (XXE policy)",
    };
  }

  const warnings: string[] = [];
  const points: RawPoint[] = [];
  let device: string | undefined;
  let courseNameHint: string | undefined;
  let trkNameSeen = false;
  let metadataTime: StrictTimestamp | undefined;
  let rootTime: StrictTimestamp | undefined; // GPX 1.0's top-level <time>, outside <metadata>

  let sawRoot = false;
  let rootIsGpx = false;
  let firstError: string | undefined;

  const stack: string[] = [];
  let textBuf = "";
  let current:
    | { lat: number | undefined; lon: number | undefined; timeText?: string }
    | undefined;

  const p = sax.parser(true, { trim: true, lowercase: false, xmlns: false });

  p.onerror = (err) => {
    if (!firstError) firstError = err.message;
  };
  p.ondoctype = () => {
    if (!firstError)
      firstError = "GPX file declares a DOCTYPE; refused (XXE policy)";
  };
  // `xmlns: false` (set above) means sax always hands us the plain `Tag`
  // shape at runtime; the cast just matches the SDK's always-union
  // callback signature.
  p.onopentag = (rawTag: Tag | QualifiedTag) => {
    const tag = rawTag as Tag;
    const name = localName(tag.name);
    if (!sawRoot) {
      sawRoot = true;
      rootIsGpx = name === "gpx";
      if (rootIsGpx) {
        const creator = tag.attributes["creator"];
        if (creator && creator.trim().length > 0)
          device = sanitizeText(creator.trim());
      }
    }
    if (name === "trkpt" || name === "rtept") {
      current = {
        lat: parseStrictDecimal(tag.attributes["lat"] ?? ""),
        lon: parseStrictDecimal(tag.attributes["lon"] ?? ""),
      };
    }
    textBuf = "";
    stack.push(name);
  };
  p.ontext = (t: string) => {
    textBuf += t;
  };
  p.onclosetag = (rawName: string) => {
    const name = localName(rawName);
    const parent = stack[stack.length - 2];

    if (
      name === "time" &&
      current !== undefined &&
      (parent === "trkpt" || parent === "rtept")
    ) {
      current.timeText = textBuf.trim();
    } else if (name === "time" && parent === "metadata") {
      metadataTime = parseStrictTimestamp(textBuf.trim());
    } else if (name === "time" && parent === "gpx") {
      rootTime = parseStrictTimestamp(textBuf.trim());
    } else if (name === "name" && parent === "trk" && !trkNameSeen) {
      const v = textBuf.trim();
      if (v.length > 0) {
        courseNameHint = sanitizeText(v);
        trkNameSeen = true;
      }
    } else if (name === "name" && parent === "metadata" && !trkNameSeen) {
      const v = textBuf.trim();
      if (v.length > 0) courseNameHint = sanitizeText(v);
    } else if (name === "name" && parent === "gpx" && !trkNameSeen) {
      // GPX 1.0's top-level <name>, sibling of <trk>, not <trk>'s own name.
      const v = textBuf.trim();
      if (v.length > 0 && courseNameHint === undefined)
        courseNameHint = sanitizeText(v);
    }

    if ((name === "trkpt" || name === "rtept") && current !== undefined) {
      const { lat, lon, timeText } = current;
      if (
        lat === undefined ||
        lon === undefined ||
        !isValidLat(lat) ||
        !isValidLon(lon)
      ) {
        warnings.push(
          `a <${name}> had an invalid or missing lat/lon and was dropped`,
        );
      } else {
        let timestamp: number | undefined;
        if (timeText && timeText.length > 0) {
          const parsedTime = parseStrictTimestamp(timeText);
          if (parsedTime !== undefined) {
            timestamp = parsedTime.ms;
          } else {
            warnings.push(
              `a <${name}> had an unparseable <time> "${truncateEcho(timeText)}", timestamp dropped`,
            );
          }
        }
        points.push({
          lat,
          lon,
          ...(timestamp !== undefined ? { timestamp } : {}),
        });
      }
      current = undefined;
    }

    textBuf = "";
    stack.pop();
  };

  try {
    p.write(text);
    p.close();
  } catch (err) {
    if (!firstError)
      firstError = err instanceof Error ? err.message : String(err);
  }

  if (firstError) {
    return {
      ok: false,
      error: finalizeError(`GPX parse error: ${firstError}`),
    };
  }
  if (!sawRoot || !rootIsGpx) {
    return { ok: false, error: "not a GPX file (root element is not <gpx>)" };
  }

  const timed = points.filter(
    (pt): pt is RawPoint & { timestamp: number } => pt.timestamp !== undefined,
  );
  const untimedCount = points.length - timed.length;
  if (untimedCount > 0 && timed.length > 0) {
    warnings.push(
      `${untimedCount} track point(s) had no <time> and were dropped from the route`,
    );
  }

  const fixesRaw: ImportedFix[] = timed.map((pt) => ({
    lat: pt.lat,
    lon: pt.lon,
    timestamp: pt.timestamp,
  }));
  const { fixes, warnings: capWarnings } = capAndSortFixes(fixesRaw);
  warnings.push(...capWarnings);

  const round: ImportedRound = {
    source: "file_import",
    format: "gpx",
    fixes,
    warnings,
    ...(device !== undefined ? { device } : {}),
    ...(courseNameHint !== undefined ? { courseNameHint } : {}),
  };

  if (fixes.length > 0) {
    // Routed: real timestamps only, never a derived date (A2-17).
    round.startedAt = fixes[0]!.timestamp;
    round.endedAt = fixes[fixes.length - 1]!.timestamp;
  } else {
    // Routeless: `localDate` only (build plan A2-17/§4.5), preferring a
    // file-level timestamp that carries its own explicit offset (used
    // as-is, per the build task's instruction that an offset-bearing
    // source timestamp is authoritative for its own date), then a `tz`
    // option, then nothing.
    const fileLevel = metadataTime ?? rootTime;
    if (fileLevel !== undefined && fileLevel.hasExplicitOffset) {
      round.localDate = fileLevel.literalDate;
    } else if (options.tz !== undefined && fileLevel !== undefined) {
      const tzDate = localDateForTz(fileLevel.ms, options.tz);
      if (tzDate !== undefined) {
        round.localDate = tzDate;
      } else {
        warnings.push(
          `could not derive a local date using tz "${truncateEcho(options.tz)}"`,
        );
      }
    } else if (options.tz !== undefined && fileLevel === undefined) {
      warnings.push(
        "no usable timestamp of any kind found; a tz option alone has nothing to convert",
      );
    } else if (fileLevel !== undefined) {
      // Has a Z-normalized file-level time but no tz to project it
      // through, and no explicit offset to trust as-is.
      warnings.push(
        "file-level <time> is UTC (Z) with no facility tz option; local date left undefined",
      );
    } else if (points.length === 0) {
      warnings.push("GPX file has no track/route points");
    } else {
      warnings.push(
        "no usable timestamp (per-point or file-level) found; local date left undefined",
      );
    }
  }

  round.warnings = finalizeWarnings(warnings);
  return { ok: true, round };
}
