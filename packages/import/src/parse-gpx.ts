/**
 * GPX 1.0/1.1 track and route import (build plan §7.3 lane 2). Reads
 * `trkpt`/`rtept` `lat`/`lon` attributes and `time`; `ele` is read but not
 * carried into `ImportedFix` (the matcher has no use for elevation).
 *
 * Parsed with `sax` in strict mode — same pinned version (`1.4.1`) as
 * `tools/p0`. `sax` never performs any I/O of its own (it's a pure string
 * tokenizer), but a `<!DOCTYPE`/external-entity declaration is refused
 * outright before the file is handed to the parser at all, and again if
 * `sax` itself reports a doctype — belt and suspenders against XXE, and
 * "no DTD fetch" is trivially true because nothing in this package ever
 * makes a network or filesystem call.
 */
import { parser as createSaxParser, type Tag, type QualifiedTag } from "sax";
import type { ImportedFix, ImportedRound, ImportResult } from "./types.js";
import { checkInputSize, capAndSortFixes, isValidLat, isValidLon } from "./safety.js";

const DOCTYPE_RE = /<!DOCTYPE|<!ENTITY/i;

function localName(tagName: string): string {
  const i = tagName.indexOf(":");
  return i === -1 ? tagName : tagName.slice(i + 1);
}

interface RawPoint {
  lat: number;
  lon: number;
  timestamp?: number;
}

export function parseGpxFile(bytes: Uint8Array): ImportResult {
  const sizeError = checkInputSize(bytes.byteLength);
  if (sizeError) return { ok: false, error: sizeError };

  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  if (DOCTYPE_RE.test(text)) {
    return { ok: false, error: "GPX file declares a DOCTYPE/ENTITY; refused (XXE policy)" };
  }

  const warnings: string[] = [];
  const points: RawPoint[] = [];
  let device: string | undefined;
  let courseNameHint: string | undefined;
  let trkNameSeen = false;
  let metadataTimeIso: string | undefined;
  let rootTimeIso: string | undefined; // GPX 1.0's top-level <time>, outside <metadata>

  let sawRoot = false;
  let rootIsGpx = false;
  let firstError: string | undefined;

  const stack: string[] = [];
  let textBuf = "";
  let current: { lat: number; lon: number; timeText?: string } | undefined;

  const p = createSaxParser(true, { trim: true, lowercase: false, xmlns: false });

  p.onerror = (err) => {
    if (!firstError) firstError = err.message;
  };
  p.ondoctype = () => {
    if (!firstError) firstError = "GPX file declares a DOCTYPE; refused (XXE policy)";
  };
  // `xmlns: false` (set below) means sax always hands us the plain `Tag`
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
        if (creator && creator.trim().length > 0) device = creator.trim();
      }
    }
    if (name === "trkpt" || name === "rtept") {
      const latRaw = tag.attributes["lat"];
      const lonRaw = tag.attributes["lon"];
      const lat = latRaw !== undefined ? Number(latRaw) : NaN;
      const lon = lonRaw !== undefined ? Number(lonRaw) : NaN;
      current = { lat, lon };
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

    if (name === "time" && current !== undefined && (parent === "trkpt" || parent === "rtept")) {
      current.timeText = textBuf.trim();
    } else if (name === "time" && parent === "metadata") {
      metadataTimeIso = textBuf.trim();
    } else if (name === "time" && parent === "gpx") {
      rootTimeIso = textBuf.trim();
    } else if (name === "name" && parent === "trk" && !trkNameSeen) {
      const v = textBuf.trim();
      if (v.length > 0) {
        courseNameHint = v;
        trkNameSeen = true;
      }
    } else if (name === "name" && parent === "metadata" && !trkNameSeen) {
      const v = textBuf.trim();
      if (v.length > 0) courseNameHint = v;
    } else if (name === "name" && parent === "gpx" && !trkNameSeen) {
      // GPX 1.0's top-level <name>, sibling of <trk>, not <trk>'s own name.
      const v = textBuf.trim();
      if (v.length > 0 && courseNameHint === undefined) courseNameHint = v;
    }

    if ((name === "trkpt" || name === "rtept") && current !== undefined) {
      const { lat, lon, timeText } = current;
      if (!isValidLat(lat) || !isValidLon(lon)) {
        warnings.push(`a <${name}> had an invalid or missing lat/lon and was dropped`);
      } else {
        let timestamp: number | undefined;
        if (timeText && timeText.length > 0) {
          const parsed = Date.parse(timeText);
          if (Number.isFinite(parsed)) {
            timestamp = parsed;
          } else {
            warnings.push(`a <${name}> had an unparseable <time> "${timeText}", timestamp dropped`);
          }
        }
        points.push({ lat, lon, ...(timestamp !== undefined ? { timestamp } : {}) });
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
    if (!firstError) firstError = err instanceof Error ? err.message : String(err);
  }

  if (firstError) {
    return { ok: false, error: `GPX parse error: ${firstError}` };
  }
  if (!sawRoot || !rootIsGpx) {
    return { ok: false, error: "not a GPX file (root element is not <gpx>)" };
  }

  const timed = points.filter((pt): pt is RawPoint & { timestamp: number } => pt.timestamp !== undefined);
  const untimedCount = points.length - timed.length;
  if (untimedCount > 0 && timed.length > 0) {
    warnings.push(`${untimedCount} track point(s) had no <time> and were dropped from the route`);
  }

  const fixesRaw: ImportedFix[] = timed.map((pt) => ({ lat: pt.lat, lon: pt.lon, timestamp: pt.timestamp }));
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
    round.startedAt = fixes[0]!.timestamp;
    round.endedAt = fixes[fixes.length - 1]!.timestamp;
  } else {
    // No usable route. Fall back to a file-level timestamp for a
    // date-only round (build plan A2-17), preferring GPX 1.1's
    // <metadata><time> then GPX 1.0's top-level <time>.
    const fallbackIso = metadataTimeIso || rootTimeIso;
    const fallbackMs = fallbackIso ? Date.parse(fallbackIso) : NaN;
    if (Number.isFinite(fallbackMs)) {
      round.localDate = new Date(fallbackMs).toISOString().slice(0, 10);
    } else if (points.length === 0) {
      warnings.push("GPX file has no track/route points");
    } else {
      warnings.push("no usable timestamp (per-point or file-level) found; round has no date");
    }
  }

  return { ok: true, round };
}
