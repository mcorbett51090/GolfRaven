/**
 * Synthetic FIT file builders for tests, using `fit-file-parser`'s own
 * `FitEncoder` (build plan §7.3 lane 2: "Build synthetic FIT files in the
 * tests with the chosen library's encoder"). Field numbers/base types are
 * taken from `fit-file-parser`'s bundled profile table (the public FIT
 * SDK profile every decoder ships) — see `parse-fit.ts`'s doc comment.
 */
import { FitEncoder, FitBaseType } from "fit-file-parser";

const SEMICIRCLES_PER_DEGREE = Math.pow(2, 31) / 180;

export function toSemicircles(degrees: number): number {
  return Math.round(degrees * SEMICIRCLES_PER_DEGREE);
}

export interface FitRecordPoint {
  lat: number;
  lon: number;
  time: Date;
  accuracyMeters?: number;
}

export interface BuildGolfFitOptions {
  manufacturer?: number; // FIT `manufacturer` enum value; 1 = garmin
  productName?: string;
  timeCreated?: Date;
  sport?: number; // 25 = golf
  startTime?: Date;
  endTime?: Date;
  records?: FitRecordPoint[];
  /** Adds an extra message under an entirely unmapped global message
   * number, to exercise the "unknown FIT message" warning path (a stand-in
   * for the not-yet-decoded Garmin scorecard shape). */
  includeUnknownMessage?: boolean;
}

/** Builds a synthetic golf-activity FIT file: `file_id`, `session`,
 * (optionally) `record`s, and `activity`. */
export function buildGolfActivityFit(options: BuildGolfFitOptions = {}): Uint8Array {
  const enc = new FitEncoder();
  const manufacturer = options.manufacturer ?? 1; // garmin
  const timeCreated = options.timeCreated ?? new Date("2026-06-01T14:00:00Z");
  const startTime = options.startTime ?? new Date("2026-06-01T14:05:00Z");
  const endTime = options.endTime ?? new Date("2026-06-01T17:35:00Z");
  const sport = options.sport ?? 25; // golf

  const fileIdFields: Parameters<FitEncoder["writeMessage"]>[1] = [
    { number: 1, size: 2, baseType: FitBaseType.Uint16, value: manufacturer },
    { number: 4, size: 4, baseType: FitBaseType.Uint32, value: FitEncoder.toFitTimestamp(timeCreated) },
  ];
  if (options.productName) {
    const bytes = FitEncoder.string(options.productName);
    fileIdFields.push({ number: 8, size: bytes.length, baseType: FitBaseType.String, value: bytes });
  }
  enc.writeMessage(0, fileIdFields);

  enc.writeMessage(18, [
    { number: 2, size: 4, baseType: FitBaseType.Uint32, value: FitEncoder.toFitTimestamp(startTime) },
    { number: 5, size: 1, baseType: FitBaseType.Enum, value: sport },
    { number: 253, size: 4, baseType: FitBaseType.Uint32, value: FitEncoder.toFitTimestamp(endTime) },
  ]);

  for (const rec of options.records ?? []) {
    const fields: Parameters<FitEncoder["writeMessage"]>[1] = [
      { number: 0, size: 4, baseType: FitBaseType.Sint32, value: toSemicircles(rec.lat) },
      { number: 1, size: 4, baseType: FitBaseType.Sint32, value: toSemicircles(rec.lon) },
      { number: 253, size: 4, baseType: FitBaseType.Uint32, value: FitEncoder.toFitTimestamp(rec.time) },
    ];
    if (rec.accuracyMeters !== undefined) {
      fields.push({ number: 31, size: 1, baseType: FitBaseType.Uint8, value: rec.accuracyMeters });
    }
    enc.writeMessage(20, fields, 1);
  }

  enc.writeMessage(34, [
    { number: 253, size: 4, baseType: FitBaseType.Uint32, value: FitEncoder.toFitTimestamp(endTime) },
    { number: 1, size: 2, baseType: FitBaseType.Uint16, value: 1 },
  ]);

  if (options.includeUnknownMessage) {
    // A stand-in for Garmin's undecoded golf-scorecard message shape
    // (GARMIN/SCORE/SCORECARD, [unverified]) — any global message number
    // outside the standard FIT profile exercises the same "report,
    // don't drop" path.
    enc.writeMessage(65280, [{ number: 0, size: 1, baseType: FitBaseType.Uint8, value: 42 }]);
  }

  return enc.close();
}

/** Corrupts a valid FIT buffer so the record stream no longer decodes,
 * without touching the header's declared lengths (the file still looks
 * well-formed enough to start parsing, and fails inside the message
 * loop instead — a truncation test covers the length-mismatch path).
 *
 * The very first data byte is always that first message's record header
 * (`0x40 | localMessageNumber` for a definition record). Clearing its
 * top bit turns it into a *data* record referencing a local message type
 * that was never defined — the decoder rejects this deterministically
 * (`FIT data record has no local definition`), confirmed against this
 * decoder directly rather than assumed. */
export function corruptFitRecordBytes(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes);
  const headerLength = copy[0]!;
  copy[headerLength] = 0x00;
  return copy;
}

/** Truncates a valid FIT buffer partway through its data section. The
 * header's declared data length still claims the original size, so the
 * parser's own "file data exceeds input length" bounds check fires. */
export function truncateFit(bytes: Uint8Array, keepBytes: number): Uint8Array {
  return bytes.slice(0, keepBytes);
}
