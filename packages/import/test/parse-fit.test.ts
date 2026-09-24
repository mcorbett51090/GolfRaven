import { describe, expect, it } from "vitest";
import { FitEncoder, FitBaseType } from "fit-file-parser";
import { parseFitFile } from "../src/parse-fit.js";
import { MAX_INPUT_BYTES } from "../src/safety.js";
import {
  buildGolfActivityFit,
  corruptFitRecordBytes,
  toSemicircles,
  truncateFit,
} from "./fixtures/fit-helpers.js";

const COURSE_LAT = 43.65;
const COURSE_LON = -79.38;

function trackAround(n: number, startTime: Date) {
  return Array.from({ length: n }, (_, i) => ({
    lat: COURSE_LAT + i * 0.0002,
    lon: COURSE_LON + i * 0.0002,
    time: new Date(startTime.getTime() + i * 60_000),
    accuracyMeters: 5,
  }));
}

describe("parseFitFile: golf activity with a GPS track", () => {
  it("returns fixes, device, and a matching start/end", async () => {
    const startTime = new Date("2026-06-01T14:00:00Z");
    const bytes = buildGolfActivityFit({
      productName: "Approach S62",
      startTime,
      endTime: new Date("2026-06-01T17:30:00Z"),
      records: trackAround(6, startTime),
    });

    const result = await parseFitFile(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.round.format).toBe("fit");
    expect(result.round.source).toBe("file_import");
    expect(result.round.fixes).toHaveLength(6);
    expect(result.round.fixes[0]!.timestamp).toBeLessThan(result.round.fixes[5]!.timestamp);
    expect(result.round.startedAt).toBe(result.round.fixes[0]!.timestamp);
    expect(result.round.endedAt).toBe(result.round.fixes[5]!.timestamp);
    expect(result.round.localDate).toBeUndefined();
    expect(result.round.device).toContain("garmin");
    expect(result.round.device).toContain("Approach S62");
    expect(result.round.fixes[0]!.accuracyMeters).toBe(5);
  });

  it("sorts fixes even when the file's record order is out of order", async () => {
    const startTime = new Date("2026-06-01T14:00:00Z");
    const points = trackAround(4, startTime).reverse();
    const bytes = buildGolfActivityFit({ startTime, records: points });

    const result = await parseFitFile(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const timestamps = result.round.fixes.map((f) => f.timestamp);
    expect(timestamps).toEqual([...timestamps].sort((a, b) => a - b));
  });
});

describe("parseFitFile: golf activity without a track", () => {
  it("returns an empty fixes array and falls back to session start/end", async () => {
    const startTime = new Date("2026-06-02T13:00:00Z");
    const endTime = new Date("2026-06-02T16:45:00Z");
    const bytes = buildGolfActivityFit({ startTime, endTime, records: [] });

    const result = await parseFitFile(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toEqual([]);
    expect(result.round.startedAt).toBe(startTime.getTime());
    expect(result.round.endedAt).toBe(endTime.getTime());
    expect(result.round.localDate).toBeUndefined();
  });
});

describe("parseFitFile: a corrupt file", () => {
  it("is refused rather than throwing", async () => {
    const valid = buildGolfActivityFit({ records: trackAround(3, new Date("2026-06-01T14:00:00Z")) });
    const corrupt = corruptFitRecordBytes(valid);

    await expect(parseFitFile(corrupt)).resolves.toEqual(
      expect.objectContaining({ ok: false, error: expect.stringContaining("FIT") }),
    );
  });
});

describe("parseFitFile: a truncated file", () => {
  it("is refused rather than throwing", async () => {
    const valid = buildGolfActivityFit({ records: trackAround(10, new Date("2026-06-01T14:00:00Z")) });
    const truncated = truncateFit(valid, Math.floor(valid.length * 0.6));

    const result = await parseFitFile(truncated);
    expect(result.ok).toBe(false);
  });

  it("also refuses a file cut off before the 12-byte minimum", async () => {
    const result = await parseFitFile(new Uint8Array([0x0e, 1, 2, 3]));
    expect(result.ok).toBe(false);
  });
});

describe("parseFitFile: unmapped FIT messages (scorecard stand-in)", () => {
  it("reports the unknown message number as a warning instead of dropping the round", async () => {
    const bytes = buildGolfActivityFit({
      records: trackAround(2, new Date("2026-06-01T14:00:00Z")),
      includeUnknownMessage: true,
    });

    const result = await parseFitFile(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(2);
    expect(result.round.warnings.some((w) => w.includes("65280"))).toBe(true);
    expect(result.round.warnings.some((w) => w.toLowerCase().includes("scorecard"))).toBe(true);
  });
});

describe("parseFitFile: non-golf sport", () => {
  it("imports anyway but warns", async () => {
    const bytes = buildGolfActivityFit({ sport: 1 /* running */ });
    const result = await parseFitFile(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.warnings.some((w) => w.toLowerCase().includes("not golf"))).toBe(true);
  });
});

describe("parseFitFile: invalid record coordinates", () => {
  it("drops an out-of-range fix and warns, keeping the rest of the round", async () => {
    const startTime = new Date("2026-06-01T14:00:00Z");
    const enc = new FitEncoder();
    enc.writeMessage(0, [{ number: 1, size: 2, baseType: FitBaseType.Uint16, value: 1 }]);
    enc.writeMessage(18, [
      { number: 2, size: 4, baseType: FitBaseType.Uint32, value: FitEncoder.toFitTimestamp(startTime) },
      { number: 5, size: 1, baseType: FitBaseType.Enum, value: 25 },
      {
        number: 253,
        size: 4,
        baseType: FitBaseType.Uint32,
        value: FitEncoder.toFitTimestamp(new Date(startTime.getTime() + 3600_000)),
      },
    ]);
    // A valid record.
    enc.writeMessage(
      20,
      [
        { number: 0, size: 4, baseType: FitBaseType.Sint32, value: toSemicircles(COURSE_LAT) },
        { number: 1, size: 4, baseType: FitBaseType.Sint32, value: toSemicircles(COURSE_LON) },
        { number: 253, size: 4, baseType: FitBaseType.Uint32, value: FitEncoder.toFitTimestamp(startTime) },
      ],
      1,
    );
    // An out-of-range "latitude" (100°, a valid sint32 semicircle value but
    // outside ±90°) — a device bug or bit-flip, not something a real GPS
    // chip would report, but the safety net must not trust the file.
    enc.writeMessage(
      20,
      [
        { number: 0, size: 4, baseType: FitBaseType.Sint32, value: toSemicircles(100) },
        { number: 1, size: 4, baseType: FitBaseType.Sint32, value: toSemicircles(COURSE_LON) },
        {
          number: 253,
          size: 4,
          baseType: FitBaseType.Uint32,
          value: FitEncoder.toFitTimestamp(new Date(startTime.getTime() + 60_000)),
        },
      ],
      1,
    );
    const bytes = enc.close();

    const result = await parseFitFile(bytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.round.fixes).toHaveLength(1);
    expect(result.round.warnings.some((w) => w.includes("invalid"))).toBe(true);
  });
});

describe("parseFitFile: oversized input", () => {
  it("is refused before any parsing work", async () => {
    const oversized = new Uint8Array(MAX_INPUT_BYTES + 1);
    const result = await parseFitFile(oversized);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("bytes");
  });
});
