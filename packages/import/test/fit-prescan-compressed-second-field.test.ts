/**
 * Pins the *asymmetric* half of the compressed-timestamp fix
 * (`fit-prescan.ts`'s "fix (b)" doc comment): `fit-file-parser` only
 * omits field 253's bytes from a compressed-timestamp record's wire
 * length when 253 is the definition's *first* native field. This test
 * builds a definition where 253 is the **second** field and confirms
 * the prescan counts the **full** record length — no 4-byte skip — and
 * agrees exactly with `fit-file-parser`'s own low-level record reader,
 * mirroring `/tmp/claude-0/probe/diff.mjs`'s fuzzer methodology at a
 * small, fixed, readable scale instead of a randomized one.
 *
 * Reaches into `fit-file-parser`'s internal `binary.js` (not part of its
 * public `exports` map) via a plain relative path — the same way
 * `diff.mjs` does — specifically because the whole point of this test is
 * to compare against the real decoder's own byte-consumption logic, not
 * a black-box re-implementation of it.
 */
import { describe, expect, it } from "vitest";
import { prescanFit } from "../src/fit-prescan.js";
import { parseFitFile } from "../src/parse-fit.js";
// eslint-disable-next-line import/no-relative-packages
import { readRecord } from "../node_modules/fit-file-parser/dist/binary.js";

function wrap(data: Uint8Array): Uint8Array {
  const header = new Uint8Array(14);
  header[0] = 14;
  header[1] = 0x10;
  new DataView(header.buffer).setUint32(4, data.length, true);
  header.set([0x2e, 0x46, 0x49, 0x54], 8); // ".FIT"
  const out = new Uint8Array(16 + data.length); // +2 for a (blank) trailing CRC
  out.set(header);
  out.set(data, 14);
  return out;
}

/** Walks the file with `fit-file-parser`'s own `readRecord`, the same
 * way `parse-fit.ts`'s real decode eventually will, counting messages
 * and confirming it lands exactly on `crcStart` with no desync. */
function countViaFitFileParser(blob: Uint8Array): { count: number; end: number; crcStart: number } {
  const crcStart = 14 + new DataView(blob.buffer).getUint32(4, true);
  const messageTypes: never[] = [];
  const developerFields: never[] = [];
  const decoderState = {};
  const dataView = new DataView(blob.buffer);
  const options = {
    force: true,
    mode: "list" as const,
    includeUnmappedMessages: false,
    lengthUnit: "m",
    speedUnit: "m/s",
    temperatureUnit: "celsius",
    elapsedRecordField: false,
    pressureUnit: "bar",
  };
  let i = 14;
  let count = 0;
  while (i < crcStart) {
    const r = readRecord(blob, messageTypes, developerFields, i, options, undefined, 0, dataView, decoderState, crcStart);
    if (r.nextIndex <= i) throw new Error("no progress");
    i = r.nextIndex;
    count++;
  }
  return { count, end: i, crcStart };
}

/**
 * A definition for global message 20 (`record`) with two native fields:
 * `position_lat` (field 0, size 4) then `timestamp` (field 253, size 4)
 * — 253 is second, not first. One normal (non-compressed) seed record,
 * then `compressedCount` compressed-timestamp records, each carrying the
 * **full** 8-byte body (4 for lat + 4 for the timestamp field — never
 * skipped, because 253 isn't index 0 here).
 */
function buildSecondFieldFit(compressedCount: number): Uint8Array {
  const def = [0x40, 0, 0, 20, 0, 2, 0, 4, 0x85, 253, 4, 0x86]; // 12 bytes
  const seedRecord = [0x00, 0, 0, 0, 0, 0x10, 0x20, 0x30, 0x40]; // header + lat(4) + timestamp(4)
  const bytes: number[] = [...def, ...seedRecord];
  for (let k = 0; k < compressedCount; k++) {
    bytes.push(0x80, 0, 0, 0, k, 0, 0, 0, 0); // header + lat(4, varies) + timestamp field bytes(4, discarded)
  }
  return wrap(new Uint8Array(bytes));
}

describe("fit-prescan: 253 as the second native field, compressed-timestamp records", () => {
  it("counts the full 8-byte body per compressed record (no 4-byte skip) and matches fit-file-parser exactly", async () => {
    const compressedCount = 3;
    const blob = buildSecondFieldFit(compressedCount);

    const scan = prescanFit(blob);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;

    // 1 definition + 1 seed record + 3 compressed records.
    const expectedMessageCount = 1 + 1 + compressedCount;
    expect(scan.messageCount).toBe(expectedMessageCount);

    // Cross-checked directly against fit-file-parser's own low-level
    // record reader: same count, and it lands exactly on crcStart (no
    // byte-alignment drift in either direction).
    const viaParser = countViaFitFileParser(blob);
    expect(viaParser.end).toBe(viaParser.crcStart);
    expect(viaParser.count).toBe(scan.messageCount);
    expect(viaParser.count).toBe(expectedMessageCount);

    // And the full parse succeeds cleanly — no "truncated"/"no matching
    // definition" errors, which is what a byte-alignment desync would
    // produce.
    const result = await parseFitFile(blob);
    expect(result.ok).toBe(true);
  });

  it("scales the same way for a larger compressed-record count (not a coincidence of a small number)", () => {
    const compressedCount = 200;
    const blob = buildSecondFieldFit(compressedCount);
    const scan = prescanFit(blob);
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    expect(scan.messageCount).toBe(1 + 1 + compressedCount);

    const viaParser = countViaFitFileParser(blob);
    expect(viaParser.count).toBe(scan.messageCount);
    expect(viaParser.end).toBe(viaParser.crcStart);
  });
});
