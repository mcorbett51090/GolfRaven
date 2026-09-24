/**
 * FIT flood-shape safety tests (Opus security gate follow-up). These
 * mirror the three flood shapes the gate's probe (`f2.mjs`) used to drive
 * `fit-file-parser` to 2–3.4 GB peak RSS / up to 30 s wall time: a
 * message-count flood, a field-count (large-definition) flood, and a
 * declared-length-exceeds-actual-bytes file. Each is built well under the
 * new 5 MB FIT cap, so these specifically exercise `fit-prescan.ts`'s own
 * message/field-count walk — not just the cheap size-cap refusal — and
 * each asserts refusal completes fast (a loose but meaningful proxy for
 * "before decoding": the real decode of a file this size, if it ran,
 * would itself take measurable time under `fit-file-parser`, so a
 * sub-100ms refusal here is strong evidence the real decode never ran).
 */
import { describe, expect, it } from "vitest";
import { parseFitFile } from "../src/parse-fit.js";
import { prescanFit, MAX_FIT_MESSAGES, MAX_FIT_DEFINITION_FIELDS } from "../src/fit-prescan.js";

function header(dataLen: number): Uint8Array {
  const h = new Uint8Array(14);
  h[0] = 14;
  h[1] = 0x10;
  h[2] = 0x08;
  h[3] = 0x08;
  new DataView(h.buffer).setUint32(4, dataLen, true);
  h.set([0x2e, 0x46, 0x49, 0x54], 8); // ".FIT"
  return h;
}

function fileFrom(data: Uint8Array): Uint8Array {
  const h = header(data.length);
  const out = new Uint8Array(14 + data.length + 2);
  out.set(h);
  out.set(data, 14);
  return out;
}

/** A definition for global message 20 (`record`) with zero fields (6
 * bytes: header byte, reserved, architecture, global msg number LE,
 * field count 0), followed by `messageCount` 1-byte data records (each
 * just the record-header byte, referencing local type 0 with a 0-byte
 * body). */
function zeroFieldRecordFlood(messageCount: number): Uint8Array {
  const def = [0x40, 0, 0, 20, 0, 0];
  const data = new Uint8Array(def.length + messageCount);
  data.set(def);
  return fileFrom(data);
}

/** A definition for global message 20 with 255 fields (1 byte each),
 * repeated `defCount` times back to back — no data records at all. Each
 * repeat is 6 + 255*3 = 771 bytes. Every field uses field number 10
 * (deliberately never 253 — a definition-time field number of 253 now
 * triggers the compressed-timestamp-bypass fix's own, more specific
 * "timestamp field must be size 4" refusal, which this test isn't
 * about). */
function bigDefinitionFlood(defCount: number): Uint8Array {
  const def = [0x40, 0, 0, 20, 0, 255];
  const fieldDefs: number[] = [];
  for (let i = 0; i < 255; i++) fieldDefs.push(10, 1, 0x02 /* Uint8 */);
  const one = new Uint8Array([...def, ...fieldDefs]);
  const data = new Uint8Array(one.length * defCount);
  for (let i = 0; i < defCount; i++) data.set(one, i * one.length);
  return fileFrom(data);
}

describe("FIT safety: message-count flood", () => {
  it("prescanFit refuses well before MAX_FIT_MESSAGES worth of bytes are needed, and fast", () => {
    const bytes = zeroFieldRecordFlood(MAX_FIT_MESSAGES + 50_000);
    expect(bytes.length).toBeLessThan(1024 * 1024); // well under the 5 MB cap
    const t0 = performance.now();
    const result = prescanFit(bytes);
    const elapsedMs = performance.now() - t0;
    expect(result.ok).toBe(false);
    expect(elapsedMs).toBeLessThan(500);
  });

  it("parseFitFile refuses the same flood, fast, before any decode", async () => {
    const bytes = zeroFieldRecordFlood(MAX_FIT_MESSAGES + 50_000);
    const t0 = performance.now();
    const result = await parseFitFile(bytes);
    const elapsedMs = performance.now() - t0;
    expect(result.ok).toBe(false);
    expect(elapsedMs).toBeLessThan(500);
  });
});

describe("FIT safety: field-count (large-definition) flood", () => {
  it("prescanFit refuses a file of repeated 255-field definitions, fast", () => {
    const bytes = bigDefinitionFlood(2000); // 2000 * 255 = 510,000 fields
    expect(bytes.length).toBeLessThan(2 * 1024 * 1024); // well under the 5 MB cap
    const t0 = performance.now();
    const result = prescanFit(bytes);
    const elapsedMs = performance.now() - t0;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain(String(MAX_FIT_DEFINITION_FIELDS));
    expect(elapsedMs).toBeLessThan(500);
  });

  it("parseFitFile refuses it too, before any decode", async () => {
    const bytes = bigDefinitionFlood(2000);
    const t0 = performance.now();
    const result = await parseFitFile(bytes);
    const elapsedMs = performance.now() - t0;
    expect(result.ok).toBe(false);
    expect(elapsedMs).toBeLessThan(500);
  });

  it("does NOT refuse a small, legitimate number of large-ish definitions", () => {
    // Sanity check the cap isn't so tight it rejects real files: a
    // handful of full-width definitions (well under the cumulative cap)
    // must still pass the prescan.
    const bytes = bigDefinitionFlood(5); // 5 * 255 = 1,275 fields
    const result = prescanFit(bytes);
    expect(result.ok).toBe(true);
  });
});

describe("FIT safety: declared length exceeds actual input", () => {
  it("is refused immediately from the header alone, without walking any records", () => {
    const h = header(0xfffffff0);
    const bytes = new Uint8Array(100);
    bytes.set(h);
    const t0 = performance.now();
    const result = prescanFit(bytes);
    const elapsedMs = performance.now() - t0;
    expect(result.ok).toBe(false);
    expect(elapsedMs).toBeLessThan(50);
  });
});

describe("FIT safety: the 5 MB size cap refuses before prescan even runs", () => {
  it("refuses a >5 MB file instantly, regardless of its contents", async () => {
    const oversized = new Uint8Array(5 * 1024 * 1024 + 1);
    const t0 = performance.now();
    const result = await parseFitFile(oversized);
    const elapsedMs = performance.now() - t0;
    expect(result.ok).toBe(false);
    expect(elapsedMs).toBeLessThan(50);
  });
});

describe("FIT safety: the compressed-timestamp bypass (round 2 security-gate finding)", () => {
  // A definition for global message `global` (default: 20, record) with
  // one native field: field number 253 (timestamp), declared with a
  // non-standard size. `fit-file-parser` never actually reads field
  // 253's bytes for a *compressed*-timestamp record when it's the
  // definition's first field (the timestamp is folded into the header
  // byte instead) — so a prescan that (wrongly) counted those bytes
  // would advance far more per record than the real decoder does,
  // undercounting the message count by orders of magnitude.
  function compressedTimestampBypass(fieldSize: number, global = 20, byteCount = 1_000_000): Uint8Array {
    const def = [0x40, 0, 0, global & 0xff, (global >> 8) & 0xff, 1, 253, fieldSize, 0x86];
    const data = new Uint8Array(def.length + byteCount);
    data.set(def);
    data.fill(0x80, def.length); // compressed-timestamp header bytes, local type 0
    return fileFrom(data);
  }

  it("refuses a definition declaring timestamp field 253 with a non-4 size, before decode", async () => {
    const bytes = compressedTimestampBypass(255);
    const t0 = performance.now();
    const scanResult = prescanFit(bytes);
    const elapsedMs = performance.now() - t0;
    expect(scanResult.ok).toBe(false);
    if (!scanResult.ok) {
      expect(scanResult.error).toContain("253");
      expect(scanResult.error).toContain("4");
    }
    expect(elapsedMs).toBeLessThan(100);

    const parseResult = await parseFitFile(bytes);
    expect(parseResult.ok).toBe(false);
  });

  it("refuses the same bypass shape on an unmapped global message number", () => {
    const bytes = compressedTimestampBypass(255, 0xff00);
    const result = prescanFit(bytes);
    expect(result.ok).toBe(false);
  });

  it("refuses the bypass even when a legitimate timestamp precedes it (a real prior lastTimestamp)", () => {
    const seedDef = [0x40, 0, 0, 20, 0, 1, 253, 4, 0x86];
    const seedRecord = [0x00, 0x10, 0x20, 0x30, 0x40]; // a normal, correctly-sized record
    const badDef = [0x40, 0, 0, 20, 0, 1, 253, 255, 0x86];
    const prefix = new Uint8Array([...seedDef, ...seedRecord, ...badDef]);
    const data = new Uint8Array(prefix.length + 1_000_000);
    data.set(prefix);
    data.fill(0x80, prefix.length);
    const result = prescanFit(fileFrom(data));
    expect(result.ok).toBe(false);
  });

  it("does not falsely refuse a definition where field 253 is correctly sized (size 4)", () => {
    const bytes = compressedTimestampBypass(4, 20, 100);
    const result = prescanFit(bytes);
    expect(result.ok).toBe(true);
  });

  it("does not falsely refuse field 253 with a non-4 size when it isn't a timestamp-typed field elsewhere (still refused — 253 always means timestamp)", () => {
    // Sanity: the rule applies to field number 253 regardless of where
    // it appears in the field list, not only when it's field index 0.
    const def = [0x40, 0, 0, 20, 0, 2, 0, 4, 0x85, 253, 255, 0x86];
    const bytes = fileFrom(new Uint8Array(def));
    const result = prescanFit(bytes);
    expect(result.ok).toBe(false);
  });

  it("mirrors the real decoder's byte-skip rule for a legitimate compressed-timestamp record (fix b)", async () => {
    // field 253 is size 4 (legitimate) and IS the definition's only (so
    // first) field, so a compressed-timestamp record using it carries 0
    // bytes for it on the wire (per fit-file-parser's own rule) —
    // prescan and the real decoder must agree on where the next record
    // starts, i.e. a compressed record here is 1 byte (just the header)
    // total, not 1 + 4. Seed a real timestamp first so decoding a
    // compressed record doesn't fail for lack of a `lastTimestamp`.
    const def = [0x40, 0, 0, 20, 0, 1, 253, 4, 0x86]; // 9 bytes
    const seedRecord = [0x00, 0x00, 0x10, 0x20, 0x30]; // header (local 0) + 4-byte timestamp
    const compressedRecords = [0x80, 0x80, 0x80]; // 3 compressed-timestamp records, 1 byte each
    const bytes = new Uint8Array([...def, ...seedRecord, ...compressedRecords]);
    const file = fileFrom(bytes);

    const scanResult = prescanFit(file);
    expect(scanResult.ok).toBe(true);
    if (scanResult.ok) expect(scanResult.messageCount).toBe(5); // def + seed record + 3 compressed records

    const parseResult = await parseFitFile(file);
    expect(parseResult.ok).toBe(true);
    if (parseResult.ok) expect(parseResult.round.warnings.join(" ")).not.toContain("truncated");
  });
});
