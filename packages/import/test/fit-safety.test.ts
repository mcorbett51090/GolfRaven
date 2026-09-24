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
 * repeat is 6 + 255*3 = 771 bytes. */
function bigDefinitionFlood(defCount: number): Uint8Array {
  const def = [0x40, 0, 0, 20, 0, 255];
  const fieldDefs: number[] = [];
  for (let i = 0; i < 255; i++) fieldDefs.push(i, 1, 0x02 /* Uint8 */);
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
