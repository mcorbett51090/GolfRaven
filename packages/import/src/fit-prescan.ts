/**
 * A cheap, allocation-free walk over a FIT file's record headers —
 * before `fit-file-parser` ever sees the bytes — added after the Opus
 * security gate found that a 19 MB crafted FIT file (millions of tiny
 * record messages, or a handful of definitions with 255 fields each
 * repeated thousands of times) drove `fit-file-parser` to 2–3.4 GB peak
 * RSS and up to 30 s wall time. `fit-file-parser` has no message-count or
 * field-count limit of its own — every record becomes a decoded object,
 * so file size alone doesn't bound the damage a densely-packed file can
 * do.
 *
 * This walker never decodes a field value; it only reads record/
 * definition *headers* (a handful of bytes each) to compute how long
 * each message is and advance past it, tallying two cheap counters that
 * `parse-fit.ts` checks *before* handing the bytes to the real decoder:
 * total message count, and cumulative field-definition count (which
 * catches the "few messages, absurdly large definitions" flood shape
 * that a message-count cap alone would miss). It also tallies which
 * global message numbers actually occur, replacing `fit-file-parser`'s
 * `includeUnmappedMessages` option (which retains full raw field data
 * for every unmapped message — exactly the kind of per-message
 * allocation this module exists to avoid).
 *
 * It also verifies the header/file CRCs itself (the same CRC-16/ARC
 * algorithm `fit-file-parser`'s own encoder uses), since `parse-fit.ts`
 * always parses with `force: true` (tolerating a bad CRC, because real
 * devices occasionally ship one) but the build plan asks that a mismatch
 * still be surfaced as a warning rather than silently ignored.
 *
 * **The compressed-timestamp bypass (round 2 security-gate finding).** A
 * FIT "compressed timestamp" record header (top bit set) omits its
 * timestamp field's bytes from the wire entirely — the timestamp is a
 * 5-bit offset folded into the header byte itself instead — but
 * `fit-file-parser` only applies that omission when field 253
 * (timestamp) is the definition's *first* native field. A definition
 * declaring `{fieldNumber: 253, size: 255}` made this walker and the
 * real decoder disagree on how many bytes each compressed record
 * consumes (the walker used the full declared size; the decoder used 0,
 * since it never reads that field's bytes for a compressed record at
 * all) — so ~20k "messages" by this walker's old counting decoded into
 * ~5.2M by the real one, entirely past the message-count cap. Fixed two
 * ways, deliberately redundant: (a) any definition declaring field 253
 * with a size other than 4 is refused outright (closes the exploit
 * regardless of the byte-counting logic), and (b) the byte-counting
 * logic itself now mirrors the decoder's exact rule — see
 * `compressedRecordByteLength` below — so the two can never silently
 * drift apart again even for a shape neither of us has thought of yet.
 */

/** Refuse a FIT file with more than this many total messages
 * (definitions + data records combined) — chosen well above what any
 * real multi-hour round produces (a few thousand at most) and well below
 * what turns "cheap per-message bookkeeping" into a real CPU/memory
 * cost. */
export const MAX_FIT_MESSAGES = 250_000;

/** Refuse a FIT file whose definitions declare more than this many
 * fields in total (summed across every definition message seen,
 * including redefinitions) — catches the "few enormous definitions"
 * flood shape, which a plain message-count cap doesn't bound on its own
 * (FIT's field count is a single byte, so no *individual* definition can
 * declare more than 255 fields — the danger is many such definitions in
 * a row). */
export const MAX_FIT_DEFINITION_FIELDS = 250_000;

/** The global FIT message numbers this package actually reads
 * (`file_id` 0, `session` 18, `record` 20, `activity` 34) plus a small
 * set of other standard messages common enough in a real device export
 * that flagging them as "unmapped" would just be noise (`event` 21,
 * `device_info` 23, `lap` 19, `sport` 12, `device_settings` 2,
 * `file_creator` 49, `user_profile` 3). This is a curated allowlist, not
 * the full ~200-entry FIT SDK profile table — the previous version of
 * this warning relied on `fit-file-parser`'s own full profile via
 * `includeUnmappedMessages`, which is exactly the option this module
 * exists to avoid (it retains full field data per unmapped message). The
 * trade-off is honest: a legitimate standard message this package
 * doesn't otherwise care about, but that also isn't on this short list,
 * will now be reported as "unmapped" even though a full profile lookup
 * would recognize it. That's a false positive in a *warning*, never a
 * dropped or misread field — worth it for not reintroducing the
 * allocation this whole module exists to bound. */
export const KNOWN_FIT_MESSAGE_NUMBERS: ReadonlySet<number> = new Set([
  0, 2, 3, 12, 18, 19, 20, 21, 23, 34, 49,
]);

export interface FitPrescanSuccess {
  ok: true;
  headerLength: number;
  /** `headerLength + declaredDataLength` — the offset the trailing
   * 2-byte file CRC starts at, if present. */
  crcStart: number;
  messageCount: number;
  /** Occurrences of each global message number actually seen in a
   * *data* record (definitions aren't counted here — a definition with
   * no data record using it never produced a message). */
  globalMessageCounts: Map<number, number>;
  /** `undefined` when the 12-byte header form is used (no header CRC to
   * check). */
  headerCrcOk?: boolean;
  /** `undefined` when there's no trailing file CRC to check at all
   * (`fileCrcMissing` is `true` in that case) — distinct from a *wrong*
   * CRC (`false`), which still means the file declared one. */
  fileCrcOk?: boolean;
  /** True when the file has no room at all for the trailing 2-byte file
   * CRC (the FIT spec always expects one, `force: true` notwithstanding)
   * — `parse-fit.ts` warns on this distinctly from a CRC *mismatch*. */
  fileCrcMissing: boolean;
}

export interface FitPrescanFailure {
  ok: false;
  error: string;
}

export type FitPrescanResult = FitPrescanSuccess | FitPrescanFailure;

function calculateFitCrc(
  bytes: Uint8Array,
  start: number,
  end: number,
): number {
  let crc = 0;
  for (let i = start; i < end; i++) {
    let value = crc ^ bytes[i]!;
    for (let bit = 0; bit < 8; bit++) {
      value = value & 1 ? (value >>> 1) ^ 0xa001 : value >>> 1;
    }
    crc = value;
  }
  return crc;
}

interface Definition {
  globalMessageNumber: number;
  /** Total bytes of one *normal* data record using this definition (sum
   * of every native + developer field's declared size). */
  recordByteLength: number;
  /** Total bytes of one *compressed-timestamp* data record using this
   * definition — see this file's doc comment on the compressed-
   * timestamp bypass for why this can differ from `recordByteLength`. */
  compressedRecordByteLength: number;
}

export interface PrescanOptions {
  signal?: AbortSignal;
  /** How often (in messages processed) to check `signal.aborted`. A
   * synchronous walk can only be interrupted between iterations, not
   * mid-iteration — see `parse-fit.ts`'s doc comment on `parseRound`. */
  abortCheckInterval?: number;
}

/** Walks a FIT file's record structure without decoding any field value.
 * Returns `{ok:false}` the moment the file is malformed, out of bounds,
 * or exceeds either cap — including, for the cap checks, *before*
 * finishing the walk over the rest of a hostile file (so a 250,001st
 * message aborts immediately rather than after walking the other
 * millions). */
export function prescanFit(
  bytes: Uint8Array,
  options: PrescanOptions = {},
): FitPrescanResult {
  const abortCheckInterval = options.abortCheckInterval ?? 5000;

  if (bytes.length < 12) {
    return { ok: false, error: "FIT file too small (under 12 bytes)" };
  }
  const headerLength = bytes[0]!;
  if (headerLength !== 12 && headerLength !== 14) {
    return { ok: false, error: `unexpected FIT header size ${headerLength}` };
  }
  if (bytes.length < headerLength) {
    return {
      ok: false,
      error: "FIT file shorter than its own declared header size",
    };
  }
  const magic = String.fromCharCode(
    bytes[8]!,
    bytes[9]!,
    bytes[10]!,
    bytes[11]!,
  );
  if (magic !== ".FIT") {
    return { ok: false, error: 'missing ".FIT" file-type marker in header' };
  }
  const dataLength = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  ).getUint32(4, true);
  const crcStart = headerLength + dataLength;
  if (crcStart > bytes.length || crcStart < headerLength) {
    // The second condition catches a declared length so large that
    // `headerLength + dataLength` wraps in a way that would otherwise
    // slip past the first bounds check (defensive; `dataLength` is a
    // uint32 read via DataView so it can't itself be negative, but keep
    // the check explicit rather than relying on that fact silently).
    return {
      ok: false,
      error: "FIT file data length exceeds the actual input size",
    };
  }

  let headerCrcOk: boolean | undefined;
  if (headerLength === 14) {
    const declared = bytes[12]! | (bytes[13]! << 8);
    if (declared !== 0) {
      headerCrcOk = declared === calculateFitCrc(bytes, 0, 12);
    }
  }
  let fileCrcOk: boolean | undefined;
  const fileCrcMissing = crcStart + 2 > bytes.length;
  if (!fileCrcMissing) {
    const declared = bytes[crcStart]! | (bytes[crcStart + 1]! << 8);
    if (declared !== 0) {
      fileCrcOk = declared === calculateFitCrc(bytes, 0, crcStart);
    }
  }

  const definitions = new Map<number, Definition>();
  const globalMessageCounts = new Map<number, number>();
  let messageCount = 0;
  let totalDefinitionFields = 0;
  let index = headerLength;

  while (index < crcStart) {
    if (options.signal?.aborted && messageCount % abortCheckInterval === 0) {
      return { ok: false, error: "FIT prescan aborted" };
    }

    const headerByte = bytes[index]!;
    const isCompressedTimestamp = (headerByte & 0x80) !== 0;
    const isDefinition = !isCompressedTimestamp && (headerByte & 0x40) !== 0;
    const localType = isCompressedTimestamp
      ? (headerByte >> 5) & 0x3
      : headerByte & 0x0f;
    index += 1;

    if (isDefinition) {
      const hasDeveloperFields = (headerByte & 0x20) !== 0;
      if (index + 5 > crcStart) {
        return { ok: false, error: "truncated FIT definition record" };
      }
      const architecture = bytes[index + 1]!;
      const littleEndian = architecture === 0;
      const globalMessageNumber = littleEndian
        ? bytes[index + 2]! | (bytes[index + 3]! << 8)
        : (bytes[index + 2]! << 8) | bytes[index + 3]!;
      const numFields = bytes[index + 4]!;
      index += 5;

      if (index + numFields * 3 > crcStart) {
        return { ok: false, error: "truncated FIT definition field list" };
      }
      let recordByteLength = 0;
      let firstFieldNumber: number | undefined;
      let firstFieldSize = 0;
      for (let f = 0; f < numFields; f++) {
        const fieldNumber = bytes[index + f * 3]!;
        const fieldSize = bytes[index + f * 3 + 1]!;
        // Fix (a): the compressed-timestamp bypass depends on declaring
        // field 253 (timestamp) with a non-standard size (the parser
        // always treats it as a 4-byte uint32 regardless of what a
        // definition claims — see fit-file-parser's `binary.js`
        // `readData`/`FIT.types`). Refusing any other declared size
        // closes the exploit outright, independent of the byte-counting
        // fix below.
        if (fieldNumber === 253 && fieldSize !== 4) {
          return {
            ok: false,
            error: `FIT definition declares timestamp field 253 with size ${fieldSize}, not 4; refused`,
          };
        }
        if (f === 0) {
          firstFieldNumber = fieldNumber;
          firstFieldSize = fieldSize;
        }
        recordByteLength += fieldSize;
      }
      index += numFields * 3;
      totalDefinitionFields += numFields;

      let numDevFields = 0;
      if (hasDeveloperFields) {
        if (index + 1 > crcStart) {
          return { ok: false, error: "truncated FIT developer field count" };
        }
        numDevFields = bytes[index]!;
        index += 1;
        if (index + numDevFields * 3 > crcStart) {
          return { ok: false, error: "truncated FIT developer field list" };
        }
        for (let f = 0; f < numDevFields; f++) {
          recordByteLength += bytes[index + f * 3 + 1]!;
        }
        index += numDevFields * 3;
        totalDefinitionFields += numDevFields;
      }

      // Fix (b): mirror `fit-file-parser`'s own rule for a compressed-
      // timestamp record's byte length exactly (`binary.js`'s
      // `readRecord`: `isCompressedTimestamp && i === 0 && fDef.fDefNo
      // === 253` skips consuming that field's bytes — and *only* when
      // it's the definition's first native field). Any other shape
      // (253 elsewhere in the field list, or absent) consumes the full
      // `recordByteLength`, exactly like a normal record — getting this
      // asymmetric special case exactly right, not just "field 253 is
      // always free", is what keeps the prescan's message boundaries
      // identical to the real decoder's.
      const compressedRecordByteLength =
        firstFieldNumber === 253
          ? recordByteLength - firstFieldSize
          : recordByteLength;

      definitions.set(localType, {
        globalMessageNumber,
        recordByteLength,
        compressedRecordByteLength,
      });
      messageCount += 1;
    } else {
      const def = definitions.get(localType);
      if (!def) {
        return {
          ok: false,
          error: "FIT data record has no matching definition",
        };
      }
      const bodyLength = isCompressedTimestamp
        ? def.compressedRecordByteLength
        : def.recordByteLength;
      if (index + bodyLength > crcStart) {
        return { ok: false, error: "truncated FIT data record" };
      }
      index += bodyLength;
      messageCount += 1;
      globalMessageCounts.set(
        def.globalMessageNumber,
        (globalMessageCounts.get(def.globalMessageNumber) ?? 0) + 1,
      );
    }

    if (messageCount > MAX_FIT_MESSAGES) {
      return {
        ok: false,
        error: `FIT file has over ${MAX_FIT_MESSAGES} messages; refused`,
      };
    }
    if (totalDefinitionFields > MAX_FIT_DEFINITION_FIELDS) {
      return {
        ok: false,
        error: `FIT file's definitions declare over ${MAX_FIT_DEFINITION_FIELDS} fields in total; refused`,
      };
    }
  }

  return {
    ok: true,
    headerLength,
    crcStart,
    messageCount,
    globalMessageCounts,
    fileCrcMissing,
    ...(headerCrcOk !== undefined ? { headerCrcOk } : {}),
    ...(fileCrcOk !== undefined ? { fileCrcOk } : {}),
  };
}
