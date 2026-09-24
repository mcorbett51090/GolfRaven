/**
 * A minimal RFC 4180 CSV tokenizer: comma-separated fields, `"..."`
 * quoting with `""` as an escaped quote inside a quoted field, and a
 * quoted field allowed to contain embedded commas and newlines. Rows are
 * separated by `\r\n` or `\n`. No external dependency — the grammar is
 * small and this package's CSV format (`parse-csv.ts`) is itself minimal.
 *
 * **Row cap, checked during the scan (Opus security gate follow-up).** A
 * 19.9 MB file of ~9.9 million empty rows (`,\n` repeated) — well under
 * the 20 MB size cap — took 17.8 seconds to tokenize: millions of tiny
 * row/array allocations, not any one large field, is what actually hurt.
 * `parseCsvRows` now stops scanning the moment it *would* produce more
 * than `maxRows` rows, rather than tokenizing the rest of a hostile file
 * only to have a later cap (fix count, warning count) discard the
 * excess — the same "stop walking, don't just stop using the result"
 * principle as `fit-prescan.ts`'s message-count cap.
 */

export interface CsvRowsResult {
  rows: string[][];
  /** True when the input had more rows than `maxRows` and the scan
   * stopped early — the returned `rows` is a prefix, not the whole
   * file. */
  truncated: boolean;
}

export function parseCsvRows(text: string, maxRows: number = Infinity): CsvRowsResult {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const n = text.length;
  let truncated = false;

  function endField() {
    row.push(field);
    field = "";
  }
  function endRow() {
    endField();
    rows.push(row);
    row = [];
  }

  while (i < n) {
    if (rows.length >= maxRows) {
      truncated = true;
      break;
    }
    const c = text[i]!;
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += c;
      i += 1;
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      i += 1;
      continue;
    }
    if (c === ",") {
      endField();
      i += 1;
      continue;
    }
    if (c === "\r") {
      if (text[i + 1] === "\n") i += 1;
      endRow();
      i += 1;
      continue;
    }
    if (c === "\n") {
      endRow();
      i += 1;
      continue;
    }
    field += c;
    i += 1;
  }
  // Last field/row, if the input didn't end with a newline and we
  // stopped naturally (not via the row cap above).
  if (!truncated && (field.length > 0 || row.length > 0)) {
    endRow();
  }
  // Drop a single trailing fully-empty row (a common trailing-newline
  // artifact), but never drop a genuine blank line in the middle.
  if (!truncated && rows.length > 0) {
    const last = rows[rows.length - 1]!;
    if (last.length === 1 && last[0] === "") {
      rows.pop();
    }
  }
  return { rows, truncated };
}
