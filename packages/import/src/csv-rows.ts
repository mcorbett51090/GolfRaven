/**
 * A minimal RFC 4180 CSV tokenizer: comma-separated fields, `"..."`
 * quoting with `""` as an escaped quote inside a quoted field, and a
 * quoted field allowed to contain embedded commas and newlines. Rows are
 * separated by `\r\n` or `\n`. No external dependency — the grammar is
 * small and this package's CSV format (`parse-csv.ts`) is itself minimal.
 */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const n = text.length;

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
  // Last field/row, if the input didn't end with a newline.
  if (field.length > 0 || row.length > 0) {
    endRow();
  }
  // Drop a single trailing fully-empty row (a common trailing-newline
  // artifact), but never drop a genuine blank line in the middle.
  if (rows.length > 0) {
    const last = rows[rows.length - 1]!;
    if (last.length === 1 && last[0] === "") {
      rows.pop();
    }
  }
  return rows;
}
