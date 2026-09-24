/**
 * Builds a tiny, deterministic, valid single-page PDF containing exactly
 * `text` as its one line of content — used to prove gate S3's pinned PDF
 * extractor (`unpdf`) actually extracts real text from real PDF bytes,
 * without committing a binary fixture. Hand-rolled (object table + xref +
 * trailer) rather than pulling in a PDF-WRITING dependency, since the tool
 * under test only ever needs to READ a PDF. `mediaWidth` is generously wide
 * so the single text line is never clipped by the page's own bounds
 * (verified empirically against `unpdf`/pdf.js: a narrow MediaBox truncates
 * `extractText`'s output well before the glyphs would visually overflow).
 */
export function buildMinimalPdf(text: string, mediaWidth = 4000): Buffer {
  const escaped = text.replace(/([()\\])/g, "\\$1");
  const stream = `BT /F1 18 Tf 20 100 Td (${escaped}) Tj ET`;
  const header = "%PDF-1.4\n";
  const objStrs = [
    `1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`,
    `2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n`,
    `3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${mediaWidth} 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n`,
    `4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`,
    `5 0 obj\n<< /Length ${Buffer.byteLength(stream, "latin1")} >>\nstream\n${stream}\nendstream\nendobj\n`,
  ];
  let body = "";
  const xrefOffsets: number[] = [];
  let cursor = Buffer.byteLength(header, "latin1");
  for (const s of objStrs) {
    xrefOffsets.push(cursor);
    body += s;
    cursor += Buffer.byteLength(s, "latin1");
  }
  const xrefStart = cursor;
  let xref = `xref\n0 ${objStrs.length + 1}\n0000000000 65535 f\r\n`;
  for (const off of xrefOffsets) {
    xref += `${String(off).padStart(10, "0")} 00000 n\r\n`;
  }
  const trailer = `trailer\n<< /Size ${objStrs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return Buffer.from(header + body + xref + trailer, "latin1");
}
