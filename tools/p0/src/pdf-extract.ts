/**
 * Pinned, pure-JS PDF text extraction for X2 evidence (gate finding S3 /
 * decision 0001 Addendum G "do not pretend"). `unpdf` is a pure-JS wrapper
 * around Mozilla's `pdf.js` with no native (node-gyp) build step, pinned to
 * an EXACT version in `package.json` (never a range) so the extractor
 * behaves identically at fetch time and at verdict time.
 *
 * Used from two places, deliberately the SAME function both times (gate S1 /
 * S3): `x2-fetch.ts` derives a convenience `text/<sha>.txt` copy when it
 * first stores a PDF's raw bytes, and `x2-verdict.ts` re-derives the text
 * from those same raw bytes at verdict time rather than trusting the stored
 * copy or the manifest's `textExtraction` field.
 */
import { extractText, getDocumentProxy } from "unpdf";

export const PDF_EXTRACTOR_ID = "unpdf@1.8.1";

/** `%PDF-` magic bytes (gate finding N5) — checked on the raw buffer, not
 * the HTTP content-type or URL suffix, either of which can lie. */
export function looksLikePdf(buf: Uint8Array): boolean {
  return (
    buf.length >= 5 &&
    buf[0] === 0x25 && // %
    buf[1] === 0x50 && // P
    buf[2] === 0x44 && // D
    buf[3] === 0x46 && // F
    buf[4] === 0x2d // -
  );
}

/** Extracts all pages' text, merged in reading order, whitespace-collapsed
 * the same way `stripHtmlToText` collapses HTML text (Addendum G: quotes are
 * compared "after whitespace collapsing" regardless of source format).
 * Throws on an unparseable PDF — a P0 evidence tool refuses rather than
 * silently returning empty text for bytes it could not actually read. */
export async function extractPdfText(buf: Uint8Array): Promise<string> {
  // `unpdf` requires a plain `Uint8Array`, not a `Buffer` subclass instance
  // (Node's `Buffer` IS a `Uint8Array`, but `unpdf` rejects it by
  // constructor identity) — copy into a plain one rather than trying to
  // detect every caller's exact type.
  const plain = new Uint8Array(buf);
  const pdf = await getDocumentProxy(plain);
  const { text } = await extractText(pdf, { mergePages: true });
  return text.replace(/\s+/g, " ").trim();
}
