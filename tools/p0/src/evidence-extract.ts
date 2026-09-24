/**
 * Shared "raw bytes -> evidence text" extraction, used identically by
 * `x2-fetch.ts` (at fetch time, to write the convenience `text/<sha>.txt`
 * copy) and `x2-verdict.ts` (at verdict time, re-deriving from the SAME raw
 * bytes rather than trusting that copy — gate findings S1/S3). Using one
 * function in both places is the point: there is exactly one definition of
 * "what this evidence's text is."
 */
import { stripHtmlToText } from "./text-extract.js";
import { extractPdfText, looksLikePdf, PDF_EXTRACTOR_ID } from "./pdf-extract.js";

export type EvidenceKind = "pdf" | "html" | "bin";

const CHARSET_FROM_CONTENT_TYPE_RE = /charset\s*=\s*"?([a-zA-Z0-9_-]+)"?/i;
const CHARSET_FROM_META_RE = /<meta[^>]+charset\s*=\s*["']?([a-zA-Z0-9_-]+)["']?[^>]*>/i;

/** Gate finding N4: the HTTP `content-type` header's `charset` wins; failing
 * that, sniff a `<meta charset>`/`<meta http-equiv="Content-Type" ...>` tag
 * in the first 1024 bytes (safe to read as Latin-1 for this sniff, since
 * ASCII-range markup bytes are identical across single-byte encodings);
 * default to UTF-8 only when neither says otherwise. Previously every
 * response was decoded as UTF-8 regardless of `charset`. */
export function detectHtmlCharset(buf: Uint8Array, contentType: string | null): string {
  const fromHeader = contentType ? CHARSET_FROM_CONTENT_TYPE_RE.exec(contentType)?.[1] : null;
  if (fromHeader) return fromHeader.toLowerCase();
  const sniffWindow = Buffer.from(buf.subarray(0, 1024)).toString("latin1");
  const fromMeta = CHARSET_FROM_META_RE.exec(sniffWindow)?.[1];
  if (fromMeta) return fromMeta.toLowerCase();
  return "utf-8";
}

/** Decodes HTML bytes using the detected charset, falling back to UTF-8 for
 * an unrecognized/unsupported charset label rather than throwing. */
export function decodeHtmlBytes(buf: Uint8Array, contentType: string | null): string {
  const charset = detectHtmlCharset(buf, contentType);
  try {
    return new TextDecoder(charset, { fatal: false }).decode(buf);
  } catch {
    return new TextDecoder("utf-8", { fatal: false }).decode(buf);
  }
}

/** Gate finding N5: classify by magic bytes first (a PDF's true signature),
 * falling back to content-type / URL suffix only for non-PDF bytes, where
 * there is no magic-byte signature to check against. */
export function classifyEvidenceBytes(
  buf: Uint8Array,
  contentType: string | null,
  url: string,
): EvidenceKind {
  if (looksLikePdf(buf)) return "pdf";
  const ct = (contentType ?? "").toLowerCase();
  if (ct.includes("pdf") || url.toLowerCase().split("?")[0]?.endsWith(".pdf")) {
    // Content-type/URL says PDF but the magic bytes don't confirm it (e.g. an
    // HTML error page served at a `.pdf` URL) — treat as binary, not PDF and
    // not HTML, so it is neither mis-extracted as tag-stripped HTML nor
    // pretended to be PDF text that was never actually there.
    return "bin";
  }
  if (ct.includes("html")) return "html";
  return "bin";
}

export interface ExtractedEvidence {
  text: string | null;
  textExtraction: "auto" | "auto-pdf" | "n/a";
  extractor: string | null;
}

/** Derives evidence text from raw bytes — the ONE extractor used at both
 * fetch time and verdict time (gate S1/S3). */
export async function extractEvidenceText(
  buf: Uint8Array,
  contentType: string | null,
  url: string,
): Promise<ExtractedEvidence> {
  const kind = classifyEvidenceBytes(buf, contentType, url);
  if (kind === "html") {
    return {
      text: stripHtmlToText(decodeHtmlBytes(buf, contentType)),
      textExtraction: "auto",
      extractor: null,
    };
  }
  if (kind === "pdf") {
    const text = await extractPdfText(buf);
    return { text, textExtraction: "auto-pdf", extractor: PDF_EXTRACTOR_ID };
  }
  return { text: null, textExtraction: "n/a", extractor: null };
}
