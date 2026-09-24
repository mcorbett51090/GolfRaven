import { describe, expect, it } from "vitest";
import { extractPdfText, looksLikePdf, PDF_EXTRACTOR_ID } from "../src/pdf-extract.js";
import { buildMinimalPdf } from "./fixtures/pdf/build-mini-pdf.js";

describe("pdf-extract: looksLikePdf (gate finding N5 — magic bytes, not content-type/suffix)", () => {
  it("true for real %PDF- magic bytes", () => {
    expect(looksLikePdf(Buffer.from("%PDF-1.4 rest of file"))).toBe(true);
  });
  it("false for an HTML error page, even if it would be served at a .pdf URL", () => {
    expect(looksLikePdf(Buffer.from("<html>Not Found</html>"))).toBe(false);
  });
  it("false for bytes shorter than the magic sequence", () => {
    expect(looksLikePdf(Buffer.from("%PD"))).toBe(false);
  });
});

describe("pdf-extract: extractPdfText (gate finding S3 — pinned pure-JS extractor)", () => {
  it("extracts the exact text from a real, minimal, deterministically-built PDF", async () => {
    const quote = "Bear Trace at Harrison Bay is a member course, year-round.";
    const pdf = buildMinimalPdf(quote);
    expect(looksLikePdf(pdf)).toBe(true);
    const text = await extractPdfText(pdf);
    expect(text).toContain(quote);
  });

  it("PDF_EXTRACTOR_ID names the pinned extractor and exact version", () => {
    expect(PDF_EXTRACTOR_ID).toBe("unpdf@1.8.1");
  });

  it("throws on bytes that are not a real PDF", async () => {
    await expect(extractPdfText(Buffer.from("not a pdf at all"))).rejects.toThrow();
  });
});
