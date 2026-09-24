import { describe, expect, it } from "vitest";
import {
  classifyEvidenceBytes,
  detectHtmlCharset,
  decodeHtmlBytes,
  extractEvidenceText,
} from "../src/evidence-extract.js";
import { buildMinimalPdf } from "./fixtures/pdf/build-mini-pdf.js";

describe("evidence-extract: classifyEvidenceBytes (gate N5 — magic bytes first)", () => {
  it("classifies real PDF bytes as pdf even with no content-type", () => {
    expect(
      classifyEvidenceBytes(buildMinimalPdf("x"), null, "https://x/y"),
    ).toBe("pdf");
  });
  it("classifies an HTML error page served at a .pdf URL as 'bin', not 'pdf' or 'html'", () => {
    const buf = Buffer.from("<html>404</html>");
    expect(
      classifyEvidenceBytes(buf, "application/pdf", "https://x/y.pdf"),
    ).toBe("bin");
  });
  it("classifies real HTML by content-type", () => {
    const buf = Buffer.from("<html></html>");
    expect(
      classifyEvidenceBytes(buf, "text/html; charset=utf-8", "https://x/y"),
    ).toBe("html");
  });
});

describe("evidence-extract: detectHtmlCharset / decodeHtmlBytes (gate N4)", () => {
  it("prefers the content-type header's charset", () => {
    expect(
      detectHtmlCharset(Buffer.from(""), "text/html; charset=iso-8859-1"),
    ).toBe("iso-8859-1");
  });
  it("falls back to a <meta charset> tag when the header has none", () => {
    const buf = Buffer.from('<meta charset="iso-8859-1"><p>x</p>', "latin1");
    expect(detectHtmlCharset(buf, "text/html")).toBe("iso-8859-1");
  });
  it("defaults to utf-8 when neither says otherwise", () => {
    expect(detectHtmlCharset(Buffer.from("<p>x</p>"), "text/html")).toBe(
      "utf-8",
    );
  });
  it("decodes Latin-1 bytes correctly when the header names iso-8859-1", () => {
    const buf = Buffer.from([0xe9]); // é in Latin-1
    expect(decodeHtmlBytes(buf, "text/html; charset=iso-8859-1")).toBe("é");
  });
});

describe("evidence-extract: extractEvidenceText — the ONE extractor used at fetch AND verdict time (gate S1/S3)", () => {
  it("HTML -> stripped text", async () => {
    const buf = Buffer.from("<h1>Trail</h1><p>Nine courses.</p>");
    const result = await extractEvidenceText(buf, "text/html", "https://x/y");
    expect(result.text).toBe("Trail Nine courses.");
    expect(result.textExtraction).toBe("auto");
  });
  it("PDF -> derived text via the pinned extractor", async () => {
    const buf = buildMinimalPdf("Season runs year-round.");
    const result = await extractEvidenceText(
      buf,
      "application/pdf",
      "https://x/y.pdf",
    );
    expect(result.text).toContain("Season runs year-round.");
    expect(result.textExtraction).toBe("auto-pdf");
    expect(result.extractor).toBe("unpdf@1.8.1");
  });
  it("opaque binary -> null text, never guessed at", async () => {
    const buf = Buffer.from([0x00, 0x01, 0x02, 0x03]);
    const result = await extractEvidenceText(
      buf,
      "application/octet-stream",
      "https://x/y.bin",
    );
    expect(result.text).toBeNull();
    expect(result.textExtraction).toBe("n/a");
  });
});
