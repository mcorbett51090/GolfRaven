import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseK3Log } from "../src/k3-log.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const realMarkdown = readFileSync(path.join(__dirname, "..", "..", "..", "docs", "p0", "K3.md"), "utf8");

const PROPERTY_SECTION = (body: string) => `## SWC Search Console property\n\n${body}\n`;
const SC_HEADER = "| Month | Total organic clicks |";
const SC_SEP = "|---|---|";
const KW_HEADER = "| Term | Lower bound | Upper bound | Point value |";
const KW_SEP = "|---|---|---|---|";

function scRow(month: string, clicks = ""): string {
  return `| ${month} | ${clicks} |`;
}

function kwRow(term: string, lower = "", upper = "", point = ""): string {
  return `| ${term} | ${lower} | ${upper} | ${point} |`;
}

const DEFAULT_SC_ROWS = [scRow("2026-07"), scRow("2026-08"), scRow("2026-09")];
const DEFAULT_KW_ROWS = [
  kwRow("golf trail"),
  kwRow("golf trails"),
  kwRow("robert trent jones golf trail"),
  kwRow("tennessee golf trail"),
  kwRow("vancouver island golf trail"),
  kwRow("oklahoma golf trail"),
];

function buildK3(opts: {
  propertyBody?: string;
  scRows?: string[];
  scHeader?: string;
  kwRows?: string[];
  kwHeader?: string;
  includeSc?: boolean;
  includeKw?: boolean;
  includeProperty?: boolean;
}): string {
  const {
    propertyBody = "_(blank)_",
    scRows: sc = DEFAULT_SC_ROWS,
    scHeader = SC_HEADER,
    kwRows: kw = DEFAULT_KW_ROWS,
    kwHeader = KW_HEADER,
    includeSc = true,
    includeKw = true,
    includeProperty = true,
  } = opts;
  const parts: string[] = [];
  if (includeProperty) parts.push(PROPERTY_SECTION(propertyBody));
  if (includeSc) parts.push(["## Search Console read", "", "Note.", "", scHeader, SC_SEP, ...sc, ""].join("\n"));
  if (includeKw) parts.push(["## Keyword Planner read", "", "Note.", "", kwHeader, KW_SEP, ...kw, ""].join("\n"));
  return parts.join("\n");
}

describe("parseK3Log", () => {
  it("parses the real, pre-read docs/p0/K3.md without throwing, all blank", () => {
    const log = parseK3Log(realMarkdown);
    expect(log.propertyId).toBe("");
    expect(log.searchConsole).toHaveLength(3);
    for (const r of log.searchConsole) expect(r.clicks).toBeNull();
    expect(log.keywords).toHaveLength(6);
    for (const k of log.keywords) {
      expect(k.lowerBound).toBeNull();
      expect(k.upperBound).toBeNull();
      expect(k.pointValue).toBeNull();
    }
  });

  it("reads a filled property id, trimmed", () => {
    const log = parseK3Log(buildK3({ propertyBody: "  sc-domain:southernwinecountry.com  " }));
    expect(log.propertyId).toBe("sc-domain:southernwinecountry.com");
  });

  it("reads filled Search Console and Keyword Planner rows", () => {
    const log = parseK3Log(
      buildK3({
        scRows: [scRow("2026-07", "1200"), scRow("2026-08", "900"), scRow("2026-09", "1100")],
        kwRows: [
          kwRow("golf trail", "1000", "10000"),
          kwRow("golf trails", "500", "5000"),
          kwRow("robert trent jones golf trail", "", "", "50"),
          kwRow("tennessee golf trail", "", "", "40"),
          kwRow("vancouver island golf trail", "", "", "30"),
          kwRow("oklahoma golf trail", "", "", "20"),
        ],
      }),
    );
    expect(log.searchConsole.find((r) => r.month === "2026-07")!.clicks).toBe(1200);
    expect(log.keywords.find((k) => k.term === "golf trail")).toEqual({
      term: "golf trail",
      lowerBound: 1000,
      upperBound: 10000,
      pointValue: null,
    });
    expect(log.keywords.find((k) => k.term === "robert trent jones golf trail")!.pointValue).toBe(50);
  });

  it("throws when a Search Console month is missing", () => {
    expect(() =>
      parseK3Log(buildK3({ scRows: [scRow("2026-07"), scRow("2026-08")] })),
    ).toThrow(/missing the required month/);
  });

  it("throws on an unexpected Search Console month", () => {
    expect(() =>
      parseK3Log(buildK3({ scRows: [scRow("2026-07"), scRow("2026-08"), scRow("2026-10")] })),
    ).toThrow(/unexpected month/);
  });

  it("throws on a duplicate Search Console month row", () => {
    expect(() =>
      parseK3Log(buildK3({ scRows: [scRow("2026-07"), scRow("2026-07"), scRow("2026-08")] })),
    ).toThrow(/duplicate row/);
  });

  it("throws on a malformed click count", () => {
    expect(() =>
      parseK3Log(buildK3({ scRows: [scRow("2026-07", "lots"), scRow("2026-08"), scRow("2026-09")] })),
    ).toThrow(/malformed number/);
  });

  it("throws on an off-list keyword term", () => {
    const rows = [...DEFAULT_KW_ROWS.slice(0, 5), kwRow("golf courses near me")];
    expect(() => parseK3Log(buildK3({ kwRows: rows }))).toThrow(/off-list term/);
  });

  it("throws when a required keyword term is missing", () => {
    const rows = DEFAULT_KW_ROWS.slice(0, 5); // drop "oklahoma golf trail"
    expect(() => parseK3Log(buildK3({ kwRows: rows }))).toThrow(/missing the required term/);
  });

  it("throws on a duplicate keyword term row", () => {
    const rows = [...DEFAULT_KW_ROWS, kwRow("golf trail")];
    expect(() => parseK3Log(buildK3({ kwRows: rows }))).toThrow(/duplicate row/);
  });

  it("throws when a keyword row has BOTH a range and a point value", () => {
    const rows = [
      kwRow("golf trail", "1000", "2000", "1500"),
      ...DEFAULT_KW_ROWS.slice(1),
    ];
    expect(() => parseK3Log(buildK3({ kwRows: rows }))).toThrow(/BOTH a point value and a range/);
  });

  it("throws when only one of lower/upper bound is filled", () => {
    const rows = [kwRow("golf trail", "1000"), ...DEFAULT_KW_ROWS.slice(1)];
    expect(() => parseK3Log(buildK3({ kwRows: rows }))).toThrow(/needs both bounds/);
  });

  it("throws when the Search Console read table is missing", () => {
    expect(() => parseK3Log(buildK3({ includeSc: false }))).toThrow(/Search Console read/);
  });

  it("throws when the Keyword Planner read table is missing", () => {
    expect(() => parseK3Log(buildK3({ includeKw: false }))).toThrow(/Keyword Planner read/);
  });

  it("throws when the SWC Search Console property heading is missing", () => {
    expect(() => parseK3Log(buildK3({ includeProperty: false }))).toThrow(/SWC Search Console property/);
  });

  it("throws on an unexpected Search Console column layout", () => {
    expect(() => parseK3Log(buildK3({ scHeader: "| Month | Clicks |" }))).toThrow(/unexpected column layout/);
  });

  it("throws on an unexpected Keyword Planner column layout", () => {
    expect(() => parseK3Log(buildK3({ kwHeader: "| Term | Volume |" }))).toThrow(/unexpected column layout/);
  });
});
