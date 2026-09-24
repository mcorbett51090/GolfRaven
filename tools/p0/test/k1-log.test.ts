import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseK1Table } from "../src/k1-log.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const realMarkdown = readFileSync(
  path.join(__dirname, "..", "..", "..", "docs", "partners", "k1-outreach.md"),
  "utf8",
);

const HEADER =
  "| Target | Type | Contacted date | Call accepted date | LOI date | Fee willingness (Y/N) | OK swap replaces | Sponsor: decision-maker named (Y/N) | Sponsor: budget range stated (Y/N) | Sponsor: attribution interest (Y/N) | Sponsor conversation date | Notes |";
const SEP = "|---|---|---|---|---|---|---|---|---|---|---|---|";

function opRow(
  target: string,
  type: string,
  overrides: {
    contacted?: string;
    callAccepted?: string;
    loi?: string;
    fee?: string;
    okSwap?: string;
    dm?: string;
    budget?: string;
    attribution?: string;
    sponsorConversation?: string;
    notes?: string;
  } = {},
): string {
  const o = {
    contacted: "",
    callAccepted: "",
    loi: "",
    fee: "",
    okSwap: "",
    dm: "",
    budget: "",
    attribution: "",
    sponsorConversation: "",
    notes: "",
    ...overrides,
  };
  return `| ${target} | ${type} | ${o.contacted} | ${o.callAccepted} | ${o.loi} | ${o.fee} | ${o.okSwap} | ${o.dm} | ${o.budget} | ${o.attribution} | ${o.sponsorConversation} | ${o.notes} |`;
}

function baseSixRows(): string[] {
  return [
    opRow("Tennessee Golf Trail", "Operator (slate)"),
    opRow("Vancouver Island Golf Trail", "Operator (slate)"),
    opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
    opRow("Oklahoma Golf Trail", "Operator (reserve)"),
    opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
    opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
  ];
}

function buildTable(header: string, rows: string[]): string {
  return ["## (g) K1 tracking table", "", "Note line.", "", header, SEP, ...rows, ""].join("\n");
}

describe("parseK1Table", () => {
  it("parses the real, pre-outreach docs/partners/k1-outreach.md without throwing, all blank", () => {
    const rows = parseK1Table(realMarkdown);
    expect(rows.length).toBeGreaterThanOrEqual(10);
    for (const r of rows) {
      expect(r.contactedDate).toBeNull();
      expect(r.callAcceptedDate).toBeNull();
      expect(r.loiDate).toBeNull();
      expect(r.feeWillingness).toBeNull();
      expect(r.okSwapReplaces).toBeNull();
      expect(r.sponsorConversationDate).toBeNull();
    }
  });

  it("parses a well-formed table with filled cells, including a sponsor conversation date", () => {
    const rows = [
      opRow("Tennessee Golf Trail", "Operator (slate)", {
        contacted: "2026-09-23",
        callAccepted: "2026-10-10",
        loi: "2026-11-20",
        fee: "Y",
      }),
      opRow("Vancouver Island Golf Trail", "Operator (slate)"),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)"),
      opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
      opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
      opRow("Alabama Tourism Department", "Sponsor", {
        dm: "Y",
        budget: "Y",
        attribution: "Y",
        sponsorConversation: "2026-11-01",
      }),
    ];
    const parsed = parseK1Table(buildTable(HEADER, rows));
    const tn = parsed.find((r) => r.target === "Tennessee Golf Trail")!;
    expect(tn.callAcceptedDate).toBe("2026-10-10");
    expect(tn.loiDate).toBe("2026-11-20");
    expect(tn.feeWillingness).toBe("Y");
    const sponsor = parsed.find((r) => r.target === "Alabama Tourism Department")!;
    expect(sponsor.sponsorDecisionMakerNamed).toBe("Y");
    expect(sponsor.sponsorConversationDate).toBe("2026-11-01");
  });

  it("accepts the 'Hammock Coast' alias and canonicalizes it to 'Hammock Coast Golf Trail'", () => {
    const rows = [
      opRow("Tennessee Golf Trail", "Operator (slate)"),
      opRow("Vancouver Island Golf Trail", "Operator (slate)"),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)"),
      opRow("Hammock Coast", "Operator (co-op reserve)"), // alias, not the full name
      opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
    ];
    const parsed = parseK1Table(buildTable(HEADER, rows));
    expect(parsed.find((r) => r.target === "Hammock Coast Golf Trail")).toBeDefined();
    expect(parsed.find((r) => r.target === "Hammock Coast")).toBeUndefined();
  });

  it("throws on an unexpected column layout", () => {
    const badHeader = HEADER.replace("Notes", "Comments");
    expect(() => parseK1Table(buildTable(badHeader, baseSixRows()))).toThrow(/unexpected column layout/);
  });

  it("throws on an unknown operator name", () => {
    const rows = [
      opRow("Pebble Beach Trail", "Operator (slate)"),
      opRow("Vancouver Island Golf Trail", "Operator (slate)"),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)"),
      opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
      opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
    ];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/unknown operator name/);
  });

  it("throws when a sponsor row's target matches a known operator name", () => {
    const rows = [...baseSixRows(), opRow("Tennessee Golf Trail", "Sponsor")];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/matches a known operator name/);
  });

  it("throws on a malformed date", () => {
    const rows = [
      opRow("Tennessee Golf Trail", "Operator (slate)", { callAccepted: "10/20/2026" }),
      opRow("Vancouver Island Golf Trail", "Operator (slate)"),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)"),
      opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
      opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
    ];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/malformed date/);
  });

  it("throws on a malformed Y/N cell", () => {
    const rows = [
      opRow("Tennessee Golf Trail", "Operator (slate)", { fee: "yes" }),
      opRow("Vancouver Island Golf Trail", "Operator (slate)"),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)"),
      opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
      opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
    ];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/malformed value/);
  });

  it("throws when 'OK swap replaces' is set on a non-Oklahoma row", () => {
    const rows = [
      opRow("Tennessee Golf Trail", "Operator (slate)"),
      opRow("Vancouver Island Golf Trail", "Operator (slate)", { okSwap: "Tennessee Golf Trail" }),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)"),
      opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
      opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
    ];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/only applies to the "Oklahoma Golf Trail" row/);
  });

  it("throws when 'OK swap replaces' isn't one of the 3 slate trail names", () => {
    const rows = [
      opRow("Tennessee Golf Trail", "Operator (slate)"),
      opRow("Vancouver Island Golf Trail", "Operator (slate)"),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)", { okSwap: "Hammock Coast Golf Trail" }),
      opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
      opRow("Canadian Rockies Golf Consortium", "Operator (co-op reserve)"),
    ];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/not one of the 3 slate trail names/);
  });

  it("throws when a required operator row is missing", () => {
    const rows = [
      opRow("Tennessee Golf Trail", "Operator (slate)"),
      opRow("Vancouver Island Golf Trail", "Operator (slate)"),
      opRow("Robert Trent Jones Golf Trail", "Operator (slate)"),
      opRow("Oklahoma Golf Trail", "Operator (reserve)"),
      opRow("Hammock Coast Golf Trail", "Operator (co-op reserve)"),
      // Canadian Rockies Golf Consortium row dropped
    ];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/missing the required operator row/);
  });

  it("throws on a duplicate operator row", () => {
    const rows = [...baseSixRows(), opRow("Tennessee Golf Trail", "Operator (slate)")];
    expect(() => parseK1Table(buildTable(HEADER, rows))).toThrow(/duplicate operator row/);
  });

  it("throws when the '(g)' heading is missing", () => {
    const markdown = ["## Not the right heading", "", HEADER, SEP, ...baseSixRows(), ""].join("\n");
    expect(() => parseK1Table(markdown)).toThrow(/\(g\)/);
  });

  it("throws when a qualified sponsor row appears after a blank line (separated from the table)", () => {
    const markdown = [
      "## (g) K1 tracking table",
      "",
      "Note line.",
      "",
      HEADER,
      SEP,
      ...baseSixRows(),
      "",
      opRow("Alabama Tourism Department", "Sponsor", { dm: "Y", budget: "Y", attribution: "Y" }),
      "",
    ].join("\n");
    expect(() => parseK1Table(markdown)).toThrow(/separated from the table by a blank line/);
  });
});
