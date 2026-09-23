import { describe, expect, it } from "vitest";
import {
  computeX2Verdict,
  type EvidenceTextMap,
  type X2ConfirmationFile,
} from "../src/x2-verdict.js";

const SHA_TN = "a".repeat(64);
const SHA_VI = "b".repeat(64);
const SHA_RTJ = "c".repeat(64);
const SHA_PDF = "d".repeat(64); // exists, but no extracted text (manual)

function baseEvidence(): EvidenceTextMap {
  return new Map<string, string | null>([
    [
      SHA_TN,
      "Tennessee Golf Trail. Bear Trace at Harrison Bay is a member course. " +
        "The Trail counts a course as the completion unit. The season runs year-round.",
    ],
    [
      SHA_VI,
      "Vancouver Island Golf Trail. Arbutus Ridge is a member course. " +
        "Canada's only year-round golf trail — counted by facility.",
    ],
    [SHA_RTJ, null], // e.g. cited a PDF whose text extraction is "manual"
  ]);
}

function tnConfirmation(overrides: Partial<X2ConfirmationFile["TN"]> = {}) {
  return {
    roster: [
      {
        name: "Bear Trace at Harrison Bay",
        quote: "Bear Trace at Harrison Bay is a member course.",
        evidenceSha: SHA_TN,
      },
    ],
    completionUnit: {
      value: "course",
      quote: "The Trail counts a course as the completion unit.",
      evidenceSha: SHA_TN,
    },
    season: {
      value: "year-round",
      quote: "The season runs year-round.",
      evidenceSha: SHA_TN,
    },
    ...overrides,
  };
}

describe("x2-verdict: quote/name matching (decision 0001 Addendum G, literal)", () => {
  it("confirms a trail when every quote and every roster name appears verbatim in the cited evidence", () => {
    const confirmation: X2ConfirmationFile = { TN: tnConfirmation() };
    const result = computeX2Verdict(confirmation, baseEvidence(), ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(true);
    expect(result.perTrail.TN?.reasons).toEqual([]);
  });

  it("a whitespace-variant quote (extra spaces/newlines) still matches, after collapsing", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        completionUnit: {
          value: "course",
          quote: "The Trail counts   a course\nas the   completion unit.",
          evidenceSha: SHA_TN,
        },
      }),
    };
    const result = computeX2Verdict(confirmation, baseEvidence(), ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(true);
  });

  it("an absent quote (not present in the evidence text at all) leaves the trail unconfirmed with a reason", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: {
          value: "spring only",
          quote: "This exact sentence does not appear anywhere in the evidence.",
          evidenceSha: SHA_TN,
        },
      }),
    };
    const result = computeX2Verdict(confirmation, baseEvidence(), ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.reasons.some((r) => r.includes("season"))).toBe(
      true,
    );
  });

  it("a quote citing evidence with no extracted text (manual PDF) is unconfirmed, not refused", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: SHA_RTJ, // exists in the map, but text is null
        },
      }),
    };
    const result = computeX2Verdict(confirmation, baseEvidence(), ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(
      result.perTrail.TN?.reasons.some((r) => r.includes("manual PDF extraction")),
    ).toBe(true);
  });

  it("missing season fact entirely leaves the trail unconfirmed", () => {
    const confirmation = {
      TN: {
        roster: tnConfirmation().roster,
        completionUnit: tnConfirmation().completionUnit,
      },
    } as unknown as X2ConfirmationFile;
    const result = computeX2Verdict(confirmation, baseEvidence(), ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.reasons).toContain("season is missing.");
  });

  it("a roster entry whose NAME does not appear in the cited evidence (even though the quote does) is unconfirmed", () => {
    const evidence: EvidenceTextMap = new Map([
      [SHA_TN, "This trail has a member course. It counts a course. The season runs year-round."],
    ]);
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        roster: [
          {
            name: "Bear Trace at Harrison Bay",
            quote: "This trail has a member course.",
            evidenceSha: SHA_TN,
          },
        ],
      }),
    };
    const result = computeX2Verdict(confirmation, evidence, ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(
      result.perTrail.TN?.reasons.some((r) => r.includes("name does not appear")),
    ).toBe(true);
  });

  it("a cited evidenceSha with NO matching evidence at all is a hard refusal (throws)", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: "f".repeat(64), // not in the evidence map
        },
      }),
    };
    expect(() => computeX2Verdict(confirmation, baseEvidence(), ["TN"])).toThrow(
      /does not match any evidence/,
    );
  });

  it("an empty roster leaves the trail unconfirmed", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({ roster: [] }),
    };
    const result = computeX2Verdict(confirmation, baseEvidence(), ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.reasons).toContain("Roster is empty or missing.");
  });
});

describe("x2-verdict: pass bar — 2 of 3 slate trails confirmed", () => {
  function fullyConfirmingEvidence(): EvidenceTextMap {
    return new Map<string, string | null>([
      [
        SHA_TN,
        "Bear Trace at Harrison Bay is a member course. Course is the completion unit. Season runs year-round.",
      ],
      [
        SHA_VI,
        "Arbutus Ridge is a member course. Facility is the completion unit. Season runs year-round.",
      ],
    ]);
  }

  function trailConfirmation(sha: string, courseName: string) {
    return {
      roster: [
        { name: courseName, quote: `${courseName} is a member course.`, evidenceSha: sha },
      ],
      completionUnit: { value: "course", quote: "Course is the completion unit.", evidenceSha: sha },
      season: { value: "year-round", quote: "Season runs year-round.", evidenceSha: sha },
    };
  }

  it("exactly 2 of 3 confirmed -> PASS", () => {
    const confirmation: X2ConfirmationFile = {
      TN: trailConfirmation(SHA_TN, "Bear Trace at Harrison Bay"),
      VI: {
        roster: [
          { name: "Arbutus Ridge", quote: "Arbutus Ridge is a member course.", evidenceSha: SHA_VI },
        ],
        completionUnit: { value: "facility", quote: "Facility is the completion unit.", evidenceSha: SHA_VI },
        season: { value: "year-round", quote: "Season runs year-round.", evidenceSha: SHA_VI },
      },
      // RTJ has no confirmation entry at all -> unconfirmed
    };
    const result = computeX2Verdict(confirmation, fullyConfirmingEvidence());
    expect(result.confirmedCount).toBe(2);
    expect(result.overallVerdict).toBe("pass");
  });

  it("exactly 1 of 3 confirmed -> KILL (boundary just below the bar)", () => {
    const confirmation: X2ConfirmationFile = {
      TN: trailConfirmation(SHA_TN, "Bear Trace at Harrison Bay"),
    };
    const result = computeX2Verdict(confirmation, fullyConfirmingEvidence());
    expect(result.confirmedCount).toBe(1);
    expect(result.overallVerdict).toBe("kill");
  });
});
