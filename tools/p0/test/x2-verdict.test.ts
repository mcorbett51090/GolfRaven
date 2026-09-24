import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  buildEvidenceByTrail,
  computeX2Verdict,
  sameConfiguredHost,
  type EvidenceByTrail,
  type X2ConfirmationFile,
  type X2CorroborationFile,
} from "../src/x2-verdict.js";
import type { X2FetchEntry, X2FetchManifest } from "../src/x2-fetch.js";
import type { RecordedLedger } from "../src/x2-recorded-ledger.js";

function sha(bytes: string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

const TN_BYTES =
  "Tennessee Golf Trail. Bear Trace at Harrison Bay is a member course. " +
  "The Trail counts a course as the completion unit. The season runs year-round.";
const VI_BYTES =
  "Vancouver Island Golf Trail. Arbutus Ridge is a member course. " +
  "Canada's only year-round golf trail — counted by facility.";

const SHA_TN = sha(TN_BYTES);
const SHA_VI = sha(VI_BYTES);
const SHA_PDF = "d".repeat(64); // known to this trail but has no extracted text

function baseEvidenceByTrail(): EvidenceByTrail {
  return {
    TN: {
      bySha: new Map([
        [
          SHA_TN,
          {
            text: TN_BYTES,
            method: "direct" as const,
            methodDefaulted: false,
            recorded: true,
          },
        ],
        [
          SHA_PDF,
          {
            text: null,
            method: "direct" as const,
            methodDefaulted: false,
            recorded: true,
          },
        ],
      ]),
      failedSources: [],
    },
    VI: {
      bySha: new Map([
        [
          SHA_VI,
          {
            text: VI_BYTES,
            method: "direct" as const,
            methodDefaulted: false,
            recorded: true,
          },
        ],
      ]),
      failedSources: [],
    },
    RTJ: { bySha: new Map(), failedSources: [] },
  };
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
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.confirmed).toBe(true);
    expect(result.perTrail.TN?.reasons).toEqual([]);
    expect(result.perTrail.TN?.rosterSize).toBe(1);
  });

  it("decision 0001 Addendum J: carries the evidence's `method` through to the facts output", () => {
    const confirmation: X2ConfirmationFile = { TN: tnConfirmation() };
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.facts.roster[0]?.method).toBe("direct");
    expect(result.perTrail.TN?.facts.completionUnit?.method).toBe("direct");
    expect(result.perTrail.TN?.facts.season?.method).toBe("direct");
  });

  it("decision 0001 Addendum J: a `rendered` evidence method is echoed, not silently normalised to direct", () => {
    const bytes =
      "Rendered SPA text. Arbutus Ridge is a member course. It counts a facility. Plays year-round.";
    const evidenceByTrail: EvidenceByTrail = {
      VI: {
        bySha: new Map([
          [
            sha(bytes),
            {
              text: bytes,
              method: "rendered" as const,
              methodDefaulted: false,
              recorded: true,
            },
          ],
        ]),
        failedSources: [],
      },
    };
    const confirmation: X2ConfirmationFile = {
      VI: {
        roster: [
          {
            name: "Arbutus Ridge",
            quote: "Arbutus Ridge is a member course.",
            evidenceSha: sha(bytes),
          },
        ],
        completionUnit: {
          value: "facility",
          quote: "It counts a facility.",
          evidenceSha: sha(bytes),
        },
        season: {
          value: "year-round",
          quote: "Plays year-round.",
          evidenceSha: sha(bytes),
        },
      },
    };
    const result = computeX2Verdict(confirmation, evidenceByTrail, ["VI"]);
    expect(result.perTrail.VI?.confirmed).toBe(true);
    expect(result.perTrail.VI?.facts.roster[0]?.method).toBe("rendered");
    expect(result.perTrail.VI?.facts.completionUnit?.method).toBe("rendered");
    expect(result.perTrail.VI?.facts.season?.method).toBe("rendered");
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
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.confirmed).toBe(true);
  });

  it("an absent quote (not present in the evidence text at all) leaves the trail unconfirmed with a reason", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: {
          value: "spring only",
          quote:
            "This exact sentence does not appear anywhere in the evidence.",
          evidenceSha: SHA_TN,
        },
      }),
    };
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.reasons.some((r) => r.includes("season"))).toBe(
      true,
    );
  });

  it("a quote citing evidence with no extracted text is unconfirmed, not refused", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: SHA_PDF, // exists in TN's own map, but text is null
        },
      }),
    };
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(
      result.perTrail.TN?.reasons.some((r) => r.includes("no extracted text")),
    ).toBe(true);
  });

  it("missing season fact entirely leaves the trail unconfirmed", () => {
    const confirmation = {
      TN: {
        roster: tnConfirmation().roster,
        completionUnit: tnConfirmation().completionUnit,
      },
    } as unknown as X2ConfirmationFile;
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.reasons).toContain("season is missing.");
  });

  it("a roster entry whose NAME does not appear in the cited evidence (even though the quote does) is unconfirmed", () => {
    const bytes =
      "This trail has a member course. It counts a course. The season runs year-round.";
    const evidenceByTrail: EvidenceByTrail = {
      TN: {
        bySha: new Map([
          [
            sha(bytes),
            {
              text: bytes,
              method: "direct" as const,
              methodDefaulted: false,
              recorded: true,
            },
          ],
        ]),
        failedSources: [],
      },
    };
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        roster: [
          {
            name: "Bear Trace at Harrison Bay",
            quote: "This trail has a member course.",
            evidenceSha: sha(bytes),
          },
        ],
        completionUnit: {
          value: "course",
          quote: "It counts a course.",
          evidenceSha: sha(bytes),
        },
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: sha(bytes),
        },
      }),
    };
    const result = computeX2Verdict(confirmation, evidenceByTrail, ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(
      result.perTrail.TN?.reasons.some((r) =>
        r.includes("name does not appear"),
      ),
    ).toBe(true);
  });

  it("a cited evidenceSha with NO matching evidence for this trail at all is a hard refusal (throws)", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: "f".repeat(64), // not in TN's evidence
        },
      }),
    };
    expect(() =>
      computeX2Verdict(confirmation, baseEvidenceByTrail(), ["TN"]),
    ).toThrow(/is not "TN"'s own confirmed evidence/);
  });

  it("gate S2: a fact citing ANOTHER trail's SHA is a hard refusal (throws), not a confirmation — probe P2", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: {
          value: "year-round",
          quote: "Canada's only year-round golf trail",
          evidenceSha: SHA_VI, // belongs to VI, not TN
        },
      }),
    };
    expect(() =>
      computeX2Verdict(confirmation, baseEvidenceByTrail(), ["TN"]),
    ).toThrow(/is not "TN"'s own confirmed evidence/);
  });

  it("an empty roster leaves the trail unconfirmed", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({ roster: [] }),
    };
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.reasons).toContain(
      "Roster is empty or missing.",
    );
  });

  it("gate N8: an empty value / quote shorter than 12 chars is unconfirmed", () => {
    const confirmation: X2ConfirmationFile = {
      TN: tnConfirmation({
        season: { value: "", quote: "short", evidenceSha: SHA_TN },
      }),
    };
    const result = computeX2Verdict(confirmation, baseEvidenceByTrail(), [
      "TN",
    ]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(
      result.perTrail.TN?.reasons.some((r) => r.includes("shorter than 12")),
    ).toBe(true);
  });

  it("gate S5: a failed/blocked source is listed in reasons even for an unconfirmed trail", () => {
    const evidenceByTrail: EvidenceByTrail = {
      TN: {
        bySha: new Map(),
        failedSources: [
          {
            url: "https://tngolftrail.net/",
            blocked: true,
            error: "BLOCKED — network policy",
          },
        ],
      },
    };
    const result = computeX2Verdict({}, evidenceByTrail, ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.hasFailedSource).toBe(true);
    expect(
      result.perTrail.TN?.reasons.some((r) => r.includes("tngolftrail.net")),
    ).toBe(true);
    expect(result.anyUnconfirmedWithFailedSource).toBe(true);
  });

  it("gate S5: a CONFIRMED trail with an unrelated failed source is not flagged as needing a refusal-worthy re-run", () => {
    const evidenceByTrail: EvidenceByTrail = {
      TN: {
        bySha: new Map([
          [
            SHA_TN,
            {
              text: TN_BYTES,
              method: "direct" as const,
              methodDefaulted: false,
              recorded: true,
            },
          ],
        ]),
        failedSources: [
          { url: "https://tn.gov/", blocked: false, error: "404" },
        ],
      },
    };
    const confirmation: X2ConfirmationFile = { TN: tnConfirmation() };
    const result = computeX2Verdict(confirmation, evidenceByTrail, ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(true);
    expect(result.perTrail.TN?.hasFailedSource).toBe(true);
    expect(result.anyUnconfirmedWithFailedSource).toBe(false);
  });
});

describe("x2-verdict: pass bar — 2 of 3 slate trails confirmed", () => {
  function trailConfirmation(sha256: string, courseName: string) {
    return {
      roster: [
        {
          name: courseName,
          quote: `${courseName} is a member course.`,
          evidenceSha: sha256,
        },
      ],
      completionUnit: {
        value: "course",
        quote: "Course is the completion unit.",
        evidenceSha: sha256,
      },
      season: {
        value: "year-round",
        quote: "Season runs year-round.",
        evidenceSha: sha256,
      },
    };
  }

  function fullyConfirmingEvidence(): EvidenceByTrail {
    const tnBytes =
      "Bear Trace at Harrison Bay is a member course. Course is the completion unit. Season runs year-round.";
    const viBytes =
      "Arbutus Ridge is a member course. Facility is the completion unit. Season runs year-round.";
    return {
      TN: {
        bySha: new Map([
          [
            sha(tnBytes),
            {
              text: tnBytes,
              method: "direct" as const,
              methodDefaulted: false,
              recorded: true,
            },
          ],
        ]),
        failedSources: [],
      },
      VI: {
        bySha: new Map([
          [
            sha(viBytes),
            {
              text: viBytes,
              method: "direct" as const,
              methodDefaulted: false,
              recorded: true,
            },
          ],
        ]),
        failedSources: [],
      },
      RTJ: { bySha: new Map(), failedSources: [] },
    };
  }

  it("exactly 2 of 3 confirmed -> PASS", () => {
    const evidence = fullyConfirmingEvidence();
    const tnSha = [...evidence.TN!.bySha.keys()][0]!;
    const viSha = [...evidence.VI!.bySha.keys()][0]!;
    const confirmation: X2ConfirmationFile = {
      TN: trailConfirmation(tnSha, "Bear Trace at Harrison Bay"),
      VI: {
        roster: [
          {
            name: "Arbutus Ridge",
            quote: "Arbutus Ridge is a member course.",
            evidenceSha: viSha,
          },
        ],
        completionUnit: {
          value: "facility",
          quote: "Facility is the completion unit.",
          evidenceSha: viSha,
        },
        season: {
          value: "year-round",
          quote: "Season runs year-round.",
          evidenceSha: viSha,
        },
      },
      // RTJ has no confirmation entry at all -> unconfirmed
    };
    const result = computeX2Verdict(confirmation, evidence);
    expect(result.confirmedCount).toBe(2);
    expect(result.overallVerdict).toBe("pass");
  });

  it("exactly 1 of 3 confirmed -> KILL (boundary just below the bar)", () => {
    const evidence = fullyConfirmingEvidence();
    const tnSha = [...evidence.TN!.bySha.keys()][0]!;
    const confirmation: X2ConfirmationFile = {
      TN: trailConfirmation(tnSha, "Bear Trace at Harrison Bay"),
    };
    const result = computeX2Verdict(confirmation, evidence);
    expect(result.confirmedCount).toBe(1);
    expect(result.overallVerdict).toBe("kill");
  });
});

function fetchedEntry(
  overrides: Partial<X2FetchEntry> & { trail: string; url: string },
): X2FetchEntry {
  return {
    status: "fetched",
    httpStatus: 200,
    finalUrl: overrides.url,
    contentType: "text/html",
    fetchedAt: new Date().toISOString(),
    sha256: null,
    rawFile: null,
    textFile: null,
    textExtraction: "auto",
    extractor: null,
    blocked: false,
    error: null,
    draftCandidateNames: [],
    method: "direct",
    ownerSavedDate: null,
    renderArgs: null,
    renderProxyHost: null,
    recorded: true,
    ...overrides,
  };
}

describe("x2-verdict: buildEvidenceByTrail (gate findings S1/S2/S5)", () => {
  it("gate S1: recomputes SHA-256 from the raw bytes and derives text from them — an edited text file does NOT confirm (probe P3)", async () => {
    const rawBytes = Buffer.from(
      "<h1>Tennessee Golf Trail</h1><p>Nine courses make up the Trail.</p>",
    );
    const realSha = sha(rawBytes.toString("utf8"));
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: {
        TN: [
          fetchedEntry({
            trail: "TN",
            url: "https://www.tnstateparks.com/golf",
            sha256: realSha,
            rawFile: "raw/x.html",
            textFile: "text/x.txt",
          }),
        ],
      },
      draftCandidateNames: { TN: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async (rel) => {
      if (rel === "raw/x.html") return rawBytes;
      // An operator hand-edited the STORED TEXT FILE, but the raw bytes are
      // unchanged — the verdict must ignore this file entirely.
      return Buffer.from(
        "Fabricated roster: Bear Trace, Arbutus Ridge, some invented course.",
      );
    });
    const text = byTrail.TN?.bySha.get(realSha)?.text ?? "";
    expect(text).toContain("Tennessee Golf Trail");
    expect(text).not.toContain("Fabricated");
  });

  it("decision 0001 Addendum J: carries a manifest entry's `method` (e.g. rendered) through into the evidence map", async () => {
    const rawBytes = Buffer.from(
      "<h1>Vancouver Island Golf Trail</h1><p>Rendered SPA content.</p>",
    );
    const realSha = sha(rawBytes.toString("utf8"));
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-render-evidence",
      trails: {
        VI: [
          fetchedEntry({
            trail: "VI",
            url: "https://golfvancouverisland.ca/",
            sha256: realSha,
            rawFile: "raw/vi-rendered.html",
            method: "rendered",
          }),
        ],
      },
      draftCandidateNames: { VI: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () => rawBytes);
    expect(byTrail.VI?.bySha.get(realSha)?.method).toBe("rendered");
  });

  it("gate S1: refuses (throws) when the raw bytes' recomputed SHA does not match the manifest's recorded SHA", async () => {
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: {
        TN: [
          fetchedEntry({
            trail: "TN",
            url: "https://www.tnstateparks.com/golf",
            sha256: "0".repeat(64), // deliberately wrong
            rawFile: "raw/x.html",
          }),
        ],
      },
      draftCandidateNames: { TN: [] },
    };
    await expect(
      buildEvidenceByTrail(manifest, async () =>
        Buffer.from("<p>Real content.</p>"),
      ),
    ).rejects.toThrow(/does not match the manifest's recorded/);
  });

  it("gate S2: excludes evidence whose final URL redirected to a FOREIGN HOST from that trail's evidence", async () => {
    const rawBytes = Buffer.from("<p>Parked domain.</p>");
    const realSha = sha(rawBytes.toString("utf8"));
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: {
        RTJ: [
          fetchedEntry({
            trail: "RTJ",
            url: "https://www.rtjgolf.com/",
            finalUrl: "https://parking-page.example/rtjgolf",
            sha256: realSha,
            rawFile: "raw/y.html",
          }),
        ],
      },
      draftCandidateNames: { RTJ: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () => rawBytes);
    expect(byTrail.RTJ?.bySha.has(realSha)).toBe(false);
    // The exclusion is reported, never dropped silently.
    expect(
      byTrail.RTJ?.failedSources.some((f) =>
        f.error.includes("redirected off the configured host"),
      ),
    ).toBe(true);
  });

  it("same-site rule: a bare domain redirecting to its www. host still counts as that trail's evidence", async () => {
    const rawBytes = Buffer.from("<p>Golf Vancouver Island Trail Pass</p>");
    const realSha = sha(rawBytes.toString("utf8"));
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: {
        VI: [
          fetchedEntry({
            trail: "VI",
            url: "https://golfvancouverisland.ca/",
            finalUrl: "https://www.golfvancouverisland.ca/",
            sha256: realSha,
            rawFile: "raw/vi.html",
          }),
        ],
      },
      draftCandidateNames: { VI: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () => rawBytes);
    expect(byTrail.VI?.bySha.has(realSha)).toBe(true);
    expect(byTrail.VI?.failedSources).toHaveLength(0);
  });

  it("sameConfiguredHost: only exact or www.-prefix variants match", () => {
    expect(
      sameConfiguredHost("golfvancouverisland.ca", "golfvancouverisland.ca"),
    ).toBe(true);
    expect(
      sameConfiguredHost(
        "golfvancouverisland.ca",
        "www.golfvancouverisland.ca",
      ),
    ).toBe(true);
    expect(sameConfiguredHost("www.rtjgolf.com", "rtjgolf.com")).toBe(true);
    expect(sameConfiguredHost("rtjgolf.com", "rtjgolf.com.evil.example")).toBe(
      false,
    );
    expect(sameConfiguredHost("rtjgolf.com", "shop.rtjgolf.com")).toBe(false);
    expect(sameConfiguredHost("tnstateparks.com", "tn.gov")).toBe(false);
  });

  it("gate S5: a failed entry is recorded as a failedSource for its trail", async () => {
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: {
        VI: [
          {
            trail: "VI",
            url: "https://golfvancouverisland.ca/wp-content/uploads/2024/10/terms.pdf",
            status: "failed",
            httpStatus: null,
            finalUrl: null,
            contentType: null,
            fetchedAt: new Date().toISOString(),
            sha256: null,
            rawFile: null,
            textFile: null,
            textExtraction: "n/a",
            extractor: null,
            blocked: true,
            error: "BLOCKED — network policy (golfvancouverisland.ca)",
            draftCandidateNames: [],
            method: "direct",
            ownerSavedDate: null,
            renderArgs: null,
            renderProxyHost: null,
            recorded: true,
          },
        ],
      },
      draftCandidateNames: { VI: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () =>
      Buffer.from(""),
    );
    expect(byTrail.VI?.failedSources).toEqual([
      {
        url: "https://golfvancouverisland.ca/wp-content/uploads/2024/10/terms.pdf",
        blocked: true,
        error: "BLOCKED — network policy (golfvancouverisland.ca)",
      },
    ]);
  });
});

describe("x2-verdict: gate findings — legacy method default, method/httpStatus cross-check, non-recorded refusal", () => {
  function baseManifestEntry(
    overrides: Partial<X2FetchEntry> = {},
  ): X2FetchEntry {
    return {
      trail: "TN",
      url: "https://www.tnstateparks.com/golf",
      status: "fetched",
      httpStatus: 200,
      finalUrl: "https://www.tnstateparks.com/golf",
      contentType: "text/html",
      fetchedAt: new Date().toISOString(),
      sha256: null,
      rawFile: null,
      textFile: null,
      textExtraction: "auto",
      extractor: null,
      blocked: false,
      error: null,
      draftCandidateNames: [],
      method: "direct",
      ownerSavedDate: null,
      renderArgs: null,
      renderProxyHost: null,
      recorded: true,
      ...overrides,
    };
  }

  it('gate finding: a legacy manifest entry with NO `method` field at all defaults to "direct", and it is stated in reasons', async () => {
    const bytes =
      "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const legacyEntry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
    });
    // Simulate a REAL legacy manifest read from disk (JSON.parse'd), which
    // never had a `method` key at all — strip it, defeating the TS type.
    delete (legacyEntry as { method?: unknown }).method;
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [legacyEntry] },
      draftCandidateNames: { TN: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () =>
      Buffer.from(bytes),
    );
    expect(byTrail.TN?.bySha.get(rawSha)?.method).toBe("direct");
    expect(byTrail.TN?.bySha.get(rawSha)?.methodDefaulted).toBe(true);

    const confirmation: X2ConfirmationFile = {
      TN: {
        roster: [
          {
            name: "Nine courses make up",
            quote: "Nine courses make up the Trail.",
            evidenceSha: rawSha,
          },
        ],
        completionUnit: {
          value: "course",
          quote: "It counts a course.",
          evidenceSha: rawSha,
        },
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: rawSha,
        },
      },
    };
    const result = computeX2Verdict(confirmation, byTrail, ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(true);
    expect(result.perTrail.TN?.facts.completionUnit?.method).toBe("direct");
    expect(
      result.perTrail.TN?.reasons.some(
        (r) =>
          r.includes("legacy manifest") && r.includes('defaulted to "direct"'),
      ),
    ).toBe(true);
  });

  it("gate finding: cross-checks method against httpStatus — an owner-saved entry with a NUMERIC httpStatus refuses (throws)", async () => {
    const bytes = "Some evidence text.";
    const rawSha = sha(bytes);
    const badEntry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      method: "owner-saved",
      httpStatus: 200, // should be the literal string "owner-saved"
      ownerSavedDate: "2026-09-24",
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [badEntry] },
      draftCandidateNames: { TN: [] },
    };
    await expect(
      buildEvidenceByTrail(manifest, async () => Buffer.from(bytes)),
    ).rejects.toThrow(/inconsistent/);
  });

  it('gate finding: cross-checks method against httpStatus — a "direct" entry with httpStatus "owner-saved" refuses (throws)', async () => {
    const bytes = "Some evidence text.";
    const rawSha = sha(bytes);
    const badEntry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      method: "direct",
      httpStatus: "owner-saved", // should be numeric
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [badEntry] },
      draftCandidateNames: { TN: [] },
    };
    await expect(
      buildEvidenceByTrail(manifest, async () => Buffer.from(bytes)),
    ).rejects.toThrow(/inconsistent/);
  });

  it('a consistent owner-saved entry (method owner-saved, httpStatus "owner-saved") builds evidence fine — the owner-saved verdict path', async () => {
    const bytes =
      "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const entry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      method: "owner-saved",
      httpStatus: "owner-saved",
      ownerSavedDate: "2026-09-24",
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [entry] },
      draftCandidateNames: { TN: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () =>
      Buffer.from(bytes),
    );
    const confirmation: X2ConfirmationFile = {
      TN: {
        roster: [
          {
            name: "Nine courses make up",
            quote: "Nine courses make up the Trail.",
            evidenceSha: rawSha,
          },
        ],
        completionUnit: {
          value: "course",
          quote: "It counts a course.",
          evidenceSha: rawSha,
        },
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: rawSha,
        },
      },
    };
    // Gate finding 4: an owner-saved fact needs a corroboration record to
    // count — without one it is "owner-attested, uncorroborated" and does
    // not confirm the trail. Supplying Matt's dated acceptance is enough.
    const corroboration: X2CorroborationFile = {
      TN: {
        [rawSha]: { type: "acceptance", acceptedBy: "Matt", date: "2026-09-24" },
      },
    };
    const result = computeX2Verdict(confirmation, byTrail, ["TN"], corroboration);
    expect(result.perTrail.TN?.confirmed).toBe(true);
    expect(result.perTrail.TN?.facts.season?.method).toBe("owner-saved");
    expect(result.perTrail.TN?.facts.season?.corroboration).toBe(
      "owner-attested, accepted uncorroborated by Matt on 2026-09-24",
    );
  });

  it('gate finding 4: the SAME owner-saved entry, with NO corroboration file supplied, does NOT confirm', async () => {
    const bytes =
      "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const entry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      method: "owner-saved",
      httpStatus: "owner-saved",
      ownerSavedDate: "2026-09-24",
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [entry] },
      draftCandidateNames: { TN: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () =>
      Buffer.from(bytes),
    );
    const confirmation: X2ConfirmationFile = {
      TN: {
        roster: [
          {
            name: "Nine courses make up",
            quote: "Nine courses make up the Trail.",
            evidenceSha: rawSha,
          },
        ],
        completionUnit: {
          value: "course",
          quote: "It counts a course.",
          evidenceSha: rawSha,
        },
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: rawSha,
        },
      },
    };
    const result = computeX2Verdict(confirmation, byTrail, ["TN"]);
    expect(result.perTrail.TN?.confirmed).toBe(false);
    expect(result.perTrail.TN?.facts.season?.corroboration).toBe(
      "owner-attested, uncorroborated",
    );
  });

  it("Addendum J correction (first-capture-wins): refuses (throws) a confirmation that cites a NON-RECORDED capture", async () => {
    const bytes =
      "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const entry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      method: "owner-saved",
      httpStatus: "owner-saved",
      ownerSavedDate: "2026-09-24",
      recorded: false, // an --additional, non-recorded capture
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [entry] },
      draftCandidateNames: { TN: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () =>
      Buffer.from(bytes),
    );
    expect(byTrail.TN?.bySha.get(rawSha)?.recorded).toBe(false);
    const confirmation: X2ConfirmationFile = {
      TN: {
        roster: [
          {
            name: "Nine courses make up",
            quote: "Nine courses make up the Trail.",
            evidenceSha: rawSha,
          },
        ],
        completionUnit: {
          value: "course",
          quote: "It counts a course.",
          evidenceSha: rawSha,
        },
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: rawSha,
        },
      },
    };
    expect(() => computeX2Verdict(confirmation, byTrail, ["TN"])).toThrow(
      /NON-RECORDED capture/,
    );
  });

  it("a legacy entry with no `recorded` field at all defaults to recorded: true", async () => {
    const bytes =
      "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const legacyEntry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
    });
    delete (legacyEntry as { recorded?: unknown }).recorded;
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [legacyEntry] },
      draftCandidateNames: { TN: [] },
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () =>
      Buffer.from(bytes),
    );
    expect(byTrail.TN?.bySha.get(rawSha)?.recorded).toBe(true);
  });
});

describe("x2-verdict: gate finding 2c — buildEvidenceByTrail's `recorded` is LEDGER-authoritative when a ledger is supplied", () => {
  function baseManifestEntry(
    overrides: Partial<X2FetchEntry> = {},
  ): X2FetchEntry {
    return {
      trail: "TN",
      url: "https://www.tnstateparks.com/golf",
      status: "fetched",
      httpStatus: 200,
      finalUrl: "https://www.tnstateparks.com/golf",
      contentType: "text/html",
      fetchedAt: new Date().toISOString(),
      sha256: null,
      rawFile: null,
      textFile: null,
      textExtraction: "auto",
      extractor: null,
      blocked: false,
      error: null,
      draftCandidateNames: [],
      method: "direct",
      ownerSavedDate: null,
      renderArgs: null,
      renderProxyHost: null,
      recorded: true,
      ...overrides,
    };
  }

  it("a manifest entry hand-edited (or stale) to say recorded: true is overridden to false when the ledger does NOT contain its SHA — the ledger wins, not the manifest field", async () => {
    const bytes = "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const entry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      recorded: true, // the manifest's OWN claim — must be ignored
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [entry] },
      draftCandidateNames: { TN: [] },
    };
    const emptyLedger: RecordedLedger = { entries: [] };
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger: emptyLedger },
    );
    expect(byTrail.TN?.bySha.get(rawSha)?.recorded).toBe(false);
  });

  it("a manifest entry saying recorded: false is overridden to true when the ledger DOES contain its (method, SHA) pair", async () => {
    const bytes = "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const entry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      method: "direct",
      recorded: false, // the manifest's OWN (stale) claim — must be ignored
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [entry] },
      draftCandidateNames: { TN: [] },
    };
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "direct",
          normalizedUrl: "www.tnstateparks.com/golf",
          url: "https://www.tnstateparks.com/golf",
          sha256: rawSha,
          recordedAt: new Date().toISOString(),
        },
      ],
    };
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger },
    );
    expect(byTrail.TN?.bySha.get(rawSha)?.recorded).toBe(true);
  });

  it("the ledger match is scoped by METHOD too — a ledger entry for the SHA under a different method does not make this entry recorded", async () => {
    const bytes = "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const entry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      method: "rendered",
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [entry] },
      draftCandidateNames: { TN: [] },
    };
    // The ledger has this exact SHA recorded, but for "direct", not
    // "rendered" — must NOT match.
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "direct",
          normalizedUrl: "www.tnstateparks.com/golf",
          url: "https://www.tnstateparks.com/golf",
          sha256: rawSha,
          recordedAt: new Date().toISOString(),
        },
      ],
    };
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger },
    );
    expect(byTrail.TN?.bySha.get(rawSha)?.recorded).toBe(false);
  });

  it("end to end: a confirmation citing the non-ledger-recorded SHA is refused (throws), even though the manifest entry itself claims recorded: true", async () => {
    const bytes = "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const entry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
      recorded: true,
    });
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [entry] },
      draftCandidateNames: { TN: [] },
    };
    const emptyLedger: RecordedLedger = { entries: [] };
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger: emptyLedger },
    );
    const confirmation: X2ConfirmationFile = {
      TN: {
        roster: [
          {
            name: "Nine courses make up",
            quote: "Nine courses make up the Trail.",
            evidenceSha: rawSha,
          },
        ],
        completionUnit: {
          value: "course",
          quote: "It counts a course.",
          evidenceSha: rawSha,
        },
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: rawSha,
        },
      },
    };
    expect(() => computeX2Verdict(confirmation, byTrail, ["TN"])).toThrow(
      /NON-RECORDED capture/,
    );
  });
});

describe("x2-verdict: gate finding 4 — owner-saved facts require corroboration", () => {
  const OWNER_BYTES =
    "North Carolina Golf Trail. Pinehurst Creek is a member course. " +
    "The Trail counts a course as the completion unit. The season runs March-November.";
  const SHA_OWNER = sha(OWNER_BYTES);

  function ownerEvidenceByTrail(): EvidenceByTrail {
    return {
      NC: {
        bySha: new Map([
          [
            SHA_OWNER,
            {
              text: OWNER_BYTES,
              method: "owner-saved" as const,
              methodDefaulted: false,
              recorded: true,
            },
          ],
        ]),
        failedSources: [],
      },
    };
  }

  function ncConfirmation(): X2ConfirmationFile {
    return {
      NC: {
        roster: [
          {
            name: "Pinehurst Creek",
            quote: "Pinehurst Creek is a member course.",
            evidenceSha: SHA_OWNER,
          },
        ],
        completionUnit: {
          value: "course",
          quote: "The Trail counts a course as the completion unit.",
          evidenceSha: SHA_OWNER,
        },
        season: {
          value: "March-November",
          quote: "The season runs March-November.",
          evidenceSha: SHA_OWNER,
        },
      },
    };
  }

  it("an owner-saved fact with NO corroboration record is uncorroborated and does not confirm the trail", () => {
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"]);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(false);
    expect(nc?.reasons.join("\n")).toMatch(/owner-attested, UNCORROBORATED/);
    expect(nc?.facts.roster[0]?.corroboration).toBe("owner-attested, uncorroborated");
    expect(nc?.facts.completionUnit?.corroboration).toBe("owner-attested, uncorroborated");
    expect(nc?.facts.season?.corroboration).toBe("owner-attested, uncorroborated");
  });

  it("an owner-saved fact backed by Matt's dated acceptance record passes, uncorroborated-by-source but named in output", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: {
          type: "acceptance",
          acceptedBy: "Matt",
          date: "2026-09-20",
        },
      },
    };
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(true);
    expect(nc?.facts.roster[0]?.corroboration).toBe(
      "owner-attested, accepted uncorroborated by Matt on 2026-09-20",
    );
    expect(nc?.reasons.join("\n")).toMatch(/accepted uncorroborated by Matt on 2026-09-20/);
  });

  it("an owner-saved fact backed by a Wayback snapshot whose text contains the quote passes and names the snapshot", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: {
          type: "wayback",
          snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/nc-trail",
          snapshotSha256: "e".repeat(64),
          snapshotText: "The North Carolina Golf Trail. Pinehurst Creek is a member course.",
        },
      },
    };
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration);
    const nc = result.perTrail.NC;
    // completionUnit/season quotes are NOT in the snapshot text, so the
    // trail as a whole still does not confirm — but the roster entry
    // itself, which IS corroborated, must say so.
    expect(nc?.facts.roster[0]?.corroboration).toMatch(
      /^owner-attested, corroborated by Wayback snapshot https:\/\/web\.archive\.org\/web\/20260101000000\/https:\/\/example\.com\/nc-trail \(sha256 eeeeeeeeeeee\.\.\.\)$/,
    );
    expect(nc?.reasons.join("\n")).toMatch(/corroborated by Wayback snapshot/);
  });

  it("an owner-saved fact backed by a Wayback snapshot whose text does NOT contain the quote fails corroboration", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: {
          type: "wayback",
          snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/nc-trail",
          snapshotSha256: "f".repeat(64),
          snapshotText: "This snapshot says nothing about the roster at all.",
        },
      },
    };
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(false);
    expect(nc?.facts.roster[0]?.corroboration).toMatch(/Wayback corroboration FAILED/);
    expect(nc?.reasons.join("\n")).toMatch(
      /quote does NOT appear verbatim in the snapshot's own text/,
    );
  });

  it("a direct/rendered fact needs no corroboration — corroboration is always null and never checked", () => {
    const TN_BYTES2 =
      "Tennessee Golf Trail. Bear Trace at Harrison Bay is a member course. " +
      "The Trail counts a course as the completion unit. The season runs year-round.";
    const shaTn = sha(TN_BYTES2);
    const evidenceByTrail: EvidenceByTrail = {
      TN: {
        bySha: new Map([
          [
            shaTn,
            {
              text: TN_BYTES2,
              method: "direct" as const,
              methodDefaulted: false,
              recorded: true,
            },
          ],
        ]),
        failedSources: [],
      },
    };
    const confirmation: X2ConfirmationFile = {
      TN: {
        roster: [
          {
            name: "Bear Trace at Harrison Bay",
            quote: "Bear Trace at Harrison Bay is a member course.",
            evidenceSha: shaTn,
          },
        ],
        completionUnit: {
          value: "course",
          quote: "The Trail counts a course as the completion unit.",
          evidenceSha: shaTn,
        },
        season: {
          value: "year-round",
          quote: "The season runs year-round.",
          evidenceSha: shaTn,
        },
      },
    };
    // No corroboration file supplied at all (4th arg omitted) — must still
    // confirm, because none of this trail's facts are owner-saved.
    const result = computeX2Verdict(confirmation, evidenceByTrail, ["TN"]);
    const tn = result.perTrail.TN;
    expect(tn?.confirmed).toBe(true);
    expect(tn?.facts.roster[0]?.corroboration).toBeNull();
    expect(tn?.facts.completionUnit?.corroboration).toBeNull();
    expect(tn?.facts.season?.corroboration).toBeNull();
  });

  it("renderX2VerdictMarkdown prints the corroboration summary inline for an owner-saved fact", async () => {
    const { renderX2VerdictMarkdown } = await import("../src/x2-verdict.js");
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: {
          type: "acceptance",
          acceptedBy: "Matt",
          date: "2026-09-20",
        },
      },
    };
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration);
    const md = renderX2VerdictMarkdown(result);
    expect(md).toMatch(
      /corroboration: owner-attested, accepted uncorroborated by Matt on 2026-09-20/,
    );
  });
});
