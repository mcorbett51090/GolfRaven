import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { promisify } from "node:util";
import {
  buildEvidenceByTrail,
  checkLedgerAgainstGit,
  computeX2Verdict,
  corroborationResolutionKey,
  extractX2MdLogSection,
  resolveCorroboration,
  sameConfiguredHost,
  type EvidenceByTrail,
  type X2ConfirmationFile,
  type X2CorroborationFile,
  type X2ResolvedCorroboration,
} from "../src/x2-verdict.js";

const execFileAsync = promisify(execFile);
import type { X2FetchEntry, X2FetchManifest } from "../src/x2-fetch.js";
import {
  normalizeUrlForFirstCapture,
  type RecordedLedger,
} from "../src/x2-recorded-ledger.js";

/** Gate finding 2c (re-gate): `buildEvidenceByTrail`'s `ledger` option is
 * now REQUIRED — most tests in this file build a manifest they already
 * fully trust (synthetic fixtures, not a real multi-session capture
 * history) and just want every "fetched" entry to come back `recorded:
 * true`, exactly as the removed manifest-field fallback used to give
 * them. This derives a matching ledger straight from the manifest's own
 * entries, so each test keeps its EXACT prior behaviour while still
 * exercising the real, ledger-authoritative code path (never a shortcut
 * that skips it). Tests that specifically exercise ledger MISmatches
 * build their own bespoke ledger instead of calling this. */
function ledgerFromManifest(manifest: X2FetchManifest): RecordedLedger {
  const entries: RecordedLedger["entries"] = [];
  for (const trailEntries of Object.values(manifest.trails)) {
    for (const e of trailEntries) {
      if (e.status !== "fetched" || !e.sha256) continue;
      let normalizedUrl: string;
      try {
        normalizedUrl = normalizeUrlForFirstCapture(e.url);
      } catch {
        continue;
      }
      entries.push({
        method: e.method ?? "direct",
        normalizedUrl,
        url: e.url,
        sha256: e.sha256,
        recordedAt: e.fetchedAt,
      });
    }
  }
  return { entries };
}

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
            url: "https://example.com/x",
            ownerSavedDate: null,
          },
        ],
        [
          SHA_PDF,
          {
            text: null,
            method: "direct" as const,
            methodDefaulted: false,
            recorded: true,
            url: "https://example.com/x",
            ownerSavedDate: null,
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
            url: "https://example.com/x",
            ownerSavedDate: null,
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
              url: "https://example.com/x",
              ownerSavedDate: null,
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
              url: "https://example.com/x",
              ownerSavedDate: null,
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
              url: "https://example.com/x",
              ownerSavedDate: null,
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
              url: "https://example.com/x",
              ownerSavedDate: null,
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
              url: "https://example.com/x",
              ownerSavedDate: null,
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
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async (rel) => {
        if (rel === "raw/x.html") return rawBytes;
        // An operator hand-edited the STORED TEXT FILE, but the raw bytes
        // are unchanged — the verdict must ignore this file entirely.
        return Buffer.from(
          "Fabricated roster: Bear Trace, Arbutus Ridge, some invented course.",
        );
      },
      { ledger: ledgerFromManifest(manifest) },
    );
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
    const byTrail = await buildEvidenceByTrail(manifest, async () => rawBytes, {
      ledger: ledgerFromManifest(manifest),
    });
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
      buildEvidenceByTrail(
        manifest,
        async () => Buffer.from("<p>Real content.</p>"),
        { ledger: ledgerFromManifest(manifest) },
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
    const byTrail = await buildEvidenceByTrail(manifest, async () => rawBytes, {
      ledger: ledgerFromManifest(manifest),
    });
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
    const byTrail = await buildEvidenceByTrail(manifest, async () => rawBytes, {
      ledger: ledgerFromManifest(manifest),
    });
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
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(""),
      { ledger: ledgerFromManifest(manifest) },
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
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger: ledgerFromManifest(manifest) },
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
      buildEvidenceByTrail(manifest, async () => Buffer.from(bytes), {
        ledger: ledgerFromManifest(manifest),
      }),
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
      buildEvidenceByTrail(manifest, async () => Buffer.from(bytes), {
        ledger: ledgerFromManifest(manifest),
      }),
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
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger: ledgerFromManifest(manifest) },
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
    // not confirm the trail. Supplying Matt's dated, X2.md-logged
    // acceptance is enough — gate finding 2 (re-gate): one owner-saved
    // capture backing THREE different facts needs THREE separate
    // acceptance records (one per fact), each resolved as logged — never
    // one blanket acceptance covering whichever facts get cited against
    // this SHA.
    const corroboration: X2CorroborationFile = {
      TN: {
        [rawSha]: [
          { type: "acceptance", fact: "roster:Nine courses make up", acceptedBy: "Matt", date: "2026-09-24" },
          { type: "acceptance", fact: "completionUnit", acceptedBy: "Matt", date: "2026-09-24" },
          { type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-24" },
        ],
      },
    };
    const resolved: X2ResolvedCorroboration = new Map([
      [corroborationResolutionKey("TN", rawSha, "roster:Nine courses make up"), { acceptanceLogged: true }],
      [corroborationResolutionKey("TN", rawSha, "completionUnit"), { acceptanceLogged: true }],
      [corroborationResolutionKey("TN", rawSha, "season"), { acceptanceLogged: true }],
    ]);
    const result = computeX2Verdict(confirmation, byTrail, ["TN"], corroboration, resolved);
    expect(result.perTrail.TN?.confirmed).toBe(true);
    expect(result.perTrail.TN?.facts.season?.method).toBe("owner-saved");
    expect(result.perTrail.TN?.facts.season?.corroboration).toBe(
      "owner-attested, accepted by Matt on 2026-09-24 (X2.md Log row, commit unavailable)",
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
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger: ledgerFromManifest(manifest) },
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
    // Gate finding 2c (re-gate): this entry's OWN `recorded: false` field
    // is no longer what decides anything — an EMPTY ledger (nothing ever
    // registered this SHA as the recorded capture) is what correctly
    // produces `recorded: false` here now; the manifest field is inert.
    const byTrail = await buildEvidenceByTrail(manifest, async () =>
      Buffer.from(bytes),
      { ledger: { entries: [] } },
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

  it("gate finding 2c (re-gate): a legacy entry with no `method` field defaults method to \"direct\" — but `recorded` is now PURELY ledger-derived, never assumed from the (now-ignored) manifest field, present or absent", async () => {
    const bytes =
      "Nine courses make up the Trail. It counts a course. The season runs year-round.";
    const rawSha = sha(bytes);
    const legacyEntry = baseManifestEntry({
      sha256: rawSha,
      rawFile: "raw/x.html",
    });
    delete (legacyEntry as { recorded?: unknown }).recorded;
    delete (legacyEntry as { method?: unknown }).method;
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: { TN: [legacyEntry] },
      draftCandidateNames: { TN: [] },
    };

    // With NOTHING in the ledger, this legacy entry is NOT recorded —
    // there is no more "missing field defaults to true" fallback.
    const byTrailEmpty = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      { ledger: { entries: [] } },
    );
    expect(byTrailEmpty.TN?.bySha.get(rawSha)?.method).toBe("direct");
    expect(byTrailEmpty.TN?.bySha.get(rawSha)?.methodDefaulted).toBe(true);
    expect(byTrailEmpty.TN?.bySha.get(rawSha)?.recorded).toBe(false);

    // With a MATCHING ledger row (method "direct" — the defaulted value,
    // since that's what a real ledger entry for a legacy capture would
    // have been registered under), it IS recorded.
    const byTrailWithLedger = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      {
        ledger: {
          entries: [
            {
              method: "direct",
              normalizedUrl: normalizeUrlForFirstCapture(legacyEntry.url),
              url: legacyEntry.url,
              sha256: rawSha,
              recordedAt: new Date().toISOString(),
            },
          ],
        },
      },
    );
    expect(byTrailWithLedger.TN?.bySha.get(rawSha)?.recorded).toBe(true);
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
          // www. is stripped by normalizeUrlForFirstCapture — this must
          // match EXACTLY what the manifest entry's own URL normalises
          // to, per gate finding 2b (re-gate): a mismatched normalizedUrl
          // here would no longer match, by design (see the mismatch test
          // right after this one).
          normalizedUrl: "tnstateparks.com/golf",
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
          normalizedUrl: "tnstateparks.com/golf",
          url: "https://www.tnstateparks.com/golf",
          sha256: rawSha,
          recordedAt: new Date().toISOString(),
        },
      ],
    };
    const byTrail = await buildEvidenceByTrail(
      manifest,
      async () => Buffer.from(bytes),
      // This test is about ledger method-scoping, not the rendered-route
      // allow-list (should-fix, re-gate) — TN is explicitly allowed a
      // "rendered" entry here so the two concerns stay independently
      // testable.
      { ledger, renderedAllowedTrails: ["VI", "TN"] },
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

describe("x2-verdict: rendered-route allow-list is VI-only by default (should-fix, re-gate)", () => {
  function renderedEntry(trail: string, sha256: string, url: string) {
    return {
      trail,
      url,
      status: "fetched" as const,
      httpStatus: 200,
      finalUrl: url,
      contentType: "text/html",
      fetchedAt: new Date().toISOString(),
      sha256,
      rawFile: "raw/x.html",
      textFile: null,
      textExtraction: "auto" as const,
      extractor: null,
      blocked: false,
      error: null,
      draftCandidateNames: [],
      method: "rendered" as const,
      ownerSavedDate: null,
      renderArgs: [],
      renderProxyHost: null,
      recorded: true,
    };
  }

  it("refuses (throws) a rendered entry for a trail OTHER than VI, with the default allow-list", async () => {
    const bytes = "Some rendered content.";
    const rawSha = sha(bytes);
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-render-evidence",
      trails: { RTJ: [renderedEntry("RTJ", rawSha, "https://www.rtjgolf.com/")] },
      draftCandidateNames: { RTJ: [] },
    };
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "rendered",
          normalizedUrl: "rtjgolf.com/",
          url: "https://www.rtjgolf.com/",
          sha256: rawSha,
          recordedAt: new Date().toISOString(),
        },
      ],
    };
    await expect(
      buildEvidenceByTrail(manifest, async () => Buffer.from(bytes), { ledger }),
    ).rejects.toThrow(/rendered-route allow-list/);
  });

  it("accepts a rendered entry for VI, with the default allow-list", async () => {
    const bytes = "Some rendered VI content.";
    const rawSha = sha(bytes);
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-render-evidence",
      trails: { VI: [renderedEntry("VI", rawSha, "https://golfvancouverisland.ca/")] },
      draftCandidateNames: { VI: [] },
    };
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "rendered",
          normalizedUrl: "golfvancouverisland.ca/",
          url: "https://golfvancouverisland.ca/",
          sha256: rawSha,
          recordedAt: new Date().toISOString(),
        },
      ],
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () => Buffer.from(bytes), { ledger });
    expect(byTrail.VI?.bySha.get(rawSha)?.method).toBe("rendered");
  });

  it("an explicit renderedAllowedTrails override widens the list for a deliberate, documented exception", async () => {
    const bytes = "Some rendered TN content.";
    const rawSha = sha(bytes);
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-render-evidence",
      trails: { TN: [renderedEntry("TN", rawSha, "https://www.tnstateparks.com/golf")] },
      draftCandidateNames: { TN: [] },
    };
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "rendered",
          normalizedUrl: "tnstateparks.com/golf",
          url: "https://www.tnstateparks.com/golf",
          sha256: rawSha,
          recordedAt: new Date().toISOString(),
        },
      ],
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () => Buffer.from(bytes), {
      ledger,
      renderedAllowedTrails: ["VI", "TN"],
    });
    expect(byTrail.TN?.bySha.get(rawSha)?.method).toBe("rendered");
  });

  it("a DIRECT or owner-saved entry for a non-VI trail is unaffected — the allow-list only gates method 'rendered'", async () => {
    const bytes = "Direct-fetched TN content.";
    const rawSha = sha(bytes);
    const manifest: X2FetchManifest = {
      generatedAt: new Date().toISOString(),
      outDir: "x2-evidence",
      trails: {
        TN: [
          {
            ...renderedEntry("TN", rawSha, "https://www.tnstateparks.com/golf"),
            method: "direct" as const,
          },
        ],
      },
      draftCandidateNames: { TN: [] },
    };
    const ledger: RecordedLedger = {
      entries: [
        {
          method: "direct",
          normalizedUrl: "tnstateparks.com/golf",
          url: "https://www.tnstateparks.com/golf",
          sha256: rawSha,
          recordedAt: new Date().toISOString(),
        },
      ],
    };
    const byTrail = await buildEvidenceByTrail(manifest, async () => Buffer.from(bytes), { ledger });
    expect(byTrail.TN?.bySha.get(rawSha)?.method).toBe("direct");
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
              url: "https://example.com/x",
              ownerSavedDate: null,
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

  it("an owner-saved fact backed by Matt's dated acceptance record, LOGGED in X2.md, passes and names it", () => {
    // Gate finding 2 (re-gate): roster/completionUnit/season all cite the
    // SAME owner-saved SHA — each needs its OWN acceptance record, naming
    // its own fact, for the trail to confirm overall.
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: [
          { type: "acceptance", fact: "roster:Pinehurst Creek", acceptedBy: "Matt", date: "2026-09-20" },
          { type: "acceptance", fact: "completionUnit", acceptedBy: "Matt", date: "2026-09-20" },
          { type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" },
        ],
      },
    };
    const resolved: X2ResolvedCorroboration = new Map([
      [corroborationResolutionKey("NC", SHA_OWNER, "roster:Pinehurst Creek"), { acceptanceLogged: true }],
      [corroborationResolutionKey("NC", SHA_OWNER, "completionUnit"), { acceptanceLogged: true }],
      [corroborationResolutionKey("NC", SHA_OWNER, "season"), { acceptanceLogged: true }],
    ]);
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration, resolved);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(true);
    expect(nc?.facts.roster[0]?.corroboration).toBe(
      "owner-attested, accepted by Matt on 2026-09-20 (X2.md Log row, commit unavailable)",
    );
    expect(nc?.reasons.join("\n")).toMatch(/accepted by Matt on 2026-09-20/);
  });

  it("gate finding 2 (re-gate): an acceptance record whose fact does NOT match the fact being checked is rejected — one fact's acceptance never backs another", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
      },
    };
    const resolved: X2ResolvedCorroboration = new Map([
      [corroborationResolutionKey("NC", SHA_OWNER, "season"), { acceptanceLogged: true }],
    ]);
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration, resolved);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(false);
    // Roster/completionUnit have no MATCHING record at all (only "season"
    // is in the array) — uncorroborated for THIS fact, distinctly worded.
    expect(nc?.facts.roster[0]?.corroboration).toBe("owner-attested, uncorroborated for this fact");
    expect(nc?.facts.completionUnit?.corroboration).toBe("owner-attested, uncorroborated for this fact");
    expect(nc?.facts.season?.corroboration).toBe(
      "owner-attested, accepted by Matt on 2026-09-20 (X2.md Log row, commit unavailable)",
    );
  });

  it("gate finding 3 (re-gate): an acceptance record whose acceptedBy is NOT exactly \"Matt\" is rejected outright, even if it WOULD be logged", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: [
          {
            type: "acceptance",
            fact: "roster:Pinehurst Creek",
            acceptedBy: "matt", // wrong case — not exact
            date: "2026-09-20",
          },
        ],
      },
    };
    const resolved: X2ResolvedCorroboration = new Map([
      [corroborationResolutionKey("NC", SHA_OWNER, "roster:Pinehurst Creek"), { acceptanceLogged: true }],
    ]);
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration, resolved);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(false);
    expect(nc?.facts.roster[0]?.corroboration).toMatch(/acceptedBy is not Matt/);
    expect(nc?.reasons.join("\n")).toMatch(/acceptedBy must be exactly "Matt"/);
  });

  it("gate finding 2 (re-gate): an acceptance record that is NOT resolved as logged (and pushed) in X2.md's Log is rejected — the JSON file alone is never enough", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: [
          { type: "acceptance", fact: "roster:Pinehurst Creek", acceptedBy: "Matt", date: "2026-09-20" },
        ],
      },
    };
    // No resolved map entry at all (as if the resolution pass never ran,
    // or ran and found nothing) — the safe default.
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(false);
    expect(nc?.facts.roster[0]?.corroboration).toMatch(/NOT FOUND\/NOT PUSHED in X2\.md's Log/);
    expect(nc?.reasons.join("\n")).toMatch(/reachable from origin\/main, was found in docs\/p0\/X2\.md/);
  });

  it("an owner-saved fact backed by a VERIFIED Wayback snapshot whose re-derived text contains the quote passes and names the snapshot", () => {
    // Gate finding 3 (second re-gate): a `wayback` record is NOT
    // fact-specific — one snapshot of the whole page corroborates every
    // fact drawn from it, regardless of which one is being checked.
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: [
          {
            type: "wayback",
            snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/nc-trail",
            snapshotSha256: "e".repeat(64),
            rawFile: "raw/wayback-e.html",
          },
        ],
      },
    };
    const resolved: X2ResolvedCorroboration = new Map([
      [
        corroborationResolutionKey("NC", SHA_OWNER),
        {
          waybackVerified: true,
          waybackText: "The North Carolina Golf Trail. Pinehurst Creek is a member course.",
        },
      ],
    ]);
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration, resolved);
    const nc = result.perTrail.NC;
    // completionUnit/season quotes are NOT in the re-derived text, so the
    // trail as a whole still does not confirm — but the roster entry
    // itself, which IS corroborated, must say so.
    expect(nc?.facts.roster[0]?.corroboration).toMatch(
      /^owner-attested, corroborated by Wayback snapshot https:\/\/web\.archive\.org\/web\/20260101000000\/https:\/\/example\.com\/nc-trail \(sha256 eeeeeeeeeeee\.\.\.\)$/,
    );
    expect(nc?.reasons.join("\n")).toMatch(/corroborated by Wayback snapshot/);
  });

  it("an owner-saved fact backed by a VERIFIED Wayback snapshot whose re-derived text does NOT contain the quote fails corroboration", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: [
          {
            type: "wayback",
            snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/nc-trail",
            snapshotSha256: "f".repeat(64),
            rawFile: "raw/wayback-f.html",
          },
        ],
      },
    };
    const resolved: X2ResolvedCorroboration = new Map([
      [
        corroborationResolutionKey("NC", SHA_OWNER),
        { waybackVerified: true, waybackText: "This snapshot says nothing about the roster at all." },
      ],
    ]);
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration, resolved);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(false);
    expect(nc?.facts.roster[0]?.corroboration).toMatch(/Wayback corroboration FAILED/);
    expect(nc?.reasons.join("\n")).toMatch(
      /quote does NOT appear verbatim in the snapshot's own \(re-derived\) text/,
    );
  });

  it("gate finding 3 (re-gate): a Wayback record whose evidence FAILED re-verification (SHA mismatch/unreadable) is UNVERIFIABLE, regardless of what text a forger might claim", () => {
    const corroboration: X2CorroborationFile = {
      NC: {
        [SHA_OWNER]: [
          {
            type: "wayback",
            snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/nc-trail",
            snapshotSha256: "a".repeat(64),
            rawFile: "raw/wayback-a.html",
          },
        ],
      },
    };
    // No resolved map entry (as the CLI's own pass would produce if the
    // raw file's recomputed SHA did not match `snapshotSha256`, or the
    // file could not be read at all) — the safe default.
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration);
    const nc = result.perTrail.NC;
    expect(nc?.confirmed).toBe(false);
    expect(nc?.facts.roster[0]?.corroboration).toMatch(/Wayback corroboration UNVERIFIABLE/);
    expect(nc?.reasons.join("\n")).toMatch(/failed re-validation/);
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
              url: "https://example.com/x",
              ownerSavedDate: null,
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
        [SHA_OWNER]: [
          { type: "acceptance", fact: "roster:Pinehurst Creek", acceptedBy: "Matt", date: "2026-09-20" },
        ],
      },
    };
    const resolved: X2ResolvedCorroboration = new Map([
      [corroborationResolutionKey("NC", SHA_OWNER, "roster:Pinehurst Creek"), { acceptanceLogged: true }],
    ]);
    const result = computeX2Verdict(ncConfirmation(), ownerEvidenceByTrail(), ["NC"], corroboration, resolved);
    const md = renderX2VerdictMarkdown(result);
    expect(md).toMatch(
      /corroboration: owner-attested, accepted by Matt on 2026-09-20 \(X2\.md Log row, commit unavailable\)/,
    );
  });
});

describe("x2-verdict: extractX2MdLogSection (gate finding 3, re-gate)", () => {
  it("extracts everything from a top-level '## Log' heading onward", () => {
    const doc = "# X2\n\n## STATUS\n\nsome status\n\n## Log\n\n| Date | Entry |\n|---|---|\n| 2026-09-24 | did a thing |\n";
    const section = extractX2MdLogSection(doc);
    expect(section.startsWith("## Log")).toBe(true);
    expect(section).toContain("did a thing");
    expect(section).not.toContain("some status");
  });

  it("returns the WHOLE text when no '## Log' heading exists — a missing section is surfaced, not silently empty", () => {
    const doc = "# X2\n\n## STATUS\n\nno log section here at all\n";
    const section = extractX2MdLogSection(doc);
    expect(section).toBe(doc);
  });

  it("a stray mention of an id/date OUTSIDE the Log section does not count as logged (scoped correctly)", () => {
    const doc =
      "# X2\n\n## STATUS\n\nNC-2026-09-20-acceptance was discussed informally on 2026-09-20 but not logged.\n\n## Log\n\n| Date | Entry |\n|---|---|\n| 2026-09-19 | unrelated |\n";
    const section = extractX2MdLogSection(doc);
    expect(section).not.toContain("NC-2026-09-20-acceptance");
  });
});

describe("x2-verdict: resolveCorroboration (gate finding 3 second re-gate / finding 2 re-gate)", () => {
  const SHA_OWNER_FOR_RESOLVE = sha("arbitrary evidence sha key for these tests");
  const OWNER_STATED_URL = "https://example.com/x";
  const OWNER_SAVED_DATE = "2026-01-01"; // within 90 days of the 2026-01-01... wayback timestamps below

  function ownerEvidenceByTrail(): EvidenceByTrail {
    return {
      NC: {
        bySha: new Map([
          [
            SHA_OWNER_FOR_RESOLVE,
            {
              text: "owner text",
              method: "owner-saved",
              methodDefaulted: false,
              recorded: true,
              url: OWNER_STATED_URL,
              ownerSavedDate: OWNER_SAVED_DATE,
            },
          ],
        ]),
        failedSources: [],
      },
    };
  }

  const EVIDENCE_DIR = "/evidence-dir";

  describe("wayback (gate finding 3, second re-gate — re-validates every rule itself)", () => {
    it("verifies a record that passes every rule, re-deriving text with the real extractor", async () => {
      const html = "<html><body><p>Real snapshot content, fetched for real.</p></body></html>";
      const buf = Buffer.from(html);
      const shaOfBuf = sha(html);
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/x",
              snapshotSha256: shaOfBuf,
              rawFile: `raw/${shaOfBuf}.html`,
            },
          ],
        },
      };
      const ledger: RecordedLedger = {
        entries: [
          {
            method: "wayback",
            normalizedUrl: "example.com/x",
            url: OWNER_STATED_URL,
            sha256: shaOfBuf,
            recordedAt: new Date().toISOString(),
          },
        ],
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async (rel) => {
          expect(rel).toBe(`raw/${shaOfBuf}.html`);
          return buf;
        },
        evidenceDir: EVIDENCE_DIR,
        ledger,
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(true);
      expect(entry?.waybackText).toContain("Real snapshot content, fetched for real.");
    });

    it("refuses a snapshotUrl not in the required Wayback URL form", async () => {
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://not-archive.example/x",
              snapshotSha256: "e".repeat(64),
              rawFile: `raw/${"e".repeat(64)}.html`,
            },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackDetail).toMatch(/required.*form/);
    });

    it("refuses when the embedded URL does not normalise to the owner-saved fact's OWN stated URL", async () => {
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/completely-different",
              snapshotSha256: "e".repeat(64),
              rawFile: `raw/${"e".repeat(64)}.html`,
            },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackDetail).toMatch(/does not match the owner-saved fact's own stated URL/);
    });

    it("refuses a timestamp more than 90 days from the owner-saved fact's OWN ownerSavedDate", async () => {
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              // OWNER_SAVED_DATE is 2026-01-01; this timestamp is wildly later.
              snapshotUrl: "https://web.archive.org/web/20270101000000/https://example.com/x",
              snapshotSha256: "e".repeat(64),
              rawFile: `raw/${"e".repeat(64)}.html`,
            },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackDetail).toMatch(/90-day tolerance/);
    });

    it("gate finding 3 (second re-gate), probe C: refuses a rawFile path-escape attempt (e.g. ../../outside.html) outright — it can never match the required shape", async () => {
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/x",
              snapshotSha256: "e".repeat(64),
              rawFile: "../../outside.html",
            },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => Buffer.from("<p>The quote you want to see is right here.</p>"),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackDetail).toMatch(/raw\/<snapshotSha256>\.<ext>/);
    });

    it("gate finding 3 (second re-gate), probe B: refuses a snapshot SHA IDENTICAL to the owner-saved fact's own SHA (self-referential forgery)", async () => {
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/x",
              snapshotSha256: SHA_OWNER_FOR_RESOLVE, // identical to the owner-saved fact's own SHA
              rawFile: `raw/${SHA_OWNER_FOR_RESOLVE}.html`,
            },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => Buffer.from("owner text"),
        evidenceDir: EVIDENCE_DIR,
        ledger: {
          entries: [
            {
              method: "wayback",
              normalizedUrl: "example.com/x",
              url: OWNER_STATED_URL,
              sha256: SHA_OWNER_FOR_RESOLVE,
              recordedAt: new Date().toISOString(),
            },
          ],
        },
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackDetail).toMatch(/IDENTICAL to the owner-saved fact's own SHA/);
    });

    it("refuses a snapshot that is otherwise well-formed but NOT registered in the ledger under method wayback — never produced by x2-corroborate-wayback", async () => {
      const html = "<p>some snapshot text</p>";
      const shaOfBuf = sha(html);
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/x",
              snapshotSha256: shaOfBuf,
              rawFile: `raw/${shaOfBuf}.html`,
            },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => Buffer.from(html),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] }, // empty — never registered
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackDetail).toMatch(/no ledger entry registers this snapshot/);
    });

    it("a SHA mismatch (tampered/wrong raw bytes) resolves to unverified even after every other rule passes", async () => {
      const claimedSha = "d".repeat(64);
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/x",
              snapshotSha256: claimedSha,
              rawFile: `raw/${claimedSha}.html`,
            },
          ],
        },
      };
      const ledger: RecordedLedger = {
        entries: [
          {
            method: "wayback",
            normalizedUrl: "example.com/x",
            url: OWNER_STATED_URL,
            sha256: claimedSha,
            recordedAt: new Date().toISOString(),
          },
        ],
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => Buffer.from("<p>The quote you want to see is right here.</p>"),
        evidenceDir: EVIDENCE_DIR,
        ledger,
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackText).toBeUndefined();
    });

    it("a read failure (missing/unreadable raw file) resolves to unverified, never throws", async () => {
      const claimedSha = "d".repeat(64);
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            {
              type: "wayback",
              snapshotUrl: "https://web.archive.org/web/20260101000000/https://example.com/x",
              snapshotSha256: claimedSha,
              rawFile: `raw/${claimedSha}.html`,
            },
          ],
        },
      };
      const ledger: RecordedLedger = {
        entries: [
          {
            method: "wayback",
            normalizedUrl: "example.com/x",
            url: OWNER_STATED_URL,
            sha256: claimedSha,
            recordedAt: new Date().toISOString(),
          },
        ],
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: ownerEvidenceByTrail(),
        readRaw: async () => {
          throw new Error("ENOENT");
        },
        evidenceDir: EVIDENCE_DIR,
        ledger,
        x2Md: null,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
    });
  });

  describe("acceptance (gate finding 2, re-gate — structured row + git provenance)", () => {
    async function initGitRepoWithOrigin(): Promise<{ dir: string; originDir: string }> {
      const originDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-x2md-origin-"));
      await execFileAsync("git", ["init", "-q", "--bare"], { cwd: originDir });
      const dir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-x2md-work-"));
      await execFileAsync("git", ["init", "-q"], { cwd: dir });
      await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: dir });
      await execFileAsync("git", ["config", "user.name", "Test"], { cwd: dir });
      await execFileAsync("git", ["remote", "add", "origin", originDir], { cwd: dir });
      return { dir, originDir };
    }

    it("resolves logged: true only when a structured ACCEPT row exists in the Log section AND its commit is reachable from origin/main", async () => {
      const { dir } = await initGitRepoWithOrigin();
      const x2MdPath = nodePath.join(dir, "X2.md");
      const fullText = `# X2\n\n## Log\n\nACCEPT NC roster:Pinehurst Creek ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
      writeFileSync(x2MdPath, fullText, "utf8");
      await execFileAsync("git", ["add", "X2.md"], { cwd: dir });
      await execFileAsync("git", ["commit", "-q", "-m", "accept"], { cwd: dir });
      await execFileAsync("git", ["push", "-q", "origin", "HEAD:main"], { cwd: dir });

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            { type: "acceptance", fact: "roster:Pinehurst Creek", acceptedBy: "Matt", date: "2026-09-20" },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: {},
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
      });
      const entry = resolved.get(
        corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "roster:Pinehurst Creek"),
      );
      expect(entry?.acceptanceLogged).toBe(true);
      expect(entry?.acceptanceProvenance?.reachableFromOriginMain).toBe(true);
      expect(entry?.acceptanceProvenance?.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(entry?.acceptanceProvenance?.author).toBe("Test");
    });

    it("resolves logged: false when the matching row exists but its commit is NOT reachable from origin/main (never pushed)", async () => {
      const { dir } = await initGitRepoWithOrigin();
      const x2MdPath = nodePath.join(dir, "X2.md");
      const fullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
      writeFileSync(x2MdPath, fullText, "utf8");
      await execFileAsync("git", ["add", "X2.md"], { cwd: dir });
      await execFileAsync("git", ["commit", "-q", "-m", "accept, never pushed"], { cwd: dir });
      // Deliberately never pushed to origin.

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: {},
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
      expect(entry?.acceptanceLogged).toBe(false);
      expect(entry?.acceptanceDetail).toMatch(/not reachable from origin\/main/);
    });

    it("resolves logged: false when no matching structured row exists at all", async () => {
      const { dir } = await initGitRepoWithOrigin();
      const x2MdPath = nodePath.join(dir, "X2.md");
      const fullText = "# X2\n\n## Log\n\nsome unrelated line, not an ACCEPT row\n";
      writeFileSync(x2MdPath, fullText, "utf8");
      await execFileAsync("git", ["add", "X2.md"], { cwd: dir });
      await execFileAsync("git", ["commit", "-q", "-m", "init"], { cwd: dir });

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: {},
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
      expect(entry?.acceptanceLogged).toBe(false);
      expect(entry?.acceptanceDetail).toMatch(/no line reading exactly/);
    });

    it("gate finding 2 (re-gate), should-fix: a row matching everything but sitting AFTER the next '## ' heading (outside the bounded Log section) does not count", async () => {
      const { dir } = await initGitRepoWithOrigin();
      const x2MdPath = nodePath.join(dir, "X2.md");
      const fullText =
        "# X2\n\n## Log\n\nunrelated\n\n## Later Section\n\n" +
        `ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
      writeFileSync(x2MdPath, fullText, "utf8");
      await execFileAsync("git", ["add", "X2.md"], { cwd: dir });
      await execFileAsync("git", ["commit", "-q", "-m", "init"], { cwd: dir });
      await execFileAsync("git", ["push", "-q", "origin", "HEAD:main"], { cwd: dir });

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: {},
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
      expect(entry?.acceptanceLogged).toBe(false);
    });

    it("a null x2Md (X2.md unreadable) resolves logged: false, never throws", async () => {
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: {},
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: null,
      });
      expect(
        resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"))?.acceptanceLogged,
      ).toBe(false);
    });
  });
});

describe("x2-verdict: checkLedgerAgainstGit (gate finding 2d / gate finding 4, re-gate)", () => {
  /** Gate finding 4: a repo with a real `origin` (bare) remote, so
   * "pushed to origin/main" is genuinely checkable — every probe in this
   * describe block needs this now, not just an origin-less local repo. */
  async function initGitRepoWithOrigin(): Promise<{ dir: string; ledgerPath: string }> {
    const originDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-ledger-origin-"));
    await execFileAsync("git", ["init", "-q", "--bare"], { cwd: originDir });
    const dir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-ledger-git-test-"));
    await execFileAsync("git", ["init", "-q"], { cwd: dir });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: dir });
    await execFileAsync("git", ["config", "user.name", "Test"], { cwd: dir });
    await execFileAsync("git", ["remote", "add", "origin", originDir], { cwd: dir });
    mkdirSync(nodePath.join(dir, "docs", "p0"), { recursive: true });
    const ledgerPath = nodePath.join(dir, "docs", "p0", "x2-recorded-ledger.json");
    return { dir, ledgerPath };
  }

  it("gate finding 4, probe A: a canonical-path, committed, PUSHED ledger is reported clean, with its git blob hash and last commit", async () => {
    const { dir, ledgerPath } = await initGitRepoWithOrigin();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger"], { cwd: dir });
    await execFileAsync("git", ["push", "-q", "origin", "HEAD:main"], { cwd: dir });

    const result = await checkLedgerAgainstGit(ledgerPath);
    expect(result.pathIsCanonical).toBe(true);
    expect(result.pushedToOriginMain).toBe(true);
    expect(result.originMainMissingPath).toBe(false);
    expect(result.hiddenByGitFlag).toBe(false);
    expect(result.clean).toBe(true);
    expect(result.blobHash).toMatch(/^[0-9a-f]{40}$/);
    expect(result.lastCommit?.hash).toMatch(/^[0-9a-f]{40}$/);
    expect(result.lastCommit?.author).toBe("Test");

    const { stdout } = await execFileAsync(
      "git",
      ["hash-object", "docs/p0/x2-recorded-ledger.json"],
      { cwd: dir },
    );
    expect(result.blobHash).toBe(stdout.trim());
  });

  it("gate finding 4: a WRONG-location ledger (right repo, right filename, wrong directory) is refused as not canonical, never treated as if it were", async () => {
    const { dir } = await initGitRepoWithOrigin();
    const wrongPath = nodePath.join(dir, "x2-recorded-ledger.json"); // repo root, not docs/p0/
    writeFileSync(wrongPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "wrong location"], { cwd: dir });
    await execFileAsync("git", ["push", "-q", "origin", "HEAD:main"], { cwd: dir });

    const result = await checkLedgerAgainstGit(wrongPath);
    expect(result.pathIsCanonical).toBe(false);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/is not the canonical ledger path/);
  });

  it("a committed, canonical-path ledger with an UNCOMMITTED edit is reported dirty, with a reason", async () => {
    const { dir, ledgerPath } = await initGitRepoWithOrigin();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger"], { cwd: dir });
    await execFileAsync("git", ["push", "-q", "origin", "HEAD:main"], { cwd: dir });

    // Edit it WITHOUT committing — simulates a hand-edited ledger row
    // (e.g. the gate's own `edited-ledger.json` bypass attempt) that
    // never went through review/commit.
    writeFileSync(
      ledgerPath,
      '{"entries": [{"method": "rendered", "normalizedUrl": "x", "url": "x", "sha256": "' +
        "a".repeat(64) +
        '", "recordedAt": "2026-01-01T00:00:00Z"}]}\n',
      "utf8",
    );

    const result = await checkLedgerAgainstGit(ledgerPath);
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/uncommitted changes/);
    // The blob hash is still reported (of the CURRENT, dirty content) —
    // never withheld just because the ledger is dirty.
    expect(result.blobHash).toMatch(/^[0-9a-f]{40}$/);
  });

  it("an UNTRACKED ledger file (never git-added at all) is reported dirty — `git diff` alone would miss this", async () => {
    const { dir, ledgerPath } = await initGitRepoWithOrigin();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    // Deliberately never `git add`ed or committed.

    const result = await checkLedgerAgainstGit(ledgerPath);
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/untracked/);
  });

  it("gate finding 4, probe D: a canonical, committed ledger that origin/main does NOT have yet is marked UNOFFICIAL (originMainMissingPath), never a plain dirty refusal", async () => {
    const { dir, ledgerPath } = await initGitRepoWithOrigin();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger, never pushed"], { cwd: dir });
    // Deliberately never pushed — origin has no "main" ref at all yet.

    const result = await checkLedgerAgainstGit(ledgerPath);
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.pushedToOriginMain).toBe(false);
    expect(result.originMainMissingPath).toBe(true);
    expect(result.detail).toMatch(/has not been pushed yet/);
  });

  it("gate finding 4, probe D: a canonical, committed ledger whose content DIVERGED from what origin/main already has is refused as dirty (not the missing-path carve-out)", async () => {
    const { dir, ledgerPath } = await initGitRepoWithOrigin();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "v1"], { cwd: dir });
    await execFileAsync("git", ["push", "-q", "origin", "HEAD:main"], { cwd: dir });

    // A second, LOCAL-ONLY commit changes the ledger's content without
    // re-pushing — origin/main still has the OLD blob.
    writeFileSync(
      ledgerPath,
      '{"entries": [{"method": "direct", "normalizedUrl": "x", "url": "x", "sha256": "' +
        "b".repeat(64) +
        '", "recordedAt": "2026-01-01T00:00:00Z"}]}\n',
      "utf8",
    );
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "v2, local only"], { cwd: dir });

    const result = await checkLedgerAgainstGit(ledgerPath);
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.pushedToOriginMain).toBe(false);
    expect(result.originMainMissingPath).toBe(false);
    expect(result.detail).toMatch(/locally diverged from the pushed record/);
  });

  it("gate finding 4, probe E: a ledger marked assume-unchanged in git is refused (hiddenByGitFlag), even though git diff/status report it clean", async () => {
    const { dir, ledgerPath } = await initGitRepoWithOrigin();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger"], { cwd: dir });
    await execFileAsync("git", ["push", "-q", "origin", "HEAD:main"], { cwd: dir });
    await execFileAsync(
      "git",
      ["update-index", "--assume-unchanged", "docs/p0/x2-recorded-ledger.json"],
      { cwd: dir },
    );
    // Edit the file AFTER marking it assume-unchanged — git diff/status
    // will NOT see this edit at all (that is the whole point of the flag).
    writeFileSync(
      ledgerPath,
      '{"entries": [{"method": "direct", "normalizedUrl": "hidden", "url": "hidden", "sha256": "' +
        "c".repeat(64) +
        '", "recordedAt": "2026-01-01T00:00:00Z"}]}\n',
      "utf8",
    );

    const result = await checkLedgerAgainstGit(ledgerPath);
    expect(result.hiddenByGitFlag).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/assume-unchanged or skip-worktree/);
  });

  it("a path outside any git repository (or a missing file) resolves to NOT clean, never silently 'clean'", async () => {
    const outsideDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-not-a-repo-"));
    const ledgerPath = nodePath.join(outsideDir, "recorded-ledger.json");
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    const result = await checkLedgerAgainstGit(ledgerPath);
    expect(result.clean).toBe(false);
    expect(result.pathIsCanonical).toBe(false);
  });
});
