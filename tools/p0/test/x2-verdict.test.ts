import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { chmodSync, chownSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { promisify } from "node:util";
import {
  buildEvidenceByTrail,
  checkLedgerAgainstGit,
  computeMarkdownLineVisibility,
  computeX2Verdict,
  corroborationResolutionKey,
  detectRuntimeTamper,
  extractX2MdLogSection,
  findAcceptRowLine,
  isNodeOptionTokenAllowed,
  resolveCorroboration,
  resolveGitBinary,
  sameConfiguredHost,
  tokenizeNodeOptions,
  verifyAgainstGitHub,
  type EvidenceByTrail,
  type GitHubVerification,
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

/** Round 6: a hand-built `GitHubVerification` stand-in for tests that
 * don't exercise the real disposable-repo verification mechanism itself
 * (that mechanism has its own dedicated describe blocks further down,
 * against real local bare repos via `verifyAgainstGitHub({repoUrl})`).
 * Every field defaults to a benign "verification succeeded, nothing
 * relevant on GitHub main" shape; pass `overrides` to tune one field
 * (e.g. `ok: false`, or a `blameX2MdLine` that returns a specific
 * provenance) without repeating the rest. */
function fakeGitHubVerification(overrides: Partial<GitHubVerification> = {}): GitHubVerification {
  return {
    ok: true,
    detail: "fake verification (test-only)",
    ledgerBlobHash: null,
    x2MdBlobHash: null,
    x2MdText: null,
    blameX2MdLine: async () => ({
      ok: false,
      detail: "fakeGitHubVerification: blameX2MdLine not configured for this test.",
    }),
    cleanup: async () => {},
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

describe("x2-verdict: computeMarkdownLineVisibility / findAcceptRowLine (gate finding, third re-gate, fix (c))", () => {
  it("a plain prose line is visible", () => {
    const visible = computeMarkdownLineVisibility("hello\nworld\n");
    expect(visible).toEqual([true, true, true]); // trailing empty line from the final \n
  });

  it("a fenced code block (```) hides its own fence lines and everything between them", () => {
    const text = "before\n```\nhidden 1\nhidden 2\n```\nafter\n";
    const visible = computeMarkdownLineVisibility(text);
    const lines = text.split("\n");
    expect(lines[visible.indexOf(false)]).toBe("```");
    expect(visible).toEqual([true, false, false, false, false, true, true]);
  });

  it("a tilde fence (~~~) behaves the same as a backtick fence", () => {
    const text = "before\n~~~\nhidden\n~~~\nafter\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, false, false, false, true, true]);
  });

  it("a MISMATCHED fence character (opened with ```, 'closed' with ~~~) does NOT close the fence — everything after stays hidden", () => {
    const text = "before\n```\nhidden\n~~~\nstill hidden\n```\nafter\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([
      true, // before
      false, // ```
      false, // hidden
      false, // ~~~ (wrong char, does not close)
      false, // still hidden
      false, // ``` (this closes it)
      true, // after
      true, // trailing
    ]);
  });

  it("an unclosed fence hides everything to the end of the file", () => {
    const text = "before\n```\nhidden forever\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, false, false, false]);
  });

  it("a single-line HTML comment hides only that line", () => {
    const text = "before\n<!-- hidden --> \nafter\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, false, true, true]);
  });

  it("a multi-line HTML comment hides every line from the opening <!-- through the closing -->", () => {
    const text = "before\n<!--\nhidden 1\nhidden 2\n-->\nafter\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, false, false, false, false, true, true]);
  });

  it("an unclosed HTML comment hides everything to the end of the file", () => {
    const text = "before\n<!--\nhidden forever\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, false, false, false]);
  });

  it("an indented code block (4 leading spaces, or a tab) is hidden", () => {
    const text = "before\n    indented\n\ttabbed\nafter\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, false, false, true, true]);
  });

  it("3 leading spaces is NOT an indented code block (CommonMark requires 4)", () => {
    const text = "before\n   only three\nafter\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, true, true, true]);
  });

  it("findAcceptRowLine: a fake '## Log' heading hidden inside a comment does not shift where the real section starts", () => {
    const text =
      "# X2\n\n<!--\n## Log\nACCEPT NC season deadbeef 2026-09-20 Matt\n-->\n\n## Log\n\n" +
      "ACCEPT NC season deadbeef 2026-09-20 Matt\n";
    const match = findAcceptRowLine(text, "NC", "season", "deadbeef", "2026-09-20");
    expect(match).not.toBeNull();
    // The REAL "## Log" is on line 8 (1-based) — the row itself on line 10.
    expect(match?.lineNumber).toBe(10);
  });

  it("findAcceptRowLine: returns null when the only matching row is inside a fence", () => {
    const text = "## Log\n\n```\nACCEPT NC season deadbeef 2026-09-20 Matt\n```\n";
    expect(findAcceptRowLine(text, "NC", "season", "deadbeef", "2026-09-20")).toBeNull();
  });

  it("findAcceptRowLine: finds a visible row and reports the correct 1-based line number", () => {
    const text = "# X2\n\n## Log\n\nACCEPT NC season deadbeef 2026-09-20 Matt\n";
    const match = findAcceptRowLine(text, "NC", "season", "deadbeef", "2026-09-20");
    expect(match?.lineNumber).toBe(5);
    expect(match?.line).toBe("ACCEPT NC season deadbeef 2026-09-20 Matt");
  });

  it("round 7 follow-up: <details> stays hidden across a blank line, unlike a generic HTML block", () => {
    const detailsText = "before\n<details>\n<summary>x</summary>\n\nhidden even after the blank line\n\n</details>\nafter\n";
    expect(computeMarkdownLineVisibility(detailsText)).toEqual([
      true, // before
      false, // <details>
      false, // <summary>x</summary>
      false, // (blank line — still inside for <details> specifically)
      false, // hidden even after the blank line
      false, // (blank line)
      false, // </details>
      true, // after
      true, // trailing
    ]);
  });

  it("round 7 follow-up, control: a generic HTML block (<div>) still ends at the first blank line, unaffected by the <details>-specific change", () => {
    const divText = "before\n<div>\nhidden\n\nvisible again after the blank line\n</div>\nafter\n";
    expect(computeMarkdownLineVisibility(divText)).toEqual([
      true, // before
      false, // <div>
      false, // hidden
      true, // (blank line ends the block for <div>, per the generic rule)
      true, // visible again after the blank line
      // `</div>` itself re-matches the generic open/close block-tag
      // regex (pre-existing behaviour, unchanged by this round — errs
      // toward hiding MORE), re-opening tracking through the next line:
      false, // </div>
      false, // after (still "inside" per the re-opened tracking)
      true, // trailing (blank — ends it again)
    ]);
  });

  it("<details> opened and closed on the same line hides only that line", () => {
    const text = "before\n<details>one-liner</details>\nafter\n";
    expect(computeMarkdownLineVisibility(text)).toEqual([true, false, true, true]);
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
    });
  });

  describe("should-fix (fourth re-gate): a Wayback corroboration requires an OFFICIAL ledger", () => {
    it("resolveWaybackRecord refuses (waybackVerified: false) when ledgerOfficial is false, even though the record itself is otherwise fully valid — round 5's exploit A3 shape", async () => {
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
        readRaw: async () => buf,
        evidenceDir: EVIDENCE_DIR,
        ledger,
        x2Md: null,
        ledgerOfficial: false, // <-- the should-fix gate under test
        githubVerification: fakeGitHubVerification(),
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(false);
      expect(entry?.waybackDetail).toMatch(/ledger is not OFFICIAL/);
    });

    it("the SAME record resolves waybackVerified: true when ledgerOfficial is true (control — proves the gate above fails for officialness, not some other reason)", async () => {
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
        readRaw: async () => buf,
        evidenceDir: EVIDENCE_DIR,
        ledger,
        x2Md: null,
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification(),
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE));
      expect(entry?.waybackVerified).toBe(true);
    });
  });

  describe("acceptance (gate finding 2, re-gate; gate finding third+fourth re-gate — trust root + visibility + date rules)", () => {
    /** Round 6: a local BARE repo stands in for "GitHub's real main" —
     * `verifyAgainstGitHub({repoUrl: bareDir})` fetches from it exactly
     * the way the real CLI fetches from GOLFRAVEN_CANONICAL_REPO_URL,
     * through the SAME disposable-repo + scrubbed-environment machinery.
     * No network, no real GitHub. */
    async function initUpstreamBare(): Promise<string> {
      const bareDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-x2-upstream-"));
      await execFileAsync("git", ["init", "-q", "--bare", bareDir]);
      return bareDir;
    }

    /** Pushes `X2.md` to `bareDir`'s `main` — the ONLY way content in
     * these tests ever becomes part of what `verifyAgainstGitHub` will
     * read (gate finding, fourth re-gate: content authority is GitHub
     * main, never a local, un-pushed working tree). Returns the local
     * work tree's own X2.md path too, since `--x2-log`/`canonicalX2MdPath`
     * still need a LOCAL file to exist (used only to confirm the flag
     * POINTS at the right place — never for its content). */
    async function pushX2Md(
      bareDir: string,
      fullText: string,
      message = "log",
    ): Promise<{ workDir: string; x2MdPath: string }> {
      const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-x2-work-"));
      await execFileAsync("git", ["init", "-q"], { cwd: workDir });
      await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: workDir });
      await execFileAsync("git", ["config", "user.name", "Test"], { cwd: workDir });
      // Round 6: verifyAgainstGitHub always reads
      // CANONICAL_X2MD_REPO_RELATIVE_PATH ("docs/p0/X2.md") from
      // refs/heads/main — the pushed file MUST live at that exact
      // repo-relative path, not at the repo root.
      mkdirSync(nodePath.join(workDir, "docs", "p0"), { recursive: true });
      const x2MdPath = nodePath.join(workDir, "docs", "p0", "X2.md");
      writeFileSync(x2MdPath, fullText, "utf8");
      await execFileAsync("git", ["add", "docs/p0/X2.md"], { cwd: workDir });
      await execFileAsync("git", ["commit", "-q", "-m", message], { cwd: workDir });
      await execFileAsync("git", ["branch", "-M", "main"], { cwd: workDir });
      await execFileAsync("git", ["push", "-q", bareDir, "HEAD:main"], { cwd: workDir });
      return { workDir, x2MdPath };
    }

    /** A local X2.md that exists on disk (so `canonicalX2MdPath` can point
     * at it and `realpath` succeeds) but was NEVER pushed anywhere —
     * simulates "a row that looks right locally but never reached GitHub
     * main" (gate finding, fourth re-gate: local content is never
     * trusted). */
    function localOnlyX2Md(fullText: string): { workDir: string; x2MdPath: string } {
      const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-x2-localonly-"));
      const x2MdPath = nodePath.join(workDir, "X2.md");
      writeFileSync(x2MdPath, fullText, "utf8");
      return { workDir, x2MdPath };
    }

    function evidenceWithOwnerSavedDate(ownerSavedDate: string | null): EvidenceByTrail {
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
                url: "https://example.com/nc",
                ownerSavedDate,
              },
            ],
          ]),
          failedSources: [],
        },
      };
    }

    it("resolves logged: true when the row is on GitHub main (the bare upstream), x2Md.path is the (test-injected) canonical path, and blame runs against refs/heads/main", async () => {
      const bareDir = await initUpstreamBare();
      const fullText = `# X2\n\n## Log\n\nACCEPT NC roster:Pinehurst Creek ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
      const { x2MdPath } = await pushX2Md(bareDir, fullText);
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
      expect(verification.ok).toBe(true);

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [
            { type: "acceptance", fact: "roster:Pinehurst Creek", acceptedBy: "Matt", date: "2026-09-20" },
          ],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-19"),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
        canonicalX2MdPath: x2MdPath,
        ledgerOfficial: true,
        githubVerification: verification,
      });
      const entry = resolved.get(
        corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "roster:Pinehurst Creek"),
      );
      expect(entry?.acceptanceLogged).toBe(true);
      expect(entry?.acceptanceProvenance?.reachableFromVerifiedMain).toBe(true);
      expect(entry?.acceptanceProvenance?.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(entry?.acceptanceProvenance?.author).toBe("Test");
      await verification.cleanup();
    });

    it("gate finding, third re-gate, fix (a): a well-formed, GitHub-reachable row is STILL refused when x2Md.path is NOT the canonical path", async () => {
      const bareDir = await initUpstreamBare();
      const fullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
      const { x2MdPath } = await pushX2Md(bareDir, fullText);
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      // Deliberately NO `canonicalX2MdPath` override.
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-19"),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
        ledgerOfficial: true,
        githubVerification: verification,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
      expect(entry?.acceptanceLogged).toBe(false);
      expect(entry?.acceptanceDetail).toMatch(/is not this toolkit's own canonical docs\/p0\/X2\.md/);
      await verification.cleanup();
    });

    it("gate finding, fourth re-gate: a matching row that exists LOCALLY but was NEVER PUSHED to GitHub main is not counted — local content is never trusted", async () => {
      const bareDir = await initUpstreamBare();
      // The upstream has SOME content, but not the row we're about to cite.
      await pushX2Md(bareDir, "# X2\n\n## Log\n\nunrelated\n");
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

      const localFullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
      const { x2MdPath } = localOnlyX2Md(localFullText);

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-19"),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText: localFullText, path: x2MdPath },
        canonicalX2MdPath: x2MdPath,
        ledgerOfficial: true,
        githubVerification: verification,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
      expect(entry?.acceptanceLogged).toBe(false);
      expect(entry?.acceptanceDetail).toMatch(/no VISIBLE line reading exactly/);
      expect(entry?.acceptanceDetail).toMatch(/GitHub main/);
      await verification.cleanup();
    });

    it("resolves logged: false when no matching structured row exists on GitHub main at all", async () => {
      const bareDir = await initUpstreamBare();
      const fullText = "# X2\n\n## Log\n\nsome unrelated line, not an ACCEPT row\n";
      const { x2MdPath } = await pushX2Md(bareDir, fullText);
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-19"),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
        canonicalX2MdPath: x2MdPath,
        ledgerOfficial: true,
        githubVerification: verification,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
      expect(entry?.acceptanceLogged).toBe(false);
      expect(entry?.acceptanceDetail).toMatch(/no VISIBLE line reading exactly/);
      await verification.cleanup();
    });

    it("gate finding 2 (re-gate), should-fix: a row matching everything but sitting AFTER the next '## ' heading (outside the bounded Log section) does not count", async () => {
      const bareDir = await initUpstreamBare();
      const fullText =
        "# X2\n\n## Log\n\nunrelated\n\n## Later Section\n\n" +
        `ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
      const { x2MdPath } = await pushX2Md(bareDir, fullText);
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolved = await resolveCorroboration(corroboration, {
        evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-19"),
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText, path: x2MdPath },
        canonicalX2MdPath: x2MdPath,
        ledgerOfficial: true,
        githubVerification: verification,
      });
      const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
      expect(entry?.acceptanceLogged).toBe(false);
      await verification.cleanup();
    });

    it("a null local x2Md (X2.md unreadable locally) resolves logged: false, never throws", async () => {
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
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification({ ok: true, x2MdText: "" }),
      });
      expect(
        resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"))?.acceptanceLogged,
      ).toBe(false);
    });

    it("gate finding, fourth re-gate: a null/failed githubVerification resolves logged: false, never throws", async () => {
      const corroboration: X2CorroborationFile = {
        NC: {
          [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
        },
      };
      const resolvedNull = await resolveCorroboration(corroboration, {
        evidenceByTrail: {},
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText: "anything", path: "/does/not/matter" },
        ledgerOfficial: true,
        githubVerification: null,
      });
      expect(
        resolvedNull.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"))?.acceptanceLogged,
      ).toBe(false);

      const resolvedFailed = await resolveCorroboration(corroboration, {
        evidenceByTrail: {},
        readRaw: async () => Buffer.from(""),
        evidenceDir: EVIDENCE_DIR,
        ledger: { entries: [] },
        x2Md: { fullText: "anything", path: "/does/not/matter" },
        ledgerOfficial: true,
        githubVerification: fakeGitHubVerification({ ok: false, detail: "simulated failure" }),
      });
      expect(
        resolvedFailed.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"))?.acceptanceLogged,
      ).toBe(false);
      expect(
        resolvedFailed.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"))?.acceptanceDetail,
      ).toMatch(/simulated failure/);
    });

    describe("gate finding, third re-gate, fix (c) / should-fix (fourth re-gate): only a VISIBLE row counts", () => {
      /** Runs one visibility scenario end-to-end: pushes `fullText`
       * (which embeds the ACCEPT row inside whatever hiding construct the
       * test wants to check) to a real bare upstream, verifies against
       * it, and resolves the acceptance record. */
      async function resolveHiddenRowScenario(fullText: string, fact = "season"): Promise<boolean | undefined> {
        const bareDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-x2-hidden-upstream-"));
        await execFileAsync("git", ["init", "-q", "--bare", bareDir]);
        const { x2MdPath } = await pushX2Md(bareDir, fullText, "forged, as Matt");
        const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
        const corroboration: X2CorroborationFile = {
          NC: {
            [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact, acceptedBy: "Matt", date: "2026-09-20" }],
          },
        };
        const resolved = await resolveCorroboration(corroboration, {
          evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-19"),
          readRaw: async () => Buffer.from(""),
          evidenceDir: EVIDENCE_DIR,
          ledger: { entries: [] },
          x2Md: { fullText, path: x2MdPath },
          canonicalX2MdPath: x2MdPath,
          ledgerOfficial: true,
          githubVerification: verification,
        });
        const logged = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, fact))?.acceptanceLogged;
        await verification.cleanup();
        return logged;
      }

      it("exploit A: a row hidden inside a multi-line HTML comment is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n<!--\n" +
          `ACCEPT NC roster:Course A ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n` +
          "-->\n\n## Other\n";
        expect(await resolveHiddenRowScenario(fullText, "roster:Course A")).toBe(false);
      });

      it("a row hidden inside a SINGLE-line HTML comment is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n" + `<!-- ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt -->\n`;
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("exploit A2: a row hidden inside a fenced code block (```) is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n```\n" +
          `ACCEPT NC completionUnit ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n` +
          "```\n";
        expect(await resolveHiddenRowScenario(fullText, "completionUnit")).toBe(false);
      });

      it("a row hidden inside a tilde-fenced code block (~~~) is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n~~~\n" + `ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n` + "~~~\n";
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("a row hidden inside an INDENTED code block (4+ leading spaces) is NOT counted", async () => {
        const fullText = "# X2\n\n## Log\n\n" + `    ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("should-fix, fourth re-gate: a row hidden inside a <details> raw HTML block is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n<details>\n<summary>old</summary>\n" +
          `ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n` +
          "</details>\n";
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("round 7 follow-up: a row inside <details>...</details> is STILL hidden even ACROSS a blank line — unlike every other HTML block, which the generic CommonMark rule ends at the first blank line", async () => {
        // GitHub's own renderer keeps a <details> section collapsed
        // across internal blank lines/paragraph breaks — the generic
        // "ends at the first blank line" rule (still correct for every
        // OTHER block tag, see the <div> test below) would let this row
        // read as "visible" here even though it is still inside the
        // collapsed section on GitHub.
        const fullText =
          "# X2\n\n## Log\n\n<details>\n<summary>old</summary>\n\n" +
          `ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n` +
          "\n</details>\n";
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("round 7 follow-up, control: the SAME row after a blank line, with NO enclosing <details>, DOES count — proves the test above is about <details> specifically, not blank lines in general", async () => {
        const fullText =
          "# X2\n\n## Log\n\nsome unrelated preceding line\n\n" +
          `ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
        expect(await resolveHiddenRowScenario(fullText)).toBe(true);
      });

      it("should-fix, fourth re-gate: a row hidden inside any other raw HTML block (a <div>) is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n<div>\n" + `ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n` + "</div>\n";
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("should-fix, fourth re-gate: a row carrying a `hidden` attribute is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n" +
          `<span hidden>ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt</span>\n`;
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("should-fix, fourth re-gate: a row carrying a `style` attribute is NOT counted", async () => {
        const fullText =
          "# X2\n\n## Log\n\n" +
          `<span style="display:none">ACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt</span>\n`;
        expect(await resolveHiddenRowScenario(fullText)).toBe(false);
      });

      it("the SAME row, NOT hidden (plain prose), DOES count — proves the hiding tests above fail for visibility, not some other reason", async () => {
        const fullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
        expect(await resolveHiddenRowScenario(fullText)).toBe(true);
      });
    });

    describe("should-fix: acceptance date rules", () => {
      it("refuses when the acceptance date is BEFORE the evidence's own ownerSavedDate", async () => {
        const bareDir = await initUpstreamBare();
        const fullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-01-01 Matt\n`;
        const { x2MdPath } = await pushX2Md(bareDir, fullText);
        const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
        const corroboration: X2CorroborationFile = {
          NC: {
            [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-01-01" }],
          },
        };
        const resolved = await resolveCorroboration(corroboration, {
          evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-20"),
          readRaw: async () => Buffer.from(""),
          evidenceDir: EVIDENCE_DIR,
          ledger: { entries: [] },
          x2Md: { fullText, path: x2MdPath },
          canonicalX2MdPath: x2MdPath,
          ledgerOfficial: true,
          githubVerification: verification,
        });
        const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
        expect(entry?.acceptanceLogged).toBe(false);
        expect(entry?.acceptanceDetail).toMatch(/is BEFORE the evidence's own ownerSavedDate/);
        await verification.cleanup();
      });

      it("refuses when the acceptance date is more than 1 day after the commit date that introduced the row", async () => {
        const bareDir = await initUpstreamBare();
        const fullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2099-01-01 Matt\n`;
        const { x2MdPath } = await pushX2Md(bareDir, fullText);
        const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
        const corroboration: X2CorroborationFile = {
          NC: {
            [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2099-01-01" }],
          },
        };
        const resolved = await resolveCorroboration(corroboration, {
          evidenceByTrail: evidenceWithOwnerSavedDate("2026-01-01"),
          readRaw: async () => Buffer.from(""),
          evidenceDir: EVIDENCE_DIR,
          ledger: { entries: [] },
          x2Md: { fullText, path: x2MdPath },
          canonicalX2MdPath: x2MdPath,
          ledgerOfficial: true,
          githubVerification: verification,
        });
        const entry = resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"));
        expect(entry?.acceptanceLogged).toBe(false);
        expect(entry?.acceptanceDetail).toMatch(/is more than 1 day after the commit date/);
        await verification.cleanup();
      });

      it("accepts when the date equals the evidence's ownerSavedDate exactly, and the commit is dated today (the normal case)", async () => {
        const bareDir = await initUpstreamBare();
        const fullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
        const { x2MdPath } = await pushX2Md(bareDir, fullText);
        const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
        const corroboration: X2CorroborationFile = {
          NC: {
            [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
          },
        };
        const resolved = await resolveCorroboration(corroboration, {
          evidenceByTrail: evidenceWithOwnerSavedDate("2026-09-20"),
          readRaw: async () => Buffer.from(""),
          evidenceDir: EVIDENCE_DIR,
          ledger: { entries: [] },
          x2Md: { fullText, path: x2MdPath },
          canonicalX2MdPath: x2MdPath,
          ledgerOfficial: true,
          githubVerification: verification,
        });
        expect(
          resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"))?.acceptanceLogged,
        ).toBe(true);
        await verification.cleanup();
      });

      it("does not refuse on the date rule when the evidence has no ownerSavedDate recorded at all (legacy/unknown — the rule simply doesn't apply)", async () => {
        const bareDir = await initUpstreamBare();
        const fullText = `# X2\n\n## Log\n\nACCEPT NC season ${SHA_OWNER_FOR_RESOLVE} 2026-09-20 Matt\n`;
        const { x2MdPath } = await pushX2Md(bareDir, fullText);
        const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
        const corroboration: X2CorroborationFile = {
          NC: {
            [SHA_OWNER_FOR_RESOLVE]: [{ type: "acceptance", fact: "season", acceptedBy: "Matt", date: "2026-09-20" }],
          },
        };
        const resolved = await resolveCorroboration(corroboration, {
          evidenceByTrail: evidenceWithOwnerSavedDate(null),
          readRaw: async () => Buffer.from(""),
          evidenceDir: EVIDENCE_DIR,
          ledger: { entries: [] },
          x2Md: { fullText, path: x2MdPath },
          canonicalX2MdPath: x2MdPath,
          ledgerOfficial: true,
          githubVerification: verification,
        });
        expect(
          resolved.get(corroborationResolutionKey("NC", SHA_OWNER_FOR_RESOLVE, "season"))?.acceptanceLogged,
        ).toBe(true);
        await verification.cleanup();
      });
    });
  });
});

describe("x2-verdict: verifyAgainstGitHub (gate finding, fourth re-gate — disposable repo + scrubbed environment)", () => {
  async function initUpstreamBare(): Promise<string> {
    const bareDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-upstream-"));
    await execFileAsync("git", ["init", "-q", "--bare", bareDir]);
    return bareDir;
  }

  async function pushDocs(
    bareDir: string,
    files: { x2Md?: string; ledger?: string },
    message = "update",
  ): Promise<{ workDir: string; sha: string }> {
    const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-work-"));
    await execFileAsync("git", ["init", "-q"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.name", "Test"], { cwd: workDir });
    mkdirSync(nodePath.join(workDir, "docs", "p0"), { recursive: true });
    if (files.x2Md !== undefined) {
      writeFileSync(nodePath.join(workDir, "docs", "p0", "X2.md"), files.x2Md, "utf8");
    }
    if (files.ledger !== undefined) {
      writeFileSync(nodePath.join(workDir, "docs", "p0", "x2-recorded-ledger.json"), files.ledger, "utf8");
    }
    if (files.x2Md === undefined && files.ledger === undefined) {
      writeFileSync(nodePath.join(workDir, "README.md"), "placeholder\n", "utf8");
    }
    await execFileAsync("git", ["add", "-A"], { cwd: workDir });
    await execFileAsync("git", ["commit", "-q", "-m", message], { cwd: workDir });
    await execFileAsync("git", ["branch", "-M", "main"], { cwd: workDir });
    await execFileAsync("git", ["push", "-q", bareDir, "HEAD:main"], { cwd: workDir });
    const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: workDir });
    return { workDir, sha: stdout.trim() };
  }

  const savedEnv: Record<string, string | undefined> = {};
  function stashEnv(...keys: string[]): void {
    for (const k of keys) savedEnv[k] = process.env[k];
  }
  function restoreEnv(): void {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }

  it("succeeds against a real (local, bare-repo-standing-in-for-GitHub) main, reading the ledger and X2.md blobs directly from refs/heads/main", async () => {
    const bareDir = await initUpstreamBare();
    await pushDocs(bareDir, { x2Md: "# X2\n\nhello\n", ledger: '{"entries": []}\n' });
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
    expect(verification.ok).toBe(true);
    expect(verification.x2MdText).toBe("# X2\n\nhello\n");
    expect(verification.x2MdBlobHash).toMatch(/^[0-9a-f]{40}$/);
    expect(verification.ledgerBlobHash).toMatch(/^[0-9a-f]{40}$/);
    await verification.cleanup();
  });

  it("a bad/unreachable repoUrl gives ok: false, never throws", async () => {
    const verification = await verifyAgainstGitHub({ repoUrl: "/this/path/does/not/exist/at/all", runtimeExecArgv: [] });
    expect(verification.ok).toBe(false);
    expect(verification.ledgerBlobHash).toBeNull();
    await verification.cleanup();
  });

  it("a source repo missing docs/p0/X2.md or the ledger resolves ok: true with those blob hashes null, never a hard failure", async () => {
    const bareDir = await initUpstreamBare();
    await pushDocs(bareDir, {}); // placeholder commit, no docs/p0 files
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
    expect(verification.ok).toBe(true);
    expect(verification.ledgerBlobHash).toBeNull();
    expect(verification.x2MdBlobHash).toBeNull();
    expect(verification.x2MdText).toBeNull();
    await verification.cleanup();
  });

  it("refuses a SHALLOW source (rev-parse --is-shallow-repository) rather than trust a boundary commit", async () => {
    const bareDir = await initUpstreamBare();
    const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-shallow-src-"));
    await execFileAsync("git", ["init", "-q"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.name", "Test"], { cwd: workDir });
    writeFileSync(nodePath.join(workDir, "a.txt"), "1\n", "utf8");
    await execFileAsync("git", ["add", "-A"], { cwd: workDir });
    await execFileAsync("git", ["commit", "-q", "-m", "c1"], { cwd: workDir });
    writeFileSync(nodePath.join(workDir, "a.txt"), "2\n", "utf8");
    await execFileAsync("git", ["add", "-A"], { cwd: workDir });
    await execFileAsync("git", ["commit", "-q", "-m", "c2"], { cwd: workDir });
    await execFileAsync("git", ["branch", "-M", "main"], { cwd: workDir });
    await execFileAsync("git", ["push", "-q", bareDir, "HEAD:main"], { cwd: workDir });

    // A SHALLOW clone of bareDir, used as the "repoUrl" — git can re-serve
    // from a shallow repo, producing a shallow result on our end too.
    const shallowDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-shallow-clone-"));
    await execFileAsync("git", ["clone", "-q", "--depth", "1", bareDir, shallowDir]);

    const verification = await verifyAgainstGitHub({ repoUrl: shallowDir, runtimeExecArgv: [] });
    expect(verification.ok).toBe(false);
    expect(verification.detail).toMatch(/shallow/);
    await verification.cleanup();
  });

  describe("exploit I: insteadOf URL redirection", () => {
    afterEach(() => {
      restoreEnv();
    });

    it("GIT_CONFIG_COUNT/KEY/VALUE env-var redirection in the CALLING process has NO EFFECT — scrubbedGitEnv drops every GIT_CONFIG_* variable", async () => {
      const realBareDir = await initUpstreamBare();
      await pushDocs(realBareDir, { x2Md: "# X2\n\nREAL CONTENT\n" });
      const fakeBareDir = await initUpstreamBare();
      await pushDocs(fakeBareDir, { x2Md: "# X2\n\nFAKE CONTENT (attacker's own repo)\n" });

      stashEnv("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0");
      process.env.GIT_CONFIG_COUNT = "1";
      process.env.GIT_CONFIG_KEY_0 = `url.${fakeBareDir}.insteadOf`;
      process.env.GIT_CONFIG_VALUE_0 = realBareDir;

      // Confirms the cause: an UNPROTECTED git invocation that inherits
      // this env DOES get redirected.
      const { stdout: unprotectedUrl } = await execFileAsync("git", ["ls-remote", "--get-url", realBareDir]);
      expect(unprotectedUrl.trim()).toBe(fakeBareDir);

      // The fix: verifyAgainstGitHub is unaffected — it reads the REAL repo.
      const verification = await verifyAgainstGitHub({ repoUrl: realBareDir, runtimeExecArgv: [] });
      expect(verification.ok).toBe(true);
      expect(verification.x2MdText).toContain("REAL CONTENT");
      expect(verification.x2MdText).not.toContain("FAKE CONTENT");
      await verification.cleanup();
    });

    it("a malicious GLOBAL config (via a forged HOME) has NO EFFECT — HOME and GIT_CONFIG_GLOBAL are both pinned inside verifyAgainstGitHub", async () => {
      const realBareDir = await initUpstreamBare();
      await pushDocs(realBareDir, { x2Md: "# X2\n\nREAL CONTENT 2\n" });
      const fakeBareDir = await initUpstreamBare();
      await pushDocs(fakeBareDir, { x2Md: "# X2\n\nFAKE CONTENT 2\n" });

      const maliciousHome = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-malicious-home-"));
      writeFileSync(
        nodePath.join(maliciousHome, ".gitconfig"),
        `[url "${fakeBareDir}"]\n\tinsteadOf = ${realBareDir}\n`,
        "utf8",
      );
      stashEnv("HOME");
      process.env.HOME = maliciousHome;

      const verification = await verifyAgainstGitHub({ repoUrl: realBareDir, runtimeExecArgv: [] });
      expect(verification.ok).toBe(true);
      expect(verification.x2MdText).toContain("REAL CONTENT 2");
      expect(verification.x2MdText).not.toContain("FAKE CONTENT 2");
      await verification.cleanup();
    });
  });

  describe("exploit R: git replace", () => {
    it("confirms the cause: an UNPROTECTED git command substitutes a `git replace`d object; GIT_NO_REPLACE_OBJECTS=1 defeats it", async () => {
      const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-replace-src-"));
      await execFileAsync("git", ["init", "-q"], { cwd: workDir });
      await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: workDir });
      await execFileAsync("git", ["config", "user.name", "Test"], { cwd: workDir });
      writeFileSync(nodePath.join(workDir, "f.txt"), "real\n", "utf8");
      await execFileAsync("git", ["add", "-A"], { cwd: workDir });
      await execFileAsync("git", ["commit", "-q", "-m", "real commit"], { cwd: workDir });
      const { stdout: realSha } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: workDir });

      writeFileSync(nodePath.join(workDir, "f.txt"), "forged\n", "utf8");
      await execFileAsync("git", ["add", "-A"], { cwd: workDir });
      await execFileAsync("git", ["commit", "-q", "-m", "forged commit"], { cwd: workDir });
      const { stdout: forgedSha } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: workDir });

      await execFileAsync("git", ["replace", realSha.trim(), forgedSha.trim()], { cwd: workDir });

      // Confirms the cause: unprotected, the replaced object is what a
      // reader sees.
      const { stdout: unprotectedShow } = await execFileAsync(
        "git",
        ["show", "-s", "--format=%s", realSha.trim()],
        { cwd: workDir },
      );
      expect(unprotectedShow.trim()).toBe("forged commit");

      // The fix's own ingredient: GIT_NO_REPLACE_OBJECTS=1 defeats it.
      const { stdout: protectedShow } = await execFileAsync(
        "git",
        ["show", "-s", "--format=%s", realSha.trim()],
        { cwd: workDir, env: { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" } },
      );
      expect(protectedShow.trim()).toBe("real commit");
    });

    it("verifyAgainstGitHub's own disposable repo never acquires refs/replace/* from a fetch of a single ref — it is fresh every run", async () => {
      const bareDir = await initUpstreamBare();
      await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
      // A `git replace` in the SOURCE repo is local-only and is never
      // part of what `+refs/heads/main:refs/heads/main` transfers — the
      // disposable repo verifyAgainstGitHub builds is fresh every run, so
      // this simply succeeds normally.
      expect(verification.ok).toBe(true);
      await verification.cleanup();
    });
  });

  describe("exploit G: .git/info/grafts", () => {
    it("confirms the cause: an UNPROTECTED reader honours a graft that rewrites parentage, making a forged commit an ancestor", async () => {
      const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-grafts-src-"));
      await execFileAsync("git", ["init", "-q"], { cwd: workDir });
      await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: workDir });
      await execFileAsync("git", ["config", "user.name", "Test"], { cwd: workDir });
      writeFileSync(nodePath.join(workDir, "f.txt"), "1\n", "utf8");
      await execFileAsync("git", ["add", "-A"], { cwd: workDir });
      await execFileAsync("git", ["commit", "-q", "-m", "genuine root"], { cwd: workDir });
      const { stdout: c1 } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: workDir });

      // A forged, UNRELATED commit — no real ancestry relationship to c1.
      const forgedDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-grafts-forged-"));
      await execFileAsync("git", ["init", "-q"], { cwd: forgedDir });
      await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: forgedDir });
      await execFileAsync("git", ["config", "user.name", "Test"], { cwd: forgedDir });
      writeFileSync(nodePath.join(forgedDir, "g.txt"), "forged\n", "utf8");
      await execFileAsync("git", ["add", "-A"], { cwd: forgedDir });
      await execFileAsync("git", ["commit", "-q", "-m", "forged, as Matt"], { cwd: forgedDir });
      const { stdout: forgedSha } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: forgedDir });
      await execFileAsync("git", ["fetch", "-q", forgedDir, "HEAD:refs/forged"], { cwd: workDir });

      // Before the graft: NOT an ancestor.
      await expect(
        execFileAsync("git", ["merge-base", "--is-ancestor", forgedSha.trim(), c1.trim()], { cwd: workDir }),
      ).rejects.toThrow();

      mkdirSync(nodePath.join(workDir, ".git", "info"), { recursive: true });
      writeFileSync(
        nodePath.join(workDir, ".git", "info", "grafts"),
        `${c1.trim()} ${forgedSha.trim()}\n`,
        "utf8",
      );

      // Confirms the cause: WITH the graft, git now reports it reachable.
      await expect(
        execFileAsync("git", ["merge-base", "--is-ancestor", forgedSha.trim(), c1.trim()], { cwd: workDir }),
      ).resolves.toBeDefined();
    });

    it("verifyAgainstGitHub's disposable repo never has info/grafts (it is created fresh via `git init --bare` every run) — a graft in the SOURCE repo never transfers", async () => {
      const bareDir = await initUpstreamBare();
      await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
      expect(verification.ok).toBe(true);
      await verification.cleanup();
    });
  });

  describe("GIT_DIR / GIT_WORK_TREE in the caller's own environment", () => {
    afterEach(() => {
      restoreEnv();
    });

    it("a caller-set GIT_DIR pointing at an unrelated repo has NO EFFECT — scrubbedGitEnv always overrides GIT_DIR to the disposable repo itself", async () => {
      const unrelatedRepo = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-unrelated-"));
      await execFileAsync("git", ["init", "-q"], { cwd: unrelatedRepo });

      const bareDir = await initUpstreamBare();
      await pushDocs(bareDir, { x2Md: "# X2\n\nGIT_DIR test\n" });

      stashEnv("GIT_DIR", "GIT_WORK_TREE");
      process.env.GIT_DIR = nodePath.join(unrelatedRepo, ".git");
      process.env.GIT_WORK_TREE = unrelatedRepo;

      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
      expect(verification.ok).toBe(true);
      expect(verification.x2MdText).toContain("GIT_DIR test");
      await verification.cleanup();
    });
  });

  describe(".git/hooks", () => {
    it("a hook that WOULD run on an unprotected ref update does not fire under core.hooksPath=/dev/null (the flag verifyAgainstGitHub always passes)", async () => {
      const repo = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gh-hooks-"));
      await execFileAsync("git", ["init", "-q"], { cwd: repo });
      writeFileSync(nodePath.join(repo, "f.txt"), "1\n", "utf8");
      await execFileAsync("git", ["add", "-A"], { cwd: repo });
      await execFileAsync(
        "git",
        ["-c", "user.email=t@e.com", "-c", "user.name=T", "commit", "-q", "-m", "c"],
        { cwd: repo },
      );

      const marker = nodePath.join(repo, "hook-ran.marker");
      mkdirSync(nodePath.join(repo, ".git", "hooks"), { recursive: true });
      writeFileSync(
        nodePath.join(repo, ".git", "hooks", "reference-transaction"),
        `#!/bin/sh\ntouch "${marker}"\nexit 0\n`,
        { mode: 0o755 },
      );

      // Confirms the cause: an unprotected ref update runs the hook.
      await execFileAsync("git", ["update-ref", "refs/heads/y", "HEAD"], { cwd: repo });
      expect(existsSync(marker)).toBe(true);

      // The fix: the SAME kind of ref update, but with
      // core.hooksPath=/dev/null (exactly what verifyAgainstGitHub always
      // passes), never runs it.
      const marker2 = nodePath.join(repo, "hook-ran-2.marker");
      writeFileSync(
        nodePath.join(repo, ".git", "hooks", "reference-transaction"),
        `#!/bin/sh\ntouch "${marker2}"\nexit 0\n`,
        { mode: 0o755 },
      );
      await execFileAsync(
        "git",
        ["-c", "core.hooksPath=/dev/null", "update-ref", "refs/heads/z", "HEAD"],
        { cwd: repo },
      );
      expect(existsSync(marker2)).toBe(false);
    });
  });

  it("GIT_SSL_NO_VERIFY set in the ORIGINAL environment refuses outright, before any fetch", async () => {
    const bareDir = await initUpstreamBare();
    await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
    stashEnv("GIT_SSL_NO_VERIFY");
    process.env.GIT_SSL_NO_VERIFY = "1";
    try {
      const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
      expect(verification.ok).toBe(false);
      expect(verification.detail).toMatch(/GIT_SSL_NO_VERIFY/);
      await verification.cleanup();
    } finally {
      restoreEnv();
    }
  });

  describe("round 7 hardening: absolute git path, fixed child PATH, runtime-tamper detection", () => {
    describe("resolveGitBinary", () => {
      it("with no override, resolves to a real, root-owned, non-writable absolute path in this environment", () => {
        const res = resolveGitBinary();
        expect(res.ok).toBe(true);
        expect(res.path).toMatch(/^\/(usr\/)?bin\/git$/);
      });

      it("the override seam still runs the real ownership/writability checks — a trustworthy override validates fine", () => {
        const res = resolveGitBinary("/usr/bin/git");
        expect(res.ok).toBe(true);
        expect(res.path).toBe("/usr/bin/git");
      });

      it("refuses a non-root-owned git path, via the seam", () => {
        const dir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gitbin-uid-"));
        const fakeGit = nodePath.join(dir, "git");
        writeFileSync(fakeGit, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
        // This test environment runs as root, so a file this test creates
        // is root-owned by default — chown it to a non-zero uid directly
        // (root can chown to any uid) to construct the exact shape being
        // refused, rather than merely asserting the seam exists.
        chownSync(fakeGit, 1000, 1000);
        const res = resolveGitBinary(fakeGit);
        expect(res.ok).toBe(false);
        expect(res.detail).toMatch(/not owned by root/);
      });

      it("refuses a group/world-writable git path, via the seam", () => {
        const dir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gitbin-mode-"));
        const fakeGit = nodePath.join(dir, "git");
        writeFileSync(fakeGit, "#!/bin/sh\nexit 0\n", { mode: 0o777 });
        // writeFileSync's mode is subject to the process umask (0022
        // here), which would silently strip the write bits being tested
        // — chmodSync bypasses umask and sets the exact mode.
        chmodSync(fakeGit, 0o777); // world-writable
        const res = resolveGitBinary(fakeGit);
        expect(res.ok).toBe(false);
        expect(res.detail).toMatch(/group- or world-writable/);
      });

      it("refuses when the override path does not exist at all", () => {
        const res = resolveGitBinary("/this/path/does/not/exist/git");
        expect(res.ok).toBe(false);
        expect(res.path).toBeNull();
      });
    });

    describe("tokenizeNodeOptions / isNodeOptionTokenAllowed (round 8: allow-list, not a denylist)", () => {
      it("splits on whitespace", () => {
        expect(tokenizeNodeOptions("--max-old-space-size=8192 --no-warnings")).toEqual([
          "--max-old-space-size=8192",
          "--no-warnings",
        ]);
      });

      it("keeps a double-quoted value with an embedded space as one token, stripping the quotes", () => {
        expect(tokenizeNodeOptions('--title="my app name"')).toEqual(['--title=my app name']);
      });

      it("keeps a single-quoted value with an embedded space as one token, stripping the quotes", () => {
        expect(tokenizeNodeOptions("--title='my app name'")).toEqual(["--title=my app name"]);
      });

      it("a bare value following a space-separated flag is its own token", () => {
        expect(tokenizeNodeOptions("--stack-size 984")).toEqual(["--stack-size", "984"]);
      });

      it("isNodeOptionTokenAllowed: a bare (non-flag) value is always allowed — it's not itself a vector", () => {
        expect(isNodeOptionTokenAllowed("984")).toBe(true);
        expect(isNodeOptionTokenAllowed("./evil.cjs")).toBe(true);
      });

      it("isNodeOptionTokenAllowed: every named benign flag is allowed", () => {
        for (const flag of [
          "--max-old-space-size=8192",
          "--max-semi-space-size=64",
          "--stack-size",
          "--stack-size=984",
          "--no-warnings",
          "--enable-source-maps",
          "--trace-warnings",
          "--unhandled-rejections=warn",
        ]) {
          expect(isNodeOptionTokenAllowed(flag)).toBe(true);
        }
      });

      it("isNodeOptionTokenAllowed: every named dangerous/unvetted flag is refused", () => {
        for (const flag of [
          "-r",
          "--require",
          "--require=./evil.cjs",
          "--loader",
          "--experimental-loader",
          "--import",
          "--inspect",
          "--inspect-brk=0",
          "--env-file=/tmp/x",
          "--conditions=x",
          "--openssl-config=/tmp/x",
          "--use-openssl-ca",
          "--preserve-symlinks",
          "--preserve-symlinks-main",
          "--experimental-anything",
          "--totally-unknown-flag",
        ]) {
          expect(isNodeOptionTokenAllowed(flag)).toBe(false);
        }
      });
    });

    describe("detectRuntimeTamper", () => {
      it("a clean environment (no tamper vars, empty execArgv) is not flagged", () => {
        const res = detectRuntimeTamper({}, []);
        expect(res.tampered).toBe(false);
      });

      it("a BENIGN NODE_OPTIONS (e.g. a memory-limit flag, this environment's own ordinary shell value) is NOT flagged", () => {
        const res = detectRuntimeTamper({ NODE_OPTIONS: "--max-old-space-size=8192" }, []);
        expect(res.tampered).toBe(false);
      });

      it("NODE_OPTIONS carrying --require is flagged", () => {
        const res = detectRuntimeTamper({ NODE_OPTIONS: "--require ./evil.cjs" }, []);
        expect(res.tampered).toBe(true);
        expect(res.detail).toMatch(/NODE_OPTIONS/);
      });

      it("NODE_OPTIONS carrying -r is flagged", () => {
        const res = detectRuntimeTamper({ NODE_OPTIONS: "-r ./evil.cjs" }, []);
        expect(res.tampered).toBe(true);
      });

      it("NODE_OPTIONS carrying --loader/--experimental-loader/--import is flagged", () => {
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--loader ./evil.mjs" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--experimental-loader ./evil.mjs" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--import ./evil.mjs" }, []).tampered).toBe(true);
      });

      it("LD_PRELOAD is flagged", () => {
        const res = detectRuntimeTamper({ LD_PRELOAD: "/tmp/evil.so" }, []);
        expect(res.tampered).toBe(true);
        expect(res.detail).toMatch(/LD_PRELOAD/);
      });

      it("LD_LIBRARY_PATH is flagged", () => {
        expect(detectRuntimeTamper({ LD_LIBRARY_PATH: "/tmp/evil" }, []).tampered).toBe(true);
      });

      it("GIT_EXEC_PATH is flagged", () => {
        expect(detectRuntimeTamper({ GIT_EXEC_PATH: "/tmp/evil" }, []).tampered).toBe(true);
      });

      it("any DYLD_* variable is flagged", () => {
        expect(detectRuntimeTamper({ DYLD_INSERT_LIBRARIES: "/tmp/evil.dylib" }, []).tampered).toBe(true);
      });

      it("round 8 follow-up: any LD_* variable is flagged, not just LD_PRELOAD/LD_LIBRARY_PATH — LD_AUDIT loaded native code in the gate's own round-8 probe", () => {
        const res = detectRuntimeTamper({ LD_AUDIT: "/tmp/evil-audit.so" }, []);
        expect(res.tampered).toBe(true);
        expect(res.detail).toMatch(/LD_AUDIT/);
      });

      it("round 8: NODE_OPTIONS carrying --inspect is flagged (not on the allow-list)", () => {
        const res = detectRuntimeTamper({ NODE_OPTIONS: "--inspect" }, []);
        expect(res.tampered).toBe(true);
        expect(res.detail).toMatch(/--inspect/);
      });

      it("round 8: NODE_OPTIONS carrying --inspect-brk=0 is flagged", () => {
        const res = detectRuntimeTamper({ NODE_OPTIONS: "--inspect-brk=0" }, []);
        expect(res.tampered).toBe(true);
      });

      it("round 8: NODE_OPTIONS carrying any UNKNOWN flag not on the allow-list is flagged — default-deny, not a denylist of known attacks", () => {
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--env-file=/tmp/evil.env" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--conditions=evil" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--openssl-config=/tmp/evil.cnf" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--use-openssl-ca" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--preserve-symlinks" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--experimental-fetch" }, []).tampered).toBe(true);
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--totally-made-up-flag" }, []).tampered).toBe(true);
      });

      it("round 8: every flag on the benign allow-list passes, individually and combined", () => {
        const benign = [
          "--max-old-space-size=8192",
          "--max-semi-space-size=64",
          "--max-http-header-size=16384", // any other --max-* flag
          "--stack-size=984",
          "--no-warnings",
          "--enable-source-maps",
          "--trace-warnings",
          "--unhandled-rejections=warn",
          "--unhandled-rejections=strict", // any value for this flag
        ];
        for (const flag of benign) {
          expect(detectRuntimeTamper({ NODE_OPTIONS: flag }, []).tampered).toBe(false);
        }
        expect(detectRuntimeTamper({ NODE_OPTIONS: benign.join(" ") }, []).tampered).toBe(false);
      });

      it("round 8: this environment's own ambient NODE_OPTIONS (--max-old-space-size=8192) still passes — the exact live-shell value, not just a synthetic one", () => {
        expect(detectRuntimeTamper({ NODE_OPTIONS: "--max-old-space-size=8192" }, []).tampered).toBe(false);
      });

      it("round 9: NODE_OPTIONS containing any quote or backslash is refused, even when every quoted flag is benign", () => {
        for (const opts of [
          '"--max-old-space-size=100 --title=probe"',
          "'--max-old-space-size=100 --require x'",
          "--max-old-space-size=100\\ --require\\ x",
        ]) {
          const res = detectRuntimeTamper({ NODE_OPTIONS: opts }, []);
          expect(res.tampered, opts).toBe(true);
          expect(res.detail).toMatch(/quote or backslash/);
        }
      });

      it("a non-empty execArgv is flagged", () => {
        const res = detectRuntimeTamper({}, ["--require", "/tmp/evil.cjs"]);
        expect(res.tampered).toBe(true);
        expect(res.detail).toMatch(/execArgv/);
      });
    });

    describe("verifyAgainstGitHub wired to the round 7 checks", () => {
      it("a fake git shimmed EARLIER on the caller's own PATH has NO EFFECT — the absolute-path resolution never consults PATH", async () => {
        const realBareDir = await initUpstreamBare();
        await pushDocs(realBareDir, { x2Md: "# X2\n\nREAL-PATH-SHIM-TEST\n" });
        const fakeBareDir = await initUpstreamBare();
        await pushDocs(fakeBareDir, { x2Md: "# X2\n\nFAKE-PATH-SHIM-TEST\n" });

        // A fake `git` that rewrites the real URL to the fake repo and
        // lies about ls-remote --get-url — the same shape as this
        // round's own gate fixture (fakebin/git).
        const fakeBinDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-fakebin-"));
        const fakeGitPath = nodePath.join(fakeBinDir, "git");
        writeFileSync(
          fakeGitPath,
          "#!/bin/bash\n" +
            `args=(); for a in "$@"; do a="\${a//${realBareDir.replace(/\//g, "\\/")}/${fakeBareDir.replace(/\//g, "\\/")}}"; args+=("$a"); done\n` +
            `if [[ "$*" == *"ls-remote --get-url"* ]]; then echo ${realBareDir}; exit 0; fi\n` +
            `exec /usr/bin/git "\${args[@]}"\n`,
          { mode: 0o755 },
        );

        stashEnv("PATH");
        process.env.PATH = `${fakeBinDir}:${process.env.PATH}`;
        try {
          // Confirms the shim IS first on PATH (the setup is real).
          const { stdout: whichGit } = await execFileAsync("bash", ["-lc", "command -v git"]);
          expect(whichGit.trim()).toBe(fakeGitPath);

          const verification = await verifyAgainstGitHub({ repoUrl: realBareDir, runtimeExecArgv: [] });
          expect(verification.ok).toBe(true);
          expect(verification.x2MdText).toContain("REAL-PATH-SHIM-TEST");
          expect(verification.x2MdText).not.toContain("FAKE-PATH-SHIM-TEST");
          await verification.cleanup();
        } finally {
          restoreEnv();
        }
      });

      it("NODE_OPTIONS with a --require flag in the calling process's env gives UNOFFICIAL (ok: false)", async () => {
        const bareDir = await initUpstreamBare();
        await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
        const verification = await verifyAgainstGitHub({
          repoUrl: bareDir,
          runtimeEnv: { ...process.env, NODE_OPTIONS: "--require /tmp/evil.cjs" },
          runtimeExecArgv: [],
        });
        expect(verification.ok).toBe(false);
        expect(verification.detail).toMatch(/NODE_OPTIONS/);
        await verification.cleanup();
      });

      it("LD_PRELOAD in the calling process's env gives UNOFFICIAL (ok: false)", async () => {
        const bareDir = await initUpstreamBare();
        await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
        const verification = await verifyAgainstGitHub({
          repoUrl: bareDir,
          runtimeEnv: { ...process.env, LD_PRELOAD: "/tmp/evil.so" },
          runtimeExecArgv: [],
        });
        expect(verification.ok).toBe(false);
        expect(verification.detail).toMatch(/LD_PRELOAD/);
        await verification.cleanup();
      });

      it("a non-empty execArgv gives UNOFFICIAL (ok: false) — e.g. node --require=evil.cjs or -e", async () => {
        const bareDir = await initUpstreamBare();
        await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
        const verification = await verifyAgainstGitHub({
          repoUrl: bareDir,
          runtimeExecArgv: ["--require", "/tmp/evil.cjs"],
        });
        expect(verification.ok).toBe(false);
        expect(verification.detail).toMatch(/execArgv/);
        await verification.cleanup();
      });

      it("a BENIGN NODE_OPTIONS (this environment's own ordinary-shell value) does NOT trip the check — the live CLI must not falsely refuse on a clean shell", async () => {
        const bareDir = await initUpstreamBare();
        await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
        const verification = await verifyAgainstGitHub({
          repoUrl: bareDir,
          runtimeEnv: { ...process.env, NODE_OPTIONS: "--max-old-space-size=8192" },
          runtimeExecArgv: [],
        });
        expect(verification.ok).toBe(true);
        await verification.cleanup();
      });

      it("a non-root-owned git binary (via the gitBinary seam) gives UNOFFICIAL (ok: false)", async () => {
        const bareDir = await initUpstreamBare();
        await pushDocs(bareDir, { x2Md: "# X2\n\nok\n" });
        const dir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-gitbin-live-"));
        const fakeGit = nodePath.join(dir, "git");
        writeFileSync(fakeGit, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
        chownSync(fakeGit, 1000, 1000);
        const verification = await verifyAgainstGitHub({
          repoUrl: bareDir,
          gitBinary: fakeGit,
          runtimeExecArgv: [],
        });
        expect(verification.ok).toBe(false);
        expect(verification.detail).toMatch(/not owned by root/);
        await verification.cleanup();
      });

      it("the child git process's own PATH is fixed to /usr/bin:/bin — a caller-PATH-only tool is not reachable from it", async () => {
        const bareDir = await initUpstreamBare();
        await pushDocs(bareDir, { x2Md: "# X2\n\nPATH-FIX-TEST\n" });
        // A directory-only-on-the-caller's-PATH marker tool; if the
        // child inherited the caller's PATH, a hook or helper could find
        // it. We assert indirectly: the real fetch still succeeds
        // (proving /usr/bin:/bin has everything git itself needs) while
        // a PATH-dependent probe placed ONLY in a caller-only PATH entry
        // is not on the child's resolved PATH.
        const onlyCallerDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-only-caller-path-"));
        writeFileSync(nodePath.join(onlyCallerDir, "not-on-child-path"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
        stashEnv("PATH");
        process.env.PATH = `${onlyCallerDir}:${process.env.PATH}`;
        try {
          const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
          expect(verification.ok).toBe(true);
          expect(verification.x2MdText).toContain("PATH-FIX-TEST");
          await verification.cleanup();
        } finally {
          restoreEnv();
        }
      });
    });
  });
});

describe("x2-verdict: checkLedgerAgainstGit (gate finding 2d / gate finding 4 / gate finding third+fourth re-gate)", () => {
  async function initUpstreamBare(): Promise<string> {
    const bareDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-ledger-upstream-"));
    await execFileAsync("git", ["init", "-q", "--bare", bareDir]);
    return bareDir;
  }

  async function pushLedger(bareDir: string, ledgerJson: string, message = "add ledger"): Promise<void> {
    const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-ledger-work-"));
    await execFileAsync("git", ["init", "-q"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.name", "Test"], { cwd: workDir });
    mkdirSync(nodePath.join(workDir, "docs", "p0"), { recursive: true });
    writeFileSync(nodePath.join(workDir, "docs", "p0", "x2-recorded-ledger.json"), ledgerJson, "utf8");
    await execFileAsync("git", ["add", "-A"], { cwd: workDir });
    await execFileAsync("git", ["commit", "-q", "-m", message], { cwd: workDir });
    await execFileAsync("git", ["branch", "-M", "main"], { cwd: workDir });
    await execFileAsync("git", ["push", "-q", bareDir, "HEAD:main"], { cwd: workDir });
  }

  async function initGitRepo(): Promise<{ dir: string; ledgerPath: string }> {
    const dir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-ledger-git-test-"));
    await execFileAsync("git", ["init", "-q"], { cwd: dir });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: dir });
    await execFileAsync("git", ["config", "user.name", "Test"], { cwd: dir });
    mkdirSync(nodePath.join(dir, "docs", "p0"), { recursive: true });
    const ledgerPath = nodePath.join(dir, "docs", "p0", "x2-recorded-ledger.json");
    return { dir, ledgerPath };
  }

  it("gate finding 4, probe A: a canonical-path, committed ledger VERIFIED against GitHub main (the bare upstream) is reported clean, with its git blob hash and last commit", async () => {
    const { dir, ledgerPath } = await initGitRepo();
    const ledgerJson = '{"entries": []}\n';
    writeFileSync(ledgerPath, ledgerJson, "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger"], { cwd: dir });

    const bareDir = await initUpstreamBare();
    await pushLedger(bareDir, ledgerJson);
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

    const result = await checkLedgerAgainstGit(ledgerPath, verification, { canonicalPath: ledgerPath });
    expect(result.pathIsCanonical).toBe(true);
    expect(result.verifiedAgainstGithub).toBe(true);
    expect(result.verifiedMainUnavailable).toBe(false);
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
    await verification.cleanup();
  });

  it("gate finding, third re-gate, fix (a): a WRONG-location ledger (right repo, right filename, wrong directory) is refused as not canonical, never treated as if it were, even when otherwise clean and verified", async () => {
    const { dir, ledgerPath: intendedCanonicalPath } = await initGitRepo();
    const wrongPath = nodePath.join(dir, "x2-recorded-ledger.json");
    const ledgerJson = '{"entries": []}\n';
    writeFileSync(wrongPath, ledgerJson, "utf8");
    await execFileAsync("git", ["add", "x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "wrong location"], { cwd: dir });

    const bareDir = await initUpstreamBare();
    await pushLedger(bareDir, ledgerJson);
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

    const result = await checkLedgerAgainstGit(wrongPath, verification, { canonicalPath: intendedCanonicalPath });
    expect(result.pathIsCanonical).toBe(false);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/is not the canonical ledger path/);
    await verification.cleanup();
  });

  it("gate finding, third re-gate, fix (a): with NO canonicalPath override, a scratch repo's own docs/p0/x2-recorded-ledger.json never matches the REAL toolkit's canonical path — exploit A3's own shape", async () => {
    const { dir, ledgerPath } = await initGitRepo();
    const ledgerJson = '{"entries": []}\n';
    writeFileSync(ledgerPath, ledgerJson, "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "scratch, forged"], { cwd: dir });

    const bareDir = await initUpstreamBare();
    await pushLedger(bareDir, ledgerJson);
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

    const result = await checkLedgerAgainstGit(ledgerPath, verification);
    expect(result.pathIsCanonical).toBe(false);
    expect(result.clean).toBe(false);
    await verification.cleanup();
  });

  it("a committed, canonical-path ledger with an UNCOMMITTED edit is reported dirty, with a reason", async () => {
    const { dir, ledgerPath } = await initGitRepo();
    const ledgerJson = '{"entries": []}\n';
    writeFileSync(ledgerPath, ledgerJson, "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger"], { cwd: dir });

    const bareDir = await initUpstreamBare();
    await pushLedger(bareDir, ledgerJson);
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

    writeFileSync(
      ledgerPath,
      '{"entries": [{"method": "rendered", "normalizedUrl": "x", "url": "x", "sha256": "' +
        "a".repeat(64) +
        '", "recordedAt": "2026-01-01T00:00:00Z"}]}\n',
      "utf8",
    );

    const result = await checkLedgerAgainstGit(ledgerPath, verification, { canonicalPath: ledgerPath });
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/uncommitted changes/);
    expect(result.blobHash).toMatch(/^[0-9a-f]{40}$/);
    await verification.cleanup();
  });

  it("an UNTRACKED ledger file (never git-added at all) is reported dirty — `git diff` alone would miss this", async () => {
    const { ledgerPath } = await initGitRepo();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");

    const verification = await verifyAgainstGitHub({ repoUrl: "/this/path/does/not/exist/at/all", runtimeExecArgv: [] });
    const result = await checkLedgerAgainstGit(ledgerPath, verification, { canonicalPath: ledgerPath });
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/untracked/);
    await verification.cleanup();
  });

  it("gate finding 4, probe D: a canonical, committed ledger that GitHub main does NOT have yet is marked UNOFFICIAL (verifiedMainUnavailable), never a plain dirty refusal", async () => {
    const { dir, ledgerPath } = await initGitRepo();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger, never verified"], { cwd: dir });

    const bareDir = await initUpstreamBare();
    const workDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-ledger-empty-upstream-"));
    await execFileAsync("git", ["init", "-q"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: workDir });
    await execFileAsync("git", ["config", "user.name", "Test"], { cwd: workDir });
    writeFileSync(nodePath.join(workDir, "README.md"), "x\n", "utf8");
    await execFileAsync("git", ["add", "-A"], { cwd: workDir });
    await execFileAsync("git", ["commit", "-q", "-m", "placeholder"], { cwd: workDir });
    await execFileAsync("git", ["branch", "-M", "main"], { cwd: workDir });
    await execFileAsync("git", ["push", "-q", bareDir, "HEAD:main"], { cwd: workDir });
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

    const result = await checkLedgerAgainstGit(ledgerPath, verification, { canonicalPath: ledgerPath });
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.verifiedAgainstGithub).toBe(false);
    expect(result.verifiedMainUnavailable).toBe(true);
    await verification.cleanup();
  });

  it("gate finding 4, probe D: a canonical, committed ledger whose content DIVERGED from what GitHub main already has is refused as dirty (not the missing-path carve-out)", async () => {
    const { dir, ledgerPath } = await initGitRepo();
    const v1 = '{"entries": []}\n';
    writeFileSync(ledgerPath, v1, "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "v1"], { cwd: dir });

    const bareDir = await initUpstreamBare();
    await pushLedger(bareDir, v1);

    const v2 =
      '{"entries": [{"method": "direct", "normalizedUrl": "x", "url": "x", "sha256": "' +
      "b".repeat(64) +
      '", "recordedAt": "2026-01-01T00:00:00Z"}]}\n';
    writeFileSync(ledgerPath, v2, "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "v2, not re-verified"], { cwd: dir });

    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });
    const result = await checkLedgerAgainstGit(ledgerPath, verification, { canonicalPath: ledgerPath });
    expect(result.pathIsCanonical).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.verifiedAgainstGithub).toBe(false);
    expect(result.verifiedMainUnavailable).toBe(false);
    expect(result.detail).toMatch(/does not match what GitHub's real main/);
    await verification.cleanup();
  });

  it("gate finding 4, probe E: a ledger marked assume-unchanged in git is refused (hiddenByGitFlag), even though git diff/status report it clean", async () => {
    const { dir, ledgerPath } = await initGitRepo();
    const v1 = '{"entries": []}\n';
    writeFileSync(ledgerPath, v1, "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "add ledger"], { cwd: dir });
    await execFileAsync(
      "git",
      ["update-index", "--assume-unchanged", "docs/p0/x2-recorded-ledger.json"],
      { cwd: dir },
    );
    writeFileSync(
      ledgerPath,
      '{"entries": [{"method": "direct", "normalizedUrl": "hidden", "url": "hidden", "sha256": "' +
        "c".repeat(64) +
        '", "recordedAt": "2026-01-01T00:00:00Z"}]}\n',
      "utf8",
    );

    const bareDir = await initUpstreamBare();
    await pushLedger(bareDir, v1);
    const verification = await verifyAgainstGitHub({ repoUrl: bareDir, runtimeExecArgv: [] });

    const result = await checkLedgerAgainstGit(ledgerPath, verification, { canonicalPath: ledgerPath });
    expect(result.hiddenByGitFlag).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.detail).toMatch(/assume-unchanged or skip-worktree/);
    await verification.cleanup();
  });

  it("a path outside any git repository (or a missing file) resolves to NOT clean, never silently 'clean'", async () => {
    const outsideDir = mkdtempSync(nodePath.join(tmpdir(), "golfraven-p0-not-a-repo-"));
    const ledgerPath = nodePath.join(outsideDir, "recorded-ledger.json");
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    const verification = await verifyAgainstGitHub({ repoUrl: "/this/path/does/not/exist/at/all", runtimeExecArgv: [] });
    const result = await checkLedgerAgainstGit(ledgerPath, verification);
    expect(result.clean).toBe(false);
    expect(result.pathIsCanonical).toBe(false);
    await verification.cleanup();
  });

  it("gate finding, fourth re-gate: a verification that itself failed (ok: false) flows through as UNOFFICIAL, never a false OFFICIAL", async () => {
    const { dir, ledgerPath } = await initGitRepo();
    writeFileSync(ledgerPath, '{"entries": []}\n', "utf8");
    await execFileAsync("git", ["add", "docs/p0/x2-recorded-ledger.json"], { cwd: dir });
    await execFileAsync("git", ["commit", "-q", "-m", "ledger"], { cwd: dir });

    const verification = await verifyAgainstGitHub({ repoUrl: "/nonexistent", runtimeExecArgv: [] });
    expect(verification.ok).toBe(false);
    const result = await checkLedgerAgainstGit(ledgerPath, verification, { canonicalPath: ledgerPath });
    expect(result.clean).toBe(false);
    expect(result.verifiedMainUnavailable).toBe(true);
    expect(result.verifiedAgainstGithub).toBe(false);
    await verification.cleanup();
  });
});
