#!/usr/bin/env node
/**
 * `x2-fetch` — X2 (build plan §10 P0; `docs/p0/X2.md`) pilot-slate
 * roster/rules direct-fetch: for each slate trail's official URLs (seeded
 * in `config/x2-sources.json` from X2.md's URL table), fetches each URL
 * DIRECTLY — never a search snippet, per X2.md METHOD — and stores evidence
 * per decision 0001 Addendum G: the raw bytes, the final URL after
 * redirects, the HTTP status, the retrieval time (UTC), a SHA-256 of the
 * bytes, and an extracted-text file. HTML is tag-stripped (`text-extract.
 * ts`, gate S4: inline element boundaries never insert a space); a PDF's
 * text is derived with the pinned pure-JS extractor (`pdf-extract.ts`,
 * gate S3) — the SAME extraction function `x2-verdict` re-runs over the
 * raw bytes at verdict time (`evidence-extract.ts`), so the stored
 * `text/<sha>.txt` file is a convenience copy, never itself trusted.
 *
 * A fetch that fails — including a network-policy block, see `net.ts` — is
 * recorded as FAILED with the exact error; it is never silently skipped or
 * dropped from the manifest. The abort timer used for the request timeout
 * stays live through the full body read (gate S6), and the body is capped
 * at `DEFAULT_MAX_RESPONSE_BYTES` while streaming.
 *
 * This tool only gathers and stores evidence. It does NOT confirm a
 * trail's roster/completionUnit/season — that is `x2-verdict`, a separate,
 * human-in-the-loop step: Addendum G requires a fact to be backed by a
 * quote in a human-written confirmation file, verified against this
 * evidence, never by this tool's own DRAFT candidate-name list (printed
 * below, clearly labelled — it is a hint for a human writing the
 * confirmation file, never itself a confirmation).
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractDraftCandidateNames } from "./text-extract.js";
import { classifyEvidenceBytes, extractEvidenceText } from "./evidence-extract.js";
import { buildAsciiUserAgent, DEFAULT_MAX_RESPONSE_BYTES, fetchWithBlockDetection, readBodyCapped } from "./net.js";
import { assertOutsideRepoUnlessExplicit, defaultOutsideRepoDir } from "./run-dir.js";

export const X2_DEFAULT_TIMEOUT_MS = 30_000;

export function buildX2UserAgent(): string {
  return buildAsciiUserAgent({
    toolTag: "GolfRaven-P0-X2/0.1",
    docRef: "docs/p0/X2.md",
    envVarName: "X2_CONTACT",
  });
}

/** trail name -> list of official URLs to fetch (`config/x2-sources.json`). */
export type X2SourceConfig = Record<string, string[]>;

export interface X2FetchEntry {
  trail: string;
  url: string;
  status: "fetched" | "failed";
  httpStatus: number | null;
  finalUrl: string | null;
  contentType: string | null;
  /** UTC ISO-8601 retrieval time (Addendum G: "the retrieval time (UTC)"). */
  fetchedAt: string;
  sha256: string | null;
  /** Path to the raw bytes, relative to the evidence output dir. */
  rawFile: string | null;
  /** Path to the extracted-text file, relative to the evidence output dir
   * — `null` when there is no extractable text or the fetch failed. */
  textFile: string | null;
  /** `"auto-pdf"` (gate S3) records which pinned extractor produced the
   * text, so a verdict-time re-derivation can assert it used the same one. */
  textExtraction: "auto" | "auto-pdf" | "n/a";
  extractor: string | null;
  /** True when the failure was this environment's own network-policy block
   * (see `net.ts`), not a genuine site-side failure. */
  blocked: boolean;
  error: string | null;
  /** Headings/link texts pulled from this one URL's HTML — DRAFT only, see
   * module doc. Empty for PDFs and failed fetches. */
  draftCandidateNames: string[];
}

export interface X2FetchManifest {
  generatedAt: string;
  outDir: string;
  trails: Record<string, X2FetchEntry[]>;
  /** Deduplicated union, per trail, of every URL's `draftCandidateNames` —
   * still DRAFT, never a confirmation. */
  draftCandidateNames: Record<string, string[]>;
}

function failedEntry(
  trail: string,
  url: string,
  fetchedAt: string,
  error: string,
  opts: { blocked?: boolean; httpStatus?: number | null; finalUrl?: string | null } = {},
): X2FetchEntry {
  return {
    trail,
    url,
    status: "failed",
    httpStatus: opts.httpStatus ?? null,
    finalUrl: opts.finalUrl ?? null,
    contentType: null,
    fetchedAt,
    sha256: null,
    rawFile: null,
    textFile: null,
    textExtraction: "n/a",
    extractor: null,
    blocked: opts.blocked ?? false,
    error,
    draftCandidateNames: [],
  };
}

async function fetchOne(
  trail: string,
  url: string,
  outDir: string,
  timeoutMs: number,
): Promise<X2FetchEntry> {
  const fetchedAt = new Date().toISOString();

  // Gate finding N6: only ever fetch https: URLs — a repo-controlled config
  // is low-risk, but a `data:`/`http:` entry should still be refused rather
  // than silently "fetched" as evidence.
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return failedEntry(trail, url, fetchedAt, `not a valid URL: "${url}" (gate N6)`);
  }
  if (parsedUrl.protocol !== "https:") {
    return failedEntry(
      trail,
      url,
      fetchedAt,
      `refusing to fetch non-https URL "${url}" (scheme "${parsedUrl.protocol}") — gate N6`,
    );
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let outcome: Awaited<ReturnType<typeof fetchWithBlockDetection>>;
    try {
      outcome = await fetchWithBlockDetection(url, {
        method: "GET",
        headers: { "User-Agent": buildX2UserAgent() },
        redirect: "follow",
        signal: controller.signal,
      });
    } catch (err) {
      return failedEntry(
        trail,
        url,
        fetchedAt,
        `fetch threw unexpectedly: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    if (outcome.kind !== "ok") {
      return failedEntry(
        trail,
        url,
        fetchedAt,
        outcome.kind === "blocked"
          ? `BLOCKED — network policy (${outcome.host}): ${outcome.detail}`
          : `fetch error (${outcome.host}): ${outcome.detail}`,
        { blocked: outcome.kind === "blocked" },
      );
    }

    const response = outcome.response;
    const finalUrl = response.url || url;
    try {
      const finalParsed = new URL(finalUrl);
      if (finalParsed.protocol !== "https:") {
        return failedEntry(
          trail,
          url,
          fetchedAt,
          `refusing evidence whose final URL downgraded to "${finalParsed.protocol}" (gate N6)`,
          { httpStatus: response.status, finalUrl },
        );
      }
    } catch {
      // finalUrl not parseable — fall through, handled generically below.
    }

    if (!response.ok) {
      const bodySample = await readBodyCapped(response, {
        signal: controller.signal,
        maxBytes: DEFAULT_MAX_RESPONSE_BYTES,
      })
        .then((buf) => buf.toString("utf8"))
        .catch(() => "");
      return failedEntry(
        trail,
        url,
        fetchedAt,
        `HTTP ${response.status} ${response.statusText} — ${bodySample.slice(0, 300)}`,
        { httpStatus: response.status, finalUrl },
      );
    }

    const contentType = response.headers.get("content-type");
    let buf: Buffer;
    try {
      buf = await readBodyCapped(response, {
        signal: controller.signal,
        maxBytes: DEFAULT_MAX_RESPONSE_BYTES,
      });
    } catch (err) {
      return failedEntry(
        trail,
        url,
        fetchedAt,
        `body read failed (timeout or size cap, gate S6): ${err instanceof Error ? err.message : String(err)}`,
        { httpStatus: response.status, finalUrl },
      );
    }

    const sha256 = createHash("sha256").update(buf).digest("hex");
    const kind = classifyEvidenceBytes(buf, contentType, url);
    const ext = kind === "pdf" ? "pdf" : kind === "html" ? "html" : "bin";
    const rawRelPath = path.join("raw", `${sha256}.${ext}`);
    await mkdir(path.join(outDir, "raw"), { recursive: true });
    await writeFile(path.join(outDir, rawRelPath), buf);

    const { text, textExtraction, extractor } = await extractEvidenceText(buf, contentType, url);
    let textFile: string | null = null;
    let draftCandidateNames: string[] = [];
    if (text !== null) {
      const textRelPath = path.join("text", `${sha256}.txt`);
      await mkdir(path.join(outDir, "text"), { recursive: true });
      await writeFile(path.join(outDir, textRelPath), text, "utf8");
      textFile = textRelPath;
    }
    if (kind === "html") {
      draftCandidateNames = extractDraftCandidateNames(buf.toString("utf8"));
    }

    return {
      trail,
      url,
      status: "fetched",
      httpStatus: response.status,
      finalUrl,
      contentType,
      fetchedAt,
      sha256,
      rawFile: rawRelPath,
      textFile,
      textExtraction,
      extractor,
      blocked: false,
      error: null,
      draftCandidateNames,
    };
  } finally {
    // Gate S6: the timer stays live through the ENTIRE fetch — including
    // the body read above — and is cleared only once everything is done.
    clearTimeout(timer);
  }
}

export async function runX2Fetch(
  config: X2SourceConfig,
  outDir: string,
  opts: { timeoutMs?: number } = {},
): Promise<X2FetchManifest> {
  const timeoutMs = opts.timeoutMs ?? X2_DEFAULT_TIMEOUT_MS;
  if (Object.keys(config).length === 0) {
    throw new Error(
      "x2-fetch config has no trails — refusing to run against an empty source list.",
    );
  }
  await mkdir(outDir, { recursive: true });
  const trails: Record<string, X2FetchEntry[]> = {};
  const draftCandidateNames: Record<string, string[]> = {};
  for (const [trail, urls] of Object.entries(config)) {
    const entries: X2FetchEntry[] = [];
    const names: string[] = [];
    const seenNames = new Set<string>();
    for (const url of urls) {
      // Sequential, not parallel: polite to the destination hosts, and
      // keeps fetchedAt strictly ordered for a human reading the log.
      const entry = await fetchOne(trail, url, outDir, timeoutMs);
      entries.push(entry);
      for (const n of entry.draftCandidateNames) {
        if (!seenNames.has(n)) {
          seenNames.add(n);
          names.push(n);
        }
      }
    }
    trails[trail] = entries;
    draftCandidateNames[trail] = names;
  }
  const manifest: X2FetchManifest = {
    generatedAt: new Date().toISOString(),
    outDir,
    trails,
    draftCandidateNames,
  };
  await writeFile(
    path.join(outDir, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  return manifest;
}

export function renderManifestSummary(manifest: X2FetchManifest): string {
  const lines: string[] = [];
  for (const [trail, entries] of Object.entries(manifest.trails)) {
    const fetched = entries.filter((e) => e.status === "fetched").length;
    lines.push(`${trail}: ${fetched}/${entries.length} URL(s) fetched`);
    for (const e of entries) {
      if (e.status === "failed") {
        lines.push(`  FAILED ${e.url} — ${e.error}`);
      } else {
        lines.push(
          `  OK ${e.url} -> ${e.finalUrl} (sha256 ${e.sha256?.slice(0, 12)}..., text: ${e.textExtraction})`,
        );
      }
    }
    const names = manifest.draftCandidateNames[trail] ?? [];
    lines.push(
      `  DRAFT candidate names (headings/links — NOT a confirmation; x2-verdict decides that from a ` +
        `human-written confirmation file): ${names.length > 0 ? names.join("; ") : "(none)"}`,
    );
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseFlags(argv: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      flags[arg.slice(2)] = argv[i + 1] ?? "";
      i += 1;
    }
  }
  return flags;
}

/** Repo-relative path to `config/x2-sources.json`, resolved from THIS
 * module's own location (works from `src/` via vitest and from `dist/`,
 * since both sit exactly one level under `tools/p0`). */
export function resolveDefaultX2ConfigPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const pkgRoot = path.join(here, "..");
  return path.join(pkgRoot, "config", "x2-sources.json");
}

async function main(argv: string[]): Promise<void> {
  const flags = parseFlags(argv);
  const configPath = flags.config || resolveDefaultX2ConfigPath();
  const outDirExplicit = Boolean(flags["out-dir"]);
  const outDir = flags["out-dir"] || defaultOutsideRepoDir("x2-evidence");
  assertOutsideRepoUnlessExplicit(outDir, outDirExplicit);
  const config = JSON.parse(
    await readFile(configPath, "utf8"),
  ) as X2SourceConfig;
  const manifest = await runX2Fetch(config, outDir);
  process.stdout.write(`${renderManifestSummary(manifest)}\n`);
  process.stdout.write(
    `Manifest written to ${path.join(outDir, "manifest.json")}\n`,
  );
}

/** Gate finding B-11-style real-path comparison (x5-overpass.ts /
 * x1-verdict.ts): compares REAL paths so this still runs correctly when
 * invoked through a symlinked checkout path. */
async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
    const [herePath, argvPath] = await Promise.all([
      realpath(fileURLToPath(import.meta.url)),
      realpath(process.argv[1]),
    ]);
    return herePath === argvPath;
  } catch {
    return false;
  }
}

if (await isMainModule()) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`x2-fetch: ${message}\n`);
    process.exitCode = 1;
  });
}
