#!/usr/bin/env node
/**
 * `x2-fetch` — X2 (build plan §10 P0; `docs/p0/X2.md`) pilot-slate
 * roster/rules direct-fetch: for each slate trail's official URLs (seeded
 * in `config/x2-sources.json` from X2.md's URL table), fetches each URL
 * DIRECTLY — never a search snippet, per X2.md METHOD — and stores evidence
 * per decision 0001 Addendum G: the raw bytes, the final URL after
 * redirects, the HTTP status, the retrieval time (UTC), a SHA-256 of the
 * bytes, and an extracted-text file (HTML → text, tags stripped and
 * whitespace collapsed — `text-extract.ts`; PDF → the bytes are stored and
 * text extraction is recorded as `"manual"`, since no PDF-parsing library
 * is added as a dependency — "do not pretend" applies here exactly as it
 * does to any other unverified claim in this codebase).
 *
 * A fetch that fails — including a network-policy block, see `net.ts` — is
 * recorded as FAILED with the exact error; it is never silently skipped or
 * dropped from the manifest.
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
import { extractDraftCandidateNames, stripHtmlToText } from "./text-extract.js";
import { buildAsciiUserAgent, fetchWithBlockDetection } from "./net.js";

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
   * — `null` when extraction is `"manual"` or the fetch failed. */
  textFile: string | null;
  textExtraction: "auto" | "manual" | "n/a";
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

function extForUrlAndType(contentType: string | null, url: string): string {
  const ct = (contentType ?? "").toLowerCase();
  if (ct.includes("pdf") || url.toLowerCase().split("?")[0]?.endsWith(".pdf")) {
    return "pdf";
  }
  if (ct.includes("html")) return "html";
  return "bin";
}

function isPdf(contentType: string | null, url: string): boolean {
  return extForUrlAndType(contentType, url) === "pdf";
}

async function fetchOne(
  trail: string,
  url: string,
  outDir: string,
  timeoutMs: number,
): Promise<X2FetchEntry> {
  const fetchedAt = new Date().toISOString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let outcome: Awaited<ReturnType<typeof fetchWithBlockDetection>>;
  try {
    outcome = await fetchWithBlockDetection(url, {
      method: "GET",
      headers: { "User-Agent": buildX2UserAgent() },
      redirect: "follow",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (outcome.kind !== "ok") {
    return {
      trail,
      url,
      status: "failed",
      httpStatus: null,
      finalUrl: null,
      contentType: null,
      fetchedAt,
      sha256: null,
      rawFile: null,
      textFile: null,
      textExtraction: "n/a",
      blocked: outcome.kind === "blocked",
      error:
        outcome.kind === "blocked"
          ? `BLOCKED — network policy (${outcome.host}): ${outcome.detail}`
          : `fetch error (${outcome.host}): ${outcome.detail}`,
      draftCandidateNames: [],
    };
  }

  const response = outcome.response;
  if (!response.ok) {
    const bodySample = await response.text().catch(() => "");
    return {
      trail,
      url,
      status: "failed",
      httpStatus: response.status,
      finalUrl: response.url || null,
      contentType: response.headers.get("content-type"),
      fetchedAt,
      sha256: null,
      rawFile: null,
      textFile: null,
      textExtraction: "n/a",
      blocked: false,
      error: `HTTP ${response.status} ${response.statusText} — ${bodySample.slice(0, 300)}`,
      draftCandidateNames: [],
    };
  }

  const contentType = response.headers.get("content-type");
  const buf = Buffer.from(await response.arrayBuffer());
  const sha256 = createHash("sha256").update(buf).digest("hex");
  const ext = extForUrlAndType(contentType, url);
  const rawRelPath = path.join("raw", `${sha256}.${ext}`);
  await mkdir(path.join(outDir, "raw"), { recursive: true });
  await writeFile(path.join(outDir, rawRelPath), buf);

  let textFile: string | null = null;
  let textExtraction: "auto" | "manual" | "n/a" = "n/a";
  let draftCandidateNames: string[] = [];
  if (isPdf(contentType, url)) {
    // Addendum G / task instruction: no pure-JS PDF extractor is pinned as
    // a dependency, so a PDF's text is never pretended to have been read —
    // the bytes are stored and this is recorded plainly as "manual".
    textExtraction = "manual";
  } else {
    const html = buf.toString("utf8");
    const text = stripHtmlToText(html);
    const textRelPath = path.join("text", `${sha256}.txt`);
    await mkdir(path.join(outDir, "text"), { recursive: true });
    await writeFile(path.join(outDir, textRelPath), text, "utf8");
    textFile = textRelPath;
    textExtraction = "auto";
    draftCandidateNames = extractDraftCandidateNames(html);
  }

  return {
    trail,
    url,
    status: "fetched",
    httpStatus: response.status,
    finalUrl: response.url || url,
    contentType,
    fetchedAt,
    sha256,
    rawFile: rawRelPath,
    textFile,
    textExtraction,
    blocked: false,
    error: null,
    draftCandidateNames,
  };
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
  const outDir = flags["out-dir"] || "x2-evidence";
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
