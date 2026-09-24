#!/usr/bin/env node
/**
 * `x2-ingest` — the third X2 evidence route (decision 0001 Addendum J(a)
 * (ii), 2026-09-24, written AFTER the first X2 run showed TN's site
 * returning HTTP 403 to the tool's own polite, non-browser User-Agent —
 * see `docs/decisions/0001-owner-decisions-and-p0-thresholds.md`). Takes a
 * page the OWNER saved from their own browser ("Save Page As", HTML), the
 * URL they state it came from, and the date they state they saved it, and
 * stores it as evidence into an `x2-fetch`-shaped evidence dir with
 * `method: "owner-saved"`.
 *
 * This tool never fetches anything itself and never spoofs a browser User-
 * Agent to get past a site's own block — the owner's own browser already
 * did the fetching, outside this tool entirely; this tool only ingests the
 * result. The stored record keeps everything Addendum G already requires:
 * the raw bytes, the final URL, the HTTP status (`"owner-saved"`, since
 * there is no real HTTP exchange this tool witnessed), the retrieval time
 * in UTC (`fetchedAt` — the ingestion time, distinct from `ownerSavedDate`,
 * the date the OWNER states they saved it), and a SHA-256.
 *
 * **Host allow-list (Addendum J(a)):** the stated URL's host must be on
 * that trail's OWN configured host list (`config/x2-sources.json`'s URLs
 * for that trail) — the same same-host equivalence `x2-verdict.ts`'s
 * `sameConfiguredHost` already uses (bare domain / `www.` prefix only). A
 * stated URL on a host that trail's config never named is refused outright
 * — an owner-saved page cannot smuggle in evidence for a host the trail's
 * own config never listed as official.
 *
 * The output evidence dir is `x2-fetch`-shaped: writing into an EXISTING
 * evidence dir (from a prior `x2-fetch`/`x2-fetch --render` run) MERGES
 * this entry into that trail's array and rewrites `manifest.json` — the
 * same `manifest.json` `x2-verdict` already reads, so a confirmation file
 * can cite an owner-saved SHA exactly like a direct-fetch or rendered one.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractDraftCandidateNames } from "./text-extract.js";
import {
  classifyEvidenceBytes,
  extractEvidenceText,
} from "./evidence-extract.js";
import {
  resolveDefaultX2ConfigPath,
  type X2FetchEntry,
  type X2FetchManifest,
  type X2SourceConfig,
} from "./x2-fetch.js";
import { sameConfiguredHost } from "./x2-verdict.js";
import {
  assertOutsideRepoUnlessExplicit,
  defaultOutsideRepoDir,
} from "./run-dir.js";

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Every host that trail's own `config/x2-sources.json` entry names —
 * Addendum J(a)'s host allow-list for an owner-saved page. Malformed URLs
 * in the config (should not happen — it is repo-controlled) are simply
 * skipped rather than thrown on, since this is a read of trusted config,
 * not of untrusted input. */
export function trailConfiguredHosts(urls: readonly string[]): string[] {
  const hosts: string[] = [];
  for (const u of urls) {
    try {
      hosts.push(new URL(u).hostname);
    } catch {
      // Skip an unparseable configured URL — not this function's job to
      // validate the config file.
    }
  }
  return hosts;
}

/** True when `statedUrl`'s host matches at least one of `configuredHosts`
 * under the same same-host equivalence `x2-verdict.ts` uses (exact match,
 * or differing only by a leading "www."). */
export function statedHostAllowed(
  statedUrl: string,
  configuredHosts: readonly string[],
): boolean {
  let host: string;
  try {
    host = new URL(statedUrl).hostname;
  } catch {
    return false;
  }
  return configuredHosts.some((h) => sameConfiguredHost(h, host));
}

export interface X2IngestResult {
  entry: X2FetchEntry;
  manifest: X2FetchManifest;
}

/**
 * Ingests one owner-saved HTML file as X2 evidence. Refuses (throws) when:
 * the stated URL is not `https:` (gate N6, same rule as `x2-fetch`); the
 * stated URL's host is not on the trail's configured host list (Addendum
 * J(a)'s host allow-list); the stated date is not a real `YYYY-MM-DD`
 * calendar date; or the file cannot be read. Never fabricates a fact that
 * isn't in the bytes it was given — it only stores what the owner handed
 * it, honestly labelled.
 */
export async function ingestOwnerSavedPage(opts: {
  trail: string;
  filePath: string;
  statedUrl: string;
  statedDate: string;
  sourceConfig: X2SourceConfig;
  outDir: string;
}): Promise<X2IngestResult> {
  const { trail, filePath, statedUrl, statedDate, sourceConfig, outDir } = opts;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(statedUrl);
  } catch {
    throw new Error(`--url "${statedUrl}" is not a valid URL (gate N6).`);
  }
  if (parsedUrl.protocol !== "https:") {
    throw new Error(
      `refusing to ingest evidence whose stated URL "${statedUrl}" is not https (scheme ` +
        `"${parsedUrl.protocol}") — gate N6.`,
    );
  }

  if (!DATE_RE.test(statedDate)) {
    throw new Error(
      `--date "${statedDate}" is not a real YYYY-MM-DD calendar date.`,
    );
  }
  const [y, m, d] = statedDate.split("-").map(Number);
  const asDate = new Date(Date.UTC(y!, m! - 1, d!));
  if (
    asDate.getUTCFullYear() !== y ||
    asDate.getUTCMonth() !== m! - 1 ||
    asDate.getUTCDate() !== d
  ) {
    throw new Error(`--date "${statedDate}" is not a real calendar date.`);
  }

  const trailUrls = sourceConfig[trail];
  if (!trailUrls) {
    throw new Error(
      `Trail "${trail}" has no entry in the source config — refusing to ingest evidence for a trail this ` +
        "config doesn't even know about (decision 0001 Addendum J(a): the host allow-list is per trail).",
    );
  }
  const configuredHosts = trailConfiguredHosts(trailUrls);
  if (!statedHostAllowed(statedUrl, configuredHosts)) {
    throw new Error(
      `Stated URL "${statedUrl}" (host "${parsedUrl.hostname}") is not on trail "${trail}"'s configured host ` +
        `list (${configuredHosts.join(", ") || "(none)"}) — decision 0001 Addendum J(a): an owner-saved page's ` +
        "stated host must be on that trail's own configured host list.",
    );
  }

  let buf: Buffer;
  try {
    buf = await readFile(filePath);
  } catch (err) {
    throw new Error(
      `could not read --file "${filePath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const fetchedAt = new Date().toISOString();
  const contentType = "text/html";
  const sha256 = createHash("sha256").update(buf).digest("hex");
  const kind = classifyEvidenceBytes(buf, contentType, statedUrl);
  const ext = kind === "pdf" ? "pdf" : kind === "html" ? "html" : "bin";
  const rawRelPath = path.join("raw", `${sha256}.${ext}`);
  await mkdir(path.join(outDir, "raw"), { recursive: true });
  await writeFile(path.join(outDir, rawRelPath), buf);

  const { text, textExtraction, extractor } = await extractEvidenceText(
    buf,
    contentType,
    statedUrl,
  );
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

  const entry: X2FetchEntry = {
    trail,
    url: statedUrl,
    status: "fetched",
    httpStatus: "owner-saved",
    finalUrl: statedUrl,
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
    method: "owner-saved",
    ownerSavedDate: statedDate,
  };

  const manifestPath = path.join(outDir, "manifest.json");
  let manifest: X2FetchManifest;
  const exists = await stat(manifestPath).catch(() => null);
  if (exists) {
    manifest = JSON.parse(
      await readFile(manifestPath, "utf8"),
    ) as X2FetchManifest;
  } else {
    manifest = {
      generatedAt: fetchedAt,
      outDir,
      trails: {},
      draftCandidateNames: {},
    };
  }
  manifest.trails[trail] = [...(manifest.trails[trail] ?? []), entry];
  const seen = new Set(manifest.draftCandidateNames[trail] ?? []);
  const names = [...(manifest.draftCandidateNames[trail] ?? [])];
  for (const n of draftCandidateNames) {
    if (!seen.has(n)) {
      seen.add(n);
      names.push(n);
    }
  }
  manifest.draftCandidateNames[trail] = names;
  manifest.generatedAt = fetchedAt;
  await writeFile(
    manifestPath,
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );

  return { entry, manifest };
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

async function main(argv: string[]): Promise<void> {
  const flags = parseFlags(argv);
  const { trail, file, url, date } = flags;
  if (!trail || !file || !url || !date) {
    throw new Error(
      "Usage: node dist/x2-ingest.js --trail TN|VI|RTJ --file <owner-saved.html> --url <stated URL> " +
        "--date YYYY-MM-DD [--config <x2-sources.json>] [--out-dir <dir>]",
    );
  }
  const configPath = flags.config || resolveDefaultX2ConfigPath();
  const sourceConfig = JSON.parse(
    await readFile(configPath, "utf8"),
  ) as X2SourceConfig;
  const outDirExplicit = Boolean(flags["out-dir"]);
  const outDir = flags["out-dir"] || defaultOutsideRepoDir("x2-evidence");
  assertOutsideRepoUnlessExplicit(outDir, outDirExplicit);

  const { entry } = await ingestOwnerSavedPage({
    trail,
    filePath: file,
    statedUrl: url,
    statedDate: date,
    sourceConfig,
    outDir,
  });
  process.stdout.write(
    `Ingested owner-saved evidence for ${trail}: ${entry.url} (saved ${entry.ownerSavedDate}, sha256 ` +
      `${entry.sha256?.slice(0, 12)}...)\n`,
  );
  process.stdout.write(
    `Manifest written to ${path.join(outDir, "manifest.json")}\n`,
  );
}

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
    process.stderr.write(`x2-ingest: ${message}\n`);
    process.exitCode = 1;
  });
}
