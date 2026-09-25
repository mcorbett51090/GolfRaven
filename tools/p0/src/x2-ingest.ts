#!/usr/bin/env node
/**
 * `x2-ingest` — the third X2 evidence route (decision 0001 Addendum J(a)
 * (ii), 2026-09-24, written AFTER the first X2 run showed TN's site
 * returning HTTP 403 to the tool's own polite, non-browser User-Agent —
 * see `docs/decisions/0001-owner-decisions-and-p0-thresholds.md`, including
 * its 2026-09-24 correction). Takes a page the OWNER saved from their own
 * browser ("Save Page As", HTML), the URL they state it came from, and the
 * date they state they saved it, and stores it as evidence into an
 * `x2-fetch`-shaped evidence dir with `method: "owner-saved"`.
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
 * **Nothing here independently verifies the file's bytes ever touched the
 * stated URL** (the Addendum J correction's own point) — that is what the
 * correction's web.archive.org corroboration requirement, and Matt's
 * written acceptance of an uncorroborated fact, are for; neither is
 * mechanically enforced by this tool (they are `x2-verdict`/human-process
 * concerns), but this tool's OWN safeguards are the ones a gate review
 * found missing, fixed below.
 *
 * **Host allow-list (Addendum J(a)):** the stated URL's host must be on
 * that trail's OWN configured host list (`config/x2-sources.json`'s URLs
 * for that trail) — the same same-host equivalence `x2-verdict.ts`'s
 * `sameConfiguredHost` already uses (bare domain / `www.` prefix only). A
 * stated URL on a host that trail's config never named is refused outright
 * — an owner-saved page cannot smuggle in evidence for a host the trail's
 * own config never listed as official.
 *
 * **First-capture-wins (Addendum J correction).** The first owner-saved
 * capture of a given URL is the RECORDED one (`recorded: true`); ingesting
 * a second owner-saved capture of the SAME url+trail refuses outright
 * unless `--additional` is passed, in which case it is stored anyway —
 * still real evidence, never discarded — but stamped `recorded: false`.
 * `x2-verdict` refuses to let a confirmation file cite a non-recorded
 * capture.
 *
 * The output evidence dir is `x2-fetch`-shaped: writing into an EXISTING
 * evidence dir (from a prior `x2-fetch`/`x2-fetch --render` run) MERGES
 * this entry into that trail's array and rewrites `manifest.json` — the
 * same `manifest.json` `x2-verdict` already reads, so a confirmation file
 * can cite an owner-saved SHA exactly like a direct-fetch or rendered one.
 * The merge never rewrites the manifest's own original `generatedAt` (gate
 * finding — it used to be clobbered on every ingest).
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
  findLedgerEntry,
  loadLedger,
  normalizeUrlForFirstCapture,
  registerCapture,
} from "./x2-recorded-ledger.js";
import {
  assertOutsideRepoUnlessExplicit,
  defaultOutsideRepoDir,
} from "./run-dir.js";

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Decision 0001 Addendum I precedent (K1/K3 date sanity), applied here:
 * no owner-saved date earlier than the P0 work actually started. */
export const X2_INGEST_MIN_DATE = "2026-09-01";

/** 10 MB — same cap `net.ts`'s `DEFAULT_MAX_RESPONSE_BYTES` uses for a
 * direct fetch's response body, applied here to the owner-saved file
 * itself so a huge file can't be read into memory unbounded. Checked via
 * `stat` BEFORE the file is read, not after. */
export const X2_INGEST_MAX_FILE_BYTES = 10 * 1024 * 1024;

/** Gate finding: a `trail` (or any other string this tool uses as an
 * object key) of `"__proto__"`, `"constructor"` or `"prototype"` can
 * corrupt a plain object's prototype chain via bracket-notation assignment
 * (`obj[trail] = …`) rather than creating an ordinary own property. Refused
 * outright, cleanly, before any such assignment is attempted. */
const DANGEROUS_OBJECT_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);
export function assertSafeObjectKey(key: string, label: string): void {
  if (DANGEROUS_OBJECT_KEYS.has(key)) {
    throw new Error(
      `${label} "${key}" is refused outright — it is a JavaScript object-prototype key name, not a real ` +
        "value this tool will use as an object key.",
    );
  }
}

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
 * or differing only by a leading "www."). Retained (and still tested) as
 * a general host-level equivalence check; `statedUrlAllowed` below is the
 * STRICTER, actually-enforced gate on an owner-saved stated URL — a
 * matching host is necessary but, since gate finding 2a (re-gate), no
 * longer sufficient. */
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

/** Gate finding 2a (re-gate): an owner-saved stated URL must exactly
 * match, after normalisation (`normalizeUrlForFirstCapture` — the SAME
 * normalisation `registerCapture`'s first-capture-wins check uses, so
 * "matches the config" and "matches an earlier capture" agree on what
 * counts as the same URL), one of `trailUrls` — that trail's own
 * `config/x2-sources.json` entry. A host-only check (the OLDER
 * `statedHostAllowed`) let an owner-saved page smuggle in evidence for
 * ANY OTHER PATH on an allowed host — a stated URL for
 * `https://www.tnstateparks.com/anything-at-all` used to pass as long as
 * the trail's config named `tnstateparks.com` for ANY page. This is
 * stricter and supersedes it. */
export function normalizedTrailUrls(urls: readonly string[]): Set<string> {
  const out = new Set<string>();
  for (const u of urls) {
    try {
      out.add(normalizeUrlForFirstCapture(u));
    } catch {
      // Skip an unparseable configured URL — not this function's job to
      // validate the config file (matches `trailConfiguredHosts` above).
    }
  }
  return out;
}

/** True when `statedUrl`, normalised, is EXACTLY one of `trailUrls`
 * (normalised the same way) — not merely on an allowed host. */
export function statedUrlAllowed(
  statedUrl: string,
  trailUrls: readonly string[],
): boolean {
  let normalized: string;
  try {
    normalized = normalizeUrlForFirstCapture(statedUrl);
  } catch {
    return false;
  }
  return normalizedTrailUrls(trailUrls).has(normalized);
}

export interface X2IngestResult {
  entry: X2FetchEntry;
  manifest: X2FetchManifest;
}

/**
 * Ingests one owner-saved HTML file as X2 evidence. Refuses (throws) when:
 * the stated URL is not `https:` (gate N6, same rule as `x2-fetch`); the
 * stated URL's host is not on the trail's configured host list (Addendum
 * J(a)'s host allow-list); `trail` is a dangerous object-key name; the
 * stated date is not a real `YYYY-MM-DD` calendar date, is earlier than
 * `X2_INGEST_MIN_DATE`, or is later than the ingestion time; the file is
 * larger than `X2_INGEST_MAX_FILE_BYTES`, cannot be read, or cannot be
 * read at all; or a RECORDED owner-saved capture of this URL already
 * exists for this trail and `opts.additional` was not set. Never fabricates
 * a fact that isn't in the bytes it was given — it only stores what the
 * owner handed it, honestly labelled.
 */
export async function ingestOwnerSavedPage(opts: {
  trail: string;
  filePath: string;
  statedUrl: string;
  statedDate: string;
  sourceConfig: X2SourceConfig;
  outDir: string;
  /** First-capture-wins: without this, a second owner-saved capture of the
   * same URL for the same trail is refused. With it, the capture proceeds
   * and is stored with `recorded: false`. */
  additional?: boolean;
  /** Gate finding 2c (re-gate): REQUIRED — the recorded-captures ledger
   * path, see `x2-recorded-ledger.ts`. There is no more automatic
   * `<outDir>/recorded-ledger.json` default; pass the SAME explicit path
   * `x2-fetch --render`/`x2-fetch` used for TN/VI/RTJ's own evidence when
   * ingesting into a different `--out-dir` for the same URL set, so
   * first-capture-wins is enforced across all of them, not just within
   * this one directory. */
  ledgerPath: string;
}): Promise<X2IngestResult> {
  const { trail, filePath, statedUrl, statedDate, sourceConfig, outDir } = opts;

  if (!opts.ledgerPath) {
    throw new Error(
      "ingestOwnerSavedPage: `ledgerPath` is required (gate finding 2c, re-gate) — the per-directory default " +
        "ledger was removed; pass an explicit `--ledger <path>` (or `ledgerPath` option) shared across every " +
        "run that captures evidence for the same URL set.",
    );
  }

  assertSafeObjectKey(trail, "--trail");

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

  const fetchedAt = new Date().toISOString();
  // Gate finding (should-fix): the "future" bound is the OWNER's stated
  // date, and the owner could genuinely be anywhere on Earth — including
  // UTC+14 (Kiribati / the Line Islands), the furthest-ahead timezone that
  // exists. Comparing against plain UTC "today" would falsely refuse a
  // real, honest date from someone already living tomorrow relative to
  // UTC. The bound is therefore "today, anywhere on Earth" — UTC + 14h —
  // not "today in UTC".
  const latestPossibleTodayAnywhere = new Date(Date.now() + 14 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 10); // YYYY-MM-DD

  // Gate finding: an owner-saved date has to be a real, sane claim — not
  // before P0 work started, and never later than the moment of ingestion
  // (a date in the future is not a date anything was actually saved on).
  // String comparison is exact here because both sides are fixed-width
  // YYYY-MM-DD, so lexical order equals chronological order.
  if (statedDate < X2_INGEST_MIN_DATE) {
    throw new Error(
      `--date "${statedDate}" is earlier than ${X2_INGEST_MIN_DATE} — refusing a date before this work began.`,
    );
  }
  if (statedDate > latestPossibleTodayAnywhere) {
    throw new Error(
      `--date "${statedDate}" is after the latest possible "today" anywhere on Earth ` +
        `(${latestPossibleTodayAnywhere}, UTC+14) — refusing a date in the future.`,
    );
  }

  const trailUrls = sourceConfig[trail];
  if (!trailUrls) {
    throw new Error(
      `Trail "${trail}" has no entry in the source config — refusing to ingest evidence for a trail this ` +
        "config doesn't even know about (decision 0001 Addendum J(a): the host allow-list is per trail).",
    );
  }
  // Gate finding 2a (re-gate): the stated URL must exactly match — after
  // normalisation — one of the trail's own configured URLs, not merely
  // share an allowed HOST. A host-only check let a stated URL name ANY
  // path on that host; this is what actually closes it.
  if (!statedUrlAllowed(statedUrl, trailUrls)) {
    throw new Error(
      `Stated URL "${statedUrl}" does not exactly match (after normalisation) any URL in trail "${trail}"'s ` +
        `configured list (${trailUrls.join(", ") || "(none)"}) — decision 0001 Addendum J(a) / gate finding ` +
        "2a (re-gate): an owner-saved page's stated URL must be one of the trail's own configured URLs, not " +
        "merely on an allowed host.",
    );
  }

  // Gate finding: a 10 MB cap on the OWNER-SAVED FILE ITSELF, checked via
  // `stat` before ever reading it into memory — this tool never streams,
  // so the cap has to be a pre-check, not an enforced-while-reading one
  // like `net.ts`'s direct-fetch cap.
  let fileStat: Awaited<ReturnType<typeof stat>>;
  try {
    fileStat = await stat(filePath);
  } catch (err) {
    throw new Error(
      `could not read --file "${filePath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (fileStat.size > X2_INGEST_MAX_FILE_BYTES) {
    throw new Error(
      `--file "${filePath}" is ${fileStat.size} bytes, over the ${X2_INGEST_MAX_FILE_BYTES}-byte cap — refusing ` +
        "to read it into memory.",
    );
  }

  // Gate finding 2: first-capture-wins is checked against the shared
  // LEDGER (not by scanning this one manifest's own entries — a capture
  // ingested into a DIFFERENT `--out-dir` for the same URL still counts),
  // BEFORE any bytes are read or written, so a refusal never leaves an
  // orphaned raw/text file on disk. URL matching is normalised (gate
  // finding 2a — case/`www.`/trailing-slash/fragment/query insensitive).
  const ledgerPath = opts.ledgerPath;
  const existingLedgerEntry = findLedgerEntry(await loadLedger(ledgerPath), "owner-saved", statedUrl);
  if (existingLedgerEntry && !opts.additional) {
    throw new Error(
      `A recorded owner-saved capture of "${statedUrl}" (normalised: "${existingLedgerEntry.normalizedUrl}") ` +
        `already exists in the ledger (sha256 ${existingLedgerEntry.sha256.slice(0, 12)}..., recorded ` +
        `${existingLedgerEntry.recordedAt}) — first-capture-wins (Addendum J correction). Pass --additional ` +
        "to ingest a further, non-recorded capture; the recorded one is never replaced.",
    );
  }

  // The manifest itself is loaded separately from the ledger — it is
  // where this entry's full evidence record is stored/merged; the ledger
  // is only "which SHA is the recorded one for this URL+method."
  const manifestPath = path.join(outDir, "manifest.json");
  let manifest: X2FetchManifest;
  const manifestExists = await stat(manifestPath).catch(() => null);
  if (manifestExists) {
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

  let buf: Buffer;
  try {
    buf = await readFile(filePath);
  } catch (err) {
    throw new Error(
      `could not read --file "${filePath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const contentType = "text/html";
  const sha256 = createHash("sha256").update(buf).digest("hex");
  const kind = classifyEvidenceBytes(buf, contentType, statedUrl);
  const ext = kind === "pdf" ? "pdf" : kind === "html" ? "html" : "bin";

  // Gate finding: extract text BEFORE writing the raw file, so a failure
  // in extraction never leaves a raw file on disk with no corresponding
  // text — the two are written together or not at all, raw-file-write last.
  const { text, textExtraction, extractor } = await extractEvidenceText(
    buf,
    contentType,
    statedUrl,
  );
  const draftCandidateNames =
    kind === "html" ? extractDraftCandidateNames(buf.toString("utf8")) : [];

  const rawRelPath = path.join("raw", `${sha256}.${ext}`);
  let textFile: string | null = null;
  if (text !== null) {
    const textRelPath = path.join("text", `${sha256}.txt`);
    await mkdir(path.join(outDir, "text"), { recursive: true });
    await writeFile(path.join(outDir, textRelPath), text, "utf8");
    textFile = textRelPath;
  }
  await mkdir(path.join(outDir, "raw"), { recursive: true });
  await writeFile(path.join(outDir, rawRelPath), buf);

  // Register against the ledger now that the SHA is known. The pre-check
  // above already refused a duplicate without `--additional`; this call
  // cannot refuse again (nothing changed the ledger in between within one
  // call), so its `recorded` result is what actually gets stored.
  const { recorded } = await registerCapture(
    ledgerPath,
    { method: "owner-saved", url: statedUrl, sha256 },
    { allowAdditional: opts.additional ?? false },
  );

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
    renderArgs: null,
    renderProxyHost: null,
    recorded,
  };

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
  // Gate finding: do NOT rewrite `generatedAt` on a merge — that field is
  // the manifest's own original creation time (from whichever tool made it
  // first, `x2-fetch` or this one), not "the last time anything touched
  // this file." Only the `else` branch above (a brand-new manifest) sets it.
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
  // `--additional` is a bare boolean toggle (no value) — stripped before
  // `parseFlags` runs, same reasoning as `--render` in `x2-fetch.ts`.
  const additional = argv.includes("--additional");
  const flags = parseFlags(argv.filter((a) => a !== "--additional"));
  const { trail, file, url, date } = flags;
  if (!trail || !file || !url || !date || !flags.ledger) {
    throw new Error(
      "Usage: node dist/x2-ingest.js --trail TN|VI|RTJ --file <owner-saved.html> --url <stated URL> " +
        "--date YYYY-MM-DD --ledger <path> [--config <x2-sources.json>] [--out-dir <dir>] [--additional] " +
        "— `--ledger` is REQUIRED (gate finding 2c, re-gate): the per-directory default ledger was removed.",
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
    additional,
    ledgerPath: flags.ledger,
  });
  process.stdout.write(
    `Ingested owner-saved evidence for ${trail}: ${entry.url} (saved ${entry.ownerSavedDate}, sha256 ` +
      `${entry.sha256?.slice(0, 12)}..., recorded: ${entry.recorded})\n`,
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
