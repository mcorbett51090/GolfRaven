#!/usr/bin/env node
/**
 * `x2-corroborate-wayback` — gate finding 3 (re-gate, Addendum J re-gate at
 * 24b2b6a): the corroboration file's OLD `wayback` record type could be
 * forged outright — `snapshotText` was free text a human (or a compromised
 * agent) typed directly into a JSON file, never actually checked against
 * anything real. `x2-verdict` trusted it verbatim.
 *
 * This tool closes that: it is the ONLY way a "wayback" corroboration
 * record gets made. It:
 *
 *  1. Requires the archive URL to be in the EXACT form
 *     `https://web.archive.org/web/<14-digit timestamp>/<url>` — refuses
 *     anything else (a shortened/redirect-style Wayback URL, a different
 *     host entirely, a missing timestamp).
 *  2. Parses the embedded `<url>` out of that path and requires it to
 *     normalise (`x2-recorded-ledger.ts`'s `normalizeUrlForFirstCapture`
 *     — the SAME normalisation first-capture-wins and the owner-saved
 *     URL allow-list already use) to the SAME thing as `--stated-url` —
 *     a snapshot of a DIFFERENT page can never corroborate THIS fact.
 *  3. Parses the 14-digit timestamp and requires it to be within ±90 days
 *     of `--owner-saved-date` — a snapshot from a wildly different time
 *     says nothing about what the owner saw on the date they state.
 *  4. ACTUALLY FETCHES the snapshot itself (an injectable fetcher, same
 *     dependency-injection principle `x2-fetch.ts` uses for `global.
 *     fetch`, so tests never hit the real network) — never trusts bytes
 *     a human supplies.
 *  5. Stores the fetched bytes as real evidence (gate S1 style: raw file
 *     + a SHA-256 computed from ONLY those bytes, `raw/<sha>.html`) and
 *     derives its text with the SAME extractor (`evidence-extract.ts`)
 *     every other evidence route in this tool family uses.
 *  6. Produces a corroboration record that cites ONLY the stored SHA-256
 *     and the raw file's path — never inline text. `x2-verdict` later
 *     RE-VERIFIES this record itself (re-reads the raw bytes, recomputes
 *     the SHA, re-derives the text) before trusting it for anything —
 *     this tool's own output is not itself the trust boundary, the
 *     re-verification is.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractEvidenceText } from "./evidence-extract.js";
import { loadLedger, normalizeUrlForFirstCapture, saveLedger } from "./x2-recorded-ledger.js";
import {
  assertOutsideRepoUnlessExplicit,
  defaultOutsideRepoDir,
} from "./run-dir.js";
import type { X2CorroborationFile, X2WaybackCorroboration } from "./x2-verdict.js";

/**
 * Gate finding 3 (second re-gate): registers this snapshot in the
 * canonical ledger under method `"wayback"` — `x2-verdict`'s own
 * re-validation REQUIRES such an entry to exist before trusting a
 * `wayback` corroboration record at all, so a hand-crafted record (never
 * produced by this tool, never registered here) is refused regardless of
 * how well-formed it otherwise looks. Deliberately NOT `registerCapture`
 * (first-capture-wins, evidence-registry semantics): a `wayback` entry is
 * a CORROBORATION record, not competing evidence — the same URL can
 * legitimately be corroborated more than once (different owner-saved
 * captures of it, corroborated at different times), so this appends a
 * new entry for a genuinely new (sha256, url) pair and is a no-op if the
 * EXACT same one is already there (idempotent re-runs, never a duplicate
 * row for identical content).
 */
async function registerWaybackInLedger(
  ledgerPath: string,
  entry: { url: string; sha256: string },
): Promise<void> {
  const ledger = await loadLedger(ledgerPath);
  const normalizedUrl = normalizeUrlForFirstCapture(entry.url);
  const alreadyThere = ledger.entries.some(
    (le) => le.method === "wayback" && le.sha256 === entry.sha256 && le.normalizedUrl === normalizedUrl,
  );
  if (!alreadyThere) {
    ledger.entries.push({
      method: "wayback",
      normalizedUrl,
      url: entry.url,
      sha256: entry.sha256,
      recordedAt: new Date().toISOString(),
    });
    await saveLedger(ledgerPath, ledger);
  }
}

const WAYBACK_URL_RE = /^https:\/\/web\.archive\.org\/web\/(\d{14})\/(.+)$/;
const WAYBACK_TIMESTAMP_RE = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/;

export const WAYBACK_TIMESTAMP_TOLERANCE_DAYS = 90;
export const WAYBACK_USER_AGENT = "GolfRaven-P0-X2/0.1 (wayback corroboration)";
export const DEFAULT_WAYBACK_FETCH_TIMEOUT_MS = 30_000;
export const DEFAULT_WAYBACK_MAX_BYTES = 10 * 1024 * 1024; // 10 MB, matches net.ts's cap

/**
 * Parses `archiveUrl`, requiring the EXACT form
 * `https://web.archive.org/web/<14 digits>/<url>` — refuses (returns
 * `null`, never throws; the caller decides how loud to be) anything else:
 * a different host, a missing/short/non-numeric timestamp, a flag suffix
 * (`id_`, `if_`) Wayback sometimes appends to the timestamp (a real
 * Wayback URL shape, deliberately NOT accepted — widening the accepted
 * shape is a policy call this tool does not make unilaterally), or a
 * missing embedded URL.
 */
export function parseWaybackUrl(
  archiveUrl: string,
): { timestamp: string; embeddedUrl: string } | null {
  const m = WAYBACK_URL_RE.exec(archiveUrl);
  if (!m) return null;
  const [, timestamp, embeddedUrl] = m;
  if (!timestamp || !embeddedUrl) return null;
  return { timestamp, embeddedUrl };
}

/** Parses a 14-digit Wayback timestamp (`YYYYMMDDHHMMSS`, always UTC per
 * Wayback's own convention) into a `Date`. Throws on a syntactically
 * 14-digit but semantically impossible timestamp (e.g. month 13) — the
 * same "recompute and compare" integrity discipline this tool family uses
 * elsewhere, never trusting that 14 digits alone means a real date. */
export function waybackTimestampToDate(timestamp: string): Date {
  const m = WAYBACK_TIMESTAMP_RE.exec(timestamp);
  if (!m) {
    throw new Error(`"${timestamp}" is not a 14-digit Wayback timestamp.`);
  }
  const [, y, mo, d, h, mi, s] = m as unknown as [
    string,
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  const date = new Date(
    Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)),
  );
  if (
    date.getUTCFullYear() !== Number(y) ||
    date.getUTCMonth() !== Number(mo) - 1 ||
    date.getUTCDate() !== Number(d)
  ) {
    throw new Error(`"${timestamp}" is not a real calendar date/time.`);
  }
  return date;
}

/** Absolute difference between two dates, in whole days. */
export function daysBetween(a: Date, b: Date): number {
  return Math.abs(a.getTime() - b.getTime()) / (24 * 60 * 60 * 1000);
}

export type WaybackFetcher = (
  url: string,
  init: RequestInit,
) => Promise<{ status: number; ok: boolean; arrayBuffer(): Promise<ArrayBuffer> }>;

export interface CorroborateWaybackOptions {
  /** The Wayback snapshot URL to corroborate with — see `parseWaybackUrl`
   * for the exact required shape. */
  archiveUrl: string;
  /** The URL of the fact being corroborated — the archive URL's OWN
   * embedded URL must normalise to the same thing. */
  statedUrl: string;
  /** `YYYY-MM-DD` — the owner-saved fact's own stated date; the snapshot's
   * timestamp must be within `WAYBACK_TIMESTAMP_TOLERANCE_DAYS` of this. */
  ownerSavedDate: string;
  /** Where to store the fetched evidence — same `raw/`/`text/` layout
   * `x2-fetch.ts`/`x2-ingest.ts` already use, so `x2-verdict.ts`'s own
   * `readRaw` (already scoped to an evidence dir) can read it back. */
  outDir: string;
  /** Gate finding 3 (second re-gate): REQUIRED — the canonical ledger to
   * register this snapshot in, under method `"wayback"`. `x2-verdict`'s
   * own re-validation pass now REQUIRES a matching ledger entry before it
   * trusts any `wayback` record, so a caller that forgot this flag would
   * silently produce a record `x2-verdict` can never actually accept —
   * making it required here surfaces that at corroboration time, not
   * later as a confusing verdict failure. Same required-flag discipline
   * as `--ledger` on `x2-fetch`/`x2-ingest`/`x2-verdict` (gate finding
   * 2c, re-gate). */
  ledgerPath: string;
  /** Injectable — defaults to `globalThis.fetch`. Tests inject a fake so
   * this tool's own tests never hit the real network; a real invocation
   * uses the real one (and, per this environment's own proxy rules, may
   * need `NODE_USE_ENV_PROXY=1` — see this module's own CLI notes). */
  fetcher?: WaybackFetcher;
  timeoutMs?: number;
  maxBytes?: number;
}

/**
 * Runs the full pipeline described in this module's own doc. Throws
 * (refuses) on: a malformed archive URL; an embedded URL that does not
 * normalise to `statedUrl`; a timestamp outside the tolerance window; a
 * non-https archive URL (should be structurally impossible given the
 * regex, checked anyway); a fetch failure or non-2xx response; a response
 * over `maxBytes`. Never fabricates a corroboration record for bytes it
 * has not itself verified.
 */
export async function corroborateWayback(
  opts: CorroborateWaybackOptions,
): Promise<X2WaybackCorroboration> {
  const parsed = parseWaybackUrl(opts.archiveUrl);
  if (!parsed) {
    throw new Error(
      `"${opts.archiveUrl}" is not a Wayback snapshot URL in the required form ` +
        '"https://web.archive.org/web/<14-digit timestamp>/<url>" — refusing (gate finding 3, re-gate).',
    );
  }
  const { timestamp, embeddedUrl } = parsed;

  let embeddedNormalized: string;
  let statedNormalized: string;
  try {
    embeddedNormalized = normalizeUrlForFirstCapture(embeddedUrl);
  } catch {
    throw new Error(`the archive URL's embedded URL "${embeddedUrl}" is not a valid URL.`);
  }
  try {
    statedNormalized = normalizeUrlForFirstCapture(opts.statedUrl);
  } catch {
    throw new Error(`--stated-url "${opts.statedUrl}" is not a valid URL.`);
  }
  if (embeddedNormalized !== statedNormalized) {
    throw new Error(
      `the archive URL's embedded URL ("${embeddedUrl}", normalises to "${embeddedNormalized}") does not ` +
        `match --stated-url ("${opts.statedUrl}", normalises to "${statedNormalized}") — a snapshot of a ` +
        "DIFFERENT page can never corroborate this fact (gate finding 3, re-gate).",
    );
  }

  const snapshotDate = waybackTimestampToDate(timestamp);
  const [y, mo, d] = opts.ownerSavedDate.split("-").map(Number);
  if (y === undefined || mo === undefined || d === undefined) {
    throw new Error(`--owner-saved-date "${opts.ownerSavedDate}" is not YYYY-MM-DD.`);
  }
  const ownerSavedDate = new Date(Date.UTC(y, mo - 1, d));
  const gapDays = daysBetween(snapshotDate, ownerSavedDate);
  if (gapDays > WAYBACK_TIMESTAMP_TOLERANCE_DAYS) {
    throw new Error(
      `the snapshot's timestamp (${timestamp}, ${snapshotDate.toISOString()}) is ${gapDays.toFixed(1)} days ` +
        `from --owner-saved-date "${opts.ownerSavedDate}" — outside the ` +
        `${WAYBACK_TIMESTAMP_TOLERANCE_DAYS}-day tolerance (gate finding 3, re-gate): a snapshot from a ` +
        "wildly different time says nothing about what the owner saw on the date they state.",
    );
  }

  const fetcher = opts.fetcher ?? (globalThis.fetch as WaybackFetcher);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_WAYBACK_FETCH_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_WAYBACK_MAX_BYTES;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let buf: Buffer;
  try {
    let response: { status: number; ok: boolean; arrayBuffer(): Promise<ArrayBuffer> };
    try {
      response = await fetcher(opts.archiveUrl, {
        method: "GET",
        headers: { "User-Agent": WAYBACK_USER_AGENT },
        signal: controller.signal,
      });
    } catch (err) {
      throw new Error(
        `fetching the Wayback snapshot failed: ${err instanceof Error ? err.message : String(err)} — ` +
          "if this is a connectivity/timeout error, check whether web.archive.org is reachable from this " +
          "environment at all (this session's own agent proxy may block it outright — try " +
          "`NODE_USE_ENV_PROXY=1`, and report reachability either way rather than assuming).",
      );
    }
    if (!response.ok) {
      throw new Error(`the Wayback snapshot fetch returned HTTP ${response.status} (not 2xx).`);
    }
    const arrayBuf = await response.arrayBuffer();
    if (arrayBuf.byteLength > maxBytes) {
      throw new Error(`the Wayback snapshot is ${arrayBuf.byteLength} bytes, over the ${maxBytes}-byte cap.`);
    }
    buf = Buffer.from(arrayBuf);
  } finally {
    clearTimeout(timer);
  }

  const sha256 = createHash("sha256").update(buf).digest("hex");
  // Gate finding 3 (second re-gate): `x2-verdict`'s own re-validation
  // requires `rawFile` to be exactly `raw/<snapshotSha256>.<ext>` — no
  // "wayback-" prefix (that shape can never match the required regex, so
  // it would refuse its OWN output otherwise).
  const rawRelPath = path.join("raw", `${sha256}.html`);
  await mkdir(path.join(opts.outDir, "raw"), { recursive: true });
  await writeFile(path.join(opts.outDir, rawRelPath), buf);

  // Store the text too (a convenience copy, exactly like `x2-fetch.ts`'s
  // own `storeEvidenceBytes` — `x2-verdict.ts` re-derives it from the raw
  // bytes at verdict time regardless, never trusting this file).
  const { text } = await extractEvidenceText(buf, "text/html", opts.archiveUrl);
  let textRelPath: string | null = null;
  if (text !== null) {
    textRelPath = path.join("text", `${sha256}.txt`);
    await mkdir(path.join(opts.outDir, "text"), { recursive: true });
    await writeFile(path.join(opts.outDir, textRelPath), text, "utf8");
  }

  // Gate finding 3 (second re-gate): registers this snapshot in the
  // canonical ledger under method "wayback" — `x2-verdict`'s own
  // re-validation REQUIRES this entry to exist before it will trust the
  // record this function is about to return.
  await registerWaybackInLedger(opts.ledgerPath, { url: opts.statedUrl, sha256 });

  return {
    type: "wayback",
    snapshotUrl: opts.archiveUrl,
    snapshotSha256: sha256,
    rawFile: rawRelPath,
  };
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
  const { url, trail } = flags;
  const statedUrl = flags["stated-url"];
  const ownerSavedDate = flags["owner-saved-date"];
  if (!url || !statedUrl || !ownerSavedDate || !trail || !flags.ledger) {
    throw new Error(
      "Usage: node dist/x2-corroborate-wayback.js --url <https://web.archive.org/web/…> " +
        "--stated-url <url being corroborated> --owner-saved-date YYYY-MM-DD --trail TN|VI|RTJ " +
        "--evidence-sha <the owner-saved fact's evidenceSha> --ledger <path to the canonical ledger> " +
        "[--out-dir <dir>] [--corroboration-file <file.json>] — writes/merges a corroboration record into " +
        "--corroboration-file (default: <out-dir>/corroboration.json) and registers the snapshot in " +
        "--ledger under method \"wayback\" (gate finding 3, second re-gate: x2-verdict's own re-validation " +
        "requires that ledger entry to exist). NODE_USE_ENV_PROXY=1 may be needed for the real fetch, " +
        "depending on this environment's proxy policy.",
    );
  }
  const evidenceSha = flags["evidence-sha"];
  if (!evidenceSha) {
    throw new Error("--evidence-sha is required — which owner-saved fact this record corroborates.");
  }
  const outDirExplicit = Boolean(flags["out-dir"]);
  const outDir = flags["out-dir"] || defaultOutsideRepoDir("x2-wayback-evidence");
  assertOutsideRepoUnlessExplicit(outDir, outDirExplicit);

  const record = await corroborateWayback({
    archiveUrl: url,
    statedUrl,
    ownerSavedDate,
    outDir,
    ledgerPath: flags.ledger,
  });

  const corroborationFilePath = flags["corroboration-file"] || path.join(outDir, "corroboration.json");
  let corroboration: X2CorroborationFile = {};
  try {
    corroboration = JSON.parse(await readFile(corroborationFilePath, "utf8")) as X2CorroborationFile;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  // Gate finding 2 (re-gate): the corroboration file's per-(trail,
  // evidenceSha) slot is a LIST now — a wayback record is appended
  // alongside whatever `acceptance` records (each for a different fact)
  // Matt may already have added by hand, never overwriting them.
  const trailCorroboration = corroboration[trail] ?? {};
  const existingForSha = (trailCorroboration[evidenceSha] ?? []).filter(
    (r) => r.type !== "wayback",
  );
  corroboration[trail] = { ...trailCorroboration, [evidenceSha]: [...existingForSha, record] };
  await writeFile(corroborationFilePath, `${JSON.stringify(corroboration, null, 2)}\n`, "utf8");

  process.stdout.write(
    `Corroborated ${trail}/${evidenceSha.slice(0, 12)}... via ${url} — stored sha256 ${record.snapshotSha256}, ` +
      `written to ${corroborationFilePath}\n`,
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
    process.stderr.write(`x2-corroborate-wayback: ${message}\n`);
    process.exitCode = 1;
  });
}
