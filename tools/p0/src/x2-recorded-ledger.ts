/**
 * The recorded-captures LEDGER (Addendum J correction's first-capture-wins
 * rule, gate finding 2). This is the ONE authoritative record of which
 * capture, of a given URL by a given method, is "the recorded one" — the
 * only one a confirmation file may cite.
 *
 * Why a ledger and not just each manifest entry's own `recorded` field:
 * `recorded` on a manifest entry answers "was this capture the first one
 * ITS OWN WRITER (x2-fetch / x2-ingest) knew about, in the evidence dir it
 * happened to write to" — which a gate review found could be hard-coded
 * `true` by construction (a single manifest never has two entries for the
 * same URL+method within itself) and, more importantly, cannot detect a
 * duplicate capture written to a DIFFERENT evidence directory in a LATER
 * run. The ledger is deliberately NOT scoped to one evidence directory —
 * it is a small, separate, explicitly-pathed file that every capture
 * (across however many `--out-dir`s a real investigation ends up using)
 * consults and updates, so "first capture, anywhere" is actually
 * enforceable, not just "first capture in this one folder."
 *
 * URL matching uses `normalizeUrlForFirstCapture` (below) — the SAME
 * effective URL reached via a different host-casing, a `www.` prefix, a
 * trailing slash, or a fragment/query is treated as one URL for this
 * purpose, per the gate's own finding that those were bypasses.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export type X2LedgerMethod = "direct" | "rendered" | "owner-saved";

/**
 * Normalizes a URL for first-capture-wins matching: lowercases the host,
 * drops a leading "www.", drops the fragment and the query string
 * entirely (decision, documented in the task report: treating `?a=1` as
 * the SAME resource as the bare URL, the simpler of the two options the
 * gate finding offered — not the "flag distinct" alternative), and drops
 * ONE trailing slash from the path (except the bare root, which stays
 * `/`). Scheme is not part of the key — every URL this tool ever fetches
 * is already https-only (gate N6), enforced well before this function
 * runs. Throws on an unparseable URL — a caller should already have
 * validated the URL before reaching this point.
 */
export function normalizeUrlForFirstCapture(url: string): string {
  const u = new URL(url);
  let host = u.hostname.toLowerCase();
  if (host.startsWith("www.")) host = host.slice(4);
  let pathname = u.pathname;
  if (pathname.length > 1 && pathname.endsWith("/")) pathname = pathname.slice(0, -1);
  if (pathname === "") pathname = "/";
  return `${host}${pathname}`;
}

export interface RecordedLedgerEntry {
  method: X2LedgerMethod;
  normalizedUrl: string;
  /** The original, un-normalized URL — kept for a human reading the file. */
  url: string;
  sha256: string;
  /** UTC ISO-8601 — when this capture was registered as the recorded one. */
  recordedAt: string;
}

export interface RecordedLedger {
  entries: RecordedLedgerEntry[];
}

export const RECORDED_LEDGER_FILENAME = "recorded-ledger.json";

/** Default ledger path for a given evidence/out directory — callers that
 * want ONE ledger shared across several `--out-dir`s (the realistic case
 * for a multi-session investigation, and required for the gate's own
 * finding 2c) pass an explicit `--ledger` path instead of relying on this. */
export function defaultLedgerPath(outDir: string): string {
  return path.join(outDir, RECORDED_LEDGER_FILENAME);
}

/** Loads a ledger file, or returns an empty one if it doesn't exist yet —
 * a missing ledger is not an error (the very first capture anywhere has
 * nothing to load), but a MALFORMED one is (refuses rather than silently
 * discarding a real record). */
export async function loadLedger(ledgerPath: string): Promise<RecordedLedger> {
  let raw: string;
  try {
    raw = await readFile(ledgerPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { entries: [] };
    }
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Ledger file "${ledgerPath}" is not valid JSON — refusing to treat it as empty: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !Array.isArray((parsed as { entries?: unknown }).entries)
  ) {
    throw new Error(`Ledger file "${ledgerPath}" does not have the expected { entries: [...] } shape.`);
  }
  return parsed as RecordedLedger;
}

export async function saveLedger(ledgerPath: string, ledger: RecordedLedger): Promise<void> {
  await mkdir(path.dirname(ledgerPath), { recursive: true });
  await writeFile(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`, "utf8");
}

/** Finds the existing ledger entry for this method+URL (URL normalized
 * internally), if any. */
export function findLedgerEntry(
  ledger: RecordedLedger,
  method: X2LedgerMethod,
  url: string,
): RecordedLedgerEntry | undefined {
  const normalizedUrl = normalizeUrlForFirstCapture(url);
  return ledger.entries.find((e) => e.method === method && e.normalizedUrl === normalizedUrl);
}

/**
 * Registers a capture against the ledger at `ledgerPath` and reports
 * whether it is the RECORDED one. If no prior entry exists for this
 * method+URL, this capture is added as the recorded one (`recorded:
 * true`, ledger updated and saved). If a prior entry already exists,
 * `allowAdditional` decides what happens: `false` (the default — used by
 * `x2-fetch`'s own direct/render paths, which have no `--additional`
 * concept) REFUSES outright; `true` (used by `x2-ingest --additional`)
 * allows the capture through as `recorded: false`, WITHOUT touching the
 * ledger — the first entry stays the recorded one, forever, for this
 * method+URL.
 */
export async function registerCapture(
  ledgerPath: string,
  entry: { method: X2LedgerMethod; url: string; sha256: string },
  opts: { allowAdditional?: boolean } = {},
): Promise<{ recorded: boolean; ledger: RecordedLedger }> {
  const ledger = await loadLedger(ledgerPath);
  const existing = findLedgerEntry(ledger, entry.method, entry.url);
  if (existing) {
    if (!opts.allowAdditional) {
      throw new Error(
        `A recorded ${entry.method} capture of "${entry.url}" (normalized: "${existing.normalizedUrl}") ` +
          `already exists in the ledger "${ledgerPath}" (sha256 ${existing.sha256.slice(0, 12)}..., recorded ` +
          `${existing.recordedAt}) — first-capture-wins. This capture is refused; pass the allow-additional ` +
          "option to store it anyway as a non-recorded capture.",
      );
    }
    return { recorded: false, ledger };
  }
  const normalizedUrl = normalizeUrlForFirstCapture(entry.url);
  const newEntry: RecordedLedgerEntry = {
    method: entry.method,
    normalizedUrl,
    url: entry.url,
    sha256: entry.sha256,
    recordedAt: new Date().toISOString(),
  };
  ledger.entries.push(newEntry);
  await saveLedger(ledgerPath, ledger);
  return { recorded: true, ledger };
}
