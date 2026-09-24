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
 * trailing slash, a fragment/query, unreserved percent-encoding, a
 * doubled path slash or a `;param` path segment is treated as one URL for
 * this purpose, per the gate's own findings that those were bypasses
 * (first round: host-casing/www./trailing-slash/fragment/query; re-gate
 * round: percent-encoding/`//`/`;params` — see the function's own doc).
 *
 * **Re-gate finding 2c: there is no more per-directory DEFAULT ledger
 * path.** `defaultLedgerPath`/`RECORDED_LEDGER_FILENAME`'s old role as an
 * automatic, silent fallback (`opts.ledgerPath ?? defaultLedgerPath(outDir)`
 * inside `x2-fetch`/`x2-ingest`/`x2-verdict`) is REMOVED — a caller that
 * forgot to pass `--ledger` used to silently get a fresh, empty,
 * `outDir`-scoped ledger, under which "first capture in THIS directory"
 * trivially always succeeds — re-opening the exact cross-directory
 * duplicate-capture hole finding 2c already existed to close, just one
 * missed flag away. `ledgerPath` is now a REQUIRED argument everywhere
 * evidence is captured or verified (`x2-fetch`, `x2-ingest`, `x2-verdict`)
 * — every caller, CLI or test, makes an explicit, conscious choice of
 * WHICH ledger a capture counts against. `RECORDED_LEDGER_FILENAME`
 * remains exported as a plain naming convention (`path.join(dir,
 * RECORDED_LEDGER_FILENAME)`) for a caller who deliberately wants one
 * ledger per directory — that is now something a caller opts INTO, not
 * something that happens whether they meant to or not.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export type X2LedgerMethod = "direct" | "rendered" | "owner-saved";

const UNRESERVED_PERCENT_ENCODED_RE = /%[0-9A-Fa-f]{2}/g;
/** RFC 3986 2.3 "unreserved" characters — the only ones this function will
 * decode out of a percent-encoding. Everything else (including `%2F`,
 * which encodes `/` — decoding THAT would change how many path segments
 * there are, not just how one is spelled) is left exactly as written. */
function isUnreservedChar(ch: string): boolean {
  return /^[A-Za-z0-9\-._~]$/.test(ch);
}

/** Gate finding 2a (re-gate): decodes ONLY unreserved-character percent
 * escapes (e.g. `%67` -> `g`) — per RFC 3986 6.2.2.2, a percent-encoding
 * of an unreserved character is defined to be equivalent to the character
 * itself, so `/%67olf` and `/golf` are, by spec, the identical resource,
 * not merely similar-looking ones. A reserved or unassigned escape (e.g.
 * `%2F`, `%20`) is left untouched — decoding those WOULD change the URL's
 * structure or introduce characters normalisation has to treat specially,
 * which is a different, not-yet-needed problem this function does not
 * attempt to solve. */
function decodeUnreservedPercentEncoding(input: string): string {
  return input.replace(UNRESERVED_PERCENT_ENCODED_RE, (match) => {
    const ch = String.fromCharCode(Number.parseInt(match.slice(1), 16));
    return isUnreservedChar(ch) ? ch : match;
  });
}

/** Gate finding 2a (re-gate): strips a leading `;param` segment-parameter
 * (RFC 3986 3.3 — `;` inside a path segment introduces segment-scoped
 * parameters, e.g. `/golf;x` is the SAME resource as `/golf` with a `x`
 * parameter attached, which this tool has no use for and must not let
 * become a distinct, unrefused "different" URL) from EVERY path segment,
 * not just the last one. */
function stripPathParams(pathname: string): string {
  return pathname
    .split("/")
    .map((segment) => {
      const i = segment.indexOf(";");
      return i === -1 ? segment : segment.slice(0, i);
    })
    .join("/");
}

/**
 * Normalizes a URL for first-capture-wins matching: lowercases the host,
 * drops a leading "www.", KEEPS a non-default port (the WHATWG `URL`
 * parser already drops an explicit `:443` on an `https:` URL as
 * redundant, since 443 IS the scheme's default — so `u.port` is only
 * ever non-empty here for a genuinely different, non-default port, which
 * this function deliberately does NOT treat as the same resource), drops
 * the fragment and the query string entirely (decision, documented in the
 * task report: treating `?a=1` as the SAME resource as the bare URL, the
 * simpler of the two options the gate finding offered — not the "flag
 * distinct" alternative; **this drop is why a query-string difference
 * never distinguishes two captures for this tool's purposes — documented
 * here, not just implied**), decodes unreserved percent-encoding in the
 * path (`decodeUnreservedPercentEncoding`, gate finding 2a re-gate),
 * collapses a run of 2+ consecutive path slashes into one (gate finding
 * 2a re-gate — `//golf` and `/golf` read as the same path to a real HTTP
 * server), strips a `;param` from every path segment (gate finding 2a
 * re-gate, `stripPathParams`), and drops ONE trailing slash from the
 * (already-processed) path (except the bare root, which stays `/`). Path
 * CASE is deliberately left untouched (gate finding 2a re-gate: `/GOLF`
 * and `/golf` are treated as genuinely DIFFERENT resources — most web
 * servers' paths are case-sensitive, and normalising case away would blur
 * a real distinction, not just a cosmetic one). Scheme is not part of the
 * key — every URL this tool ever fetches is already https-only (gate N6),
 * enforced well before this function runs. Throws on an unparseable URL —
 * a caller should already have validated the URL before reaching this
 * point.
 */
export function normalizeUrlForFirstCapture(url: string): string {
  const u = new URL(url);
  let host = u.hostname.toLowerCase();
  if (host.startsWith("www.")) host = host.slice(4);
  if (u.port) host += `:${u.port}`;
  let pathname = decodeUnreservedPercentEncoding(u.pathname);
  pathname = pathname.replace(/\/{2,}/g, "/");
  pathname = stripPathParams(pathname);
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

/** Gate finding 2c (re-gate): a plain naming convention, not an automatic
 * default — `defaultLedgerPath(outDir)` (`path.join(outDir,
 * RECORDED_LEDGER_FILENAME)`) was REMOVED because it let a caller who
 * forgot `--ledger` silently get a private, `outDir`-scoped ledger instead
 * of an error. A caller that genuinely wants one ledger per directory
 * still can, by writing `path.join(dir, RECORDED_LEDGER_FILENAME)`
 * explicitly at the call site — the difference is that it is now a
 * decision the caller visibly makes, never a fallback the tool makes for
 * them. */
export const RECORDED_LEDGER_FILENAME = "recorded-ledger.json";

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
