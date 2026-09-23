#!/usr/bin/env node
// K2 signup count CLI — decision 0001 Addendum D R3 / docs/p0/K2.md.
//
// Usage:
//   node scripts/k2-count.mjs --export <path-to-d1-json-export.json>
//
// Day 0 and the excluded-addresses list are ALWAYS parsed from the REPO'S
// OWN docs/p0/K2.md — resolved relative to the repo root, with NO CLI
// override for the path, the day 0 value, or the exclusion list (gate
// finding F1/F7: a `--k2-doc <path>` override previously let a caller point
// at an arbitrary file and substitute a different Day 0 and exclusion list
// entirely, which is exactly the mistake R3 exists to make impossible).
//
// Day 0 MUST be a single bare `YYYY-MM-DD` date (Addendum D: "the UTC
// date"), interpreted as 00:00 UTC. The CLI refuses to run — with a clear,
// non-zero-exit message — if that field is blank, holds more than one
// date, holds a date-time instead of a bare date (ambiguous local time if
// it has no explicit Z/offset), or doesn't parse as a real calendar date.
//
// The excluded-addresses list is found by a heading that STARTS WITH
// "Excluded addresses" (case-insensitive) — matching the real heading's
// "(pre-Day-0 list)" suffix — and FAILS LOUDLY (non-zero exit) if no such
// heading exists at all, rather than silently returning an empty list.
// Each bullet entry must decode to EXACTLY ONE clean email address (an
// ambiguous or unparseable bullet is a hard refusal, not a silent drop —
// gate finding F8 residual), with markdown decoration (backticks, `_`/`*`
// emphasis wrapping, angle brackets, link syntax, a leading "mailto:",
// trailing punctuation) stripped and unicode local parts accepted, then
// lower-cased.
//
// F7/F8 residual (R3's "listed BEFORE Day 0" rule): every candidate
// exclusion is additionally checked against `git blame` on docs/p0/K2.md —
// it counts as excluded ONLY if its own line's commit author-time is
// strictly before Day 0 00:00 UTC. An address added on/after Day 0, or
// whose line is not yet committed, is listed in the output as "not
// excluded" rather than silently applied. Day 0's own line must be
// committed too, or the CLI refuses outright. The actual decision logic
// lives in the pure, git-free src/k2-blame.ts (unit-tested with fake blame
// data) — this script only shells out to git and parses its output.
//
// Producing the export (see also README.md "How to run the K2 count"):
//   wrangler d1 execute golfraven-signups --remote --json \
//     --command "SELECT email_lc, confirmed_at FROM signups" > export.json
//
// Requires `pnpm --filter @golfraven/signup-worker build` to have run
// first (this script imports the built dist/k2-count.js and dist/k2-blame.js —
// the pure logic has no test-only escape hatch here, so the logic run by
// an owner is exactly the logic the test suite exercises).
import { execFileSync } from "node:child_process";
import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const repoRoot = join(packageRoot, "..", "..");
const K2_DOC_RELATIVE_PATH = "docs/p0/K2.md";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--export") out.exportPath = argv[++i];
    else if (arg === "--help" || arg === "-h") out.help = true;
    else {
      throw new Error(
        `unrecognized argument: ${arg} (there is no --day0 or --k2-doc override — day 0 and the ` +
          `exclusion list come only from the repo's own docs/p0/K2.md; see --help)`,
      );
    }
  }
  return out;
}

function usage() {
  console.log("Usage: node scripts/k2-count.mjs --export <export.json>");
}

/** Extracts the heading text of a markdown "## ..." (1-6 #s) line, or null. */
function headingText(line) {
  const m = line.trim().match(/^#{1,6}\s*(.+?)\s*$/);
  return m ? m[1] : null;
}

/**
 * Finds the 0-indexed [start, end) range of BODY lines (never including
 * the heading itself) belonging to the first heading for which
 * `matchHeading` returns true, ending at the next heading or EOF. Returns
 * `null` when no matching heading exists at all, so callers can
 * distinguish "heading missing" from "heading present, body blank".
 */
function findSectionRange(lines, matchHeading) {
  const startIdx = lines.findIndex((l) => {
    const text = headingText(l);
    return text !== null && matchHeading(text);
  });
  if (startIdx === -1) return null;
  const bodyStart = startIdx + 1;
  let bodyEnd = lines.length;
  for (let i = bodyStart; i < lines.length; i += 1) {
    if (headingText(lines[i]) !== null) {
      bodyEnd = i;
      break;
    }
  }
  return { bodyStart, bodyEnd };
}

const DAY0_HEADING_RE = /^day 0\b/i;
const EXCLUDED_HEADING_RE = /^excluded addresses/i;

// Matches a bare date OR a date-time (with optional offset) — used to
// detect "how many date-like things are in this section" and "is the one
// we found a bare date or something with a time attached".
const DATE_TOKEN_RE = /\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?/g;
const BARE_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
// Non-global sibling of DATE_TOKEN_RE, used per-line to find WHICH line
// holds the (already-validated) date token, for git-blame purposes.
const DATE_TOKEN_LINE_RE = /\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?/;

/**
 * Gate findings F1/F7. Returns:
 *   - a bare "YYYY-MM-DD" string once day 0 is set and valid,
 *   - `null` if the "## Day 0" section exists but is still blank (the
 *     normal pre-launch state — the caller prints the standard "not set
 *     yet" refusal for this case),
 *   - throws for every other problem (missing heading, more than one
 *     date, a date-time instead of a bare date, an invalid calendar date)
 *     — these are configuration mistakes, not the normal blank state, and
 *     must not be swallowed into "not set yet".
 */
export function parseDay0FromK2Doc(markdown) {
  const lines = markdown.split("\n");
  const range = findSectionRange(lines, (text) => DAY0_HEADING_RE.test(text));
  if (range === null) {
    throw new Error('K2.md is missing its "## Day 0" heading — cannot determine day 0.');
  }
  const body = lines.slice(range.bodyStart, range.bodyEnd).join("\n");

  const tokens = [...body.matchAll(DATE_TOKEN_RE)].map((m) => m[0]);
  if (tokens.length === 0) return null; // still blank — not an error
  if (tokens.length > 1) {
    throw new Error(
      `K2 Day 0 section contains more than one date (${tokens.join(", ")}) — it must contain exactly one bare YYYY-MM-DD date.`,
    );
  }

  const token = tokens[0];
  if (!BARE_DATE_RE.test(token)) {
    const hasExplicitOffset = /(Z|[+-]\d{2}:?\d{2})$/.test(token);
    throw new Error(
      hasExplicitOffset
        ? `K2 Day 0 ("${token}") includes a time — it must be a bare YYYY-MM-DD date (Addendum D: "the UTC date"), interpreted as 00:00 UTC.`
        : `K2 Day 0 ("${token}") includes a time with no explicit UTC offset (ambiguous local time) — it must be a bare YYYY-MM-DD date.`,
    );
  }

  const [y, m, d] = token.split("-").map(Number);
  const check = new Date(Date.UTC(y, m - 1, d));
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== m - 1 || check.getUTCDate() !== d) {
    throw new Error(`K2 Day 0 ("${token}") is not a valid calendar date.`);
  }
  return token;
}

/**
 * F7/F8 residual (blame gating): the 1-indexed absolute line number within
 * `markdown` where Day 0's own date token lives. Only meaningful once
 * `parseDay0FromK2Doc` has returned a non-null, validated value — this
 * re-scans independently rather than trusting that ordering, so it throws
 * its own clear error if the heading is somehow missing when called.
 */
export function parseDay0LineFromK2Doc(markdown) {
  const lines = markdown.split("\n");
  const range = findSectionRange(lines, (text) => DAY0_HEADING_RE.test(text));
  if (range === null) {
    throw new Error('K2.md is missing its "## Day 0" heading — cannot determine day 0.');
  }
  for (let i = range.bodyStart; i < range.bodyEnd; i += 1) {
    if (DATE_TOKEN_LINE_RE.test(lines[i])) {
      return i + 1; // 1-indexed
    }
  }
  throw new Error('K2.md\'s "## Day 0" section has no date token on any line — cannot locate it for git blame.');
}

/**
 * Gate finding F8 residual (1): markdown italic/bold wraps a token in a
 * MATCHING pair of `_`/`*` at its very start and end. Unlike the other
 * decoration this can't just be excluded from the email character class,
 * because `_` is a legal EMAIL LOCAL-PART character — stripping every `_`
 * would corrupt a real address like `test_user@x.com`. Instead, strip only
 * a paired leading/trailing emphasis marker (same character, same run
 * length) from the trimmed line.
 */
function stripPairedEmphasis(line) {
  const trimmed = line.trim();
  const m = trimmed.match(/^([_*])\1*/);
  if (!m) return line;
  const marker = m[0];
  if (trimmed.length > marker.length * 2 && trimmed.endsWith(marker)) {
    return trimmed.slice(marker.length, trimmed.length - marker.length);
  }
  return line;
}

/** Strips a leading markdown bullet marker ("- ", "* ", "+ ", "1. "), if present. */
function stripBulletPrefix(line) {
  const trimmed = line.trimStart();
  const m = trimmed.match(/^(?:[-*+]|\d+\.)\s+/);
  return m ? trimmed.slice(m[0].length) : line;
}

function isBulletLine(line) {
  return /^\s*(?:[-*+]|\d+\.)\s+/.test(line);
}

/**
 * Gate finding F8: strips markdown decoration around an email address —
 * backticks, angle brackets, link-syntax brackets/parens, and a leading
 * "mailto:" — by replacing (not deleting) them with a space, so two
 * decorated addresses on one line (e.g. a `[text](mailto:url)` link)
 * never get concatenated into one bad token.
 */
function stripMarkdownDecoration(text) {
  return text.replace(/`+/g, " ").replace(/mailto:/gi, " ").replace(/[<>[\]()]/g, " ");
}

// Deliberately tighter than validate.ts's pragmatic signup-time regex: this
// one must reject trailing markdown punctuation like a bullet's trailing
// period ("a@b.com.") without being told to — and it does, because the
// domain/TLD groups only match letters/digits/dot/hyphen, so a trailing
// "." (not followed by 2+ letters) is simply left out of the match.
//
// Gate finding F8 residual: the local part accepts unicode letters/digits
// (`\p{L}`/`\p{N}`) in addition to the usual ASCII set, so e.g. "ünï13"
// parses as one token instead of the unicode prefix being dropped and only
// the trailing ASCII digits ("13") matching.
const EMAIL_TOKEN_RE = /[\p{L}\p{N}._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gu;

/**
 * One line's worth of address extraction: strips the bullet prefix, paired
 * emphasis, and markdown decoration, then extracts distinct lower-cased
 * email addresses. Gate finding F8 residual (3): if the line IS a bullet
 * list item and its cleaned content does not resolve to EXACTLY ONE
 * distinct address, this throws instead of silently dropping it (an
 * unparseable bullet like "matt at golfraven dot com" or "test10@localhost"
 * used to vanish with no trace but the total count).
 */
function extractAddressesFromLine(rawLine) {
  const wasBullet = isBulletLine(rawLine);
  const withoutBullet = stripBulletPrefix(rawLine);
  const withoutEmphasis = stripPairedEmphasis(withoutBullet);
  const cleaned = stripMarkdownDecoration(withoutEmphasis);
  const matches = [...new Set([...cleaned.matchAll(EMAIL_TOKEN_RE)].map((m) => m[0].toLowerCase()))];

  if (wasBullet && withoutBullet.trim() !== "" && matches.length !== 1) {
    throw new Error(
      `K2 Excluded-addresses bullet does not contain exactly one parseable email address: "${rawLine.trim()}"`,
    );
  }
  return matches;
}

/**
 * Gate finding F1: the heading is matched by PREFIX ("starts with
 * 'excluded addresses'", case-insensitive) so it finds the real K2.md
 * heading "Excluded addresses (pre-Day-0 list)", not just an exact
 * "Excluded addresses" — and throws (never silently returns `[]`) if no
 * such heading exists in the document at all.
 */
export function parseExcludedAddressesFromK2Doc(markdown) {
  return parseExcludedAddressEntriesFromK2Doc(markdown).map((e) => e.address);
}

/**
 * Same parsing as parseExcludedAddressesFromK2Doc, but also returns each
 * FIRST-occurrence address's 1-indexed absolute line number — needed for
 * the git-blame timing check (F7/F8 residual). Order matches first
 * appearance in the document, same as the flat-array form.
 */
export function parseExcludedAddressEntriesFromK2Doc(markdown) {
  const lines = markdown.split("\n");
  const range = findSectionRange(lines, (text) => EXCLUDED_HEADING_RE.test(text));
  if (range === null) {
    throw new Error(
      'K2.md is missing an "Excluded addresses" heading (expected one starting with "Excluded ' +
        'addresses", case-insensitive) — refusing to silently treat the exclusion list as empty.',
    );
  }

  const seen = new Set();
  const entries = [];
  for (let i = range.bodyStart; i < range.bodyEnd; i += 1) {
    const addresses = extractAddressesFromLine(lines[i]);
    for (const address of addresses) {
      if (seen.has(address)) continue;
      seen.add(address);
      entries.push({ address, line: i + 1 }); // 1-indexed
    }
  }
  return entries;
}

/**
 * Accepts either a plain array of rows, OR the array `wrangler d1 execute
 * --json` actually prints (`[{ results: [...], success: true, meta: {...} }]`).
 */
export function extractRows(parsed) {
  if (Array.isArray(parsed) && parsed.length > 0 && parsed[0] && Array.isArray(parsed[0].results)) {
    return parsed[0].results;
  }
  if (Array.isArray(parsed)) return parsed;
  throw new Error("export JSON is neither a row array nor a `wrangler d1 execute --json` result array");
}

/**
 * Parses `git blame --porcelain`'s output into a `line -> {authorTimeIso}`
 * map covering every line of the file. An uncommitted (working-tree-only)
 * line reports the all-zero SHA and is mapped to `authorTimeIso: null`
 * regardless of its (bogus/current-time) `author-time` field — matching
 * src/k2-blame.ts's `BlameLine` shape.
 */
export function parseGitBlamePorcelain(output) {
  const lines = output.split("\n");
  const shaAuthorTimeUnix = new Map();
  const finalLineSha = new Map();
  const headerRe = /^([0-9a-f]{40}) (\d+) (\d+)(?: \d+)?$/;

  let i = 0;
  while (i < lines.length) {
    const header = headerRe.exec(lines[i]);
    if (!header) {
      i += 1;
      continue;
    }
    const sha = header[1];
    const finalLineNo = Number(header[3]);
    i += 1;
    while (i < lines.length && !lines[i].startsWith("\t")) {
      const authorTimeMatch = /^author-time (\d+)$/.exec(lines[i]);
      if (authorTimeMatch) shaAuthorTimeUnix.set(sha, Number(authorTimeMatch[1]));
      i += 1;
    }
    if (i < lines.length) i += 1; // consume the tab-prefixed content line
    finalLineSha.set(finalLineNo, sha);
  }

  const blameByLine = new Map();
  for (const [lineNo, sha] of finalLineSha) {
    const isUncommitted = /^0+$/.test(sha);
    const authorTimeUnix = shaAuthorTimeUnix.get(sha);
    const authorTimeIso =
      !isUncommitted && typeof authorTimeUnix === "number"
        ? new Date(authorTimeUnix * 1000).toISOString()
        : null;
    blameByLine.set(lineNo, { authorTimeIso });
  }
  return blameByLine;
}

/** Runs `git blame --porcelain` on K2.md (relative to the repo root) and parses it. */
function getK2DocBlame() {
  let output;
  try {
    output = execFileSync("git", ["blame", "--porcelain", "--", K2_DOC_RELATIVE_PATH], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (err) {
    throw new Error(`could not run "git blame" on ${K2_DOC_RELATIVE_PATH}: ${err.message}`);
  }
  return parseGitBlamePorcelain(output);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.exportPath) {
    usage();
    process.exitCode = args.help ? 0 : 1;
    return;
  }

  const k2DocPath = join(repoRoot, K2_DOC_RELATIVE_PATH);
  const k2Doc = await readFile(k2DocPath, "utf8").catch((err) => {
    throw new Error(`could not read K2 doc at ${k2DocPath}: ${err.message}`);
  });

  const day0 = parseDay0FromK2Doc(k2Doc);
  if (!day0) {
    console.error(
      `K2 day 0 is not set in ${k2DocPath} (the "## Day 0" section is still blank).\n` +
        "Refusing to run — decision 0001 Addendum D R3: day 0 must be logged before any count is read.",
    );
    process.exitCode = 1;
    return;
  }

  const day0Line = parseDay0LineFromK2Doc(k2Doc);
  const excludedEntries = parseExcludedAddressEntriesFromK2Doc(k2Doc);
  const blameByLine = getK2DocBlame();

  const distJsPath = join(packageRoot, "dist", "k2-count.js");
  const blameJsPath = join(packageRoot, "dist", "k2-blame.js");
  let k2CountModule;
  let k2BlameModule;
  try {
    [k2CountModule, k2BlameModule] = await Promise.all([import(distJsPath), import(blameJsPath)]);
  } catch (err) {
    console.error(
      `could not load ${distJsPath} / ${blameJsPath} — run "pnpm --filter @golfraven/signup-worker build" first.\n${err.message}`,
    );
    process.exitCode = 1;
    return;
  }

  const exclusionResult = k2BlameModule.resolveK2Exclusions({
    day0,
    day0Line,
    entries: excludedEntries,
    blameByLine,
  });
  if (!exclusionResult.ok) {
    console.error(exclusionResult.error);
    process.exitCode = 1;
    return;
  }
  const excludedAddresses = exclusionResult.excluded;

  const rawExport = JSON.parse(await readFile(resolve(args.exportPath), "utf8"));
  const rows = extractRows(rawExport);

  const result = k2CountModule.computeK2Counts({ rows, day0, excludedAddresses });

  console.log(`K2 signup count — day 0: ${result.day0}`);
  console.log(`  excluded addresses (${excludedAddresses.length}): ${excludedAddresses.length > 0 ? excludedAddresses.join(", ") : "(none)"}`);
  if (exclusionResult.notExcluded.length > 0) {
    for (const entry of exclusionResult.notExcluded) {
      console.log(`    ${entry.address} (K2.md:${entry.line}) — ${entry.note}`);
    }
  }
  console.log(`  export rows: ${result.totalRows}  confirmed (raw): ${result.totalConfirmedRaw}`);
  if (result.malformedConfirmedAtCount > 0) {
    console.log(`  WARNING: rows with an unparsable confirmed_at, skipped: ${result.malformedConfirmedAtCount}`);
  }
  console.log(`  excluded rows matched: ${result.excludedMatchCount}`);
  console.log(`  distinct confirmed (post-exclusion): ${result.distinctConfirmed}`);
  console.log("");
  console.log(
    `  Advisory (< ${result.advisoryCutoff}, day0+14d): ${result.advisoryCount} / ${k2CountModule.ADVISORY_THRESHOLD} — ${
      result.advisoryPass ? "PASS" : "FAIL"
    }`,
  );
  console.log(
    `  Gate     (< ${result.gateCutoff}, day0+42d): ${result.gateCount} / ${k2CountModule.GATE_THRESHOLD} — ${
      result.gatePass ? "PASS" : "FAIL"
    }`,
  );
  console.log("");
  console.log(JSON.stringify(result, null, 2));
}

// Only auto-run when executed directly (`node scripts/k2-count.mjs ...`),
// not when imported by tests (test/k2-count-cli.test.ts imports the
// parsing helpers above without wanting main()'s argv/process.exit side
// effects). Gate finding N7: both sides are resolved to their REAL path
// (`fs.realpath`) before comparing — `import.meta.url` is already the
// realpath, but `process.argv[1]` is not, so running the CLI through a
// symlinked checkout path used to make this comparison fail silently (the
// script printed nothing and exited 0 — a refusal that exits 0 can pass a
// wrapper script's "did it run" check).
async function isMainModule() {
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
  main().catch((err) => {
    console.error(err.message ?? err);
    process.exitCode = 1;
  });
}
