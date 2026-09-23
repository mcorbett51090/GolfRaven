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
// K2 exclusion dating (decision 0001 Addendum F, superseding the round-2
// per-line `git blame` rule, and gate findings F-S2/F-S3 superseding the
// round-3 `git log -S<address>` pickaxe — see src/k2-blame.ts's module doc
// for the full history):
//
// This script walks docs/p0/K2.md's FULL history, oldest to newest, via
// `git log --reverse -p --format=... -- docs/p0/K2.md` (argv only, no
// shell — every element is a separate execFileSync argv entry). At each
// revision it reads the file's full content (`git show <sha>:<path>`) and
// parses its "Excluded addresses" section with EXACTLY the same
// decoration-stripping / lower-casing extraction the count itself uses
// (never a raw `-S` substring search — gate finding F-S3: `-S` matched
// `ba@x.com` for a search on `a@x.com`, and was case-sensitive so
// `A@X.com` evaded a lower-cased exclusion). An address's first appearance
// is the EARLIEST revision whose parsed address set contains it that the
// immediately preceding revision's parsed set did not — so a later
// reformat (which leaves the parsed address unchanged) never re-dates it.
// The candidate set is every address ANY revision of the full history ever
// added, not just the addresses currently listed (gate finding F-S2:
// deleting an excluded address from K2.md after day 0 no longer silently
// un-excludes it). The address counts as excluded ONLY if its
// first-appearance COMMITTER time is strictly before Day 0 00:00 UTC. This
// script REFUSES OUTRIGHT (non-zero exit) in a shallow clone
// (`git rev-parse --is-shallow-repository`) — a shallow clone cannot hold
// the full history this needs, and would otherwise silently under- or
// over-exclude. The actual decision logic lives in the pure, git-free
// src/k2-blame.ts (unit-tested with fake first-appearance data) — this
// script only shells out to git and parses its output.
//
// Known limit (decision 0001 Addendum F, stated verbatim): git timestamps
// are set by whoever makes the commit, so this is not tamper-proof by
// itself — the protection is that exclusions are pushed to GitHub before
// day 0, which leaves a server-side record Matt can check independently.
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
const DATE_TOKEN_RE =
  /\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?/g;
const BARE_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

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
    throw new Error(
      'K2.md is missing its "## Day 0" heading — cannot determine day 0.',
    );
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
  if (
    check.getUTCFullYear() !== y ||
    check.getUTCMonth() !== m - 1 ||
    check.getUTCDate() !== d
  ) {
    throw new Error(`K2 Day 0 ("${token}") is not a valid calendar date.`);
  }
  return token;
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
  return text
    .replace(/`+/g, " ")
    .replace(/mailto:/gi, " ")
    .replace(/[<>[\]()]/g, " ");
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
 * Gate finding A-8 (F8 residual): `stripPairedEmphasis` above only strips
 * emphasis that wraps the WHOLE trimmed line. `- _a2@x.com_ (owner)` does
 * NOT end with the marker (it ends with `)`), so that whole-line strip
 * leaves the leading `_` in place — and since `_` is a legal email
 * local-part character, `EMAIL_TOKEN_RE` then happily swallows it, matching
 * `_a2@x.com` instead of the real address `a2@x.com`. This strips a paired
 * `_`/`*` wrapped TIGHTLY around an email-shaped token specifically
 * (`_x@y.com_`, `*x@y.com*`), wherever it sits on the line, leaving a bare
 * underscore that is NOT part of such a pair (a genuine local-part
 * character) untouched.
 */
function stripPairedEmphasisAroundTokens(text) {
  return text.replace(
    /([_*])([\p{L}\p{N}._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\1/gu,
    (_m, _marker, token) => token,
  );
}

/**
 * One line's worth of address extraction, WITHOUT the "exactly one address"
 * rule: strips the bullet prefix, paired emphasis (both whole-line and
 * per-token — gate finding A-8), and markdown decoration, then returns every
 * distinct lower-cased email address found on the line (zero, one, or more).
 * Also returns `wasBullet`/`withoutBullet` so a caller can apply its own
 * exactly-one policy on top (see `extractAddressesFromLine`, the strict
 * HEAD-only wrapper, and `parseExclusionSetLenientPerLine`, the lenient
 * per-line historical wrapper — gate finding G-S1).
 */
function extractAddressesFromLineLenient(rawLine) {
  const wasBullet = isBulletLine(rawLine);
  const withoutBullet = stripBulletPrefix(rawLine);
  const withoutEmphasis = stripPairedEmphasis(withoutBullet);
  const cleaned = stripPairedEmphasisAroundTokens(
    stripMarkdownDecoration(withoutEmphasis),
  );
  const matches = [
    ...new Set(
      [...cleaned.matchAll(EMAIL_TOKEN_RE)].map((m) => m[0].toLowerCase()),
    ),
  ];
  return { wasBullet, withoutBullet, matches };
}

/**
 * Gate finding F8 residual (3): if the line IS a bullet list item and its
 * cleaned content does not resolve to EXACTLY ONE distinct address, this
 * throws instead of silently dropping it (an unparseable bullet like "matt
 * at golfraven dot com" or "test10@localhost" used to vanish with no trace
 * but the total count). This strict, throw-on-ambiguity behavior is used
 * for the CURRENT (HEAD) K2.md only (`parseExcludedAddressEntriesFromK2Doc`,
 * called directly by `main()`). Gate finding G-S1: a HISTORICAL revision
 * uses the lenient `extractAddressesFromLineLenient` above instead, via
 * `parseExclusionSetLenientPerLine`, so a malformed bullet somewhere in the
 * repo's past skips only that one line rather than refusing to date the
 * whole revision.
 */
function extractAddressesFromLine(rawLine) {
  const { wasBullet, withoutBullet, matches } =
    extractAddressesFromLineLenient(rawLine);
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
  const range = findSectionRange(lines, (text) =>
    EXCLUDED_HEADING_RE.test(text),
  );
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
  if (
    Array.isArray(parsed) &&
    parsed.length > 0 &&
    parsed[0] &&
    Array.isArray(parsed[0].results)
  ) {
    return parsed[0].results;
  }
  if (Array.isArray(parsed)) return parsed;
  throw new Error(
    "export JSON is neither a row array nor a `wrangler d1 execute --json` result array",
  );
}

/**
 * Decision 0001 Addendum F / gate findings A-5, A-6: `git rev-parse
 * --is-shallow-repository` prints "true"/"false". A shallow clone cannot
 * hold the full history `git log -S` needs to find an address's TRUE first
 * appearance — a shallow boundary commit can make a line look "recently
 * added" when it is not — so the CLI refuses outright rather than risk
 * silently mis-dating every exclusion.
 */
export function isShallowRepository() {
  let output;
  try {
    output = execFileSync("git", ["rev-parse", "--is-shallow-repository"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
  } catch (err) {
    throw new Error(
      `could not run "git rev-parse --is-shallow-repository": ${err.message}`,
    );
  }
  return output.trim() === "true";
}

// A control character that cannot appear in `git log`'s own output (commit
// messages, diff text) — used as an unambiguous per-revision delimiter so
// the header line (sha + committer time) can be split out even though `-p`
// also emits each revision's full diff body, which this parses past (see
// getK2DocRevisions's doc comment for why `-p` is used at all).
const REVISION_DELIMITER = "\x01";

/**
 * Gate findings F-S2/F-S3: walks docs/p0/K2.md's FULL history via `git log
 * --reverse -p --format=... -- docs/p0/K2.md` (argv only — every element
 * below is a separate execFileSync argv entry, never shell-interpolated)
 * and returns `{sha, committerTimeIso}` for every revision that touched
 * the file, oldest first. `-p` is passed (rather than a plain `git log`)
 * so the per-revision diff is available for anyone auditing this output by
 * eye; this function itself only reads the `--format` header line ahead of
 * each diff and discards the diff body — the actual first-appearance dating
 * below reads each revision's FULL FILE content (`git show <sha>:<path>`),
 * not the diff, so a content reformat can never look like an "add".
 */
function getK2DocRevisions() {
  let output;
  try {
    output = execFileSync(
      "git",
      [
        "log",
        "--reverse",
        "-p",
        `--format=${REVISION_DELIMITER}%H%x09%cI`,
        "--",
        K2_DOC_RELATIVE_PATH,
      ],
      { cwd: repoRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
    );
  } catch (err) {
    throw new Error(
      `could not run "git log -p" over ${K2_DOC_RELATIVE_PATH}'s full history: ${err.message}`,
    );
  }
  return output
    .split(REVISION_DELIMITER)
    .map((chunk) => chunk.split("\n", 1)[0])
    .filter((header) => header && header.trim() !== "")
    .map((header) => {
      const tabIdx = header.indexOf("\t");
      return {
        sha: header.slice(0, tabIdx),
        committerTimeIso: header.slice(tabIdx + 1).trim(),
      };
    });
}

/** The file's content at one revision, or `null` if it did not exist there
 * (deleted, or the commit predates the file's creation). */
function getFileContentAtRevision(sha) {
  try {
    return execFileSync("git", ["show", `${sha}:${K2_DOC_RELATIVE_PATH}`], {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}

/**
 * Gate finding G-S1: parses a historical revision's "Excluded addresses"
 * section leniently PER LINE, not per document. The strict HEAD parser
 * (`extractAddressesFromLine`, via `parseExcludedAddressEntriesFromK2Doc`)
 * refuses to run on a bullet that doesn't hold exactly one address — that
 * refusal is correct and stays in force for the CURRENT K2.md (main()
 * calls the strict parser directly for `excludedEntries`). But applying
 * that same all-or-nothing throw to a HISTORICAL revision is wrong: the
 * CLI only ever runs after day 0, so fixing a malformed pre-day-0 bullet is
 * necessarily a post-day-0 commit, and the previous behavior
 * (`parseExclusionSetLenient`, deleted) caught the whole-document throw and
 * returned an EMPTY set for that entire revision — silently re-dating every
 * OTHER, well-formed address in that same bullet section to the later,
 * fixed revision, un-excluding addresses that were genuinely listed before
 * day 0.
 *
 * This finds the same "Excluded addresses" section (a missing heading —
 * e.g. a revision that predates the heading entirely — still yields an
 * empty set, matching every other caller's expectation for pre-heading
 * revisions) and extracts addresses line by line. Per line, this collects
 * EVERY email token found — deliberately WITHOUT
 * the strict parser's "exactly one address" rule, using the same
 * stripping/lower-casing (`extractAddressesFromLineLenient`). A bullet that
 * holds more than one address (e.g. `- b@x.com, c@x.com (owner aliases)`)
 * has ALL of its addresses collected and dated to that revision, not zero
 * of them — dropping an over-full bullet's addresses entirely would be the
 * same bug in miniature (re-dating them to whichever later revision
 * eventually separates them onto their own lines). A line with NO email
 * token at all (prose, a blank line) contributes nothing, silently — there
 * is nothing there to warn about. A warning is recorded only for a line
 * that a bullet-shaped, non-blank line failed the strict "exactly one"
 * check (i.e. the one case that WOULD have thrown under the strict HEAD
 * parser), so a reader knows some address's first-appearance date came
 * from a line the strict parser would have refused.
 *
 * Returns `{ addresses: Set<string>, warnings: string[] }`.
 */
function parseExclusionSetLenientPerLine(markdown) {
  const addresses = new Set();
  const warnings = [];
  const lines = markdown.split("\n");
  const range = findSectionRange(lines, (text) =>
    EXCLUDED_HEADING_RE.test(text),
  );
  if (range === null) return { addresses, warnings };
  for (let i = range.bodyStart; i < range.bodyEnd; i += 1) {
    const { wasBullet, withoutBullet, matches } =
      extractAddressesFromLineLenient(lines[i]);
    for (const address of matches) addresses.add(address);
    if (wasBullet && withoutBullet.trim() !== "" && matches.length !== 1) {
      warnings.push(
        `line ${i + 1}: bullet does not hold exactly one address (holds ${matches.length}) — ` +
          `all collected leniently for historical dating: "${lines[i].trim()}"`,
      );
    }
  }
  return { addresses, warnings };
}

/**
 * Gate findings F-S2/F-S3: builds `address -> {committerTimeIso}` for
 * EVERY address any revision of docs/p0/K2.md's full history ever added
 * to the "Excluded addresses" section — independent of whether it is
 * still listed today (F-S2) — by walking revisions oldest-to-newest and,
 * at each one, diffing its PARSED address set against the immediately
 * preceding revision's PARSED address set (never a raw-line diff): an
 * address counts as "added" at the first revision whose set contains it
 * that the prior revision's set did not. Because both sides of that
 * comparison are fully-parsed, exact, lower-cased addresses (F-S3), a pure
 * reformat that leaves the address itself unchanged is never seen as an
 * "add", and a later deletion never removes the address's already-recorded
 * first appearance (only ADDING it again after having been previously
 * absent could, and even then the earliest recorded date wins, since this
 * only ever sets a date the first time an address is seen at all).
 */
function getFirstAppearanceByAddress() {
  const revisions = getK2DocRevisions();
  const firstSeen = new Map();
  const historyWarnings = [];
  let previousSet = new Set();
  for (const { sha, committerTimeIso } of revisions) {
    const content = getFileContentAtRevision(sha);
    const { addresses: currentSet, warnings } =
      content === null
        ? { addresses: new Set(), warnings: [] }
        : parseExclusionSetLenientPerLine(content);
    for (const warning of warnings) {
      historyWarnings.push(`${sha.slice(0, 12)}: ${warning}`);
    }
    for (const address of currentSet) {
      if (!previousSet.has(address) && !firstSeen.has(address)) {
        firstSeen.set(address, { committerTimeIso });
      }
    }
    previousSet = currentSet;
  }
  return { firstSeen, historyWarnings };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.exportPath) {
    usage();
    process.exitCode = args.help ? 0 : 1;
    return;
  }

  // Decision 0001 Addendum F / gate findings A-5, A-6: refuse outright in a
  // shallow clone, before anything else — a shallow checkout cannot be
  // trusted for ANY of the git-history-dependent exclusion dating below.
  if (isShallowRepository()) {
    console.error(
      "This is a shallow git clone (git rev-parse --is-shallow-repository = true) — the K2 exclusion " +
        "dating rule (decision 0001 Addendum F) needs docs/p0/K2.md's FULL history to find each excluded " +
        "address's true first appearance. Refusing to run. Un-shallow the clone (e.g. `git fetch " +
        "--unshallow`) and try again.",
    );
    process.exitCode = 1;
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

  const excludedEntries = parseExcludedAddressEntriesFromK2Doc(k2Doc);
  const { firstSeen: firstAppearanceByAddress, historyWarnings } =
    getFirstAppearanceByAddress();

  const distJsPath = join(packageRoot, "dist", "k2-count.js");
  const blameJsPath = join(packageRoot, "dist", "k2-blame.js");
  let k2CountModule;
  let k2BlameModule;
  try {
    [k2CountModule, k2BlameModule] = await Promise.all([
      import(distJsPath),
      import(blameJsPath),
    ]);
  } catch (err) {
    console.error(
      `could not load ${distJsPath} / ${blameJsPath} — run "pnpm --filter @golfraven/signup-worker build" first.\n${err.message}`,
    );
    process.exitCode = 1;
    return;
  }

  const exclusionResult = k2BlameModule.resolveK2Exclusions({
    day0,
    firstAppearanceByAddress,
    currentEntries: excludedEntries,
  });
  const excludedAddresses = exclusionResult.excluded;

  // Gate finding G-S1: a malformed bullet in some HISTORICAL revision skips
  // only that one line (its own addresses stay un-dated by that revision,
  // picked up at a later well-formed revision if any), never the whole
  // revision's exclusion set — but it's still worth surfacing, since it
  // means some address's first-appearance date came from a later revision
  // than the one that actually first listed it.
  if (historyWarnings.length > 0) {
    console.log(
      `  WARNING: malformed exclusion-list line(s) in K2.md's history, skipped per-line (not per-revision) ` +
        `(${historyWarnings.length}):`,
    );
    for (const warning of historyWarnings) {
      console.log(`    ${warning}`);
    }
  }

  const rawExport = JSON.parse(
    await readFile(resolve(args.exportPath), "utf8"),
  );
  const rows = extractRows(rawExport);

  const result = k2CountModule.computeK2Counts({
    rows,
    day0,
    excludedAddresses,
  });

  console.log(`K2 signup count — day 0: ${result.day0}`);
  console.log(
    `  excluded addresses (${excludedAddresses.length}): ${excludedAddresses.length > 0 ? excludedAddresses.join(", ") : "(none)"}`,
  );
  if (exclusionResult.notExcluded.length > 0) {
    for (const entry of exclusionResult.notExcluded) {
      console.log(`    ${entry.address} (K2.md:${entry.line}) — ${entry.note}`);
    }
  }
  // Gate finding F-S2: an address excluded by history but no longer
  // visible in today's K2.md — still applied, but a reader of the current
  // doc alone would otherwise never know it exists.
  if (exclusionResult.excludedButNoLongerListed.length > 0) {
    console.log(
      `  NOTE: excluded (by history) but no longer listed in K2.md (${exclusionResult.excludedButNoLongerListed.length}): ` +
        `${exclusionResult.excludedButNoLongerListed.join(", ")}`,
    );
  }
  // A-6 / runbook step 9: an address whose first appearance lands ON day 0
  // itself is correctly NOT excluded (Addendum F requires strictly BEFORE
  // day 0) — warn so a same-UTC-day exclusion commit is caught, not
  // silently absorbed into the count.
  if (exclusionResult.excludedOnDay0.length > 0) {
    console.log(
      `  WARNING: first appeared ON day 0 itself — correctly NOT excluded, but check the runbook's ` +
        `"commit before day 0" step (${exclusionResult.excludedOnDay0.length}): ${exclusionResult.excludedOnDay0.join(", ")}`,
    );
  }
  console.log(
    `  export rows: ${result.totalRows}  confirmed (raw): ${result.totalConfirmedRaw}`,
  );
  if (result.malformedConfirmedAtCount > 0) {
    console.log(
      `  WARNING: rows with an unparsable confirmed_at, skipped: ${result.malformedConfirmedAtCount}`,
    );
  }
  console.log(`  excluded rows matched: ${result.excludedMatchCount}`);
  console.log(
    `  distinct confirmed (post-exclusion): ${result.distinctConfirmed}`,
  );
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
