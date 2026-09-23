#!/usr/bin/env node
// K2 signup count CLI — decision 0001 Addendum D R3 / docs/p0/K2.md.
//
// Usage:
//   node scripts/k2-count.mjs --export <path-to-d1-json-export.json> [--day0 <ISO-8601>] [--k2-doc <path>]
//
// If --day0 is omitted, it's parsed from docs/p0/K2.md's "## Day 0"
// section. If --k2-doc is omitted, it defaults to the repo's
// docs/p0/K2.md relative to this script. Excluded addresses are ALWAYS
// parsed from that same file's "## Excluded addresses" section — there is
// no CLI override for those, so the pre-registered list is always the one
// actually used (decision 0001 Addendum D R3).
//
// Producing the export (see also README.md "How to run the K2 count"):
//   wrangler d1 execute golfraven-signups --remote --json \
//     --command "SELECT email_lc, confirmed_at FROM signups" > export.json
//
// Requires `pnpm --filter @golfraven/signup-worker build` to have run
// first (this script imports the built dist/k2-count.js — the pure
// counting function has no test-only escape hatch here, so the logic run
// by an owner is exactly the logic the test suite exercises).
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const repoRoot = join(packageRoot, "..", "..");

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--export") out.exportPath = argv[++i];
    else if (arg === "--day0") out.day0 = argv[++i];
    else if (arg === "--k2-doc") out.k2Doc = argv[++i];
    else if (arg === "--help" || arg === "-h") out.help = true;
  }
  return out;
}

function usage() {
  console.log(
    "Usage: node scripts/k2-count.mjs --export <export.json> [--day0 <ISO-8601>] [--k2-doc <path/to/K2.md>]",
  );
}

/** Extracts the text between a "## <heading>" line and the next "## " line (or EOF). */
function sectionBody(markdown, heading) {
  const lines = markdown.split("\n");
  const startIdx = lines.findIndex((l) => l.trim().toLowerCase() === `## ${heading}`.toLowerCase());
  if (startIdx === -1) return "";
  const rest = lines.slice(startIdx + 1);
  const endIdx = rest.findIndex((l) => l.startsWith("## "));
  return (endIdx === -1 ? rest : rest.slice(0, endIdx)).join("\n");
}

const ISO_DATE_RE = /\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/;
const EMAIL_RE = /[^\s,()<>]+@[^\s,()<>]+\.[^\s,()<>]+/g;

export function parseDay0FromK2Doc(markdown) {
  const body = sectionBody(markdown, "Day 0");
  const match = body.match(ISO_DATE_RE);
  return match ? match[0] : null;
}

export function parseExcludedAddressesFromK2Doc(markdown) {
  const body = sectionBody(markdown, "Excluded addresses");
  return [...body.matchAll(EMAIL_RE)].map((m) => m[0]);
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.exportPath) {
    usage();
    process.exitCode = args.help ? 0 : 1;
    return;
  }

  const k2DocPath = args.k2Doc ? resolve(args.k2Doc) : join(repoRoot, "docs", "p0", "K2.md");
  const k2Doc = await readFile(k2DocPath, "utf8").catch((err) => {
    throw new Error(`could not read K2 doc at ${k2DocPath}: ${err.message}`);
  });

  const day0 = args.day0 ?? parseDay0FromK2Doc(k2Doc);
  if (!day0) {
    console.error(
      `K2 day 0 is not set in ${k2DocPath} (the "## Day 0" section is still blank) and --day0 was not passed.\n` +
        "Refusing to run — decision 0001 Addendum D R3: day 0 must be logged before any count is read.",
    );
    process.exitCode = 1;
    return;
  }

  const excludedAddresses = parseExcludedAddressesFromK2Doc(k2Doc);

  const distJsPath = join(packageRoot, "dist", "k2-count.js");
  let k2CountModule;
  try {
    k2CountModule = await import(distJsPath);
  } catch (err) {
    console.error(
      `could not load ${distJsPath} — run "pnpm --filter @golfraven/signup-worker build" first.\n${err.message}`,
    );
    process.exitCode = 1;
    return;
  }

  const rawExport = JSON.parse(await readFile(resolve(args.exportPath), "utf8"));
  const rows = extractRows(rawExport);

  const result = k2CountModule.computeK2Counts({ rows, day0, excludedAddresses });

  console.log(`K2 signup count — day 0: ${result.day0}`);
  console.log(`  excluded addresses (from ${k2DocPath}): ${excludedAddresses.length}`);
  console.log(`  export rows: ${result.totalRows}  confirmed (raw): ${result.totalConfirmedRaw}`);
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
// parsing helpers above without wanting main()'s argv/process.exit side effects).
const isMainModule = process.argv[1] && import.meta.url === new URL(process.argv[1], "file://").href;
if (isMainModule) {
  main().catch((err) => {
    console.error(err.message ?? err);
    process.exitCode = 1;
  });
}
