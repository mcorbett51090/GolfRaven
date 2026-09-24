#!/usr/bin/env node
/**
 * check-links.mjs — the weekly booking-link checker (build plan §10 P2
 * stage-2 scope item 3: "Add `scripts/check-links.mjs`, the weekly link
 * checker. It must never run in CI and has an explicit `--live` flag.
 * With no network, it exits and says so.").
 *
 * Lists every `booking[]` URL in the catalog (real `data/`, or the demo
 * fixture with `--demo` / `GOLFRAVEN_DEMO=1`, for exercising this script
 * without real content). By DEFAULT it is a dry run — it never makes a
 * network request, matching `discover-websites.mjs`/`discover-socials.mjs`'s
 * own SWC precedent of "SSRF-hardened fetch kept; never run in CI" (§5.1):
 * this script's *liveness check* half is exactly that kind of fetch, so it
 * is opt-in via `--live` and this file is never invoked from
 * `.github/workflows/ci.yml`.
 *
 * `--live` HEADs (falling back to a ranged GET on a 405/501) each URL with
 * a short timeout and reports 2xx/3xx as ok, anything else as a finding —
 * it never mutates anything and never follows a booking link's own
 * redirect chain past `fetch`'s default handling. A network-unreachable
 * environment (this repo's own sandboxed sessions, per AGENTS.md's
 * "Codex CLI ... sandbox_mode = workspace-write has network OFF") is
 * expected, not a bug: on the FIRST connection failure in `--live` mode,
 * this script stops attempting further requests, reports plainly that no
 * network is available, and exits 0 (a routine op tool with no network to
 * use is not a failure of the tool).
 *
 * Usage:
 *   node scripts/check-links.mjs                # dry run (default) — lists links, no network
 *   node scripts/check-links.mjs --demo          # dry run against the demo catalog
 *   node scripts/check-links.mjs --live          # actually check each link (needs network)
 *   node scripts/check-links.mjs --live --timeout-ms 5000
 */
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadCatalog, loadCatalogFromBundle, primaryTrailOf } from "@golfraven/catalog";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = join(HERE, "..");

function parseArgs(argv) {
  const args = { live: false, demo: false, timeoutMs: 8000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--live") args.live = true;
    else if (a === "--demo") args.demo = true;
    else if (a === "--timeout-ms") args.timeoutMs = Number(argv[++i]) || args.timeoutMs;
    else if (a === "--help" || a === "-h") {
      console.log(
        "Usage: check-links.mjs [--demo] [--live] [--timeout-ms <n>]\n" +
          "  (no flags)   dry run against real data/ — lists booking links, no network\n" +
          "  --demo       use apps/site's synthetic demo catalog instead of data/\n" +
          "  --live       actually request each link (never used in CI)\n",
      );
      process.exit(0);
    }
  }
  return args;
}

async function loadLinkCatalog(demo) {
  if (demo || process.env.GOLFRAVEN_DEMO === "1") {
    const { demoBundleForSite } = await import(
      join(REPO_ROOT, "apps/site/fixtures/demo-catalog/build-bundle.mjs")
    );
    return loadCatalogFromBundle(demoBundleForSite());
  }
  return loadCatalog({ dataDir: join(REPO_ROOT, "data") });
}

function collectLinks(catalog) {
  const links = [];
  for (const facility of catalog.facilities) {
    for (const entry of facility.booking) {
      const trail = primaryTrailOf(catalog, facility.id, new Map());
      links.push({
        facilitySlug: facility.slug,
        facilityName: facility.name ?? facility.slug,
        trail: trail?.name ?? null,
        provider: entry.provider,
        url: entry.url,
        checkedAt: entry.checkedAt,
      });
    }
  }
  return links;
}

async function checkOne(link, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let res = await fetch(link.url, { method: "HEAD", redirect: "follow", signal: controller.signal });
    if (res.status === 405 || res.status === 501) {
      // Some booking hosts reject HEAD outright — retry as a plain GET.
      res = await fetch(link.url, { method: "GET", redirect: "follow", signal: controller.signal });
    }
    return { ok: res.ok, status: res.status };
  } finally {
    clearTimeout(timer);
  }
}

/** Distinguishes "no network reachable at all" from an ordinary per-URL
 * failure (404, timeout on one flaky host, etc.) — only the FORMER stops
 * the run early and prints the "no network" message this script's own
 * contract promises ("With no network, it exits and says so."). A DNS/
 * connection-refused error on the very first request is the signal; a
 * later single-URL failure is just a finding to report. */
function looksLikeNoNetwork(err) {
  const code = err?.cause?.code ?? err?.code;
  return (
    code === "ENOTFOUND" ||
    code === "EAI_AGAIN" ||
    code === "ECONNREFUSED" ||
    code === "ENETUNREACH" ||
    /EGRESS_BLOCKED|network/i.test(String(err?.message ?? ""))
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const catalog = await loadLinkCatalog(args.demo);
  const links = collectLinks(catalog);

  console.log(`check-links: ${links.length} booking link(s) in the catalog.`);
  if (links.length === 0) {
    console.log("Nothing to check.");
    return;
  }

  if (!args.live) {
    console.log("(dry run — pass --live to actually request each link; never done in CI)\n");
    for (const l of links) {
      console.log(`  [${l.provider}] ${l.facilityName}${l.trail ? ` (${l.trail})` : ""} -> ${l.url}`);
    }
    return;
  }

  console.log(`--live: checking ${links.length} link(s), ${args.timeoutMs}ms timeout each...\n`);
  const findings = [];
  for (const [i, link] of links.entries()) {
    try {
      const result = await checkOne(link, args.timeoutMs);
      const mark = result.ok ? "ok  " : "FAIL";
      console.log(`  ${mark} [${result.status}] ${link.facilityName} -> ${link.url}`);
      if (!result.ok) findings.push({ ...link, ...result });
    } catch (err) {
      if (i === 0 && looksLikeNoNetwork(err)) {
        console.log(
          `check-links: no network reachable (${err?.cause?.code ?? err?.code ?? err?.message}) — ` +
            `exiting without checking the remaining ${links.length - 1} link(s). This is expected in a ` +
            `sandboxed/offline session; re-run with network access for a real weekly check.`,
        );
        process.exit(0);
      }
      console.log(`  FAIL [error] ${link.facilityName} -> ${link.url} :: ${err?.message ?? err}`);
      findings.push({ ...link, ok: false, status: null, error: String(err?.message ?? err) });
    }
  }

  console.log(`\ncheck-links: ${findings.length} finding(s) of ${links.length} link(s) checked.`);
  if (findings.length > 0) {
    for (const f of findings) {
      console.log(`  - ${f.facilityName} [${f.provider}] ${f.url} :: ${f.status ?? f.error}`);
    }
    // A non-zero exit only in --live mode with real findings — this is an
    // ops report, not a CI gate (this script "must never run in CI").
    process.exitCode = 1;
  }
}

await main();
