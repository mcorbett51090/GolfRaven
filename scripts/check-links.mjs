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
 * network request. `--live` is opt-in, and this file is never invoked
 * from `.github/workflows/ci.yml`.
 *
 * **Opus gate should-fix ("check-links") — the `--live` fetch is now
 * SSRF-hardened**, porting the exact technique southern-wine-country's
 * `discover-socials.mjs`/`discover-websites.mjs` already use for their
 * own outbound fetches (this repo's own §5.1 row: "SSRF-hardened fetch
 * kept; never run in CI"):
 *
 *   - **https only** — no plain `http:`, ever (a booking link redirecting
 *     to `http:` mid-chain is refused, not silently downgraded-and-
 *     followed).
 *   - **DNS resolved and checked on EVERY hop** — private/loopback/
 *     link-local/CGNAT/multicast/reserved ranges (including the
 *     169.254.169.254 cloud-metadata address) are refused before any
 *     connection is attempted, re-checked after every redirect (a DNS
 *     answer that was public on hop 1 is not trusted to still be public
 *     on hop 2).
 *   - **Redirects followed MANUALLY, at most 3 hops** — `fetch`'s own
 *     automatic `redirect: "follow"` never re-validates a redirect
 *     target before connecting to it; this script reads each
 *     `Location` header itself and re-runs the full scheme+DNS+allow-
 *     list check before following it.
 *   - **Only allow-listed hosts are ever fetched** — the SAME allow-list
 *     `booking-hosts.ts`/`verify-catalog` use (`config/booking-hosts.json`),
 *     plus (for a `course-native` entry) the facility's own `url` host —
 *     a link that shouldn't RENDER is also never REQUESTED.
 *   - **Exits non-zero when the network is unreachable** — the previous
 *     version of this script exited 0 on a network-unreachable
 *     environment (reasoning: a sandboxed session with no network isn't
 *     a tool failure). The gate review corrected this: a WEEKLY checker
 *     that silently reports "success" when it never actually reached the
 *     network would mask exactly the failure mode it exists to catch.
 *     `--live` now exits 1 on a network-unreachable first request,
 *     printing why — still never attempted in CI (this script is never
 *     invoked there at all, `--live` or not).
 *
 * Usage:
 *   node scripts/check-links.mjs                # dry run (default) — lists links, no network
 *   node scripts/check-links.mjs --demo          # dry run against the demo catalog
 *   node scripts/check-links.mjs --live          # actually check each link (needs network)
 *   node scripts/check-links.mjs --live --timeout-ms 5000
 */
import dns from "node:dns";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadCatalog, loadCatalogFromBundle, primaryTrailOf } from "@golfraven/catalog";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = join(HERE, "..");
const BOOKING_HOSTS_PATH = join(REPO_ROOT, "config", "booking-hosts.json");

const UA = "Mozilla/5.0 (compatible; GolfRaven-LinkChecker/1.0; +offline weekly ops bot)";
const MAX_REDIRECTS = 3;

// ---------------------------------------------------------------------
// SSRF hardening (ported from southern-wine-country's discover-socials.mjs)
// ---------------------------------------------------------------------

function ipv4ToInt(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}
function v4InCidr(ipInt, base, bits) {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  // BOTH sides need `>>> 0`: JS's `&` returns a SIGNED 32-bit int, so for
  // any network whose masked prefix has bit 31 set (172.16/12, 192.168/16,
  // 169.254/16 — including the 169.254.169.254 cloud-metadata address —
  // 224/4, 240/4, …) the left side came back negative while only the
  // right side was coerced unsigned, so the comparison silently failed
  // and every one of those ranges was NEVER flagged as private. Found by
  // this file's own unit tests (apps/site/test/check-links.test.ts) —
  // ported from southern-wine-country's discover-socials.mjs, which
  // carries the identical bug (out of scope to fix there).
  return ((ipInt & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0);
}
export function isPrivateV4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return true; // unparseable -> treat as unsafe
  return (
    v4InCidr(n, "0.0.0.0", 8) ||
    v4InCidr(n, "10.0.0.0", 8) ||
    v4InCidr(n, "100.64.0.0", 10) ||
    v4InCidr(n, "127.0.0.0", 8) ||
    v4InCidr(n, "169.254.0.0", 16) || // link-local incl. cloud metadata 169.254.169.254
    v4InCidr(n, "172.16.0.0", 12) ||
    v4InCidr(n, "192.0.0.0", 24) ||
    v4InCidr(n, "192.168.0.0", 16) ||
    v4InCidr(n, "198.18.0.0", 15) ||
    v4InCidr(n, "224.0.0.0", 4) ||
    v4InCidr(n, "240.0.0.0", 4)
  );
}
export function isPrivateIp(addr) {
  const ip = addr.toLowerCase();
  if (ip.startsWith("::ffff:")) return isPrivateV4(ip.slice(7));
  if (ip.includes(".") && !ip.includes(":")) return isPrivateV4(ip);
  if (ip === "::1" || ip === "::" || ip === "0:0:0:0:0:0:0:1") return true;
  if (ip.startsWith("fe80") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb")) return true;
  const hi = ip.slice(0, 2);
  if (hi === "fc" || hi === "fd") return true;
  return false;
}

async function assertPublicHost(hostname) {
  let addrs;
  try {
    addrs = await dns.promises.lookup(hostname, { all: true });
  } catch (e) {
    throw new Error(`dns-fail:${e.code || e.message}`);
  }
  if (!addrs.length) throw new Error("dns-empty");
  for (const a of addrs) {
    if (isPrivateIp(a.address)) throw new Error(`private-ip:${a.address}`);
  }
}

function validateHttpsUrl(raw) {
  const u = new URL(raw);
  if (u.protocol !== "https:") throw new Error(`bad-scheme:${u.protocol} (https only)`);
  return u;
}

/**
 * Hardened link check — https-only, DNS+private-IP-checked and
 * allow-list-checked on EVERY hop, manual redirects (<= MAX_REDIRECTS).
 * Never follows a redirect off the allow-list, whatever status it 30x'd
 * with.
 */
export async function hardenedCheck(startUrl, allowList, timeoutMs) {
  let current = startUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const u = validateHttpsUrl(current);
    if (!allowList.includes(u.host)) {
      throw Object.assign(new Error(`host-not-allow-listed:${u.host}`), { code: "NOT_ALLOW_LISTED" });
    }
    await assertPublicHost(u.hostname);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(u.href, {
        method: "HEAD",
        redirect: "manual",
        credentials: "omit",
        signal: controller.signal,
        headers: { "user-agent": UA },
      });
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 405 || res.status === 501) {
      // Some booking hosts reject HEAD outright — retry this SAME,
      // already-validated hop as a GET.
      const controller2 = new AbortController();
      const timer2 = setTimeout(() => controller2.abort(), timeoutMs);
      try {
        res = await fetch(u.href, {
          method: "GET",
          redirect: "manual",
          credentials: "omit",
          signal: controller2.signal,
          headers: { "user-agent": UA },
        });
      } finally {
        clearTimeout(timer2);
      }
    }

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      try {
        await res.body?.cancel();
      } catch {
        /* ignore */
      }
      if (!loc) return { ok: false, status: res.status, reason: "redirect-no-location" };
      if (hop === MAX_REDIRECTS) return { ok: false, status: res.status, reason: "too-many-redirects" };
      current = new URL(loc, u).href;
      continue;
    }
    return { ok: res.ok, status: res.status };
  }
  return { ok: false, status: null, reason: "too-many-redirects" };
}

// ---------------------------------------------------------------------
// Catalog / CLI
// ---------------------------------------------------------------------

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
          "  --live       actually request each link, SSRF-hardened (never done in CI)\n",
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
        facilityUrl: facility.url ?? null,
        trail: trail?.name ?? null,
        provider: entry.provider,
        url: entry.url,
        checkedAt: entry.checkedAt,
      });
    }
  }
  return links;
}

/** Same rule `booking-hosts.ts`'s `bookingEntryAllowed` enforces: a
 * `course-native` entry's own facility domain is allowed too, on top of
 * the committed allow-list — this script fetches nothing a rendered page
 * wouldn't also have linked to. */
function allowListFor(link, configuredHosts) {
  if (link.provider === "course-native" && link.facilityUrl) {
    try {
      return [...configuredHosts, new URL(link.facilityUrl).host];
    } catch {
      return configuredHosts;
    }
  }
  return configuredHosts;
}

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
  const configuredHosts = JSON.parse(await readFile(BOOKING_HOSTS_PATH, "utf8")).hosts ?? [];

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

  console.log(`--live: checking ${links.length} link(s), ${args.timeoutMs}ms timeout each, https-only, SSRF-hardened...\n`);
  const findings = [];
  for (const [i, link] of links.entries()) {
    const allowList = allowListFor(link, configuredHosts);
    try {
      const result = await hardenedCheck(link.url, allowList, args.timeoutMs);
      const mark = result.ok ? "ok  " : "FAIL";
      console.log(`  ${mark} [${result.status ?? "?"}] ${link.facilityName} -> ${link.url}`);
      if (!result.ok) findings.push({ ...link, ...result });
    } catch (err) {
      if (i === 0 && looksLikeNoNetwork(err)) {
        console.error(
          `check-links: no network reachable (${err?.cause?.code ?? err?.code ?? err?.message}) — ` +
            `stopping without checking the remaining ${links.length - 1} link(s). A weekly checker that ` +
            `silently reported success here would be worse than an honest failure, so this exits non-zero.`,
        );
        process.exitCode = 1;
        return;
      }
      if (err?.code === "NOT_ALLOW_LISTED") {
        console.log(`  FAIL [not-allow-listed] ${link.facilityName} -> ${link.url} :: ${err.message}`);
      } else {
        console.log(`  FAIL [error] ${link.facilityName} -> ${link.url} :: ${err?.message ?? err}`);
      }
      findings.push({ ...link, ok: false, status: null, error: String(err?.message ?? err) });
    }
  }

  console.log(`\ncheck-links: ${findings.length} finding(s) of ${links.length} link(s) checked.`);
  if (findings.length > 0) {
    for (const f of findings) {
      console.log(`  - ${f.facilityName} [${f.provider}] ${f.url} :: ${f.status ?? f.error ?? f.reason}`);
    }
    // A non-zero exit only in --live mode with real findings — this is an
    // ops report, not a CI gate (this script "must never run in CI").
    process.exitCode = 1;
  }
}

await main();
