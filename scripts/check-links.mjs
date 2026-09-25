#!/usr/bin/env node
/**
 * check-links.mjs — the weekly booking-link checker (build plan §10 P2
 * stage-2 scope item 3: "Add `scripts/check-links.mjs`, the weekly link
 * checker. It must never run in CI and has an explicit `--live` flag.
 * With no network, it exits and says so." — and P2 stage-3 scope: "Add a
 * scheduled GitHub Actions workflow ... that runs it. It is report-only:
 * no deploy, no secrets, no issue creation.").
 *
 * Lists every `booking[]` URL in the catalog (real `data/`, or the demo
 * fixture with `--demo` / `GOLFRAVEN_DEMO=1`, for exercising this script
 * without real content). By DEFAULT it is a dry run — it never makes a
 * network request. `--live` is opt-in, and this file is still NEVER
 * invoked from the PR-gating `.github/workflows/ci.yml` — it's a report,
 * not a merge gate, and a flaky third-party booking host must never block
 * an unrelated PR. It IS invoked, with `--live`, by the scheduled
 * `.github/workflows/check-links.yml` (weekly cron + `workflow_dispatch`)
 * added alongside it — that workflow reads this script's own exit code
 * and uploads the report file it writes (see `--report` below); it never
 * deploys anything, never touches a secret, and never opens an issue.
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
 *   - **Exits non-zero when the network is unreachable — but only once a
 *     CONTROL HOST confirms it** (re-gate R1, blocking correction): a
 *     first-link failure that classifies as `"no-network"` no longer
 *     aborts the run on its own — `www.golfnow.com` (the catalog's own
 *     first allow-listed host) is probed through the identical
 *     DNS+fetch path first (`probeControlHost()`), and the run only
 *     stops if THAT also fails. A single genuinely-dead domain
 *     (`ENOTFOUND`/NXDOMAIN — now classified `"dead"`, never
 *     `"no-network"`, see `classifyError()`) was previously
 *     indistinguishable from "this sandbox has no network at all", which
 *     silently skipped checking every OTHER link in the catalog over one
 *     unrelated domain's own DNS failure. `--live` still exits 1 when the
 *     control confirms the network really is down, printing why — never
 *     attempted in CI (this script is never invoked there at all,
 *     `--live` or not).
 *
 * Usage:
 *   node scripts/check-links.mjs                # dry run (default) — lists links, no network
 *   node scripts/check-links.mjs --demo          # dry run against the demo catalog
 *   node scripts/check-links.mjs --live          # actually check each link (needs network)
 *   node scripts/check-links.mjs --live --timeout-ms 5000
 *   node scripts/check-links.mjs --live --report .check-links-report.json
 *
 * `--report <path>` (--live only): writes a JSON report of every non-"ok"
 * finding to `<path>` (default `.check-links-report.json` at the repo
 * root — gitignored, same convention as `apps/site/.lighthouse-*.json`).
 * Each finding carries a `classification` of `"dead"`,
 * `"not-allow-listed"`, `"redirect-off-host"`, `"no-network"` or
 * `"error"` — see the classification section below for exactly what
 * produces each. A dry run never writes a report (there is nothing to
 * report — no request was ever made).
 */
import dns from "node:dns";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Agent, fetch as undiciFetch } from "undici";
import { loadCatalog, loadCatalogFromBundle, primaryTrailOf } from "@golfraven/catalog";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = join(HERE, "..");
const BOOKING_HOSTS_PATH = join(REPO_ROOT, "config", "booking-hosts.json");
const DEFAULT_REPORT_PATH = join(REPO_ROOT, ".check-links-report.json");

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
/**
 * Expands ANY textual IPv6 form (`::`-compressed, an embedded IPv4 tail
 * like `::ffff:1.2.3.4` or `64:ff9b::1.2.3.4`) into its 8 numeric 16-bit
 * groups. Returns `null` on anything unparseable (callers then fail
 * closed, same as `ipv4ToInt`'s `null` convention).
 */
export function expandIPv6(addr) {
  const lower = addr.toLowerCase().trim();
  const expandV4Tail = (parts) => {
    const last = parts[parts.length - 1];
    if (!last || !last.includes(".")) return parts;
    const v4 = last.split(".").map(Number);
    if (v4.length !== 4 || v4.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    return [...parts.slice(0, -1), hi, lo];
  };

  let headParts, tailParts;
  if (lower.includes("::")) {
    const sides = lower.split("::");
    if (sides.length !== 2) return null; // "::" may appear at most once
    headParts = sides[0] ? sides[0].split(":").filter(Boolean) : [];
    tailParts = sides[1] ? sides[1].split(":").filter(Boolean) : [];
  } else {
    headParts = lower.split(":").filter(Boolean);
    tailParts = [];
  }
  headParts = expandV4Tail(headParts);
  tailParts = expandV4Tail(tailParts);
  if (headParts === null || tailParts === null) return null;

  let groups;
  if (lower.includes("::")) {
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    groups = [...headParts, ...Array(missing).fill("0"), ...tailParts];
  } else {
    groups = headParts;
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => parseInt(g, 16));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  return nums;
}

/**
 * IPv6 private/reserved/transition-mechanism ranges. Each range whose
 * transport is really an embedded IPv4 address (NAT64 `64:ff9b::/96`,
 * 6to4 `2002::/16`, v4-mapped `::ffff:0:0/96`, v4-compatible `::/96`)
 * recurses into `isPrivateV4` on that embedded address — a NAT64/6to4/
 * v4-mapped/v4-compatible wrapper around a PUBLIC v4 address is not
 * itself private, only wrapping a PRIVATE one is.
 */
export function isPrivateIpv6(addr) {
  const g = expandIPv6(addr);
  if (g === null) return true; // unparseable -> treat as unsafe
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g;
  const embeddedV4 = () => `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;

  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 0) {
    return true; // ::  (unspecified)
  }
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1) {
    return true; // ::1 (loopback)
  }
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) {
    return isPrivateV4(embeddedV4()); // ::ffff:0:0/96 (v4-mapped)
  }
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return isPrivateV4(embeddedV4()); // ::0.0.0.0/96 (v4-compatible, deprecated)
  }
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return isPrivateV4(embeddedV4()); // 64:ff9b::/96 (NAT64)
  }
  if (g0 === 0x2002) {
    return isPrivateV4(`${g1 >> 8}.${g1 & 0xff}.${g2 >> 8}.${g2 & 0xff}`); // 2002::/16 (6to4)
  }
  // Nit (gate review): Teredo 2001::/32 (RFC 4380) is a tunneling
  // mechanism carrying an obfuscated (XOR'd) embedded client address —
  // decoding it accurately is unnecessary complexity for an SSRF gate.
  // Treated as non-public outright, same conservative "unsafe by default"
  // stance as an unparseable address.
  if (g0 === 0x2001 && g1 === 0x0000) return true; // Teredo 2001::/32
  if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 (multicast)
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 (link-local)
  if ((g0 & 0xffc0) === 0xfec0) return true; // fec0::/10 (site-local, deprecated)
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 (unique local)
  return false;
}

export function isPrivateIp(addr) {
  const ip = addr.toLowerCase();
  if (ip.includes(".") && !ip.includes(":")) return isPrivateV4(ip);
  return isPrivateIpv6(ip);
}

async function assertPublicHost(hostname) {
  let addrs;
  try {
    addrs = await dns.promises.lookup(hostname, { all: true });
  } catch (e) {
    // Should-fix (gate review S4a): keep `e.code` (ENOTFOUND/EAI_AGAIN/…)
    // ON the rethrown error, not just folded into its message text —
    // `looksLikeNoNetwork()`/`classifyError()` read `err.code` directly,
    // and `main()`'s first-request early-stop path depends on that
    // classification landing on "no-network" for a real DNS failure, not
    // the generic "error" bucket.
    throw Object.assign(new Error(`dns-fail:${e.code || e.message}`), { code: e.code });
  }
  if (!addrs.length) throw new Error("dns-empty");
  for (const a of addrs) {
    if (isPrivateIp(a.address)) throw new Error(`private-ip:${a.address}`);
  }
}

// ---------------------------------------------------------------------
// Should-fix (Opus gate, "check-links DNS pinning"): the pre-flight
// `assertPublicHost` above and the actual TCP connection are two SEPARATE
// DNS resolutions — a DNS answer that was public when checked can change
// (a rebind) by the time the socket actually connects. This `Agent`'s
// `connect.lookup` is the SAME function undici's connector calls to
// resolve the address it actually dials, so pinning it here closes that
// gap instead of merely narrowing it.
//
// **Must use undici's OWN `fetch` export, not Node's global `fetch`, with
// this `Agent`.** Confirmed this session: Node 22.22.2 bundles undici
// 6.24.1 internally for `globalThis.fetch`; passing a `dispatcher` built
// from the separately npm-installed `undici@8.11.2` package into the
// GLOBAL fetch throws `"invalid onRequestStart method"` (an internal
// interceptor-interface mismatch across major versions) — passing it to
// `undiciFetch` (the matching version) works correctly, verified against
// both a blocked-private-IP case (`https://localhost/`) and a real host.
// ---------------------------------------------------------------------
function pinnedLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return callback(err);
    const list = Array.isArray(addrs) ? addrs : [addrs];
    for (const a of list) {
      if (isPrivateIp(a.address)) {
        return callback(new Error(`private-ip:${a.address}`));
      }
    }
    if (options.all) callback(null, list);
    else callback(null, list[0].address, list[0].family);
  });
}
const pinnedAgent = new Agent({ connect: { lookup: pinnedLookup } });

function validateHttpsUrl(raw) {
  const u = new URL(raw);
  if (u.protocol !== "https:") throw new Error(`bad-scheme:${u.protocol} (https only)`);
  return u;
}

/**
 * The REAL network-calling fetch — undici's own `fetch`, pinned to the
 * DNS-rebind-hardened agent. See the doc comment above for why this must
 * be `undiciFetch` (not Node's global `fetch`) paired with `pinnedAgent`.
 */
async function realFetchImpl(url, init) {
  return undiciFetch(url, { ...init, dispatcher: pinnedAgent });
}

/**
 * Hardened link check — https-only, DNS+private-IP-checked and
 * allow-list-checked on EVERY hop, manual redirects (<= MAX_REDIRECTS).
 * Never follows a redirect off the allow-list, whatever status it 30x'd
 * with.
 *
 * **`opts.fetchImpl` / `opts.assertPublicHost` (should-fix, "check-links
 * classification logic tests"):** both default to the real, network-
 * calling implementations above, but a caller (this file's own unit
 * tests) can inject fakes — a `fetchImpl` that returns canned
 * Response-like objects for given URLs, and a no-op `assertPublicHost`
 * — to exercise the REAL redirect-following / allow-list / classification
 * decisions end-to-end against a scripted sequence of responses, with
 * NO real network or DNS call ever made. Production code (`main()` below)
 * never passes `opts`, so it always gets the real implementations.
 *
 * **`hop` is attached to a `NOT_ALLOW_LISTED` error** — `hop === 0` means
 * the link's OWN host was never on the allow-list to begin with;
 * `hop > 0` means a REDIRECT led off the allow-list. `classifyError()`
 * below is what turns that distinction into "not-allow-listed" vs.
 * "redirect-off-host" for the report.
 */
export async function hardenedCheck(startUrl, allowList, timeoutMs, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? realFetchImpl;
  const assertHost = opts.assertPublicHost ?? assertPublicHost;

  let current = startUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const u = validateHttpsUrl(current);
    if (!allowList.includes(u.host)) {
      throw Object.assign(new Error(`host-not-allow-listed:${u.host}`), {
        code: "NOT_ALLOW_LISTED",
        hop,
        host: u.host,
      });
    }
    await assertHost(u.hostname);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(u.href, {
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
        res = await fetchImpl(u.href, {
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
    // Nit (gate review): drain/cancel the response body before returning.
    // A HEAD response never carries one, but the HEAD->GET fallback above
    // (405/501) DOES fetch a real body we never read — leaving it open
    // holds the underlying connection instead of releasing it back to the
    // agent's pool. We only ever need status/headers here, never content.
    try {
      await res.body?.cancel();
    } catch {
      /* ignore */
    }
    return { ok: res.ok, status: res.status };
  }
  return { ok: false, status: null, reason: "too-many-redirects" };
}

// ---------------------------------------------------------------------
// Catalog / CLI
// ---------------------------------------------------------------------

function parseArgs(argv) {
  // `reportPath` defaults to DEFAULT_REPORT_PATH — a report is written on
  // every --live run unless explicitly turned off with --no-report.
  const args = { live: false, demo: false, timeoutMs: 8000, reportPath: DEFAULT_REPORT_PATH };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--live") args.live = true;
    else if (a === "--demo") args.demo = true;
    else if (a === "--timeout-ms") args.timeoutMs = Number(argv[++i]) || args.timeoutMs;
    else if (a === "--report") args.reportPath = argv[++i] || args.reportPath;
    else if (a === "--no-report") args.reportPath = null;
    else if (a === "--help" || a === "-h") {
      console.log(
        "Usage: check-links.mjs [--demo] [--live] [--timeout-ms <n>] [--report <path>] [--no-report]\n" +
          "  (no flags)     dry run against real data/ — lists booking links, no network\n" +
          "  --demo         use apps/site's synthetic demo catalog instead of data/\n" +
          "  --live         actually request each link, SSRF-hardened (never done in ci.yml)\n" +
          `  --report <p>   write findings to <p> as JSON (--live only; default ${DEFAULT_REPORT_PATH})\n` +
          "  --no-report    skip writing a report file even in --live mode\n",
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

/**
 * Re-gate correction (R1, blocking): `ENOTFOUND` is DELIBERATELY NOT here
 * any more. `ENOTFOUND` means DNS resolved (the resolver answered) and
 * said "no such name" — that's a genuinely DEAD domain, not proof the
 * network itself is unreachable (see `classifyError()`, which now maps
 * `ENOTFOUND` to `"dead"` before this function is ever consulted). Only
 * these four mean "the network path itself is broken", matching
 * `EAI_AGAIN` (resolver itself unreachable/timed out — NOT "no such
 * name"), `ENETUNREACH`, `ECONNREFUSED`, and this sandboxed environment's
 * own `EGRESS_BLOCKED` marker.
 */
function looksLikeNoNetwork(err) {
  const code = err?.cause?.code ?? err?.code;
  return (
    code === "EAI_AGAIN" ||
    code === "ECONNREFUSED" ||
    code === "ENETUNREACH" ||
    /EGRESS_BLOCKED/i.test(String(err?.message ?? ""))
  );
}

// ---------------------------------------------------------------------
// Classification (should-fix, "check-links classification logic tests" —
// this task's scope item 2: "Report dead links, redirects off-host and
// non-allow-listed hosts"). Two small, PURE functions — no network, no
// DNS, no catalog — so they're directly unit-testable against canned
// `hardenedCheck()` results/errors, and `checkLink()` below is what wires
// them to the real (or, in a test, an injected) `hardenedCheck()`.
//
// The five report categories, and what produces each:
//   - "ok"                a 2xx (after allowed redirects)
//   - "blocked"            the host answered with 401, 403 or 429 —
//                          INCONCLUSIVE, not proof the link is dead. A
//                          booking host commonly 403s/429s an
//                          unauthenticated HEAD/GET from an unfamiliar
//                          user-agent/IP (bot defense, rate limiting) even
//                          though the SAME link works fine in a browser —
//                          folding this into "dead" would false-positive
//                          on a healthy link every time that host has a
//                          bad day with this checker specifically.
//   - "dead"               hardenedCheck resolved but !ok, and the status
//                          is NOT one of the "blocked" codes above
//                          (other 4xx/5xx, too-many-redirects,
//                          redirect-no-location) — OR the DNS resolver
//                          positively answered "no such domain"
//                          (ENOTFOUND/NXDOMAIN, detail "nxdomain"; re-gate
//                          R1: this is proof THIS domain is dead, not
//                          that the network is unreachable).
//   - "not-allow-listed"   the link's OWN host was never on the allow-list
//                          (NOT_ALLOW_LISTED at hop 0)
//   - "redirect-off-host"  an ALLOWED starting host redirected somewhere
//                          NOT on the allow-list (NOT_ALLOW_LISTED at
//                          hop > 0) — the exact case a static `verify-
//                          catalog` publish-time gate can never see, since
//                          it never follows the link.
//   - "no-network"         the checker itself couldn't reach the network
//                          (see looksLikeNoNetwork) — never a false "ok".
//   - "error"              anything else (timeout, bad scheme, DNS
//                          failure on a single host, …).
// ---------------------------------------------------------------------

/** Status codes that mean "this specific request was refused", not "this
 * link is dead" — see the "blocked" category note above. */
const BLOCKED_STATUSES = new Set([401, 403, 429]);

/** Classifies a THROWN error from `hardenedCheck()` — never a resolved result. */
export function classifyError(err) {
  if (err?.code === "NOT_ALLOW_LISTED") {
    return err.hop === 0 ? "not-allow-listed" : "redirect-off-host";
  }
  // Re-gate correction (R1, blocking): a resolver that positively answers
  // "no such domain" (ENOTFOUND) is telling us THIS domain is dead — not
  // that the network is unreachable. Checked BEFORE looksLikeNoNetwork so
  // it's never shadowed by that function's own (now-narrower) rules.
  if (err?.code === "ENOTFOUND") return "dead";
  if (looksLikeNoNetwork(err)) return "no-network";
  return "error";
}

/**
 * The `detail` a report shows for a THROWN error — mostly the error's own
 * message, except `ENOTFOUND`, which reads as the plain, well-known term
 * "nxdomain" (re-gate R1) rather than the internal `dns-fail:ENOTFOUND`
 * wrapper text.
 */
function detailForError(err) {
  if (err?.code === "ENOTFOUND") return "nxdomain";
  return String(err?.message ?? err);
}

/** Classifies a RESOLVED `hardenedCheck()` result (`{ ok, status, reason? }`) — never a thrown error. */
export function classifyResult(result) {
  if (result.ok) return "ok";
  if (result.status !== null && BLOCKED_STATUSES.has(result.status)) return "blocked";
  return "dead";
}

/**
 * Runs `hardenedCheck()` for one link and returns a flat, JSON-report-
 * ready record: the link's own fields plus `classification`/`status`/
 * `detail`. `opts` passes straight through to `hardenedCheck()` — a test
 * injects `{ fetchImpl, assertPublicHost }` here; production code (below)
 * never does, so it always exercises the real network path.
 */
export async function checkLink(link, allowList, timeoutMs, opts = {}) {
  try {
    const result = await hardenedCheck(link.url, allowList, timeoutMs, opts);
    return {
      ...link,
      classification: classifyResult(result),
      status: result.status ?? null,
      detail: result.reason ?? null,
    };
  } catch (err) {
    return {
      ...link,
      classification: classifyError(err),
      status: null,
      detail: detailForError(err),
    };
  }
}

/**
 * Re-gate correction (R1, blocking): "Before aborting on a first-link
 * failure, probe one allow-listed control host ... through the same
 * injectable lookup/fetch. Conclude 'no network' only if that control
 * also fails."
 *
 * Probes `host` (a real, well-known, always-allow-listed host — the
 * catalog's own `configuredHosts[0]`, never a booking link's own,
 * possibly-genuinely-dead host) with the SAME `hardenedCheck()` used for
 * real links, so it exercises the identical DNS/fetch path (and accepts
 * the same injectable `opts.fetchImpl`/`opts.assertPublicHost` a test
 * provides — no real network in tests).
 *
 * Returns `true` when the network appears reachable (the control
 * succeeded, OR failed for a reason that ISN'T itself "no-network" —
 * e.g. the control host is momentarily down for an unrelated reason;
 * that's not this checker's network being unreachable). Returns `false`
 * — "the network really is unreachable" — only when `host` is missing
 * (nothing to probe, fail closed) or the control itself classifies as
 * `"no-network"`.
 */
export async function probeControlHost(host, timeoutMs, opts = {}) {
  if (!host) return false;
  try {
    await hardenedCheck(`https://${host}/`, [host], timeoutMs, opts);
    return true;
  } catch (err) {
    return classifyError(err) !== "no-network";
  }
}

/**
 * Checks every link in order, applying the SAME first-link no-network
 * abort logic `main()` always has — extracted into its own, fully
 * unit-testable function (injectable `opts.fetchImpl`/
 * `opts.assertPublicHost`, no real network/DNS/catalog needed) so the
 * abort-vs-continue decision itself has direct test coverage, not just
 * the classification it's built on.
 *
 * `onResult(record, index)` — optional — is called once per link, in
 * order, as each result comes in; `main()` uses it to print progress
 * live, tests simply omit it.
 *
 * Returns `{ results, networkUnreachable, controlHost }`. When
 * `networkUnreachable` is true, `results` holds only the first link's own
 * (already-recorded) finding — checking stopped there, exactly as before.
 * Otherwise every link was checked, INCLUDING one whose own classification
 * is still `"no-network"` (the control probe only decides whether to
 * ABORT the whole run, never rewrites that one link's own finding).
 *
 * @param {Array<Record<string, unknown>>} links
 * @param {string[]} configuredHosts
 * @param {number} timeoutMs
 * @param {{ fetchImpl?: Function, assertPublicHost?: Function }} [opts]
 * @param {(record: Record<string, unknown>, index: number) => void} [onResult]
 */
export async function runLinkChecks(links, configuredHosts, timeoutMs, opts = {}, onResult = () => {}) {
  const results = [];
  for (const [i, link] of links.entries()) {
    const allowList = allowListFor(link, configuredHosts);
    const record = await checkLink(link, allowList, timeoutMs, opts);
    results.push(record);
    onResult(record, i);

    if (record.classification === "no-network" && i === 0) {
      const controlHost = configuredHosts[0] ?? null;
      const networkOk = await probeControlHost(controlHost, timeoutMs, opts);
      if (!networkOk) {
        return { results, networkUnreachable: true, controlHost };
      }
      // The control succeeded (or failed for a non-network reason): the
      // network itself is fine — this first link's own "no-network"
      // finding stands (a transient/host-specific resolution issue for
      // THAT domain specifically), but the run continues to every
      // remaining link rather than aborting the whole thing over it.
    }
  }
  return { results, networkUnreachable: false, controlHost: null };
}

async function writeReport(reportPath, payload) {
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(payload, null, 2) + "\n");
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

  console.log(
    `--live: checking ${links.length} link(s), ${args.timeoutMs}ms timeout each, https-only, SSRF-hardened...\n`,
  );
  const { results, networkUnreachable, controlHost } = await runLinkChecks(
    links,
    configuredHosts,
    args.timeoutMs,
    {},
    (record) => {
      const mark = record.classification === "ok" ? "ok  " : "FAIL";
      console.log(
        `  ${mark} [${record.classification}${record.status ? `:${record.status}` : ""}] ${record.facilityName} -> ${record.url}`,
      );
    },
  );

  if (networkUnreachable) {
    const first = results[0];
    console.error(
      `check-links: first link classified no-network (${first?.detail}); the control host ` +
        `(${controlHost ?? "none configured"}) also failed — the network itself really is unreachable. ` +
        `Stopping without checking the remaining ${links.length - 1} link(s). A weekly checker that ` +
        `silently reported success here would be worse than an honest failure, so this exits non-zero.`,
    );
    if (args.reportPath) {
      await writeReport(args.reportPath, {
        generatedAt: new Date().toISOString(),
        totalLinks: links.length,
        checked: results.length,
        noNetwork: true,
        findings: results,
      });
      console.error(`check-links: wrote ${args.reportPath}`);
    }
    process.exitCode = 1;
    return;
  }

  const findings = results.filter((r) => r.classification !== "ok");
  console.log(`\ncheck-links: ${findings.length} finding(s) of ${links.length} link(s) checked.`);
  for (const f of findings) {
    console.log(`  - ${f.facilityName} [${f.provider}] ${f.url} :: ${f.classification} (${f.status ?? f.detail})`);
  }

  if (args.reportPath) {
    await writeReport(args.reportPath, {
      generatedAt: new Date().toISOString(),
      totalLinks: links.length,
      checked: results.length,
      noNetwork: false,
      findings,
    });
    console.log(`check-links: wrote ${args.reportPath} (${findings.length} finding(s))`);
  }

  if (findings.length > 0) {
    // A non-zero exit only in --live mode with real findings — this is an
    // ops report, not a PR-gating CI check (see this file's own module
    // doc: never invoked from ci.yml; the scheduled check-links.yml
    // workflow that DOES run it treats this exit code as its whole job).
    process.exitCode = 1;
  }
}

// Should-fix (Opus gate, "check-links `main()` guard"): only run when this
// file is the entry point, not merely imported (e.g. by
// `check-links.test.ts`, which imports `hardenedCheck`/`isPrivateIp`/etc.
// directly and must not trigger a live catalog load + network attempt as
// a side effect of that import).
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  await main();
}
