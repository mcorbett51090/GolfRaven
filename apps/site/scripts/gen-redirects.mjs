#!/usr/bin/env node
/**
 * gen-redirects.mjs — build plan §5.1 `public/_redirects`: "Rewrite (now
 * live) | generated from `data/redirects.json` | Cloudflare Pages honours
 * path rules. Do not port SWC's only rule (`/?winery=:slug`) ... Above the
 * rule cap, slug 301s move to Cloudflare Bulk Redirects (§5.2)."
 *
 * **Runs POSTBUILD, writes directly into `<dist>/_redirects`** — same
 * reasoning and same move as `gen-headers.mjs` (Opus gate nit: stop
 * rewriting the tracked `public/_redirects`; §5.1's shape ["do not port
 * ... a query string [rule]"] is unaffected by where the file lands).
 * Moving this to postbuild ALSO makes B1's "`to` must be a built page"
 * check possible at all: `data/redirects.json` is read before `astro
 * build` even runs, so there is no `dist/` to check a target against
 * until now.
 *
 * **B1 (Opus gate, blocking) — redirect injection.** `from`/`to` are
 * validated against PATH_RE below (lower-case, digits, slash, underscore,
 * hyphen only, always app-absolute, always trailing-slash) — no whitespace, no
 * newline (confirmed empirically: JS `$` without the `m` flag does NOT
 * match before a trailing `\n`, so this alone rejects embedded/trailing
 * newline injection), no query string, no fragment, no scheme, no host.
 * That regex ALONE still admits a protocol-relative path made only of
 * allowed characters (`//evilhost/path/` — no dot, so it passes the
 * charset) `[docs: confirmed this session by testing the regex directly]`
 * — `rejectsDoubleSlashPrefix` below is the separate, explicit check for
 * exactly that. `to` is additionally required to be a page that actually
 * exists in `distDir` (an `index.html` at that path) — a typo'd or
 * removed target 404s instead of silently shipping a dead 301. The status
 * is always `301` (no caller-suppliable status).
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.GOLFRAVEN_DATA_DIR ?? join(here, "..", "..", "..", "data");
const REDIRECTS_JSON_PATH = join(DATA_DIR, "redirects.json");

/** Every character `from`/`to` may contain, and the overall shape: always
 * app-absolute, always trailing-slash, lower-case only. */
const PATH_RE = /^\/[a-z0-9/_-]*\/$/;

function rejectsDoubleSlashPrefix(path) {
  return path.startsWith("//");
}

/**
 * @param {string} path
 * @param {string} field
 * @param {number} i
 */
function validatePathShape(path, field, i) {
  if (typeof path !== "string") {
    throw new Error(`data/redirects.json: redirects[${i}].${field} must be a string`);
  }
  if (rejectsDoubleSlashPrefix(path)) {
    throw new Error(
      `data/redirects.json: redirects[${i}].${field} ("${JSON.stringify(path)}") starts with "//" — ` +
        `a protocol-relative path is never valid here (it would redirect off-site).`,
    );
  }
  if (!PATH_RE.test(path)) {
    throw new Error(
      `data/redirects.json: redirects[${i}].${field} (${JSON.stringify(path)}) must match ` +
        `${PATH_RE} — an app-absolute, trailing-slash, lower-case path only (no scheme, no host, ` +
        `no query string, no fragment, no whitespace, no newline).`,
    );
  }
}

/** @param {unknown} raw @returns {{from: string, to: string}[]} */
export function parseRedirects(raw) {
  const parsed = /** @type {{ redirects?: unknown }} */ (raw);
  const list = Array.isArray(parsed?.redirects) ? parsed.redirects : [];
  return list.map((entry, i) => {
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`data/redirects.json: redirects[${i}] must be {"from": "/…/", "to": "/…/"}`);
    }
    const { from, to } = /** @type {{ from?: unknown; to?: unknown }} */ (entry);
    validatePathShape(/** @type {string} */ (from), "from", i);
    validatePathShape(/** @type {string} */ (to), "to", i);
    return { from: /** @type {string} */ (from), to: /** @type {string} */ (to) };
  });
}

/** B1: `to` must resolve to a REAL built page in `distDir` — an
 * `index.html` at that path, the same convention `verify-sitemap.mjs`/
 * `verify-budget.mjs` already use to enumerate built pages. */
export function assertTargetsBuilt(rules, distDir) {
  for (const [i, rule] of rules.entries()) {
    const trimmed = rule.to.replace(/^\/|\/$/g, "");
    const indexPath = join(distDir, trimmed, "index.html");
    if (!existsSync(indexPath)) {
      throw new Error(
        `data/redirects.json: redirects[${i}].to ("${rule.to}") does not correspond to a built ` +
          `page (expected ${indexPath} to exist). Fix the target, or remove the stale rule.`,
      );
    }
  }
}

/** Nit (Opus gate): a redirect whose `from` equals its `to` is a no-op at
 * best and a same-path redirect loop at worst — refuse it outright rather
 * than shipping a rule that can never do anything useful. */
export function assertNoSelfRedirects(rules) {
  for (const [i, rule] of rules.entries()) {
    if (rule.from === rule.to) {
      throw new Error(
        `data/redirects.json: redirects[${i}] has from === to ("${rule.from}") — a redirect to ` +
          `itself is always either a no-op or a loop. Remove the rule.`,
      );
    }
  }
}

/** Nit (Opus gate): a redirect whose `from` matches a page that was
 * ACTUALLY built would shadow that real page — Cloudflare Pages applies
 * `_redirects` rules ahead of serving a matching static asset, so a real
 * built page at `from` would become permanently unreachable the moment
 * this rule shipped. Refuse it rather than silently orphaning a page
 * (the same "fail loud, not silent" shape `assertTargetsBuilt` already
 * applies to `to`). */
export function assertFromNotShadowingBuiltPage(rules, distDir) {
  for (const [i, rule] of rules.entries()) {
    const trimmed = rule.from.replace(/^\/|\/$/g, "");
    const indexPath = join(distDir, trimmed, "index.html");
    if (existsSync(indexPath)) {
      throw new Error(
        `data/redirects.json: redirects[${i}].from ("${rule.from}") IS a real built page ` +
          `(${indexPath} exists) — this redirect rule would shadow it (Cloudflare Pages applies ` +
          `_redirects rules ahead of matching static assets), making that page permanently ` +
          `unreachable. Remove the redirect rule, or retire the page itself first.`,
      );
    }
  }
}

export function renderRedirectsFile(rules) {
  const header =
    "# GENERATED by apps/site/scripts/gen-redirects.mjs from data/redirects.json — do not hand-edit.\n";
  if (rules.length === 0) return header;
  // Status is ALWAYS 301 — never taken from the input (B1).
  return header + rules.map((r) => `${r.from}\t${r.to}\t301`).join("\n") + "\n";
}

async function main() {
  const distDir = process.env.DIST_DIR ?? process.argv[2] ?? join(here, "..", "dist");
  let raw = { redirects: [] };
  try {
    raw = JSON.parse(await readFile(REDIRECTS_JSON_PATH, "utf8"));
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
    // No redirects.json at all (e.g. a bare fixture dir) — zero rules,
    // never an error; matches loadCatalog()'s own "missing = empty" rule.
  }
  const rules = parseRedirects(raw);
  assertNoSelfRedirects(rules);
  assertTargetsBuilt(rules, distDir);
  assertFromNotShadowingBuiltPage(rules, distDir);
  const outPath = join(distDir, "_redirects");
  await mkdir(distDir, { recursive: true });
  await writeFile(outPath, renderRedirectsFile(rules));
  console.log(`gen-redirects: wrote ${rules.length} rule(s) to ${outPath}`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) await main();
