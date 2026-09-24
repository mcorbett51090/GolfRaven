#!/usr/bin/env node
/**
 * verify-sitemap.mjs — build plan §5.3: "The postbuild gate
 * `verify-sitemap.mjs` asserts that the `<loc>` set equals the set of
 * built pages without `noindex`." Runs as `apps/site`'s `postbuild` step
 * (see `package.json`) and is also imported directly by
 * `test/acceptance.test.ts` (AT1), so the CLI and the test assert exactly
 * the same thing against exactly the same logic.
 */
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(full)));
    else out.push(full);
  }
  return out;
}

/** `dist/<a>/<b>/index.html` -> `/<a>/<b>/`; `dist/index.html` -> `/`. */
function pathOf(distDir, htmlFile) {
  const rel = relative(distDir, dirname(htmlFile)).split(sep).join("/");
  return rel === "" ? "/" : `/${rel}/`;
}

/**
 * Scans `distDir` for every `index.html`, splitting them into "indexable"
 * (no `noindex` robots meta) and "noindex", then compares the indexable
 * set to the sitemap's `<loc>` set (read from `sitemap-0.xml`, or treated
 * as empty if that file does not exist — an empty-filter build, e.g. a
 * demo build, legitimately produces none).
 */
export async function verifySitemap(distDir) {
  const issues = [];

  const htmlFiles = (await walk(distDir)).filter((f) =>
    f.endsWith("index.html"),
  );
  const indexablePages = new Set();
  const noindexPages = new Set();
  for (const file of htmlFiles) {
    const html = await readFile(file, "utf8");
    const path = pathOf(distDir, file);
    if (/<meta\s+name="robots"\s+content="noindex/i.test(html)) {
      noindexPages.add(path);
    } else {
      indexablePages.add(path);
    }
  }

  let sitemapLocs = new Set();
  try {
    const sitemap = await readFile(join(distDir, "sitemap-0.xml"), "utf8");
    sitemapLocs = new Set(
      [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(
        (m) => new URL(m[1]).pathname,
      ),
    );
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
    // No sitemap-0.xml at all — only valid when nothing was indexable.
  }

  for (const loc of sitemapLocs) {
    if (!indexablePages.has(loc)) {
      issues.push(
        noindexPages.has(loc)
          ? `sitemap <loc> "${loc}" points at a page that carries noindex`
          : `sitemap <loc> "${loc}" does not correspond to any built page`,
      );
    }
  }
  for (const path of indexablePages) {
    if (!sitemapLocs.has(path)) {
      issues.push(`built indexable page "${path}" is missing from the sitemap`);
    }
  }

  return {
    ok: issues.length === 0,
    issues,
    indexablePages,
    noindexPages,
    sitemapLocs,
  };
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const distDir =
    process.env.DIST_DIR ??
    process.argv[2] ??
    join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
  const result = await verifySitemap(distDir);
  if (result.ok) {
    console.log(
      `verify-sitemap: PASS (${result.indexablePages.size} indexable page(s), ` +
        `${result.noindexPages.size} noindex page(s))`,
    );
  } else {
    console.error(`verify-sitemap: FAIL (${result.issues.length} issue(s))`);
    for (const issue of result.issues) console.error(`  - ${issue}`);
    process.exit(1);
  }
}
