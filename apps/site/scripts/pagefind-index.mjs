#!/usr/bin/env node
/**
 * pagefind-index.mjs — build plan §10 P2 stage-2 scope item 4: "Search.
 * Pagefind over the built site, lazy-loaded, working under the CSP."
 *
 * Runs the `pagefind` CLI over the built `dist/` (a static full-text index
 * of the rendered HTML — no server, no third-party search service), AFTER
 * `astro build` and BEFORE `verify-sitemap`/`verify-budget` (see
 * `package.json`'s `build` script) so the index's own files land inside
 * `dist/pagefind/` in time for those postbuild gates to count them too
 * (file-count/size budgets, AT(12)).
 *
 * Deliberately excludes the demo banner and nav chrome from the index via
 * `data-pagefind-ignore` (see `BaseLayout.astro`) so search results are
 * course/trail content, not boilerplate repeated on every page.
 *
 * `@pagefind/linux-x64` (the native indexer binary, an `optionalDependency`
 * of `pagefind`) is present in this session's install — confirmed via
 * `find node_modules/.pnpm -iname "@pagefind+linux-x64@*"`.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));

const distDir = process.env.DIST_DIR ?? process.argv[2] ?? join(here, "..", "dist");
const pagefindBin = join(here, "..", "node_modules", ".bin", "pagefind");

async function main() {
  if (!existsSync(distDir)) {
    throw new Error(`pagefind-index: ${distDir} does not exist — run \`astro build\` first.`);
  }
  const bin = existsSync(pagefindBin) ? pagefindBin : "pagefind";
  const { stdout, stderr } = await execFileAsync(bin, ["--site", distDir, "--output-subdir", "pagefind"], {
    cwd: join(here, ".."),
  });
  if (stdout.trim()) console.log(stdout.trim());
  if (stderr.trim()) console.error(stderr.trim());
  console.log(`pagefind-index: indexed ${distDir} -> ${join(distDir, "pagefind")}`);
}

await main();
