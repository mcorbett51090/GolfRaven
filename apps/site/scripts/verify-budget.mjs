#!/usr/bin/env node
/**
 * verify-budget.mjs — build plan §5.2 "Build and deploy budget gate
 * (FM-12, G-P1-10)" / §10 P2 AT(12): "File-count, `_redirects`-count,
 * max-file and geometry-shard gates pass (§5.2)." Runs postbuild, same
 * position as `verify-sitemap.mjs` (see `package.json`'s `build` script).
 *
 * The exact thresholds from §5.2's table:
 *
 *   | Measure                  | Gate       |
 *   |---------------------------|-----------|
 *   | `dist/` size               | ≤ 400 MB  |
 *   | Files in `dist/`           | ≤ 18,000  |
 *   | `_redirects` rules         | ≤ 1,800 static |
 *   | Largest single file        | ≤ 20 MiB  |
 *   | Any `geometry/*` shard     | ≤ 5 MiB   |
 *
 * §5.2's "Warm `astro build` ≤ 12 min" gate is deliberately NOT enforced
 * as a hard failure here — build wall-clock varies enormously by host
 * (this repo's own sandboxed sessions in particular), and a flaky timing
 * gate is worse than an honest advisory one; `GOLFRAVEN_BUILD_STARTED_MS`
 * (set by the caller, e.g. `package.json`'s `build` script, to
 * `$(date +%s%3N)` before the chain starts) is read and REPORTED if
 * present, never failed on. §5.2's own text agrees with the "advisory,
 * never blocks" shape for the analogous nightly-cold-build case ("it
 * never blocks a deploy") — the same reasoning applies to a hot,
 * resource-constrained CI/dev sandbox.
 */
import { readdir, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MiB = 1024 * 1024;
const MB = 1_000_000;

const GATES = {
  distSizeBytes: 400 * MB,
  maxFiles: 18_000,
  maxRedirectsRules: 1_800,
  maxFileBytes: 20 * MiB,
  maxGeometryShardBytes: 5 * MiB,
};

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

function countRedirectsRules(text) {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#")).length;
}

export async function verifyBudget(distDir) {
  const issues = [];
  const files = await walk(distDir);

  let totalBytes = 0;
  let largest = { path: "", bytes: 0 };
  const geometryOffenders = [];
  for (const file of files) {
    const s = await stat(file);
    totalBytes += s.size;
    if (s.size > largest.bytes) largest = { path: relative(distDir, file), bytes: s.size };
    if (s.size > GATES.maxFileBytes) {
      issues.push(
        `${relative(distDir, file)} is ${(s.size / MiB).toFixed(2)} MiB, exceeds the ${GATES.maxFileBytes / MiB} MiB largest-file gate`,
      );
    }
    const relPath = relative(distDir, file).split(sep).join("/");
    if (/(^|\/)geometry\//.test(relPath) && s.size > GATES.maxGeometryShardBytes) {
      geometryOffenders.push(relPath);
      issues.push(
        `${relPath} is ${(s.size / MiB).toFixed(2)} MiB, exceeds the ${GATES.maxGeometryShardBytes / MiB} MiB geometry-shard gate`,
      );
    }
  }

  if (files.length > GATES.maxFiles) {
    issues.push(`dist/ has ${files.length} files, exceeds the ${GATES.maxFiles}-file gate`);
  }
  if (totalBytes > GATES.distSizeBytes) {
    issues.push(
      `dist/ is ${(totalBytes / MB).toFixed(1)} MB, exceeds the ${GATES.distSizeBytes / MB} MB gate`,
    );
  }

  let redirectsRules = 0;
  try {
    const { readFile } = await import("node:fs/promises");
    const text = await readFile(join(distDir, "_redirects"), "utf8");
    redirectsRules = countRedirectsRules(text);
    if (redirectsRules > GATES.maxRedirectsRules) {
      issues.push(
        `_redirects has ${redirectsRules} rule(s), exceeds the ${GATES.maxRedirectsRules}-rule static gate ` +
          `(§5.2: move the overflow to Cloudflare Bulk Redirects)`,
      );
    }
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
    // No _redirects at all (e.g. zero configured rules) — 0 is well under
    // the gate, nothing to report.
  }

  return {
    ok: issues.length === 0,
    issues,
    fileCount: files.length,
    totalBytes,
    largest,
    redirectsRules,
    geometryOffenders,
  };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const distDir =
    process.env.DIST_DIR ??
    process.argv[2] ??
    join(new URL(".", import.meta.url).pathname, "..", "dist");
  const result = await verifyBudget(distDir);

  const startedMs = Number(process.env.GOLFRAVEN_BUILD_STARTED_MS);
  if (Number.isFinite(startedMs) && startedMs > 0) {
    const elapsedMin = (Date.now() - startedMs) / 60_000;
    const flag = elapsedMin > 12 ? " (over the §5.2 12 min warm-build target — advisory only)" : "";
    console.log(`verify-budget: build took ~${elapsedMin.toFixed(1)} min${flag}`);
  }

  if (result.ok) {
    console.log(
      `verify-budget: PASS (${result.fileCount} files, ${(result.totalBytes / MB).toFixed(1)} MB, ` +
        `largest ${result.largest.path || "(none)"} ${(result.largest.bytes / MiB).toFixed(2)} MiB, ` +
        `${result.redirectsRules} _redirects rule(s))`,
    );
  } else {
    console.error(`verify-budget: FAIL (${result.issues.length} issue(s))`);
    for (const issue of result.issues) console.error(`  - ${issue}`);
    process.exit(1);
  }
}
