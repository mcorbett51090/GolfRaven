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
 * §5.2's "Warm `astro build` ≤ 12 min" gate (Opus gate should-fix,
 * "Gates": "Add a warm-build timing check with the 12-minute gate and a
 * warning at 90%.") IS now a real gate — `GOLFRAVEN_BUILD_STARTED_MS`
 * (`package.json`'s `build` script sets it to `$(date +%s%3N)` before the
 * chain starts) is read by `verifyBudget()` itself: past 12 min it's a
 * FAILING issue (same list every other gate reports into); past 90% of
 * that (10.8 min) it's a printed warning, never a failure — an early
 * heads-up while there's still time to notice a build creeping toward
 * the wall before it actually crosses it. Absent `GOLFRAVEN_BUILD_STARTED_MS`
 * (a caller that never set it, or `verifyBudget()` called directly from a
 * test with no timing to judge), the timing check is skipped outright —
 * never a false pass OR fail from a missing signal.
 */
import { readdir, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MiB = 1024 * 1024;
const MB = 1_000_000;
const MIN = 60_000;

const GATES = {
  distSizeBytes: 400 * MB,
  maxFiles: 18_000,
  maxRedirectsRules: 1_800,
  maxFileBytes: 20 * MiB,
  maxGeometryShardBytes: 5 * MiB,
  warmBuildMs: 12 * MIN,
  warmBuildWarnFraction: 0.9,
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

export async function verifyBudget(distDir, opts = {}) {
  const env = opts.env ?? process.env;
  const nowMs = opts.nowMs ?? Date.now();
  const issues = [];
  const warnings = [];
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

  let warmBuildMs = null;
  const startedMs = Number(env.GOLFRAVEN_BUILD_STARTED_MS);
  if (Number.isFinite(startedMs) && startedMs > 0) {
    warmBuildMs = nowMs - startedMs;
    if (warmBuildMs > GATES.warmBuildMs) {
      issues.push(
        `warm build took ${(warmBuildMs / MIN).toFixed(1)} min, exceeds the §5.2 ${GATES.warmBuildMs / MIN} min warm-build gate`,
      );
    } else if (warmBuildMs > GATES.warmBuildMs * GATES.warmBuildWarnFraction) {
      warnings.push(
        `warm build took ${(warmBuildMs / MIN).toFixed(1)} min — over ${GATES.warmBuildWarnFraction * 100}% of the ` +
          `§5.2 ${GATES.warmBuildMs / MIN} min warm-build gate`,
      );
    }
  }

  return {
    ok: issues.length === 0,
    issues,
    warnings,
    fileCount: files.length,
    totalBytes,
    largest,
    redirectsRules,
    geometryOffenders,
    warmBuildMs,
  };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const distDir =
    process.env.DIST_DIR ??
    process.argv[2] ??
    join(new URL(".", import.meta.url).pathname, "..", "dist");
  const result = await verifyBudget(distDir);

  if (result.warmBuildMs !== null) {
    console.log(`verify-budget: warm build took ~${(result.warmBuildMs / MIN).toFixed(1)} min`);
  }
  for (const warning of result.warnings) console.warn(`verify-budget: WARN — ${warning}`);

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
