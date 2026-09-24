#!/usr/bin/env node
/**
 * verify-a11y-budget.mjs — build plan §10 P2 stage-2 scope item 8 /
 * AT(2): "A Lighthouse-style budget check, best-effort and offline:
 * assert the hub, trail and course pages ship under a JS/CSS byte
 * budget, and that each has a `<main>`, a `lang` attribute, labelled
 * landmarks and alt text on every `<img>`."
 *
 * This is a deterministic, offline STAND-IN for real Lighthouse — it
 * checks the same rough shape real Lighthouse's performance/accessibility
 * categories score on (payload weight; landmark/`lang`/alt-text presence),
 * without needing a browser. Runs postbuild, same position as
 * `verify-sitemap.mjs`/`verify-budget.mjs`.
 *
 * **The gap this doesn't close**: this is NOT a real Lighthouse run — no
 * Core Web Vitals, no colour-contrast, no real device-CPU throttling
 * model. `scripts/lighthouse-audit.mjs` runs the REAL thing (headless
 * Chromium at `/opt/pw-browsers`, confirmed working this session) against
 * a built `dist/`, but is deliberately NOT wired into `pnpm build`/`pnpm
 * test`/CI — a real Lighthouse run is slow and its performance score is
 * host-dependent (flaky in a shared/sandboxed CI runner in a way this
 * repo's own budget-gate philosophy, §5.2's "the nightly cold build
 * alerts, never blocks", already treats as the wrong shape for a required
 * gate). Run it by hand: `node scripts/lighthouse-audit.mjs [dist]`.
 */
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

// A generous heuristic proxy for "Lighthouse mobile performance ~90":
// combined same-origin CSS + JS (module scripts only — the map/search
// islands are lazy/code-split, so a page with neither ships far under
// this) referenced from the page. Overridable for a page whose real
// budget legitimately differs.
const DEFAULT_BUDGET_BYTES = 260 * 1024;

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

function firstMatch(html, pageRelPath) {
  const issues = [];

  if (!/<html[^>]*\slang="[a-z-]+"/i.test(html)) {
    issues.push(`${pageRelPath}: <html> has no lang attribute`);
  }
  if (!/<main[\s>]/i.test(html)) {
    issues.push(`${pageRelPath}: no <main> element`);
  }
  // Labelled landmarks: every <nav> must carry an aria-label (a page can
  // legitimately have more than one — e.g. primary nav + a pager nav —
  // and an unlabelled second nav is exactly the ambiguity this checks).
  const navTags = [...html.matchAll(/<nav\b[^>]*>/gi)];
  for (const [tag] of navTags) {
    if (!/aria-label="[^"]+"/i.test(tag)) {
      issues.push(
        `${pageRelPath}: a <nav> has no aria-label — ${tag.slice(0, 60)}`,
      );
    }
  }
  // Alt text on every <img> (an empty alt="" is a valid, deliberate
  // decorative-image annotation — still present, so it passes).
  const imgTags = [...html.matchAll(/<img\b[^>]*>/gi)];
  for (const [tag] of imgTags) {
    if (!/\salt="[^"]*"/i.test(tag)) {
      issues.push(
        `${pageRelPath}: an <img> has no alt attribute — ${tag.slice(0, 80)}`,
      );
    }
  }

  return issues;
}

async function pageWeight(distDir, html) {
  let bytes = 0;
  const linkHrefs = [
    ...html.matchAll(/<link\s+rel="stylesheet"\s+href="([^"]+)"/gi),
  ].map((m) => m[1]);
  const scriptSrcs = [
    ...html.matchAll(/<script\s+type="module"\s+src="([^"]+)"/gi),
  ].map((m) => m[1]);
  for (const href of [...linkHrefs, ...scriptSrcs]) {
    if (!href.startsWith("/")) continue; // same-origin only
    try {
      const { stat } = await import("node:fs/promises");
      const s = await stat(join(distDir, href.replace(/^\//, "")));
      bytes += s.size;
    } catch {
      // A referenced asset that isn't in THIS dist (shouldn't happen) is
      // not this gate's concern — verify-sitemap/the build itself would
      // already have failed for a genuinely broken reference.
    }
  }
  return bytes;
}

export async function verifyA11yBudget(distDir, opts = {}) {
  const budgetBytes = opts.budgetBytes ?? DEFAULT_BUDGET_BYTES;
  const files = (await walk(distDir)).filter((f) => f.endsWith("index.html"));

  // Exactly the three page KINDS the spec names: the hub, ONE trail page,
  // ONE course page (checking every single one would just re-run AT(3)'s
  // "hub < 300 KB" logic N times over; one representative of each kind is
  // what "hub, trail and course pages" asks for).
  const relOf = (f) => relative(distDir, f).split(sep).join("/");
  const targets = [];
  const hub = files.find((f) => relOf(f) === "index.html");
  if (hub) targets.push({ kind: "hub", file: hub });
  const trail = files.find(
    (f) => relOf(f).startsWith("trails/") && relOf(f) !== "trails/index.html",
  );
  if (trail) targets.push({ kind: "trail", file: trail });
  const course = files.find((f) => relOf(f).startsWith("courses/"));
  if (course) targets.push({ kind: "course", file: course });

  const issues = [];
  const report = [];
  for (const { kind, file } of targets) {
    const html = await readFile(file, "utf8");
    const relPath = relOf(file);
    const a11yIssues = firstMatch(html, relPath);
    const weight = await pageWeight(distDir, html);
    if (weight > budgetBytes) {
      issues.push(
        `${relPath} (${kind}): ${(weight / 1024).toFixed(1)} KB of same-origin CSS+JS, exceeds the ` +
          `${(budgetBytes / 1024).toFixed(0)} KB budget`,
      );
    }
    issues.push(...a11yIssues);
    report.push({
      kind,
      path: relPath,
      weightBytes: weight,
      issues: a11yIssues,
    });
  }

  return { ok: issues.length === 0, issues, report };
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const distDir =
    process.env.DIST_DIR ??
    process.argv[2] ??
    join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
  const result = await verifyA11yBudget(distDir);
  if (result.ok) {
    console.log(
      `verify-a11y-budget: PASS (${result.report.map((r) => `${r.kind}: ${(r.weightBytes / 1024).toFixed(1)} KB`).join(", ")})`,
    );
  } else {
    console.error(
      `verify-a11y-budget: FAIL (${result.issues.length} issue(s))`,
    );
    for (const issue of result.issues) console.error(`  - ${issue}`);
    process.exit(1);
  }
}
