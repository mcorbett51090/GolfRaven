#!/usr/bin/env node
/**
 * lighthouse-audit.mjs — the REAL Lighthouse half of AT(2) ("Lighthouse
 * mobile ≥ 90 performance / 100 accessibility on hub, trail and course
 * pages `[target]`"). Best-effort, run BY HAND against a built `dist/`
 * (`pnpm build` first) — NOT wired into `pnpm build`/`pnpm test`/CI. See
 * `verify-a11y-budget.mjs`'s module doc for why: real Lighthouse needs a
 * browser and its performance score is host-dependent, which is the wrong
 * shape for a required gate (§5.2's own "advisory, never blocks" pattern
 * for the analogous cold-build-timing case).
 *
 * Confirmed working this session: `npx --yes lighthouse --version` (13.5.0)
 * installs via the repo's proxy, and Chromium is present at
 * `/opt/pw-browsers/chromium-1194/chrome-linux/chrome`.
 *
 * Usage:
 *   pnpm build   (or otherwise produce apps/site/dist/)
 *   node scripts/lighthouse-audit.mjs [dist]
 */
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const here = fileURLToPath(new URL(".", import.meta.url));
const distDir = process.argv[2] ?? join(here, "..", "dist");
const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
].filter(Boolean);

const MIME = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webmanifest": "application/manifest+json",
};

function findChrome() {
  return CHROME_CANDIDATES.find((p) => existsSync(p));
}

function serveStatic(root, port) {
  const server = createServer(async (req, res) => {
    try {
      let path = decodeURIComponent(
        new URL(req.url, "http://localhost").pathname,
      );
      if (path.endsWith("/")) path += "index.html";
      const full = join(root, path);
      const s = await stat(full).catch(() => null);
      const target = s?.isDirectory() ? join(full, "index.html") : full;
      const body = await readFile(target);
      res.writeHead(200, {
        "Content-Type": MIME[extname(target)] ?? "application/octet-stream",
      });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end("not found");
    }
  });
  return new Promise((resolve) =>
    server.listen(port, "127.0.0.1", () => resolve(server)),
  );
}

async function auditOne(chrome, port, path, label) {
  const url = `http://127.0.0.1:${port}${path}`;
  const outFile = join(here, "..", `.lighthouse-${label}.json`);
  try {
    await execFileAsync(
      "npx",
      [
        "--yes",
        "lighthouse",
        url,
        "--output=json",
        `--output-path=${outFile}`,
        "--only-categories=performance,accessibility",
        "--form-factor=mobile",
        "--screenEmulation.mobile",
        "--chrome-flags=--headless=new --no-sandbox --disable-gpu",
        "--quiet",
      ],
      // Lighthouse's CLI reads CHROME_PATH from the environment, NOT a
      // --chrome-path flag (confirmed this session: the flag is silently
      // ignored and chrome-launcher then fails with "The CHROME_PATH
      // environment variable must be set").
      {
        cwd: join(here, ".."),
        timeout: 120_000,
        env: { ...process.env, CHROME_PATH: chrome },
      },
    );
    const report = JSON.parse(await readFile(outFile, "utf8"));
    const perf = Math.round((report.categories?.performance?.score ?? 0) * 100);
    const a11y = Math.round(
      (report.categories?.accessibility?.score ?? 0) * 100,
    );
    return { label, path, perf, a11y };
  } catch (err) {
    return { label, path, error: String(err?.message ?? err) };
  }
}

async function main() {
  if (!existsSync(distDir)) {
    console.error(
      `lighthouse-audit: ${distDir} does not exist — run \`pnpm build\` first.`,
    );
    process.exit(1);
  }
  const chrome = findChrome();
  if (!chrome) {
    console.error(
      "lighthouse-audit: no Chrome/Chromium binary found (checked CHROME_PATH and " +
        "/opt/pw-browsers/chromium-1194/chrome-linux/chrome). Documenting the gap rather than " +
        "failing: this script is best-effort only.",
    );
    process.exit(1);
  }

  const port = 4321 + Math.floor(Math.random() * 1000);
  const server = await serveStatic(distDir, port);
  console.log(
    `lighthouse-audit: serving ${distDir} on http://127.0.0.1:${port}`,
  );

  // Hub + one representative trail + one representative course page — the
  // exact three page KINDS AT(2) names. The paths below match the demo
  // fixture; pass real slugs via env when auditing a real build.
  const pages = [
    { path: "/", label: "hub" },
    {
      path: process.env.LH_TRAIL_PATH ?? "/trails/fictional-ridge-golf-trail/",
      label: "trail",
    },
    {
      path: process.env.LH_COURSE_PATH ?? "/courses/ridge-overlook-golf-club/",
      label: "course",
    },
  ];

  const results = [];
  for (const p of pages) {
    if (
      !existsSync(join(distDir, p.path.slice(1), "index.html")) &&
      p.path !== "/"
    ) {
      console.log(
        `lighthouse-audit: skipping ${p.label} (${p.path}) — not present in this dist`,
      );
      continue;
    }
    console.log(`lighthouse-audit: auditing ${p.label} (${p.path})...`);
    results.push(await auditOne(chrome, port, p.path, p.label));
  }

  server.close();

  console.log(
    "\nlighthouse-audit results (target: performance >= 90, accessibility = 100):",
  );
  for (const r of results) {
    if (r.error) {
      console.log(
        `  ${r.label.padEnd(6)} ${r.path.padEnd(40)} ERROR: ${r.error}`,
      );
    } else {
      const perfFlag = r.perf >= 90 ? "ok" : "BELOW TARGET";
      const a11yFlag = r.a11y === 100 ? "ok" : "BELOW TARGET";
      console.log(
        `  ${r.label.padEnd(6)} ${r.path.padEnd(40)} performance=${r.perf} (${perfFlag})  accessibility=${r.a11y} (${a11yFlag})`,
      );
    }
  }
}

await main();
