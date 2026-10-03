#!/usr/bin/env node
/**
 * `expo export <args>`, then `scan-bundle.mjs` over its output directory. Run by `pnpm export:ios` / `pnpm export:android` (package.json), which
 * pass `--clear --platform <p>`; any extra arguments (`pnpm export:ios --output-dir /tmp/out`) go to `expo export` too, and the scan reads the
 * SAME directory (`--output-dir <d>` / `--output-dir=<d>` / `-o <d>`, else `dist`). A plain `a && b` chain in package.json cannot do that: pnpm
 * appends extra arguments to the END of the command, i.e. to the scan, so the export would write somewhere the scan never looks.
 * Exit code: expo's if the export failed, else the scan's (0 clean, 1 a finding, 2 the scan could not run).
 */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

/** The export's output directory as `expo export` will read it from `args`. */
export function outputDirOf(argv) {
  let dir = "dist";
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? "";
    if (a === "--output-dir" || a === "-o") dir = argv[i + 1] ?? dir;
    else if (a.startsWith("--output-dir=")) dir = a.slice("--output-dir=".length);
  }
  return dir;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  // pnpm puts `node_modules/.bin` on PATH for package scripts, so `expo` resolves to the app's own pinned CLI.
  const exported = spawnSync("expo", ["export", ...args], { stdio: "inherit", shell: process.platform === "win32" });
  if (exported.status !== 0) process.exit(exported.status ?? 1);
  const scan = spawnSync(process.execPath, [join(here, "scan-bundle.mjs"), outputDirOf(args)], { stdio: "inherit" });
  process.exit(scan.status ?? 2);
}
