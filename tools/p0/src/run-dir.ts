/**
 * Gate finding S7: every tool's output must default to a location OUTSIDE
 * the source tree, and refuse to write under the repo unless the caller
 * gave an explicit `--out`/`--out-dir`/`--run-dir` flag. Shared by
 * `x2-fetch.ts`, `x2-verdict.ts`, `x4-verify.ts` and `p0-desk.ts` so the
 * rule lives in exactly one place.
 */
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** This package's root (`tools/p0`), resolved from THIS module's own
 * location so it works from both `src/` (vitest) and `dist/`. */
export function packageRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.join(here, "..");
}

/** The repo root, two levels above `tools/p0`. */
export function repoRoot(): string {
  return path.join(packageRoot(), "..", "..");
}

/** A fresh default output directory OUTSIDE the source tree — the OS temp
 * dir, never `process.cwd()` (which, run via `pnpm --filter` or from
 * `tools/p0`, IS the source tree). */
export function defaultOutsideRepoDir(prefix: string): string {
  return path.join(
    tmpdir(),
    `${prefix}-${new Date().toISOString().replace(/[:.]/g, "-")}-${process.pid}`,
  );
}

/** Refuses (throws) when `outDir` resolves to a path under the repo root
 * and the caller did NOT explicitly choose it. A caller who explicitly
 * passed `--out`/`--out-dir`/`--run-dir` is trusted, even if that explicit
 * choice happens to be inside the repo (the point is stopping an ACCIDENTAL
 * write into the source tree, not vetoing a deliberate one). */
export function assertOutsideRepoUnlessExplicit(
  outDir: string,
  wasExplicit: boolean,
): void {
  if (wasExplicit) return;
  const resolved = path.resolve(outDir);
  const root = path.resolve(repoRoot());
  const withinRepo = resolved === root || resolved.startsWith(root + path.sep);
  if (withinRepo) {
    throw new Error(
      `Refusing to write run output under the repo (${resolved}) without an explicit --out/--out-dir/--run-dir. ` +
        "Pass one explicitly, or omit the flag to use the OS temp dir default (gate finding S7).",
    );
  }
}
