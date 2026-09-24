/**
 * The test suite's temporary build root — a fresh `mkdtemp()` directory
 * per test run (gate review: "test/paths.mjs uses mkdtemp, not a fixed
 * /tmp path"), never a fixed, guessable, shared name.
 *
 * vitest runs `globalSetup` in a SEPARATE process from the test files, so
 * the `mkdtemp()` path itself has to cross that process boundary somehow.
 * This module is the coordination point: `global-setup.mjs` calls
 * `createTmpBase()` once (creates the real `mkdtemp()` directory and
 * records its path), and `paths.mjs` — imported only by the test files —
 * calls `readTmpBase()` to read that same path back. The POINTER file
 * this writes to is fixed and tiny (one path, nothing else); it is never
 * itself a build output directory, and every actual per-build directory
 * under the path it points to still comes from `mkdtemp()`.
 */
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const POINTER_PATH = join(tmpdir(), "golfraven-site-tests.pointer");

/** Creates a fresh `mkdtemp()` base directory for this test run and
 * records its path in the pointer file. Call this ONCE, from
 * `global-setup.mjs`, before anything imports `paths.mjs`. */
export async function createTmpBase() {
  const base = await mkdtemp(join(tmpdir(), "golfraven-site-tests-"));
  await writeFile(POINTER_PATH, base, "utf8");
  return base;
}

/** Reads back the path `createTmpBase()` recorded. Throws if
 * `createTmpBase()` hasn't run yet in this test run (i.e. `global-setup.mjs`
 * didn't run first) — a missing pointer is a real ordering bug, not
 * something to paper over with a fallback fixed path. */
export async function readTmpBase() {
  const raw = await readFile(POINTER_PATH, "utf8");
  const base = raw.trim();
  if (!base) throw new Error(`tmp-base.mjs: pointer file at ${POINTER_PATH} is empty`);
  return base;
}
