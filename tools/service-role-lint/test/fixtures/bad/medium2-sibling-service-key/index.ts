// ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): "importing from __fixtures__
// bypasses the lint." This is the regression fixture for that finding,
// exercised end-to-end through lintDirectory() (the real walker), not
// lintSource() on a single file in isolation — see
// tools/service-role-lint/test/index.test.ts's own "MEDIUM-2" describe
// block.
//
// This file is an entirely ordinary-looking real function: its own
// import is a plain RELATIVE sibling import, inside the same directory
// tree it lives in — never flagged by the specifier-shape checks (M1's
// relative-escape check only fires when a relative import walks OUTSIDE
// the functions root; this one does not), and never a banned bare
// specifier either. The bug this fixture proves is fixed is NOT in this
// file's own import statement — it is in whether the WALKER discovers
// and independently lints `_internal/service-key-reader.ts` at all.
// Before the fix, a directory carrying an excluded name anywhere in the
// tree (the lint's own `__fixtures__`, matched by resolved path) meant a
// file living there was invisible to lintDirectory() regardless of who
// imported it, while Deno would run it at deploy time exactly like any
// other file. Nothing under a linted functions root is excluded by name
// any more, so `_internal/service-key-reader.ts` below is walked and
// flagged on its own content, independent of this import.
import { readServiceKey } from "./_internal/service-key-reader.ts";

export function handler() {
  return readServiceKey();
}
