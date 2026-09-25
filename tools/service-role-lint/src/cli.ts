#!/usr/bin/env node
// tools/service-role-lint/src/cli.ts
// CLI entry point run by tools/db/test.sh and CI: lints every file under
// supabase/functions/**.
//
// ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): this comment used to say
// the CLI run excluded `__fixtures__/good` and only included
// `__fixtures__/bad` "when explicitly asked" — that described the OLD
// exclusion in index.ts's walker, not anything this file itself ever
// did. It is stale now regardless: the lint's fixtures no longer live
// anywhere under supabase/functions at all (moved to
// tools/service-role-lint/test/fixtures/**, exercised only by the vitest
// suite's must-fail/must-pass assertions), so nothing under a real
// supabase/functions run is ever a fixture to begin with, and nothing is
// excluded by name any more either way.
// A plain repo-wide run over supabase/functions/** is what a real CI gate
// would run once real functions exist; it is exposed here mainly for local
// manual use.

import { lintDirectory } from "./index.js";

const root = process.argv[2] ?? "supabase/functions";
const results = lintDirectory(root);

if (results.length === 0) {
  console.log(`service-role-lint: clean (${root})`);
  process.exit(0);
}

for (const result of results) {
  for (const finding of result.findings) {
    console.error(
      `${result.filePath}:${finding.line}:${finding.column} [${finding.rule}] ${finding.message}`,
    );
  }
}
console.error(
  `service-role-lint: ${results.reduce((n, r) => n + r.findings.length, 0)} finding(s) in ${results.length} file(s)`,
);
process.exit(1);
