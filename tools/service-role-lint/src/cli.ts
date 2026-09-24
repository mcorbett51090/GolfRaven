#!/usr/bin/env node
// tools/service-role-lint/src/cli.ts
// CLI entry point run by tools/db/test.sh and CI: lints
// supabase/functions/** (excluding __fixtures__/good, which must pass, and
// including __fixtures__/bad only when explicitly asked, since those are
// meant to fail — see the vitest suite for the must-fail assertions).
// A plain repo-wide run over supabase/functions/** is what a real CI gate
// would run once real functions exist; it is exposed here mainly for local
///manual use.

import { lintDirectory } from "./index.js";

const root = process.argv[2] ?? "supabase/functions";
const results = lintDirectory(root);

if (results.length === 0) {
  console.log(`service-role-lint: clean (${root})`);
  process.exit(0);
}

for (const result of results) {
  for (const finding of result.findings) {
    console.error(`${result.filePath}:${finding.line}:${finding.column} [${finding.rule}] ${finding.message}`);
  }
}
console.error(`service-role-lint: ${results.reduce((n, r) => n + r.findings.length, 0)} finding(s) in ${results.length} file(s)`);
process.exit(1);
