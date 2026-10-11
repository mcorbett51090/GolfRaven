#!/usr/bin/env node
// tools/db/rotate-partner-pin-pepper.mjs
//
// OPERATOR TOOL (docs/security/partner-auth-design.md §77): prints the SQL that
// calls private.partner_pin_pepper_rotate. Nothing is written to a file, a
// database or a log by this script: the SQL goes to STDOUT and is meant to be
// PIPED straight into psql as the project's owner role (the role that may SET
// ROLE private_definer — granted in 0016 — and thus EXECUTE the owner-only
// definer). Node never holds pepper bytes; gen_random_bytes runs inside Postgres.
//
//   node tools/db/rotate-partner-pin-pepper.mjs non-compromise | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
//   node tools/db/rotate-partner-pin-pepper.mjs compromise     | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
//   node tools/db/rotate-partner-pin-pepper.mjs retire-previous | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
//
// Modes (CLI hyphen aliases → SQL underscore):
//   non-compromise / non_compromise — scheduled rotation; refuses while previous exists
//   compromise — replace current; drop previous; no epoch row
//   retire-previous / retire_previous — delete previous only when latest effective_from ≤ now()−7d

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const MODES = {
  "non-compromise": "non_compromise",
  non_compromise: "non_compromise",
  compromise: "compromise",
  "retire-previous": "retire_previous",
  retire_previous: "retire_previous",
};

export function resolveMode(arg) {
  if (typeof arg !== "string") return null;
  return MODES[arg] ?? null;
}

export function renderSql(sqlMode) {
  return [
    "BEGIN;",
    "SET LOCAL ROLE private_definer;",
    `SELECT private.partner_pin_pepper_rotate('${sqlMode}');`,
    "COMMIT;",
    "",
  ].join("\n");
}

function main(argv) {
  const arg = argv[2];
  const rest = argv.slice(3);
  const sqlMode = resolveMode(arg);
  if (rest.length > 0 || sqlMode === null) {
    process.stderr.write(
      "usage: node tools/db/rotate-partner-pin-pepper.mjs <non-compromise|compromise|retire-previous> | psql ...\n",
    );
    process.exitCode = 2;
    return;
  }
  process.stdout.write(renderSql(sqlMode));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv);
}
