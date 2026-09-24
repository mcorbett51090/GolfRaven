// MUST-FAIL: every raw-Postgres-driver specifier shape the gate named —
// npm:, jsr:, and deno.land/x: prefixed specifiers, none of which are the
// bare "pg"/"postgres" package names an npm-only check would look for.
import postgresNpm from "npm:postgres";
import pgNpm from "npm:pg";
import dbPostgresJsr from "jsr:@db/postgres";
import denoPostgres from "deno.land/x/postgres";

export function connectAll() {
  return [postgresNpm, pgNpm, dbPostgresJsr, denoPostgres];
}
