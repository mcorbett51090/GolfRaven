// supabase/tests/integration/owner-access-helper.deno.test.ts
//
// `withTemporaryOwnerAccess` (_helpers.ts) must leave the connecting role's table privileges exactly as it found them (design 128). In HARNESS_MODE=restricted the connecting role is the table's OWNER, which already
// holds every privilege; the helper used to `revoke` what it had "granted", which stripped the owner's OWN privileges, and PostgreSQL runs a foreign-key check with the owner's privileges, so every later insert that
// referenced the table failed "permission denied". partner-entitlements.deno.test.ts found it (design 127). In HARNESS_MODE=superuser nothing can be stripped, so the first cell is only meaningful in restricted mode;
// the second builds a table the connecting role has NO privilege on, so that the helper's grant-then-revoke path is exercised in the mode that can show it.

import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { rawOwnerSql, withTemporaryOwnerAccess } from "./_helpers.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;

async function privilegesOn(table: string): Promise<Record<string, boolean>> {
  const sql = rawOwnerSql();
  const out: Record<string, boolean> = {};
  for (const p of PRIVS)
    out[p] = (
      await sql`select has_table_privilege(current_user, ${table}, ${p}) as held`
    )[0]!.held as boolean;
  return out;
}
const isSuperuser = async (): Promise<boolean> =>
  (
    await rawOwnerSql()`select rolsuper as s from pg_roles where rolname = current_user`
  )[0]!.s as boolean;

Deno.test(
  "withTemporaryOwnerAccess leaves the connecting role's privileges on a table exactly as it found them (the owner keeps its own, which a foreign-key check needs)",
  DT,
  async () => {
    for (const table of [
      "app.special_marker_stock",
      "app.partner_org",
      "app.catalog_facility",
      "app.offer",
    ]) {
      const before = await privilegesOn(table);
      await withTemporaryOwnerAccess(
        table,
        async (sql) => {
          await sql`select 1`;
        },
        "select, insert, update, delete",
      );
      assertEquals(
        await privilegesOn(table),
        before,
        `${table}: the privileges after the helper are the privileges before it`,
      );
    }
  },
);

Deno.test(
  "withTemporaryOwnerAccess grants what the role lacks for the duration of the call and takes exactly that back",
  DT,
  async () => {
    if (await isSuperuser()) return; // a superuser holds every privilege: there is nothing to grant or take back, so this path cannot be reached in HARNESS_MODE=superuser
    const sql = rawOwnerSql();
    await sql.unsafe("drop table if exists app.zz_owner_access_probe");
    await sql.unsafe(
      "create table app.zz_owner_access_probe (id int primary key)",
    );
    try {
      // the owner takes its own privileges away: the state the helper meets when the role does not hold what it asks for
      await sql.unsafe(
        "revoke all on app.zz_owner_access_probe from current_user",
      );
      assertEquals(await privilegesOn("app.zz_owner_access_probe"), {
        SELECT: false,
        INSERT: false,
        UPDATE: false,
        DELETE: false,
      });

      const during = await withTemporaryOwnerAccess(
        "app.zz_owner_access_probe",
        async (s) => {
          await s`insert into app.zz_owner_access_probe (id) values (1)`;
          return await privilegesOn("app.zz_owner_access_probe");
        },
        "insert, update",
      );
      assertEquals(
        [during.INSERT, during.UPDATE, during.SELECT, during.DELETE],
        [true, true, false, false],
        "during the call: what was asked for, nothing more",
      );
      assertEquals(
        await privilegesOn("app.zz_owner_access_probe"),
        { SELECT: false, INSERT: false, UPDATE: false, DELETE: false },
        "after: exactly back to what it was",
      );
    } finally {
      await sql.unsafe(
        "grant all on app.zz_owner_access_probe to current_user",
      );
      await sql.unsafe("drop table if exists app.zz_owner_access_probe");
    }
  },
);
