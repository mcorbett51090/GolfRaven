// supabase/tests/unit/partner-resolve-statuses.test.ts
//
// The SQL <-> Edge status vocabulary of the held-reward resolve definers (0057, 0061, 0069). The `_apply` helpers translate SQLSTATEs into a
// returned `o_status`; `privileged.ts` accepts only the statuses in `RESOLVE_HELD_STATUSES` and throws "returned no usable status" (an
// uncaught 500) for anything else. That is exactly how `no_active_staff` (0061) reached production code unmapped: the SQL learned a status,
// the pgTAP matrix pinned it, and nothing tied the Edge list to the SQL.
//
// This file reads the LATEST definition of every `private.partner_resolve_*_apply` across the migrations and requires the set of statuses
// they can return to EQUAL the Edge list: a status the SQL can return but the Edge does not know (a 500), and a status the Edge lists that
// no SQL returns (dead code that hides the next gap), both fail here. The HTTP answer for each listed status is pinned in
// partner-review-handler.test.ts; the PWA text in apps/partners/test/messages.test.ts.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { RESOLVE_HELD_STATUSES } from "../../functions/_shared/partner/ports.ts";

/** Every `private.partner_resolve_*_apply` definition in the given migrations (name -> body), the later migration replacing the earlier. */
function latestResolveApplyBodies(
  files: ReadonlyArray<{ name: string; sql: string }>,
): Map<string, string> {
  const out = new Map<string, string>();
  for (const { sql } of [...files].sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    for (const m of sql.matchAll(
      /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(private\.partner_resolve_[a-z_]+_apply)\s*\(/gi,
    )) {
      const open = sql.indexOf("AS $$", m.index);
      const close = open < 0 ? -1 : sql.indexOf("$$;", open + 5);
      if (open < 0 || close < 0)
        throw new Error(`could not find the body of ${m[1]}`);
      out.set(m[1]!, sql.slice(open, close));
    }
  }
  return out;
}

/** The literal statuses a body RETURNs (`RETURN QUERY SELECT 'x'::text, ...`). */
function returnedStatuses(body: string): Set<string> {
  return new Set(
    [...body.matchAll(/RETURN\s+QUERY\s+SELECT\s+'([a-z_]+)'::text/gi)].map(
      (m) => m[1]!,
    ),
  );
}

const dir = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "migrations",
);
const files = readdirSync(dir)
  .filter((f) => /^\d{4}_.*\.sql$/.test(f))
  .map((name) => ({ name, sql: readFileSync(join(dir, name), "utf8") }));

describe("the parser this pin stands on", () => {
  it("takes the LATER definition of a function and the literal RETURN QUERY statuses of that body only", () => {
    const early = {
      name: "0001_a.sql",
      sql: "CREATE FUNCTION private.partner_resolve_x_apply(a int) RETURNS TABLE (o_status text) AS $$ BEGIN RETURN QUERY SELECT 'old'::text; END $$;",
    };
    const late = {
      name: "0002_b.sql",
      sql: "CREATE OR REPLACE FUNCTION private.partner_resolve_x_apply(a int) RETURNS TABLE (o_status text) AS $$ BEGIN RETURN QUERY SELECT 'ok'::text, 1; RETURN QUERY SELECT 'new_one'::text, NULL; END $$;\nCREATE FUNCTION private.other() AS $$ RETURN QUERY SELECT 'unrelated'::text; $$;",
    };
    const bodies = latestResolveApplyBodies([late, early]); // order of the input must not matter
    expect([...bodies.keys()]).toEqual(["private.partner_resolve_x_apply"]);
    expect(
      [
        ...returnedStatuses(bodies.get("private.partner_resolve_x_apply")!),
      ].sort(),
    ).toEqual(["new_one", "ok"]);
  });

  it("fails loudly on a function whose body it cannot find, instead of seeing nothing", () => {
    expect(() =>
      latestResolveApplyBodies([
        {
          name: "0001_a.sql",
          sql: "CREATE FUNCTION private.partner_resolve_y_apply(a int) RETURNS void",
        },
      ]),
    ).toThrow(/could not find the body/);
  });
});

describe("the held-reward resolve statuses: SQL and Edge agree", () => {
  const bodies = latestResolveApplyBodies(files);
  const sql = new Set(
    [...bodies.values()].flatMap((b) => [...returnedStatuses(b)]),
  );

  it("sees the three resolve apply helpers (so this pin is not vacuous)", () => {
    expect([...bodies.keys()].sort()).toEqual([
      "private.partner_resolve_held_entitlement_apply",
      "private.partner_resolve_held_offer_code_apply",
      "private.partner_resolve_receipt_cross_user_match_apply",
    ]);
    expect(sql.size).toBeGreaterThan(3);
  });

  it("every status the SQL can return is known to the Edge (otherwise privileged.ts throws and an admin gets a 500)", () => {
    const unknown = [...sql].filter(
      (s) => !(RESOLVE_HELD_STATUSES as readonly string[]).includes(s),
    );
    expect(
      unknown,
      "add the status to RESOLVE_HELD_STATUSES (ports.ts), map it in review-handler.ts, and add the PWA text",
    ).toEqual([]);
  });

  it("every status the Edge lists is returned by some SQL helper (no dead entry that hides the next gap)", () => {
    const dead = RESOLVE_HELD_STATUSES.filter((s) => !sql.has(s));
    expect(dead).toEqual([]);
  });

  it("no_active_staff (0061) is on both sides", () => {
    expect(sql.has("no_active_staff")).toBe(true);
    expect(RESOLVE_HELD_STATUSES).toContain("no_active_staff");
  });
});
