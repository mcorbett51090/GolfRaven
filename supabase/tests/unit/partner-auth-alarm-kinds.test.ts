// supabase/tests/unit/partner-auth-alarm-kinds.test.ts
//
// The auth-alarm trail has grown one `kind` per seam (0048 .. 0107, design 95 .. 113), and each seam widens the SAME two table constraints and adds a portal label.
// Until now nothing tied them together: `apps/partners/test/auth-alarms.test.ts` hard-codes a subset of kinds, so a kind added to the database CHECK without its
// `review.authAlarms.kind.*` label would reach an admin as a raw token (`authAlarmKindLabel` falls back to the kind), in either language.
//
// This file reads the LATEST migration that defines each constraint, so the next seam is covered the moment its migration lands:
//   1. every kind the latest `partner_auth_alarm_kind_check` allows has an EN and an fr-CA label, and no label names a kind the database cannot hold;
//   2. every such kind is placed by the latest `partner_auth_alarm_bucket_shape_check` (a kind in the first CHECK and in no branch of the second can never be inserted).

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { en } from "../../../apps/partners/src/i18n/messages/en.ts";
import { frCA } from "../../../apps/partners/src/i18n/messages/fr-CA.ts";

/** The text inside the parentheses that follow `ADD CONSTRAINT <name> CHECK`, balanced, quoted strings skipped. */
function checkBody(sql: string, name: string): string[] {
  const out: string[] = [];
  for (const m of sql.matchAll(
    new RegExp(`ADD\\s+CONSTRAINT\\s+${name}\\s+CHECK\\s*\\(`, "gi"),
  )) {
    let depth = 1;
    let i = m.index! + m[0].length;
    const start = i;
    while (i < sql.length && depth > 0) {
      const ch = sql[i]!;
      if (ch === "'") {
        i += 1;
        while (i < sql.length && !(sql[i] === "'" && sql[i + 1] !== "'"))
          i += sql[i] === "'" ? 2 : 1;
      } else if (ch === "(") depth += 1;
      else if (ch === ")") depth -= 1;
      i += 1;
    }
    if (depth !== 0) throw new Error(`unbalanced CHECK for ${name}`);
    out.push(sql.slice(start, i - 1));
  }
  return out;
}

/** The body of the constraint's LAST definition across the migrations (a later migration drops and re-adds it). */
function latestCheck(
  files: ReadonlyArray<{ name: string; sql: string }>,
  name: string,
): { file: string; body: string } {
  let found: { file: string; body: string } | null = null;
  for (const f of [...files].sort((a, b) => a.name.localeCompare(b.name))) {
    const bodies = checkBody(f.sql, name);
    if (bodies.length > 0)
      found = { file: f.name, body: bodies[bodies.length - 1]! };
  }
  if (found === null) throw new Error(`no migration defines ${name}`);
  return found;
}

const quoted = (body: string): string[] =>
  [...body.matchAll(/'([a-z_]+)'/g)].map((m) => m[1]!);

const dir = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "migrations",
);
const files = readdirSync(dir)
  .filter((f) => /^\d{4}_.*\.sql$/.test(f))
  .map((name) => ({ name, sql: readFileSync(join(dir, name), "utf8") }));

describe("the helper this guard stands on", () => {
  it("takes the balanced body, skips parentheses inside quoted strings, and returns the LAST definition", () => {
    const early = {
      name: "0001_a.sql",
      sql: "ALTER TABLE t ADD CONSTRAINT c CHECK (kind IN ('a', 'b'));",
    };
    const late = {
      name: "0002_b.sql",
      sql: "ALTER TABLE t ADD CONSTRAINT c CHECK ((kind IN ('a', 'b', 'c') AND x ~ '^(a|b)$') OR length(y) BETWEEN 1 AND 2);",
    };
    const got = latestCheck([late, early], "c");
    expect(got.file).toBe("0002_b.sql");
    expect(quoted(got.body)).toEqual(["a", "b", "c"]);
    expect(() => latestCheck([early], "missing")).toThrow(
      /no migration defines/,
    );
    expect(() =>
      checkBody("ALTER TABLE t ADD CONSTRAINT c CHECK (kind IN ('a'", "c"),
    ).toThrow(/unbalanced/);
  });
});

describe("the auth-alarm kinds: database and portal agree", () => {
  const kindCheck = latestCheck(files, "partner_auth_alarm_kind_check");
  const kinds = quoted(kindCheck.body);
  const labelled = (catalogue: Record<string, string>) =>
    Object.keys(catalogue)
      .filter((k) => k.startsWith("review.authAlarms.kind."))
      .map((k) => k.slice("review.authAlarms.kind.".length));

  it("reads a plausible kind list from the latest migration (so this guard is not vacuous)", () => {
    expect(kindCheck.file).toMatch(/^\d{4}_/);
    expect(kinds.length).toBeGreaterThanOrEqual(23);
    expect(new Set(kinds).size).toBe(kinds.length);
    expect(kinds).toContain("signature_invalid");
    expect(kinds).toContain("totp_enrol");
  });

  it.each([
    ["EN", en],
    ["fr-CA", frCA],
  ] as const)(
    "every kind the database allows has a %s label, and no label names a kind it cannot hold",
    (_name, catalogue) => {
      const have = new Set(labelled(catalogue as Record<string, string>));
      expect(
        kinds.filter((k) => !have.has(k)),
        "a kind with no label renders as a raw token for an admin: add review.authAlarms.kind.<kind> to en.ts and fr-CA.ts",
      ).toEqual([]);
      expect(
        [...have].filter((k) => !kinds.includes(k)),
        "a stale label: the kind CHECK no longer allows it",
      ).toEqual([]);
    },
  );

  it("every allowed kind is placed by the latest bucket-shape CHECK (otherwise no row of that kind can ever be inserted)", () => {
    const shape = latestCheck(files, "partner_auth_alarm_bucket_shape_check");
    const placed = new Set(quoted(shape.body));
    expect(
      kinds.filter((k) => !placed.has(k)),
      `${shape.file} must name the kind in one branch of partner_auth_alarm_bucket_shape_check`,
    ).toEqual([]);
  });
});
