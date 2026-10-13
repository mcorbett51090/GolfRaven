// supabase/tests/unit/integration-account-labels.test.ts
//
// Every Deno integration file runs against ONE database, and `createTestUser(uid, label)` inserts `<label>@integration.test` into `auth.users`, which is unique. Two files that build their labels from the same prefix and a
// counter therefore collide the moment both run in one harness pass: `duplicate key value violates unique constraint "users_email_key"`. It does not show when a file is run alone (every per-file run passes), only in the full
// suite. It happened twice, both times in a file whose helpers were copied from a sibling and kept the sibling's prefix: partner-entitlements (design 127, `rd-` from offers-redeem) and partner-sponsorships (design 134,
// `prg-` from partner-programme).
//
// This pin reads every `createTestUser(<uid>, <label>)` call in the integration directory and requires that no literal label prefix (the text before the first `${`) is used by more than one file. It does NOT see a label built
// from a variable, a prefix that is a strict prefix of another file's (`rv-` against `rv-staff-` is safe only because the suffixes differ in kind), or users created some other way than `createTestUser`.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/** file -> the literal label prefixes its `createTestUser` calls use. */
export function labelPrefixes(
  files: ReadonlyArray<{ name: string; src: string }>,
): Map<string, Set<string>> {
  const byPrefix = new Map<string, Set<string>>();
  for (const { name, src } of files) {
    for (const m of src.matchAll(
      /createTestUser\(\s*(?:[^,()]|\([^()]*\))+,\s*(?:`([^`]*)`|"([^"]*)"|'([^']*)')/g,
    )) {
      const prefix = (m[1] ?? m[2] ?? m[3] ?? "").split("${")[0]!;
      const set = byPrefix.get(prefix) ?? new Set<string>();
      set.add(name);
      byPrefix.set(prefix, set);
    }
  }
  return byPrefix;
}
export const sharedPrefixes = (
  files: ReadonlyArray<{ name: string; src: string }>,
) =>
  [...labelPrefixes(files)]
    .filter(([, f]) => f.size > 1)
    .map(([prefix, f]) => ({ prefix, files: [...f].sort() }));

describe("reading account-label prefixes", () => {
  const f = (name: string, src: string) => ({ name, src });
  it("takes the text before the first ${ of a template, or a whole string, and groups files by prefix", () => {
    const m = labelPrefixes([
      f(
        "a.ts",
        "await createTestUser(uid, `rd-staff-${seq}`); await createTestUser(u2, 'x');",
      ),
      f(
        "b.ts",
        'await createTestUser(uid, "fixed-label"); await createTestUser(freshUuid(), `plr-${n}`);',
      ),
    ]);
    expect([...m.keys()].sort()).toEqual([
      "fixed-label",
      "plr-",
      "rd-staff-",
      "x",
    ]);
  });
  it("flags a prefix two files share, and not one a file uses twice", () => {
    expect(
      sharedPrefixes([
        f(
          "a.ts",
          "createTestUser(u, `ent-${n}`); createTestUser(v, `ent-${m}`)",
        ),
        f("b.ts", "createTestUser(u, `stk-${n}`)"),
      ]),
    ).toEqual([]);
    expect(
      sharedPrefixes([
        f("a.ts", "createTestUser(u, `rd-${n}`)"),
        f("b.ts", "createTestUser(u, `rd-${n}`)"),
      ]),
    ).toEqual([{ prefix: "rd-", files: ["a.ts", "b.ts"] }]);
  });
});

describe("the integration files against each other", () => {
  const dir = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "integration",
  );
  const files = readdirSync(dir)
    .filter((n) => /\.deno\.test\.ts$/.test(n))
    .map((name) => ({ name, src: readFileSync(join(dir, name), "utf8") }));
  it("sees a realistic number of files and createTestUser calls (a reader that saw nothing would pass everything)", () => {
    expect(files.length).toBeGreaterThan(30);
    expect(
      [...labelPrefixes(files).values()].reduce((n, s) => n + s.size, 0),
    ).toBeGreaterThan(30);
  });
  it("no two files build their account labels from the same prefix", () => {
    expect(sharedPrefixes(files)).toEqual([]);
  });
});
