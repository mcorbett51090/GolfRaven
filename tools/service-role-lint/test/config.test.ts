import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildConfigIndex, stripJsonComments } from "../src/config.js";
import { lintDirectory } from "../src/index.js";

// ⛔ M2 BLOCKING (post-P3a re-gate): "the lint's import-map model
// diverges from what Deno actually loads." Each fixture directory below
// reproduces one of the reviewer's four confirmed real-Deno-2.5.2
// bypasses (n1-n4), plus the disallowed-key case and a good control —
// supabase/functions/__fixtures__/m2-config/<case>/, pointed at directly
// as its own `functionsRoot` (these live under the lint's own excluded
// __fixtures__ directory, so they are never picked up by a real
// `lintDirectory(supabase/functions)` run — exercised here explicitly
// instead).

const FIXTURES_ROOT = join(import.meta.dirname, "..", "..", "..", "supabase", "functions", "__fixtures__", "m2-config");
const PINNED = new Set(["https://esm.sh/zod@3.23.8"]);

describe("config.ts — M2 (post-P3a re-gate): config files anywhere, regardless of importers", () => {
  it("n1: flags a `scopes` key in deno.json (never inspected by the old host-trust model)", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "n1-scopes"), PINNED);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('disallowed top-level key "scopes"'))),
    ).toBe(true);
  });

  it("n2: deno.json AND import_map.json both present is flagged as ambiguous -- neither silently wins", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "n2-both-present"), PINNED);
    const messages = index.results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes("more than one config file present"))).toBe(true);
    // Fails CLOSED: the directory resolves to an EMPTY map, so import_map.json's
    // "admin" target never silently wins and never resolves to anything.
    const resolved = index.resolveFor(join(FIXTURES_ROOT, "n2-both-present", "index.ts"));
    expect(resolved).toEqual({});
  });

  it("n3: a per-function fn/deno.json is found by walking UP from fn/lib/x.ts (two directory levels), not just checking the file's own directory merged with the root", () => {
    const results = lintDirectory(join(FIXTURES_ROOT, "n3-nested-function"));
    const flat = results.flatMap((r) => r.findings);
    expect(
      flat.some((f) => f.rule === "banned-import-specifier" && f.message.includes("not on the committed pinned-import-targets allow-list")),
    ).toBe(true);
  });

  it("n4: deno.jsonc is read (was never read at all by the old model)", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "n4-jsonc"), PINNED);
    const messages = index.results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes('imports["admin"]') && m.includes("not on the committed pinned-import-targets allow-list"))).toBe(true);
  });

  it("disallowed-key: an `importMap` key is rejected outright, even alongside an otherwise-clean, pinned `imports` entry", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "disallowed-key"), PINNED);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('disallowed top-level key "importMap"'))),
    ).toBe(true);
  });

  it("good control: a per-function deno.json whose only target is pinned produces ZERO findings, config or otherwise", () => {
    const results = lintDirectory(join(FIXTURES_ROOT, "good-control"));
    expect(results).toEqual([]);
  });
});

describe("config.ts — allowed top-level keys", () => {
  it("does not flag compilerOptions/lint/fmt/tasks alongside imports", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "good-control", "somefn"), PINNED);
    expect(index.results).toEqual([]);
  });
});

describe("stripJsonComments", () => {
  it("strips // and /* */ comments", () => {
    const out = stripJsonComments('{\n  // a comment\n  "a": 1, /* inline */ "b": 2\n}');
    expect(JSON.parse(out)).toEqual({ a: 1, b: 2 });
  });

  it("does NOT strip a // or /* sequence that appears INSIDE a string literal", () => {
    const out = stripJsonComments('{"url": "https://esm.sh/zod@3.23.8", "note": "a /* not a comment */ still a string"}');
    expect(JSON.parse(out)).toEqual({
      url: "https://esm.sh/zod@3.23.8",
      note: "a /* not a comment */ still a string",
    });
  });
});
