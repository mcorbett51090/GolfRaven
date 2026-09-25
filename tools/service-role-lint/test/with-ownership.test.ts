import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1189-1196).
//
// ⛔ SUPERSEDED (P3c): this used to assert B6's fail-closed STUB ("throws
// synchronously... never invokes the callback") — that was correct for
// the placeholder that shipped before P3c's Edge Functions existed at
// all. `withOwnership` is now genuinely implemented
// (supabase/functions/_shared/privileged.ts): it constructs a real
// service-role Postgres connection and a real Supabase Auth client, both
// via `https://` URL imports Deno resolves natively at runtime (a
// pinned Deno driver + supabase-js, confirmed reachable this session via
// `deno eval`; see privileged.ts's own header comment) — which plain
// Node/vitest's ESM loader cannot import at all ("Only URLs with a
// scheme in: file and data are supported"). So this file no longer
// imports privileged.ts as a module; it reads its SOURCE TEXT and
// asserts the structural invariants that make it the sole allow-listed
// construction site, the same invariants tools/service-role-lint/src/
// lint.ts enforces mechanically over the whole supabase/functions tree
// (`node tools/service-role-lint/dist/cli.js supabase/functions` is
// clean — see tools/db/test.sh's own "service-role lint" step). The
// REAL functional behaviour (does withOwnership's callback actually run,
// does it return the right thing) is exercised through the `Repo`
// interface's callers instead — supabase/tests/unit/evidence-handler.
// test.ts and checkin-handlers.test.ts — which is where the actual
// business logic (not just "is this the one construction site") lives.
const PRIVILEGED_TS = readFileSync(join(import.meta.dirname, "..", "..", "..", "supabase", "functions", "_shared", "privileged.ts"), "utf8");

describe("privileged.ts — withOwnership is genuinely implemented (P3c), not the old fail-closed stub", () => {
  it("exports withOwnership and getActorFromRequest", () => {
    expect(PRIVILEGED_TS).toMatch(/export function withOwnership/);
    expect(PRIVILEGED_TS).toMatch(/export async function getActorFromRequest/);
  });

  it("no longer throws unconditionally — the B6 stub's 'fails closed' RAISE is gone", () => {
    expect(PRIVILEGED_TS).not.toMatch(/withOwnership\(\) is not implemented yet/);
  });

  it("withOwnership actually calls its callback (op), rather than swallowing it", () => {
    expect(PRIVILEGED_TS).toMatch(/export function withOwnership<T>\(_actor: Actor, op: Op<T>\): Promise<T> \{\s*return op\(buildRepo\(\)\);\s*\}/);
  });

  it("still never returns the raw supabase-js/postgres client to a caller — only a narrow Repo object", () => {
    // buildRepo()'s return type is `Repo` (types.ts) everywhere this file
    // constructs one; `deno check` (this session) confirms it type-checks
    // against that interface, which has no method returning a client.
    expect(PRIVILEGED_TS).toMatch(/function buildRepo\(\): Repo \{/);
  });
});
