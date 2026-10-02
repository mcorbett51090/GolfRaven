// supabase/tests/unit/edge-system-path-isolation.test.ts
//
// Edge role PR3: structural guarantees for the SYSTEM path that a behavioural test cannot state as strongly (they read the source, like
// attest-key-isolation.test.ts). The behaviour itself is proved against a real cluster in
// supabase/tests/integration/edge-system-path.deno.test.ts; these pins fail fast when someone re-points a piece of the wiring.
//
//   1. import-catalog's drains are DELEGATED: index.ts hands `withDelegatedActor` (never `withOwnership`) to both orchestrators, and the
//      orchestrators open per-row transactions only through the function they are given.
//   2. `withSystemCatalogImport` has an edge branch that runs as edge_system and returns BEFORE the legacy pool is touched.
//   3. `withDelegatedActor` binds through the delegate binders (the "delegate" kind of openScopedTx), never through `bind_actor`, and its
//      legacy branch is exactly `withOwnership`.
//   4. In edge mode the importer repo reads and purges through the edge_system definers, not through app.evidence / app.play.
//   5. The self-check is scheduled (periodic), not once per pool.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const FUNCTIONS = join(import.meta.dirname, "..", "..", "functions");
const stripTs = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
const read = (rel: string) => stripTs(readFileSync(join(FUNCTIONS, rel), "utf8"));
const PRIV = read("_shared/privileged.ts");
const INDEX = read("import-catalog/index.ts");

/** The body of `function <name>` / `async function <name>` up to the next top-level `}` at column 0. */
function fnBody(src: string, name: string): string {
  const m = new RegExp(`(?:async )?function ${name}\\b[\\s\\S]*?\\n\\}\\n`).exec(src);
  if (!m) throw new Error(`function ${name} not found`);
  return m[0];
}

describe("PR3: the drains are delegated", () => {
  it("import-catalog/index.ts passes withDelegatedActor to BOTH drains and imports no withOwnership", () => {
    expect(INDEX).toMatch(/drainQueuedCatalog\(drainReadRepo, withDelegatedActor,/);
    expect(INDEX).toMatch(/drainRescoreBacklog\(drainReadRepo, withDelegatedActor,/);
    expect(INDEX).not.toMatch(/\bwithOwnership\b/);
    expect(INDEX).not.toMatch(/bind_actor|userBind|openScopedTx/);
  });

  it("the orchestrators take the per-row transaction function as a parameter and import nothing from privileged.ts", () => {
    for (const f of ["_shared/catalog/drain-orchestrator.ts", "_shared/catalog/rescore-orchestrator.ts"]) {
      const src = read(f);
      expect(src, f).not.toMatch(/privileged\.ts/);
      expect(src, f).toMatch(/withDelegatedActor: WithDelegatedActorFn/);
      expect(src, f).not.toMatch(/\bwithOwnership\(/);
    }
  });

  it("the drain names the row it acts on: the evidence id; the rescore names the backlog row AND the play", () => {
    expect(read("_shared/catalog/drain-orchestrator.ts")).toMatch(/kind: "queued_evidence", evidenceId: row\.id/);
    expect(read("_shared/catalog/rescore-orchestrator.ts")).toMatch(/kind: "rescore", backlogId: row\.id, playId: p\.playId/);
  });
});

describe("PR3: withDelegatedActor", () => {
  const body = fnBody(PRIV, "withDelegatedActor");
  it("binds through the delegate binders (openScopedTx 'delegate' + delegateBind) and never through bind_actor / userBind", () => {
    expect(body).toMatch(/openScopedTx\("delegate", delegateBind\(delegate, actor\.uid\)/);
    expect(body).not.toMatch(/userBind|bind_actor/);
  });
  it("its legacy branch is exactly withOwnership(actor, op)", () => {
    expect(body).toMatch(/return withOwnership\(actor, op\);/);
  });
  it("the delegate binders are called only in delegateBind, and only as edge_system (the transaction starts as edge_system, switches to edge_actor AFTER the bind)", () => {
    const calls = PRIV.match(/private\.bind_delegate_for_(queued_evidence|rescore)\(/g) ?? [];
    expect(calls.length).toBe(2);
    expect(fnBody(PRIV, "delegateBind")).toMatch(/bind_delegate_for_queued_evidence[\s\S]*bind_delegate_for_rescore/);
    const tx = fnBody(PRIV, "openScopedTx");
    const start = tx.indexOf("if (kind === \"actor\") await trx`set local role edge_actor`;");
    const bind = tx.indexOf("if (bind.run) await bind.run(trx);");
    const switchRole = tx.indexOf("if (kind === \"delegate\") await trx`set local role edge_actor`;");
    expect(start).toBeGreaterThan(-1);
    expect(bind).toBeGreaterThan(start);
    expect(switchRole).toBeGreaterThan(bind);
    expect(tx).toMatch(/else await trx`set local role edge_system`;/);
  });
});

describe("PR3: the importer repo runs as edge_system in edge mode", () => {
  const body = fnBody(PRIV, "withSystemCatalogImport");
  it("the edge branch comes first, runs as edge_system, and returns before sql() (the legacy pool) is reached", () => {
    const edge = body.indexOf('if (getDbMode() === "edge")');
    const legacyPool = body.indexOf("sql()");
    expect(edge).toBeGreaterThan(-1);
    expect(legacyPool).toBeGreaterThan(edge);
    const edgeBranch = body.slice(edge, legacyPool);
    expect(edgeBranch).toMatch(/openScopedTx\("system", \{ expectedUid: null \}, \(trx\) => op\(buildImporterRepo\(trx, "edge"\)\)\)/);
    expect(edgeBranch).not.toMatch(/sql\(\)/);
  });

  it("in edge mode the three cross-user statements go through the edge_system definers", () => {
    expect(PRIV).toMatch(/private\.list_queued_catalog\(/);
    expect(PRIV).toMatch(/private\.list_rescore_plays\(/);
    expect(PRIV).toMatch(/private\.purge_fix_coords\(/);
    expect(PRIV).toMatch(/private\.purge_install_link_tombstones\(/);
  });

  it("the queued list carries no raw submission in either mode (the drain re-reads it as the owner)", () => {
    const listOpen = PRIV.slice(PRIV.indexOf("async listOpen(limit: number): Promise<QueuedEvidenceRow[]>"));
    const stmt = listOpen.slice(0, listOpen.indexOf("currentSiteVersion"));
    expect(stmt).not.toMatch(/queued_input/);
    expect(PRIV).toMatch(/async readQueuedInput\(id: string\)/);
  });
});

describe("PR3: the self-check is scheduled", () => {
  it("openScopedTx goes through the gate, which re-checks on an interval and a call budget; the gate is not a once-per-pool cache", () => {
    expect(PRIV).toMatch(/const EDGE_SELF_CHECK_INTERVAL_MS = /);
    expect(PRIV).toMatch(/const EDGE_SELF_CHECK_EVERY_N_TX = /);
    expect(fnBody(PRIV, "openScopedTx")).toMatch(/await edgeChecked\(\);/);
    expect(PRIV).toMatch(/return _edgeGate\.ensure\(\);/);
    expect(PRIV).not.toMatch(/_edgeChecked\b/);
  });
});
