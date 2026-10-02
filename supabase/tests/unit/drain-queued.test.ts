// supabase/tests/unit/drain-queued.test.ts
//
// ⛔ REWRITE (P3e round 2 gate, B2/M1). `decideQueuedDrainOutcome` no
// longer takes `idsNowResolve: boolean` — a real re-derivation attempt
// (`redrainQueuedEvidenceRow`) now decides "resolved" for itself, before
// this module is ever consulted (this module's own header: "this
// module's only job now is the 'what to do about a row that STILL isn't
// resolved' decision"). The input is now `redrainKind` (what that real
// attempt already concluded) plus `coveringImportAlreadyRan` (M1 — a
// caller-computed boolean, never a version string this module parses
// itself).
import { describe, expect, it } from "vitest";
import { decideQueuedDrainOutcome } from "../../functions/_shared/catalog/drain-queued.js";

const NOW = new Date("2026-09-25T00:00:00.000Z");

describe("decideQueuedDrainOutcome", () => {
  it("passes through 'resolved' unconditionally — already applied by redrainQueuedEvidenceRow, this module is purely informational here", () => {
    const r = decideQueuedDrainOutcome({ redrainKind: "resolved", createdAt: NOW, now: NOW, coveringImportAlreadyRan: false });
    expect(r.kind).toBe("resolved");
  });

  it("a VERY old already-resolved row still reports 'resolved' — age is irrelevant once redrainQueuedEvidenceRow succeeded", () => {
    const createdAt = new Date(NOW.getTime() - 30 * 24 * 60 * 60 * 1000);
    const r = decideQueuedDrainOutcome({ redrainKind: "resolved", createdAt, now: NOW, coveringImportAlreadyRan: false });
    expect(r.kind).toBe("resolved");
  });

  it("passes through 'terminal_unknown_id' unconditionally — a structural failure redrainQueuedEvidenceRow already found (forged pairing, bad local date, ...)", () => {
    const r = decideQueuedDrainOutcome({ redrainKind: "terminal_unknown_id", createdAt: NOW, now: NOW, coveringImportAlreadyRan: false });
    expect(r.kind).toBe("terminal_unknown_id");
  });

  it("leaves a fresh, still-unresolved row queued when the covering import hasn't run yet (build plan §3.3: never silently dropped)", () => {
    const createdAt = new Date(NOW.getTime() - 1 * 24 * 60 * 60 * 1000);
    const r = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt, now: NOW, coveringImportAlreadyRan: false });
    expect(r.kind).toBe("still_queued");
  });

  it("flips a still-unresolved row older than 7 days to needs_attention (AT 15), when the covering import hasn't run yet", () => {
    const createdAt = new Date(NOW.getTime() - 8 * 24 * 60 * 60 * 1000);
    const r = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt, now: NOW, coveringImportAlreadyRan: false });
    expect(r.kind).toBe("needs_attention");
  });

  it("is exactly at the 7-day boundary -> needs_attention (>= , not merely >)", () => {
    const createdAt = new Date(NOW.getTime() - 7 * 24 * 60 * 60 * 1000);
    const r = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt, now: NOW, coveringImportAlreadyRan: false });
    expect(r.kind).toBe("needs_attention");
  });

  it("just under the 7-day boundary stays queued", () => {
    const createdAt = new Date(NOW.getTime() - 7 * 24 * 60 * 60 * 1000 + 1000);
    const r = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt, now: NOW, coveringImportAlreadyRan: false });
    expect(r.kind).toBe("still_queued");
  });

  it("respects a custom maxAgeDays", () => {
    const createdAt = new Date(NOW.getTime() - 2 * 24 * 60 * 60 * 1000);
    const r = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt, now: NOW, coveringImportAlreadyRan: false, maxAgeDays: 1 });
    expect(r.kind).toBe("needs_attention");
  });

  // ⛔ NEW (P3e round 2 gate, M1: "an id still absent after an import
  // that covers its claimed version -> terminal unknown_id status, not
  // left queued"). Distinct from the age-based cases above: a FRESH row
  // (would otherwise stay queued on age alone) terminates immediately
  // once the covering import has already run.
  it("M1: a FRESH still-unresolved row terminates as unknown_id immediately once the covering import already ran — age never gets a chance to matter", () => {
    const r = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt: NOW, now: NOW, coveringImportAlreadyRan: true });
    expect(r.kind).toBe("terminal_unknown_id");
  });

  it("M1: coveringImportAlreadyRan overrides even a row that would otherwise still be well within the 7-day window", () => {
    const createdAt = new Date(NOW.getTime() - 1000); // one second old
    const r = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt, now: NOW, coveringImportAlreadyRan: true });
    expect(r.kind).toBe("terminal_unknown_id");
  });
});
