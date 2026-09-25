// supabase/tests/unit/classify-version.test.ts
import { describe, expect, it } from "vitest";
import { classifyCatalogSubmission, classifyCatalogVersion } from "../../functions/_shared/catalog/classify-version.js";

const NOW = new Date("2026-06-01T00:00:00.000Z");

describe("classifyCatalogVersion", () => {
  it("accepts the current version", () => {
    const r = classifyCatalogVersion({ declaredVersion: 5, currentVersion: 5, declaredVersionRow: null, now: NOW });
    expect(r.kind).toBe("current_or_within_window");
  });

  it("accepts a version within the skew window (recent enough, few enough versions behind)", () => {
    const r = classifyCatalogVersion({
      declaredVersion: 3,
      currentVersion: 5,
      declaredVersionRow: { publishedAt: "2026-05-20T00:00:00.000Z" },
      now: NOW,
    });
    expect(r.kind).toBe("current_or_within_window");
  });

  it("rejects a version published more than 30 days ago as stale (AT 8)", () => {
    const r = classifyCatalogVersion({
      declaredVersion: 4,
      currentVersion: 5,
      declaredVersionRow: { publishedAt: "2026-01-01T00:00:00.000Z" },
      now: NOW,
    });
    expect(r.kind).toBe("stale");
  });

  it("rejects a version more than 5 releases behind as stale, even if recently published", () => {
    const r = classifyCatalogVersion({
      declaredVersion: 1,
      currentVersion: 10,
      declaredVersionRow: { publishedAt: "2026-05-31T00:00:00.000Z" },
      now: NOW,
    });
    expect(r.kind).toBe("stale");
  });

  it("rejects an older version the server has no record of at all as stale", () => {
    const r = classifyCatalogVersion({ declaredVersion: 3, currentVersion: 5, declaredVersionRow: null, now: NOW });
    expect(r.kind).toBe("stale");
  });

  it("treats a version newer than current (not far-future) as 'forged' at THIS layer — classifyCatalogSubmission is what can upgrade it via a verified signature", () => {
    const r = classifyCatalogVersion({ declaredVersion: 6, currentVersion: 5, declaredVersionRow: null, now: NOW });
    expect(r.kind).toBe("forged");
  });

  it("rejects a far-future version outright (G3-10)", () => {
    const r = classifyCatalogVersion({ declaredVersion: 500, currentVersion: 5, declaredVersionRow: null, now: NOW });
    expect(r.kind).toBe("forged");
  });

  it("fails closed when no catalog has ever been imported", () => {
    const r = classifyCatalogVersion({ declaredVersion: 1, currentVersion: null, declaredVersionRow: null, now: NOW });
    expect(r.kind).toBe("stale");
  });
});

describe("classifyCatalogSubmission (the AT 8 / G3-10 outer decision, folding in signature verification)", () => {
  it("a newer version with NO manifestSig at all is catalog_forged", async () => {
    const r = await classifyCatalogSubmission(
      { declaredVersion: 6, currentVersion: 5, declaredVersionRow: null, now: NOW },
      async () => true, // even a verifier that would say yes never runs without a claim
    );
    expect(r.kind).toBe("forged");
  });

  it("a newer version with a manifestSig that FAILS to verify is catalog_forged", async () => {
    const r = await classifyCatalogSubmission(
      { declaredVersion: 6, currentVersion: 5, declaredVersionRow: null, now: NOW, manifestSig: { kid: "k1", signatureB64Url: "abc", payload: "6" } },
      async () => false,
    );
    expect(r.kind).toBe("forged");
  });

  it("a newer version with a manifestSig that VERIFIES is accepted (202-queued outcome, per AT 8 — the caller decides the HTTP status)", async () => {
    const r = await classifyCatalogSubmission(
      { declaredVersion: 6, currentVersion: 5, declaredVersionRow: null, now: NOW, manifestSig: { kid: "k1", signatureB64Url: "abc", payload: "6" } },
      async () => true,
    );
    expect(r).toEqual({ kind: "ok", resolvedVersion: 6 });
  });

  it("a far-future version is forged even with a manifestSig present (G3-10: never queued)", async () => {
    const r = await classifyCatalogSubmission(
      { declaredVersion: 500, currentVersion: 5, declaredVersionRow: null, now: NOW, manifestSig: { kid: "k1", signatureB64Url: "abc", payload: "500" } },
      async () => true,
    );
    expect(r.kind).toBe("forged");
  });

  it("a stale version stays stale regardless of any manifestSig", async () => {
    const r = await classifyCatalogSubmission(
      { declaredVersion: 1, currentVersion: 10, declaredVersionRow: { publishedAt: "2026-05-31T00:00:00.000Z" }, now: NOW },
      async () => true,
    );
    expect(r.kind).toBe("stale");
  });

  it("the current version is ok with no signature question at all", async () => {
    const r = await classifyCatalogSubmission({ declaredVersion: 5, currentVersion: 5, declaredVersionRow: null, now: NOW }, async () => {
      throw new Error("should never be called");
    });
    expect(r).toEqual({ kind: "ok", resolvedVersion: 5 });
  });
});
