// supabase/tests/unit/classify-version.test.ts
//
// ⛔ REWRITE (P3e round 2 gate, H1: "change the intake contract to the
// site version string (yyyymmdd-gitsha7)... update every test, fixture
// and the money-path doc text that pins the int form"). Every fixture
// below now uses a real `yyyymmdd-gitsha7` string (never a bare int) for
// `declaredVersion`/`currentVersion`, and the "N releases behind" check
// is driven by a SEPARATE `internalVersion`/`currentInternalVersion`
// int — classify-version.ts's own header explains why these are two
// different sources now, not one int diff. `manifestSig` fixtures use
// the real outer-layer `ManifestSigClaim` shape (`{kid, signature,
// payload}`), never the old `signatureB64Url` field name.
import { describe, expect, it } from "vitest";
import { classifyCatalogSubmission, classifyCatalogVersion } from "../../functions/_shared/catalog/classify-version.js";

const NOW = new Date("2026-06-01T00:00:00.000Z");

// A deliberately readable ladder of site version strings, oldest to
// newest by DATE PREFIX (compareCatalogVersions is date-primary) — the
// `internalVersion` a fixture supplies alongside one of these is
// independent of this ordering (classify-version.ts's own header: two
// versions cut the same week are still "1 release apart"), so each test
// below sets `internalVersion` explicitly to whatever that test needs,
// never inferred from the string.
const V_OLD1 = "20260101-1111111"; // Jan 1 2026
const V_OLD2 = "20260215-2222222"; // Feb 15 2026
const V_OLD3 = "20260515-3333333"; // May 15 2026 — 17 days before NOW
const V_CURRENT = "20260601-5555555"; // == NOW's own date — "current"
const V_NEWER_NOT_FAR_FUTURE = "20260602-6666666"; // exactly 1 day ahead of NOW (the default maxFutureDays boundary — NOT over it)
const V_FAR_FUTURE = "20500101-7777777"; // decades ahead — always far-future
const V_HIGH_CURRENT = "20261201-aaaaaaa"; // a later "current" for the releases-behind fixtures

describe("classifyCatalogVersion", () => {
  it("accepts the current version", () => {
    const r = classifyCatalogVersion({ declaredVersion: V_CURRENT, currentVersion: V_CURRENT, declaredVersionRow: null, currentInternalVersion: 5, now: NOW });
    expect(r.kind).toBe("current_or_within_window");
  });

  it("accepts a version within the skew window (recent enough, few enough versions behind)", () => {
    const r = classifyCatalogVersion({
      declaredVersion: V_OLD3,
      currentVersion: V_CURRENT,
      declaredVersionRow: { publishedAt: "2026-05-15T00:00:00.000Z", kidRevoked: false, internalVersion: 3 },
      currentInternalVersion: 5,
      now: NOW,
    });
    expect(r.kind).toBe("current_or_within_window");
  });

  it("rejects a version published more than 30 days ago as stale (AT 8)", () => {
    const r = classifyCatalogVersion({
      declaredVersion: V_OLD2,
      currentVersion: V_CURRENT,
      declaredVersionRow: { publishedAt: "2026-01-01T00:00:00.000Z", kidRevoked: false, internalVersion: 2 },
      currentInternalVersion: 5,
      now: NOW,
    });
    expect(r.kind).toBe("stale");
  });

  it("rejects a version more than 5 releases behind as stale, even if recently published", () => {
    const r = classifyCatalogVersion({
      declaredVersion: V_OLD1,
      currentVersion: V_HIGH_CURRENT,
      declaredVersionRow: { publishedAt: "2026-05-31T00:00:00.000Z", kidRevoked: false, internalVersion: 1 },
      currentInternalVersion: 10,
      now: NOW,
    });
    expect(r.kind).toBe("stale");
  });

  it("rejects an older version the server has no record of at all as stale", () => {
    const r = classifyCatalogVersion({ declaredVersion: V_OLD3, currentVersion: V_CURRENT, declaredVersionRow: null, currentInternalVersion: 5, now: NOW });
    expect(r.kind).toBe("stale");
  });

  it("treats a version newer than current (not far-future) as 'forged' at THIS layer — classifyCatalogSubmission is what can upgrade it via a verified signature", () => {
    const r = classifyCatalogVersion({ declaredVersion: V_NEWER_NOT_FAR_FUTURE, currentVersion: V_CURRENT, declaredVersionRow: null, currentInternalVersion: 5, now: NOW });
    expect(r.kind).toBe("forged");
  });

  it("rejects a far-future version outright (G3-10)", () => {
    const r = classifyCatalogVersion({ declaredVersion: V_FAR_FUTURE, currentVersion: V_CURRENT, declaredVersionRow: null, currentInternalVersion: 5, now: NOW });
    expect(r.kind).toBe("forged");
  });

  it("rejects a malformed (non yyyymmdd-gitsha7) declaredVersion as forged, defensively", () => {
    const r = classifyCatalogVersion({ declaredVersion: "not-a-real-version", currentVersion: V_CURRENT, declaredVersionRow: null, currentInternalVersion: 5, now: NOW });
    expect(r.kind).toBe("forged");
  });

  it("fails closed when no catalog has ever been imported", () => {
    const r = classifyCatalogVersion({ declaredVersion: V_OLD1, currentVersion: null, declaredVersionRow: null, currentInternalVersion: null, now: NOW });
    expect(r.kind).toBe("stale");
  });

  // should-fix (P3c gate round 2, AT 15): "a revoked kid returns 422
  // catalog_stale."
  it("AT 15: a revoked-kid version is stale even when it IS the current version", () => {
    const r = classifyCatalogVersion({
      declaredVersion: V_CURRENT,
      currentVersion: V_CURRENT,
      declaredVersionRow: { publishedAt: "2026-05-20T00:00:00.000Z", kidRevoked: true, internalVersion: 5 },
      currentInternalVersion: 5,
      now: NOW,
    });
    expect(r.kind).toBe("stale");
  });

  it("AT 15: a revoked-kid version is stale even when it's otherwise within the skew window", () => {
    const r = classifyCatalogVersion({
      declaredVersion: V_OLD3,
      currentVersion: V_CURRENT,
      declaredVersionRow: { publishedAt: "2026-05-15T00:00:00.000Z", kidRevoked: true, internalVersion: 3 },
      currentInternalVersion: 5,
      now: NOW,
    });
    expect(r.kind).toBe("stale");
  });
});

describe("classifyCatalogSubmission (the AT 8 / G3-10 outer decision, folding in signature verification)", () => {
  it("a newer version with NO manifestSig at all is catalog_forged", async () => {
    const r = await classifyCatalogSubmission(
      { declaredVersion: V_NEWER_NOT_FAR_FUTURE, currentVersion: V_CURRENT, declaredVersionRow: null, currentInternalVersion: 5, now: NOW },
      async () => true, // even a verifier that would say yes never runs without a claim
    );
    expect(r.kind).toBe("forged");
  });

  it("a newer version with a manifestSig that FAILS to verify is catalog_forged", async () => {
    const r = await classifyCatalogSubmission(
      {
        declaredVersion: V_NEWER_NOT_FAR_FUTURE,
        currentVersion: V_CURRENT,
        declaredVersionRow: null,
        currentInternalVersion: 5,
        now: NOW,
        manifestSig: { kid: "k1", signature: "AAAA", payload: V_NEWER_NOT_FAR_FUTURE },
      },
      async () => false,
    );
    expect(r.kind).toBe("forged");
  });

  it("a newer version with a manifestSig that VERIFIES is accepted (202-queued outcome, per AT 8 — the caller decides the HTTP status)", async () => {
    const r = await classifyCatalogSubmission(
      {
        declaredVersion: V_NEWER_NOT_FAR_FUTURE,
        currentVersion: V_CURRENT,
        declaredVersionRow: null,
        currentInternalVersion: 5,
        now: NOW,
        manifestSig: { kid: "k1", signature: "AAAA", payload: V_NEWER_NOT_FAR_FUTURE },
      },
      async () => true,
    );
    expect(r).toEqual({ kind: "ok", resolvedVersion: V_NEWER_NOT_FAR_FUTURE });
  });

  it("a far-future version is forged even with a manifestSig present (G3-10: never queued)", async () => {
    const r = await classifyCatalogSubmission(
      {
        declaredVersion: V_FAR_FUTURE,
        currentVersion: V_CURRENT,
        declaredVersionRow: null,
        currentInternalVersion: 5,
        now: NOW,
        manifestSig: { kid: "k1", signature: "AAAA", payload: V_FAR_FUTURE },
      },
      async () => true,
    );
    expect(r.kind).toBe("forged");
  });

  it("a stale version stays stale regardless of any manifestSig", async () => {
    const r = await classifyCatalogSubmission(
      {
        declaredVersion: V_OLD1,
        currentVersion: V_HIGH_CURRENT,
        declaredVersionRow: { publishedAt: "2026-05-31T00:00:00.000Z", kidRevoked: false, internalVersion: 1 },
        currentInternalVersion: 10,
        now: NOW,
        manifestSig: { kid: "k1", signature: "AAAA", payload: V_OLD1 },
      },
      async () => true,
    );
    expect(r.kind).toBe("stale");
  });

  it("the current version is ok with no signature question at all", async () => {
    const r = await classifyCatalogSubmission(
      { declaredVersion: V_CURRENT, currentVersion: V_CURRENT, declaredVersionRow: null, currentInternalVersion: 5, now: NOW },
      async () => {
        throw new Error("should never be called");
      },
    );
    expect(r).toEqual({ kind: "ok", resolvedVersion: V_CURRENT });
  });
});
