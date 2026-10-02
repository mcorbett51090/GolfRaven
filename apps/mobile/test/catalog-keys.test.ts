import { describe, expect, it } from "vitest";
import { parseCatalogVersion } from "@golfraven/catalog-tools/manifest-core";
import { assertReleaseKeyset, MIN_CATALOG_VERSION, resolveTrustAnchors, TRUSTED_KEYSET } from "../src/catalog/keys";
import { makeKey } from "./support/signed-catalog";

describe("assertReleaseKeyset", () => {
  it("accepts two distinct well-formed keys", () => {
    expect(() => assertReleaseKeyset([makeKey("k-a").trusted, makeKey("k-b").trusted])).not.toThrow();
  });
  it("needs at least two (rotation, §4.8)", () => {
    expect(() => assertReleaseKeyset([])).toThrow(/at least 2/);
    expect(() => assertReleaseKeyset([makeKey("k-a").trusted])).toThrow(/at least 2/);
  });
  it("rejects duplicates, bad kids and wrong-size keys", () => {
    const a = makeKey("k-a").trusted;
    expect(() => assertReleaseKeyset([a, { ...a }])).toThrow(/duplicate/);
    expect(() => assertReleaseKeyset([a, { kid: "Bad Kid", publicKeyB64Url: a.publicKeyB64Url }])).toThrow(/malformed kid/);
    expect(() => assertReleaseKeyset([a, { kid: "k-b", publicKeyB64Url: "AAAA" }])).toThrow(/want 32/);
    expect(() => assertReleaseKeyset([a, { kid: "k-b", publicKeyB64Url: "!!!" }])).toThrow(/base64url/);
  });
});

describe("the compiled-in keyset", () => {
  it("is empty until the §3.5 production keyset exists (P3 gate) — so a build verifies nothing", () => {
    expect(TRUSTED_KEYSET).toHaveLength(0);
    expect(() => assertReleaseKeyset(TRUSTED_KEYSET)).toThrow();
  });
});

describe("the compiled-in minimum catalogVersion", () => {
  it("is empty (no floor yet) or a well-formed yyyymmdd-sha7 version — a typo here would refuse every catalog", () => {
    expect(MIN_CATALOG_VERSION === "" || parseCatalogVersion(MIN_CATALOG_VERSION) !== undefined).toBe(true);
  });
});

describe("resolveTrustAnchors (assertReleaseKeyset at startup, never throwing)", () => {
  const two = [makeKey("k-a").trusted, makeKey("k-b").trusted];

  it("release build + releasable keyset: the keys are used", () => {
    expect(resolveTrustAnchors(two, false)).toEqual({ trustedKeys: two, problem: null });
  });
  it("release build + EMPTY keyset (every build today): fails closed with a reason — and does not throw", () => {
    const r = resolveTrustAnchors(TRUSTED_KEYSET, false);
    expect(r.trustedKeys).toEqual([]);
    expect(r.problem).toMatch(/at least 2/);
  });
  it("release build + a keyset that is not releasable trusts NONE of its keys (not even the valid one)", () => {
    const a = makeKey("k-a").trusted;
    expect(resolveTrustAnchors([a], false)).toEqual({ trustedKeys: [], problem: expect.stringMatching(/at least 2/) as string });
    expect(resolveTrustAnchors([a, { kid: "Bad Kid", publicKeyB64Url: a.publicKeyB64Url }], false).trustedKeys).toEqual([]);
  });
  it("development build: the check does not apply (tests / local keysets use fewer than two keys)", () => {
    const one = [makeKey("k-a").trusted];
    expect(resolveTrustAnchors(one, true)).toEqual({ trustedKeys: one, problem: null });
    expect(resolveTrustAnchors([], true)).toEqual({ trustedKeys: [], problem: null });
  });
});
