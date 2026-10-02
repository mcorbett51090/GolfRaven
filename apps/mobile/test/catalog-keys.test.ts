import { describe, expect, it } from "vitest";
import { assertReleaseKeyset, TRUSTED_KEYSET } from "../src/catalog/keys";
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
