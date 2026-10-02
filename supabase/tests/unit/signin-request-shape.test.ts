import { describe, expect, it } from "vitest";
import { parseSigninBody } from "../../functions/_shared/signin/request-shape.ts";

const JWT = "aaaa.bbbb.cccc";
const link = (over: Record<string, unknown> = {}) => ({ action: "link", provider: "apple", identityToken: JWT, authorizationCode: "code-1", nonce: "raw-nonce-0123", ...over });

describe("parseSigninBody", () => {
  it("accepts a link and an unlink", () => {
    expect(parseSigninBody(link())).toMatchObject({ ok: true, value: { action: "link", provider: "apple" } });
    expect(parseSigninBody({ action: "unlink", provider: "google" })).toEqual({ ok: true, value: { action: "unlink", provider: "google" } });
    expect(parseSigninBody(link({ emailProof: { code: "123456" } }))).toMatchObject({ ok: true, value: { emailProof: { code: "123456" } } });
  });

  it("there is no field that names an account: userId / user_id / uid / email / target are REJECTED, not ignored", () => {
    for (const k of ["userId", "user_id", "uid", "email", "targetUserId", "accountId"]) {
      const r = parseSigninBody(link({ [k]: "00000000-0000-4000-8000-000000000001" }));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.issues.some((i) => i.path === k)).toBe(true);
      const u = parseSigninBody({ action: "unlink", provider: "apple", [k]: "x" });
      expect(u.ok).toBe(false);
    }
  });

  it("emailProof carries a code only: an email or a user inside it is rejected", () => {
    expect(parseSigninBody(link({ emailProof: { code: "123456", email: "x@y.test" } })).ok).toBe(false);
    expect(parseSigninBody(link({ emailProof: { code: "12ab56" } })).ok).toBe(false);
    expect(parseSigninBody(link({ emailProof: { code: "12345" } })).ok).toBe(false);
    expect(parseSigninBody(link({ emailProof: "123456" })).ok).toBe(false);
  });

  it.each([
    ["not an object", "x"],
    ["an array", []],
    ["null", null],
    ["no action", { provider: "apple" }],
    ["an unknown action", { action: "merge", provider: "apple" }],
    ["unlink of an unknown provider", { action: "unlink", provider: "facebook" }],
    ["link with provider email", link({ provider: "email" })],
    ["a token that is not a JWT", link({ identityToken: "nope" })],
    ["an oversized token", link({ identityToken: "a.b." + "c".repeat(9000) })],
    ["a missing nonce", link({ nonce: undefined })],
    ["a short nonce", link({ nonce: "short" })],
    ["a nonce with spaces", link({ nonce: "has a space in it" })],
    ["an empty authorization code", link({ authorizationCode: "" })],
    ["an authorization code with whitespace", link({ authorizationCode: "a b" })],
    ["a non-string authorization code", link({ authorizationCode: 5 })],
  ])("rejects %s", (_n, body) => {
    expect(parseSigninBody(body).ok).toBe(false);
  });
});
