/**
 * The sign-in state machines (build plan §3.4/§7.8; P4 AT 17, 20): age first for every provider, the nonce split (hash to Apple, raw to the
 * server), Google "not configured", the Apple-button rule, and the email OTP request/verify path.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { apiError, b64url, FakeLinkApi, FakeApple, FakeAuth, FakeGoogle, fixedRandom, gateIn, jwt } from "./support/fakes";
import {
  bytesToBase64Url,
  createNonce,
  emailFromIdentityToken,
  offeredProviders,
  randomUuid,
  requestEmailSignInCode,
  signInWithApple,
  signInWithGoogle,
  startSignIn,
  verifyEmailSignInCode,
  type SignInDeps,
} from "../src/signin";
import { AuthError } from "../src/auth";

async function deps(state: "unknown" | "eligible" | "ineligible", over: Partial<SignInDeps> = {}) {
  const apple = new FakeApple();
  const google = new FakeGoogle();
  const auth = new FakeAuth();
  const api = new FakeLinkApi();
  const d: SignInDeps = { gate: await gateIn(state), auth, api, apple, google, random: fixedRandom(), ...over };
  return { d, apple, google, auth, api };
}

describe("offeredProviders — Apple 4.8 / AT 17: the Apple button is present in every build that offers Google", () => {
  it.each([
    ["ios", true],
    ["ios", false],
    ["android", true],
    ["android", false],
    ["web", true],
  ])("%s, google configured = %s", (platform, googleConfigured) => {
    const list = offeredProviders({ platform, googleConfigured });
    if (googleConfigured) {
      expect(list).toContain("google");
      expect(list).toContain("apple");
      expect(list.indexOf("apple")).toBeLessThan(list.indexOf("google"));
    }
    expect(list).toContain("email");
  });

  it("iOS always shows Apple (native); a build that offers neither Google nor Apple natively shows email only", () => {
    expect(offeredProviders({ platform: "ios", googleConfigured: false })).toEqual(["apple", "email"]);
    expect(offeredProviders({ platform: "android", googleConfigured: false })).toEqual(["email"]);
    expect(offeredProviders({ platform: "android", googleConfigured: true })).toEqual(["apple", "google", "email"]);
  });
});

describe("the age gate comes before ANY provider (O18, AT 20)", () => {
  it.each(["apple", "google"] as const)("%s: gate unknown => age_required, and neither the adapter nor the auth server is touched", async (id) => {
    const { d, apple, google, auth, api } = await deps("unknown");
    google.availabilityResult = "available";
    expect(await startSignIn(id, d)).toEqual({ status: "age_required" });
    expect(apple.availabilityCalls + google.availabilityCalls).toBe(0);
    expect(apple.hashedNonces).toEqual([]);
    expect(google.hashedNonces).toEqual([]);
    expect(auth.idTokenCalls).toEqual([]);
    expect(api.calls).toEqual([]);
  });

  it.each(["apple", "google"] as const)("%s: after an under-age answer it is blocked, on every retry, and nothing is called", async (id) => {
    const { d, apple, google, auth, api } = await deps("ineligible");
    google.availabilityResult = "available";
    for (let i = 0; i < 3; i += 1) expect(await startSignIn(id, d)).toEqual({ status: "blocked" });
    expect(await d.gate.submitBirthYear(1980, 16)).toEqual({ status: "blocked" });
    expect(await startSignIn(id, d)).toEqual({ status: "blocked" });
    expect(apple.hashedNonces.length + google.hashedNonces.length).toBe(0);
    expect(auth.idTokenCalls).toEqual([]);
    expect(api.calls).toEqual([]);
  });

  it("email: requesting a code and verifying one are both refused before the gate passes; Auth is not called", async () => {
    for (const state of ["unknown", "ineligible"] as const) {
      const { d, auth } = await deps(state);
      const want = state === "unknown" ? "age_required" : "blocked";
      expect(await requestEmailSignInCode("a@example.test", d)).toEqual({ status: want });
      expect(await verifyEmailSignInCode("a@example.test", "123456", d)).toEqual({ status: want });
      expect(auth.emailCodeRequests).toEqual([]);
      expect(auth.verifyCalls).toEqual([]);
    }
  });

  it("an eligible gate lets each provider through exactly once", async () => {
    const { d, apple, auth } = await deps("eligible");
    expect(await signInWithApple(d)).toMatchObject({ status: "signed_in" });
    expect(apple.hashedNonces).toHaveLength(1);
    expect(auth.idTokenCalls).toHaveLength(1);
  });
});

describe("the Apple nonce: the HASH goes to Apple, the RAW value goes to the server (server F1)", () => {
  it("the adapter receives sha256(raw) as lowercase hex; Supabase Auth and the grant-capture call receive raw; never the other way round", async () => {
    const { d, apple, auth, api } = await deps("eligible");
    const r = await signInWithApple(d);
    expect(r).toMatchObject({ status: "signed_in", grantCaptured: true });

    const toApple = apple.hashedNonces[0]!;
    const toAuth = auth.idTokenCalls[0]!.nonce;
    const toServer = api.calls[0]!.nonce;

    expect(toAuth).toBe(toServer); // one raw nonce for both
    expect(toApple).toMatch(/^[0-9a-f]{64}$/);
    expect(toApple).toBe(createHash("sha256").update(toServer, "utf8").digest("hex"));
    expect(toApple).not.toBe(toServer); // the hash is not the raw value
    expect(toServer).toMatch(/^[A-Za-z0-9._~+/=-]{16,256}$/); // the server's own NONCE_RE (request-shape.ts)
    expect(toServer).not.toMatch(/^[0-9a-f]{64}$/); // and it is not the hex digest
  });

  it("the Apple adapter is never handed the raw nonce, in any call", async () => {
    const { d, apple, auth } = await deps("eligible");
    await signInWithApple(d);
    expect(apple.hashedNonces).not.toContain(auth.idTokenCalls[0]!.nonce);
  });

  it("a fresh nonce per attempt", async () => {
    const a = await deps("eligible", { random: fixedRandom(1) });
    const b = await deps("eligible", { random: fixedRandom(2) });
    await signInWithApple(a.d);
    await signInWithApple(b.d);
    expect(a.auth.idTokenCalls[0]!.nonce).not.toBe(b.auth.idTokenCalls[0]!.nonce);
  });

  it("createNonce: 32 random bytes as base64url (43 chars), hash = sha256 of that STRING; a bad random source is refused", () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 3);
    const n = createNonce(() => bytes);
    expect(n.raw).toBe(Buffer.from(bytes).toString("base64url"));
    expect(n.raw).toHaveLength(43);
    expect(n.hashed).toBe(createHash("sha256").update(n.raw, "utf8").digest("hex"));
    expect(() => createNonce(() => new Uint8Array(16))).toThrow();
    expect(() => createNonce(() => new Uint8Array(32))).toThrow(/all zeros/);
  });

  it("bytesToBase64Url agrees with Node for every length (no padding)", () => {
    for (let len = 0; len < 40; len += 1) {
      const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 37 + len) % 256);
      expect(bytesToBase64Url(bytes)).toBe(Buffer.from(bytes).toString("base64url"));
    }
  });

  it("randomUuid is a version-4 UUID", () => {
    const id = randomUuid(fixedRandom(9));
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe("Apple: the rest of the flow", () => {
  it("grant capture sends the SAME token, the authorization code and the raw nonce, for the caller's own account, with no emailProof", async () => {
    const { d, apple, api } = await deps("eligible");
    await signInWithApple(d);
    expect(api.calls).toHaveLength(1);
    const call = api.calls[0]!;
    expect(call).toEqual({
      provider: "apple",
      identityToken: (apple.result as { identityToken: string }).identityToken,
      authorizationCode: "auth-code-1",
      nonce: expect.any(String),
    });
    expect("emailProof" in call).toBe(false);
  });

  it("a failed grant capture does not undo the sign-in: signed in, grantCaptured false", async () => {
    const { d, api } = await deps("eligible");
    api.script = [apiError("conflict", 409, "email_proof_required", { emailProofRequired: true })];
    expect(await signInWithApple(d)).toMatchObject({ status: "signed_in", grantCaptured: false });
    // and a sign-in NEVER answers the proof challenge by itself: exactly one link call, no retry with a proof
    expect(api.calls).toHaveLength(1);
    expect(api.calls.some((c) => c.emailProof !== undefined)).toBe(false);
  });

  it("unsupported platform (Apple on Android): reported, no nonce made, no auth call", async () => {
    const { d, apple, auth } = await deps("eligible");
    apple.availabilityResult = "unsupported_platform";
    expect(await signInWithApple(d)).toEqual({ status: "unsupported_platform" });
    expect(apple.hashedNonces).toEqual([]);
    expect(auth.idTokenCalls).toEqual([]);
  });

  it("the player cancelling Apple's sheet is not an error", async () => {
    const { d, apple, auth } = await deps("eligible");
    apple.result = { status: "cancelled" };
    expect(await signInWithApple(d)).toEqual({ status: "cancelled" });
    expect(auth.idTokenCalls).toEqual([]);
  });

  it("an adapter failure and an auth failure are reported, and no grant capture is attempted after an auth failure", async () => {
    const a = await deps("eligible");
    a.apple.throws = new Error("native exploded");
    expect(await signInWithApple(a.d)).toEqual({ status: "failed", reason: "unknown" });
    const b = await deps("eligible");
    b.auth.failWith = new AuthError("network");
    expect(await signInWithApple(b.d)).toEqual({ status: "failed", reason: "network" });
    expect(b.api.calls).toEqual([]);
    const c = await deps("eligible");
    c.auth.failWith = new AuthError("rate_limited");
    expect(await signInWithApple(c.d)).toEqual({ status: "failed", reason: "rate_limited" });
  });
});

describe("Google: integration layer present, native SDK absent => 'not configured' (needs owner keys + a native package)", () => {
  it("not configured: age passed, but nothing is called and no nonce is used", async () => {
    const { d, google, auth } = await deps("eligible");
    expect(google.availabilityResult).toBe("not_configured");
    expect(await signInWithGoogle(d)).toEqual({ status: "not_configured" });
    expect(google.hashedNonces).toEqual([]);
    expect(auth.idTokenCalls).toEqual([]);
  });

  it("configured: same nonce discipline as Apple, and no grant capture (the server's Google link is a 501)", async () => {
    const { d, google, auth, api } = await deps("eligible");
    google.availabilityResult = "available";
    const r = await signInWithGoogle(d);
    expect(r).toMatchObject({ status: "signed_in", grantCaptured: null });
    expect(google.hashedNonces[0]).toBe(createHash("sha256").update(auth.idTokenCalls[0]!.nonce, "utf8").digest("hex"));
    expect(auth.idTokenCalls[0]).toMatchObject({ provider: "google" });
    expect(api.calls).toEqual([]);
  });

  it("the shipped Google adapter says not configured", async () => {
    const { notConfiguredGoogle } = await import("../src/signin");
    expect(await notConfiguredGoogle().availability()).toBe("not_configured");
    await expect(notConfiguredGoogle().authenticate("x")).rejects.toThrow(/not configured/);
  });
});

describe("email OTP: request, then verify (Supabase Auth, codes not links)", () => {
  it("the request creates the account on first use (createUser true) and trims the address", async () => {
    const { d, auth } = await deps("eligible");
    expect(await requestEmailSignInCode("  Alice@Example.test ", d)).toEqual({ status: "sent" });
    expect(auth.emailCodeRequests).toEqual([{ email: "Alice@Example.test", createUser: true }]);
  });

  it("a malformed address is refused locally", async () => {
    const { d, auth } = await deps("eligible");
    for (const bad of ["", "no-at", "a@b", "a b@c.d"]) expect(await requestEmailSignInCode(bad, d)).toEqual({ status: "failed", reason: "invalid_email" });
    expect(auth.emailCodeRequests).toEqual([]);
  });

  it("verify: a 6-10 digit code starts the session; anything else is refused without a call", async () => {
    const { d, auth } = await deps("eligible");
    for (const bad of ["", "12345", "12345678901", "12a456"]) expect(await verifyEmailSignInCode("a@example.test", bad, d)).toEqual({ status: "failed", reason: "invalid_code" });
    expect(auth.verifyCalls).toEqual([]);
    const r = await verifyEmailSignInCode("a@example.test", " 123456 ", d);
    expect(r).toMatchObject({ status: "signed_in", session: { provider: "email" }, grantCaptured: null });
    expect(auth.verifyCalls).toEqual([{ email: "a@example.test", code: "123456" }]);
  });

  it("auth failures map to reasons the screen has copy for", async () => {
    const cases: [AuthError, string][] = [
      [new AuthError("invalid_credentials", { status: 403 }), "invalid_code"],
      [new AuthError("rate_limited", { status: 429 }), "rate_limited"],
      [new AuthError("network"), "network"],
      [new AuthError("other"), "unknown"],
    ];
    for (const [err, reason] of cases) {
      const { d, auth } = await deps("eligible");
      auth.failWith = err;
      expect(await verifyEmailSignInCode("a@example.test", "123456", d)).toEqual({ status: "failed", reason });
      const req = await requestEmailSignInCode("a@example.test", d);
      expect(req).toEqual({ status: "failed", reason });
    }
  });
});

describe("emailFromIdentityToken (read, not trusted: only to know where to send a proof code)", () => {
  it("reads a verified address; ignores an unverified or malformed one", () => {
    expect(emailFromIdentityToken(jwt({ email: "bob@example.test", email_verified: true }))).toBe("bob@example.test");
    expect(emailFromIdentityToken(jwt({ email: "bob@example.test", email_verified: "true" }))).toBe("bob@example.test");
    expect(emailFromIdentityToken(jwt({ email: "bob@example.test", email_verified: "false" }))).toBeNull();
    expect(emailFromIdentityToken(jwt({ email: "bob@example.test" }))).toBeNull();
    expect(emailFromIdentityToken(jwt({ email: "not an email", email_verified: true }))).toBeNull();
    expect(emailFromIdentityToken("garbage")).toBeNull();
    expect(emailFromIdentityToken(`a.${b64url("not json")}.c`)).toBeNull();
  });
});
