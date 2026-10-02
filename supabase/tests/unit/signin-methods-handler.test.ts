// The §3.4 account-linking rules and the O12 provider-grant handling, at the handler level (pure, against fake-signin-repo.ts,
// which mirrors the 0035 definers; the same scenarios run against the real SQL in the Deno integration suite).

import { beforeEach, describe, expect, it } from "vitest";
import { HttpError } from "../../functions/_shared/http.ts";
import { handleLinkProvider, handleListMethods, handleUnlinkProvider, type SigninDeps } from "../../functions/_shared/signin/methods-handler.ts";
import { AppleGrantError, AppleTokenError, NotConfiguredError, VendorUnavailableError } from "../../functions/_shared/signin/errors.ts";
import { decryptToken } from "../../functions/_shared/signin/envelope.ts";
import { sha256Hex } from "../../functions/_shared/signin/bytes.ts";
import type { LinkRequest } from "../../functions/_shared/signin/request-shape.ts";
import type { AppleSigninPort, EmailOtpResult, EmailOtpVerifier, OtpFailureCounter } from "../../functions/_shared/signin/types.ts";
import type { VerifiedAppleIdentity } from "../../functions/_shared/signin/apple-id-token.ts";
import { makeFakeState, type FakeState } from "./fake-repo.ts";
import { addAccount, addKek, makeFakeRevocationDb, makeFakeSigninRepo, signinFake } from "./fake-signin-repo.ts";

const ALICE = "aaaaaaaa-0000-4000-8000-000000000001";
const BOB = "bbbbbbbb-0000-4000-8000-000000000002";
const CAROL = "cccccccc-0000-4000-8000-000000000003";

interface Harness {
  state: FakeState;
  deps: SigninDeps;
  log: Array<Record<string, unknown>>;
  apple: {
    port: AppleSigninPort;
    verifyCalls: Array<{ token: string; nonce: string }>;
    exchangeCalls: string[];
    revoked: string[];
    identity: VerifiedAppleIdentity;
    verifyError: unknown;
    exchangeError: unknown;
    grant: { refreshToken: string; subject: string };
    revokeError: unknown;
  };
  otp: {
    failures: Map<string, number>;
    verifierCalls: Array<{ email: string; code: string }>;
    result: EmailOtpResult;
    throws: boolean;
    /** The hour window the fake counter is currently in (what `reserve` returns), and every `release` it was asked to do. */
    windowStart: string;
    releases: Array<{ hash: string; windowStart: string }>;
    /** Runs inside the verifier, after its delay: lets a cell move the clock past the top of the hour mid-proof. */
    onVerify: (() => void) | null;
  };
}

function harness(actor = ALICE, opts: { appleConfigured?: boolean; crossAccountLink?: boolean } = {}): Harness {
  const state = makeFakeState();
  addKek(state, "k1");
  addAccount(state, ALICE, "alice@example.test");
  addAccount(state, BOB, "bob@example.test", [{ provider: "google", subject: "g-bob" }]);
  const apple: Harness["apple"] = {
    verifyCalls: [],
    exchangeCalls: [],
    revoked: [],
    identity: { subject: "apple-sub-alice", email: "alice@example.test", emailVerified: true, isPrivateRelay: false },
    verifyError: null,
    exchangeError: null,
    grant: { refreshToken: "r.refresh-token-A", subject: "apple-sub-alice" },
    revokeError: null,
    port: undefined as unknown as AppleSigninPort,
  };
  apple.port = {
    async verifyIdentityToken(token, nonce) {
      apple.verifyCalls.push({ token, nonce });
      if (apple.verifyError) throw apple.verifyError;
      return apple.identity;
    },
    async exchangeAuthorizationCode(code) {
      apple.exchangeCalls.push(code);
      if (apple.exchangeError) throw apple.exchangeError;
      return apple.grant;
    },
    async revokeRefreshToken(t) {
      apple.revoked.push(t);
      if (apple.revokeError) throw apple.revokeError;
    },
  };
  const otp: Harness["otp"] = { failures: new Map(), verifierCalls: [], result: { ok: false }, throws: false, windowStart: "2030-01-01T10:00:00.000Z", releases: [], onVerify: null };
  // Mirrors private.reserve_signin_otp_attempt / release_signin_otp_attempt: take-with-cap is ONE step, release never goes below zero, and
  // a release decrements only the window it names (`failures` holds the CURRENT window's counts; a release naming an older window is a no-op on it, L2).
  const counter: OtpFailureCounter = {
    async peek(h) {
      return otp.failures.get(h) ?? 0;
    },
    async reserve(h) {
      const n = otp.failures.get(h) ?? 0;
      if (n >= 5) return null;
      otp.failures.set(h, n + 1);
      return { used: n + 1, windowStart: otp.windowStart };
    },
    async release(h, windowStart) {
      otp.releases.push({ hash: h, windowStart });
      if (windowStart !== otp.windowStart) return;
      otp.failures.set(h, Math.max(0, (otp.failures.get(h) ?? 0) - 1));
    },
  };
  // A verifier that is NOT instantaneous: like the real GoTrue round trip it yields for ~25 ms, which is the window in which a
  // check-then-act counter (peek, verify, record) lets every parallel proof pass its read. With an instant verifier the round-1 shape
  // still passed the F3 cell (N1).
  const verifier: EmailOtpVerifier = {
    async verify(email, code) {
      otp.verifierCalls.push({ email, code });
      await new Promise((r) => setTimeout(r, 25));
      otp.onVerify?.();
      if (otp.throws) throw new Error("gotrue unreachable");
      return otp.result;
    },
  };
  const log: Array<Record<string, unknown>> = [];
  const configured = opts.appleConfigured ?? true;
  const deps: SigninDeps = {
    withRepo: (op) => op(makeFakeSigninRepo(state, actor, { crossAccountLink: opts.crossAccountLink })),
    otpFailures: counter,
    apple: configured ? apple.port : null,
    emailOtp: verifier,
    revocation: { db: makeFakeRevocationDb(state), apple: configured ? apple.port : null, google: null, log: (e) => log.push(e) },
    log: (e) => log.push(e),
  };
  return { state, deps, log, apple, otp };
}

const linkReq = (over: Partial<LinkRequest> = {}): LinkRequest => ({ action: "link", provider: "apple", identityToken: "aaa.bbb.ccc", authorizationCode: "auth-code-1", nonce: "raw-nonce-0123", ...over });

async function failure(p: Promise<unknown>): Promise<HttpError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof HttpError) return e;
    throw e;
  }
  throw new Error("expected an HttpError, got success");
}

describe("list", () => {
  it("lists the caller's own methods and marks the only one non-unlinkable", async () => {
    const h = harness();
    const r = await handleListMethods(h.deps);
    expect(r.methods).toEqual([{ provider: "email", linkedAt: expect.any(String), isPrivateRelay: false, canUnlink: false }]);
    expect(JSON.stringify(r)).not.toContain("alice@example.test"); // no subject, no email on the wire
  });

  it("never returns another account's methods", async () => {
    const h = harness(ALICE);
    expect((await handleListMethods(h.deps)).methods.map((m) => m.provider)).toEqual(["email"]);
    const hb = harness(BOB);
    expect((await handleListMethods(hb.deps)).methods.map((m) => m.provider).sort()).toEqual(["email", "google"]);
  });
});

describe("link (Apple): the pass cases", () => {
  it("links Apple to the caller, stores the refresh token envelope-encrypted, and returns the new method list", async () => {
    const h = harness();
    const r = await handleLinkProvider(linkReq(), ALICE, h.deps);
    expect(r.linkedTo).toBe("self");
    expect(r.linked).toEqual({ provider: "apple", created: true, isPrivateRelay: false });
    expect(r.methods!.map((m) => m.provider).sort()).toEqual(["apple", "email"]);
    expect(h.apple.verifyCalls).toEqual([{ token: "aaa.bbb.ccc", nonce: "raw-nonce-0123" }]);
    expect(h.apple.exchangeCalls).toEqual(["auth-code-1"]);

    const f = signinFake(h.state);
    expect(f.tokens).toHaveLength(1);
    const stored = f.tokens[0]!;
    expect(stored.userId).toBe(ALICE);
    expect(new TextDecoder("latin1").decode(stored.envelope.ciphertext)).not.toContain("refresh-token");
    expect(stored.envelope.kekId).toBe("k1");
    const kek = { kekId: "k1", key: f.keks.get("k1")! };
    expect(await decryptToken(stored.envelope, "apple", kek)).toBe("r.refresh-token-A");
  });

  it("the plaintext refresh token is never logged", async () => {
    const h = harness();
    await handleLinkProvider(linkReq(), ALICE, h.deps);
    expect(JSON.stringify(h.log)).not.toContain("refresh-token");
  });

  it("an Apple private-relay address is its own email: it links to the signed-in caller (rule 3) and is flagged", async () => {
    const h = harness();
    h.apple.identity = { subject: "apple-sub-alice", email: "xyz@privaterelay.appleid.com", emailVerified: true, isPrivateRelay: true };
    const r = await handleLinkProvider(linkReq(), ALICE, h.deps);
    expect(r.linkedTo).toBe("self");
    expect(r.linked.isPrivateRelay).toBe(true);
    expect(r.methods!.find((m) => m.provider === "apple")!.isPrivateRelay).toBe(true);
    expect(h.otp.verifierCalls).toHaveLength(0);
  });

  it("an Apple identity whose email is the caller's own links without any proof", async () => {
    const h = harness();
    const r = await handleLinkProvider(linkReq(), ALICE, h.deps);
    expect(r.linkedTo).toBe("self");
    expect(h.otp.verifierCalls).toHaveLength(0);
  });

  it("an Apple identity with no email links to the caller", async () => {
    const h = harness();
    h.apple.identity = { subject: "apple-sub-alice", email: null, emailVerified: false, isPrivateRelay: false };
    expect((await handleLinkProvider(linkReq(), ALICE, h.deps)).linkedTo).toBe("self");
  });

  it("an UNVERIFIED email claim is neither matched nor stored (it cannot trigger or dodge the proof rule)", async () => {
    const h = harness();
    h.apple.identity = { subject: "apple-sub-alice", email: "bob@example.test", emailVerified: false, isPrivateRelay: false };
    const r = await handleLinkProvider(linkReq(), ALICE, h.deps);
    expect(r.linkedTo).toBe("self");
    expect(signinFake(h.state).identities.find((i) => i.userId === ALICE && i.provider === "apple")!.email).toBeNull();
  });

  it("re-capturing the SAME Apple identity is idempotent (created: false) and queues the superseded token for revocation", async () => {
    const h = harness();
    await handleLinkProvider(linkReq(), ALICE, h.deps);
    h.apple.grant = { refreshToken: "r.refresh-token-B", subject: "apple-sub-alice" };
    const r = await handleLinkProvider(linkReq({ authorizationCode: "auth-code-2" }), ALICE, h.deps);
    expect(r.linked.created).toBe(false);
    const f = signinFake(h.state);
    expect(f.identities.filter((i) => i.userId === ALICE && i.provider === "apple")).toHaveLength(1);
    expect(f.tokens).toHaveLength(1);
    expect(f.queue.filter((q) => q.source === "replaced" && q.status === "pending")).toHaveLength(1);
  });
});

describe("link (Apple): must-fail", () => {
  it("Apple unconfigured -> 503 provider_not_configured, and nothing else is touched (never a fallback)", async () => {
    const h = harness(ALICE, { appleConfigured: false });
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([503, "provider_not_configured"]);
    expect(signinFake(h.state).calls).toEqual([]);
  });

  it("Google -> 501 provider_not_supported (TODO(P4): capture is not built)", async () => {
    const h = harness();
    const e = await failure(handleLinkProvider(linkReq({ provider: "google" }), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([501, "provider_not_supported"]);
  });

  it.each(["issuer", "audience", "nonce", "expired", "unknown_kid", "signature", "alg", "malformed"] as const)("identity token rejected (%s) -> 422 invalid_identity_token with only the closed reason; no exchange, no database call", async (reason) => {
    const h = harness();
    h.apple.verifyError = new AppleTokenError(reason);
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([422, "invalid_identity_token"]);
    expect(e.details).toEqual({ reason });
    expect(h.apple.exchangeCalls).toHaveLength(0);
    expect(signinFake(h.state).calls).toEqual([]);
  });

  it("Apple's keys unreachable -> 502 upstream_unavailable (not a verified token, not a 500)", async () => {
    const h = harness();
    h.apple.verifyError = new VendorUnavailableError("jwks_status_5xx");
    expect((await failure(handleLinkProvider(linkReq(), ALICE, h.deps))).status).toBe(502);
  });

  it("the Apple key unconfigured at exchange time -> 503 (fail closed), nothing linked", async () => {
    const h = harness();
    h.apple.exchangeError = new NotConfiguredError("apple_siwa_key");
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([503, "provider_not_configured"]);
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple")).toBe(false);
  });

  it("authorization code rejected by Apple -> 422, nothing linked", async () => {
    const h = harness();
    h.apple.exchangeError = new AppleGrantError("invalid_grant");
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([422, "authorization_code_rejected"]);
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple")).toBe(false);
    expect(signinFake(h.state).tokens).toHaveLength(0);
  });

  it("an authorization code that belongs to a DIFFERENT Apple user than the identity token -> 422, nothing linked, the stray grant revoked", async () => {
    const h = harness();
    h.apple.grant = { refreshToken: "r.refresh-token-X", subject: "someone-else" };
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([422, "authorization_code_mismatch"]);
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple")).toBe(false);
    expect(h.apple.revoked).toEqual(["r.refresh-token-X"]);
  });

  it("the account already has a DIFFERENT Apple ID linked -> 409 provider_already_linked, before any exchange", async () => {
    const h = harness();
    await handleLinkProvider(linkReq(), ALICE, h.deps);
    h.apple.exchangeCalls.length = 0;
    h.apple.identity = { subject: "a-different-apple-user", email: "alice@example.test", emailVerified: true, isPrivateRelay: false };
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([409, "provider_already_linked"]);
    expect(h.apple.exchangeCalls).toHaveLength(0);
  });

  it("an Apple identity that belongs to ANOTHER account is never moved -> 409 identity_conflict, and the grant minted for it is revoked", async () => {
    const h = harness();
    // Bob holds apple-sub-X already.
    signinFake(h.state).identities.push({ userId: BOB, provider: "apple", subject: "apple-sub-X", email: null, isPrivateRelay: false, linkedAt: h.state.now.toISOString() });
    h.apple.identity = { subject: "apple-sub-X", email: null, emailVerified: false, isPrivateRelay: false };
    h.apple.grant = { refreshToken: "r.refresh-token-Y", subject: "apple-sub-X" };
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([409, "identity_conflict"]);
    expect(signinFake(h.state).identities.find((i) => i.provider === "apple")!.userId).toBe(BOB);
    expect(signinFake(h.state).tokens).toHaveLength(0);
    expect(h.apple.revoked).toEqual(["r.refresh-token-Y"]);
  });

  it("the Vault KEK missing -> 503 kek_unavailable, nothing linked, the grant revoked", async () => {
    const h = harness();
    signinFake(h.state).keks.clear();
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([503, "kek_unavailable"]);
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple")).toBe(false);
    expect(h.apple.revoked).toEqual(["r.refresh-token-A"]);
  });

  it("a database failure after the exchange propagates, and the unrecorded grant is revoked (no live token nobody can revoke)", async () => {
    const h = harness();
    signinFake(h.state).failNext.set("storeToken", new Error("db down"));
    await expect(handleLinkProvider(linkReq(), ALICE, h.deps)).rejects.toThrow("db down");
    expect(h.apple.revoked).toEqual(["r.refresh-token-A"]);
  });

  it("if even that revocation fails, the orphan is logged (and the original error is still the one thrown)", async () => {
    const h = harness();
    signinFake(h.state).failNext.set("storeToken", new Error("db down"));
    h.apple.revokeError = new VendorUnavailableError("revoke_5xx");
    await expect(handleLinkProvider(linkReq(), ALICE, h.deps)).rejects.toThrow("db down");
    expect(h.log.some((e) => e.event === "signin_orphan_grant")).toBe(true);
  });
});

describe("link: never auto-link a social identity whose email matches an existing account (rules 1 and 2)", () => {
  beforeEach(() => undefined);

  it("Alice presents an Apple identity carrying BOB's email: 409 email_proof_required, NOTHING linked to anyone, no exchange", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    const e = await failure(handleLinkProvider(linkReq(), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([409, "email_proof_required"]);
    const f = signinFake(h.state);
    expect(f.identities.some((i) => i.provider === "apple")).toBe(false);
    expect(f.tokens).toHaveLength(0);
    expect(h.apple.exchangeCalls).toHaveLength(0);
    expect(h.otp.verifierCalls).toHaveLength(0);
  });

  it("edge mode (no cross-account link): Bob's email answers 501 email_proof_link_unavailable BEFORE any proof is invited, counted or consumed, and no code is exchanged", async () => {
    const h = harness(ALICE, { crossAccountLink: false });
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    for (const emailProof of [undefined, { code: "123456" }]) {
      const e = await failure(handleLinkProvider(linkReq(emailProof ? { emailProof } : {}), ALICE, h.deps));
      expect([e.status, e.code]).toEqual([501, "email_proof_link_unavailable"]);
    }
    const f = signinFake(h.state);
    expect(f.identities.some((i) => i.provider === "apple")).toBe(false);
    expect(f.tokens).toHaveLength(0);
    expect(h.apple.exchangeCalls).toHaveLength(0);
    expect(h.otp.verifierCalls).toHaveLength(0);
    expect(h.otp.failures.size).toBe(0);
  });

  it("edge mode still links the caller's OWN Apple identity (no foreign email, or the caller's own email match)", async () => {
    const h = harness(ALICE, { crossAccountLink: false });
    h.apple.identity = { subject: "apple-sub-own", email: null, emailVerified: false, isPrivateRelay: false };
    h.apple.grant = { refreshToken: "r.own", subject: "apple-sub-own" };
    const out = await handleLinkProvider(linkReq(), ALICE, h.deps);
    expect(out.linkedTo).toBe("self");
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple" && i.userId === ALICE)).toBe(true);
  });

  it("a relay address that is another account's email never takes the proof path: 409 email_belongs_to_another_account", async () => {
    const h = harness(ALICE);
    addAccount(h.state, CAROL, "relay9@privaterelay.appleid.com");
    h.apple.identity = { subject: "apple-sub-2", email: "relay9@privaterelay.appleid.com", emailVerified: true, isPrivateRelay: true };
    const e = await failure(handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([409, "email_belongs_to_another_account"]);
    expect(h.otp.verifierCalls).toHaveLength(0);
  });

  it("with a VALID proof the identity is linked to the account whose mailbox was proven (Bob), not to the caller", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    h.apple.grant = { refreshToken: "r.refresh-token-B1", subject: "apple-sub-1" };
    h.otp.result = { ok: true, userId: BOB };
    const r = await handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps);
    expect(r.linkedTo).toBe("proven_account");
    expect(r.methods).toBeNull(); // nothing about Bob's account is returned to Alice
    const f = signinFake(h.state);
    expect(f.identities.find((i) => i.provider === "apple")!.userId).toBe(BOB);
    expect(f.tokens.map((t) => t.userId)).toEqual([BOB]);
    expect(f.identities.filter((i) => i.userId === ALICE).map((i) => i.provider)).toEqual(["email"]);
    expect(h.otp.verifierCalls).toEqual([{ email: "bob@example.test", code: "123456" }]);
    expect([...h.otp.failures.values()].every((v) => v === 0)).toBe(true); // the attempt was reserved, then given back
  });

  it("a WRONG proof code: 422 email_proof_invalid with the attempts remaining, the failure counted, nothing linked, no exchange", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    h.otp.result = { ok: false };
    const e = await failure(handleLinkProvider(linkReq({ emailProof: { code: "000000" } }), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([422, "email_proof_invalid"]);
    expect(e.details).toEqual({ attemptsRemaining: 4 });
    expect([...h.otp.failures.values()]).toEqual([1]);
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple")).toBe(false);
    expect(h.apple.exchangeCalls).toHaveLength(0);
  });

  it("5 failed proofs per target email per hour: the 6th attempt is 429 even with the right code, and the verifier is not even called", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    h.otp.result = { ok: false };
    for (let i = 0; i < 5; i++) await failure(handleLinkProvider(linkReq({ emailProof: { code: "000000" } }), ALICE, h.deps));
    expect(h.otp.verifierCalls).toHaveLength(5);
    h.otp.result = { ok: true, userId: BOB };
    const e = await failure(handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([429, "rate_limited"]);
    expect(e.details).toEqual({ retryAfterSeconds: 3600 });
    expect(h.otp.verifierCalls).toHaveLength(5);
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple")).toBe(false);
  });

  it("the failure counter is per TARGET email: Bob's exhausted address does not block proofs for Carol's", async () => {
    const h = harness(ALICE);
    addAccount(h.state, CAROL, "carol@example.test");
    h.otp.failures.set(await sha256Hex("bob@example.test"), 9);
    h.apple.identity = { subject: "apple-sub-3", email: "carol@example.test", emailVerified: true, isPrivateRelay: false };
    h.apple.grant = { refreshToken: "r.refresh-token-C", subject: "apple-sub-3" };
    h.otp.result = { ok: true, userId: CAROL };
    expect((await handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps)).linkedTo).toBe("proven_account");
  });

  it("the target email is normalised before it is counted (case and whitespace cannot dodge the limit)", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    await failure(handleLinkProvider(linkReq({ emailProof: { code: "000000" } }), ALICE, h.deps));
    expect(h.otp.failures.get(await sha256Hex("bob@example.test"))).toBe(1);
  });

  it("F3: 20 PARALLEL wrong proofs reach the verifier at most 5 times (the attempt is reserved before verifying, not read-then-written)", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    h.otp.result = { ok: false };
    const slowVerify = h.otp.verifierCalls;
    const results = await Promise.all(Array.from({ length: 20 }, () => failure(handleLinkProvider(linkReq({ emailProof: { code: "000000" } }), ALICE, h.deps))));
    expect(slowVerify.length).toBe(5);
    expect(results.filter((e) => e.status === 422)).toHaveLength(5);
    expect(results.filter((e) => e.status === 429)).toHaveLength(15);
  });

  it("L2: a proof that straddles the top of the hour releases the window it reserved in and does NOT refund the new window", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    const hash = await sha256Hex("bob@example.test");
    const w1 = h.otp.windowStart;
    h.otp.throws = true; // a transport failure: the attempt is given back
    h.otp.onVerify = () => {
      // the clock passes the top of the hour while the proof is in flight; the new window already holds 3 attempts
      h.otp.windowStart = "2030-01-01T11:00:00.000Z";
      h.otp.failures.set(hash, 3);
    };
    expect((await failure(handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps))).status).toBe(502);
    expect(h.otp.releases).toEqual([{ hash, windowStart: w1 }]); // it named the window the attempt was TAKEN in
    expect(h.otp.failures.get(hash)).toBe(3); // the new window was not refunded
  });

  it("a transport failure of the OTP check is a 502 and is NOT counted against the address", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    h.otp.throws = true;
    expect((await failure(handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps))).status).toBe(502);
    expect([...h.otp.failures.values()].every((v) => v === 0)).toBe(true); // the attempt was reserved, then given back
  });

  it("a proof for a DIFFERENT account than the one looked up (the address changed hands) is refused: 409 email_proof_mismatch", async () => {
    const h = harness(ALICE);
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    h.otp.result = { ok: true, userId: CAROL };
    const e = await failure(handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps));
    expect([e.status, e.code]).toEqual([409, "email_proof_mismatch"]);
    expect(signinFake(h.state).identities.some((i) => i.provider === "apple")).toBe(false);
  });

  it("no OTP verifier configured -> 503, not a silent pass", async () => {
    const h = harness(ALICE);
    h.deps.emailOtp = null;
    h.apple.identity = { subject: "apple-sub-1", email: "bob@example.test", emailVerified: true, isPrivateRelay: false };
    expect((await failure(handleLinkProvider(linkReq({ emailProof: { code: "123456" } }), ALICE, h.deps))).status).toBe(503);
  });

  it("another user's id cannot be smuggled in: the handler takes the actor from the session only (the request type has no user field)", async () => {
    const h = harness(ALICE);
    // @ts-expect-error: there is deliberately no such field; at runtime an extra property is simply never read
    const sneaky: LinkRequest = { ...linkReq(), userId: BOB };
    await handleLinkProvider(sneaky, ALICE, h.deps);
    expect(signinFake(h.state).identities.find((i) => i.provider === "apple")!.userId).toBe(ALICE);
  });
});

describe("unlink", () => {
  async function linked(h: Harness) {
    await handleLinkProvider(linkReq(), ALICE, h.deps);
    h.apple.revoked.length = 0;
  }

  it("unlinks Apple while email remains: queues the grant, REVOKES IT AT APPLE with the right token, deletes the grant row", async () => {
    const h = harness();
    await linked(h);
    const r = await handleUnlinkProvider({ action: "unlink", provider: "apple" }, h.deps);
    expect(r.methods.map((m) => m.provider)).toEqual(["email"]);
    expect(h.apple.revoked).toEqual(["r.refresh-token-A"]);
    expect(r.revocation).toEqual([{ queueId: expect.any(String), provider: "apple", status: "revoked" }]);
    const f = signinFake(h.state);
    expect(f.tokens).toHaveLength(0);
    expect(f.queue.map((q) => [q.status, q.envelope])).toEqual([["revoked", null]]);
  });

  it("unlinking the LAST method is 422 last_sign_in_method and changes nothing", async () => {
    const h = harness();
    const e = await failure(handleUnlinkProvider({ action: "unlink", provider: "email" }, h.deps));
    expect([e.status, e.code]).toEqual([422, "last_sign_in_method"]);
    expect(signinFake(h.state).identities.filter((i) => i.userId === ALICE)).toHaveLength(1);
  });

  it("unlinking a method that is not linked is 404", async () => {
    const h = harness();
    const e = await failure(handleUnlinkProvider({ action: "unlink", provider: "google" }, h.deps));
    expect(e.status).toBe(404);
  });

  it("another account's method cannot be unlinked through yours: Alice unlinking google is 404 and Bob's google is intact", async () => {
    const h = harness(ALICE);
    expect((await failure(handleUnlinkProvider({ action: "unlink", provider: "google" }, h.deps))).status).toBe(404);
    expect(signinFake(h.state).identities.some((i) => i.userId === BOB && i.provider === "google")).toBe(true);
  });

  it("an Apple outage during the unlink does not undo it: the method is gone, the grant stays queued for retry", async () => {
    const h = harness();
    await linked(h);
    h.apple.revokeError = new VendorUnavailableError("revoke_5xx");
    const r = await handleUnlinkProvider({ action: "unlink", provider: "apple" }, h.deps);
    expect(r.methods.map((m) => m.provider)).toEqual(["email"]);
    expect(r.revocation).toEqual([{ queueId: expect.any(String), provider: "apple", status: "queued_for_retry", error: "revoke_5xx" }]);
    const q = signinFake(h.state).queue[0]!;
    expect(q.status).toBe("pending");
    expect(q.lastError).toBe("revoke_5xx");
    expect(q.envelope).not.toBeNull();
  });

  it("an email method with no stored grant unlinks and attempts no revocation", async () => {
    const h = harness();
    await linked(h);
    const r = await handleUnlinkProvider({ action: "unlink", provider: "email" }, h.deps);
    expect(r.revocation).toEqual([]);
    expect(h.apple.revoked).toEqual([]);
    expect(r.methods.map((m) => m.provider)).toEqual(["apple"]);
  });
});
