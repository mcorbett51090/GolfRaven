// supabase/tests/unit/checkin-token-idempotency.test.ts
//
// checkin/token-handler.ts: (1) idempotent redemption (a lost response must not lose the co-signal), (2) the no-attestation rule that NARROWS the
// self-reported capability claim for honest clients, and (3) the fake Repo's `consumeForFix` mirroring the real statement's CHALLENGE window (privileged.ts).

import { describe, expect, it } from "vitest";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.js";
import { handleTokenRequest, type CheckinAttestationDeps } from "../../functions/_shared/checkin/token-handler.js";
import type { TokenRequest } from "../../functions/_shared/checkin/token-request-shape.js";
import { HttpError } from "../../functions/_shared/http.js";
import { verifyP256WebCrypto } from "../../functions/_shared/rewards/app-attest.js";
import { fromBase64UrlStrict, toBase64Url, toHex } from "../../functions/_shared/rewards/binding.js";
import { computeIosCheckinBinding } from "../../functions/_shared/rewards/string-binding.js";
import { VendorUnavailableError, type AndroidPort } from "../../functions/_shared/rewards/types.js";
import { buildIosAssertionPort } from "../../functions/_shared/rewards/verification-ports.js";
import { FAKE_DEVICE_ID, makeFakeRepo, makeFakeState, type FakeState } from "./fake-repo.js";
import { rewardsState, seedDevice } from "./fake-rewards-repo.js";
import { buildAssertion, generateP256, sha256, toB64, type TestKey } from "./rewards-test-crypto.js";

const USER_A = "user-a";
const USER_B = "user-b";
const D1 = FAKE_DEVICE_ID;
const APP_ID = "TEAMID1234.com.example.golfraven";
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const keyIdOf = async (key: TestKey) => toB64(await sha256(key.publicKeyRaw));
const MIN = 60_000;

async function codeOf(p: Promise<unknown>): Promise<string | null> {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return e.code;
    throw e;
  }
}

async function issue(state: FakeState, opts: { prefetch?: boolean; uid?: string } = {}) {
  const [c] = await handleChallengeRequest({ deviceId: D1, ...(opts.prefetch ? { prefetchCount: 1 } : {}) }, makeFakeRepo(state, opts.uid ?? USER_A), randomBytes, digestHex);
  return { id: c!.id, nonce: c!.nonce, nonceBytes: fromBase64UrlStrict(c!.nonce)! };
}
const tokens = (s: FakeState) => [...s.checkinTokens.values()];
const attestationSignals = (s: FakeState) => rewardsState(s).signals.filter((x) => x.kind === "attestation_failed");
const noAtt = (ch: { id: string; nonce: string }, hardware = false): TokenRequest => ({ challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: hardware });
const run = (s: FakeState, body: TokenRequest, deps?: CheckinAttestationDeps, uid = USER_A) => handleTokenRequest(body, makeFakeRepo(s, uid), digestHex, deps);
const iosDeps = (port = buildIosAssertionPort(APP_ID, { sha256, verifyP256: verifyP256WebCrypto })): CheckinAttestationDeps => ({ userId: USER_A, ports: { ios: port, android: null }, sha256 });

async function iosWorld(counter = 5) {
  const state = makeFakeState();
  const key = await generateP256();
  seedDevice(state, { id: D1, userId: USER_A, platform: "ios", attestKeyId: await keyIdOf(key), attestCounter: counter, attestPublicKey: key.publicKeyRaw });
  return { state, key };
}
async function iosReq(ch: { id: string; nonce: string }, key: TestKey, counter: number): Promise<TokenRequest> {
  const hash = await computeIosCheckinBinding(sha256, { challengeId: ch.id, deviceId: D1, nonce: ch.nonce, userId: USER_A });
  const built = await buildAssertion({ key, appId: APP_ID, counter, clientDataHash: hash });
  return { challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: true, attestation: { platform: "ios", keyId: await keyIdOf(key), assertion: built.assertionB64 } };
}
const androidAttestedPort = (): AndroidPort & { calls: number } => {
  const p = {
    calls: 0,
    async verifyIntegrity() {
      p.calls++;
      return { grade: "attested" as const };
    },
  };
  return p;
};

describe("idempotent redemption (a lost response must not lose the co-signal)", () => {
  it("a repeat of an `attested` redemption — even with the SAME iOS assertion and counter — returns the ORIGINAL jti, expiry and grade; nothing is re-verified, re-counted or re-issued", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issue(state);
    const req = await iosReq(ch, key, 6);
    const spyReal = buildIosAssertionPort(APP_ID, { sha256, verifyP256: verifyP256WebCrypto });
    let verifications = 0;
    const deps = iosDeps({ verifyAssertion: (i) => (verifications++, spyReal.verifyAssertion(i)) });
    const first = await run(state, req, deps);
    expect(first.attestationGrade).toBe("attested");
    state.now = new Date(state.now.getTime() + 30_000); // the retry arrives later
    const again = await run(state, req, deps);
    expect(again).toEqual(first);
    expect(verifications).toBe(1); // the repeat never reached the verifier, so a repeat counter is not a counter failure
    expect(rewardsState(state).deviceAttest.get(D1)!.attestCounter).toBe(6);
    expect(tokens(state)).toHaveLength(1);
    expect(attestationSignals(state)).toEqual([]);
    // and again, and again
    expect(await run(state, req, deps)).toEqual(first);
  });

  it("a repeat of a `failed` redemption returns `failed` (same jti) even when the repeat carries a VALID, higher-counter assertion: never re-graded upward; no second signal", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issue(state);
    const first = await run(state, await iosReq(ch, key, 5), iosDeps()); // replayed counter -> failed
    expect(first.attestationGrade).toBe("failed");
    const again = await run(state, await iosReq(ch, key, 6), iosDeps()); // a perfectly valid assertion this time
    expect(again).toEqual(first);
    expect(rewardsState(state).deviceAttest.get(D1)!.attestCounter).toBe(5);
    expect(attestationSignals(state)).toHaveLength(1);
    expect(tokens(state)).toHaveLength(1);
  });

  it("a repeat of an `unattestable` redemption returns `unattestable` even when the repeat carries an attestation that would grade `attested`", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    const ch = await issue(state);
    const first = await run(state, noAtt(ch, false));
    expect(first.attestationGrade).toBe("unattestable");
    const port = androidAttestedPort();
    const body: TokenRequest = { ...noAtt(ch, true), attestation: { platform: "android", integrityToken: "TOKEN.abc" } };
    const again = await run(state, body, { userId: USER_A, ports: { ios: null, android: port }, sha256 });
    expect(again).toEqual(first);
    expect(port.calls).toBe(0);
    expect(tokens(state)).toHaveLength(1);
  });

  it("a repeat is answered even though the vendor is down or the platform is unconfigured: it never verifies", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    const ch = await issue(state);
    const up = androidAttestedPort();
    const body: TokenRequest = { ...noAtt(ch, true), attestation: { platform: "android", integrityToken: "TOKEN.abc" } };
    const first = await run(state, body, { userId: USER_A, ports: { ios: null, android: up }, sha256 });
    const down: AndroidPort = {
      async verifyIntegrity() {
        throw new VendorUnavailableError("503");
      },
    };
    expect(await run(state, body, { userId: USER_A, ports: { ios: null, android: down }, sha256 })).toEqual(first);
    expect(await run(state, body, undefined)).toEqual(first); // not configured at all
  });

  it("works after the CHALLENGE has expired, as long as the issued token is still valid (a live challenge lives 120 s, the token 15 min)", async () => {
    const state = makeFakeState();
    const ch = await issue(state);
    const first = await run(state, noAtt(ch));
    state.now = new Date(state.now.getTime() + 10 * MIN);
    expect(await run(state, noAtt(ch))).toEqual(first);
  });

  it("is `challenge_used` once the issued token has EXPIRED", async () => {
    const state = makeFakeState();
    const ch = await issue(state);
    await run(state, noAtt(ch));
    state.now = new Date(state.now.getTime() + 16 * MIN);
    expect(await codeOf(run(state, noAtt(ch)))).toBe("challenge_used");
  });

  it("is `challenge_used` once the token has been CONSUMED by a fix (it is no longer a valid session)", async () => {
    const state = makeFakeState();
    const ch = await issue(state);
    const first = await run(state, noAtt(ch));
    const consumed = await makeFakeRepo(state, USER_A).checkinToken.consumeForFix(first.jti, D1, state.now.getTime());
    expect(consumed).not.toBeNull();
    expect(await codeOf(run(state, noAtt(ch)))).toBe("challenge_used");
  });

  it("a DIFFERENT nonce stays `challenge_used`; an undecodable nonce too; another account stays 404; a used challenge with no token stays `challenge_used`", async () => {
    const state = makeFakeState();
    const ch = await issue(state);
    await run(state, noAtt(ch));
    const other = toBase64Url(randomBytes(32));
    expect(await codeOf(run(state, { ...noAtt(ch), nonce: other }))).toBe("challenge_used");
    expect(await codeOf(run(state, { ...noAtt(ch), nonce: "***" }))).toBe("challenge_used");
    expect(await codeOf(run(state, noAtt(ch), undefined, USER_B))).toBe("not_found");
    // a used challenge that produced no token (should not happen; fail closed)
    const ch2 = await issue(state);
    state.challenges.get(ch2.id)!.usedAt = state.now.toISOString();
    expect(await codeOf(run(state, noAtt(ch2)))).toBe("challenge_used");
    expect(tokens(state)).toHaveLength(1);
  });

  it("the repeat belongs to the (challenge, device) it was issued for: the returned token is the one for THIS challenge, and a second challenge gets its own token", async () => {
    const state = makeFakeState();
    const a = await issue(state);
    const b = await issue(state);
    const ta = await run(state, noAtt(a));
    const tb = await run(state, noAtt(b));
    expect(ta.jti).not.toBe(tb.jti);
    expect(await run(state, noAtt(a))).toEqual(ta);
    expect(await run(state, noAtt(b))).toEqual(tb);
    expect(tokens(state)).toHaveLength(2);
  });

  it("a request that LOSES the atomic consume to an identical one answers with the winner's token (the concurrent retry)", async () => {
    const state = makeFakeState();
    const ch = await issue(state);
    const first = await run(state, noAtt(ch));
    // The loser read the challenge BEFORE the winner committed (usedAt null) and its consume then matches no row.
    const repo = makeFakeRepo(state, USER_A);
    const stale = { ...(await repo.challenge.getOwn(ch.id))!, usedAt: null };
    const racing = { ...repo, challenge: { ...repo.challenge, getOwn: async () => stale } };
    expect(await handleTokenRequest(noAtt(ch), racing, digestHex)).toEqual(first);
    // ...but with a WRONG nonce the lost race is still a refusal
    expect(await codeOf(handleTokenRequest({ ...noAtt(ch), nonce: toBase64Url(randomBytes(32)) }, racing, digestHex))).toBe("challenge_not_consumable");
  });
});

describe("the no-attestation rule: a self-reported `cannot attest` is not believed for a device that has attested (narrowed for honest clients, not closed: the device id is client-chosen)", () => {
  const dodgeSignal = (s: FakeState) => s.fraudSignals.filter((x) => x.kind === "attestation_failed");

  it("iOS: a device with a REGISTERED App Attest key that sends no attestation is `failed` + signal, whatever it claims", async () => {
    for (const claim of [false, true]) {
      const { state } = await iosWorld(5);
      const ch = await issue(state);
      const out = await run(state, noAtt(ch, claim));
      expect(out.attestationGrade, `claim ${claim}`).toBe("failed");
      expect(dodgeSignal(state)).toHaveLength(1);
      // The same vocabulary as rewards-activate (one `reasons` array, source named), and the proven case is told apart from the claimed one.
      expect(dodgeSignal(state)[0]!.detail).toMatchObject({
        challengeId: ch.id,
        deviceId: D1,
        platform: null,
        source: "checkin-token",
        reasons: claim ? ["no_attestation_token"] : ["no_attestation_token", "device_has_attested_before"],
      });
    }
  });

  it("iOS: a device with NO registered key keeps the claim's meaning: false -> `unattestable` (no signal), true -> `failed`", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "ios", attestKeyId: null, attestPublicKey: null });
    const c1 = await issue(state);
    expect((await run(state, noAtt(c1, false))).attestationGrade).toBe("unattestable");
    expect(dodgeSignal(state)).toEqual([]);
    const c2 = await issue(state);
    expect((await run(state, noAtt(c2, true))).attestationGrade).toBe("failed");
  });

  it("Android: a device that was already issued an `attested` token is `failed` when it later sends none and claims it cannot attest", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    const c1 = await issue(state);
    const port = androidAttestedPort();
    const attested = await run(state, { ...noAtt(c1, true), attestation: { platform: "android", integrityToken: "TOKEN.abc" } }, { userId: USER_A, ports: { ios: null, android: port }, sha256 });
    expect(attested.attestationGrade).toBe("attested");
    const c2 = await issue(state);
    const out = await run(state, noAtt(c2, false));
    expect(out.attestationGrade).toBe("failed");
    expect(dodgeSignal(state)).toHaveLength(1);
  });

  it("Android: a prior `failed` or `unattestable` token is NOT evidence of capability; neither is another account's token", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    const c1 = await issue(state);
    expect((await run(state, noAtt(c1, false))).attestationGrade).toBe("unattestable");
    const c2 = await issue(state);
    expect((await run(state, noAtt(c2, false))).attestationGrade).toBe("unattestable"); // still: the first was only unattestable
    state.checkinTokens.set("jti_other", { jti: "jti_other", userId: USER_B, deviceId: D1, facilityId: null, attestationGrade: "attested", challengeKind: "live", challengeId: "x", expiresAt: "2099-01-01T00:00:00.000Z", issuedAt: "2026-01-01T00:00:00.000Z", consumedAt: null });
    const c3 = await issue(state);
    expect((await run(state, noAtt(c3, false))).attestationGrade).toBe("unattestable");
  });

  // NIT-2: the no-attestation `failed` path used to INSERT a signal every time; it now opens ONE per account, like the presented-attestation path.
  it("the no-attestation `failed` path opens ONE signal per account, however many such check-ins follow (deduplicated like a presented-attestation failure)", async () => {
    const { state } = await iosWorld(5);
    for (let i = 0; i < 4; i++) {
      const ch = await issue(state);
      expect((await run(state, noAtt(ch, i % 2 === 0))).attestationGrade).toBe("failed");
    }
    expect(tokens(state)).toHaveLength(4); // every one still issued its (failed) token
    expect(attestationSignals(state)).toHaveLength(1);
    expect(dodgeSignal(state)).toHaveLength(1);
  });

  it("... and it shares that single open signal with a presented-attestation failure (either order), and a CLEARED signal lets the next failure open a new one", async () => {
    const { state, key } = await iosWorld(5);
    const c1 = await issue(state);
    expect((await run(state, noAtt(c1, true))).attestationGrade).toBe("failed");
    const c2 = await issue(state);
    expect((await run(state, await iosReq(c2, key, 5), iosDeps())).attestationGrade).toBe("failed"); // a non-increasing counter
    expect(attestationSignals(state)).toHaveLength(1);
    for (const sig of rewardsState(state).signals) sig.cleared = true;
    const c3 = await issue(state);
    expect((await run(state, noAtt(c3, true))).attestationGrade).toBe("failed");
    expect(attestationSignals(state).filter((x) => !x.cleared)).toHaveLength(1);
    expect(attestationSignals(state)).toHaveLength(2);
  });

  it("the signal is scoped to the ACCOUNT: another account's open signal does not suppress this one's", async () => {
    const { state } = await iosWorld(5);
    rewardsState(state).signals.push({ userId: USER_B, kind: "attestation_failed", detail: {}, cleared: false, onceKey: null, at: 1 });
    const ch = await issue(state);
    expect((await run(state, noAtt(ch, true))).attestationGrade).toBe("failed");
    expect(rewardsState(state).signals.filter((x) => x.kind === "attestation_failed" && x.userId === USER_A)).toHaveLength(1);
  });

  // NIT-3 (0043): an activation that graded `attested` counts as Android evidence of capability, and it is sticky.
  it("Android: a device whose ACTIVATION verdict was `attested` (no attested check-in token at all) is `failed` when it sends no attestation and claims it cannot attest", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    await makeFakeRepo(state, USER_A).rewards.recordDeviceVerdict(D1, { grade: "attested", tokenHash: "h" });
    expect(tokens(state)).toEqual([]); // the only evidence is the activation's
    const ch = await issue(state);
    const out = await run(state, noAtt(ch, false));
    expect(out.attestationGrade).toBe("failed");
    expect(dodgeSignal(state)).toHaveLength(1);
    expect(dodgeSignal(state)[0]!.detail).toMatchObject({ reasons: ["no_attestation_token", "device_has_attested_before"] });
  });

  it("... and the evidence survives a later `failed` activation verdict (integrity_last is overwritten, the mark is not); a device with no `attested` verdict is still believed", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    const repo = makeFakeRepo(state, USER_A);
    await repo.rewards.recordDeviceVerdict(D1, { grade: "attested", tokenHash: null });
    await repo.rewards.recordDeviceVerdict(D1, { grade: "failed", tokenHash: null });
    expect(rewardsState(state).deviceAttest.get(D1)!.integrityLast).toEqual({ grade: "failed" });
    const c1 = await issue(state);
    expect((await run(state, noAtt(c1, false))).attestationGrade).toBe("failed");

    const other = makeFakeState();
    seedDevice(other, { id: D1, userId: USER_A, platform: "android" });
    await makeFakeRepo(other, USER_A).rewards.recordDeviceVerdict(D1, { grade: "unattestable", tokenHash: null });
    const c2 = await issue(other);
    expect((await run(other, noAtt(c2, false))).attestationGrade).toBe("unattestable");
    expect(dodgeSignal(other)).toEqual([]);
  });

  it("the account-level variant is NOT applied: a second device of an account whose OTHER device attested still gets its honest `cannot attest` believed (an old iPad, an Android without Play services)", async () => {
    const state = makeFakeState();
    const D_OLD = "44444444-4444-4444-8444-444444444444";
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    seedDevice(state, { id: D_OLD, userId: USER_A, platform: "android" });
    await makeFakeRepo(state, USER_A).rewards.recordDeviceVerdict(D1, { grade: "attested", tokenHash: null });
    const [c] = await handleChallengeRequest({ deviceId: D_OLD }, makeFakeRepo(state, USER_A), randomBytes, digestHex);
    const out = await run(state, noAtt({ id: c!.id, nonce: c!.nonce }, false));
    expect(out.attestationGrade).toBe("unattestable");
    expect(dodgeSignal(state)).toEqual([]);
  });

  it("a PRESENTED attestation is unaffected by the rule (it is graded on its merits)", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issue(state);
    expect((await run(state, await iosReq(ch, key, 6), iosDeps())).attestationGrade).toBe("attested");
  });
});

describe("the fake Repo#checkinToken.consumeForFix mirrors the real statement: the CHALLENGE's window, not the token's", () => {
  /** Issues a prefetched challenge at t0 (24 h), redeems it `redeemAfterMs` later; returns the token and the clock values. */
  async function prefetchedRedeemedLater(redeemAfterMs: number) {
    const state = makeFakeState();
    const t0 = state.now.getTime();
    const ch = await issue(state, { prefetch: true });
    state.now = new Date(t0 + redeemAfterMs);
    const token = await run(state, noAtt(ch));
    return { state, token, t0, ch };
  }

  it("a fix captured HOURS before the redemption of a PREFETCHED challenge is accepted: it is inside the challenge's 24 h window (the token's own 15 min window would have refused it)", async () => {
    const { state, token, t0 } = await prefetchedRedeemedLater(4 * 60 * MIN);
    const tokenIssuedAt = Date.parse(state.checkinTokens.get(token.jti)!.issuedAt);
    const capturedAt = t0 + 60 * MIN; // 3 h before the redemption
    expect(capturedAt).toBeLessThan(tokenIssuedAt); // outside the token's own window...
    const out = await makeFakeRepo(state, USER_A).checkinToken.consumeForFix(token.jti, D1, capturedAt);
    expect(out).not.toBeNull(); // ...inside the challenge's, like privileged.ts's UPDATE ... FROM app.checkin_challenge
    expect(out!.challengeKind).toBe("prefetched");
  });

  it("a fix captured BEFORE the challenge was issued, or AFTER it expired, is refused — even when it is inside the token's own window", async () => {
    const before = await prefetchedRedeemedLater(60 * MIN);
    expect(await makeFakeRepo(before.state, USER_A).checkinToken.consumeForFix(before.token.jti, D1, before.t0 - 1)).toBeNull();
    // redeem near the end of the challenge's 24 h life: the token (15 min) then outlives the challenge
    const late = await prefetchedRedeemedLater(23 * 60 * MIN + 55 * MIN);
    const challengeExpiry = Date.parse(late.state.challenges.get(late.ch.id)!.expiresAt);
    const tokenRow = late.state.checkinTokens.get(late.token.jti)!;
    const capturedAt = challengeExpiry + MIN; // inside the token's window, outside the challenge's
    expect(capturedAt).toBeGreaterThanOrEqual(Date.parse(tokenRow.issuedAt));
    expect(capturedAt).toBeLessThanOrEqual(Date.parse(tokenRow.expiresAt));
    expect(await makeFakeRepo(late.state, USER_A).checkinToken.consumeForFix(late.token.jti, D1, capturedAt)).toBeNull();
    // and inside both is accepted
    expect(await makeFakeRepo(late.state, USER_A).checkinToken.consumeForFix(late.token.jti, D1, challengeExpiry - MIN)).not.toBeNull();
  });

  it("the token's own expiry, single use, device and owner still apply", async () => {
    const { state, token, t0 } = await prefetchedRedeemedLater(60 * MIN);
    const repo = makeFakeRepo(state, USER_A);
    expect(await makeFakeRepo(state, USER_B).checkinToken.consumeForFix(token.jti, D1, t0 + MIN)).toBeNull();
    expect(await repo.checkinToken.consumeForFix(token.jti, "other-device", t0 + MIN)).toBeNull();
    expect(await repo.checkinToken.consumeForFix(token.jti, D1, t0 + MIN)).not.toBeNull();
    expect(await repo.checkinToken.consumeForFix(token.jti, D1, t0 + MIN)).toBeNull(); // single use
    const expired = await prefetchedRedeemedLater(60 * MIN);
    expired.state.now = new Date(expired.state.now.getTime() + 16 * MIN);
    expect(await makeFakeRepo(expired.state, USER_A).checkinToken.consumeForFix(expired.token.jti, D1, expired.t0 + MIN)).toBeNull();
  });
});
