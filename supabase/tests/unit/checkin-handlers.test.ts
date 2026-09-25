// supabase/tests/unit/checkin-handlers.test.ts
//
// ⛔ REWRITE (P3c gate round 2, item 5): both handlers dropped their
// `actorUid` parameter — every test below scopes ownership by building
// its `Repo` via `makeFakeRepo(state, actorUid)` instead of passing the
// uid into the handler call itself.
// should-fix "nonce": `handleTokenRequest` now requires the raw nonce
// POST /v1/checkin/challenge returned, hashed with the SAME injected
// `digestHex` the challenge issuance used, so every test that consumes a
// token now threads the nonce through instead of the bare challenge id.
import { describe, expect, it } from "vitest";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.js";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.js";
import { makeFakeRepo, makeFakeState } from "./fake-repo.js";
import { HttpError } from "../../functions/_shared/http.js";

const randomBytes = (n: number) => new Uint8Array(n).map((_, i) => i);
const digestHex = async (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("handleChallengeRequest", () => {
  it("issues a single LIVE challenge by default", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    const issued = await handleChallengeRequest({ deviceId: "dev_1" }, repo, randomBytes, digestHex);
    expect(issued).toHaveLength(1);
    expect(issued[0].kind).toBe("live");
  });

  it("issues up to `prefetchCount` PREFETCHED challenges", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    const issued = await handleChallengeRequest({ deviceId: "dev_1", prefetchCount: 5 }, repo, randomBytes, digestHex);
    expect(issued).toHaveLength(5);
    expect(issued.every((c) => c.kind === "prefetched")).toBe(true);
  });

  it("caps prefetched challenges at 10 unused per device (build plan §4.4 line 829)", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    await handleChallengeRequest({ deviceId: "dev_1", prefetchCount: 8 }, repo, randomBytes, digestHex);
    const second = await handleChallengeRequest({ deviceId: "dev_1", prefetchCount: 8 }, repo, randomBytes, digestHex);
    expect(second).toHaveLength(2); // room was only 10-8=2
  });

  it("429s once a device already holds 10 unused prefetched challenges", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    await handleChallengeRequest({ deviceId: "dev_1", prefetchCount: 10 }, repo, randomBytes, digestHex);
    await expect(handleChallengeRequest({ deviceId: "dev_1", prefetchCount: 1 }, repo, randomBytes, digestHex)).rejects.toThrow(HttpError);
  });

  it("429s past 30 challenge requests/user/hour", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    for (let i = 0; i < 30; i++) await handleChallengeRequest({ deviceId: "dev_1" }, repo, randomBytes, digestHex);
    await expect(handleChallengeRequest({ deviceId: "dev_1" }, repo, randomBytes, digestHex)).rejects.toMatchObject({ code: "rate_limited" });
  });

  // ⛔ FIX (P3c gate round 2, item 7): "cap the number of devices per
  // user... don't create device rows on rejected requests."
  it("422 device_limit_exceeded once a user already has 20 devices, and never creates the 21st device row", async () => {
    const state = makeFakeState();
    for (let i = 0; i < 20; i++) state.devices.set(`dev_cap_${i}`, { id: `dev_cap_${i}`, userId: "user-a" });
    const repo = makeFakeRepo(state, "user-a");
    await expect(handleChallengeRequest({ deviceId: "dev_new" }, repo, randomBytes, digestHex)).rejects.toMatchObject({ code: "device_limit_exceeded" });
    expect(state.devices.has("dev_new")).toBe(false);
  });
});

describe("handleTokenRequest", () => {
  async function issueChallenge(actorUid = "user-a") {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, actorUid);
    const [challenge] = await handleChallengeRequest({ deviceId: "dev_1" }, repo, randomBytes, digestHex);
    return { state, repo, challenge };
  }

  it("G3-08 'no token' rule: hardwareSupportsAttestation=false grades unattestable", async () => {
    const { repo, challenge } = await issueChallenge();
    const token = await handleTokenRequest({ challengeId: challenge.id, nonce: challenge.nonce, hardwareSupportsAttestation: false }, repo, digestHex);
    expect(token.attestationGrade).toBe("unattestable");
  });

  it("G3-08 'no token' rule: hardwareSupportsAttestation=true grades failed and raises fraud_signal(attestation_failed) at intake", async () => {
    const { state, repo, challenge } = await issueChallenge();
    const token = await handleTokenRequest({ challengeId: challenge.id, nonce: challenge.nonce, hardwareSupportsAttestation: true }, repo, digestHex);
    expect(token.attestationGrade).toBe("failed");
    expect(state.fraudSignals.some((s) => s.kind === "attestation_failed")).toBe(true);
  });

  it("consumes the challenge — a second call for the same challenge fails", async () => {
    const { repo, challenge } = await issueChallenge();
    await handleTokenRequest({ challengeId: challenge.id, nonce: challenge.nonce, hardwareSupportsAttestation: false }, repo, digestHex);
    await expect(handleTokenRequest({ challengeId: challenge.id, nonce: challenge.nonce, hardwareSupportsAttestation: false }, repo, digestHex)).rejects.toMatchObject({
      code: "challenge_used",
    });
  });

  // should-fix (P3c gate round 2): "nonce — checkin-token must require the
  // challenge nonce and compare its hash."
  it("422s when the presented nonce does not match the one issued with the challenge", async () => {
    const { repo, challenge } = await issueChallenge();
    const wrongNonce = (challenge.nonce[0] === "A" ? "B" : "A") + challenge.nonce.slice(1);
    await expect(handleTokenRequest({ challengeId: challenge.id, nonce: wrongNonce, hardwareSupportsAttestation: false }, repo, digestHex)).rejects.toMatchObject({
      code: "challenge_not_consumable",
    });
  });

  it("404s for a challenge belonging to a different account", async () => {
    const { challenge } = await issueChallenge();
    // A DIFFERENT actor's Repo (Repo#challenge.getOwn is actor-scoped —
    // types.ts's own doc) never sees another user's challenge, even
    // knowing its id and nonce.
    const otherRepo = makeFakeRepo(makeFakeState(), "user-b");
    await expect(handleTokenRequest({ challengeId: challenge.id, nonce: challenge.nonce, hardwareSupportsAttestation: false }, otherRepo, digestHex)).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("422s for an expired challenge", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    state.challenges.set("chal_expired", {
      id: "chal_expired",
      userId: "user-a",
      staffUserId: null,
      deviceId: "dev_1",
      facilityId: null,
      nonceHash: "irrelevant",
      kind: "live",
      expiresAt: "2020-01-01T00:00:00.000Z",
      usedAt: null,
    });
    await expect(handleTokenRequest({ challengeId: "chal_expired", nonce: "AAAA", hardwareSupportsAttestation: false }, repo, digestHex)).rejects.toMatchObject({
      code: "challenge_expired",
    });
  });
});
