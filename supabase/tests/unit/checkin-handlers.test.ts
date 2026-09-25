// supabase/tests/unit/checkin-handlers.test.ts
import { describe, expect, it } from "vitest";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.js";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.js";
import { makeFakeRepo, makeFakeState } from "./fake-repo.js";
import { HttpError } from "../../functions/_shared/http.js";

const randomBytes = (n: number) => new Uint8Array(n).map((_, i) => i);
const digestHex = async (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("handleChallengeRequest", () => {
  it("issues a single LIVE challenge by default", async () => {
    const repo = makeFakeRepo(makeFakeState());
    const issued = await handleChallengeRequest("user-a", { deviceId: "dev_1" }, repo, randomBytes, digestHex);
    expect(issued).toHaveLength(1);
    expect(issued[0].kind).toBe("live");
  });

  it("issues up to `prefetchCount` PREFETCHED challenges", async () => {
    const repo = makeFakeRepo(makeFakeState());
    const issued = await handleChallengeRequest("user-a", { deviceId: "dev_1", prefetchCount: 5 }, repo, randomBytes, digestHex);
    expect(issued).toHaveLength(5);
    expect(issued.every((c) => c.kind === "prefetched")).toBe(true);
  });

  it("caps prefetched challenges at 10 unused per device (build plan §4.4 line 829)", async () => {
    const repo = makeFakeRepo(makeFakeState());
    await handleChallengeRequest("user-a", { deviceId: "dev_1", prefetchCount: 8 }, repo, randomBytes, digestHex);
    const second = await handleChallengeRequest("user-a", { deviceId: "dev_1", prefetchCount: 8 }, repo, randomBytes, digestHex);
    expect(second).toHaveLength(2); // room was only 10-8=2
  });

  it("429s once a device already holds 10 unused prefetched challenges", async () => {
    const repo = makeFakeRepo(makeFakeState());
    await handleChallengeRequest("user-a", { deviceId: "dev_1", prefetchCount: 10 }, repo, randomBytes, digestHex);
    await expect(handleChallengeRequest("user-a", { deviceId: "dev_1", prefetchCount: 1 }, repo, randomBytes, digestHex)).rejects.toThrow(HttpError);
  });

  it("429s past 30 challenge requests/user/hour", async () => {
    const repo = makeFakeRepo(makeFakeState());
    for (let i = 0; i < 30; i++) await handleChallengeRequest("user-a", { deviceId: "dev_1" }, repo, randomBytes, digestHex);
    await expect(handleChallengeRequest("user-a", { deviceId: "dev_1" }, repo, randomBytes, digestHex)).rejects.toMatchObject({ code: "rate_limited" });
  });
});

describe("handleTokenRequest", () => {
  async function issueChallenge() {
    const state = makeFakeState();
    const repo = makeFakeRepo(state);
    const [challenge] = await handleChallengeRequest("user-a", { deviceId: "dev_1" }, repo, randomBytes, digestHex);
    return { state, repo, challenge };
  }

  it("G3-08 'no token' rule: hardwareSupportsAttestation=false grades unattestable", async () => {
    const { repo, challenge } = await issueChallenge();
    const token = await handleTokenRequest("user-a", { challengeId: challenge.id, hardwareSupportsAttestation: false }, repo);
    expect(token.attestationGrade).toBe("unattestable");
  });

  it("G3-08 'no token' rule: hardwareSupportsAttestation=true grades failed and raises fraud_signal(attestation_failed) at intake", async () => {
    const { state, repo, challenge } = await issueChallenge();
    const token = await handleTokenRequest("user-a", { challengeId: challenge.id, hardwareSupportsAttestation: true }, repo);
    expect(token.attestationGrade).toBe("failed");
    expect(state.fraudSignals.some((s) => s.kind === "attestation_failed")).toBe(true);
  });

  it("consumes the challenge — a second call for the same challenge fails", async () => {
    const { repo, challenge } = await issueChallenge();
    await handleTokenRequest("user-a", { challengeId: challenge.id, hardwareSupportsAttestation: false }, repo);
    await expect(handleTokenRequest("user-a", { challengeId: challenge.id, hardwareSupportsAttestation: false }, repo)).rejects.toMatchObject({ code: "challenge_used" });
  });

  it("404s for a challenge belonging to a different account", async () => {
    const { repo, challenge } = await issueChallenge();
    await expect(handleTokenRequest("user-b", { challengeId: challenge.id, hardwareSupportsAttestation: false }, repo)).rejects.toMatchObject({ code: "not_found" });
  });

  it("422s for an expired challenge", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state);
    state.challenges.set("chal_expired", { userId: "user-a", staffUserId: null, deviceId: "dev_1", facilityId: null, expiresAt: "2020-01-01T00:00:00.000Z", usedAt: null });
    await expect(handleTokenRequest("user-a", { challengeId: "chal_expired", hardwareSupportsAttestation: false }, repo)).rejects.toMatchObject({ code: "challenge_expired" });
  });
});
