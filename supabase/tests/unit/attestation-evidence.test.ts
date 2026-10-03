// supabase/tests/unit/attestation-evidence.test.ts
//
// rewards/attestation-evidence.ts: the two rules checkin-token and rewards-activate share (the no-attestation rule's evidence, and the reason an atomic
// counter advance did not advance). The handlers' own suites prove each end to end; this pins the shared functions' tables directly.

import { describe, expect, it } from "vitest";
import { deviceHasShownAttestation, gradeNoAttestation, lostAdvanceReason, noAttestationReasons } from "../../functions/_shared/rewards/attestation-evidence.js";
import { FAKE_DEVICE_ID, makeFakeRepo, makeFakeState } from "./fake-repo.js";
import { rewardsState, seedDevice } from "./fake-rewards-repo.js";

const USER_A = "user-a";
const USER_B = "user-b";
const D = FAKE_DEVICE_ID;

describe("deviceHasShownAttestation: each kind of evidence counts, each non-evidence does not", () => {
  it("a registered App Attest key counts; a keyless device does not", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D, userId: USER_A, platform: "ios" });
    expect(await deviceHasShownAttestation(D, makeFakeRepo(state, USER_A))).toBe(true);
    rewardsState(state).deviceAttest.get(D)!.attestKeyId = null;
    expect(await deviceHasShownAttestation(D, makeFakeRepo(state, USER_A))).toBe(false);
  });

  it("an `attested` check-in token on the device counts; another account's, or a failed one, does not", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D, userId: USER_A, platform: "android" });
    const row = (userId: string, grade: "attested" | "failed", jti: string) =>
      state.checkinTokens.set(jti, { jti, userId, deviceId: D, facilityId: null, attestationGrade: grade, challengeKind: "live", challengeId: jti, expiresAt: "2099-01-01T00:00:00.000Z", issuedAt: "2026-01-01T00:00:00.000Z", consumedAt: null });
    row(USER_A, "failed", "j1");
    row(USER_B, "attested", "j2");
    expect(await deviceHasShownAttestation(D, makeFakeRepo(state, USER_A))).toBe(false);
    row(USER_A, "attested", "j3");
    expect(await deviceHasShownAttestation(D, makeFakeRepo(state, USER_A))).toBe(true);
  });

  it("an `attested` ACTIVATION verdict counts (0043), and keeps counting after a later `failed` one; `unattestable` / `failed` alone never do", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D, userId: USER_A, platform: "android" });
    const repo = makeFakeRepo(state, USER_A);
    await repo.rewards.recordDeviceVerdict(D, { grade: "unattestable", tokenHash: null });
    await repo.rewards.recordDeviceVerdict(D, { grade: "failed", tokenHash: null });
    expect(await deviceHasShownAttestation(D, repo)).toBe(false);
    await repo.rewards.recordDeviceVerdict(D, { grade: "attested", tokenHash: null });
    expect(await deviceHasShownAttestation(D, repo)).toBe(true);
    await repo.rewards.recordDeviceVerdict(D, { grade: "failed", tokenHash: null });
    expect(await deviceHasShownAttestation(D, repo)).toBe(true);
  });
});

describe("gradeNoAttestation", () => {
  it("claimed capable -> failed, and no evidence lookup is made (provenCapable stays false)", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D, userId: USER_A, platform: "ios" });
    expect(await gradeNoAttestation(true, D, makeFakeRepo(state, USER_A))).toEqual({ grade: "failed", claimedCapable: true, provenCapable: false });
  });

  it("claimed incapable: failed only on evidence (proven), else unattestable", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D, userId: USER_A, platform: "ios" }); // a registered key
    expect(await gradeNoAttestation(false, D, makeFakeRepo(state, USER_A))).toEqual({ grade: "failed", claimedCapable: false, provenCapable: true });
    rewardsState(state).deviceAttest.get(D)!.attestKeyId = null;
    expect(await gradeNoAttestation(false, D, makeFakeRepo(state, USER_A))).toEqual({ grade: "unattestable", claimedCapable: false, provenCapable: false });
  });

  it("the reasons: the proven case adds `device_has_attested_before`; the claimed case does not", () => {
    expect(noAttestationReasons({ grade: "failed", claimedCapable: true, provenCapable: false })).toEqual(["no_attestation_token"]);
    expect(noAttestationReasons({ grade: "failed", claimedCapable: false, provenCapable: true })).toEqual(["no_attestation_token", "device_has_attested_before"]);
    expect(noAttestationReasons({ grade: "unattestable", claimedCapable: false, provenCapable: false })).toEqual(["no_attestation_token"]);
  });
});

describe("lostAdvanceReason: why the atomic advance updated zero rows", () => {
  const KEY = "FAKE-ATTEST-KEY-ID";
  const world = (counter: number, keyId: string | null = KEY) => {
    const state = makeFakeState();
    seedDevice(state, { id: D, userId: USER_A, platform: "ios", attestKeyId: keyId, attestCounter: counter });
    return makeFakeRepo(state, USER_A);
  };

  it("a LOWER presented counter than the stored one is `counter_out_of_order`", async () => {
    expect(await lostAdvanceReason(D, KEY, 6, world(7))).toBe("counter_out_of_order");
    expect(await lostAdvanceReason(D, KEY, 0, world(9))).toBe("counter_out_of_order");
  });

  it("an EQUAL presented counter is `counter_replay`", async () => {
    expect(await lostAdvanceReason(D, KEY, 7, world(7))).toBe("counter_replay");
  });

  it("a presented counter ABOVE the stored one (the advance failed for no counter reason we can see) is `counter_replay`, never `counter_out_of_order`", async () => {
    expect(await lostAdvanceReason(D, KEY, 8, world(7))).toBe("counter_replay");
  });

  it("a different key on the device is `key_replaced`, whatever the counters say", async () => {
    expect(await lostAdvanceReason(D, KEY, 6, world(0, "ANOTHER-KEY"))).toBe("key_replaced");
    expect(await lostAdvanceReason(D, KEY, 6, world(99, "ANOTHER-KEY"))).toBe("key_replaced");
  });

  it("no verified key, or a device that is not this account's, is `counter_replay` (the old behaviour) and makes no claim about a replacement", async () => {
    expect(await lostAdvanceReason(D, null, 6, world(7))).toBe("counter_replay");
    const state = makeFakeState();
    seedDevice(state, { id: D, userId: USER_B, platform: "ios", attestCounter: 7 });
    expect(await lostAdvanceReason(D, KEY, 6, makeFakeRepo(state, USER_A))).toBe("counter_replay");
  });
});
