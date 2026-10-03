/** P4.2b-2: the composition (`createAttestation`), the services wiring, the kept-off check-in UI switch, and account deletion's wipe of the attestation records. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { deleteAccountAndWipeLocal } from "../src/account";
import { AttestStateStore, NativeAttestor, NativeRedeemer, PlainRedeemer, createAttestation } from "../src/attest";
import { CHECKIN_UI_ENABLED } from "../src/features";
import { MemorySecureStore, SECURE_KEYS } from "../src/secure";
import { FakeNativeAttestModule } from "./support/fake-native-attest";
import { CHALLENGE, DEVICE, USER, input, makeRig } from "./support/attest-rig";

const read = (rel: string): string => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

describe("createAttestation: NativeAttestor + NativeRedeemer only where it can attest; Unattestable + PlainRedeemer everywhere else", () => {
  const make = (over: Partial<Parameters<typeof createAttestation>[0]>) => createAttestation({ module: new FakeNativeAttestModule(), platform: "ios", playCloudProjectNumber: null, secure: new MemorySecureStore(), ...over });

  it("iOS + module + supported -> native", async () => {
    const a = await make({});
    expect(a.attestor).toBeInstanceOf(NativeAttestor);
    expect(a.redeemer).toBeInstanceOf(NativeRedeemer);
  });

  it("Android + module + project number -> native; Android without the number -> plain", async () => {
    expect((await make({ platform: "android", playCloudProjectNumber: "123456789012" })).redeemer).toBeInstanceOf(NativeRedeemer);
    const none = await make({ platform: "android" });
    expect(none.attestor).not.toBeInstanceOf(NativeAttestor);
    expect(none.redeemer).toBeInstanceOf(PlainRedeemer);
  });

  it("Expo Go / web / tests (no module), and an unsupported device -> plain, and a redemption then claims false with no block", async () => {
    const unsupported = new FakeNativeAttestModule();
    unsupported.supported = false;
    for (const a of [await make({ module: null }), await make({ module: unsupported }), await make({ platform: "web" })]) {
      expect(a.attestor).not.toBeInstanceOf(NativeAttestor);
      expect(a.redeemer).toBeInstanceOf(PlainRedeemer);
      expect(a.attestor.capability.hardwareSupportsAttestation).toBe(false);
      const rig = makeRig("ios");
      await a.redeemer.redeem(input(), rig.io());
      expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: expect.any(String), hardwareSupportsAttestation: false }]);
    }
  });

  it("the activation seam (P4.2c): withAssertionLock runs under the lock check-in uses, and markAttestedActivation makes a later Android local failure defer instead of going token-less", async () => {
    const a = await make({ platform: "android", playCloudProjectNumber: "123456789012" });
    expect(await a.withAssertionLock(USER, DEVICE, async (g) => (g.check(), "ok"))).toBe("ok");
    expect(await a.state.hasAttestedAndroid(USER, DEVICE)).toBe(false);
    await a.markAttestedActivation(USER, DEVICE);
    expect(await a.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
    const rig = makeRig("android");
    rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "x" };
    await rig.state.markAttestedAndroid(USER, DEVICE);
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ name: "AttestationDeferred" });
  });

  it("one lock instance and one state store are handed out, for reward activation (P4.2c) to share: the counter is shared with check-in", async () => {
    const a = await make({});
    expect(a.locks).toBeDefined();
    expect(a.state).toBeInstanceOf(AttestStateStore);
  });
});

describe("composition root", () => {
  it("services.ts picks the attestation through createAttestation with the loaded module, Platform.OS and the parsed Cloud project number, and gives the redeemer to the real client", () => {
    const services = read("../src/runtime/services.ts");
    expect(services).toMatch(/createAttestation\(\{\s*module: loadNativeAttestModule\(\),\s*platform: Platform\.OS,\s*playCloudProjectNumber: config\.playCloudProjectNumber,\s*secure,\s*\}\)/);
    expect(services).toMatch(/evidence: \{\s*redeemer: attestation\.redeemer,/);
    expect(services).not.toMatch(/new UnattestableAttestor\(\)/); // the fallback is chosen inside selectAttestor
  });

  it("CHECKIN_UI_ENABLED stays false: there is still no check-in screen, so none of this is reachable in a release build", () => {
    expect(CHECKIN_UI_ENABLED).toBe(false);
  });
});

describe("account deletion removes the DELETED user's attestation records, and only theirs", () => {
  it("wipes this device's iOS key record and Android flag for the deleted user; the other user's records and the device id stay", async () => {
    const secure = new MemorySecureStore();
    const state = new AttestStateStore(secure);
    const OTHER = "vvvvvvvv-vvvv-4vvv-8vvv-vvvvvvvvvvvv";
    const keyId = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq=";
    await secure.set(SECURE_KEYS.deviceId, DEVICE);
    for (const u of [USER, OTHER]) {
      await state.setIosKey(u, DEVICE, { state: "registered", keyId });
      await state.markAttestedAndroid(u, DEVICE);
    }
    const outcome = await deleteAccountAndWipeLocal({
      api: { deleteAccount: async () => ({ userId: USER, deletedAt: "x", authUserDeleted: true }) as never },
      auth: { clearLocalSession: async () => undefined },
      outbox: { deleteByOwners: async () => undefined } as never,
      challenges: { deleteOwner: async () => undefined } as never,
      attestState: { wipeUser: (u) => state.wipeUser(u, DEVICE) },
      sharer: { purgeStale: async () => undefined },
      currentUserId: () => USER,
      secure,
      clearUserCaches: () => undefined,
    });
    expect(outcome).toMatchObject({ status: "deleted", localWipe: "complete" });
    expect(await state.getIosKey(USER, DEVICE)).toBeNull();
    expect(await state.hasAttestedAndroid(USER, DEVICE)).toBe(false);
    expect(await state.getIosKey(OTHER, DEVICE)).toMatchObject({ state: "registered" });
    expect(await state.hasAttestedAndroid(OTHER, DEVICE)).toBe(true);
    expect(await secure.get(SECURE_KEYS.deviceId)).toBe(DEVICE);
  });

  it("a failing wipe is reported as a partial wipe (named step), not swallowed", async () => {
    const outcome = await deleteAccountAndWipeLocal({
      api: { deleteAccount: async () => ({ userId: USER, deletedAt: "x", authUserDeleted: true }) as never },
      auth: { clearLocalSession: async () => undefined },
      outbox: { deleteByOwners: async () => undefined } as never,
      challenges: { deleteOwner: async () => undefined } as never,
      attestState: { wipeUser: () => Promise.reject(new Error("keychain locked")) },
      sharer: { purgeStale: async () => undefined },
      currentUserId: () => USER,
      secure: new MemorySecureStore(),
      clearUserCaches: () => undefined,
    });
    expect(outcome).toMatchObject({ status: "deleted", localWipe: "partial", failedSteps: ["attest-state"] });
  });
});
