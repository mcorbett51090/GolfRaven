/**
 * P4.2b-3b: reward activation WITH device attestation (`src/attest/activator.ts`). The rules, each a test:
 *  - the binding is the server's (compared with the server's own functions, imported here, and with the requests the real handler accepted);
 *  - the wire body is the server's strict shape (the real `parseActivationBody` is run over every body built here);
 *  - HONEST CAPABILITY: no token-less request ever claims support; a device that can attest never goes token-less because of a LOCAL failure;
 *  - ONE ASSERTION IN FLIGHT PER KEY ACROSS check-in AND activation (the PR #40 gate LOW-1 contract): a concurrent redemption and activation are strictly sequential;
 *  - `markAttestedActivation` (Android "attested before"): only when the server graded a token, never for a replay, a refusal or a token-less request, never on iOS.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { computeRequestBinding, toBase64Url, toHex } from "../../../supabase/functions/_shared/rewards/binding.ts";
import { parseActivationBody } from "../../../supabase/functions/_shared/rewards/request-shape.ts";
import { computeIosActivationBinding } from "../../../supabase/functions/_shared/rewards/string-binding.ts";
import type { ActivationAnswer, ActivationWireRequest } from "../src/api/types";
import {
  ActivationUnsupportedPlatform,
  AttestationDeferred,
  NativeActivator,
  NativeAttestor,
  PlainActivator,
  UnattestableAttestor,
  activationWireRequest,
  androidRequestBinding,
  assertionLockKey,
  bytesToBase64Url,
  bytesToHex,
  createAttestation,
  iosActivationBinding,
  type ActivationProof,
} from "../src/attest";
import { MemorySecureStore } from "../src/secure";
import { FakeNativeAttestModule } from "./support/fake-native-attest";
import { CHALLENGE, DEVICE, NONCE, USER, grade, input } from "./support/attest-rig";
import { CLOUD, REWARD, REWARD2, actInput, answer, assertionsOf, held, integrityRequestsOf, makeActivationRig } from "./support/activation-rig";
import { VECTORS, recorded, recordedRequest } from "./support/edge-fixtures";
import { apiError, jwt } from "./support/fakes";

const sha256 = async (b: Uint8Array): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.digest("SHA-256", b.slice().buffer));
const settle = (ms = 25): Promise<void> => new Promise((r) => setTimeout(r, ms));
const src = (rel: string): string => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
// An App Attest key id (44 characters, standard base64) as the recorder made it; read from the fixture, not written here (a 44-character literal beside the word "key" trips gitleaks' generic rule).
const KEY = recordedRequest<{ attestation: { keyId: string } }>("activate_200_issued_ios").attestation.keyId;
const hex = (b64url: string): string => Buffer.from(b64url, "base64url").toString("hex");

/** An iOS rig whose key is already registered (the common case), so the tests below start at the activation itself. */
async function iosRig(opts: Parameters<typeof makeActivationRig>[1] = {}) {
  const ar = makeActivationRig("ios", opts);
  await ar.rig.state.setIosKey(USER, DEVICE, { state: "registered", keyId: KEY });
  ar.rig.module.keys.add(KEY);
  return ar;
}

describe("the binding is the server's", () => {
  it("iOS: the hash the module is asked to sign for the recorded request's inputs IS the recorded assertion (base64url of the hash the real handler accepted)", async () => {
    const req = recordedRequest<{ deviceId: string; challengeId: string; nonce: string; attestation: { keyId: string; assertion: string; deviceCheckToken: string } }>("activate_200_issued_ios");
    const ar = makeActivationRig("ios");
    await ar.rig.state.setIosKey(USER, req.deviceId, { state: "registered", keyId: req.attestation.keyId });
    ar.rig.module.keys.add(req.attestation.keyId);
    ar.rig.module.deviceCheckValue = req.attestation.deviceCheckToken;
    ar.live.push({ id: req.challengeId, nonce: req.nonce, expiresAt: "2026-06-01T12:02:00.000Z", kind: "live" });
    await ar.activator.activate(actInput({ deviceId: req.deviceId }), ar.io());
    const signed = assertionsOf(ar);
    expect(signed).toHaveLength(1);
    expect(signed[0]).toMatchObject({ keyId: req.attestation.keyId, hashHex: hex(req.attestation.assertion) });
    expect(JSON.parse(recorded("activate_200_issued_ios").body).data.state).toBe("issued");
    // and the body sent has exactly the recorded shape (the assertion bytes differ: the fake module signs for real nothing)
    expect(Object.keys(ar.posts[0]!).sort()).toEqual(Object.keys(req).sort());
    expect(ar.posts[0]).toMatchObject({ deviceId: req.deviceId, platform: "ios", challengeId: req.challengeId, nonce: req.nonce, attestation: { kind: "ios", keyId: req.attestation.keyId, deviceCheckToken: req.attestation.deviceCheckToken } });
  });

  it("iOS: the entitlement and the second-reward recordings bind the same way (a different reward id gives a different hash)", async () => {
    const req = recordedRequest<{ deviceId: string; challengeId: string; nonce: string; attestation: { keyId: string; assertion: string; deviceCheckToken: string } }>("activate_200_redeemable_ios_entitlement");
    const ar = makeActivationRig("ios");
    await ar.rig.state.setIosKey(USER, req.deviceId, { state: "registered", keyId: req.attestation.keyId });
    ar.rig.module.keys.add(req.attestation.keyId);
    ar.rig.module.deviceCheckValue = req.attestation.deviceCheckToken;
    ar.live.push({ id: req.challengeId, nonce: req.nonce, expiresAt: "x", kind: "live" });
    await ar.activator.activate(actInput({ deviceId: req.deviceId, rewardId: REWARD2 }), ar.io());
    expect(assertionsOf(ar)[0]).toMatchObject({ hashHex: hex(req.attestation.assertion) });
    const first = recordedRequest<{ attestation: { assertion: string } }>("activate_200_issued_ios");
    expect(first.attestation.assertion).not.toBe(req.attestation.assertion);
  });

  it("Android: the requestHash the module is given for the recorded request's inputs IS the hash the real handler accepted (token = 'it-' + hash), installLinkId bound", async () => {
    const req = recordedRequest<{ deviceId: string; challengeId: string; nonce: string; installLinkId: string; attestation: { integrityToken: string } }>("activate_200_issued_android");
    const ar = makeActivationRig("android");
    ar.rig.module.installLinkValue = req.installLinkId;
    ar.live.push({ id: req.challengeId, nonce: req.nonce, expiresAt: "x", kind: "live" });
    await ar.activator.activate(actInput({ deviceId: req.deviceId }), ar.io());
    const asked = integrityRequestsOf(ar);
    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatchObject({ cloud: CLOUD, requestHash: req.attestation.integrityToken.slice("it-".length) });
    expect(ar.posts[0]).toMatchObject({ deviceId: req.deviceId, platform: "android", challengeId: req.challengeId, nonce: req.nonce, installLinkId: req.installLinkId, attestation: { kind: "android", integrityToken: expect.stringMatching(/^it\./) } });
    expect(Object.keys(ar.posts[0]!).sort()).toEqual(Object.keys(req).sort());
  });

  it("Android without an install link: the hash omits it (the server's no-link vector), and the body carries none", async () => {
    const req = recordedRequest<{ deviceId: string; challengeId: string; nonce: string; attestation: { integrityToken: string } }>("activate_200_held_android_no_install_link");
    expect(req).not.toHaveProperty("installLinkId");
    const ar = makeActivationRig("android");
    ar.rig.module.nextInstallLink = [{ ok: false, code: "unsupported", message: "none" }];
    ar.live.push({ id: req.challengeId, nonce: req.nonce, expiresAt: "x", kind: "live" });
    await ar.activator.activate(actInput({ deviceId: req.deviceId }), ar.io());
    expect(integrityRequestsOf(ar)[0]).toMatchObject({ requestHash: req.attestation.integrityToken.slice(3) });
    expect(ar.posts[0]).not.toHaveProperty("installLinkId");
  });

  it("the recorded vectors (the server's output for fixed inputs) equal this client's builders", () => {
    const i = VECTORS.binding.iosActivation;
    expect(bytesToHex(iosActivationBinding(i.body))).toBe(i.hashHex);
    const a = VECTORS.binding.androidRequestBinding;
    expect(bytesToHex(androidRequestBinding(a.body, a.challengeBase64Url))).toBe(a.hashHex);
  });

  it("against the server's own functions, imported here, on 60 varied bodies (both platforms; UUID case and the install link)", async () => {
    for (let n = 0; n < 60; n += 1) {
      const u = (k: number): string => `${(n * 7 + k).toString(16).padStart(8, "0")}-1111-4111-8111-${(n * 13 + k).toString(16).padStart(12, "0")}`;
      const nonceBytes = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + n * 3) & 255);
      const nonce = bytesToBase64Url(nonceBytes);
      const link = n % 2 === 0 ? `link-${n}-0123456789` : undefined;
      const body = { rewardId: u(1), deviceId: u(2), challengeId: u(3), ...(link ? { installLinkId: link } : {}) };
      const serverAndroid = await computeRequestBinding(sha256, { ...body, platform: "android" }, nonceBytes);
      expect(bytesToHex(androidRequestBinding(n % 3 === 0 ? { rewardId: body.rewardId.toUpperCase(), deviceId: body.deviceId.toUpperCase(), challengeId: body.challengeId.toUpperCase(), ...(link ? { installLinkId: link } : {}) } : body, nonce)), `android #${n}`).toBe(toHex(serverAndroid));
      const dct = toHex(await sha256(new TextEncoder().encode(`devicecheck-${n}`)));
      const ios = { rewardId: body.rewardId, deviceId: body.deviceId, challengeId: body.challengeId, deviceCheckTokenSha256: dct, nonce };
      expect(bytesToHex(iosActivationBinding(ios)), `ios #${n}`).toBe(toHex(await computeIosActivationBinding(sha256, ios)));
      expect(toBase64Url(serverAndroid)).toBe(bytesToBase64Url(androidRequestBinding(body, nonce)));
    }
  });
});

describe("the wire body is the server's strict shape", () => {
  async function bodies(): Promise<ActivationWireRequest[]> {
    const out: ActivationWireRequest[] = [];
    {
      const ar = await iosRig();
      await ar.activator.activate(actInput(), ar.io());
      out.push(...ar.posts);
    }
    {
      const ar = makeActivationRig("ios"); // no key and the server refuses one: the none shape, with a DeviceCheck token
      ar.registerReplies = [apiError("unavailable", 503, "attestation_not_configured")];
      await ar.activator.activate(actInput(), ar.io());
      out.push(...ar.posts);
    }
    {
      const ar = makeActivationRig("android");
      await ar.activator.activate(actInput(), ar.io());
      out.push(...ar.posts);
    }
    {
      const ar = makeActivationRig("android");
      ar.rig.module.always.integrityToken = { ok: false, code: "unsupported", message: "no play" };
      await ar.activator.activate(actInput(), ar.io());
      out.push(...ar.posts);
    }
    for (const p of ["ios", "android"]) out.push(await new Promise<ActivationWireRequest>((resolve) => void new PlainActivator(p).activate(actInput(), { post: async (r) => (resolve(r), answer()), requestLiveChallenge: async () => Promise.reject(new Error("no")), registerKey: async () => undefined })));
    return out;
  }

  it("the real parseActivationBody accepts every body this client builds, and every one is one of the three attestation kinds", async () => {
    const all = await bodies();
    expect(all.length).toBe(6);
    expect(new Set(all.map((b) => b.attestation.kind))).toEqual(new Set(["ios", "none", "android"]));
    for (const b of all) {
      const parsed = parseActivationBody(JSON.parse(JSON.stringify(b)));
      expect(parsed.ok, JSON.stringify(parsed)).toBe(true);
      expect(b).not.toHaveProperty("rewardId"); // the reward is named by the path only
    }
  });

  it("an attestation always carries the challenge it was bound to; a none request carries none; installLinkId is Android only", async () => {
    for (const b of await bodies()) {
      if (b.attestation.kind === "none") {
        expect(b).not.toHaveProperty("challengeId");
        expect(b).not.toHaveProperty("nonce");
      } else {
        expect(b.challengeId).toBeTruthy();
        expect(b.nonce).toBeTruthy();
      }
      if (b.platform === "ios") expect(b).not.toHaveProperty("installLinkId");
    }
  });

  it("the server refuses what this client never builds: the reward id in the body, an install link on iOS, an attestation with no challenge (recorded 400s)", () => {
    for (const name of ["activate_400_reward_id_in_body", "activate_400_install_link_on_ios", "activate_400_attestation_without_challenge"]) {
      expect(recorded(name).status).toBe(400);
      expect(parseActivationBody(recordedRequest(name)).ok, name).toBe(false);
    }
  });
});

describe("HONEST CAPABILITY: a token-less request never claims support", () => {
  it("`activationWireRequest` is the single constructor: kind none is always `hardwareSupportsAttestation: false`, whatever else is passed", () => {
    const base = { deviceId: DEVICE, platform: "ios" as const };
    const none = activationWireRequest(base, { kind: "none" });
    expect(none.attestation).toEqual({ kind: "none", hardwareSupportsAttestation: false });
    expect(activationWireRequest(base, { kind: "none", deviceCheckToken: "dG9r" }).attestation).toEqual({ kind: "none", hardwareSupportsAttestation: false, deviceCheckToken: "dG9r" });
    // a caller cannot smuggle a claim in through the proof
    expect(activationWireRequest(base, { kind: "none", hardwareSupportsAttestation: true } as unknown as ActivationProof).attestation).toMatchObject({ hardwareSupportsAttestation: false });
    for (const key of ["ios", "android"] as const) {
      const p = key === "ios" ? ({ kind: "ios", challenge: { id: CHALLENGE, nonce: NONCE }, keyId: KEY, assertion: "QQ==", deviceCheckToken: "dG9r" } as const) : ({ kind: "android", challenge: { id: CHALLENGE, nonce: NONCE }, integrityToken: "tok" } as const);
      const w = activationWireRequest({ ...base, platform: key }, p);
      expect(w.attestation.kind).toBe(key);
      expect(JSON.stringify(w)).not.toContain("hardwareSupportsAttestation");
    }
  });

  it("the source never writes `hardwareSupportsAttestation: true` and never derives it from anything: the only occurrence is the literal false in the constructor", () => {
    const code = strip(src("../src/attest/activator.ts"));
    const hits = [...code.matchAll(/hardwareSupportsAttestation[^,}\n]*/g)].map((m) => m[0]!.trim());
    expect(hits).toEqual(["hardwareSupportsAttestation: false"]);
    expect(strip(src("../src/api/types.ts"))).toMatch(/kind: "none"; hardwareSupportsAttestation: false/);
    expect(strip(src("../src/api/http-client.ts"))).not.toMatch(/hardwareSupportsAttestation/);
  });

  it("across every failure we can inject on every platform: any request that goes out without an attestation claims false, and a device that CAN attest never sends one because of a local failure", async () => {
    type Setup = (ar: ReturnType<typeof makeActivationRig>) => Promise<void> | void;
    const injections: Array<[string, "ios" | "android", Setup, "defers" | "none" | "attests"]> = [
      ["ios: deviceCheck unavailable", "ios", async (ar) => (await keyed(ar), void (ar.rig.module.nextDeviceCheck = [{ ok: false, code: "unavailable", message: "x" }])), "defers"],
      ["ios: deviceCheck unsupported", "ios", async (ar) => (await keyed(ar), void (ar.rig.module.nextDeviceCheck = [{ ok: false, code: "unsupported", message: "x" }])), "defers"],
      ["ios: assertion unavailable", "ios", async (ar) => (await keyed(ar), void (ar.rig.module.next.generateAssertion = [{ ok: false, code: "unavailable", message: "x" }])), "defers"],
      ["ios: assertion other failure", "ios", async (ar) => (await keyed(ar), void (ar.rig.module.next.generateAssertion = [{ ok: false, code: "other", message: "x" }])), "defers"],
      ["ios: pending key (an earlier registration of unknown outcome) and the server refuses a key", "ios", async (ar) => (await ar.rig.state.setIosKey(USER, DEVICE, { state: "pending" }), void (ar.registerReplies = [apiError("unavailable", 503, "attestation_not_configured")])), "defers"],
      ["ios: attestKey unavailable (Apple down)", "ios", (ar) => void (ar.rig.module.next.attestKey = [{ ok: false, code: "unavailable", message: "x" }]), "defers"],
      ["ios: device cannot do App Attest at all", "ios", (ar) => void (ar.rig.module.next.generateKey = [{ ok: false, code: "unsupported", message: "sim" }]), "none"],
      ["ios: the server refuses to hold a key", "ios", (ar) => void (ar.registerReplies = [apiError("unavailable", 503, "attestation_not_configured")]), "none"],
      ["android: integrity unavailable (never attested)", "android", (ar) => void (ar.rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "x" }), "defers"],
      ["android: integrity other failure", "android", (ar) => void (ar.rig.module.always.integrityToken = { ok: false, code: "other", message: "x" }), "defers"],
      ["android: integrity unavailable (attested before)", "android", async (ar) => (await ar.rig.state.markAttestedAndroid(USER, DEVICE), void (ar.rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "x" })), "defers"],
      ["android: unsupported, attested before", "android", async (ar) => (await ar.rig.state.markAttestedAndroid(USER, DEVICE), void (ar.rig.module.always.integrityToken = { ok: false, code: "unsupported", message: "x" })), "defers"],
      ["android: install link unavailable", "android", (ar) => void (ar.rig.module.nextInstallLink = [{ ok: false, code: "other", message: "x" }]), "defers"],
      ["android: unsupported, never attested", "android", (ar) => void (ar.rig.module.always.integrityToken = { ok: false, code: "unsupported", message: "no play" }), "none"],
      ["android: nothing injected (the control: the token goes out)", "android", () => undefined, "attests"],
    ];
    async function keyed(ar: ReturnType<typeof makeActivationRig>): Promise<void> {
      await ar.rig.state.setIosKey(USER, DEVICE, { state: "registered", keyId: KEY });
      ar.rig.module.keys.add(KEY);
    }
    for (const [name, platform, setup, expected] of injections) {
      const ar = makeActivationRig(platform);
      await setup(ar);
      const outcome = await ar.activator.activate(actInput(), ar.io()).then(
        () => "went" as const,
        (e: unknown) => (e instanceof AttestationDeferred ? ("deferred" as const) : (e as Error)),
      );
      for (const p of ar.posts) {
        if (p.attestation.kind === "none") expect(p.attestation.hardwareSupportsAttestation, name).toBe(false);
      }
      if (expected === "defers") {
        expect(outcome, name).toBe("deferred");
        expect(ar.posts, `${name}: nothing sent`).toEqual([]);
      } else if (expected === "none") {
        expect(outcome, name).toBe("went");
        expect(ar.posts, name).toHaveLength(1);
        expect(ar.posts[0]!.attestation.kind, name).toBe("none");
      } else {
        expect(outcome, name).toBe("went");
        expect(ar.posts[0]!.attestation.kind, name).toBe("android");
      }
    }
  });

  it("the Plain activator (Expo Go, web, a build or device that cannot attest) sends kind none with the claim false, requests no challenge, and refuses a platform that is neither iOS nor Android", async () => {
    for (const platform of ["ios", "android"] as const) {
      const posts: ActivationWireRequest[] = [];
      let live = 0;
      await new PlainActivator(platform).activate(actInput(), { post: async (r) => (posts.push(r), answer()), requestLiveChallenge: async () => (live += 1, Promise.reject(new Error("no"))), registerKey: async () => undefined });
      expect(posts).toEqual([{ deviceId: DEVICE, platform, attestation: { kind: "none", hardwareSupportsAttestation: false } }]);
      expect(live).toBe(0);
    }
    await expect(new PlainActivator("web").activate(actInput(), { post: async () => answer(), requestLiveChallenge: async () => Promise.reject(new Error("no")), registerKey: async () => undefined })).rejects.toBeInstanceOf(ActivationUnsupportedPlatform);
  });
});

describe("ONE ASSERTION IN FLIGHT PER KEY, across check-in and activation (PR #40 gate LOW-1)", () => {
  it("a check-in redemption whose request is in flight holds the lock: the activation does nothing (no DeviceCheck, no challenge, no assertion) until the redemption's response has returned", async () => {
    const ar = await iosRig();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    ar.rig.postReplies = [async () => (await gate, grade("attested"))];
    const checkin = ar.rig.redeemer.redeem(input(), ar.rig.io());
    await settle();
    expect(ar.rig.timeline).toEqual(["native:generateAssertion", "http:post:start"]);
    expect(ar.rig.locks.pendingKeys()).toEqual([assertionLockKey(USER, DEVICE)]);
    const activation = ar.activator.activate(actInput(), ar.io());
    await settle();
    expect(ar.rig.timeline, "the activation waits").toEqual(["native:generateAssertion", "http:post:start"]);
    release();
    await Promise.all([checkin, activation]);
    expect(ar.rig.timeline).toEqual([
      "native:generateAssertion",
      "http:post:start",
      "http:post:end",
      "native:deviceCheckToken",
      "http:live",
      "native:generateAssertion",
      "http:act:start",
      "http:act:end",
    ]);
    expect(ar.rig.locks.pendingKeys()).toEqual([]);
  });

  it("and the other way round: an activation whose request is in flight holds the lock against a check-in redemption", async () => {
    const ar = await iosRig();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    ar.postReplies = [async () => (await gate, answer())];
    const activation = ar.activator.activate(actInput(), ar.io());
    await settle();
    expect(ar.rig.timeline.at(-1)).toBe("http:act:start");
    const checkin = ar.rig.redeemer.redeem(input(), ar.rig.io());
    await settle();
    expect(ar.rig.timeline.at(-1)).toBe("http:act:start"); // the check-in has not generated its assertion
    release();
    await Promise.all([activation, checkin]);
    expect(ar.rig.timeline.slice(-4)).toEqual(["http:act:end", "native:generateAssertion", "http:post:start", "http:post:end"]);
  });

  it("the lock is the check-in's EXACT lock: the same instance and the same key, `ios:<user>:<device lower-case>`, for both, and a DIFFERENT device does not wait", async () => {
    const ar = await iosRig();
    expect(assertionLockKey(USER, DEVICE)).toBe(`ios:${USER}:${DEVICE.toLowerCase()}`);
    expect(assertionLockKey(USER, DEVICE.toUpperCase())).toBe(assertionLockKey(USER, DEVICE));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    ar.rig.postReplies = [async () => (await gate, grade("attested"))];
    const checkin = ar.rig.redeemer.redeem(input(), ar.rig.io());
    await settle();
    const OTHER = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    await ar.rig.state.setIosKey(USER, OTHER, { state: "registered", keyId: KEY });
    await ar.activator.activate(actInput({ deviceId: OTHER }), ar.io()); // another key: not held back
    expect(ar.posts).toHaveLength(1);
    release();
    await checkin;
  });

  it("two activations of one device run strictly one after the other, on both platforms (a double tap, two rewards)", async () => {
    for (const platform of ["ios", "android"] as const) {
      const ar = platform === "ios" ? await iosRig() : makeActivationRig("android");
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      ar.postReplies = [async () => (await gate, answer()), answer({ id: REWARD2 })];
      const a = ar.activator.activate(actInput(), ar.io());
      await settle();
      const b = ar.activator.activate(actInput({ rewardId: REWARD2 }), ar.io());
      await settle();
      expect(ar.posts, platform).toHaveLength(1);
      expect(ar.liveCalls, platform).toBe(1);
      release();
      await Promise.all([a, b]);
      expect(ar.posts, platform).toHaveLength(2);
      expect(ar.rig.timeline.filter((e) => e === "http:act:start").length).toBe(2);
      const firstEnd = ar.rig.timeline.indexOf("http:act:end");
      expect(ar.rig.timeline.indexOf("http:live", ar.rig.timeline.indexOf("http:live") + 1), platform).toBeGreaterThan(firstEnd);
    }
  });

  it("the activator takes the lock through the shared seam (`withLock`), never its own, and the composition hands it `createAttestation().withAssertionLock`", () => {
    const code = strip(src("../src/attest/activator.ts"));
    expect(code).toMatch(/this\.d\.withLock\(ctx\.userId, ctx\.deviceId, \(g\) =>/);
    expect(code).not.toMatch(/new KeyedMutex|\.locks\b/);
    const setup = strip(src("../src/attest/setup.ts"));
    expect(setup).toMatch(/withLock: lock/);
    expect(setup).toMatch(/const lock: AttestationSetup\["withAssertionLock"\] = \(userId, deviceId, fn\) => withAssertionLock\(locks, userId, deviceId, fn\)/);
    expect(setup).toMatch(/redeemer: nativeRedeemer, attestor, state, withLock: lock, markAttestedActivation/);
  });

  it("the hold timeout aborts the activation instead of abandoning it: it reports a deferral, sends nothing, and a late native result changes nothing", async () => {
    const ar = await iosRig({ holdMs: 40, nativeTimeoutMs: 10_000 });
    let release!: () => void;
    ar.rig.module.stall.generateAssertion = [new Promise<void>((r) => (release = r))];
    await expect(ar.activator.activate(actInput(), ar.io())).rejects.toMatchObject({ name: "AttestationDeferred", reason: "assertion_lock_timeout" });
    release();
    await settle();
    expect(ar.posts).toEqual([]);
    expect(ar.rig.locks.pendingKeys()).toEqual([]);
    // the lock is free again
    await ar.activator.activate(actInput(), ar.io());
    expect(ar.posts).toHaveLength(1);
  });

  it("an ApiError from the activation's own live challenge (429, 401, 5xx) reaches the caller as it is, sends nothing, and releases the lock", async () => {
    const ar = await iosRig();
    const e = apiError("rate_limited", 429, "rate_limited", undefined, 60);
    ar.live.push(e);
    await expect(ar.activator.activate(actInput(), ar.io())).rejects.toBe(e);
    expect(ar.posts).toEqual([]);
    expect(ar.rig.module.ops("generateAssertion")).toEqual([]);
    expect(ar.rig.locks.pendingKeys()).toEqual([]);
  });
});

describe("markAttestedActivation (Android 'attested before')", () => {
  const markedAfter = async (reply: ActivationAnswer | Error, platform: "android" | "ios" = "android"): Promise<number> => {
    const ar = platform === "android" ? makeActivationRig("android") : await iosRig();
    ar.postReplies = [reply];
    await ar.activator.activate(actInput(), ar.io()).catch(() => undefined);
    return ar.marked.length;
  };

  it("an `attested` activation (issued / redeemable, not a replay) marks the device, once, and the local flag is then set", async () => {
    const ar = makeActivationRig("android");
    ar.postReplies = [answer({ state: "issued" })];
    await ar.activator.activate(actInput(), ar.io());
    expect(ar.marked).toEqual([{ userId: USER, deviceId: DEVICE }]);
    expect(await ar.rig.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
    const ar2 = makeActivationRig("android");
    ar2.postReplies = [answer({ kind: "entitlement", state: "redeemable" })];
    await ar2.activator.activate(actInput(), ar2.io());
    expect(ar2.marked).toHaveLength(1);
  });

  it("a held_review that grading produced (not a replay) marks too: the answer does not say whether the verdict was `attested`, and marking only makes the client more cautious", async () => {
    expect(await markedAfter(held())).toBe(1);
  });

  it("a REPLAY (an answer that wrote nothing: already held, already active here) does not mark", async () => {
    expect(await markedAfter(answer({ replay: true }))).toBe(0);
    expect(await markedAfter(held({ replay: true }))).toBe(0);
  });

  it("a definite non-application does not mark: any 4xx (404, 403, 409, 422, 429, 401, 400) and a 503 `attestation_*`", async () => {
    for (const e of [
      apiError("not_found", 404, "not_found"),
      apiError("forbidden", 403, "forbidden"),
      apiError("conflict", 409, "reward_not_activatable"),
      apiError("conflict", 409, "reward_expired"),
      apiError("rejected", 422, "platform_mismatch"),
      apiError("rejected", 422, "challenge_not_consumable"),
      apiError("rejected", 422, "device_limit_exceeded"),
      apiError("rate_limited", 429, "rate_limited"),
      apiError("unauthenticated", 401, "unauthorized"),
      apiError("rejected", 400, "bad_request"),
      apiError("unavailable", 503, "attestation_unavailable"),
      apiError("unavailable", 503, "attestation_not_configured"),
    ]) {
      expect(await markedAfter(e), `${e.status}/${e.code}`).toBe(0);
    }
  });

  it("an UNKNOWN outcome after the token was sent marks: a network error, a 500, a 502 / 504, a bare 503, a 200 whose body could not be read", async () => {
    for (const e of [apiError("network", 0, null), apiError("server", 500, "internal_error"), apiError("unavailable", 502, null), apiError("unavailable", 504, null), apiError("unavailable", 503, null), apiError("bad_response", 200, null)]) {
      expect(await markedAfter(e), `${e.kind}/${e.status}`).toBe(1);
    }
  });

  it("a token-less request (the device cannot attest) never marks: it presented no token to be graded", async () => {
    const ar = makeActivationRig("android");
    ar.rig.module.always.integrityToken = { ok: false, code: "unsupported", message: "no play" };
    ar.postReplies = [held()];
    await ar.activator.activate(actInput(), ar.io());
    expect(ar.posts[0]!.attestation.kind).toBe("none");
    expect(ar.marked).toEqual([]);
  });

  it("iOS never calls it, on any answer or error (the key-on-record rule covers iOS)", async () => {
    for (const r of [answer(), held(), answer({ replay: true }), apiError("network", 0, null), apiError("server", 500, null)]) expect(await markedAfter(r, "ios")).toBe(0);
  });

  it("after a marking activation a later local Play Integrity failure defers instead of going token-less (the point of the mark)", async () => {
    const ar = makeActivationRig("android");
    await ar.activator.activate(actInput(), ar.io());
    expect(ar.marked).toHaveLength(1);
    ar.posts.length = 0;
    ar.rig.module.always.integrityToken = { ok: false, code: "unsupported", message: "x" };
    await expect(ar.activator.activate(actInput({ rewardId: REWARD2 }), ar.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(ar.posts).toEqual([]);
    // ... and a check-in redemption defers too, through the redeemer's own rule
    await expect(ar.rig.redeemer.redeem(input(), ar.rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
  });

  it("the composition's markAttestedActivation is `createAttestation`'s (it writes the redeemer's own flag), never throws, and is what the activator is given", async () => {
    const secure = new MemorySecureStore();
    const a = await createAttestation({ module: new FakeNativeAttestModule(), platform: "android", playCloudProjectNumber: CLOUD, secure });
    await a.markAttestedActivation(USER, DEVICE);
    expect(await a.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
    expect(a.activator).toBeInstanceOf(NativeActivator);
    const code = strip(src("../src/attest/activator.ts"));
    expect(code).toMatch(/if \(!answer\.replay\) await this\.d\.markAttestedActivation/);
    expect(code).toMatch(/if \(!isDefiniteNonApplication\(e\)\) await this\.d\.markAttestedActivation/);
  });
});

describe("Android: the install link and the token", () => {
  it("the install link comes from the module, is bound into the hash AND sent; the request carries the token as kind android", async () => {
    const ar = makeActivationRig("android");
    ar.rig.module.installLinkValue = "abcdef0123456789";
    await ar.activator.activate(actInput(), ar.io());
    const hash = androidRequestBinding({ rewardId: REWARD, deviceId: DEVICE, challengeId: "dddddddd-dddd-4ddd-8ddd-000000000001", installLinkId: "abcdef0123456789" }, NONCE);
    expect(integrityRequestsOf(ar)[0]).toMatchObject({ requestHash: bytesToBase64Url(hash) });
    expect(ar.posts[0]).toMatchObject({ platform: "android", installLinkId: "abcdef0123456789", challengeId: "dddddddd-dddd-4ddd-8ddd-000000000001", nonce: NONCE, attestation: { kind: "android" } });
  });

  it("an install link the device cannot give (`unsupported`) is sent without one (the server holds the reward for want of a signal); a transient failure to read it defers BEFORE a challenge is spent", async () => {
    const a = makeActivationRig("android");
    a.rig.module.nextInstallLink = [{ ok: false, code: "unsupported", message: "none" }];
    await a.activator.activate(actInput(), a.io());
    expect(a.posts[0]).not.toHaveProperty("installLinkId");
    const b = makeActivationRig("android");
    b.rig.module.nextInstallLink = [{ ok: false, code: "other", message: "x" }];
    await expect(b.activator.activate(actInput(), b.io())).rejects.toMatchObject({ reason: "install_link_unavailable" });
    expect(b.liveCalls).toBe(0);
  });

  it("a nonce the server would refuse (non-canonical base64url) is a deferral, never a request", async () => {
    const ar = makeActivationRig("android");
    ar.live.push({ id: "dddddddd-dddd-4ddd-8ddd-000000000009", nonce: "AP", expiresAt: "x", kind: "live" });
    await expect(ar.activator.activate(actInput(), ar.io())).rejects.toMatchObject({ reason: "challenge_unusable" });
    expect(ar.posts).toEqual([]);
    expect(ar.rig.module.ops("integrityToken")).toEqual([]);
  });

  it("an unreadable 'attested before' record reads as attested: a device that cannot get a token DEFERS rather than going token-less", async () => {
    const ar = makeActivationRig("android");
    ar.rig.module.always.integrityToken = { ok: false, code: "unsupported", message: "x" };
    ar.rig.state.hasAttestedAndroid = () => Promise.reject(new Error("keystore locked"));
    await expect(ar.activator.activate(actInput(), ar.io())).rejects.toMatchObject({ reason: "integrity_token_unavailable" });
    expect(ar.posts).toEqual([]);
  });
});

describe("iOS: the key lifecycle is the redeemer's, shared", () => {
  it("no key on record: the key is registered through a LIVE challenge (one challenge), then the activation takes its OWN live challenge (a second), DeviceCheck and the assertion in that order, and the key is recorded", async () => {
    const ar = makeActivationRig("ios");
    await ar.activator.activate(actInput(), ar.io());
    expect(ar.liveCalls).toBe(2);
    expect(ar.rig.timeline).toEqual(["native:generateKey", "http:live", "native:attestKey", "http:register", "native:deviceCheckToken", "http:live", "native:generateAssertion", "http:act:start", "http:act:end"]);
    expect(ar.rig.registrations).toHaveLength(1);
    expect(await ar.rig.state.getIosKey(USER, DEVICE)).toMatchObject({ state: "registered" });
    expect(ar.posts[0]!.attestation).toMatchObject({ kind: "ios", keyId: ar.rig.registrations[0]!.keyId });
    // the key the activation used is the one check-in would use: a redemption now registers nothing
    const before = ar.rig.registrations.length;
    await ar.rig.redeemer.redeem(input(), ar.rig.io());
    expect(ar.rig.registrations.length).toBe(before);
  });

  it("a device that cannot attest (App Attest unsupported) or whose key the server refuses sends kind none, claim false, with the DeviceCheck token when the device can give one, and asks for no activation challenge", async () => {
    const ar = makeActivationRig("ios");
    ar.registerReplies = [apiError("unavailable", 503, "attestation_not_configured")];
    await ar.activator.activate(actInput(), ar.io());
    expect(ar.liveCalls).toBe(1); // the registration's challenge only
    expect(ar.posts[0]).toEqual({ deviceId: DEVICE, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false, deviceCheckToken: expect.any(String) } });
    // not asked again for an hour: the next activation does not spend another registration challenge
    await ar.activator.activate(actInput({ rewardId: REWARD2 }), ar.io());
    expect(ar.liveCalls).toBe(1);
    expect(ar.rig.registrations).toHaveLength(1);
  });

  it("the DeviceCheck token is best effort on the none path: a device that cannot produce one still reaches the server, without it", async () => {
    const ar = makeActivationRig("ios");
    ar.rig.module.next.generateKey = [{ ok: false, code: "unsupported", message: "sim" }];
    ar.rig.module.nextDeviceCheck = [{ ok: false, code: "unsupported", message: "sim" }];
    await ar.activator.activate(actInput(), ar.io());
    expect(ar.posts[0]).toEqual({ deviceId: DEVICE, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } });
  });

  it("a stale key (`invalid_key`, a reinstall): a fresh key is registered ONCE and the assertion made again over the SAME hash with the SAME activation challenge", async () => {
    const ar = await iosRig();
    ar.rig.module.destroyKeys();
    await ar.activator.activate(actInput(), ar.io());
    const signed = assertionsOf(ar);
    expect(signed).toHaveLength(2);
    expect(signed[0]!.hashHex).toBe(signed[1]!.hashHex);
    expect(signed[0]!.keyId).toBe(KEY);
    expect(signed[1]!.keyId).not.toBe(KEY);
    expect(ar.rig.registrations).toHaveLength(1);
    expect(ar.liveCalls).toBe(2); // the registration's, and the activation's (one, reused)
    expect(ar.posts).toHaveLength(1);
    expect(ar.posts[0]!.challengeId).toBe("dddddddd-dddd-4ddd-8ddd-000000000001"); // the activation's own challenge, fetched once before the first assertion; the re-registration took the second
  });

  it("DeviceCheck unavailable defers BEFORE any challenge is spent; the DeviceCheck token's SHA-256 is what the assertion signs (the token cannot be swapped)", async () => {
    const a = await iosRig();
    a.rig.module.nextDeviceCheck = [{ ok: false, code: "unavailable", message: "x" }];
    await expect(a.activator.activate(actInput(), a.io())).rejects.toMatchObject({ reason: "devicecheck_unavailable" });
    expect(a.liveCalls).toBe(0);
    const b = await iosRig();
    b.rig.module.deviceCheckValue = Buffer.from("another-token").toString("base64");
    await b.activator.activate(actInput(), b.io());
    const sent = b.posts[0]!;
    const dctSha = toHex(await sha256(new TextEncoder().encode((sent.attestation as { deviceCheckToken: string }).deviceCheckToken)));
    const expected = bytesToHex(iosActivationBinding({ rewardId: REWARD, deviceId: DEVICE, challengeId: sent.challengeId!, deviceCheckTokenSha256: dctSha, nonce: sent.nonce! }));
    expect(assertionsOf(b)[0]!.hashHex).toBe(expected);
  });

  it("the account binding: a token for another account (or one that names none) is refused with nothing done: no native call, no request", async () => {
    const ar = await iosRig();
    await expect(ar.activator.activate(actInput({ accessToken: jwt({ sub: "someone-else" }) }), ar.io())).rejects.toMatchObject({ reason: "account_mismatch" });
    await expect(ar.activator.activate(actInput({ accessToken: "not-a-jwt" }), ar.io())).rejects.toMatchObject({ reason: "no_account_binding" });
    expect(ar.rig.timeline).toEqual([]);
    expect(ar.posts).toEqual([]);
  });
});

describe("selection and the native module", () => {
  it("createAttestation: NativeActivator where the module can attest, PlainActivator everywhere else", async () => {
    const make = (over: Partial<Parameters<typeof createAttestation>[0]>) => createAttestation({ module: new FakeNativeAttestModule(), platform: "ios", playCloudProjectNumber: null, secure: new MemorySecureStore(), ...over });
    expect((await make({})).activator).toBeInstanceOf(NativeActivator);
    expect((await make({ platform: "android", playCloudProjectNumber: CLOUD })).activator).toBeInstanceOf(NativeActivator);
    for (const a of [await make({ module: null }), await make({ platform: "android" }), await make({ platform: "web" })]) expect(a.activator).toBeInstanceOf(PlainActivator);
    const unsupported = new FakeNativeAttestModule();
    unsupported.supported = false;
    expect((await make({ module: unsupported })).activator).toBeInstanceOf(PlainActivator);
  });

  it("the services wire the activator into the real client, with Platform.OS for the plain one", () => {
    const services = strip(src("../src/runtime/services.ts"));
    expect(services).toMatch(/rewards: \{ activator: attestation\.activator, platform: Platform\.OS \}/);
    expect(strip(src("../src/runtime/backend.ts"))).toMatch(/\.\.\.deps\.evidence, \.\.\.deps\.rewards/);
  });

  it("the UnattestableAttestor says unattestable for both new operations, and NativeAttestor keeps each on its own platform", async () => {
    const u = new UnattestableAttestor();
    expect(await u.deviceCheckToken()).toEqual({ kind: "unattestable", reason: "not_implemented" });
    expect(await u.installLinkId()).toEqual({ kind: "unattestable", reason: "not_implemented" });
    const ios = new NativeAttestor(new FakeNativeAttestModule(), "ios", null);
    const android = new NativeAttestor(new FakeNativeAttestModule(), "android", CLOUD);
    expect(await ios.installLinkId()).toEqual({ kind: "unattestable", reason: "platform_unsupported" });
    expect(await android.deviceCheckToken()).toEqual({ kind: "unattestable", reason: "platform_unsupported" });
    expect(await android.installLinkId()).toEqual({ kind: "ok", value: { installLinkId: "0123456789abcdef" } });
  });

  it("a module built before `installLinkId` existed answers unattestable (not a crash); a malformed id is `failed`; the server's own id shape is enforced", async () => {
    const old = new FakeNativeAttestModule();
    const a = new NativeAttestor({ ...old, capability: old.capability.bind(old), installLinkId: undefined } as never, "android", CLOUD);
    expect(await a.installLinkId()).toEqual({ kind: "unattestable", reason: "not_implemented" });
    for (const bad of ["short", "has space 0123456789", "x".repeat(129), ""]) {
      const m = new FakeNativeAttestModule();
      m.installLinkValue = bad;
      expect((await new NativeAttestor(m, "android", CLOUD).installLinkId()).kind, bad).toBe("failed");
    }
  });

  it("Kotlin reads the SSAID with no permission (and refuses the known-broken constant), Swift reports unsupported", () => {
    const kotlin = src("../modules/golfraven-attest/android/src/main/java/expo/modules/golfravenattest/GolfravenAttestModule.kt");
    expect(kotlin).toMatch(/Settings\.Secure\.getString\(context\.contentResolver, Settings\.Secure\.ANDROID_ID\)/);
    expect(kotlin).toMatch(/9774d56d682e549c/);
    expect(src("../modules/golfraven-attest/android/src/main/AndroidManifest.xml")).not.toMatch(/uses-permission/);
    expect(src("../modules/golfraven-attest/ios/GolfravenAttestModule.swift")).toMatch(/AsyncFunction\("installLinkId"\)[\s\S]*?failure\("unsupported"/);
  });
});
