/** A rig for `NativeActivator` (P4.2b-3b): the SAME fake native module, secure store, state store and assertion lock as `attest-rig.ts` (one `makeRig`), a `NativeActivator` over them, and a scripted
 * `ActivateIo` whose events go on the SAME timeline as the rig's check-in events, so a test can prove how a check-in redemption and an activation interleave. */
import { NativeActivator, NativeAttestor, NativeRedeemer, withAssertionLock, type ActivateInput, type ActivateIo, type AttestKeyRegistration } from "../../src/attest";
import type { ActivationAnswer, ActivationWireRequest, IssuedChallenge } from "../../src/api/types";
import { DEVICE, NONCE, USER, makeRig, tokenFor, type Rig } from "./attest-rig";

export const REWARD = "aaaaaaaa-0000-4000-8000-000000000001";
export const REWARD2 = "aaaaaaaa-0000-4000-8000-000000000002";
export const CLOUD = "123456789012";

export const answer = (over: Partial<ActivationAnswer> = {}): ActivationAnswer => ({ id: REWARD, kind: "offer_code", state: "issued", held: false, replay: false, ...over });
export const held = (over: Partial<ActivationAnswer> = {}): ActivationAnswer => answer({ state: "held_review", held: true, ...over });

export function actInput(over: Partial<ActivateInput> = {}): ActivateInput {
  return { rewardId: REWARD, deviceId: DEVICE, userId: USER, accessToken: tokenFor(USER), ...over };
}

type Scripted<T> = T | Error | ((n: number) => Promise<T>);

export interface ActivationRig {
  rig: Rig;
  activator: NativeActivator;
  redeemer: NativeRedeemer;
  /** Every activation body, in order. */
  posts: ActivationWireRequest[];
  /** Calls of `markAttestedActivation`. */
  marked: Array<{ userId: string; deviceId: string }>;
  /** Replies for the activation POST, consumed in order (the last repeats). */
  postReplies: Scripted<ActivationAnswer>[];
  /** Live challenges `requestLiveChallenge` hands out, consumed in order (then synthesised). */
  live: Array<IssuedChallenge | Error>;
  liveCalls: number;
  registerReplies: Scripted<void>[];
  io(): ActivateIo;
}

export function makeActivationRig(platform: "ios" | "android", opts: Parameters<typeof makeRig>[1] = {}): ActivationRig {
  const rig = makeRig(platform, opts);
  const attestor = new NativeAttestor(rig.module, platform, platform === "android" ? (opts.cloud === undefined ? CLOUD : opts.cloud) : null);
  const redeemer = rig.redeemer as NativeRedeemer;
  const marked: ActivationRig["marked"] = [];
  const ar: ActivationRig = {
    rig,
    redeemer,
    activator: new NativeActivator({
      redeemer,
      attestor,
      state: rig.state,
      withLock: (userId, deviceId, fn) => withAssertionLock(rig.locks, userId, deviceId, fn),
      markAttestedActivation: async (userId, deviceId) => {
        marked.push({ userId, deviceId });
        await rig.state.markAttestedAndroid(userId, deviceId);
      },
    }),
    posts: [],
    marked,
    postReplies: [answer()],
    live: [],
    liveCalls: 0,
    registerReplies: [undefined],
    io: () => ({
      post: async (req) => {
        ar.posts.push(req);
        rig.timeline.push("http:act:start");
        const reply = ar.postReplies[Math.min(ar.posts.length - 1, ar.postReplies.length - 1)]!;
        try {
          if (typeof reply === "function") return await reply(ar.posts.length);
          if (reply instanceof Error) throw reply;
          return reply;
        } finally {
          rig.timeline.push("http:act:end");
        }
      },
      requestLiveChallenge: async () => {
        ar.liveCalls += 1;
        rig.timeline.push("http:live");
        const next = ar.live.shift();
        if (next instanceof Error) throw next;
        return next ?? { id: `dddddddd-dddd-4ddd-8ddd-${String(ar.liveCalls).padStart(12, "0")}`, nonce: NONCE, expiresAt: "2026-06-01T12:02:00.000Z", kind: "live" };
      },
      registerKey: async (req: AttestKeyRegistration) => {
        rig.registrations.push(req);
        rig.timeline.push("http:register");
        const reply = ar.registerReplies[Math.min(rig.registrations.length - 1, ar.registerReplies.length - 1)]!;
        if (reply instanceof Error) throw reply;
        if (typeof reply === "function") await reply(rig.registrations.length);
      },
    }),
  };
  return ar;
}

/** The assertions the fake module was asked to sign, in order, typed. */
export function assertionsOf(ar: ActivationRig): Array<{ keyId: string; hashHex: string }> {
  return ar.rig.module.events.flatMap((e) => (e.op === "generateAssertion" ? [{ keyId: e.keyId, hashHex: e.hashHex }] : []));
}
export function integrityRequestsOf(ar: ActivationRig): Array<{ cloud: string; requestHash: string }> {
  return ar.rig.module.events.flatMap((e) => (e.op === "integrityToken" ? [{ cloud: e.cloud, requestHash: e.requestHash }] : []));
}
