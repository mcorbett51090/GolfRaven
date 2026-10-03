/** A rig for `NativeRedeemer`: a fake native module, an in-memory secure store, a lock, and a scripted `RedeemIo` with ONE timeline shared with the module. */
import {
  AttestStateStore,
  KeyedMutex,
  NativeAttestor,
  NativeRedeemer,
  type CheckinRedeemer,
  type RedeemInput,
  type RedeemIo,
} from "../../src/attest";
import type { ApiError } from "../../src/api/errors";
import type { CheckinTokenRequest, CheckinTokenResult, IssuedChallenge } from "../../src/api/types";
import { MemorySecureStore } from "../../src/secure";
import { jwt } from "./fakes";
import { FakeNativeAttestModule } from "./fake-native-attest";

export const USER = "uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuu";
export const DEVICE = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const CHALLENGE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const NONCE = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

export const tokenFor = (sub: string): string => jwt({ sub, role: "authenticated" });

export function input(over: Partial<RedeemInput> = {}): RedeemInput {
  return { challengeId: CHALLENGE, nonce: NONCE, deviceId: DEVICE, userId: USER, accessToken: tokenFor(USER), ...over };
}

export const grade = (g: CheckinTokenResult["attestationGrade"] = "attested"): CheckinTokenResult => ({ jti: "jti_1", expiresAt: "2026-06-01T12:15:00.000Z", attestationGrade: g });

type Scripted<T> = T | ApiError | ((n: number) => Promise<T>);

export interface Rig {
  module: FakeNativeAttestModule;
  secure: MemorySecureStore;
  state: AttestStateStore;
  locks: KeyedMutex;
  redeemer: CheckinRedeemer;
  /** Every `post` body, in order. */
  posts: CheckinTokenRequest[];
  /** Every `registerKey` body, in order. */
  registrations: Parameters<RedeemIo["registerKey"]>[0][];
  /** Module events and HTTP events in the order they happened: `native:<op>`, `http:post:start`, `http:post:end`, `http:live`, `http:register`. */
  timeline: string[];
  /** Replies for `post`, consumed in order (the last repeats). A function lets a test hold the reply. */
  postReplies: Scripted<CheckinTokenResult>[];
  registerReplies: Scripted<void>[];
  liveReplies: Scripted<IssuedChallenge>[];
  io(): RedeemIo;
}

export function makeRig(platform: "ios" | "android", opts: { cloud?: string | null; holdMs?: number } = {}): Rig {
  const module = new FakeNativeAttestModule();
  const secure = new MemorySecureStore();
  const state = new AttestStateStore(secure);
  const locks = new KeyedMutex({ holdTimeoutMs: opts.holdMs ?? 60_000 });
  const attestor = new NativeAttestor(module, platform, platform === "android" ? (opts.cloud === undefined ? "123456789012" : opts.cloud) : null);
  const timeline: string[] = [];
  // mirror module events into the shared timeline, at the moment they happen
  const push = module.events.push.bind(module.events);
  module.events.push = (...e) => {
    for (const ev of e) timeline.push(`native:${ev.op}`);
    return push(...e);
  };
  const rig: Rig = {
    module,
    secure,
    state,
    locks,
    redeemer: new NativeRedeemer({ attestor, state, locks }),
    posts: [],
    registrations: [],
    timeline,
    postReplies: [grade("attested")],
    registerReplies: [undefined],
    liveReplies: [],
    io: () => ({
      post: async (req) => {
        rig.posts.push(req);
        timeline.push("http:post:start");
        const reply = rig.postReplies[Math.min(rig.posts.length - 1, rig.postReplies.length - 1)]!;
        try {
          if (typeof reply === "function") return await reply(rig.posts.length);
          if (reply instanceof Error) throw reply;
          return reply;
        } finally {
          timeline.push("http:post:end");
        }
      },
      requestLiveChallenge: async () => {
        timeline.push("http:live");
        const n = rig.timeline.filter((t) => t === "http:live").length;
        const reply = rig.liveReplies[Math.min(n - 1, rig.liveReplies.length - 1)];
        if (reply === undefined) return { id: `dddddddd-dddd-4ddd-8ddd-${String(n).padStart(12, "0")}`, nonce: NONCE, expiresAt: "2026-06-01T12:02:00.000Z", kind: "live" };
        if (reply instanceof Error) throw reply;
        return typeof reply === "function" ? reply(n) : reply;
      },
      registerKey: async (req) => {
        rig.registrations.push(req);
        timeline.push("http:register");
        const reply = rig.registerReplies[Math.min(rig.registrations.length - 1, rig.registerReplies.length - 1)]!;
        if (reply instanceof Error) throw reply;
        if (typeof reply === "function") await reply(rig.registrations.length);
      },
    }),
  };
  return rig;
}
