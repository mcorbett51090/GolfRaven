// supabase/tests/unit/fake-rewards-repo.ts
//
// In-memory implementation of `RewardsRepo` (supabase/functions/_shared/
// rewards/types.ts) for unit-testing activate-handler.ts without a database,
// plus scripted fake vendor ports. The state-machine in `applyActivation`
// MIRRORS app.activate_offer_code / app.activate_entitlement (0027) — same
// transitions, same refusals, same ledger rows, same budget reservation — and
// the Deno integration suite (supabase/tests/integration/rewards-activate.
// deno.test.ts) runs the SAME scenarios against the real SQL, which is what
// keeps this fake honest.
//
// State is kept in a WeakMap keyed by the shared `FakeState`, so fake-repo.ts's
// own interface needs no change beyond mounting `rewards`.

import { Errors } from "../../functions/_shared/http.ts";
import type {
  AndroidPort,
  AppAttestAssertionInput,
  ApplyActivationInput,
  AssertionResult,
  AttestationPorts,
  DeviceAttestState,
  DeviceBits,
  Grade,
  IntegrityInput,
  IntegrityResult,
  IosPort,
  OwnReward,
  RewardKind,
  RewardsRepo,
} from "../../functions/_shared/rewards/types.ts";
import type { FakeState } from "./fake-repo.ts";

export interface FakeReward {
  kind: RewardKind;
  id: string;
  userId: string;
  state: string;
  activatedDeviceId: string | null;
  activatedAt: string | null;
  tokenHash: string | null;
  expiresAt: string | null;
  expiryPausedAt: string | null;
  earnedAt: string;
  restsOnUnattestable: boolean;
  playHeld: boolean;
  /** offer_code only */
  faceValue: number;
  reservedAmount: number;
}

export interface FakeDeviceAttest {
  platform: "ios" | "android";
  attestKeyId: string | null;
  attestCounter: number;
  attestPublicKey: Uint8Array | null;
  integrityLast: { grade: Grade } | null;
  tokenHash: string | null;
}

export interface FakeRewardsState {
  rewards: Map<string, FakeReward>;
  deviceAttest: Map<string, FakeDeviceAttest>;
  ledger: Array<{ deviceId: string; userId: string; kind: RewardKind; rewardId: string; tokenHash: string | null }>;
  signals: Array<{ userId: string; kind: string; detail: Record<string, unknown>; cleared: boolean; onceKey: string | null }>;
  /** budget_reserved per offer id (a single synthetic offer is enough). */
  budgetReserved: number;
  reviewItems: Array<{ kind: string; rewardId: string }>;
  applyCalls: ApplyActivationInput[];
  demoAccounts: Set<string>;
}

const states = new WeakMap<FakeState, FakeRewardsState>();

export function rewardsState(state: FakeState): FakeRewardsState {
  let s = states.get(state);
  if (!s) {
    s = { rewards: new Map(), deviceAttest: new Map(), ledger: [], signals: [], budgetReserved: 0, reviewItems: [], applyCalls: [], demoAccounts: new Set() };
    states.set(state, s);
  }
  return s;
}

export function seedReward(state: FakeState, r: Partial<FakeReward> & { id: string; userId: string; kind: RewardKind }): FakeReward {
  const reward: FakeReward = {
    state: "earned",
    activatedDeviceId: null,
    activatedAt: null,
    tokenHash: null,
    expiresAt: null,
    expiryPausedAt: null,
    earnedAt: state.now.toISOString(),
    restsOnUnattestable: false,
    playHeld: false,
    faceValue: 0,
    reservedAmount: 0,
    ...r,
  };
  rewardsState(state).rewards.set(reward.id, reward);
  return reward;
}

/** Registers a device under `userId` in BOTH the shared fake state and the
 * rewards state. */
export function seedDevice(state: FakeState, d: { id: string; userId: string; platform: "ios" | "android"; attestKeyId?: string | null; attestCounter?: number; attestPublicKey?: Uint8Array | null }): void {
  state.devices.set(d.id, { id: d.id, userId: d.userId });
  rewardsState(state).deviceAttest.set(d.id, {
    platform: d.platform,
    attestKeyId: d.attestKeyId ?? null,
    attestCounter: d.attestCounter ?? 0,
    attestPublicKey: d.attestPublicKey ?? null,
    integrityLast: null,
    tokenHash: null,
  });
}

export function openSignal(state: FakeState, userId: string, kind: string): void {
  rewardsState(state).signals.push({ userId, kind, detail: {}, cleared: false, onceKey: null });
}

export function makeFakeRewardsRepo(state: FakeState, uid: string): RewardsRepo {
  const rs = rewardsState(state);
  const own = (id: string): FakeReward | null => {
    const r = rs.rewards.get(id);
    return r && r.userId === uid ? r : null;
  };
  return {
    async isAppReviewDemoAccount(): Promise<boolean> {
      return rs.demoAccounts.has(uid);
    },
    async lockOwnReward(id: string): Promise<OwnReward | null> {
      const r = own(id);
      if (!r) return null;
      return {
        kind: r.kind,
        id: r.id,
        state: r.state,
        activatedDeviceId: r.activatedDeviceId,
        expiresAt: r.expiresAt,
        expiryPaused: r.expiryPausedAt !== null,
        restsOnUnattestable: r.restsOnUnattestable || r.playHeld,
      };
    },
    async deviceAttestState(deviceId: string): Promise<DeviceAttestState | null> {
      const dev = state.devices.get(deviceId);
      if (!dev || dev.userId !== uid) return null;
      const a = rs.deviceAttest.get(deviceId) ?? { platform: "ios" as const, attestKeyId: null, attestCounter: 0, attestPublicKey: null, integrityLast: null, tokenHash: null };
      return { id: deviceId, platform: a.platform, attestKeyId: a.attestKeyId, attestCounter: a.attestCounter, attestPublicKey: a.attestPublicKey };
    },
    async advanceAttestCounter(deviceId: string, counter: number): Promise<boolean> {
      const a = rs.deviceAttest.get(deviceId);
      const dev = state.devices.get(deviceId);
      if (!a || !dev || dev.userId !== uid || !(a.attestCounter < counter)) return false;
      a.attestCounter = counter;
      return true;
    },
    async recordDeviceVerdict(deviceId: string, verdict) {
      const a = rs.deviceAttest.get(deviceId);
      if (!a) return;
      a.integrityLast = { grade: verdict.grade };
      if (verdict.tokenHash) a.tokenHash = verdict.tokenHash;
    },
    async hasOpenAttestationFailedSignal(): Promise<boolean> {
      return rs.signals.some((s) => s.userId === uid && s.kind === "attestation_failed" && !s.cleared);
    },
    async raiseAttestationFailedIfNone(detail) {
      if (rs.signals.some((s) => s.userId === uid && s.kind === "attestation_failed" && !s.cleared)) return false;
      rs.signals.push({ userId: uid, kind: "attestation_failed", detail, cleared: false, onceKey: null });
      state.fraudSignals.push({ kind: "attestation_failed", detail });
      return true;
    },
    async raiseFraudSignalOnce(kind, detail, onceKey) {
      if (rs.signals.some((s) => s.userId === uid && s.kind === kind && !s.cleared && s.onceKey === onceKey)) return false;
      rs.signals.push({ userId: uid, kind, detail: { ...detail, onceKey }, cleared: false, onceKey });
      state.fraudSignals.push({ kind, detail: { ...detail, onceKey } });
      return true;
    },
    async hasPriorReward(): Promise<boolean> {
      if (rs.ledger.some((l) => l.userId === uid)) return true;
      for (const r of rs.rewards.values()) {
        if (r.userId !== uid) continue;
        if (r.kind === "offer_code" && (r.state === "issued" || r.state === "redeemed")) return true;
        if (r.kind === "entitlement" && (r.state === "redeemable" || r.state === "vouchered" || r.state === "redeemed")) return true;
      }
      return false;
    },
    async applyActivation(input: ApplyActivationInput) {
      rs.applyCalls.push(input);
      const r = own(input.rewardId);
      if (!r) throw Errors.notFound("no such reward");
      const dev = state.devices.get(input.deviceId);
      if (!dev || dev.userId !== uid) throw new Error("device not owned by this user");
      if (r.state === "held_review") return { state: r.state };
      const activeState = r.kind === "offer_code" ? "issued" : "redeemable";
      if (r.state !== "earned" && r.state !== activeState) throw Errors.conflict("reward_not_activatable", "state");
      if (r.expiresAt !== null && Date.parse(r.expiresAt) <= state.now.getTime() && r.expiryPausedAt === null) throw Errors.conflict("reward_not_activatable", "expired");

      if (input.decision === "activate") {
        // The DB-side backstops for table rows 2 and 3 (0027).
        const openFailed = rs.signals.some((s) => s.userId === uid && s.kind === "attestation_failed" && !s.cleared);
        if (r.restsOnUnattestable || r.playHeld || openFailed) throw Errors.conflict("reward_state_changed", "backstop");
        r.state = activeState;
        r.activatedDeviceId ??= input.deviceId;
        r.tokenHash ??= input.tokenHash;
        r.activatedAt ??= state.now.toISOString();
        if (!rs.ledger.some((l) => l.deviceId === input.deviceId && l.kind === r.kind && l.rewardId === r.id)) {
          rs.ledger.push({ deviceId: input.deviceId, userId: uid, kind: r.kind, rewardId: r.id, tokenHash: input.tokenHash });
        }
        return { state: r.state };
      }
      // held_review
      if (r.kind === "offer_code" && r.reservedAmount === 0 && r.faceValue > 0) {
        r.reservedAmount = r.faceValue;
        rs.budgetReserved += r.faceValue;
      }
      r.state = "held_review";
      r.expiryPausedAt ??= state.now.toISOString();
      r.activatedDeviceId ??= input.deviceId;
      r.tokenHash ??= input.tokenHash;
      r.activatedAt ??= state.now.toISOString();
      return { state: r.state };
    },
  };
}

// ---------------------------------------------------------------------------
// Fake vendor ports — scripted, with call counters so a test can prove WHEN a
// vendor was (not) consulted.
// ---------------------------------------------------------------------------
export interface FakeIosScript {
  assertion: (input: AppAttestAssertionInput) => AssertionResult;
  bits: DeviceBits | Error;
  setBit0Error?: Error;
}

export interface FakeIosPort extends IosPort {
  calls: { verify: number; readBits: number; setBit0: number };
  lastVerifyInput: AppAttestAssertionInput | null;
  lastSetBit0Known: DeviceBits | null;
}

export function makeFakeIosPort(script: Partial<FakeIosScript> = {}): FakeIosPort {
  const calls = { verify: 0, readBits: 0, setBit0: 0 };
  const port: FakeIosPort = {
    calls,
    lastVerifyInput: null,
    lastSetBit0Known: null,
    async verifyAssertion(input) {
      calls.verify++;
      port.lastVerifyInput = input;
      return (script.assertion ?? (() => ({ ok: true as const, counter: input.device.attestCounter + 1 })))(input);
    },
    async readBits() {
      calls.readBits++;
      const b = script.bits ?? { bit0: false, bit1: false, lastUpdateMonth: null };
      if (b instanceof Error) throw b;
      return b;
    },
    async setBit0(_token, known) {
      calls.setBit0++;
      port.lastSetBit0Known = known;
      if (script.setBit0Error) throw script.setBit0Error;
    },
  };
  return port;
}

export interface FakeAndroidPort extends AndroidPort {
  calls: { verify: number; setBit0: number };
  lastInput: IntegrityInput | null;
}

export function makeFakeAndroidPort(script: { result?: (i: IntegrityInput) => IntegrityResult | Error } = {}): FakeAndroidPort {
  const calls = { verify: 0, setBit0: 0 };
  const port: FakeAndroidPort = {
    calls,
    lastInput: null,
    async verifyIntegrity(input) {
      calls.verify++;
      port.lastInput = input;
      const r = (script.result ?? (() => ({ grade: "attested" as const, bits: { bit0: false, bit1: false, lastUpdateMonth: null } })))(input);
      if (r instanceof Error) throw r;
      return r;
    },
    async setBit0() {
      calls.setBit0++;
    },
  };
  return port;
}

export function ports(p: Partial<AttestationPorts>): AttestationPorts {
  return { ios: null, android: null, ...p };
}
