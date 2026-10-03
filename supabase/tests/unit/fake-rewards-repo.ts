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
  AndroidInstallSignals,
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
  /** Set by a reviewer's approval of a held reward no device ran the table on (H2). ISO text. */
  reviewClearedAt: string | null;
  holdDetail: Record<string, unknown> | null;
  issuedBeforeHold: boolean;
}

export interface FakeDeviceAttest {
  /** `null` = unknown (0042): first seen by an endpoint that carries no platform. */
  platform: "ios" | "android" | null;
  attestKeyId: string | null;
  attestCounter: number;
  attestPublicKey: Uint8Array | null;
  integrityLast: { grade: Grade } | null;
  /** 0043 `first_attested_at` as a boolean: set the first time an `attested` verdict is recorded, and never cleared (the trigger's rule). */
  firstAttested: boolean;
  tokenHash: string | null;
  /** SHA-256 hex of the Android install link id (0027 `install_link_hash`). */
  installLinkHash: string | null;
  /** 0027 `fraud_voided_at`: an admin fraud decision marked this device row. */
  fraudVoided: boolean;
}

export interface FakeRewardsState {
  rewards: Map<string, FakeReward>;
  deviceAttest: Map<string, FakeDeviceAttest>;
  ledger: Array<{ deviceId: string; userId: string; kind: RewardKind; rewardId: string; tokenHash: string | null }>;
  signals: Array<{ userId: string; kind: string; detail: Record<string, unknown>; cleared: boolean; onceKey: string | null; at: number }>;
  /** budget_reserved per offer id (a single synthetic offer is enough). */
  budgetReserved: number;
  /** budget_cap of that synthetic offer (budget_used is 0). Large by default. */
  budgetCap: number;
  /** The install-link tombstone (0027 5g): survives deleting the accounts it names. */
  installTombstones: Array<{ hash: string; account: string; fraudVoided: boolean }>;
  reviewItems: Array<{ kind: string; rewardId: string }>;
  applyCalls: ApplyActivationInput[];
  demoAccounts: Set<string>;
  /** A logical clock for signal / review ordering (the real database orders by microsecond timestamps). */
  seq: number;
}

const states = new WeakMap<FakeState, FakeRewardsState>();

export function rewardsState(state: FakeState): FakeRewardsState {
  let s = states.get(state);
  if (!s) {
    s = { rewards: new Map(), deviceAttest: new Map(), ledger: [], signals: [], budgetReserved: 0, budgetCap: 1_000_000, installTombstones: [], reviewItems: [], applyCalls: [], demoAccounts: new Set(), seq: 0 };
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
    reviewClearedAt: null,
    holdDetail: null,
    issuedBeforeHold: false,
    ...r,
  };
  rewardsState(state).rewards.set(reward.id, reward);
  return reward;
}

/** Registers a device under `userId` in BOTH the shared fake state and the
 * rewards state. */
/** The key id a seeded iOS device carries unless the test says otherwise (see `seedDevice`). */
export const FAKE_ATTEST_KEY_ID = "FAKE-ATTEST-KEY-ID";

export function seedDevice(
  state: FakeState,
  d: {
    id: string;
    userId: string;
    platform: "ios" | "android" | null;
    attestKeyId?: string | null;
    attestCounter?: number;
    attestPublicKey?: Uint8Array | null;
    installLinkHash?: string | null;
    fraudVoided?: boolean;
  },
): void {
  state.devices.set(d.id, { id: d.id, userId: d.userId });
  rewardsState(state).deviceAttest.set(d.id, {
    platform: d.platform,
    // An iOS device defaults to HAVING a key id: `advanceAttestCounter` is bound to the verified key's id (as the SQL is), and a
    // scripted `ok` verdict (the fake ports) stands for a key that verified. Pass `attestKeyId: null` for a keyless device.
    attestKeyId: d.attestKeyId !== undefined ? d.attestKeyId : d.platform === "ios" ? FAKE_ATTEST_KEY_ID : null,
    attestCounter: d.attestCounter ?? 0,
    attestPublicKey: d.attestPublicKey ?? null,
    integrityLast: null,
    firstAttested: false,
    tokenHash: null,
    installLinkHash: d.installLinkHash ?? null,
    fraudVoided: d.fraudVoided ?? false,
  });
}

/** What `Repo#device.ensureOwn(id, platform)` does to the rewards-side row: creates it with the platform it was given — `null` when the endpoint
 * carries none (checkin-challenge, evidence), which stays UNKNOWN (0042) instead of being guessed. A device that already has a row is left alone. */
export function registerFakeDevice(state: FakeState, id: string, platform: "ios" | "android" | null): void {
  const rs = rewardsState(state);
  if (rs.deviceAttest.has(id)) return;
  rs.deviceAttest.set(id, { platform, attestKeyId: null, attestCounter: 0, attestPublicKey: null, integrityLast: null, firstAttested: false, tokenHash: null, installLinkHash: null, fraudVoided: false });
}

export function openSignal(state: FakeState, userId: string, kind: string): void {
  rewardsState(state).signals.push({ userId, kind, detail: {}, cleared: false, onceKey: null, at: ++rewardsState(state).seq });
}

/** Account deletion as private.delete_my_data does it to the Android substitute's
 * inputs: the account's device rows go; the install-link tombstone STAYS. */
export function fakeDeleteAccountDevices(state: FakeState, userId: string): void {
  const rs = rewardsState(state);
  for (const [id, d] of [...state.devices]) {
    if (d.userId !== userId) continue;
    state.devices.delete(id);
    rs.deviceAttest.delete(id);
  }
}

/** app.mark_account_devices_fraud_voided: the account's device rows AND its tombstone rows. */
export function fakeMarkFraudVoided(state: FakeState, userId: string): void {
  const rs = rewardsState(state);
  for (const [id, d] of state.devices) if (d.userId === userId) {
    const a = rs.deviceAttest.get(id);
    if (a) a.fraudVoided = true;
  }
  for (const t of rs.installTombstones) if (t.account === userId) t.fraudVoided = true;
}

/** Mirrors app.resolve_held_offer_code / app.resolve_held_entitlement (0027).
 * A reviewer's approval of a held reward: no device ever ran the table on it ->
 * back to `earned`, review-cleared (H2); otherwise the active state, with the
 * REMAINING validity restored for a reward that was issued before the hold. */
export function fakeResolveHeld(state: FakeState, rewardId: string, approve: boolean): string {
  const rs = rewardsState(state);
  const r = rs.rewards.get(rewardId);
  if (!r || r.state !== "held_review") throw new Error("not held_review");
  if (!approve) {
    if (r.kind === "offer_code" && r.reservedAmount > 0) {
      rs.budgetReserved -= r.reservedAmount;
      r.reservedAmount = 0;
    }
    r.state = "void";
    return r.state;
  }
  r.expiryPausedAt = null;
  r.issuedBeforeHold = false;
  if (r.activatedDeviceId === null) {
    r.state = "earned";
    r.reviewClearedAt = String(++rs.seq);
  } else {
    r.state = r.kind === "offer_code" ? "issued" : "redeemable";
    if (!rs.ledger.some((l) => l.deviceId === r.activatedDeviceId && l.kind === r.kind && l.rewardId === r.id)) {
      rs.ledger.push({ deviceId: r.activatedDeviceId, userId: r.userId, kind: r.kind, rewardId: r.id, tokenHash: r.tokenHash });
    }
  }
  return r.state;
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
        restsOnUnattestable: (r.restsOnUnattestable && r.reviewClearedAt === null) || r.playHeld,
      };
    },
    async deviceAttestState(deviceId: string): Promise<DeviceAttestState | null> {
      const dev = state.devices.get(deviceId);
      if (!dev || dev.userId !== uid) return null;
      const a = rs.deviceAttest.get(deviceId) ?? { platform: null, attestKeyId: null, attestCounter: 0, attestPublicKey: null, integrityLast: null, firstAttested: false, tokenHash: null, installLinkHash: null, fraudVoided: false };
      return { id: deviceId, platform: a.platform, attestKeyId: a.attestKeyId, attestCounter: a.attestCounter, attestPublicKey: a.attestPublicKey };
    },
    async advanceAttestCounter(deviceId: string, keyId: string, counter: number): Promise<boolean> {
      const a = rs.deviceAttest.get(deviceId);
      const dev = state.devices.get(deviceId);
      if (!a || !dev || dev.userId !== uid || a.attestKeyId !== keyId || !(a.attestCounter < counter)) return false;
      a.attestCounter = counter;
      return true;
    },
    async recordDeviceVerdict(deviceId: string, verdict) {
      const a = rs.deviceAttest.get(deviceId);
      if (!a) return;
      a.integrityLast = { grade: verdict.grade };
      if (verdict.grade === "attested") a.firstAttested = true; // app.device_first_attested_stamp: sticky, unlike integrityLast
      if (verdict.tokenHash) a.tokenHash = verdict.tokenHash;
    },
    async hasAttestedVerdictOnDevice(deviceId: string): Promise<boolean> {
      const dev = state.devices.get(deviceId);
      const a = rs.deviceAttest.get(deviceId);
      if (!dev || dev.userId !== uid || !a) return false;
      return a.firstAttested || a.integrityLast?.grade === "attested";
    },
    async hasOpenAttestationFailedSignal(): Promise<boolean> {
      return rs.signals.some((s) => s.userId === uid && s.kind === "attestation_failed" && !s.cleared);
    },
    async canReserveBudget(rewardId: string): Promise<boolean> {
      const r = own(rewardId);
      if (!r || r.kind !== "offer_code" || r.state !== "earned" || r.reservedAmount > 0 || r.faceValue <= 0) return true;
      return rs.budgetReserved + r.faceValue <= rs.budgetCap;
    },
    async raiseAttestationFailedIfNone(detail) {
      if (rs.signals.some((s) => s.userId === uid && s.kind === "attestation_failed" && !s.cleared)) return false;
      rs.signals.push({ userId: uid, kind: "attestation_failed", detail, cleared: false, onceKey: null, at: ++rs.seq });
      state.fraudSignals.push({ kind: "attestation_failed", detail });
      return true;
    },
    async raiseFraudSignalOnce(kind, detail, onceKey) {
      if (rs.signals.some((s) => s.userId === uid && s.kind === kind && !s.cleared && s.onceKey === onceKey)) return false;
      rs.signals.push({ userId: uid, kind, detail: { ...detail, onceKey }, cleared: false, onceKey, at: ++rs.seq });
      state.fraudSignals.push({ kind, detail: { ...detail, onceKey } });
      return true;
    },
    async hasPriorReward(): Promise<boolean> {
      if (rs.ledger.some((l) => l.userId === uid)) return true;
      for (const r of rs.rewards.values()) {
        if (r.userId !== uid) continue;
        // A reward no device ever ran the table on is not evidence of a repeat user (H2).
        if (r.activatedDeviceId === null) continue;
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
        if ((r.restsOnUnattestable && r.reviewClearedAt === null) || r.playHeld || openFailed) throw Errors.conflict("reward_state_changed", "backstop");
        if (r.kind === "offer_code" && r.state === "earned" && r.reservedAmount === 0 && r.faceValue > 0) {
          if (rs.budgetReserved + r.faceValue > rs.budgetCap) {
            // N1: a clean activation the cap cannot reserve for is HELD, never issued unreserved.
            r.issuedBeforeHold = false;
            r.state = "held_review";
            r.holdDetail = { ...(input.holdDetail ?? {}), heldFor: "offer_budget" };
            r.expiryPausedAt ??= state.now.toISOString();
            r.activatedDeviceId ??= input.deviceId;
            r.tokenHash ??= input.tokenHash;
            r.activatedAt ??= state.now.toISOString();
            return { state: r.state };
          }
          r.reservedAmount = r.faceValue;
          rs.budgetReserved += r.faceValue;
        }
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
      if (r.kind === "offer_code" && r.reservedAmount === 0 && r.faceValue > 0 && rs.budgetReserved + r.faceValue <= rs.budgetCap) {
        r.reservedAmount = r.faceValue;
        rs.budgetReserved += r.faceValue;
      }
      r.issuedBeforeHold = r.state === activeState && r.kind === "offer_code";
      r.state = "held_review";
      r.holdDetail = input.holdDetail ?? r.holdDetail;
      r.expiryPausedAt ??= state.now.toISOString();
      r.activatedDeviceId ??= input.deviceId;
      r.tokenHash ??= input.tokenHash;
      r.activatedAt ??= state.now.toISOString();
      return { state: r.state };
    },
    async recordInstallLink(deviceId: string, installLinkHash: string) {
      const dev = state.devices.get(deviceId);
      const a = rs.deviceAttest.get(deviceId);
      if (!dev || dev.userId !== uid || !a) return;
      a.installLinkHash ??= installLinkHash;
      // the tombstone: one row per (install, account), kept when the account is deleted
      if (!rs.installTombstones.some((t) => t.hash === a.installLinkHash && t.account === uid)) {
        rs.installTombstones.push({ hash: a.installLinkHash!, account: uid, fraudVoided: false });
      }
    },
    async androidInstallSignals(deviceId: string): Promise<AndroidInstallSignals | null> {
      const dev = state.devices.get(deviceId);
      const me = rs.deviceAttest.get(deviceId);
      if (!dev || dev.userId !== uid || !me) return null;
      if (me.installLinkHash === null && me.attestKeyId === null) return null;
      const users = new Set<string>();
      let voided = false;
      for (const [id, a] of rs.deviceAttest) {
        const d = state.devices.get(id);
        if (!d) continue;
        const linked = id === deviceId || (me.installLinkHash !== null && a.installLinkHash === me.installLinkHash) || (me.attestKeyId !== null && a.attestKeyId === me.attestKeyId);
        if (!linked) continue;
        users.add(d.userId);
        if (a.fraudVoided) voided = true;
      }
      const tomb = me.installLinkHash === null ? [] : rs.installTombstones.filter((t) => t.hash === me.installLinkHash);
      return { accountsOnInstall: Math.max(users.size, new Set(tomb.map((t) => t.account)).size), voidedAccountUsedInstall: voided || tomb.some((t) => t.fraudVoided) };
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
  calls: { verify: number };
  lastInput: IntegrityInput | null;
}

export function makeFakeAndroidPort(script: { result?: (i: IntegrityInput) => IntegrityResult | Error } = {}): FakeAndroidPort {
  const calls = { verify: 0 };
  const port: FakeAndroidPort = {
    calls,
    lastInput: null,
    async verifyIntegrity(input) {
      calls.verify++;
      port.lastInput = input;
      const r = (script.result ?? (() => ({ grade: "attested" as const })))(input);
      if (r instanceof Error) throw r;
      return r;
    },
  };
  return port;
}

export function ports(p: Partial<AttestationPorts>): AttestationPorts {
  return { ios: null, android: null, ...p };
}
