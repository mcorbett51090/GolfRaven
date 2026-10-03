/**
 * Wires the attestation pieces for the composition root: which attestor, which redeemer, and the lock every assertion of this process goes through.
 * Pure over its inputs (the loaded module, `Platform.OS`, the parsed config value, the secure store), so `test/attest-setup.test.ts` runs it under Node.
 */
import type { SecureStore } from "../secure";
import { NativeActivator, PlainActivator, type RewardActivator } from "./activator";
import { KeyedMutex, withAssertionLock, type LockGuard } from "./mutex";
import { NativeAttestor, selectAttestor, type SelectAttestorInput } from "./native";
import { ASSERTION_LOCK_HOLD_MS, NativeRedeemer, PlainRedeemer, type CheckinRedeemer } from "./redeemer";
import { AttestStateStore } from "./state-store";
import type { Attestor } from "./types";

export interface AttestationSetup {
  attestor: Attestor;
  redeemer: CheckinRedeemer;
  /** Reward activation (P4.2b-3b): `NativeActivator` (over the same key lifecycle, lock and state as `redeemer`) where the module is linked and supported, `PlainActivator` (`kind: "none"`, claim `false`) elsewhere. */
  activator: RewardActivator;
  /** The per-key assertion lock. `rewards-activate` (P4.2c) must take assertions through THIS instance: the counter is shared with check-in. */
  locks: KeyedMutex;
  state: AttestStateStore;
  /** The activation seam (P4.2c): runs `fn` under the EXACT assertion lock check-in uses for (userId, deviceId) (`assertionLockKey`). `fn` calls `guard.check()` before each side
   * effect and runs the request that carries its assertion through `guard.effect(...)`, so the lock is held until that response returns or fails. */
  withAssertionLock<T>(userId: string, deviceId: string, fn: (guard: LockGuard) => Promise<T>): Promise<T>;
  /** The activation seam, Android half: the server grades a token-less request `failed` once the device has an `attested` check-in token OR an `attested` activation verdict
   * (0043, `hasAttestedVerdictOnDevice`). So an activation whose verdict is `attested` (or whose outcome is unknown after the request was sent) MUST call this, or a later check-in
   * with a local Play Integrity failure would go token-less and be graded `failed` + fraud signal. Never throws. */
  markAttestedActivation(userId: string, deviceId: string): Promise<void>;
}

export async function createAttestation(input: SelectAttestorInput & { secure: SecureStore; lockHoldMs?: number }): Promise<AttestationSetup> {
  const attestor = await selectAttestor(input);
  const locks = new KeyedMutex({ holdTimeoutMs: input.lockHoldMs ?? ASSERTION_LOCK_HOLD_MS });
  const state = new AttestStateStore(input.secure);
  const nativeRedeemer = attestor instanceof NativeAttestor ? new NativeRedeemer({ attestor, state, locks }) : null;
  const redeemer: CheckinRedeemer = nativeRedeemer ?? new PlainRedeemer();
  const lock: AttestationSetup["withAssertionLock"] = (userId, deviceId, fn) => withAssertionLock(locks, userId, deviceId, fn);
  const markAttestedActivation: AttestationSetup["markAttestedActivation"] = (userId, deviceId) => state.markAttestedAndroid(userId, deviceId).catch(() => undefined);
  const activator: RewardActivator = nativeRedeemer ? new NativeActivator({ redeemer: nativeRedeemer, attestor, state, withLock: lock, markAttestedActivation }) : new PlainActivator(input.platform);
  return { attestor, redeemer, activator, locks, state, withAssertionLock: lock, markAttestedActivation };
}
