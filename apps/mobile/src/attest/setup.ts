/**
 * Wires the attestation pieces for the composition root: which attestor, which redeemer, and the lock every assertion of this process goes through.
 * Pure over its inputs (the loaded module, `Platform.OS`, the parsed config value, the secure store), so `test/attest-setup.test.ts` runs it under Node.
 */
import type { SecureStore } from "../secure";
import { KeyedMutex } from "./mutex";
import { NativeAttestor, selectAttestor, type SelectAttestorInput } from "./native";
import { ASSERTION_LOCK_HOLD_MS, NativeRedeemer, PlainRedeemer, type CheckinRedeemer } from "./redeemer";
import { AttestStateStore } from "./state-store";
import type { Attestor } from "./types";

export interface AttestationSetup {
  attestor: Attestor;
  redeemer: CheckinRedeemer;
  /** The per-key assertion lock. `rewards-activate` (P4.2c) must take assertions through THIS instance: the counter is shared with check-in. */
  locks: KeyedMutex;
  state: AttestStateStore;
}

export async function createAttestation(input: SelectAttestorInput & { secure: SecureStore; lockHoldMs?: number }): Promise<AttestationSetup> {
  const attestor = await selectAttestor(input);
  const locks = new KeyedMutex({ holdTimeoutMs: input.lockHoldMs ?? ASSERTION_LOCK_HOLD_MS });
  const state = new AttestStateStore(input.secure);
  const redeemer: CheckinRedeemer = attestor instanceof NativeAttestor ? new NativeRedeemer({ attestor, state, locks }) : new PlainRedeemer();
  return { attestor, redeemer, locks, state };
}
