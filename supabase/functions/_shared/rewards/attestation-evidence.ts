// supabase/functions/_shared/rewards/attestation-evidence.ts
//
// The two pieces of attestation grading that `checkin-token` and `rewards-activate` MUST agree on, written once. Before this module each handler
// carried its own verbatim copy (the "has this device shown it can attest" rule, and the re-read that names why an atomic counter advance
// did not advance); a rule that exists in two places is a rule that drifts in one of them.
//
// VERIFICATION-ONLY (rewards-isolation.test.ts): imported by the earning side (`checkin/token-handler.ts`), so it reads no persistent device bit and
// names none. It uses only the `Repo` methods the earning side already holds.
//
// 1. THE NO-ATTESTATION RULE. A request that carries no attestation is graded from `hardwareSupportsAttestation`, a client self-report, so
//    "I cannot attest" counts only when the server has no evidence to the contrary for THAT DEVICE ROW. The evidence, any one of:
//      - iOS: a REGISTERED App Attest key on the device row (`deviceAttestState` returns a key only for a verified registration, 0034);
//      - Android (and iOS): a check-in token previously issued on the device graded `attested` (`checkinToken.hasAttestedOnDevice`);
//      - either platform: an ACTIVATION verdict of `attested` recorded on the device (`rewards.hasAttestedVerdictOnDevice`, 0043: sticky).
//
//    ⚠ WHAT THIS DOES AND DOES NOT CLOSE. The evidence is bound to a device ID, and the device id is CHOSEN BY THE CLIENT (up to
//    MAX_DEVICES_PER_USER = 20 per account). It therefore NARROWS the self-report for an honest client (a real device that attested once cannot
//    later claim it cannot); it does NOT close the claim for an attacker, who can claim "incapable" on a device id that has never attested.
//    Per account the cost to that attacker is `unattestable` instead of `failed`: both are held in activation and neither is a co-signal at check-in.
//    The account-level variant ("any device of the account has attested, so none may claim it cannot") was evaluated and NOT implemented: see
//    docs/security/p3-money-path-requirements.md, "Attestation follow-ups", for the trade-off and the open owner decision.
//
// 2. WHY A COUNTER DID NOT ADVANCE. The atomic advance (`UPDATE ... WHERE attest_key_id = $key AND attest_counter < $new`) updates zero rows for
//    three different reasons that grade the same (`failed`, strict monotonicity unchanged) but mean different things to a reviewer reading the
//    signal: the key was REPLACED between the read and the write; a LOWER counter than the one now stored (a concurrent assertion with a
//    higher counter committed first: an honest client that has two assertions in flight, not a replay); or an EQUAL one (the same counter was
//    presented twice). The reason is a diagnostic only: it decides nothing.

import type { Repo } from "../types.ts";

export type EvidenceRepo = Pick<Repo, "rewards" | "checkinToken">;

/** Has this account's device row shown it can attest? (the no-attestation rule, item 1 of the header) */
export async function deviceHasShownAttestation(deviceId: string, repo: EvidenceRepo): Promise<boolean> {
  const state = await repo.rewards.deviceAttestState(deviceId);
  if (state !== null && state.attestKeyId !== null) return true;
  if (await repo.checkinToken.hasAttestedOnDevice(deviceId)) return true;
  return repo.rewards.hasAttestedVerdictOnDevice(deviceId);
}

export interface NoAttestationGrade {
  grade: "failed" | "unattestable";
  /** The client said its hardware can attest. */
  claimedCapable: boolean;
  /** The claim was "cannot", and the server's own evidence says otherwise. Never true when `claimedCapable` is (no lookup is made then). */
  provenCapable: boolean;
}

/** G3-08's "no token" rule: `failed` on hardware that supports attestation, otherwise `unattestable`, with the claim believed only when the
 * server has no evidence to the contrary. The ONE implementation both endpoints call. */
export async function gradeNoAttestation(claimedCapable: boolean, deviceId: string, repo: EvidenceRepo): Promise<NoAttestationGrade> {
  const provenCapable = claimedCapable ? false : await deviceHasShownAttestation(deviceId, repo);
  return { grade: claimedCapable || provenCapable ? "failed" : "unattestable", claimedCapable, provenCapable };
}

/** The reasons stored on `fraud_signal.detail.reasons` for a `failed` no-attestation request: one vocabulary for both endpoints. */
export function noAttestationReasons(g: NoAttestationGrade): string[] {
  return g.provenCapable ? ["no_attestation_token", "device_has_attested_before"] : ["no_attestation_token"];
}

// 3. THE KEY-IDENTITY CLASS (the `rekey` hint). Of everything `verifyAppAttestAssertion` can refuse, exactly two reasons say "the key the client named is not
//    the key this server holds for this device, or it holds none": `key_id_mismatch` (graded `failed`) and `key_not_registered` (graded `unattestable`).
//    Everything else (a counter that did not advance, a bad signature, a wrong rpId, a binding that does not hash, a malformed assertion, a key replaced
//    mid-flight) says something about THIS assertion, not about which key is on record, and stays indistinguishable from the outside. The set is one
//    function so the two spellings cannot drift apart from the verifier's vocabulary (a unit test pins each against the real verifier's output).
//    See docs/security/p3-money-path-requirements.md, "Stale App Attest key recovery (the `rekey` hint)".

/** The assertion-verification reasons that mean "your key is not the one on record". */
export const KEY_IDENTITY_REASONS: readonly string[] = ["key_id_mismatch", "key_not_registered"];

/** True when a refused assertion's `reason` is a key-identity one: the one case in which `checkin-token` adds `rekey: true` to its answer. */
export function isKeyIdentityReason(reason: string): boolean {
  return KEY_IDENTITY_REASONS.includes(reason);
}

export type LostAdvanceReason = "key_replaced" | "counter_out_of_order" | "counter_replay";

/** Names why `advanceAttestCounter` updated zero rows, for the diagnostic only (the grade is `failed` either way). Reads the device again, and
 * only on this failure path, in the same transaction (READ COMMITTED sees a committed concurrent advance or replacement).
 *   - the key on the device is no longer the one the assertion verified against -> `key_replaced`;
 *   - the stored counter is now HIGHER than the presented one -> `counter_out_of_order` (strict monotonicity still refuses it);
 *   - otherwise (equal, or the device is gone, or there was no key to advance) -> `counter_replay`. */
export async function lostAdvanceReason(deviceId: string, verifiedKeyId: string | null, presentedCounter: number, repo: Pick<Repo, "rewards">): Promise<LostAdvanceReason> {
  if (verifiedKeyId === null) return "counter_replay";
  const current = await repo.rewards.deviceAttestState(deviceId);
  if (current === null) return "counter_replay";
  if (current.attestKeyId !== verifiedKeyId) return "key_replaced";
  return current.attestCounter > presentedCounter ? "counter_out_of_order" : "counter_replay";
}
