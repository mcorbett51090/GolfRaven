/**
 * Activating one earned reward from the Wallet (build plan §7.5): `activateReward(deps, rewardId)` = who, which device, which credentials, then `api.activateReward` (the attestation, the
 * assertion lock shared with check-in, the key lifecycle and the request are the activator's, `attest/activator.ts`), then the answer or the error mapped to an `ActivationOutcome`
 * (`outcome.ts`). Never throws; says what happened.
 *
 * The request is made as ONE owner with THAT owner's token (`session.accessTokenFor(owner)`), so a user who signs out and another who signs in mid-flight cannot be activated as, and the
 * answer is for the owner: the caller discards it when the signed-in user is no longer the one who asked.
 */
import type { ApiClient } from "../api/types";
import type { OutboxSession } from "../outbox";
import { outcomeFromAnswer, outcomeFromError, type ActivationOutcome } from "./outcome";

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export interface RewardActivationDeps {
  api: Pick<ApiClient, "activateReward">;
  session: OutboxSession;
  deviceId: () => Promise<string>;
}

export async function activateReward(deps: RewardActivationDeps, rewardId: string): Promise<ActivationOutcome> {
  const owner = deps.session.currentUserId();
  if (owner === null || owner === "") return { status: "signed_out" };
  if (!UUID_RE.test(rewardId)) return { status: "rejected", code: null }; // the server names a reward by a UUID in the path only
  let deviceId: string;
  try {
    deviceId = await deps.deviceId();
  } catch {
    return { status: "failed" };
  }
  let accessToken: string | null;
  try {
    accessToken = await deps.session.accessTokenFor(owner);
  } catch {
    return { status: "offline" }; // a refresh that could not reach the server: nothing was sent
  }
  if (accessToken === null) return { status: deps.session.currentUserId() === owner ? "sign_in_required" : "signed_out" };
  try {
    return outcomeFromAnswer(await deps.api.activateReward({ rewardId: rewardId.toLowerCase(), deviceId }, { userId: owner, accessToken }));
  } catch (e) {
    return outcomeFromError(e);
  }
}
