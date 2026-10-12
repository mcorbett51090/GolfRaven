/**
 * What a build with NO API configured (`EXPO_PUBLIC_API_BASE_URL` / the Supabase values unset or invalid) uses: every network call fails with
 * `not_configured`, the reads answer "nothing" and evidence stays in the outbox. It is the release-build stand-in for the mock, so a release
 * build without server config shows an honest "not available in this build" instead of fake data.
 */
import type { ServerAnswer } from "../outbox";
import { ApiError } from "./errors";
import type { ApiClient } from "./types";
import { DEFAULT_MIN_AGE } from "../age/gate";

export function createUnconfiguredApi(): ApiClient {
  const refuse = (): Promise<never> => Promise.reject(new ApiError({ kind: "not_configured", message: "this build has no API configured" }));
  return {
    getPolicy: () => Promise.resolve({ minAge: DEFAULT_MIN_AGE }),
    listPlays: () => Promise.resolve([]),
    listAchievements: () => Promise.resolve([]),
    listTrailProgrammes: () => Promise.resolve({}),
    listSignInMethods: refuse,
    linkSignInMethod: refuse,
    unlinkSignInMethod: refuse,
    deleteAccount: refuse,
    exportData: refuse,
    registerPushToken: refuse,
    requestCheckinChallenges: refuse,
    redeemCheckinChallenge: refuse,
    provisionOfflineSeed: refuse,
    scanMarker: refuse,
    uploadReceipt: refuse,
    activateReward: refuse,
    listEarnedRewards: () => Promise.resolve([]),
    submitEvidence: (): Promise<ServerAnswer> => Promise.resolve({ kind: "network_error", message: "this build has no API configured" }),
  };
}
