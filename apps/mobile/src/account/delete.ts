/**
 * Me → Delete account (Apple 5.1.1(v), P4 AT 6/19; `DELETE /v1/me` = the `me-delete` function).
 *
 * Order, and why:
 *  1. The SERVER first. `me-delete` queues the Apple/Google grants for revocation, deletes the personal rows, then deletes the Auth user; it is
 *     idempotent, so on any failure nothing local is touched and the player simply tries again. Wiping local state first could strand a player
 *     whose server deletion then failed, signed out of an account that still exists.
 *  2. Only after the server says it is done, the LOCAL wipe: the session (the server session is already gone, so no network call: `clearLocalSession`),
 *     the outbox and the prefetched check-in challenges (the deleted player's own data: nothing of it may be sent to a deleted account or carried to
 *     the next one), and the caches that hold the player's data (`clearUserCaches`) including a data export still sitting in the share cache.
 *     ONLY the deleted user's rows go (plus the ownerless legacy rows, `UNOWNED`, which no account can ever see or send): another user's dormant
 *     plays on a shared device are theirs and stay (P4.2b-0 made rows per-owner so that sign-out leaves them alone; deletion must not undo it).
 *  3. KEPT on purpose: the device-local O18 age flag. It records "this install failed the age gate", not anything about the account; wiping it
 *     with the account would let an under-age player delete their account and retry with another birth year (AT 20: "changing the year on the same
 *     install is refused"). Also kept: the language choice, the per-install device id (a random id, not personal data; the server tombstone and
 *     the device-link rules (N4) rely on a stable device identity), and the PUBLIC signed catalog and its anti-rollback floor (clearing those would be a
 *     one-tap rollback, `catalog/manager.ts`; it is not personal data).
 *
 * The result separates "the account is gone" from "this device still has leftovers" so the screen can say the true thing for each.
 */
import { isApiError } from "../api/errors";
import type { ApiClient, DeleteAccountResult } from "../api/types";
import type { AuthService } from "../auth/types";
import type { ChallengeStore } from "../challenges";
import { UNOWNED, type OutboxStore } from "../outbox";
import type { FileSharer } from "./export";
import { SECURE_KEYS, SESSION_STORAGE_KEY, type SecureStore } from "../secure";

/** The secure-store keys the wipe removes: the session, and nothing else. */
export const WIPED_SECURE_KEYS: readonly string[] = [SESSION_STORAGE_KEY];
/** The secure-store keys the wipe must NEVER remove (`test/account.test.ts` asserts the two lists are disjoint and that these survive). */
export const KEPT_SECURE_KEYS: readonly string[] = [SECURE_KEYS.ageGate, SECURE_KEYS.deviceId];

export interface DeleteDeps {
  api: Pick<ApiClient, "deleteAccount">;
  auth: Pick<AuthService, "clearLocalSession">;
  outbox: Pick<OutboxStore, "deleteByOwners">;
  /** The prefetched check-in challenges (`challenges/store.ts`): the deleted user's are removed. */
  challenges: Pick<ChallengeStore, "deleteOwner">;
  /** A data export left in the cache for a receiving app is deleted too (`FileSharer.purgeStale`, best effort, never throws). */
  sharer: Pick<FileSharer, "purgeStale">;
  /** The signed-in user's id, read BEFORE the server call (the fallback when the server's answer never arrived). */
  currentUserId: () => string | null;
  /** Removes `WIPED_SECURE_KEYS` directly (the session key), so the session is gone even if the auth library still holds it. */
  secure: Pick<SecureStore, "delete">;
  /** Drops in-memory/cached per-user data (plays, achievements, programmes). */
  clearUserCaches: () => void | Promise<void>;
}

export type DeleteOutcome =
  | { status: "deleted"; result: DeleteAccountResult; localWipe: "complete" | "partial"; failedSteps: string[] }
  /** The server never confirmed, but an earlier attempt of `DELETE me` may have been executed (its answer was lost) and the call then ended as
   * `unauthenticated`: the retry's token was refused, which is evidence the user no longer exists. The account is probably gone and the session is
   * unusable, so the local wipe ran anyway (the same steps, every owner's outbox rows included). The screen says exactly that. */
  | { status: "deleted_or_session_ended"; cause: "unauthenticated"; localWipe: "complete" | "partial"; failedSteps: string[] }
  | { status: "failed"; error: unknown };

export async function deleteAccountAndWipeLocal(deps: DeleteDeps): Promise<DeleteOutcome> {
  const signedInUser = deps.currentUserId();
  let result: DeleteAccountResult | null = null;
  try {
    result = await deps.api.deleteAccount();
  } catch (error) {
    // `DELETE me` is idempotent, so the client retries it. The sequence this guards: the server deletes the account, the response is lost, the retry
    // gets 401 (the user is gone), the refresh is refused => `unauthenticated`, and auth-js drops the session, so the player could not even try again.
    // ONLY that combination (an earlier attempt may have run AND the final answer is `unauthenticated`) is treated as "probably deleted". Every
    // other failure stays `failed` with nothing local touched and the session kept, so the player can retry: that includes plain offline or a
    // server that is down (transport failures / 5xx on every attempt say nothing about whether the account exists) and a first-attempt 401.
    if (isApiError(error) && error.mayHaveBeenApplied && error.kind === "unauthenticated") result = null;
    else return { status: "failed", error };
  }
  const failedSteps: string[] = [];
  const attempt = async (name: string, fn: () => void | Promise<void>): Promise<void> => {
    try {
      await fn();
    } catch {
      failedSteps.push(name);
    }
  };
  // Every step runs even if an earlier one failed: a stuck outbox must not leave the session behind, and vice versa.
  await attempt("session", () => deps.auth.clearLocalSession());
  await attempt("session-key", async () => {
    for (const key of WIPED_SECURE_KEYS) await deps.secure.delete(key);
  });
  // The deleted user: the server's own answer when there is one, else the user who was signed in. With neither, only the ownerless rows can be removed.
  const deletedUser = result?.userId ?? signedInUser;
  const owners = deletedUser !== null && deletedUser !== UNOWNED ? [deletedUser, UNOWNED] : [UNOWNED];
  await attempt("outbox", () => deps.outbox.deleteByOwners(owners));
  await attempt("challenges", async () => {
    if (deletedUser !== null && deletedUser !== UNOWNED) await deps.challenges.deleteOwner(deletedUser);
  });
  await attempt("export-cache", () => deps.sharer.purgeStale());
  await attempt("caches", () => deps.clearUserCaches());
  const localWipe = failedSteps.length === 0 ? "complete" : "partial";
  if (result === null) return { status: "deleted_or_session_ended", cause: "unauthenticated", localWipe, failedSteps };
  return { status: "deleted", result, localWipe, failedSteps };
}
