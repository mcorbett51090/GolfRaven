/**
 * Me → Delete account (Apple 5.1.1(v), P4 AT 6/19; `DELETE /v1/me` = the `me-delete` function).
 *
 * Order, and why:
 *  1. The SERVER first. `me-delete` queues the Apple/Google grants for revocation, deletes the personal rows, then deletes the Auth user; it is
 *     idempotent, so on any failure nothing local is touched and the player simply tries again. Wiping local state first could strand a player
 *     whose server deletion then failed, signed out of an account that still exists.
 *  2. Only after the server says it is done, the LOCAL wipe: the session (the server session is already gone, so no network call: `clearLocalSession`),
 *     the outbox (the deleted player's own data: nothing of it may be sent to a deleted account or carried to the next one), and the caches that hold
 *     the player's data (`clearUserCaches`).
 *  3. KEPT on purpose: the device-local O18 age flag. It records "this install failed the age gate", not anything about the account; wiping it
 *     with the account would let an under-age player delete their account and retry with another birth year (AT 20: "changing the year on the same
 *     install is refused"). Also kept: the language choice, the per-install device id (a random id, not personal data; the server tombstone and
 *     the device-link rules (N4) rely on a stable device identity), and the PUBLIC signed catalog and its anti-rollback floor (clearing those would be a
 *     one-tap rollback, `catalog/manager.ts`; it is not personal data).
 *
 * The result separates "the account is gone" from "this device still has leftovers" so the screen can say the true thing for each.
 */
import type { ApiClient, DeleteAccountResult } from "../api/types";
import type { AuthService } from "../auth/types";
import type { OutboxStore } from "../outbox";
import { SECURE_KEYS, SESSION_STORAGE_KEY, type SecureStore } from "../secure";

/** The secure-store keys the wipe removes: the session, and nothing else. */
export const WIPED_SECURE_KEYS: readonly string[] = [SESSION_STORAGE_KEY];
/** The secure-store keys the wipe must NEVER remove (`test/account.test.ts` asserts the two lists are disjoint and that these survive). */
export const KEPT_SECURE_KEYS: readonly string[] = [SECURE_KEYS.ageGate, SECURE_KEYS.deviceId];

export interface DeleteDeps {
  api: Pick<ApiClient, "deleteAccount">;
  auth: Pick<AuthService, "clearLocalSession">;
  outbox: Pick<OutboxStore, "deleteAll">;
  /** Removes `WIPED_SECURE_KEYS` directly (the session key), so the session is gone even if the auth library still holds it. */
  secure: Pick<SecureStore, "delete">;
  /** Drops in-memory/cached per-user data (plays, achievements, programmes). */
  clearUserCaches: () => void | Promise<void>;
}

export type DeleteOutcome =
  | { status: "deleted"; result: DeleteAccountResult; localWipe: "complete" | "partial"; failedSteps: string[] }
  | { status: "failed"; error: unknown };

export async function deleteAccountAndWipeLocal(deps: DeleteDeps): Promise<DeleteOutcome> {
  let result: DeleteAccountResult;
  try {
    result = await deps.api.deleteAccount();
  } catch (error) {
    return { status: "failed", error };
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
  await attempt("outbox", () => deps.outbox.deleteAll());
  await attempt("caches", () => deps.clearUserCaches());
  return { status: "deleted", result, localWipe: failedSteps.length === 0 ? "complete" : "partial", failedSteps };
}
