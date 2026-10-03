/**
 * The O18 under-age flag in the secure store (LOW-D, PR #26 gate).
 *
 * Why it moved: the flag used to live in `golfraven.db`, which `expo-sqlite` keeps in `<Documents>/SQLite` on iOS, a directory iCloud/iTunes
 * backups include (`test/ios-backup.test.ts` pins that). A flag that rides a backup to a restored device lets an under-age player
 * retry there. In the secure store it is written with `keychainAccessible: AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` (`secure/expo-secure-store.ts`),
 * a Keychain class that is excluded from backups and device migration. Android already has `allowBackup: false`.
 *
 * Three pieces:
 *  - `SecureDeviceFlagStore`: a `DeviceFlagStore` over any `SecureStore`, one namespaced key per flag. Read errors are NOT swallowed: an
 *    unreadable store must never read as "no flag" (that would re-open the gate), so `AgeGate` lets the error surface.
 *  - `migrateAgeFlag`: moves an existing SQLite flag across ONCE, then deletes it from SQLite. Copy, read back, then delete: the flag is never
 *    absent from both places, and a failure at any step leaves the SQLite copy in place for the next launch to retry.
 *  - `failClosedAgeFlags`: what the composition root uses when the migration or the secure store fails. It answers `ineligible` to every read
 *    and refuses writes, so sign-in is blocked (guest browse still works) until the store works again. Blocking is the safe direction.
 */
import type { SecureStore } from "../secure";
import type { DeviceFlagStore } from "./flags";
import { AGE_FLAG_KEY } from "./gate";

const NAMESPACE = "gr.flag.";

export class SecureDeviceFlagStore implements DeviceFlagStore {
  constructor(private readonly secure: SecureStore) {}
  get(key: string): Promise<string | null> {
    return this.secure.get(NAMESPACE + key);
  }
  set(key: string, value: string): Promise<void> {
    return this.secure.set(NAMESPACE + key, value);
  }
  delete(key: string): Promise<void> {
    return this.secure.delete(NAMESPACE + key);
  }
}

export type AgeFlagMigration = "nothing_to_migrate" | "migrated" | "already_secure";

/** Moves `age_gate` from `legacy` (SQLite) to `secure`, once. `ineligible` always wins over `eligible` if both exist. Throws if the secure
 * store cannot take the value; the legacy copy is then untouched. */
export async function migrateAgeFlag(legacy: DeviceFlagStore, secure: DeviceFlagStore): Promise<AgeFlagMigration> {
  const old = await legacy.get(AGE_FLAG_KEY);
  if (old === null) return "nothing_to_migrate";
  const current = await secure.get(AGE_FLAG_KEY);
  if (current === null || (current === "eligible" && old === "ineligible")) {
    await secure.set(AGE_FLAG_KEY, old);
    if ((await secure.get(AGE_FLAG_KEY)) !== old) throw new Error("age flag migration: the secure store did not keep the value");
    await legacy.delete(AGE_FLAG_KEY);
    return "migrated";
  }
  await legacy.delete(AGE_FLAG_KEY); // the secure store already holds the answer; the SQLite copy is stale
  return "already_secure";
}

/** Answers `ineligible` to `age_gate` and refuses to write: sign-in is blocked while the secure store is unusable. */
export function failClosedAgeFlags(): DeviceFlagStore {
  const refuse = (): Promise<void> => Promise.reject(new Error("age flag store unavailable (secure store failed); sign-in stays blocked"));
  return {
    get: (key) => Promise.resolve(key === AGE_FLAG_KEY ? "ineligible" : null),
    set: refuse,
    delete: refuse,
  };
}
