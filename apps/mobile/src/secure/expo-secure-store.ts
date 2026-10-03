/**
 * `SecureStore` over `expo-secure-store` 57.0.4. Imported only by the composition root (`runtime/services.ts`); tests use
 * `MemorySecureStore`. Type-checked against the package's real `.d.ts`; **never run on a device** `[unverified]`.
 *
 * Every item is written with `keychainAccessible: AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` (`[checked in the installed .d.ts]`: the option is
 * `keychainAccessible`, the constant is `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`). On iOS that Keychain class is excluded from iCloud/iTunes
 * backups and from device migration, so neither the session nor the O18 under-age flag can ride a backup to another device; the plain
 * `AFTER_FIRST_UNLOCK` and `WHEN_UNLOCKED` classes would be migrated. "After first unlock" (not "when unlocked") so a read at launch never
 * fails because the screen happens to be locked, which for the age flag would look like "no flag" and re-open the gate.
 * Android stores the value in the Keystore-encrypted preferences; `android.allowBackup` is `false` in app.json.
 * `[iOS Keychain backup semantics: platform behaviour from the option's documented meaning; not observed on a device]`
 */
import * as ExpoSecureStore from "expo-secure-store";
import { assertSecureKey, type SecureStore } from "./store";

export const KEYCHAIN_ACCESSIBLE = ExpoSecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY;

const OPTIONS: ExpoSecureStore.SecureStoreOptions = { keychainAccessible: KEYCHAIN_ACCESSIBLE };

export function createExpoSecureStore(): SecureStore {
  return {
    async get(key) {
      assertSecureKey(key);
      return ExpoSecureStore.getItemAsync(key, OPTIONS);
    },
    async set(key, value) {
      assertSecureKey(key);
      await ExpoSecureStore.setItemAsync(key, value, OPTIONS);
    },
    async delete(key) {
      assertSecureKey(key);
      await ExpoSecureStore.deleteItemAsync(key, OPTIONS);
    },
  };
}
