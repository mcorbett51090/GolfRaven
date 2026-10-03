/**
 * The per-install device id: a random UUID (v4) kept in the SECURE STORE (`gr.device_id`), made on first use. `me-push-token` takes it as
 * `deviceId` (the server validates a UUID); the attestation client (P4.2b) will reuse it.
 *
 * Why the secure store and not SQLite: SQLite's file is in the iOS backup set, so a restore would copy one device's id onto another and make
 * two devices look like one; a `ThisDeviceOnly` Keychain item does not migrate, so a restored phone gets its own id. It is a random value
 * with no meaning outside this app, not an advertising or hardware identifier (and not the "device recall" signal, which is the server's N4 work).
 */
import { SECURE_KEYS, type SecureStore } from "../secure";
import { randomUuid, type RandomBytes } from "../signin/nonce";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function createDeviceIdProvider(secure: SecureStore, random: RandomBytes): () => Promise<string> {
  let pending: Promise<string> | null = null;
  return () => {
    pending ??= (async () => {
      const stored = await secure.get(SECURE_KEYS.deviceId);
      if (stored !== null && UUID_RE.test(stored)) return stored;
      const id = randomUuid(random);
      await secure.set(SECURE_KEYS.deviceId, id);
      return id;
    })().catch((e: unknown) => {
      pending = null; // a failed read/write must not poison every later call
      throw e;
    });
    return pending;
  };
}
