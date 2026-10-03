/**
 * The hardware-backed key/value store behind an interface (build plan §7.8, §3.6: "refresh token in Keychain/Keystore").
 *
 * What goes in it: the Supabase session (access + refresh token), the device-local under-age flag (O18) and the per-install
 * device id. What NEVER goes in SQLite, `AsyncStorage` or an `EXPO_PUBLIC_*` variable: anything that can act as the player.
 * The real implementation is `expo-secure-store` (`expo-secure-store.ts`); `MemorySecureStore` is the in-memory fake the
 * tests (and nothing else) use.
 *
 * Keys: `[A-Za-z0-9._-]+` (the character set `expo-secure-store` accepts), so the fake rejects a key the real one would.
 */
export interface SecureStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export const SECURE_KEY_RE = /^[A-Za-z0-9._-]+$/;

export function assertSecureKey(key: string): void {
  if (!SECURE_KEY_RE.test(key)) throw new Error(`secure store: invalid key ${JSON.stringify(key)} (use A-Z a-z 0-9 . _ -)`);
}

export class MemorySecureStore implements SecureStore {
  private readonly m = new Map<string, string>();
  get(key: string): Promise<string | null> {
    assertSecureKey(key);
    return Promise.resolve(this.m.get(key) ?? null);
  }
  set(key: string, value: string): Promise<void> {
    assertSecureKey(key);
    this.m.set(key, value);
    return Promise.resolve();
  }
  delete(key: string): Promise<void> {
    assertSecureKey(key);
    this.m.delete(key);
    return Promise.resolve();
  }
  /** Test helper: every key currently held. */
  keys(): string[] {
    return [...this.m.keys()];
  }
  /** Test helper: every value, for "is X anywhere in it" assertions. */
  dump(): string {
    return JSON.stringify([...this.m.entries()]);
  }
}

/** A store whose every operation fails: stands in for a Keychain/Keystore that cannot be used (tests; fail-closed paths). */
export class BrokenSecureStore implements SecureStore {
  constructor(private readonly message = "secure store unavailable") {}
  get(): Promise<string | null> {
    return Promise.reject(new Error(this.message));
  }
  set(): Promise<void> {
    return Promise.reject(new Error(this.message));
  }
  delete(): Promise<void> {
    return Promise.reject(new Error(this.message));
  }
}

/** The keys this app owns in the secure store. One place, so a wipe can name exactly what it removes. */
export const SECURE_KEYS = {
  /** The device-local O18 flag. Survives account deletion on purpose. */
  ageGate: "gr.flag.age_gate",
  /** A random per-install device id (a UUID). Not personal data; `me-push-token` and later the attestation client use it. */
  deviceId: "gr.device_id",
} as const;

/** The one key the Supabase session is stored under (auth-js's `storageKey`; its default would be derived from the project URL). */
export const SESSION_STORAGE_KEY = "gr.session";
