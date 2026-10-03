/**
 * The secure store holds the session, the O18 under-age flag and the device id (LOW-D). The flag moved out of SQLite (which iOS backs up) into a
 * `…ThisDeviceOnly` Keychain item; an old SQLite flag is migrated once and deleted.
 */
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AGE_FLAG_KEY,
  AgeGate,
  MemoryDeviceFlagStore,
  SecureDeviceFlagStore,
  SqliteDeviceFlagStore,
  failClosedAgeFlags,
  migrateAgeFlag,
} from "../src/age";
import { BrokenSecureStore, MemorySecureStore, SECURE_KEYS, SECURE_KEY_RE, assertSecureKey, SESSION_STORAGE_KEY } from "../src/secure";
import { createDeviceIdProvider } from "../src/runtime/device-id";
import { checkEligible } from "../src/signin";
import { fixedRandom, NOW } from "./support/fakes";
import { openNodeSqlite } from "./support/node-sqlite";

describe("the age flag in the secure store", () => {
  it("AgeGate over the secure store: under-age is refused, retry refused, stored under the namespaced secure key and NOT in SQLite", async () => {
    const secure = new MemorySecureStore();
    const db = await openNodeSqlite();
    const gate = new AgeGate(new SecureDeviceFlagStore(secure), NOW);
    expect(await gate.submitBirthYear(2015, 16)).toEqual({ status: "ineligible" });
    expect(await gate.submitBirthYear(1980, 16)).toEqual({ status: "blocked" });
    expect(secure.keys()).toEqual([SECURE_KEYS.ageGate]);
    expect(await secure.get(SECURE_KEYS.ageGate)).toBe("ineligible");
    expect(await db.all("SELECT * FROM device_flags")).toEqual([]);
  });

  it("the flag survives a restart (a new store object over the same secure store) and never holds the birth year", async () => {
    const secure = new MemorySecureStore();
    await new AgeGate(new SecureDeviceFlagStore(secure), NOW).submitBirthYear(1985, 16);
    expect(secure.dump()).not.toContain("1985");
    const again = new AgeGate(new SecureDeviceFlagStore(secure), NOW);
    expect(await again.state()).toBe("eligible");
  });

  it("an UNREADABLE store is not 'no flag': the error surfaces, so the gate cannot be re-opened by a Keychain failure", async () => {
    const gate = new AgeGate(new SecureDeviceFlagStore(new BrokenSecureStore()), NOW);
    await expect(gate.state()).rejects.toThrow(/secure store unavailable/);
    await expect(gate.submitBirthYear(1990, 16)).rejects.toThrow();
    await expect(checkEligible(gate)).rejects.toThrow();
  });

  it("fail closed: when the store cannot be used the gate says ineligible, refuses writes, and sign-in is blocked (browse still works)", async () => {
    const gate = new AgeGate(failClosedAgeFlags(), NOW);
    expect(await gate.state()).toBe("ineligible");
    expect(await checkEligible(gate)).toEqual({ ok: false, status: "blocked" });
    expect(await gate.submitBirthYear(1990, 16)).toEqual({ status: "blocked" });
  });

  it("secure keys obey the character set expo-secure-store accepts", () => {
    for (const k of [...Object.values(SECURE_KEYS), SESSION_STORAGE_KEY]) expect(k).toMatch(SECURE_KEY_RE);
    expect(() => assertSecureKey("bad key!")).toThrow();
    expect(() => assertSecureKey("")).toThrow();
  });
});

describe("migrating an existing SQLite flag (once), then deleting it from SQLite", () => {
  it.each(["ineligible", "eligible"] as const)("moves %s across, deletes the SQLite row, and the gate reads it from the secure store", async (value) => {
    const db = await openNodeSqlite();
    const legacy = new SqliteDeviceFlagStore(db);
    await legacy.set(AGE_FLAG_KEY, value);
    await legacy.set("locale", "fr-CA"); // a preference stays where it is
    const secure = new SecureDeviceFlagStore(new MemorySecureStore());
    expect(await migrateAgeFlag(legacy, secure)).toBe("migrated");
    expect(await secure.get(AGE_FLAG_KEY)).toBe(value);
    expect(await legacy.get(AGE_FLAG_KEY)).toBeNull();
    expect(await db.all("SELECT key FROM device_flags")).toEqual([{ key: "locale" }]);
    expect(await new AgeGate(secure, NOW).state()).toBe(value);
  });

  it("runs once: a second run finds nothing, and an under-age player stays blocked across the migration", async () => {
    const legacy = new MemoryDeviceFlagStore();
    await legacy.set(AGE_FLAG_KEY, "ineligible");
    const secure = new SecureDeviceFlagStore(new MemorySecureStore());
    await migrateAgeFlag(legacy, secure);
    expect(await migrateAgeFlag(legacy, secure)).toBe("nothing_to_migrate");
    const gate = new AgeGate(secure, NOW);
    expect(await gate.submitBirthYear(1980, 16)).toEqual({ status: "blocked" });
  });

  it("nothing in SQLite: nothing to migrate and the secure store is untouched", async () => {
    const secure = new SecureDeviceFlagStore(new MemorySecureStore());
    expect(await migrateAgeFlag(new MemoryDeviceFlagStore(), secure)).toBe("nothing_to_migrate");
    expect(await secure.get(AGE_FLAG_KEY)).toBeNull();
  });

  it("'ineligible' always wins if the two stores disagree; a stale SQLite copy of the same answer is just deleted", async () => {
    const legacy = new MemoryDeviceFlagStore();
    const secure = new SecureDeviceFlagStore(new MemorySecureStore());
    await legacy.set(AGE_FLAG_KEY, "ineligible");
    await secure.set(AGE_FLAG_KEY, "eligible");
    expect(await migrateAgeFlag(legacy, secure)).toBe("migrated");
    expect(await secure.get(AGE_FLAG_KEY)).toBe("ineligible");

    await legacy.set(AGE_FLAG_KEY, "eligible");
    expect(await migrateAgeFlag(legacy, secure)).toBe("already_secure");
    expect(await secure.get(AGE_FLAG_KEY)).toBe("ineligible"); // eligible never overwrites ineligible
    expect(await legacy.get(AGE_FLAG_KEY)).toBeNull();
  });

  it("if the secure store cannot take the value, the SQLite copy is KEPT (never absent from both) and the error is raised", async () => {
    const legacy = new MemoryDeviceFlagStore();
    await legacy.set(AGE_FLAG_KEY, "ineligible");
    await expect(migrateAgeFlag(legacy, new SecureDeviceFlagStore(new BrokenSecureStore()))).rejects.toThrow();
    expect(await legacy.get(AGE_FLAG_KEY)).toBe("ineligible");
  });

  it("a secure store that accepts a write but does not keep it is detected before the SQLite copy is deleted", async () => {
    const legacy = new MemoryDeviceFlagStore();
    await legacy.set(AGE_FLAG_KEY, "ineligible");
    const forgetful = {
      get: () => Promise.resolve(null),
      set: () => Promise.resolve(),
      delete: () => Promise.resolve(),
    };
    await expect(migrateAgeFlag(legacy, new SecureDeviceFlagStore(forgetful))).rejects.toThrow(/did not keep/);
    expect(await legacy.get(AGE_FLAG_KEY)).toBe("ineligible");
  });
});

describe("the Keychain accessibility class is a ThisDeviceOnly value (excluded from iCloud backup and device migration on iOS)", () => {
  const requireHere = createRequire(import.meta.url);
  const pkgDir = dirname(requireHere.resolve("expo-secure-store/package.json"));
  const adapter = readFileSync(new URL("../src/secure/expo-secure-store.ts", import.meta.url), "utf8");

  it("the installed expo-secure-store declares the option `keychainAccessible` and the …_THIS_DEVICE_ONLY constants (read from its .d.ts)", () => {
    const dts = readFileSync(join(pkgDir, "build/SecureStore.d.ts"), "utf8");
    expect(dts).toMatch(/keychainAccessible\?: KeychainAccessibilityConstant/);
    expect(dts).toMatch(/export declare const AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY/);
    expect(dts).toMatch(/export declare const WHEN_UNLOCKED_THIS_DEVICE_ONLY/);
  });

  it("the iOS source maps those constants to kSecAttrAccessible…ThisDeviceOnly", () => {
    const swift = existsSync(join(pkgDir, "ios")) ? readFileSync(join(pkgDir, "ios/SecureStoreModule.swift"), "utf8") : "";
    expect(swift).toMatch(/kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly/);
    expect(swift).toMatch(/kSecAttrAccessibleWhenUnlockedThisDeviceOnly/);
  });

  it("the app's adapter uses a ThisDeviceOnly class for EVERY item, and passes it to all three operations", () => {
    expect(adapter).toMatch(/keychainAccessible:\s*KEYCHAIN_ACCESSIBLE/);
    expect(adapter).toMatch(/KEYCHAIN_ACCESSIBLE\s*=\s*ExpoSecureStore\.(AFTER_FIRST_UNLOCK|WHEN_UNLOCKED)_THIS_DEVICE_ONLY/);
    for (const op of ["getItemAsync", "setItemAsync", "deleteItemAsync"]) expect(adapter).toMatch(new RegExp(`${op}\\([^)]*OPTIONS\\)`));
    expect(adapter).not.toMatch(/ExpoSecureStore\.(AFTER_FIRST_UNLOCK|WHEN_UNLOCKED|ALWAYS)\b(?!_THIS)/);
  });
});

describe("the per-install device id", () => {
  it("is generated once (a v4 UUID), stored in the secure store, and stable across a restart", async () => {
    const secure = new MemorySecureStore();
    const first = await createDeviceIdProvider(secure, fixedRandom(3))();
    expect(first).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(await secure.get(SECURE_KEYS.deviceId)).toBe(first);
    const second = await createDeviceIdProvider(secure, fixedRandom(99))(); // a different RNG: the stored value wins
    expect(second).toBe(first);
  });

  it("concurrent first calls share one id; a corrupt stored value is replaced; a failing store is retried, not cached", async () => {
    const secure = new MemorySecureStore();
    const get = createDeviceIdProvider(secure, fixedRandom(5));
    const [a, b] = await Promise.all([get(), get()]);
    expect(a).toBe(b);

    const corrupt = new MemorySecureStore();
    await corrupt.set(SECURE_KEYS.deviceId, "not-a-uuid");
    const fixed = await createDeviceIdProvider(corrupt, fixedRandom(5))();
    expect(fixed).toMatch(/^[0-9a-f-]{36}$/);

    let broken = true;
    const flaky = { get: () => (broken ? Promise.reject(new Error("locked")) : Promise.resolve(null)), set: () => Promise.resolve(), delete: () => Promise.resolve() };
    const retry = createDeviceIdProvider(flaky, fixedRandom(5));
    await expect(retry()).rejects.toThrow("locked");
    broken = false;
    await expect(retry()).resolves.toMatch(/^[0-9a-f-]{36}$/);
  });
});
