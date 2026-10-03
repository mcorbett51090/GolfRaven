/**
 * P4.2b-3b: provisioning, storing and showing the offline code. What is proved here:
 *  - the seed BYTES and `seedVersion` go to the secure store and nowhere else, keyed per (user, device); a seed is never logged and never in an error or an outcome;
 *  - another user never sees it (and a record under the wrong key is refused); sign-out keeps it dormant; account deletion wipes the deleted user's, and only theirs;
 *  - 404 = "not ready" (no loop), 429 and 503 `offline_seed_unavailable` are handled, a rotation replaces the seed, a lost rotation answer is resynchronised;
 *  - the HTTP call: URL, strict body (compared with the request the real handler accepted), the strict answer schema (the pinned step / digits / algorithm), no retry;
 *  - the clock-offset estimate is display only.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError, createHttpApiClient, type OfflineSeedRequest, type OfflineSeedResult } from "../src/api";
import { deleteAccountAndWipeLocal } from "../src/account";
import {
  AUTO_PROVISION_COOLDOWN_MS,
  CLOCK_SKEW_WARN_MS,
  OfflineCodeManager,
  OfflineSeedStore,
  base32Decode,
  clockSkewOf,
  codeAt,
  formatCountdown,
  offlineSeedKey,
  provisionMessage,
  provisionOfflineSeedOnLaunch,
  skewMinutes,
  type ProvisionOutcome,
} from "../src/offline-code";
import { OFFLINE_CODE_UI_ENABLED } from "../src/features";
import { BrokenSecureStore, MemorySecureStore } from "../src/secure";
import { en } from "../src/i18n/messages/en";
import { frCA } from "../src/i18n/messages/fr-CA";
import { apiError, jwt } from "./support/fakes";
import { RECORDED, VECTORS, recorded, recordedRequest, scriptedFetch } from "./support/edge-fixtures";

const USER_A = "11111111-aaaa-4aaa-8aaa-111111111111";
const USER_B = "22222222-bbbb-4bbb-8bbb-222222222222";
const DEVICE = "11111111-1111-4111-8111-111111111111";
const tokenOf = (sub: string): string => jwt({ sub, role: "authenticated" });
/** What the real handler answered for the first provisioning: a real answer's shape, with the server test suite's test seed. */
const ANSWER = JSON.parse(RECORDED.offlineseed_200!.body).data as OfflineSeedResult;
const ROTATED = JSON.parse(RECORDED.offlineseed_200_rotate!.body).data as OfflineSeedResult;
const T0 = Date.parse("2026-06-01T12:00:00.000Z");

class Session {
  current: string | null = USER_A;
  /** The token the session would hand out for a user (default: that user's own). */
  tokenOverride: Record<string, string | null> = {};
  tokenFetches: string[] = [];
  throwOnToken = false;
  currentUserId(): string | null {
    return this.current;
  }
  accessTokenFor(userId: string): Promise<string | null> {
    this.tokenFetches.push(userId);
    if (this.throwOnToken) return Promise.reject(new Error("refresh failed"));
    if (userId in this.tokenOverride) return Promise.resolve(this.tokenOverride[userId]!);
    return Promise.resolve(this.current === userId ? tokenOf(userId) : null);
  }
}

type Reply = OfflineSeedResult | ApiError | Error;
class FakeApi {
  calls: Array<{ req: OfflineSeedRequest; credentials: { userId: string; accessToken: string } }> = [];
  replies: Reply[] = [];
  fallback: Reply = ANSWER;
  provisionOfflineSeed(req: OfflineSeedRequest, credentials: { userId: string; accessToken: string }): Promise<OfflineSeedResult> {
    this.calls.push({ req, credentials });
    const r = this.replies.shift() ?? this.fallback;
    return r instanceof Error ? Promise.reject(r) : Promise.resolve(r);
  }
}

function make(over: { secure?: MemorySecureStore } = {}) {
  const secure = over.secure ?? new MemorySecureStore();
  const session = new Session();
  const api = new FakeApi();
  let now = T0;
  const store = new OfflineSeedStore(secure);
  const manager = new OfflineCodeManager({ store, api, session, deviceId: async () => DEVICE, now: () => now });
  return { secure, session, api, store, manager, advance: (ms: number) => void (now += ms), setNow: (t: number) => void (now = t), now: () => now };
}

describe("provisioning stores the seed BYTES and seedVersion in the secure store", () => {
  it("POSTs { deviceId } as the owner, with the owner's token, and stores 32 bytes under a per-(user, device) key", async () => {
    const m = make();
    const out = await m.manager.provision();
    expect(out).toMatchObject({ status: "ready", seedVersion: 1, rotated: false });
    expect(m.api.calls).toEqual([{ req: { deviceId: DEVICE }, credentials: { userId: USER_A, accessToken: tokenOf(USER_A) } }]);
    expect(m.secure.keys()).toEqual([`gr.offline_seed.${USER_A}.${DEVICE}`]);
    expect(m.secure.keys()).toEqual([offlineSeedKey(USER_A, DEVICE)]);
    const stored = await m.store.load(USER_A, DEVICE);
    expect(stored).toMatchObject({ seedVersion: 1, resyncNeeded: false, issuedAtMs: Date.parse(ANSWER.issuedAt), receivedAtMs: T0 });
    expect(stored!.seed).toEqual(base32Decode(ANSWER.seed));
    expect(stored!.seed.length).toBe(32);
  });

  it("the secure store holds the BYTES (hex), never the base32 text the server sent, and no other place is written: the manager never touches SQLite", async () => {
    const m = make();
    await m.manager.provision();
    expect(m.secure.dump()).not.toContain(ANSWER.seed);
    const hex = Buffer.from(base32Decode(ANSWER.seed)!).toString("hex");
    expect(m.secure.dump()).toContain(hex);
    // the module's imports: the secure-store INTERFACE only (no SQLite, no file system, no AsyncStorage, no database module)
    const dir = fileURLToPath(new URL("../src/offline-code/", import.meta.url));
    const files = readdirSync(dir).filter((f) => f.endsWith(".ts"));
    expect(files.length).toBeGreaterThanOrEqual(8);
    for (const f of files) {
      const code = readFileSync(join(dir, f), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      expect(code, f).not.toMatch(/sqlite|from\s*["'][^"']*\/db|AsyncStorage|expo-file-system|localStorage|\bfs\b|console\./i);
    }
    expect(readFileSync(join(dir, "store.ts"), "utf8")).toMatch(/import type \{ SecureStore \} from "\.\.\/secure"/);
  });

  it("the keychain class: every secure-store write goes through `KEYCHAIN_ACCESSIBLE` = AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY, and the composition root gives the offline store THAT secure store", () => {
    const real = readFileSync(fileURLToPath(new URL("../src/secure/expo-secure-store.ts", import.meta.url)), "utf8");
    expect(real).toMatch(/KEYCHAIN_ACCESSIBLE = ExpoSecureStore\.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY/);
    expect(real).toMatch(/setItemAsync\(key, value, OPTIONS\)/);
    expect(real).toMatch(/const OPTIONS: ExpoSecureStore\.SecureStoreOptions = \{ keychainAccessible: KEYCHAIN_ACCESSIBLE \}/);
    const services = readFileSync(fileURLToPath(new URL("../src/runtime/services.ts", import.meta.url)), "utf8");
    expect(services).toMatch(/const secure = createExpoSecureStore\(\)/);
    expect(services).toMatch(/new OfflineSeedStore\(secure\)/);
  });

  it("the seed and its base32 text are never in an outcome, an error message or a log: a failing store, a bad answer and a mismatch say nothing of it", async () => {
    const outcomes: unknown[] = [];
    const m = make();
    outcomes.push(await m.manager.provision());
    m.api.replies.push({ ...ANSWER, seed: "not a seed" });
    outcomes.push(await m.manager.provision({ rotate: true }));
    const broken = make({ secure: new MemorySecureStore() });
    const failing = new OfflineCodeManager({ store: new OfflineSeedStore(new BrokenSecureStore()), api: broken.api, session: broken.session, deviceId: async () => DEVICE, now: () => T0 });
    outcomes.push(await failing.provision());
    const text = JSON.stringify(outcomes);
    expect(text).not.toContain(ANSWER.seed);
    expect(text).not.toContain(Buffer.from(base32Decode(ANSWER.seed)!).toString("hex"));
  });
});

describe("the code, computed with no network", () => {
  it("view() gives the six digits for the device clock, equal to the code the server's module computed for that seed at that time", async () => {
    const m = make();
    await m.manager.provision();
    const v = VECTORS.offlineCode;
    for (const t of v.times) {
      m.setNow(t.unixSeconds * 1000 + 500);
      const view = await m.manager.view();
      expect(view).toMatchObject({ status: "ready", code: t.code, seedVersion: 1 });
    }
    m.setNow(v.leadingZero.unixSeconds * 1000);
    expect(await m.manager.view()).toMatchObject({ code: v.leadingZero.code });
  });

  it("no network is used: view() makes no API call, and works with the access token unavailable", async () => {
    const m = make();
    await m.manager.provision();
    m.api.calls.length = 0;
    m.session.throwOnToken = true;
    expect((await m.manager.view()).status).toBe("ready");
    expect(m.api.calls).toEqual([]);
  });

  it("the countdown follows the step; the code changes at the boundary", async () => {
    const m = make();
    await m.manager.provision();
    const boundary = 1_790_000_400_000;
    m.setNow(boundary - 1000);
    const a = await m.manager.view();
    m.setNow(boundary);
    const b = await m.manager.view();
    expect(a).toMatchObject({ status: "ready", secondsRemaining: 1 });
    expect(b).toMatchObject({ status: "ready", secondsRemaining: 600 });
    expect((a as { code: string }).code).not.toBe((b as { code: string }).code);
    expect(formatCountdown(600)).toBe("10:00");
    expect(formatCountdown(59)).toBe("0:59");
    expect(formatCountdown(1)).toBe("0:01");
    expect(formatCountdown(-3)).toBe("0:00");
  });

  it("a stored seed of the wrong length, or a record that is not exactly what save() writes, is 'no seed' (re-provisioning restores the same seed), never a wrong code", async () => {
    const m = make();
    await m.secure.set(offlineSeedKey(USER_A, DEVICE), "not json");
    expect(await m.manager.view()).toEqual({ status: "no_seed" });
    await m.secure.set(offlineSeedKey(USER_A, DEVICE), JSON.stringify({ v: 1, userId: USER_A, deviceId: DEVICE, seedHex: "00".repeat(31), seedVersion: 1, issuedAtMs: 1, receivedAtMs: 1, resyncNeeded: false }));
    expect(await m.manager.view()).toEqual({ status: "no_seed" });
    await m.secure.set(offlineSeedKey(USER_A, DEVICE), JSON.stringify({ v: 2, userId: USER_A, deviceId: DEVICE, seedHex: "00".repeat(32), seedVersion: 1, issuedAtMs: 1, receivedAtMs: 1, resyncNeeded: false }));
    expect(await m.manager.view()).toEqual({ status: "no_seed" });
  });

  it("an unreadable secure store is 'unavailable', not 'no seed'", async () => {
    const m = make();
    const broken = new OfflineCodeManager({ store: new OfflineSeedStore(new BrokenSecureStore()), api: m.api, session: m.session, deviceId: async () => DEVICE, now: () => T0 });
    expect(await broken.view()).toEqual({ status: "unavailable" });
    expect(await broken.provisionIfMissing()).toEqual({ status: "failed", reason: "storage" });
  });
});

describe("per-user isolation, sign-out, deletion", () => {
  it("another user on the same device never sees the seed (view, load), and provisioning for B stores under B's key and leaves A's alone", async () => {
    const m = make();
    await m.manager.provision();
    const a = await m.store.load(USER_A, DEVICE);
    m.session.current = USER_B;
    expect(await m.manager.view()).toEqual({ status: "no_seed" });
    expect(await m.manager.loadSeed()).toBeNull();
    expect(await m.store.load(USER_B, DEVICE)).toBeNull();
    m.api.fallback = ROTATED; // B's seed is a different one (the server derives it per account)
    expect(await m.manager.provision()).toMatchObject({ status: "ready" });
    expect(m.secure.keys().sort()).toEqual([offlineSeedKey(USER_A, DEVICE), offlineSeedKey(USER_B, DEVICE)].sort());
    expect((await m.store.load(USER_A, DEVICE))!.seed).toEqual(a!.seed);
    expect((await m.store.load(USER_B, DEVICE))!.seed).toEqual(base32Decode(ROTATED.seed));
    expect(m.api.calls[1]!.credentials.userId).toBe(USER_B);
  });

  it("the user is IN the key, and the record names its user and device: a record that sits under another user's key is refused", async () => {
    const m = make();
    await m.manager.provision();
    const rec = (await m.secure.get(offlineSeedKey(USER_A, DEVICE)))!;
    await m.secure.set(offlineSeedKey(USER_B, DEVICE), rec); // A's record copied under B's key
    expect(await m.store.load(USER_B, DEVICE)).toBeNull();
    expect(offlineSeedKey(USER_A, DEVICE)).not.toBe(offlineSeedKey(USER_B, DEVICE));
    expect(offlineSeedKey(USER_A, DEVICE)).toContain(USER_A);
    expect(offlineSeedKey(USER_A, DEVICE.toUpperCase())).toBe(offlineSeedKey(USER_A, DEVICE)); // the device id is compared in lower case
    expect(() => offlineSeedKey("a b", DEVICE)).toThrow(/safe key part/);
    expect(() => offlineSeedKey(USER_A, "../x")).toThrow(/safe key part/);
  });

  it("a token that is not the owner's (the session handed out another account's) is never used: nothing is requested and nothing stored", async () => {
    const m = make();
    m.session.tokenOverride[USER_A] = tokenOf(USER_B);
    expect(await m.manager.provision()).toEqual({ status: "failed", reason: "account_mismatch" });
    expect(m.api.calls).toEqual([]);
    expect(m.secure.keys()).toEqual([]);
    m.session.tokenOverride[USER_A] = "not-a-jwt";
    expect(await m.manager.provision()).toEqual({ status: "failed", reason: "account_mismatch" });
  });

  it("SIGN-OUT keeps the seed, dormant: nothing is requested or wiped, nobody else sees it, and it is the same player's code again at the next sign-in, offline", async () => {
    const m = make();
    await m.manager.provision();
    const before = m.secure.dump();
    m.session.current = null; // signed out
    expect(await m.manager.view()).toEqual({ status: "signed_out" });
    expect(await m.manager.loadSeed()).toBeNull();
    expect(await m.manager.provision()).toEqual({ status: "signed_out" });
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "signed_out" });
    expect(m.secure.dump()).toBe(before);
    m.session.current = USER_A;
    m.api.calls.length = 0;
    const view = await m.manager.view();
    expect(view.status).toBe("ready");
    expect(m.api.calls).toEqual([]); // no network needed to get the code back
    // the sign-out path of the app itself touches no secure key of this module
    const provider = readFileSync(fileURLToPath(new URL("../src/runtime/AppProvider.tsx", import.meta.url)), "utf8");
    const signOut = provider.slice(provider.indexOf("signOut: async"), provider.indexOf("deleteAccount: async"));
    expect(signOut.replace(/\/\/.*$/gm, "")).not.toMatch(/offlineCode|offline|seed|wipe|delete/i);
    expect(signOut).toMatch(/services\.auth\.signOut\(\)/); // the slice is the real body, not an empty match
  });

  it("ACCOUNT DELETION wipes the deleted user's seed on this device (step `offline-seed`), and only theirs; the device id stays", async () => {
    const m = make();
    await m.manager.provision();
    m.session.current = USER_B;
    m.api.fallback = ROTATED;
    await m.manager.provision();
    await m.secure.set("gr.device_id", DEVICE);
    const outcome = await deleteAccountAndWipeLocal({
      api: { deleteAccount: async () => ({ userId: USER_A, deletedAt: "x", authUserDeleted: true }) as never },
      auth: { clearLocalSession: async () => undefined },
      outbox: { deleteByOwners: async () => undefined } as never,
      challenges: { deleteOwner: async () => undefined } as never,
      offlineSeed: { wipeUser: (u) => m.manager.wipeUser(u) },
      sharer: { purgeStale: async () => undefined },
      currentUserId: () => USER_A,
      secure: m.secure,
      clearUserCaches: () => undefined,
    });
    expect(outcome).toMatchObject({ status: "deleted", localWipe: "complete" });
    expect(await m.store.load(USER_A, DEVICE)).toBeNull();
    expect(await m.store.load(USER_B, DEVICE)).not.toBeNull();
    expect(await m.secure.get("gr.device_id")).toBe(DEVICE);
    expect(m.secure.dump()).not.toContain(Buffer.from(base32Decode(ANSWER.seed)!).toString("hex"));
  });

  it("a failing seed wipe is reported as a partial wipe (named step), not swallowed", async () => {
    const outcome = await deleteAccountAndWipeLocal({
      api: { deleteAccount: async () => ({ userId: USER_A, deletedAt: "x", authUserDeleted: true }) as never },
      auth: { clearLocalSession: async () => undefined },
      outbox: { deleteByOwners: async () => undefined } as never,
      challenges: { deleteOwner: async () => undefined } as never,
      offlineSeed: { wipeUser: () => Promise.reject(new Error("keychain locked")) },
      sharer: { purgeStale: async () => undefined },
      currentUserId: () => USER_A,
      secure: new MemorySecureStore(),
      clearUserCaches: () => undefined,
    });
    expect(outcome).toMatchObject({ status: "deleted", localWipe: "partial", failedSteps: ["offline-seed"] });
  });

  it("the app's deleteAccount wires the wipe", () => {
    const provider = readFileSync(fileURLToPath(new URL("../src/runtime/AppProvider.tsx", import.meta.url)), "utf8");
    expect(provider).toMatch(/offlineSeed: \{ wipeUser: \(userId\) => services\.offlineCode\.wipeUser\(userId\) \}/);
  });
});

describe("what the server can answer", () => {
  it("404: NOT READY (the device is not registered yet), not an error; nothing is stored", async () => {
    const m = make();
    m.api.replies.push(apiError("not_found", 404, "not_found"));
    expect(await m.manager.provision()).toEqual({ status: "not_ready" });
    expect(m.secure.keys()).toEqual([]);
    expect(provisionMessage({ status: "not_ready" })).toBe("offline.status.notReady");
  });

  it("the automatic path does not loop on a 404: one attempt, then nothing until the cooldown, then one more; a manual attempt is never held back", async () => {
    const m = make();
    m.api.fallback = apiError("not_found", 404, "not_found");
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "not_ready" });
    expect(m.api.calls.length).toBe(1);
    for (let i = 0; i < 5; i += 1) expect(await m.manager.provisionIfMissing()).toEqual({ status: "skipped", reason: "cooldown" });
    expect(m.api.calls.length).toBe(1);
    m.advance(AUTO_PROVISION_COOLDOWN_MS - 1);
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "skipped", reason: "cooldown" });
    m.advance(1);
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "not_ready" });
    expect(m.api.calls.length).toBe(2);
    expect(await m.manager.provision()).toEqual({ status: "not_ready" }); // manual: always tried
    expect(m.api.calls.length).toBe(3);
    m.api.fallback = ANSWER; // the device got registered
    expect(await m.manager.provision()).toMatchObject({ status: "ready" });
  });

  it("429: rate limited, with the server's Retry-After; the automatic path honours a longer one", async () => {
    const m = make();
    m.api.replies.push(apiError("rate_limited", 429, "rate_limited", undefined, 3600));
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "rate_limited", retryAfterSeconds: 3600 });
    m.advance(AUTO_PROVISION_COOLDOWN_MS + 1000);
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "skipped", reason: "cooldown" }); // 1 h asked, 5 min passed
    m.advance(3600 * 1000);
    expect(await m.manager.provisionIfMissing()).toMatchObject({ status: "ready" });
    expect(provisionMessage({ status: "rate_limited", retryAfterSeconds: null })).toBe("offline.status.rateLimited");
  });

  it("503 offline_seed_unavailable (the server's key is not provisioned yet) and 502 / 504 / 500: unavailable, retry later", async () => {
    for (const [kind, status, code] of [["unavailable", 503, "offline_seed_unavailable"], ["unavailable", 502, null], ["unavailable", 504, null], ["server", 500, "internal_error"]] as const) {
      const m = make();
      m.api.replies.push(apiError(kind, status, code));
      expect(await m.manager.provision(), `${status}`).toEqual({ status: "unavailable" });
      expect(m.secure.keys()).toEqual([]);
    }
    const m = make();
    m.api.fallback = apiError("unavailable", 503, "offline_seed_unavailable");
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "unavailable" });
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "skipped", reason: "cooldown" });
    expect(provisionMessage({ status: "unavailable" })).toBe("offline.status.unavailable");
  });

  it("network failure: offline; 401: sign in again; not configured / bad answer / a refused request each have their own outcome", async () => {
    const cases: Array<[ApiError | Error, ProvisionOutcome]> = [
      [apiError("network", 0, null), { status: "offline" }],
      [new Error("boom"), { status: "offline" }],
      [apiError("unauthenticated", 401, "unauthorized"), { status: "sign_in_required" }],
      [apiError("not_configured", 0, null), { status: "failed", reason: "not_configured" }],
      [apiError("bad_response", 200, null), { status: "failed", reason: "bad_response" }],
      [apiError("rejected", 400, "bad_request"), { status: "failed", reason: "rejected" }],
      [apiError("forbidden", 403, "forbidden"), { status: "failed", reason: "rejected" }],
    ];
    for (const [err, expected] of cases) {
      const m = make();
      m.api.replies.push(err);
      expect(await m.manager.provision(), String(err)).toEqual(expected);
      expect(m.secure.keys()).toEqual([]);
    }
  });

  it("a token that cannot be fetched is offline; no token for the signed-in user is 'sign in again'", async () => {
    const m = make();
    m.session.throwOnToken = true;
    expect(await m.manager.provision()).toEqual({ status: "offline" });
    m.session.throwOnToken = false;
    m.session.tokenOverride[USER_A] = null;
    expect(await m.manager.provision()).toEqual({ status: "sign_in_required" });
    expect(m.api.calls).toEqual([]);
  });

  it("every outcome has a line in both languages (the mapping is exhaustive)", () => {
    const outcomes: ProvisionOutcome[] = [
      { status: "ready", seedVersion: 1, rotated: false, clock: { offsetMs: 0, warn: false } },
      { status: "signed_out" },
      { status: "sign_in_required" },
      { status: "not_ready" },
      { status: "rate_limited", retryAfterSeconds: 5 },
      { status: "unavailable" },
      { status: "offline" },
      ...(["not_configured", "rejected", "bad_response", "storage", "no_device", "account_mismatch"] as const).map((reason): ProvisionOutcome => ({ status: "failed", reason })),
    ];
    for (const o of outcomes) {
      for (const rotated of [false, true]) {
        const key = provisionMessage(o, rotated);
        expect(en[key], key).toBeTruthy();
        expect(frCA[key], key).toBeTruthy();
      }
    }
  });
});

describe("rotation (an explicit 'reset code')", () => {
  it("POSTs { deviceId, rotate: true }; the NEW seed and version replace the old, and the old code is no longer shown", async () => {
    const m = make();
    await m.manager.provision();
    const old = (await m.store.load(USER_A, DEVICE))!;
    m.api.replies.push(ROTATED);
    const out = await m.manager.provision({ rotate: true });
    expect(out).toMatchObject({ status: "ready", seedVersion: 2, rotated: true });
    expect(m.api.calls[1]!.req).toEqual({ deviceId: DEVICE, rotate: true });
    const now = (await m.store.load(USER_A, DEVICE))!;
    expect(now.seedVersion).toBe(2);
    expect(now.seed).toEqual(base32Decode(ROTATED.seed));
    expect(now.seed).not.toEqual(old.seed);
    expect(now.resyncNeeded).toBe(false);
    expect(codeAt(now.seed, T0)).not.toBe(codeAt(old.seed, T0));
    expect(m.secure.keys().length).toBe(1);
  });

  it("a plain provisioning never sends `rotate` (a re-provision returns the same seed), and sends no other key", async () => {
    const m = make();
    await m.manager.provision();
    await m.manager.provision();
    for (const c of m.api.calls) expect(Object.keys(c.req).sort()).toEqual(["deviceId"]);
  });

  it("a refusal of the rotation (429, 4xx) leaves the earlier seed current; an UNKNOWN outcome (the answer was lost) marks it for resynchronisation, and the next automatic provisioning fetches the server's current seed", async () => {
    const m = make();
    await m.manager.provision();
    const first = (await m.store.load(USER_A, DEVICE))!;
    m.api.replies.push(apiError("rate_limited", 429, "rate_limited", undefined, 100));
    expect(await m.manager.provision({ rotate: true })).toEqual({ status: "rate_limited", retryAfterSeconds: 100 });
    expect((await m.store.load(USER_A, DEVICE))!).toMatchObject({ seedVersion: 1, resyncNeeded: false, seed: first.seed });

    m.api.replies.push(apiError("network", 0, null));
    expect(await m.manager.provision({ rotate: true })).toEqual({ status: "offline" });
    expect((await m.store.load(USER_A, DEVICE))!).toMatchObject({ seedVersion: 1, resyncNeeded: true });
    expect(await m.manager.view()).toMatchObject({ status: "ready", resyncNeeded: true });

    m.api.replies.push(ROTATED); // the server did rotate: provisioning (no rotate) returns the current seed
    expect(await m.manager.provisionIfMissing()).toMatchObject({ status: "ready", seedVersion: 2, rotated: false });
    expect((await m.store.load(USER_A, DEVICE))!).toMatchObject({ seedVersion: 2, resyncNeeded: false });
    expect(await m.manager.provisionIfMissing()).toEqual({ status: "skipped", reason: "have_seed" });
  });

  it("single-flight: two taps while a request is in flight make ONE request", async () => {
    const m = make();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    m.api.provisionOfflineSeed = async (req, credentials) => {
      m.api.calls.push({ req, credentials });
      await gate;
      return ANSWER;
    };
    const a = m.manager.provision();
    const b = m.manager.provision();
    release();
    expect(await a).toEqual(await b);
    expect(m.api.calls.length).toBe(1);
  });
});

describe("the clock offset is display only", () => {
  it("offset = server issuedAt - device clock at receipt; it warns from one step (600 s), below which the server's +-1 step window always accepts the code", () => {
    expect(CLOCK_SKEW_WARN_MS).toBe(600_000);
    expect(clockSkewOf(T0 + 5_000, T0)).toEqual({ offsetMs: 5_000, warn: false });
    expect(clockSkewOf(T0 + 599_999, T0).warn).toBe(false);
    expect(clockSkewOf(T0 + 600_000, T0).warn).toBe(true);
    expect(clockSkewOf(T0 - 600_000, T0)).toEqual({ offsetMs: -600_000, warn: true });
    expect(clockSkewOf(T0 - 599_999, T0).warn).toBe(false);
    expect(skewMinutes(-14 * 60_000 - 20_000)).toBe(14);
  });

  it("it never changes a digit: the code is computed from the device clock whatever the offset", async () => {
    const skewed = make();
    skewed.api.fallback = { ...ANSWER, issuedAt: new Date(T0 + 30 * 60_000).toISOString() }; // the device clock runs 30 minutes behind the server
    expect(await skewed.manager.provision()).toMatchObject({ status: "ready", clock: { offsetMs: 30 * 60_000, warn: true } });
    const plain = make();
    await plain.manager.provision();
    const a = await skewed.manager.view();
    const b = await plain.manager.view();
    expect(a).toMatchObject({ status: "ready", clock: { warn: true } });
    expect((a as { code: string }).code).toBe((b as { code: string }).code);
  });

  it("the server's tolerance is documented where it is decided: +-1 step, 'always accepted below one step'", () => {
    const src = readFileSync(fileURLToPath(new URL("../src/offline-code/params.ts", import.meta.url)), "utf8");
    expect(src).toMatch(/\+-1 step/);
    expect(src).toMatch(/LESS than one step/);
  });
});

describe("the HTTP call (`api.provisionOfflineSeed`) against the real handler's recorded answers", () => {
  const BASE = "https://x.test/functions/v1";
  const client = (fetch: ReturnType<typeof scriptedFetch>["fetch"]) => createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: async () => "session-token", sleep: async () => undefined });
  const creds = { userId: USER_A, accessToken: tokenOf(USER_A) };

  it("POST <base>/me-offline-seed with the strict body the real parser accepted, as the OWNER's token, and the answer parses", async () => {
    const f = scriptedFetch({ respond: "offlineseed_200" });
    const out = await client(f.fetch).provisionOfflineSeed({ deviceId: recordedRequest<{ deviceId: string }>("offlineseed_200").deviceId }, creds);
    expect(out).toEqual(ANSWER);
    expect(f.seen).toHaveLength(1);
    expect(f.seen[0]).toMatchObject({ url: `${BASE}/me-offline-seed`, method: "POST", body: recordedRequest("offlineseed_200"), redirect: "error", credentials: "omit" });
    expect(f.seen[0]!.headers.Authorization).toBe(`Bearer ${creds.accessToken}`);
  });

  it("a rotation sends exactly the recorded rotate body", async () => {
    const f = scriptedFetch({ respond: "offlineseed_200_rotate" });
    const out = await client(f.fetch).provisionOfflineSeed({ deviceId: DEVICE, rotate: true }, creds);
    expect(f.seen[0]!.body).toEqual(recordedRequest("offlineseed_200_rotate"));
    expect(out).toEqual(ROTATED);
    expect(out.seedVersion).toBe(2);
    expect(out.seed).not.toBe(ANSWER.seed);
  });

  it("every recorded refusal is mapped, and NONE is retried (every call is a seed reveal; the request goes out once)", async () => {
    const cases: Array<[string, string, number, string | null]> = [
      ["offlineseed_404_foreign_device", "not_found", 404, "not_found"],
      ["offlineseed_404_unknown_device", "not_found", 404, "not_found"],
      ["offlineseed_400_unknown_key", "rejected", 400, "bad_request"],
      ["offlineseed_429_reveal_limit", "rate_limited", 429, "rate_limited"],
      ["offlineseed_429_rotate_limit", "rate_limited", 429, "rate_limited"],
      ["offlineseed_503_not_provisioned", "unavailable", 503, "offline_seed_unavailable"],
    ];
    for (const [name, kind, status, code] of cases) {
      const f = scriptedFetch({ respond: name });
      const err = await client(f.fetch).provisionOfflineSeed({ deviceId: DEVICE }, creds).then(
        () => null,
        (e: unknown) => e as ApiError,
      );
      expect(err, name).toMatchObject({ kind, status, code });
      expect(f.seen, name).toHaveLength(1);
    }
  });

  it("an answer that echoes another step, digit count or algorithm, or a seed that is not 52 base32 characters, is bad_response: a client never shows a code the server would not accept", async () => {
    for (const patch of [{ stepSeconds: 300 }, { digits: 8 }, { algorithm: "SHA1" }, { seed: ANSWER.seed.slice(1) }, { seed: ANSWER.seed.toLowerCase() }, { seedVersion: 0 }, { issuedAt: "yesterday" }, { seed: undefined }]) {
      const body = JSON.stringify({ data: { ...ANSWER, ...patch } });
      const f = scriptedFetch({ status: 200, body });
      const err = await client(f.fetch).provisionOfflineSeed({ deviceId: DEVICE }, creds).then(
        () => null,
        (e: unknown) => e as ApiError,
      );
      expect(err, JSON.stringify(patch)).toMatchObject({ kind: "bad_response" });
    }
    const m = make();
    const api = client(scriptedFetch({ status: 200, body: JSON.stringify({ data: { ...ANSWER, stepSeconds: 300 } }) }).fetch);
    const mgr = new OfflineCodeManager({ store: m.store, api, session: m.session, deviceId: async () => DEVICE, now: () => T0 });
    expect(await mgr.provision()).toEqual({ status: "failed", reason: "bad_response" });
    expect(m.secure.keys()).toEqual([]);
  });

  it("end to end: manager over the real client over the recorded answer shows the code the server's module computed", async () => {
    const m = make();
    const api = client(scriptedFetch({ respond: "offlineseed_200" }).fetch);
    const mgr = new OfflineCodeManager({ store: m.store, api, session: m.session, deviceId: async () => DEVICE, now: () => T0 });
    expect(await mgr.provision()).toMatchObject({ status: "ready", seedVersion: 1 });
    m.setNow(0);
    const t = VECTORS.offlineCode.times.find((x) => x.unixSeconds === 1_790_000_000)!;
    const mgr2 = new OfflineCodeManager({ store: m.store, api, session: m.session, deviceId: async () => DEVICE, now: () => t.unixSeconds * 1000 });
    expect(await mgr2.view()).toMatchObject({ status: "ready", code: t.code });
    expect(recorded("offlineseed_200").status).toBe(200);
  });
});

describe("automatic provisioning is gated by OFFLINE_CODE_UI_ENABLED", () => {
  it("with the switch off nothing is requested, read or written; with it on the manager's automatic path runs", async () => {
    const m = make();
    let calls = 0;
    const spy = { provisionIfMissing: async () => void (calls += 1) };
    await provisionOfflineSeedOnLaunch(spy, false);
    expect(calls).toBe(0);
    await provisionOfflineSeedOnLaunch(spy, true);
    expect(calls).toBe(1);
    expect(OFFLINE_CODE_UI_ENABLED).toBe(false);
    await provisionOfflineSeedOnLaunch(m.manager); // the default is the switch
    expect(m.api.calls).toEqual([]);
    expect(m.session.tokenFetches).toEqual([]);
    expect(m.secure.keys()).toEqual([]);
  });
});
