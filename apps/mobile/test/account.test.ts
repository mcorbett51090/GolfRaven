/** Deletion (Apple 5.1.1(v), AT 6/19) and export (me-export + the share sheet). */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AGE_FLAG_KEY, AgeGate, SecureDeviceFlagStore } from "../src/age";
import { KEPT_SECURE_KEYS, WIPED_SECURE_KEYS, deleteAccountAndWipeLocal, exportAndShare, exportFileName, createCacheFileSharer, isExportFileName, purgeStaleExports, serializeExport, type DeleteDeps, type ExportCache, type FileSharer } from "../src/account";
import { ApiError, createHttpApiClient, type ApiClient, type DeleteAccountResult } from "../src/api";
import { createItem, MemoryOutboxStore, SqliteOutboxStore, type OutboxStore } from "../src/outbox";
import { MemorySecureStore, SECURE_KEYS, SESSION_STORAGE_KEY } from "../src/secure";
import { checkEligible } from "../src/signin";
import { FakeAuth, NOW } from "./support/fakes";
import { openNodeSqlite } from "./support/node-sqlite";
import { scriptedFetch, type Step } from "./support/edge-fixtures";

const RESULT: DeleteAccountResult = { userId: "u1", deletedAt: "2026-10-03T00:00:00.000Z", authUserDeleted: true, authUserAlreadyGone: false, signinProvidersRevoked: [] };

async function stores(): Promise<[string, () => Promise<OutboxStore>][]> {
  return [
    ["memory outbox", async () => new MemoryOutboxStore()],
    ["sqlite outbox", async () => new SqliteOutboxStore(await openNodeSqlite())],
  ];
}

async function fill(store: OutboxStore): Promise<void> {
  for (let i = 0; i < 3; i += 1) await store.insertIfAbsent(createItem({ id: `id${i}`, sourceRef: `ref${i}`, ownerUserId: i === 2 ? "user-b" : "user-a", courseId: "crs_1", catalogVersion: "1", payload: { i } }, 1000 + i));
}

describe("DELETE /v1/me then the local wipe", () => {
  for (const [name, make] of [
    ["memory outbox", async () => new MemoryOutboxStore() as OutboxStore],
    ["sqlite outbox", async () => new SqliteOutboxStore(await openNodeSqlite()) as OutboxStore],
  ] as const) {
    it(`${name}: wipes the session, the outbox and the caches, and KEEPS the device-local age flag`, async () => {
      const outbox = await make();
      await fill(outbox);
      expect(await outbox.list()).toHaveLength(3);
      const auth = new FakeAuth();
      auth.session = { userId: "u1", provider: "email", stub: false };
      // the age flag is in the secure store, next to the session-less device id
      const secure = new MemorySecureStore();
      const ageGate = new AgeGate(new SecureDeviceFlagStore(secure), NOW);
      await ageGate.submitBirthYear(1990, 16);
      await secure.set(SECURE_KEYS.deviceId, "device-id-1");
      await secure.set(SESSION_STORAGE_KEY, '{"refresh_token":"r"}');
      let cachesCleared = 0;
      const order: string[] = [];
      const deps: DeleteDeps = {
        api: { deleteAccount: () => (order.push("server"), Promise.resolve(RESULT)) },
        auth: { clearLocalSession: () => (order.push("session"), auth.clearLocalSession()) },
        outbox: { deleteAll: () => (order.push("outbox"), outbox.deleteAll()) },
        secure,
        clearUserCaches: () => {
          order.push("caches");
          cachesCleared += 1;
        },
      };

      const r = await deleteAccountAndWipeLocal(deps);

      expect(r).toEqual({ status: "deleted", result: RESULT, localWipe: "complete", failedSteps: [] });
      expect(order[0]).toBe("server"); // the server first: nothing local is touched unless it says done
      expect(auth.session).toBeNull();
      expect(auth.clearedLocal).toBe(1);
      expect(auth.signedOut).toBe(0); // no network sign-out call against a session that no longer exists
      expect(await secure.get(SESSION_STORAGE_KEY)).toBeNull(); // the session key itself is gone from the secure store
      expect(await outbox.list()).toEqual([]);
      expect(cachesCleared).toBe(1);
      // KEPT: the O18 flag (an under-age player cannot delete the account and retry with another year), and the device id
      expect(await secure.get(SECURE_KEYS.ageGate)).toBe("eligible");
      expect(await new AgeGate(new SecureDeviceFlagStore(secure), NOW).state()).toBe("eligible");
      expect(await secure.get(SECURE_KEYS.deviceId)).toBe("device-id-1");
    });
  }

  it("an under-age flag survives deletion: the player is still blocked afterwards (AT 20)", async () => {
    const secure = new MemorySecureStore();
    const gate = new AgeGate(new SecureDeviceFlagStore(secure), NOW);
    await gate.submitBirthYear(2015, 16);
    await deleteAccountAndWipeLocal({
      api: { deleteAccount: () => Promise.resolve(RESULT) },
      auth: { clearLocalSession: () => Promise.resolve() },
      outbox: { deleteAll: () => Promise.resolve() },
      secure,
      clearUserCaches: () => undefined,
    });
    expect(await secure.get(SECURE_KEYS.ageGate)).toBe("ineligible");
    expect(await checkEligible(gate)).toEqual({ ok: false, status: "blocked" });
    expect(await gate.submitBirthYear(1980, 16)).toEqual({ status: "blocked" });
  });

  it("the wipe never touches the age flag key: the only things it can reach are the session, the outbox and the caches", async () => {
    const secure = new MemorySecureStore();
    await secure.set(SECURE_KEYS.ageGate, "ineligible");
    const touched: string[] = [];
    await deleteAccountAndWipeLocal({
      api: { deleteAccount: () => Promise.resolve(RESULT) },
      auth: { clearLocalSession: () => (touched.push("session"), Promise.resolve()) },
      outbox: { deleteAll: () => (touched.push("outbox"), Promise.resolve()) },
      secure,
      clearUserCaches: () => void touched.push("caches"),
    });
    expect(touched.sort()).toEqual(["caches", "outbox", "session"]);
    expect(WIPED_SECURE_KEYS.some((k) => KEPT_SECURE_KEYS.includes(k))).toBe(false);
    expect(KEPT_SECURE_KEYS).toEqual(expect.arrayContaining([SECURE_KEYS.ageGate, SECURE_KEYS.deviceId]));
    expect(await secure.get(SECURE_KEYS.ageGate)).toBe("ineligible");
  });

  it("if the SERVER deletion fails, nothing local is touched and the player can simply try again (it is idempotent)", async () => {
    const outbox = new MemoryOutboxStore();
    await fill(outbox);
    const auth = new FakeAuth();
    auth.session = { userId: "u1", provider: "email", stub: false };
    for (const error of [new ApiError({ kind: "network" }), new ApiError({ kind: "server", status: 500, code: "internal_error" }), new ApiError({ kind: "rate_limited", status: 429 })]) {
      const r = await deleteAccountAndWipeLocal({
        api: { deleteAccount: () => Promise.reject(error) },
        auth,
        outbox,
        secure: new MemorySecureStore(),
        clearUserCaches: () => {
          throw new Error("must not run");
        },
      });
      expect(r).toEqual({ status: "failed", error });
    }
    expect(auth.session).not.toBeNull();
    expect(auth.clearedLocal).toBe(0);
    expect(await outbox.list()).toHaveLength(3);
  });

  it("a failing local step is reported as a partial wipe and does not stop the others", async () => {
    let outboxWiped = false;
    const r = await deleteAccountAndWipeLocal({
      api: { deleteAccount: () => Promise.resolve(RESULT) },
      auth: { clearLocalSession: () => Promise.reject(new Error("keychain locked")) },
      outbox: { deleteAll: () => ((outboxWiped = true), Promise.resolve()) },
      secure: new MemorySecureStore(),
      clearUserCaches: () => undefined,
    });
    expect(r).toMatchObject({ status: "deleted", localWipe: "partial", failedSteps: ["session"] });
    expect(outboxWiped).toBe(true);
  });

  it("the provider-revocation outcome (revoked / queued for the server's 72 h retry) is passed through, not hidden", async () => {
    const withRevocations: DeleteAccountResult = { ...RESULT, signinProvidersRevoked: [{ queueId: "q1", provider: "apple", status: "queued_for_retry", error: "vendor_timeout" }] };
    const r = await deleteAccountAndWipeLocal({
      api: { deleteAccount: () => Promise.resolve(withRevocations) },
      auth: { clearLocalSession: () => Promise.resolve() },
      outbox: { deleteAll: () => Promise.resolve() },
      secure: new MemorySecureStore(),
      clearUserCaches: () => undefined,
    });
    expect(r.status === "deleted" && r.result.signinProvidersRevoked[0]?.status).toBe("queued_for_retry");
  });

  it("OutboxStore.deleteAll empties both implementations and later inserts still work", async () => {
    for (const [, make] of await stores()) {
      const s = await make();
      await fill(s);
      await s.deleteAll();
      expect(await s.list()).toEqual([]);
      await fill(s);
      expect(await s.list()).toHaveLength(3);
    }
  });

  it("source check: the wipe removes secure keys only by looping over WIPED_SECURE_KEYS, and that list is exactly the session key", () => {
    const src = readFileSync(new URL("../src/account/delete.ts", import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    expect(src.match(/WIPED_SECURE_KEYS[^=]*=\s*\[([^\]]*)\]/)?.[1]?.trim()).toBe("SESSION_STORAGE_KEY");
    expect(src.match(/secure\.delete\(/g)).toHaveLength(1);
    expect(src).toMatch(/for \(const key of WIPED_SECURE_KEYS\) await deps\.secure\.delete\(key\)/);
    expect(src).not.toMatch(new RegExp(`${AGE_FLAG_KEY}|AGE_FLAG|flags\\.`));
  });
});

describe("a deletion the server may have executed (lost response, then the retry's 401) still wipes this device", () => {
  const BASE = "https://proj.supabase.co/functions/v1";

  /** The REAL http client over a scripted fetch; `refresh` says what the forced token refresh after a 401 returns. */
  function realClient(steps: Step[], refresh: "refused" | "ok" | "offline" = "refused") {
    const { fetch, seen } = scriptedFetch(...steps);
    const api = createHttpApiClient({
      baseUrl: BASE,
      fetch,
      getAccessToken: (o) => (o?.forceRefresh ? (refresh === "refused" ? Promise.resolve(null) : refresh === "offline" ? Promise.reject(new Error("offline")) : Promise.resolve("fresh")) : Promise.resolve("token-1")),
      rng: () => 0.5,
      sleep: () => Promise.resolve(),
    });
    return { api, seen };
  }

  async function runDelete(api: ApiClient) {
    const outbox = new MemoryOutboxStore();
    await fill(outbox); // two users' rows
    const secure = new MemorySecureStore();
    await secure.set(SESSION_STORAGE_KEY, "session");
    await secure.set(SECURE_KEYS.ageGate, "eligible");
    const auth = new FakeAuth();
    auth.session = { userId: "user-a", provider: "email", stub: false };
    let cachesCleared = 0;
    const outcome = await deleteAccountAndWipeLocal({ api, auth, outbox, secure, clearUserCaches: () => void (cachesCleared += 1) });
    return { outcome, outbox, secure, auth, cachesCleared };
  }

  it("DELETE succeeds server-side, the response is lost, the retry gets 401 (user gone) and the refresh is refused => deleted_or_session_ended, FULL wipe, every owner's outbox rows", async () => {
    const { api, seen } = realClient([{ network: "connection reset" }, { respond: "err_401_unauthorized" }]);
    const r = await runDelete(api);
    expect(seen.map((x) => x.method)).toEqual(["DELETE", "DELETE"]); // attempt 1 (lost), attempt 2 (401); the refresh then yields no token
    expect(r.outcome).toEqual({ status: "deleted_or_session_ended", cause: "unauthenticated", localWipe: "complete", failedSteps: [] });
    expect(await r.outbox.list()).toEqual([]); // user-a's AND user-b's rows
    expect(r.auth.session).toBeNull();
    expect(r.auth.clearedLocal).toBe(1);
    expect(await r.secure.get(SESSION_STORAGE_KEY)).toBeNull();
    expect(r.cachesCleared).toBe(1);
    expect(await r.secure.get(SECURE_KEYS.ageGate)).toBe("eligible"); // the age flag is still kept
  });

  it("the same, when the lost response was a 5xx rather than a dropped connection", async () => {
    const { api } = realClient([{ respond: "err_503_service_unavailable" }, { respond: "err_401_unauthorized" }]);
    expect((await runDelete(api)).outcome).toMatchObject({ status: "deleted_or_session_ended", cause: "unauthenticated" });
  });

  it("OFFLINE on every attempt (requests sent, no answer ever): failed, nothing wiped, the session and outbox are kept so the player can retry", async () => {
    const { api, seen } = realClient([{ network: "offline" }]);
    const r = await runDelete(api);
    expect(seen.length).toBeGreaterThan(1); // it retried, and every attempt was a transport failure
    expect(r.outcome).toMatchObject({ status: "failed", error: { kind: "network", mayHaveBeenApplied: true } });
    expect(await r.outbox.list()).toHaveLength(3);
    expect(r.auth.session).not.toBeNull();
    expect(r.auth.clearedLocal).toBe(0);
    expect(r.cachesCleared).toBe(0);
    expect(await r.secure.get(SESSION_STORAGE_KEY)).toBe("session");
  });

  it("a request was sent, then a 5xx on every attempt (server down): failed, nothing wiped, session kept", async () => {
    for (const respond of ["err_500_internal", "err_503_service_unavailable"]) {
      const r = await runDelete(realClient([{ respond }]).api);
      expect(r.outcome).toMatchObject({ status: "failed", error: { mayHaveBeenApplied: true } });
      expect(await r.outbox.list()).toHaveLength(3);
      expect(r.auth.session).not.toBeNull();
      expect(r.auth.clearedLocal).toBe(0);
      expect(r.cachesCleared).toBe(0);
      expect(await r.secure.get(SESSION_STORAGE_KEY)).toBe("session");
    }
  });

  it("a 5xx first and then a transport failure (still no 401) stays failed too", async () => {
    const r = await runDelete(realClient([{ respond: "err_503_service_unavailable" }, { network: "offline" }]).api);
    expect(r.outcome.status).toBe("failed");
    expect(await r.outbox.list()).toHaveLength(3);
  });

  it("a CLEAN first-attempt 401 (refresh refused, nothing earlier may have run) stays failed: nothing is wiped", async () => {
    const { api, seen } = realClient([{ respond: "err_401_unauthorized" }]);
    const r = await runDelete(api);
    expect(seen).toHaveLength(1);
    expect(r.outcome).toMatchObject({ status: "failed", error: { kind: "unauthenticated" } });
    expect(await r.outbox.list()).toHaveLength(3);
    expect(r.auth.clearedLocal).toBe(0);
    expect(r.cachesCleared).toBe(0);
    expect(await r.secure.get(SESSION_STORAGE_KEY)).toBe("session");
  });

  it("clean 4xx answers and a token refresh that failed before anything was sent stay failed, no wipe", async () => {
    for (const steps of [[{ respond: "err_403_forbidden" }], [{ respond: "err_404_not_found" }], [{ respond: "err_429_rate_limited" }]] as Step[][]) {
      const r = await runDelete(realClient(steps).api);
      expect(r.outcome.status).toBe("failed");
      expect(await r.outbox.list()).toHaveLength(3);
    }
    const noToken = createHttpApiClient({ baseUrl: BASE, fetch: scriptedFetch({ respond: "delete_ok" }).fetch, getAccessToken: () => Promise.reject(new Error("refresh failed: offline")), sleep: () => Promise.resolve(), rng: () => 0.5 });
    const r = await runDelete(noToken);
    expect(r.outcome).toMatchObject({ status: "failed", error: { kind: "network", mayHaveBeenApplied: false } });
    expect(await r.outbox.list()).toHaveLength(3);
  });

  it("a normal success is unchanged", async () => {
    const r = await runDelete(realClient([{ respond: "delete_ok" }]).api);
    expect(r.outcome.status).toBe("deleted");
    expect(await r.outbox.list()).toEqual([]);
  });

  it("the error flag: set only on an error raised after a request that may have run; plain network/401 errors carry false", () => {
    expect(new ApiError({ kind: "network" }).mayHaveBeenApplied).toBe(false);
    expect(new ApiError({ kind: "unauthenticated", status: 401 }).withMayHaveBeenApplied()).toMatchObject({ kind: "unauthenticated", status: 401, mayHaveBeenApplied: true });
  });

  it("copy exists for the new outcome in both languages, and the screen routes to it", () => {
    for (const lang of ["en", "fr-CA"]) {
      const src = readFileSync(new URL(`../src/i18n/messages/${lang}.ts`, import.meta.url), "utf8");
      expect(src).toMatch(/"me\.delete\.maybeDone":/);
      expect(src).toMatch(/"me\.delete\.maybePartial":/);
      expect(src).toMatch(/"me\.delete\.unreachable":/);
    }
    const me = readFileSync(new URL("../app/(tabs)/me.tsx", import.meta.url), "utf8");
    expect(me).toMatch(/deleted_or_session_ended/);
    expect(me).toMatch(/me\.delete\.unreachable/);
    const provider = readFileSync(new URL("../src/runtime/AppProvider.tsx", import.meta.url), "utf8");
    expect(provider).toMatch(/outcome\.status === "deleted_or_session_ended"/);
  });
});

describe("export: me-export, then the share sheet", () => {
  const EXPORT = { generatedAt: "2026-10-03T00:00:00.000Z", userId: "u1", data: { device: [{ id: "d" }], play: [] } };

  function sharer(behaviour: "ok" | "unavailable" | "throws" = "ok") {
    const shared: { filename: string; content: string }[] = [];
    const s: FileSharer = {
      shareJson(filename, content) {
        shared.push({ filename, content });
        if (behaviour === "throws") return Promise.reject(new Error("share sheet failed"));
        return Promise.resolve(behaviour === "ok" ? "shared" : "unavailable");
      },
      purgeStale: () => Promise.resolve(),
    };
    return { s, shared };
  }

  it("fetches the export and hands the exact JSON to the share sheet as a dated .json file", async () => {
    const { s, shared } = sharer();
    const r = await exportAndShare({ api: { exportData: () => Promise.resolve(EXPORT) }, sharer: s, now: () => new Date("2026-10-03T15:00:00Z") });
    expect(r).toEqual({ status: "shared", bytes: serializeExport(EXPORT).length });
    expect(shared).toHaveLength(1);
    expect(shared[0]!.filename).toBe("golfraven-export-2026-10-03.json");
    expect(JSON.parse(shared[0]!.content)).toEqual(EXPORT);
  });

  it("the file name carries a date and nothing personal", () => {
    expect(exportFileName(new Date("2026-01-02T03:04:05Z"))).toBe("golfraven-export-2026-01-02.json");
  });

  it("a failed fetch never reaches the share sheet; the error is kept for the screen (rate limit vs offline)", async () => {
    const { s, shared } = sharer();
    const err = new ApiError({ kind: "rate_limited", status: 429, code: "rate_limited", retryAfterSeconds: 7200 });
    const r = await exportAndShare({ api: { exportData: () => Promise.reject(err) }, sharer: s });
    expect(r).toEqual({ status: "failed", stage: "fetch", error: err });
    expect(shared).toEqual([]);
  });

  it("no share sheet on the device, and a share sheet that throws, are reported (not thrown); the content is not put in the error", async () => {
    const a = sharer("unavailable");
    expect(await exportAndShare({ api: { exportData: () => Promise.resolve(EXPORT) }, sharer: a.s })).toEqual({ status: "unavailable" });
    const b = sharer("throws");
    const r = await exportAndShare({ api: { exportData: () => Promise.resolve(EXPORT) }, sharer: b.s });
    expect(r).toMatchObject({ status: "failed", stage: "share" });
    expect(JSON.stringify(r)).not.toContain('"play"');
  });

  it("the real sharer writes to the CACHE directory and shares (source check; never run on a device), and no longer deletes the file when the sheet returns", () => {
    const src = readFileSync(new URL("../src/account/expo-share.ts", import.meta.url), "utf8");
    expect(src).toMatch(/new File\(Paths\.cache,/);
    expect(src).toMatch(/Sharing\.shareAsync\(/);
    expect(src).not.toMatch(/finally/);
    expect(src).not.toMatch(/Paths\.document/);
    expect(src).not.toMatch(/console\./);
    const shared = readFileSync(new URL("../src/account/export.ts", import.meta.url), "utf8");
    expect(shared).not.toMatch(/finally/);
  });
});

/** An in-memory stand-in for the app cache directory (`ExportCache`), with the other files a cache holds. */
function fakeCache(initial: Record<string, string> = {}) {
  const files = new Map(Object.entries(initial));
  const log: string[] = [];
  const cache: ExportCache & { failRemoveOf: string | null } = {
    failRemoveOf: null,
    listNames: () => [...files.keys()],
    remove(name) {
      if (name === cache.failRemoveOf) throw new Error("cannot delete");
      log.push(`remove ${name}`);
      files.delete(name);
    },
    write(name, content) {
      log.push(`write ${name}`);
      files.set(name, content);
      return `file:///cache/${name}`;
    },
  };
  return { files, log, cache };
}

describe("the export file outlives the share sheet and is deleted at the next export / app start (Android receivers may read it later)", () => {
  const STALE = { "golfraven-export-2026-09-01.json": "old", "golfraven-export-2026-10-03.json": "same day" };
  const OTHER = { "other-app-file.json": "keep", "golfraven-export-notes.txt": "keep", "golfraven-export-2026-10-03.json.bak": "keep" };
  const system = (events: string[], available = true) => ({
    isAvailable: () => Promise.resolve(available),
    share: (uri: string) => (events.push(`share ${uri}`), Promise.resolve()),
  });

  it("the file is still in the cache after the share sheet returns", async () => {
    const { files, cache } = fakeCache();
    const events: string[] = [];
    const sharer = createCacheFileSharer(cache, system(events));
    expect(await sharer.shareJson("golfraven-export-2026-10-03.json", "{}")).toBe("shared");
    expect(events).toEqual(["share file:///cache/golfraven-export-2026-10-03.json"]);
    expect(files.get("golfraven-export-2026-10-03.json")).toBe("{}");
  });

  it("the next export deletes every earlier export file BEFORE writing the new one, and never touches other files", async () => {
    const { files, log, cache } = fakeCache({ ...STALE, ...OTHER });
    await createCacheFileSharer(cache, system([])).shareJson("golfraven-export-2026-10-04.json", "new");
    expect(log).toEqual(["remove golfraven-export-2026-09-01.json", "remove golfraven-export-2026-10-03.json", "write golfraven-export-2026-10-04.json"]);
    expect([...files.keys()].sort()).toEqual(["golfraven-export-2026-10-04.json", ...Object.keys(OTHER)].sort());
  });

  it("app start (purgeStale) deletes stale exports, only exports, and one that cannot be deleted does not stop the rest or throw", async () => {
    const { files, cache } = fakeCache({ ...STALE, ...OTHER });
    cache.failRemoveOf = "golfraven-export-2026-09-01.json";
    await expect(createCacheFileSharer(cache, system([])).purgeStale()).resolves.toBeUndefined();
    expect([...files.keys()].sort()).toEqual(["golfraven-export-2026-09-01.json", ...Object.keys(OTHER)].sort());
    expect(purgeStaleExports({ ...cache, listNames: () => { throw new Error("no cache dir"); } })).toBe(0);
  });

  it("no share sheet on the device: nothing is written and nothing is purged", async () => {
    const { log, cache } = fakeCache(STALE);
    expect(await createCacheFileSharer(cache, system([], false)).shareJson("golfraven-export-2026-10-04.json", "x")).toBe("unavailable");
    expect(log).toEqual([]);
  });

  it("isExportFileName matches exactly the names exportFileName makes", () => {
    expect(isExportFileName(exportFileName(new Date("2026-01-02T03:04:05Z")))).toBe(true);
    for (const n of ["golfraven-export-2026-1-2.json", "../golfraven-export-2026-01-02.json", "golfraven-export-2026-01-02.json.bak", "x.json"]) expect(isExportFileName(n)).toBe(false);
  });

  it("the app calls purgeStale once at start (composition root)", () => {
    const src = readFileSync(new URL("../src/runtime/services.ts", import.meta.url), "utf8").replace(/\/\/.*$/gm, "");
    expect(src).toMatch(/sharer\.purgeStale\(\)/);
  });
});

describe("the API client type is what the flows use (compile-time)", () => {
  it("DeleteDeps/api picks exist on ApiClient", () => {
    const keys: (keyof ApiClient)[] = ["deleteAccount", "exportData", "registerPushToken", "listSignInMethods", "linkSignInMethod", "unlinkSignInMethod"];
    expect(keys).toHaveLength(6);
  });
});
