/** Deletion (Apple 5.1.1(v), AT 6/19) and export (me-export + the share sheet). */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AGE_FLAG_KEY, AgeGate, SecureDeviceFlagStore } from "../src/age";
import { KEPT_SECURE_KEYS, WIPED_SECURE_KEYS, deleteAccountAndWipeLocal, exportAndShare, exportFileName, serializeExport, type DeleteDeps, type FileSharer } from "../src/account";
import { ApiError, type ApiClient, type DeleteAccountResult } from "../src/api";
import { createItem, MemoryOutboxStore, SqliteOutboxStore, type OutboxStore } from "../src/outbox";
import { MemorySecureStore, SECURE_KEYS, SESSION_STORAGE_KEY } from "../src/secure";
import { checkEligible } from "../src/signin";
import { FakeAuth, NOW } from "./support/fakes";
import { openNodeSqlite } from "./support/node-sqlite";

const RESULT: DeleteAccountResult = { userId: "u1", deletedAt: "2026-10-03T00:00:00.000Z", authUserDeleted: true, authUserAlreadyGone: false, signinProvidersRevoked: [] };

async function stores(): Promise<[string, () => Promise<OutboxStore>][]> {
  return [
    ["memory outbox", async () => new MemoryOutboxStore()],
    ["sqlite outbox", async () => new SqliteOutboxStore(await openNodeSqlite())],
  ];
}

async function fill(store: OutboxStore): Promise<void> {
  for (let i = 0; i < 3; i += 1) await store.insertIfAbsent(createItem({ id: `id${i}`, sourceRef: `ref${i}`, courseId: "crs_1", catalogVersion: "1", payload: { i } }, 1000 + i));
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

  it("the real sharer writes to the CACHE directory, shares, and deletes the file in a finally (source check; never run on a device)", () => {
    const src = readFileSync(new URL("../src/account/expo-share.ts", import.meta.url), "utf8");
    expect(src).toMatch(/new File\(Paths\.cache,/);
    expect(src).toMatch(/Sharing\.shareAsync\(/);
    expect(src).toMatch(/finally\s*\{[\s\S]*file\.delete\(\)/);
    expect(src).not.toMatch(/Paths\.document/);
    expect(src).not.toMatch(/console\./);
  });
});

describe("the API client type is what the flows use (compile-time)", () => {
  it("DeleteDeps/api picks exist on ApiClient", () => {
    const keys: (keyof ApiClient)[] = ["deleteAccount", "exportData", "registerPushToken", "listSignInMethods", "linkSignInMethod", "unlinkSignInMethod"];
    expect(keys).toHaveLength(6);
  });
});
