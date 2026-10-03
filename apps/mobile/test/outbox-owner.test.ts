/**
 * P4.2b step 0: every outbox item is bound to the user whose session created it, and only that user's session may send or see it.
 *
 * The threat: account A signs out, account B signs in on the same device. Without an owner on the item, B's session would submit A's queued plays
 * (credited to B, A's data leaked to B). These tests run the REAL runner and BOTH stores (the memory reference and the real SQL over
 * `node:sqlite`) and fail if any one of the guards is removed (see the mutation proofs in the PR notes).
 */
import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it } from "vitest";
import { SCHEMA_VERSION, migrate } from "../src/db/sql";
import {
  MemoryOutboxStore,
  OutboxEnqueueError,
  OutboxRunner,
  SqliteOutboxStore,
  UNOWNED,
  createItem,
  enqueueOutboxItem,
  filterVisibleOutboxItems,
  isOwnedBy,
  visibleOutboxItems,
  type EvidenceCredentials,
  type EvidenceSubmitter,
  type InsertResult,
  type NewOutboxItem,
  type OutboxItem,
  type OutboxStore,
  type ServerAnswer,
} from "../src/outbox";
import { openNodeSqlite } from "./support/node-sqlite";

const T0 = 1_800_000_000_000;
const COURSE = "crs_01M39GMFJZ2P89V3ZZXPPH671T";
const A = "user-a";
const B = "user-b";

const mk = (n: number, owner: string, over: Partial<NewOutboxItem> = {}): NewOutboxItem => ({
  id: `o${n}`,
  sourceRef: `health:r${n}`,
  ownerUserId: owner,
  courseId: COURSE,
  catalogVersion: "20260101-aaaaaaa",
  payload: { n },
  ...over,
});

class RecordingApi implements EvidenceSubmitter {
  readonly sent: { ref: string; owner: string; credentials: EvidenceCredentials }[] = [];
  onSubmit: (() => void) | null = null;
  submitEvidence(item: OutboxItem, credentials: EvidenceCredentials): Promise<ServerAnswer> {
    this.sent.push({ ref: item.sourceRef, owner: item.ownerUserId, credentials });
    this.onSubmit?.();
    return Promise.resolve({ kind: "response", status: 201 });
  }
}

/** A store whose `update` runs a hook right after persisting the FIRST `sent` mark: the moment between "chosen to send" and the HTTP call. */
class HookedStore implements OutboxStore {
  afterSentMark: (() => void) | null = null;
  constructor(readonly inner: OutboxStore) {}
  insertIfAbsent(item: OutboxItem): Promise<InsertResult> {
    return this.inner.insertIfAbsent(item);
  }
  get(id: string) {
    return this.inner.get(id);
  }
  list() {
    return this.inner.list();
  }
  listByOwner(owner: string) {
    return this.inner.listByOwner(owner);
  }
  async update(item: OutboxItem): Promise<void> {
    await this.inner.update(item);
    if (item.status === "sent" && this.afterSentMark) {
      const hook = this.afterSentMark;
      this.afterSentMark = null;
      hook();
    }
  }
  delete(id: string) {
    return this.inner.delete(id);
  }
  deleteByOwners(owners: readonly string[]) {
    return this.inner.deleteByOwners(owners);
  }
  deleteAll() {
    return this.inner.deleteAll();
  }
}

const STORES: [string, () => Promise<OutboxStore>][] = [
  ["memory store", async () => new MemoryOutboxStore()],
  ["SQLite store", async () => new SqliteOutboxStore(await openNodeSqlite())],
];

describe.each(STORES)("outbox ownership (%s)", (_n, makeStore) => {
  let inner: OutboxStore;
  let store: HookedStore;
  let api: RecordingApi;
  let who: { user: string | null };
  let tokenRequests: string[];
  let beforeToken: (() => void) | null;
  let runner: OutboxRunner;
  let clock: { now: number };
  let refreshes: number;

  beforeEach(async () => {
    inner = await makeStore();
    store = new HookedStore(inner);
    api = new RecordingApi();
    who = { user: A };
    tokenRequests = [];
    beforeToken = null;
    clock = { now: T0 };
    refreshes = 0;
    runner = new OutboxRunner({
      store,
      api,
      session: {
        currentUserId: () => who.user,
        accessTokenFor: async (u) => {
          tokenRequests.push(u);
          const hook = beforeToken;
          beforeToken = null;
          hook?.();
          return `token-${u}`; // deliberately NOT null after a switch: a stale token must still be stopped by the runner's own check
        },
      },
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => {
        refreshes += 1;
      },
      rematch: async () => ({ ok: true, courseId: COURSE, catalogVersion: "v2", payload: { rematched: true } }),
      findCourseForUnlisted: async () => null,
    });
  });

  const add = async (n: number, owner: string, over: Partial<NewOutboxItem> = {}): Promise<void> => {
    clock.now += 1_000;
    await inner.insertIfAbsent(createItem(mk(n, owner, over), clock.now));
  };
  const byRef = async (n: number): Promise<OutboxItem> => (await inner.list()).find((i) => i.sourceRef === `health:r${n}`)!;

  it("A's items are never sent under B's session; B's own are, with B's token", async () => {
    await add(1, A); // A's are OLDER, so they would be reached first by a selection that ignored the owner
    await add(2, A);
    await add(3, B);
    who.user = B;
    const report = await runner.run();
    expect(report).toMatchObject({ aborted: null, sent: 1, accepted: 1 });
    expect(api.sent).toEqual([{ ref: "health:r3", owner: B, credentials: { userId: B, accessToken: `token-${B}` } }]);
    expect(tokenRequests).toEqual([B]); // a token was requested for the item's owner only
    // A's items are exactly as they were: untouched, still pending, no attempt recorded.
    for (const n of [1, 2]) expect(await byRef(n)).toMatchObject({ ownerUserId: A, status: "pending", attempts: 0 });
  });

  it("A's items are sent when A is signed in again (sign-out left them dormant, not deleted)", async () => {
    await add(1, A);
    who.user = null; // A signs out
    expect((await runner.run()).aborted).toBe("signed_out");
    who.user = B; // B signs in
    await runner.run();
    expect(api.sent).toEqual([]);
    expect(await inner.list()).toHaveLength(1); // still there
    who.user = A; // A comes back
    expect(await runner.run()).toMatchObject({ sent: 1, accepted: 1 });
    expect(api.sent[0]).toMatchObject({ owner: A, credentials: { userId: A, accessToken: `token-${A}` } });
  });

  it("with no session, nothing is sent, no token is requested, and nothing is changed", async () => {
    await add(1, A);
    await add(2, B);
    who.user = null;
    const report = await runner.run();
    expect(report.aborted).toBe("signed_out");
    expect(report.sent).toBe(0);
    expect(api.sent).toEqual([]);
    expect(tokenRequests).toEqual([]);
    for (const n of [1, 2]) expect(await byRef(n)).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("the unowned sentinel is never a session: a 'user' with id '' sends nothing", async () => {
    await add(1, A);
    who.user = UNOWNED;
    expect((await runner.run()).aborted).toBe("signed_out");
    expect(api.sent).toEqual([]);
  });

  it("a user switch AFTER selection, while the token is being fetched, aborts: nothing is sent and the item is untouched", async () => {
    await add(1, A);
    await add(2, A);
    beforeToken = () => {
      who.user = B; // B signs in just as A's first item is about to go out
    };
    const report = await runner.run();
    expect(report).toMatchObject({ aborted: "user_changed", sent: 0 });
    expect(api.sent).toEqual([]);
    for (const n of [1, 2]) expect(await byRef(n)).toMatchObject({ ownerUserId: A, status: "pending", attempts: 0 });
  });

  it("a user switch in the instant between marking the item 'sent' and the HTTP call aborts, and the 'sent' mark is undone (no phantom attempt)", async () => {
    await add(1, A);
    store.afterSentMark = () => {
      who.user = B;
    };
    const report = await runner.run();
    expect(report).toMatchObject({ aborted: "user_changed", sent: 0 });
    expect(api.sent).toEqual([]);
    expect(await byRef(1)).toMatchObject({ status: "pending", attempts: 0, ownerUserId: A });
  });

  it("a sign-out in that same instant aborts as signed_out", async () => {
    await add(1, A);
    store.afterSentMark = () => {
      who.user = null;
    };
    expect(await runner.run()).toMatchObject({ aborted: "signed_out", sent: 0 });
    expect(api.sent).toEqual([]);
    expect(await byRef(1)).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("the session user changing mid-run (after the first send) aborts the run: later items are not sent", async () => {
    await add(1, A);
    await add(2, A);
    await add(3, A);
    api.onSubmit = () => {
      who.user = B;
    };
    const report = await runner.run();
    expect(report).toMatchObject({ aborted: "user_changed", sent: 1, accepted: 1 });
    expect(api.sent.map((s) => s.ref)).toEqual(["health:r1"]); // r1 went out as A, with A's token
    expect(api.sent[0]!.credentials).toEqual({ userId: A, accessToken: `token-${A}` });
    for (const n of [2, 3]) expect(await byRef(n)).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("after the user changes mid-run the pass does no further work for the old user, not even a catalog refresh or a re-match", async () => {
    await add(1, A);
    await add(2, A, { courseId: COURSE });
    const second = await byRef(2);
    await inner.update({ ...second, rematch: true }); // r2 is waiting for a 422 catalog_stale re-match
    api.onSubmit = () => {
      who.user = B;
    };
    const report = await runner.run();
    expect(report).toMatchObject({ aborted: "user_changed", sent: 1, rematched: 0 });
    expect(refreshes).toBe(0);
    expect(await byRef(2)).toMatchObject({ status: "pending", rematch: true, attempts: 0 });
  });

  it("no token for the owner (null, or a refresh that threw) aborts the run and sends nothing", async () => {
    await add(1, A);
    const noToken = new OutboxRunner({
      store,
      api,
      session: { currentUserId: () => who.user, accessTokenFor: async () => null },
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => {},
      rematch: async () => ({ ok: false }),
      findCourseForUnlisted: async () => null,
    });
    expect(await noToken.run()).toMatchObject({ aborted: "no_token", sent: 0 });
    const throwing = new OutboxRunner({
      store,
      api,
      session: { currentUserId: () => who.user, accessTokenFor: () => Promise.reject(new Error("offline")) },
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => {},
      rematch: async () => ({ ok: false }),
      findCourseForUnlisted: async () => null,
    });
    expect(await throwing.run()).toMatchObject({ aborted: "no_token", sent: 0 });
    expect(api.sent).toEqual([]);
    expect(await byRef(1)).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("single-flight is per user: B's run does not join A's still-running pass, and sends only B's items", async () => {
    await add(1, A);
    await add(2, B);
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const slow = new OutboxRunner({
      store,
      api,
      session: {
        currentUserId: () => who.user,
        accessTokenFor: async (u) => {
          await gate;
          return `token-${u}`;
        },
      },
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => {},
      rematch: async () => ({ ok: false }),
      findCourseForUnlisted: async () => null,
    });
    const first = slow.run(); // A's pass, parked on the token
    who.user = B; // B signs in while it is parked
    const second = slow.run();
    expect(second).not.toBe(first);
    release();
    const [r1, r2] = await Promise.all([first, second]);
    expect(r1).toMatchObject({ aborted: "user_changed", sent: 0 });
    expect(r2).toMatchObject({ aborted: null, sent: 1 });
    expect(api.sent.map((s) => [s.ref, s.credentials.userId])).toEqual([["health:r2", B]]);
  });

  it("an interrupted ('sent') item of another user is not recovered under this user's session", async () => {
    await add(1, A);
    const item = await byRef(1);
    await inner.update({ ...item, status: "sent", attempts: 1, updatedAt: clock.now });
    clock.now += 10 * 60_000;
    who.user = B;
    expect(await runner.run()).toMatchObject({ recovered: 0 });
    expect((await byRef(1)).status).toBe("sent");
    who.user = A;
    expect(await runner.run()).toMatchObject({ recovered: 1, sent: 1 });
  });

  it("the same sourceRef under two users is two items; neither insert returns the other's", async () => {
    const a = await inner.insertIfAbsent(createItem(mk(1, A), T0));
    const b = await inner.insertIfAbsent(createItem({ ...mk(1, B), id: "o1-b", payload: { b: true } }, T0 + 1));
    expect(a.inserted).toBe(true);
    expect(b.inserted).toBe(true);
    expect(b.item.ownerUserId).toBe(B);
    const again = await inner.insertIfAbsent(createItem({ ...mk(1, A), id: "o1-a2" }, T0 + 2));
    expect(again).toMatchObject({ inserted: false, item: { id: "o1", ownerUserId: A } });
    expect(await inner.list()).toHaveLength(2);
  });

  it("listByOwner returns only that owner's items, oldest first, and nothing for the unowned sentinel", async () => {
    await add(1, A);
    await add(2, B);
    await add(3, A);
    expect((await inner.listByOwner(A)).map((i) => i.id)).toEqual(["o1", "o3"]);
    expect((await inner.listByOwner(B)).map((i) => i.id)).toEqual(["o2"]);
    expect(await inner.listByOwner("nobody")).toEqual([]);
    expect(await inner.listByOwner(UNOWNED)).toEqual([]);
  });

  it("an item's owner is immutable, like its id and sourceRef", async () => {
    await add(1, A);
    const item = await byRef(1);
    await expect(inner.update({ ...item, ownerUserId: B })).rejects.toThrow(/immutable/);
    expect((await byRef(1)).ownerUserId).toBe(A);
  });

  it("the store refuses an ownerless item (fail closed), including the empty string", async () => {
    const ok = createItem(mk(1, A), T0);
    await expect(inner.insertIfAbsent({ ...ok, ownerUserId: "" })).rejects.toThrow(/no owner/);
    await expect(inner.insertIfAbsent({ ...ok, ownerUserId: undefined as unknown as string })).rejects.toThrow(/no owner/);
    expect(await inner.list()).toEqual([]);
  });

  it("the UI list: the signed-in user's items only; signed out shows none; another user's rows are never in it", async () => {
    await add(1, A);
    await add(2, B);
    await add(3, A);
    expect((await visibleOutboxItems(inner, A)).map((i) => i.id)).toEqual(["o1", "o3"]);
    expect((await visibleOutboxItems(inner, B)).map((i) => i.id)).toEqual(["o2"]);
    expect(await visibleOutboxItems(inner, null)).toEqual([]);
    expect(await visibleOutboxItems(inner, UNOWNED)).toEqual([]);
  });

  describe("enqueue", () => {
    const deps = () => ({ store: inner, currentUserId: () => who.user, now: () => clock.now });
    const draft = { id: "d1", sourceRef: "dev:1", courseId: COURSE, catalogVersion: "v", payload: { dev: true } };

    it("signed out: throws a typed error and writes nothing (never an ownerless row)", async () => {
      who.user = null;
      await expect(enqueueOutboxItem(deps(), draft)).rejects.toBeInstanceOf(OutboxEnqueueError);
      await expect(enqueueOutboxItem(deps(), draft)).rejects.toMatchObject({ code: "signed_out" });
      expect(await inner.list()).toEqual([]);
    });

    it("the unowned sentinel session fails closed too", async () => {
      who.user = UNOWNED;
      await expect(enqueueOutboxItem(deps(), draft)).rejects.toMatchObject({ code: "signed_out" });
      expect(await inner.list()).toEqual([]);
    });

    it("signed in: the owner is the session's user, and a caller cannot choose another", async () => {
      const r = await enqueueOutboxItem(deps(), { ...draft, ownerUserId: B } as typeof draft);
      expect(r.inserted).toBe(true);
      expect(r.item.ownerUserId).toBe(A);
      expect((await inner.list()).map((i) => i.ownerUserId)).toEqual([A]);
    });
  });

  it("account deletion removes ONLY the deleted user's rows and the ownerless legacy rows: another user's dormant plays stay (LOW-1)", async () => {
    await add(1, A);
    await add(2, B);
    await add(3, A);
    await inner.deleteByOwners([A, UNOWNED]);
    expect((await inner.list()).map((i) => i.ownerUserId)).toEqual([B]);
    await add(4, A);
    expect(await inner.list()).toHaveLength(2);
    await inner.deleteByOwners([]);
    expect(await inner.list()).toHaveLength(2);
  });

  it("deleteAll (tests and tooling only) still empties every owner's rows, and the store works afterwards", async () => {
    await add(1, A);
    await add(2, B);
    await inner.deleteAll();
    expect(await inner.list()).toEqual([]);
    await add(3, B);
    expect(await inner.list()).toHaveLength(1);
  });
});

describe("pure ownership helpers", () => {
  const item = createItem(mk(1, A), T0);

  it("createItem refuses an item with no owner", () => {
    expect(() => createItem({ ...mk(1, A), ownerUserId: "" }, T0)).toThrow(/needs an owner/);
    expect(() => createItem({ ...mk(1, A), ownerUserId: undefined as unknown as string }, T0)).toThrow(/needs an owner/);
    expect(createItem(mk(1, A), T0).ownerUserId).toBe(A);
  });

  it("isOwnedBy: only an exact match of a real user id; signed out and the sentinel never match", () => {
    expect(isOwnedBy(item, A)).toBe(true);
    expect(isOwnedBy(item, B)).toBe(false);
    expect(isOwnedBy(item, null)).toBe(false);
    expect(isOwnedBy({ ...item, ownerUserId: UNOWNED }, UNOWNED)).toBe(false);
  });

  it("filterVisibleOutboxItems filters in-memory lists the same way (what the provider applies to its state)", () => {
    const items = [item, createItem(mk(2, B), T0), { ...createItem(mk(3, A), T0), ownerUserId: UNOWNED }];
    expect(filterVisibleOutboxItems(items, A).map((i) => i.id)).toEqual(["o1"]);
    expect(filterVisibleOutboxItems(items, B).map((i) => i.id)).toEqual(["o2"]);
    expect(filterVisibleOutboxItems(items, null)).toEqual([]);
    expect(filterVisibleOutboxItems(items, UNOWNED)).toEqual([]);
  });
});

describe("the v1 -> v2 upgrade (legacy ownerless rows)", () => {
  /** A v1 database holding rows the way P4.1/P4.2a wrote them (no owner anywhere). */
  async function legacyDb() {
    const db = await openNodeSqlite(1);
    const legacy = (n: number, status: string, extra: Record<string, unknown> = {}) => {
      const item = {
        id: `l${n}`,
        sourceRef: `dev:l${n}`,
        courseId: COURSE,
        catalogVersion: "v1",
        payload: { n },
        status,
        createdAt: T0 + n,
        updatedAt: T0 + n,
        attempts: 0,
        nextAttemptAt: null,
        rematch: false,
        lastHttpStatus: null,
        lastServerCode: null,
        reason: null,
        reported: false,
        deadLetteredAt: null,
        ...extra,
      };
      return db.run("INSERT INTO outbox (id, source_ref, status, next_attempt_at, created_at, item_json) VALUES (?, ?, ?, ?, ?, ?)", [
        item.id,
        item.sourceRef,
        status,
        null,
        item.createdAt,
        JSON.stringify(item),
      ]);
    };
    await legacy(1, "pending");
    await legacy(2, "retry", { attempts: 2, nextAttemptAt: T0 });
    await legacy(3, "sent", { attempts: 1 });
    await legacy(4, "pending", { rematch: true });
    await legacy(5, "accepted");
    return db;
  }

  it("the old schema has no owner column; the upgrade adds it NOT NULL (no default) and bumps the version", async () => {
    const db = await legacyDb();
    const cols = async () => await db.all<{ name: string; notnull: number; dflt_value: string | null }>("PRAGMA table_info(outbox)");
    expect((await cols()).map((c) => c.name)).not.toContain("owner_user_id");
    await migrate(db, { now: () => T0 + 99 });
    const owner = (await cols()).find((c) => c.name === "owner_user_id");
    expect(owner).toMatchObject({ notnull: 1, dflt_value: null });
    expect((await db.all<{ user_version: number }>("PRAGMA user_version"))[0]?.user_version).toBe(SCHEMA_VERSION);
    expect(SCHEMA_VERSION).toBe(4);
    // an ownerless INSERT is a hard SQL error, not a silent default
    await expect((async () => db.run("INSERT INTO outbox (id, source_ref, status, created_at, item_json) VALUES ('x', 'x', 'pending', 1, '{}')"))()).rejects.toThrow(/NOT NULL/i);
    await expect((async () => db.run("INSERT INTO outbox (id, source_ref, owner_user_id, status, created_at, item_json) VALUES ('y', 'y', NULL, 'pending', 1, '{}')"))()).rejects.toThrow(/NOT NULL/i);
  });

  it("the index (owner_user_id, status, next_attempt_at) exists and the old one is gone", async () => {
    const db = await legacyDb();
    await migrate(db);
    const idx = await db.all<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'outbox' AND name NOT LIKE 'sqlite_%'");
    expect(idx.map((i) => i.name)).toEqual(["outbox_owner_status_idx"]);
    const cols = await db.all<{ seqno: number; name: string }>("PRAGMA index_info(outbox_owner_status_idx)");
    expect(cols.sort((a, b) => a.seqno - b.seqno).map((c) => c.name)).toEqual(["owner_user_id", "status", "next_attempt_at"]);
  });

  it("every legacy row becomes needs_attention / owner_unknown with no owner, keeping its id, sourceRef, payload and createdAt (FM-03: none dropped)", async () => {
    const db = await legacyDb();
    await migrate(db, { now: () => T0 + 99 });
    const all = await new SqliteOutboxStore(db).list();
    expect(all.map((i) => i.id)).toEqual(["l1", "l2", "l3", "l4", "l5"]);
    for (const item of all) {
      expect(item).toMatchObject({ ownerUserId: UNOWNED, status: "needs_attention", reason: "owner_unknown", rematch: false, nextAttemptAt: null, deadLetteredAt: T0 + 99 });
    }
    expect(all[1]).toMatchObject({ sourceRef: "dev:l2", payload: { n: 2 }, createdAt: T0 + 2, attempts: 2 });
    const rows = await db.all<{ owner_user_id: string; status: string; next_attempt_at: number | null }>("SELECT owner_user_id, status, next_attempt_at FROM outbox");
    for (const r of rows) expect(r).toEqual({ owner_user_id: "", status: "needs_attention", next_attempt_at: null });
  });

  it("legacy rows are never sent: no signed-in user's pass touches them, and no user sees them", async () => {
    const db = await legacyDb();
    await migrate(db);
    const store = new SqliteOutboxStore(db);
    const api = new RecordingApi();
    const runner = (user: string | null) =>
      new OutboxRunner({
        store,
        api,
        session: { currentUserId: () => user, accessTokenFor: async (u) => `token-${u}` },
        now: () => T0 + 1_000,
        rng: () => 0,
        refreshCatalog: async () => {},
        rematch: async () => ({ ok: false }),
        findCourseForUnlisted: async () => null,
      });
    for (const user of [A, B, null, UNOWNED]) {
      await runner(user).run();
      expect(await visibleOutboxItems(store, user)).toEqual([]);
    }
    expect(api.sent).toEqual([]);
    expect((await store.list()).every((i) => i.status === "needs_attention")).toBe(true);
  });

  it("a new item can be enqueued after the upgrade, and the upgrade is idempotent (a second migrate changes nothing)", async () => {
    const db = await legacyDb();
    await migrate(db, { now: () => T0 + 99 });
    const store = new SqliteOutboxStore(db);
    await store.insertIfAbsent(createItem({ ...mk(9, A), sourceRef: "dev:l1" }, T0 + 200)); // same sourceRef as a legacy row: different owner, fine
    const before = await store.list();
    await migrate(db, { now: () => T0 + 5_000 });
    expect(await store.list()).toEqual(before);
    expect(before).toHaveLength(6);
    expect((await store.listByOwner(A)).map((i) => i.id)).toEqual(["o9"]);
  });

  it("a fresh install goes straight to v2 with the owner column and no legacy handling", async () => {
    const db = await openNodeSqlite();
    expect((await db.all<{ name: string }>("PRAGMA table_info(outbox)")).map((c) => c.name)).toContain("owner_user_id");
    expect(await db.all("SELECT * FROM outbox")).toEqual([]);
  });

  it("a failing upgrade rolls back whole: the old table and its rows are intact and the version unchanged", async () => {
    const db = await legacyDb();
    // A leftover `outbox_v2` makes the first statement of the upgrade fail, so the whole step must roll back (a corrupt row's JSON no longer fails
    // it, LOW-5: see the next test).
    await db.exec("CREATE TABLE outbox_v2 (x TEXT)");
    await expect(migrate(db)).rejects.toThrow();
    expect((await db.all<{ user_version: number }>("PRAGMA user_version"))[0]?.user_version).toBe(1);
    expect((await db.all("SELECT id FROM outbox")).length).toBe(5);
    expect((await db.all<{ name: string }>("SELECT name FROM sqlite_master WHERE name = 'outbox_v2'")).length).toBe(1); // only the one this test made
  });

  it("LOW-5: a legacy row with corrupt item_json does not abort the upgrade: it becomes an owner_unknown dead letter with a stub item", async () => {
    const db = await legacyDb();
    await db.run("UPDATE outbox SET item_json = '{not json' WHERE id = 'l3'");
    await db.run("UPDATE outbox SET item_json = '\"a string\"' WHERE id = 'l4'"); // valid JSON that is not an object
    await migrate(db, { now: () => T0 + 99 });
    expect((await db.all<{ user_version: number }>("PRAGMA user_version"))[0]?.user_version).toBe(SCHEMA_VERSION); // not stuck at 1
    const store = new SqliteOutboxStore(db);
    const all = await store.list();
    expect(all).toHaveLength(5); // nothing dropped (FM-03)
    for (const id of ["l3", "l4"]) {
      const it = all.find((i) => i.id === id)!;
      expect(it).toMatchObject({ ownerUserId: UNOWNED, status: "needs_attention", reason: "owner_unknown", deadLetteredAt: T0 + 99, payload: null, courseId: null, attempts: 0, rematch: false });
      expect(it.sourceRef).toBeTruthy();
    }
    // a second start is a no-op, not another failure
    await migrate(db);
    expect((await store.list()).length).toBe(5);
  });
});

describe("wiring (source checks: composition code that has no UI harness here)", () => {
  const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

  it("services: the runner's token is requested FOR the item's owner and the owner comes from the auth session", () => {
    const src = read("../src/runtime/services.ts");
    expect(src).toMatch(/accessTokenFor: \(userId: string, o\?: \{ forceRefresh\?: boolean \}\) =>\s*auth\.getAccessToken\(\{ forUserId: userId,/);
    expect(src).toMatch(/currentUserId = \(\): string \| null => auth\.current\(\)\?\.userId \?\? null/);
    expect(src).toMatch(/enqueueOutboxItem\(\{ store: outboxStore, currentUserId,/);
  });

  it("the UI enqueues only through enqueueOutbox, never straight into the store", () => {
    expect(read("../src/screens/DevPanel.tsx")).not.toMatch(/insertIfAbsent|createItem/);
    expect(read("../src/screens/DevPanel.tsx")).toMatch(/services\.enqueueOutbox\(/);
  });

  it("sign-out does not touch the outbox (it stays dormant); the provider lists only the signed-in user's items", () => {
    const src = read("../src/runtime/AppProvider.tsx");
    const signOut = src.match(/signOut: async \(\) => \{[\s\S]*?\n    \},/)?.[0] ?? "";
    expect(signOut).toContain("services.auth.signOut()");
    expect(signOut).not.toMatch(/outbox|deleteAll|delete\(/i);
    expect(src).toMatch(/visibleOutboxItems\(services\.outboxStore, userId\)/);
    expect(src).toMatch(/filterVisibleOutboxItems\(outboxLoaded, userId\)/);
    expect(src).not.toMatch(/outboxStore\.list\(\)/);
  });

  it("account deletion removes the deleted user's rows (deleteByOwners) and never wipes every owner's (deleteAll)", () => {
    const src = read("../src/account/delete.ts");
    expect(src).toMatch(/deps\.outbox\.deleteByOwners\(owners\)/);
    expect(src).not.toMatch(/deleteAll/);
  });
});
