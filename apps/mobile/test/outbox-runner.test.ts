/**
 * P4 AT 11 (build plan §10): "with the server returning 202, 422
 * catalog_stale, 429 and 500 in turn, no item is lost and each shows the
 * §7.6 state; a forced needs_attention item appears in Played with 'Report
 * a problem'" — run against the real runner, both stores, and a scripted
 * stand-in for `POST /v1/evidence`.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  MemoryOutboxStore,
  OUTBOX_POLICY,
  OutboxRunner,
  SqliteOutboxStore,
  createItem,
  markReported,
  playedStatus,
  type EvidenceSubmitter,
  type NewOutboxItem,
  type OutboxItem,
  type OutboxRunnerDeps,
  type OutboxStore,
  type ServerAnswer,
} from "../src/outbox";
import { openNodeSqlite } from "./support/node-sqlite";

const T0 = 1_800_000_000_000;
const COURSE = "crs_01M39GMFJZ2P89V3ZZXPPH671T";
const mk = (n: number, over: Partial<NewOutboxItem> = {}): NewOutboxItem => ({
  id: `o${n}`,
  sourceRef: `health:r${n}`,
  courseId: COURSE,
  catalogVersion: "20260101-aaaaaaa",
  payload: { n },
  ...over,
});
const resp = (status: number, code?: string, retryAfterSeconds?: number): ServerAnswer => ({ kind: "response", status, code, retryAfterSeconds });

class ScriptedApi implements EvidenceSubmitter {
  readonly calls: { ref: string; at: number }[] = [];
  private script: ServerAnswer[] = [];
  constructor(private readonly clock: { now: number }) {}
  willAnswer(...answers: ServerAnswer[]): void {
    this.script.push(...answers);
  }
  submitEvidence(item: OutboxItem): Promise<ServerAnswer> {
    this.calls.push({ ref: item.sourceRef, at: this.clock.now });
    const next = this.script.shift();
    return Promise.resolve(next ?? resp(201));
  }
}

const STORES: [string, () => Promise<OutboxStore>][] = [
  ["memory store", async () => new MemoryOutboxStore()],
  ["SQLite store", async () => new SqliteOutboxStore(await openNodeSqlite())],
];

describe.each(STORES)("OutboxRunner (%s)", (_n, makeStore) => {
  let store: OutboxStore;
  let clock: { now: number };
  let api: ScriptedApi;
  let refreshes: number;
  let rematchResult: Awaited<ReturnType<OutboxRunnerDeps["rematch"]>>;
  let catalogCourse: { courseId: string; catalogVersion: string } | null;
  let runner: OutboxRunner;

  beforeEach(async () => {
    store = await makeStore();
    clock = { now: T0 };
    api = new ScriptedApi(clock);
    refreshes = 0;
    rematchResult = { ok: true, courseId: COURSE, catalogVersion: "20260201-bbbbbbb", payload: { rematched: true } };
    catalogCourse = null;
    runner = new OutboxRunner({
      store,
      api,
      now: () => clock.now,
      rng: () => 0, // minimum jitter => deterministic
      refreshCatalog: async () => {
        refreshes += 1;
      },
      rematch: async () => rematchResult,
      findCourseForUnlisted: async () => catalogCourse,
    });
  });

  const add = async (n: number, over: Partial<NewOutboxItem> = {}): Promise<void> => {
    await store.insertIfAbsent(createItem(mk(n, over), clock.now));
  };
  const byRef = async (n: number): Promise<OutboxItem> => (await store.list()).find((i) => i.sourceRef === `health:r${n}`)!;

  it("AT 11: 202, 422 catalog_stale, 429 and 500 in turn — nothing is lost and each item shows its §7.6 state", async () => {
    for (const n of [1, 2, 3, 4]) {
      clock.now += 1_000;
      await add(n);
    }
    // oldest first: r1 -> 202, r2 -> 422 (then, after the in-pass re-match, 201), r3 -> 429, r4 -> 500
    api.willAnswer(resp(202, "queued_catalog"), resp(422, "catalog_stale"), resp(201), resp(429, undefined, 60), resp(500));

    const report = await runner.run();
    expect(report).toMatchObject({ sent: 5, queued: 1, accepted: 1, retry: 2, rematched: 1 });
    expect(refreshes).toBe(1);

    expect(await store.list()).toHaveLength(4); // none lost
    expect(playedStatus(await byRef(1), clock.now)).toBe("queued");
    expect(playedStatus(await byRef(2), clock.now)).toBe("accepted");
    expect((await byRef(2)).payload).toEqual({ rematched: true }); // resubmitted the RE-MATCHED summary
    expect((await byRef(3)).status).toBe("retry");
    expect((await byRef(3)).nextAttemptAt).toBe(clock.now + 60_000); // Retry-After honoured
    expect((await byRef(4)).status).toBe("retry");

    // Not due yet: another pass sends nothing.
    expect((await runner.run()).sent).toBe(0);
    // After the backoff, both retries are resubmitted and accepted.
    clock.now += 60_000;
    expect(await runner.run()).toMatchObject({ sent: 2, accepted: 2 });
    expect((await store.list()).map((i) => i.status).sort()).toEqual(["accepted", "accepted", "accepted", "queued"]);
  });

  it("AT 11: a forced needs_attention item stays in Played with 'Report a problem', and the dead letter is kept 90 days", async () => {
    await add(1);
    api.willAnswer(resp(422, "unknown_id"));
    await runner.run();
    const dead = await byRef(1);
    expect(playedStatus(dead, clock.now)).toBe("needs_attention");
    expect(dead).toMatchObject({ reason: "rejected", lastServerCode: "unknown_id", reported: false });

    await store.update(markReported(dead, clock.now));
    expect((await byRef(1)).reported).toBe(true);

    clock.now += OUTBOX_POLICY.deadLetterRetentionMs - 1;
    expect((await runner.run()).expired).toBe(0);
    expect(await store.list()).toHaveLength(1);
    clock.now += 1;
    expect((await runner.run()).expired).toBe(1);
    expect(await store.list()).toHaveLength(0);
  });

  it("a second consecutive 422 catalog_stale does not spin: it waits for the next pass", async () => {
    await add(1);
    api.willAnswer(resp(422, "catalog_stale"), resp(422, "catalog_stale"), resp(201));
    const r1 = await runner.run();
    expect(r1.sent).toBe(2);
    expect((await byRef(1)).status).toBe("pending");
    expect((await byRef(1)).rematch).toBe(true);
    const r2 = await runner.run();
    expect(r2).toMatchObject({ rematched: 1, accepted: 1 });
  });

  it("422 catalog_stale + a re-match that cannot run => needs_attention, not dropped", async () => {
    await add(1);
    rematchResult = { ok: false };
    api.willAnswer(resp(422, "catalog_stale"));
    await runner.run();
    expect(await byRef(1)).toMatchObject({ status: "needs_attention", reason: "rematch_failed" });
  });

  it("an 'Unlisted course' item is never sent until a catalog carries the course (G3-01), then goes out like any other", async () => {
    await add(1, { courseId: null });
    await add(2);
    await runner.run();
    expect(api.calls.map((c) => c.ref)).toEqual(["health:r2"]); // r1 held back
    expect((await byRef(1)).status).toBe("pending");

    clock.now += 86_400_000;
    await runner.run();
    expect(api.calls).toHaveLength(1); // still held: the catalog has no such course

    catalogCourse = { courseId: COURSE, catalogVersion: "20260301-ccccccc" };
    const report = await runner.run();
    expect(report).toMatchObject({ resolvedUnlisted: 1, accepted: 1 });
    expect(api.calls.map((c) => c.ref)).toEqual(["health:r2", "health:r1"]);
    expect(await byRef(1)).toMatchObject({ status: "accepted", courseId: COURSE, catalogVersion: "20260301-ccccccc" });
  });

  it("is idempotent on sourceRef: the same play enqueued twice is one item", async () => {
    const a = await store.insertIfAbsent(createItem(mk(1), clock.now));
    const b = await store.insertIfAbsent(createItem({ ...mk(1), id: "other-id", payload: { different: true } }, clock.now + 5));
    expect(a.inserted).toBe(true);
    expect(b.inserted).toBe(false);
    expect(b.item.id).toBe("o1");
    expect(await store.list()).toHaveLength(1);
    expect((await store.list())[0]!.payload).toEqual({ n: 1 });
  });

  it("a process killed mid-request leaves a 'sent' item that returns to retry and is resent; the server dedupes (409 duplicate => accepted)", async () => {
    await add(1);
    // Simulate the crash: persisted as sent, answer never recorded.
    const item = await byRef(1);
    await store.update({ ...item, status: "sent", attempts: 1, updatedAt: clock.now });

    clock.now += OUTBOX_POLICY.sentStaleMs;
    api.willAnswer(resp(409, "duplicate"));
    const report = await runner.run();
    expect(report).toMatchObject({ recovered: 1, sent: 1, accepted: 1 });
    expect((await byRef(1)).attempts).toBe(2);
  });

  it("a transport exception from the API is a network error (retry), never a lost item", async () => {
    await add(1);
    const throwing: EvidenceSubmitter = { submitEvidence: () => Promise.reject(new Error("socket hang up")) };
    const r = new OutboxRunner({
      store,
      api: throwing,
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => {},
      rematch: async () => rematchResult,
      findCourseForUnlisted: async () => null,
    });
    await r.run();
    expect(await byRef(1)).toMatchObject({ status: "retry", lastHttpStatus: null });
  });

  it("run() is single-flight", async () => {
    await add(1);
    const [a, b] = await Promise.all([runner.run(), runner.run()]);
    expect(a).toBe(b);
    expect(api.calls).toHaveLength(1);
  });

  it("the store refuses to change an item's identity (append-only)", async () => {
    await add(1);
    const item = await byRef(1);
    await expect(store.update({ ...item, sourceRef: "health:other" })).rejects.toThrow(/immutable/);
    await expect(store.update({ ...item, createdAt: item.createdAt + 1 })).rejects.toThrow(/immutable/);
  });

  it("FUZZ: under random server behaviour no item ever disappears (only an expired dead letter may leave) and every state is one of the six", async () => {
    let seed = 12345;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const answers: ServerAnswer[] = [
      resp(201), resp(409, "duplicate"), resp(202, "queued_catalog"), resp(422, "catalog_stale"), resp(429, undefined, 30),
      resp(500), resp(503), resp(400), resp(404), resp(422, "unknown_id"), { kind: "network_error" }, resp(200), resp(302),
    ];
    const total = 30;
    for (let n = 0; n < total; n += 1) await add(n, n % 7 === 0 ? { courseId: null } : {});
    const valid = new Set(["pending", "sent", "accepted", "queued", "retry", "needs_attention"]);
    let expired = 0;
    for (let step = 0; step < 200; step += 1) {
      api.willAnswer(...Array.from({ length: 10 }, () => answers[Math.floor(rnd() * answers.length)]!));
      rematchResult = rnd() < 0.8 ? { ok: true, courseId: rnd() < 0.8 ? COURSE : null, catalogVersion: "v", payload: {} } : { ok: false };
      catalogCourse = rnd() < 0.3 ? { courseId: COURSE, catalogVersion: "v" } : null;
      clock.now += Math.floor(rnd() * 3 * 3_600_000);
      expired += (await runner.run()).expired;
      const items = await store.list();
      expect(items.length + expired).toBe(total);
      for (const it of items) {
        expect(valid.has(it.status)).toBe(true);
        if (it.status === "needs_attention") expect(it.deadLetteredAt).not.toBeNull();
        if (it.courseId === null) expect(["pending", "needs_attention"]).toContain(it.status); // an unlisted item is never sent
      }
    }
  });
});
