/**
 * P4.2b-1: the REAL runner, the REAL http client (over a fake fetch serving the recorded server answers) and BOTH outbox stores, end to end:
 * the check-in token redemption, 401 handling, the owner's token, and historic imports through the batch endpoint.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { createHttpApiClient, type ApiClient } from "../src/api";
import { UnattestableAttestor } from "../src/attest";
import { buildEvidenceBody, parseEvidencePayload, toJsonValue, type EvidencePayload } from "../src/evidence";
import { BATCH_MAX_BYTES, BATCH_MAX_ITEMS, SERVER_MAX_BODY_BYTES, batchRequestBytes, planBatches, selectBatchEntries, type BatchEntry } from "../src/evidence/batch";
import { MemoryOutboxStore, OutboxRunner, SqliteOutboxStore, createItem, type OutboxItem, type OutboxStore } from "../src/outbox";
import { recorded, scriptedFetch, type Step } from "./support/edge-fixtures";
import { T0, itemFor, payloadFromWire, wireOf } from "./support/evidence";
import { openNodeSqlite } from "./support/node-sqlite";

const BASE = "https://proj.supabase.co/functions/v1";
const A = "user-a";
const B = "user-b";

const STORES: [string, () => Promise<OutboxStore>][] = [
  ["memory store", async () => new MemoryOutboxStore()],
  ["SQLite store", async () => new SqliteOutboxStore(await openNodeSqlite())],
];

describe.each(STORES)("evidence through the runner (%s)", (_n, makeStore) => {
  let store: OutboxStore;
  let who: { user: string | null };
  let clock: { now: number };
  let seen: ReturnType<typeof scriptedFetch>["seen"];
  let tokenLog: { user: string; refresh: boolean }[];
  let persisted: { id: string; payload: unknown; at: number }[];
  let hookBeforeToken: (() => void) | null;
  let refreshResult: (u: string) => string | null;
  let runner: OutboxRunner;
  let api: ApiClient;
  let rematched: number;

  function setup(steps: Step[]) {
    const f = scriptedFetch(...steps);
    seen = f.seen;
    api = createHttpApiClient({
      baseUrl: BASE,
      fetch: f.fetch,
      getAccessToken: () => Promise.reject(new Error("the evidence client must never fetch its own token")),
      rng: () => 0.5,
      sleep: () => Promise.resolve(),
      now: () => clock.now,
      attestor: new UnattestableAttestor(),
      persistEvidencePayload: async (item, payload) => {
        persisted.push({ id: item.id, payload, at: seen.length });
        const stored = await store.get(item.id);
        if (stored) await store.update({ ...stored, payload });
      },
    });
    runner = new OutboxRunner({
      store,
      api,
      session: {
        currentUserId: () => who.user,
        // Like the real auth service: a token only for the user whose session is the current one, read AFTER the (possibly slow) fetch.
        accessTokenFor: async (u, o) => {
          tokenLog.push({ user: u, refresh: o?.forceRefresh === true });
          const hook = hookBeforeToken;
          hookBeforeToken = null;
          hook?.();
          if (who.user !== u) return null;
          return o?.forceRefresh ? refreshResult(u) : `token-${u}`;
        },
      },
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => undefined,
      rematch: async (item) => {
        rematched += 1;
        return { ok: true, courseId: item.courseId, catalogVersion: item.catalogVersion ?? "20260520-a000001", payload: item.payload };
      },
      findCourseForUnlisted: async () => null,
    });
  }

  beforeEach(async () => {
    store = await makeStore();
    who = { user: A };
    clock = { now: T0 + 100_000 };
    tokenLog = [];
    persisted = [];
    hookBeforeToken = null;
    refreshResult = (u) => `fresh-${u}`;
    rematched = 0;
  });

  const add = (item: OutboxItem) => store.insertIfAbsent(item);
  const get = async (id: string): Promise<OutboxItem> => (await store.get(id))!;
  const evUrl = (s: { url: string }) => s.url.slice(BASE.length + 1);

  // ---- §7.6 through the runner -------------------------------------------------------------------------------------------------------------
  it("the four AT-11 answers in turn: 202, 422 catalog_stale, 429, 500: no item is lost and each shows its §7.6 state", async () => {
    // ev2's stale answer is followed in the same pass by a re-match and a resubmit (the 3rd answer, stale again: the next pass handles it)
    setup([{ respond: "evidence_202_queued_catalog" }, { respond: "evidence_422_catalog_stale" }, { respond: "evidence_422_catalog_stale" }, { respond: "evidence_429_rate_limited" }, { respond: "err_500_internal" }]);
    for (let n = 1; n <= 4; n += 1) await add(itemFor(wireOf("evidence_accepted_no_challenge"), n, A, {}, T0 + n));
    const r = await runner.run();
    expect(r).toMatchObject({ aborted: null, queued: 1, retry: 2 });
    expect((await get("ev1")).status).toBe("queued");
    // item 2: stale -> refresh + re-match + resubmit (the 5th scripted answer is stale again -> waits for the next pass)
    expect(await get("ev2")).toMatchObject({ status: "pending", rematch: true, lastServerCode: "catalog_stale" });
    expect(rematched).toBe(1);
    expect(await get("ev3")).toMatchObject({ status: "retry", lastHttpStatus: 429 });
    expect(await get("ev4")).toMatchObject({ status: "retry", lastHttpStatus: 500 });
    expect((await get("ev3")).nextAttemptAt).toBeGreaterThanOrEqual(clock.now + 3600_000); // Retry-After honoured
    expect(await store.list()).toHaveLength(4);
  });

  it("200 accepted -> accepted (and the same item is not sent again)", async () => {
    setup([{ respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    expect(await runner.run()).toMatchObject({ accepted: 1, sent: 1 });
    expect(await runner.run()).toMatchObject({ sent: 0 });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.headers["Authorization"]).toBe(`Bearer token-${A}`);
    expect(seen[0]!.body).toEqual(wireOf("evidence_accepted_no_challenge"));
  });

  it("a dead letter keeps the server's code and says why; a local defect never reaches the network", async () => {
    setup([{ respond: "evidence_409_conflict" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    await add(createItem({ id: "bad", sourceRef: "dev:1", ownerUserId: A, courseId: "crs_x1", catalogVersion: "20260520-a000001", payload: { dev: true } }, T0 + 9));
    await runner.run();
    expect(await get("ev1")).toMatchObject({ status: "needs_attention", reason: "rejected", lastServerCode: "evidence_conflict", lastHttpStatus: 409 });
    expect(await get("bad")).toMatchObject({ status: "needs_attention", reason: "unsendable", lastServerCode: "invalid_payload" });
    expect(seen).toHaveLength(1);
  });

  // ---- 401 ---------------------------------------------------------------------------------------------------------------------------------
  it("a 401 is NOT a rejection: one refresh for the item's owner, one resend with the fresh token, then accepted", async () => {
    setup([{ respond: "err_401_unauthorized" }, { respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    const r = await runner.run();
    expect(r).toMatchObject({ aborted: null, accepted: 1 });
    expect(seen.map((s) => s.headers["Authorization"])).toEqual([`Bearer token-${A}`, `Bearer fresh-${A}`]);
    expect(tokenLog).toEqual([{ user: A, refresh: false }, { user: A, refresh: true }]);
    expect(await get("ev1")).toMatchObject({ status: "accepted", reason: null });
  });

  it("a 401 that survives the refresh sets `retry` (never needs_attention) and stops the pass: the next items are not sent", async () => {
    setup([{ respond: "err_401_unauthorized" }]);
    for (let n = 1; n <= 3; n += 1) await add(itemFor(wireOf("evidence_accepted_no_challenge"), n, A, {}, T0 + n));
    const r = await runner.run();
    expect(r).toMatchObject({ aborted: "unauthorized", sent: 1, retry: 1, needsAttention: 0 });
    expect(await get("ev1")).toMatchObject({ status: "retry", lastHttpStatus: 401, reason: null, deadLetteredAt: null });
    expect(seen).toHaveLength(2); // the send and the single resend
    expect(await get("ev2")).toMatchObject({ status: "pending", attempts: 0 });
    expect(await get("ev3")).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("no refreshed token (the owner is no longer signed in / refresh refused): `retry`, one request only, pass stops", async () => {
    refreshResult = () => null;
    setup([{ respond: "err_401_unauthorized" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 2));
    expect(await runner.run()).toMatchObject({ aborted: "unauthorized", retry: 1 });
    expect(seen).toHaveLength(1);
    expect((await get("ev1")).status).toBe("retry");
    expect((await get("ev2")).status).toBe("pending");
  });

  it("a refresh that returns the SAME token is not a reason to resend", async () => {
    refreshResult = (u) => `token-${u}`;
    setup([{ respond: "err_401_unauthorized" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    await runner.run();
    expect(seen).toHaveLength(1);
  });

  it("the user switches during the refresh: no resend under anyone else's token, the item is `retry`", async () => {
    setup([{ respond: "err_401_unauthorized" }, { respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    const orig = refreshResult;
    refreshResult = (u) => {
      who.user = B; // B signs in as the refresh completes
      return orig(u);
    };
    const r = await runner.run();
    expect(r.aborted).not.toBeNull();
    expect(seen).toHaveLength(1);
    expect(seen.every((s) => s.headers["Authorization"] === `Bearer token-${A}`)).toBe(true);
    expect((await get("ev1")).status).toBe("retry");
  });

  // ---- A -> B -> A -------------------------------------------------------------------------------------------------------------------------
  it("A -> B -> A while A's token is being fetched: the token handed to submitEvidence is A's, or the send aborts", async () => {
    setup([{ respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    hookBeforeToken = () => {
      who.user = B;
      who.user = A; // and back, before the fetch returns
    };
    const r = await runner.run();
    expect(r).toMatchObject({ aborted: null, accepted: 1 });
    expect(seen.map((s) => s.headers["Authorization"])).toEqual([`Bearer token-${A}`]); // never B's
    expect(tokenLog).toEqual([{ user: A, refresh: false }]); // requested FOR the item's owner
  });

  it("A -> B during the fetch (B stays): the session refuses A's token; nothing is sent and the item is untouched", async () => {
    setup([{ respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    hookBeforeToken = () => {
      who.user = B;
    };
    const r = await runner.run();
    expect(r.aborted).toBe("user_changed");
    expect(seen).toEqual([]);
    expect(await get("ev1")).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("a stale token for the WRONG user (an auth service that ignores forUserId) can never be sent for A's item: the signed-in check runs after the fetch", async () => {
    setup([{ respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1));
    runner = new OutboxRunner({
      store,
      api,
      session: {
        currentUserId: () => who.user,
        accessTokenFor: async () => {
          who.user = B; // B signs in; the (buggy) service answers with B's token for A's request
          return "token-B";
        },
      },
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => undefined,
      rematch: async () => ({ ok: false }),
      findCourseForUnlisted: async () => null,
    });
    const r = await runner.run();
    expect(r.aborted).toBe("user_changed");
    expect(seen).toEqual([]);
  });

  // ---- check-in token redemption -----------------------------------------------------------------------------------------------------------
  const held = (over: Partial<Extract<EvidencePayload["challenges"][string], { state: "held" }>> = {}): Partial<EvidencePayload> => {
    const wire = wireOf("evidence_accepted_no_challenge");
    const fixId = (wire["fix"] as { fixId: string }).fixId;
    return { challenges: { [fixId]: { state: "held", challengeId: "chal_9", nonce: "bm9uY2U", kind: "prefetched", expiresAt: clock.now + 3600_000, ...over } } };
  };
  const stored = async (id: string): Promise<EvidencePayload> => {
    const p = parseEvidencePayload((await get(id)).payload);
    if (!p.ok) throw new Error(p.message);
    return p.payload;
  };
  const chOf = (p: EvidencePayload) => Object.values(p.challenges)[0]!;

  it("a held challenge is redeemed first (as the OWNER, hardwareSupportsAttestation false), then the evidence carries the jti; the jti is persisted BEFORE the evidence request", async () => {
    setup([{ respond: "token_201_unattestable" }, { respond: "evidence_accepted_with_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held()));
    expect(await runner.run()).toMatchObject({ accepted: 1 });
    expect(seen.map(evUrl)).toEqual(["checkin-token", "evidence"]);
    expect(seen[0]!.body).toEqual({ challengeId: "chal_9", nonce: "bm9uY2U", hardwareSupportsAttestation: false });
    expect(seen.map((s) => s.headers["Authorization"])).toEqual([`Bearer token-${A}`, `Bearer token-${A}`]);
    const evBody = seen[1]!.body as { fix: { checkinTokenJti?: string } };
    expect(evBody.fix.checkinTokenJti).toBe("jti_5"); // what the recorded redemption minted
    expect(persisted).toHaveLength(1);
    expect(persisted[0]!.at).toBe(1); // persisted when only the redeem request had been made
    expect(chOf(await stored("ev1"))).toMatchObject({ state: "redeemed", jti: "jti_5", grade: "unattestable", challengeId: "chal_9" });
  });

  it("an idempotent REPLAY of the redemption (the first response was lost) is accepted exactly like a first redemption: the same jti rides on the evidence", async () => {
    setup([{ respond: "token_201_idempotent_replay" }, { respond: "evidence_accepted_with_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held()));
    expect(await runner.run()).toMatchObject({ accepted: 1 });
    expect(seen.map(evUrl)).toEqual(["checkin-token", "evidence"]);
    expect((seen[1]!.body as { fix: { checkinTokenJti?: string } }).fix.checkinTokenJti).toBe("jti_5"); // the ORIGINAL token the server replayed
    expect(chOf(await stored("ev1"))).toMatchObject({ state: "redeemed", jti: "jti_5", grade: "unattestable" });
  });

  it("a REAL challenge_used drops the challenge and sends the fix without a co-signal (no retry of the redemption)", async () => {
    expect(JSON.parse(recorded("token_422_challenge_used").body).error.code).toBe("challenge_used");
    setup([{ respond: "token_422_challenge_used" }, { respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held()));
    await runner.run();
    expect(seen.map(evUrl)).toEqual(["checkin-token", "evidence"]);
    expect((seen[1]!.body as { fix: object }).fix).not.toHaveProperty("checkinTokenJti");
    expect(chOf(await stored("ev1"))).toEqual({ state: "none", reason: "unusable" });
  });

  it("a send that fails AFTER the redemption keeps the jti: the retry sends the SAME body without redeeming again (a changed replay would be a 409)", async () => {
    setup([{ respond: "token_201_unattestable" }, { respond: "err_500_internal" }, { respond: "evidence_accepted_with_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held()));
    await runner.run();
    expect(await get("ev1")).toMatchObject({ status: "retry" });
    expect(chOf(await stored("ev1"))).toMatchObject({ state: "redeemed", jti: "jti_5" }); // the runner's own write did not clobber it
    clock.now += 3_700_000;
    await runner.run();
    expect(seen.map(evUrl)).toEqual(["checkin-token", "evidence", "evidence"]); // ONE redemption
    expect(seen[2]!.body).toEqual(seen[1]!.body);
    expect(await get("ev1")).toMatchObject({ status: "accepted" });
  });

  it("a 401 on the evidence request AFTER the redemption: the resend carries the jti the first attempt recorded and does NOT redeem the challenge again", async () => {
    setup([{ respond: "token_201_unattestable" }, { respond: "err_401_unauthorized" }, { respond: "evidence_accepted_with_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held()));
    expect(await runner.run()).toMatchObject({ aborted: null, accepted: 1 });
    expect(seen.map(evUrl)).toEqual(["checkin-token", "evidence", "evidence"]); // ONE redemption
    expect(seen.map((s) => s.headers["Authorization"])).toEqual([`Bearer token-${A}`, `Bearer token-${A}`, `Bearer fresh-${A}`]);
    expect((seen[1]!.body as { fix: { checkinTokenJti?: string } }).fix.checkinTokenJti).toBe("jti_5");
    expect((seen[2]!.body as { fix: { checkinTokenJti?: string } }).fix.checkinTokenJti).toBe("jti_5"); // the resend carries it
    expect(seen[2]!.body).toEqual(seen[1]!.body);
    expect(chOf(await stored("ev1"))).toMatchObject({ state: "redeemed", jti: "jti_5" });
  });

  it("an EXPIRED held challenge is never redeemed or used: the fix goes with no challenge and the item says so", async () => {
    setup([{ respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held({ expiresAt: clock.now - 1 })));
    await runner.run();
    expect(seen.map(evUrl)).toEqual(["evidence"]); // no checkin-token request at all
    expect((seen[0]!.body as { fix: object }).fix).not.toHaveProperty("checkinTokenJti");
    expect(chOf(await stored("ev1"))).toEqual({ state: "none", reason: "expired" });
  });

  it("the server refuses the redemption for good (already used / expired / not ours): the evidence still goes, with no challenge, and the item says so", async () => {
    for (const name of ["token_422_challenge_used", "token_422_challenge_expired", "token_422_not_consumable_wrong_nonce", "token_404_not_found"]) {
      store = await makeStore();
      setup([{ respond: name }, { respond: "evidence_accepted_no_challenge" }]);
      await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held()));
      await runner.run();
      expect(seen.map(evUrl), name).toEqual(["checkin-token", "evidence"]);
      expect((seen[1]!.body as { fix: object }).fix).not.toHaveProperty("checkinTokenJti");
      expect(chOf(await stored("ev1")), name).toEqual({ state: "none", reason: "unusable" });
    }
  });

  it("a transient redemption failure (network, 5xx, 429) sends NO evidence, leaves the challenge held, and retries later", async () => {
    for (const step of [{ network: "reset" }, { respond: "err_503_service_unavailable" }, { respond: "err_429_rate_limited" }] as Step[]) {
      store = await makeStore();
      setup([step, { respond: "token_201_unattestable" }, { respond: "evidence_accepted_with_challenge" }]);
      await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held({ expiresAt: clock.now + 10 * 3600_000 })));
      await runner.run();
      expect(seen.map(evUrl)).toEqual(["checkin-token"]);
      expect(chOf(await stored("ev1")).state).toBe("held");
      expect((await get("ev1")).status).toBe("retry");
      clock.now += 3 * 3600_000 + 7200_000;
      await runner.run();
      expect(seen.map(evUrl)).toEqual(["checkin-token", "checkin-token", "evidence"]);
      expect((await get("ev1")).status).toBe("accepted");
    }
  });

  it("a challenge that expires while the item waits to retry is dropped at the next attempt, never used late", async () => {
    setup([{ network: "reset" }, { respond: "evidence_accepted_no_challenge" }]);
    await add(itemFor(wireOf("evidence_accepted_no_challenge"), 1, A, held({ expiresAt: clock.now + 600_000 })));
    await runner.run();
    expect(chOf(await stored("ev1")).state).toBe("held");
    clock.now += 7200_000;
    await runner.run();
    expect(seen.map(evUrl)).toEqual(["checkin-token", "evidence"]);
    expect(chOf(await stored("ev1"))).toEqual({ state: "none", reason: "expired" });
  });

  it("a dwell redeems one challenge per fix, in order, as the owner", async () => {
    const wire = wireOf("evidence_accepted_dwell_two_challenges");
    const p = payloadFromWire(wire);
    const [a, b] = Object.keys(p.challenges) as [string, string];
    const patch: Partial<EvidencePayload> = {
      challenges: {
        [a]: { state: "held", challengeId: "chal_1", nonce: "bm9uY2Ux", kind: "prefetched", expiresAt: clock.now + 3600_000 },
        [b]: { state: "held", challengeId: "chal_2", nonce: "bm9uY2Uy", kind: "prefetched", expiresAt: clock.now + 3600_000 },
      },
    };
    setup([{ respond: "token_201_unattestable" }, { respond: "token_201_failed_grade" }, { respond: "evidence_accepted_dwell_two_challenges" }]);
    await add(itemFor(wire, 1, A, patch));
    await runner.run();
    expect(seen.map(evUrl)).toEqual(["checkin-token", "checkin-token", "evidence"]);
    expect(seen.slice(0, 2).map((s) => (s.body as { challengeId: string }).challengeId)).toEqual(["chal_1", "chal_2"]);
    const body = seen[2]!.body as { checkinFix: { checkinTokenJti: string }; checkoutFix: { checkinTokenJti: string } };
    expect([body.checkinFix.checkinTokenJti, body.checkoutFix.checkinTokenJti]).toEqual(["jti_5", "jti_6"]);
  });

  // ---- batch -------------------------------------------------------------------------------------------------------------------------------
  const importItem = (n: number, date: string, owner = A): OutboxItem => {
    const wire = { ...wireOf("evidence_accepted_self_report"), localDate: date };
    const item = itemFor(wire, n, owner, { origin: "import" }, T0 + n); // enqueue order is NOT event order
    return { ...item, sourceRef: `import:${n}` };
  };

  it("historic imports go through POST evidence-batch, sorted by event time, split at 100, oldest request first", async () => {
    const dates: string[] = [];
    for (let i = 0; i < 230; i += 1) dates.push(new Date(Date.UTC(2026, 0, 1) + i * 86_400_000).toISOString().slice(0, 10));
    const shuffled = [...dates].sort((x, y) => (x.split("").reverse().join("") < y.split("").reverse().join("") ? -1 : 1));
    // every request answers 'accepted' for every item (one scripted body per call would not fit all sizes, so build the answers from the request)
    const f = scriptedFetch({ status: 200, body: "" });
    seen = f.seen;
    const fetchWrapped = (url: string, init: Parameters<typeof f.fetch>[1]) => {
      const n = (JSON.parse(init.body as string) as { items: unknown[] }).items.length;
      const results = Array.from({ length: n }, (_, index) => ({ index, ok: true, result: { status: "accepted" } }));
      void f.fetch(url, init);
      return Promise.resolve(new Response(JSON.stringify({ data: { results, maxBodyBytes: SERVER_MAX_BODY_BYTES } }), { status: 200 }));
    };
    api = createHttpApiClient({ baseUrl: BASE, fetch: fetchWrapped, getAccessToken: () => Promise.reject(new Error("no")), sleep: () => Promise.resolve(), now: () => clock.now });
    runner = new OutboxRunner({
      store,
      api,
      session: { currentUserId: () => who.user, accessTokenFor: async (u) => `token-${u}` },
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => undefined,
      rematch: async () => ({ ok: false }),
      findCourseForUnlisted: async () => null,
    });
    for (const [n, d] of shuffled.entries()) await add(importItem(n, d));
    const r = await runner.run();
    expect(r).toMatchObject({ aborted: null, sent: 230, accepted: 230 });
    expect(seen.map(evUrl)).toEqual(["evidence-batch", "evidence-batch", "evidence-batch"]);
    const sizes = seen.map((s) => (s.body as { items: unknown[] }).items.length);
    expect(sizes).toEqual([100, 100, 30]);
    const flat = seen.flatMap((s) => (s.body as { items: { localDate: string }[] }).items.map((i) => i.localDate));
    expect(flat).toEqual([...dates]); // globally sorted by event time across the requests
    expect(seen.every((s) => s.headers["Authorization"] === `Bearer token-${A}` && batchRequestBytes((s.body as { items: never[] }).items) <= BATCH_MAX_BYTES)).toBe(true);
    expect((await store.list()).every((i) => i.status === "accepted")).toBe(true);
  });

  it("per-item batch answers drive each item's transition (recorded: 1 accepted, 1 rate_limited)", async () => {
    setup([{ respond: "batch_200_rate_limited_item" }]);
    await add(importItem(1, "2026-05-15"));
    await add(importItem(2, "2026-05-14")); // enqueued later but older: it must go first
    const r = await runner.run();
    expect(r).toMatchObject({ aborted: null, sent: 2, accepted: 1, retry: 1 });
    expect((seen[0]!.body as { items: { localDate: string }[] }).items.map((i) => i.localDate)).toEqual(["2026-05-14", "2026-05-15"]);
    expect(await get("ev2")).toMatchObject({ status: "accepted" }); // index 0 = the older item
    expect(await get("ev1")).toMatchObject({ status: "retry", lastHttpStatus: 429, lastServerCode: "rate_limited" });
    // the item's own wait hint (error.details.retryAfterSeconds = 86400 in the recorded answer) sets the next attempt: a full day, not the ~seconds of the backoff
    expect((await get("ev1")).nextAttemptAt).toBe(clock.now + 86_400_000);
  });

  it("a batch is never auto-retried by the client: one request for a 500, items go to retry", async () => {
    setup([{ respond: "err_500_internal" }]);
    await add(importItem(1, "2026-05-15"));
    await add(importItem(2, "2026-05-14"));
    await runner.run();
    expect(seen).toHaveLength(1);
    expect((await store.list()).map((i) => i.status)).toEqual(["retry", "retry"]);
  });

  it("a whole-batch 401: one refresh, one resend of the same chunk with the fresh token", async () => {
    setup([{ respond: "err_401_unauthorized" }, { respond: "batch_200_rate_limited_item" }]);
    await add(importItem(1, "2026-05-15"));
    await add(importItem(2, "2026-05-14"));
    const r = await runner.run();
    expect(seen.map((s) => s.headers["Authorization"])).toEqual([`Bearer token-${A}`, `Bearer fresh-${A}`]);
    expect(r).toMatchObject({ accepted: 1, retry: 1 });
  });

  it("a whole-batch 401 whose refresh is refused (no token, or the same token) stops the pass with `unauthorized`: the live item behind the batch is NOT sent", async () => {
    for (const refresh of [() => null, (u: string) => `token-${u}`]) {
      store = await makeStore();
      refreshResult = refresh;
      setup([{ respond: "err_401_unauthorized" }, { respond: "evidence_accepted_no_challenge" }]);
      await add(importItem(1, "2026-05-15"));
      await add(importItem(2, "2026-05-14"));
      await add(itemFor(wireOf("evidence_accepted_no_challenge"), 3, A, {}, T0 + 3)); // a live play, sent by the single-item lane AFTER the batch
      const r = await runner.run();
      expect(r.aborted).toBe("unauthorized");
      expect(seen.map(evUrl)).toEqual(["evidence-batch"]); // one request: no resend, and the single-item lane never ran
      expect((await get("ev1")).status).toBe("retry");
      expect((await get("ev2")).status).toBe("retry");
      expect(await get("ev3")).toMatchObject({ status: "pending", attempts: 0 });
    }
  });

  it("a batch only ever holds the signed-in user's items, with that user's token", async () => {
    setup([{ respond: "batch_200_rate_limited_item" }]);
    await add(importItem(1, "2026-05-15", A));
    await add(importItem(2, "2026-05-14", A));
    await add(importItem(3, "2026-05-13", B));
    await runner.run();
    expect(seen).toHaveLength(1);
    expect((seen[0]!.body as { items: unknown[] }).items).toHaveLength(2);
    expect(await get("ev3")).toMatchObject({ status: "pending", attempts: 0 });
  });

  it("a live play is never batched", async () => {
    setup([{ respond: "evidence_accepted_self_report" }]);
    await add(itemFor(wireOf("evidence_accepted_self_report"), 1));
    await runner.run();
    expect(seen.map(evUrl)).toEqual(["evidence"]);
  });
});

describe("the batch planner (pure)", () => {
  const entry = (n: number, time: number, pad = 0): BatchEntry => ({
    item: createItem({ id: `i${n}`, sourceRef: `r${String(n).padStart(4, "0")}`, ownerUserId: "u", courseId: "c", catalogVersion: "20260101-aaaaaaa", payload: null }, 1),
    body: { n, pad: "x".repeat(pad) },
    eventTime: time,
  });

  it("sorts by event time (ties by sourceRef), whatever the input order", () => {
    const plan = planBatches([entry(3, 30), entry(1, 10), entry(2, 20), entry(5, 20), entry(4, 5)]);
    expect(plan.batches).toHaveLength(1);
    expect(plan.batches[0]!.map((e) => e.item.id)).toEqual(["i4", "i1", "i2", "i5", "i3"]);
  });

  it("splits at 100 items, no more, none lost, order kept across the requests", () => {
    const entries = Array.from({ length: 250 }, (_, i) => entry(i, 1000 - i));
    const plan = planBatches(entries);
    expect(plan.batches.map((b) => b.length)).toEqual([100, 100, 50]);
    expect(BATCH_MAX_ITEMS).toBe(100);
    const times = plan.batches.flat().map((e) => e.eventTime);
    expect(times).toEqual([...times].sort((a, b) => a - b));
    expect(new Set(plan.batches.flat().map((e) => e.item.id)).size).toBe(250);
  });

  it("splits on the server's 64 KiB body cap too, with a margin, and never exceeds it", () => {
    const entries = Array.from({ length: 40 }, (_, i) => entry(i, i, 6000)); // 40 x ~6 KB
    const plan = planBatches(entries);
    expect(plan.batches.length).toBeGreaterThan(3);
    for (const b of plan.batches) {
      expect(batchRequestBytes(b.map((e) => e.body))).toBeLessThanOrEqual(BATCH_MAX_BYTES);
      expect(b.length).toBeLessThanOrEqual(BATCH_MAX_ITEMS);
    }
    expect(BATCH_MAX_BYTES).toBeLessThan(SERVER_MAX_BODY_BYTES);
    expect(plan.batches.flat()).toHaveLength(40);
    // a chunk is full when one more item would not fit
    const first = plan.batches[0]!;
    expect(batchRequestBytes([...first, plan.batches[1]![0]!].map((e) => e.body))).toBeGreaterThan(BATCH_MAX_BYTES);
  });

  it("a single body larger than the cap is reported, not sent and not dropped", () => {
    const plan = planBatches([entry(1, 1), entry(2, 2, SERVER_MAX_BODY_BYTES + 10)]);
    expect(plan.oversized.map((e) => e.item.id)).toEqual(["i2"]);
    expect(plan.batches.flat().map((e) => e.item.id)).toEqual(["i1"]);
  });

  it("selectBatchEntries takes only import-origin items with a buildable body, and uses event time", () => {
    const live = itemFor(wireOf("evidence_accepted_self_report"), 1);
    const imp = itemFor(wireOf("evidence_accepted_self_report"), 2, "user-a", { origin: "import" });
    const noCourse = { ...itemFor(wireOf("evidence_accepted_self_report"), 3, "user-a", { origin: "import" }), courseId: null } as OutboxItem;
    const bad = createItem({ id: "x", sourceRef: "x", ownerUserId: "u", courseId: "c", catalogVersion: "20260101-aaaaaaa", payload: { dev: true } }, 1);
    const sel = selectBatchEntries([live, imp, noCourse, bad]);
    expect(sel.map((e) => e.item.id)).toEqual(["ev2"]);
    expect(sel[0]!.eventTime).toBe(Date.parse("2026-05-20T00:00:00Z"));
    expect(buildEvidenceBody(imp, parseEvidencePayloadOrThrow(imp))).toMatchObject({ ok: true });
    expect(recorded("batch_400_too_many").status).toBe(400);
    void toJsonValue;
  });
});

function parseEvidencePayloadOrThrow(i: OutboxItem): EvidencePayload {
  const p = parseEvidencePayload(i.payload);
  if (!p.ok) throw new Error(p.message);
  return p.payload;
}
