/**
 * P4 acceptance test 4: "An airplane-mode check-in is submitted exactly once, at full weight when a prefetched challenge was available."
 *
 * END TO END through the REAL pieces: the real HTTP client (over a fake `fetch` that serves the REAL handlers' recorded answers, or fails like a phone in airplane mode), the real
 * `ChallengeManager` and challenge store (memory and SQLite), the real `enqueueEvidence`, the real outbox store and `OutboxRunner`, and the real check-in flow with a scripted location.
 *
 *   1. online earlier: the pool is topped up through `checkin-challenge` (the recorded 10-challenge answer);
 *   2. airplane mode: the player taps "I'm here": the live challenge cannot be had (the request fails), one PREFETCHED challenge is consumed and held, the item is queued;
 *   3. still offline, the runner tries (twice, past the backoff): the redemption fails at the transport, NO evidence request is ever made and the item stays queued (`retry`);
 *   4. reconnected: ONE redemption (`checkin-token`), then ONE evidence request carrying the token's jti (the full-weight shape), answered 200 accepted;
 *   5. afterwards, more runner passes send nothing: the evidence request count over the whole timeline is exactly one.
 */
import { describe, expect, it } from "vitest";
import { createHttpApiClient, type ApiClient } from "../src/api";
import { ChallengeManager, MemoryChallengeStore, SqliteChallengeStore, type ChallengeStore } from "../src/challenges";
import { picksFromItems, runCheckIn } from "../src/checkin";
import { buildEvidenceBody, enqueueEvidence, parseEvidencePayload } from "../src/evidence";
import { MemoryOutboxStore, OutboxRunner, SqliteOutboxStore, enqueueOutboxItem, type OutboxStore } from "../src/outbox";
import { DEVICE, SITE_VERSION, entryOf, facility, rawFix } from "./support/checkin-rig";
import { recorded, scriptedFetch, type SeenRequest, type Step } from "./support/edge-fixtures";
import { openNodeSqlite } from "./support/node-sqlite";

const BASE = "https://proj.supabase.co/functions/v1";
const USER = "user-a";
const T0 = Date.parse("2026-06-01T12:00:00.000Z"); // the recorder's clock: the recorded challenges were issued at T0 and expire 24 h later
const H = 3600_000;

const STORES: [string, () => Promise<{ challengeStore: ChallengeStore; outbox: OutboxStore }>][] = [
  ["memory stores", async () => ({ challengeStore: new MemoryChallengeStore(), outbox: new MemoryOutboxStore() })],
  ["SQLite stores", async () => {
    const db = await openNodeSqlite();
    return { challengeStore: new SqliteChallengeStore(db), outbox: new SqliteOutboxStore(db) };
  }],
];

describe.each(STORES)("airplane-mode check-in, end to end (%s)", (_n, make) => {
  async function setup() {
    const { challengeStore, outbox } = await make();
    const clock = { now: T0 + H };
    const mode: { net: "online" | "airplane" } = { net: "online" };
    const seen: SeenRequest[] = [];
    let served = scriptedFetch({ respond: "challenge_prefetch_10_201" });
    const fetchImpl: Parameters<typeof createHttpApiClient>[0]["fetch"] = (url, init) => {
      if (mode.net === "airplane") {
        seen.push({ url, method: init.method, headers: init.headers, body: init.body === undefined ? undefined : JSON.parse(init.body), redirect: init.redirect, credentials: init.credentials });
        return Promise.reject(new TypeError("Network request failed"));
      }
      const before = served.seen.length;
      const p = served.fetch(url, init);
      seen.push(...served.seen.slice(before));
      return p;
    };
    const persisted: unknown[] = [];
    let api: ApiClient;
    const session = { currentUserId: () => USER as string | null, accessTokenFor: (u: string) => Promise.resolve(u === USER ? `token-${u}` : null) };
    api = createHttpApiClient({
      baseUrl: BASE,
      fetch: fetchImpl,
      getAccessToken: () => Promise.reject(new Error("never")),
      rng: () => 0.5,
      sleep: () => Promise.resolve(),
      now: () => clock.now,
      persistEvidencePayload: async (item, payload) => {
        persisted.push(payload);
        const stored = await outbox.get(item.id);
        if (stored) await outbox.update({ ...stored, payload });
      },
    });
    const challenges = new ChallengeManager({ store: challengeStore, api, session, deviceId: () => Promise.resolve(DEVICE), now: () => clock.now });
    let n = 0;
    const enqueue = (input: Parameters<typeof enqueueEvidence>[1]) =>
      enqueueEvidence(
        {
          challenges,
          currentUserId: () => USER,
          deviceId: () => Promise.resolve(DEVICE),
          enqueue: (draft) => enqueueOutboxItem({ store: outbox, currentUserId: () => USER, now: () => clock.now }, draft),
          existing: (o) => outbox.listByOwner(o),
          newId: () => `item-${(n += 1)}`,
        },
        input,
      );
    const runner = new OutboxRunner({
      store: outbox,
      api,
      session,
      now: () => clock.now,
      rng: () => 0,
      refreshCatalog: async () => undefined,
      rematch: async (item) => ({ ok: true, courseId: item.courseId, catalogVersion: item.catalogVersion ?? SITE_VERSION, payload: item.payload }),
      findCourseForUnlisted: async () => null,
    });
    const location = { fixes: [{ ok: true as const, fix: rawFix(T0 + H + 5_000) }] };
    const checkIn = () =>
      runCheckIn(
        {
          enabled: true,
          location: {
            permission: () => Promise.resolve({ status: "granted", approximate: false }),
            requestPermission: () => Promise.reject(new Error("must not prompt")),
            servicesEnabled: () => Promise.resolve(true),
            currentFix: () => Promise.resolve(location.fixes[0]!),
          },
          currentUserId: () => USER,
          challenges,
          enqueueEvidence: enqueue,
          existingPicks: async (o) => picksFromItems(await outbox.listByOwner(o)),
          manifestSig: () => Promise.resolve(null),
          newFixId: () => "airplaneFix1",
          now: () => clock.now,
          timing: { liveBudgetMs: 2_000, fixTimeoutMs: 5_000, maxFixAgeMs: 60_000, maxFixAheadMs: 10_000 },
        },
        { entry: entryOf(facility()), catalogVersion: SITE_VERSION, index: null },
      );
    return {
      challengeStore, outbox, clock, mode, seen, runner, challenges, checkIn, persisted,
      serve: (...steps: Step[]) => {
        served = scriptedFetch(...steps);
      },
    };
  }

  it("is submitted exactly once, with its prefetched challenge (full weight), after the phone reconnects", async () => {
    const r = await setup();

    // 1. online: the pool is topped up (the recorded real answer: 10 challenges)
    expect(await r.challenges.prefetch()).toMatchObject({ kind: "filled", added: 10 });
    expect(await r.challengeStore.countUsable(USER, DEVICE, r.clock.now)).toBe(10);
    r.seen.length = 0;

    // 2. airplane mode: the tap
    r.mode.net = "airplane";
    r.clock.now = T0 + H + 6_000;
    const o = await r.checkIn();
    expect(o).toMatchObject({ kind: "queued", challenge: "prefetched", penalty: false });
    if (o.kind !== "queued") throw new Error("unreachable");
    expect(await r.challengeStore.countUsable(USER, DEVICE, r.clock.now)).toBe(9); // exactly one consumed
    expect(r.seen.map((s) => s.url.slice(BASE.length + 1))).toEqual(["checkin-challenge"]); // the live attempt, which failed; nothing else left the phone
    expect((await r.outbox.get(o.item.id))?.status).toBe("pending");

    // 3. still offline: two runner passes, past the backoff
    r.seen.length = 0;
    await r.runner.run();
    r.clock.now += 2 * H;
    await r.runner.run();
    const offlineUrls = r.seen.map((s) => s.url.slice(BASE.length + 1));
    expect(offlineUrls.length).toBeGreaterThan(0);
    expect(offlineUrls.every((u) => u === "checkin-token")).toBe(true); // the redemption was tried and failed; NO evidence request
    expect((await r.outbox.get(o.item.id))?.status).toBe("retry");
    expect(await r.challengeStore.countUsable(USER, DEVICE, r.clock.now)).toBe(9); // a failed redemption does not spend another challenge

    // 4. reconnected
    r.mode.net = "online";
    const tokenBody = JSON.parse(recorded("token_201_unattestable").body) as { data: { jti: string } };
    const jti = tokenBody.data.jti;
    r.serve({ respond: "token_201_unattestable" }, { respond: "evidence_accepted_with_challenge" });
    r.seen.length = 0;
    r.clock.now += 2 * H;
    const report = await r.runner.run();
    expect(report).toMatchObject({ aborted: null, accepted: 1 });
    expect((await r.outbox.get(o.item.id))?.status).toBe("accepted");
    const urls = r.seen.map((s) => s.url.slice(BASE.length + 1));
    expect(urls).toEqual(["checkin-token", "evidence"]); // one redemption, then ONE submission
    const evidence = r.seen[1]!;
    expect(evidence.headers["Authorization"]).toBe(`Bearer token-${USER}`);
    // the body is the full-weight shape: it names the token (a co-signal), the facility-local date, the device-shaped fix
    const stored = parseEvidencePayload((await r.outbox.get(o.item.id))!.payload);
    expect(stored.ok).toBe(true);
    const wire = evidence.body as { fix: Record<string, unknown>; localDate: string; courseId: string; deviceId: string };
    expect(wire.fix["checkinTokenJti"]).toBe(jti);
    expect(wire).toMatchObject({ source: "foreground_checkin", courseId: "crs_x1", deviceId: DEVICE, localDate: "2026-06-01", catalogVersion: SITE_VERSION });
    expect(wire.fix).toMatchObject({ fixId: "airplaneFix1", capturedAt: T0 + H + 5_000, simulated: false, foreground: true, fromApp: true });
    if (stored.ok) expect(buildEvidenceBody({ courseId: "crs_x1", catalogVersion: SITE_VERSION }, stored.payload)).toEqual({ ok: true, body: evidence.body });

    // 5. nothing is ever sent again
    r.seen.length = 0;
    r.serve({ status: 500, body: "must not be called" });
    for (let i = 0; i < 3; i += 1) {
      r.clock.now += 6 * H;
      await r.runner.run();
    }
    expect(r.seen).toEqual([]);
    expect((await r.outbox.list()).filter((i) => i.sourceRef === o.item.sourceRef)).toHaveLength(1);
  });

  it("with NO prefetched challenge left the same airplane check-in is queued with none (x0.6) and says so, and is still submitted exactly once", async () => {
    const r = await setup();
    r.mode.net = "airplane";
    r.clock.now = T0 + H + 6_000;
    const o = await r.checkIn();
    expect(o).toMatchObject({ kind: "queued", challenge: "none", penalty: true });
    if (o.kind !== "queued") throw new Error("unreachable");
    r.mode.net = "online";
    r.serve({ respond: "evidence_accepted_no_challenge" });
    r.seen.length = 0;
    r.clock.now += 3 * H;
    await r.runner.run();
    await r.runner.run();
    expect(r.seen.map((s) => s.url.slice(BASE.length + 1))).toEqual(["evidence"]);
    expect((r.seen[0]!.body as { fix: Record<string, unknown> }).fix["checkinTokenJti"]).toBeUndefined();
    expect((await r.outbox.get(o.item.id))?.status).toBe("accepted");
  });

  it("a prefetched challenge that EXPIRES before the phone reconnects is dropped at send time: the item goes without it (x0.6), still exactly once", async () => {
    const r = await setup();
    await r.challenges.prefetch();
    r.mode.net = "airplane";
    r.clock.now = T0 + H + 6_000;
    const o = await r.checkIn();
    if (o.kind !== "queued") throw new Error("not queued");
    r.mode.net = "online";
    r.serve({ respond: "evidence_accepted_no_challenge" });
    r.seen.length = 0;
    r.clock.now = T0 + 30 * H; // past the recorded 24 h expiry
    await r.runner.run();
    expect(r.seen.map((s) => s.url.slice(BASE.length + 1))).toEqual(["evidence"]); // no redemption of an expired challenge
    expect((r.seen[0]!.body as { fix: Record<string, unknown> }).fix["checkinTokenJti"]).toBeUndefined();
    const p = parseEvidencePayload((await r.outbox.get(o.item.id))!.payload);
    expect(p.ok && p.payload.challenges["airplaneFix1"]).toEqual({ state: "none", reason: "expired" });
  });
});
