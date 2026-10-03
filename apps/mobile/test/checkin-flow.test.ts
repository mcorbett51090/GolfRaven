/**
 * P4.2c: the foreground check-in flow (`src/checkin/flow.ts`) over the REAL challenge manager / store, `enqueueEvidence` and outbox store, with a scripted location and challenge API.
 * Covers: prefetched vs live challenge, the `capturedAt` window, the order of refusals (nothing is asked or spent before it is needed), the permission states and the §4.3 one-pick guard.
 */
import { describe, expect, it } from "vitest";
import { MemoryChallengeStore, SqliteChallengeStore, type ChallengeStore } from "../src/challenges";
import { CHECKIN_TIMING, fixProblem, liveCovers, type CheckInOutcome } from "../src/checkin";
import { parseEvidencePayload } from "../src/evidence";
import { MemoryOutboxStore, SqliteOutboxStore } from "../src/outbox";
import { DEVICE, NASHVILLE, NOW0, entryOf, facility, indexOf, makeRig, rawFix } from "./support/checkin-rig";
import { openNodeSqlite } from "./support/node-sqlite";

const H = 3600_000;
type Queued = Extract<CheckInOutcome, { kind: "queued" }>;
const queued = (o: CheckInOutcome): Queued => {
  expect(o.kind).toBe("queued");
  return o as Queued;
};
const payloadOf = (o: Queued) => {
  const p = parseEvidencePayload(o.item.payload);
  if (!p.ok) throw new Error(p.message);
  return p.payload;
};
const poolUsable = (r: ReturnType<typeof makeRig>): Promise<number> => r.challengeStore.countUsable("user-a", DEVICE, r.clock.now);

const F = facility();
const E = entryOf(F);

const STORES: [string, () => Promise<{ challengeStore: ChallengeStore; outbox: MemoryOutboxStore | SqliteOutboxStore }>][] = [
  ["memory stores", async () => ({ challengeStore: new MemoryChallengeStore(), outbox: new MemoryOutboxStore() })],
  ["SQLite stores", async () => {
    const db = await openNodeSqlite();
    return { challengeStore: new SqliteChallengeStore(db), outbox: new SqliteOutboxStore(db) };
  }],
];

describe.each(STORES)("a check-in is queued with the right challenge (%s)", (_n, make) => {
  it("OFFLINE: a prefetched challenge is consumed (held), the item is pending, nothing was sent, and the fix is exactly what the device reported", async () => {
    const rig = makeRig(await make());
    rig.api.online = false;
    await rig.seedPool(3, NOW0 - 3 * H);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 2_000, { latitude: 36.14671234, longitude: -86.78159876, accuracyMeters: 8.123 }) }];
    const o = queued(await rig.run(E));
    expect(o).toMatchObject({ challenge: "prefetched", penalty: false, geometryKind: "radius", capturedAt: NOW0 - 2_000, accuracyMeters: 8.123 });
    expect(o.item).toMatchObject({ status: "pending", courseId: "crs_x1", ownerUserId: "user-a" });
    const p = payloadOf(o);
    const fixId = rig.fixIds[0]!;
    expect(p.submission).toEqual({
      source: "foreground_checkin",
      fix: { fixId, lat: 36.14671234, lng: -86.78159876, accuracyMeters: 8.123, capturedAt: NOW0 - 2_000, simulated: false, foreground: true, fromApp: true },
    });
    expect(p.challenges[fixId]).toMatchObject({ state: "held", kind: "prefetched" });
    expect(p).toMatchObject({ deviceId: DEVICE, facilityId: "fac_x", localDate: "2026-06-01", origin: "live" });
    expect(await poolUsable(rig)).toBe(2); // exactly one consumed
    expect(rig.api.redeemed).toEqual([]); // redemption happens at send time, online
  });

  it("ONLINE: a live challenge is taken BEFORE the fix, redeemed on the spot, and used for the fix; the pool is untouched", async () => {
    const rig = makeRig(await make());
    await rig.seedPool(3, NOW0 - 3 * H);
    const order: string[] = [];
    rig.location.onFix = async () => {
      order.push(`fix after ${rig.api.requests.length} challenge request(s)`);
    };
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 500) }];
    rig.clock.now = NOW0; // the live challenge is received at NOW0; the fix is stamped half a second later
    const o = queued(await rig.run(E));
    expect(order).toEqual(["fix after 1 challenge request(s)"]); // the live challenge was requested first
    expect(rig.api.requests).toEqual([{ deviceId: DEVICE, facilityId: "fac_x" }]);
    expect(o.challenge).toBe("live");
    expect(payloadOf(o).challenges[rig.fixIds[0]!]).toMatchObject({ state: "redeemed", kind: "live", jti: "jti_live1", grade: "unattestable" });
    expect(await poolUsable(rig)).toBe(3);
    expect(rig.enqueued[0]!.live).toBeUndefined(); // never `acquireForFix({ live })` after the fix (its challenge would be issued after the fix)
  });

  it("a live challenge whose window does NOT contain the fix (the fix is older than the challenge) is dropped and the POOL is used", async () => {
    const rig = makeRig(await make());
    await rig.seedPool(2, NOW0 - 3 * H);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 5_000) }]; // captured 5 s BEFORE the live challenge was received
    const o = queued(await rig.run(E));
    expect(o.challenge).toBe("prefetched");
    expect(payloadOf(o).challenges[rig.fixIds[0]!]).toMatchObject({ state: "held", kind: "prefetched" });
    expect(rig.api.redeemed).toEqual(["live1"]); // the live token was minted and is simply not used (it expires in 120 s)
  });

  it("a live challenge that EXPIRED before the fix was captured does not cover it either", async () => {
    const rig = makeRig(await make());
    await rig.seedPool(1, NOW0 - 3 * H);
    rig.location.onFix = async () => {
      rig.clock.now = NOW0 + 125_000; // the fix took 125 s: past the 120 s window
    };
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 125_000) }];
    const o = queued(await rig.run(E));
    expect(o.challenge).toBe("prefetched");
  });

  it("no live challenge and an empty pool: the item is still queued, with NO challenge, and says so (the x0.6 penalty)", async () => {
    const rig = makeRig(await make());
    rig.api.online = false;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 1_000) }];
    const o = queued(await rig.run(E));
    expect(o).toMatchObject({ challenge: "none", penalty: true });
    expect(payloadOf(o).challenges[rig.fixIds[0]!]).toEqual({ state: "none", reason: "none_available" });
  });

  it("the pool is windowed by the FIX: challenges received AFTER the fix was captured never cover it", async () => {
    const rig = makeRig(await make());
    rig.api.online = false;
    await rig.seedPool(2, NOW0 + 10_000); // received 10 s after the fix below
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 1_000) }];
    const o = queued(await rig.run(E));
    expect(o.challenge).toBe("none");
    expect(await poolUsable(rig)).toBe(2); // none consumed
  });

  it("a slow live challenge (past the budget) never delays the check-in: the pool is used", async () => {
    const rig = makeRig(await make());
    await rig.seedPool(1, NOW0 - 3 * H);
    rig.api.requestCheckinChallenges = () => new Promise(() => undefined); // never answers
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    const t0 = Date.now();
    const o = queued(await rig.run(E, { timing: { ...CHECKIN_TIMING, liveBudgetMs: 30 } }));
    expect(Date.now() - t0).toBeLessThan(1500);
    expect(o.challenge).toBe("prefetched");
  });

  it("the manifest signature is carried when the catalog has one", async () => {
    const rig = makeRig(await make());
    rig.api.online = false;
    const sig = { catalogVersion: "20260520-a000001", kid: "k1", contractVersion: 1, sig: "A".repeat(86) + "==", manifestSha: "0123456789abcdef".repeat(4) };
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    const o = queued(await rig.run(E, { manifestSig: () => Promise.resolve(sig) }));
    expect(rig.enqueued[0]!.manifestSig).toEqual(sig);
    expect(payloadOf(o).manifestSig).toEqual(sig);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 1) }];
    await rig.run(E, { manifestSig: () => Promise.reject(new Error("boom")) }); // a failure to read it is not a failed check-in
    expect(rig.enqueued[1]!.manifestSig).toBeUndefined();
  });
});

describe("the date is the FACILITY-LOCAL date of the fix's own time", () => {
  it("23:59:30 in America/Chicago on 06-01 is 06-02 in UTC: the item says 2026-06-01", async () => {
    const rig = makeRig();
    rig.api.online = false;
    const t = Date.parse("2026-06-02T04:59:30.000Z");
    rig.clock.now = t + 1_000;
    rig.location.fixes = [{ ok: true, fix: rawFix(t) }];
    const o = queued(await rig.run(E));
    expect(payloadOf(o).localDate).toBe("2026-06-01");
  });

  it("the date is the fix's, not 'now's: a fix taken at 23:59:58 and processed after midnight keeps the day it was taken", async () => {
    const rig = makeRig();
    rig.api.online = false;
    const t = Date.parse("2026-06-02T04:59:58.000Z"); // 23:59:58 on 06-01 in Chicago
    rig.clock.now = t + 5_000; // 00:00:03 on 06-02: the flow runs after midnight
    rig.location.fixes = [{ ok: true, fix: rawFix(t) }];
    expect(payloadOf(queued(await rig.run(E))).localDate).toBe("2026-06-01");
  });

  it("a check-in queued offline just after midnight keeps the date of the moment it was TAKEN, and the date follows the facility's tz, not the phone's", async () => {
    const rig = makeRig();
    rig.api.online = false;
    const toronto = entryOf(facility({ id: "fac_t", tz: "America/Toronto", courses: [{ id: "crs_t1", holes: 18 }] }));
    const t = Date.parse("2026-06-02T03:59:59.000Z"); // 23:59:59 on 06-01 in Toronto (UTC-4)
    rig.clock.now = t + 2_000;
    rig.location.fixes = [{ ok: true, fix: rawFix(t) }];
    expect(payloadOf(queued(await rig.run(toronto))).localDate).toBe("2026-06-01");
  });
});

describe("refusals: nothing is asked, requested or spent before it is needed", () => {
  const untouched = async (rig: ReturnType<typeof makeRig>, o: CheckInOutcome, kind: string): Promise<void> => {
    expect(o.kind).toBe(kind);
    expect(await rig.outbox.list()).toEqual([]);
    expect(rig.enqueued).toEqual([]);
  };

  it("the build switch is off: nothing at all runs (no permission read, no prompt, no challenge request, no fix)", async () => {
    const rig = makeRig();
    rig.location.perm = { status: "undetermined" };
    await rig.seedPool(2, NOW0 - H);
    const o = await rig.run(E, { enabled: false });
    await untouched(rig, o, "disabled");
    expect(rig.location.calls).toEqual({ permission: 0, request: 0, services: 0, fix: 0 });
    expect(rig.api.requests).toEqual([]);
    expect(await poolUsable(rig)).toBe(2);
  });

  it("signed out: nothing runs and the screen sends the player to sign in", async () => {
    const rig = makeRig({ user: null });
    rig.location.perm = { status: "undetermined" };
    await untouched(rig, await rig.run(E), "signed_out");
    expect(rig.location.calls.request).toBe(0);
  });

  it.each([
    ["an unverified facility", facility({ status: "unverified" })],
    ["an approximate coordinate", facility({ approx: true })],
    ["no coordinate at all", facility({ lat: null, lng: null })],
  ])("%s: there is no geometry on the device, so the check-in is refused BEFORE the permission prompt", async (_n, f) => {
    const rig = makeRig();
    rig.location.perm = { status: "undetermined" };
    await untouched(rig, await rig.run(entryOf(f)), "no_geometry");
    expect(rig.location.calls).toEqual({ permission: 0, request: 0, services: 0, fix: 0 });
  });

  it("a catalog version that is not a site version (the dev demo catalog) is refused before anything is asked", async () => {
    const rig = makeRig();
    rig.location.perm = { status: "undetermined" };
    const o = await rig.run(E, undefined, { catalogVersion: "00000000-demo000" });
    await untouched(rig, o, "no_catalog");
    expect(rig.location.calls.request).toBe(0);
  });

  it("a facility whose time zone the phone cannot resolve: refused, never a guessed date", async () => {
    const rig = makeRig();
    rig.location.perm = { status: "undetermined" };
    await untouched(rig, await rig.run(entryOf(facility({ tz: "Not/AZone" }))), "no_timezone");
    expect(rig.location.calls.request).toBe(0);
  });

  it("permission: undetermined -> the prompt is shown ONCE, from this call, and a grant carries on", async () => {
    const rig = makeRig();
    rig.api.online = false;
    rig.location.perm = { status: "undetermined" };
    rig.location.prompt = { status: "granted", approximate: false };
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    queued(await rig.run(E));
    expect(rig.location.calls.request).toBe(1);
    // already granted: no prompt on the next tap
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 1) }];
    queued(await rig.run(E));
    expect(rig.location.calls.request).toBe(1);
  });

  it("permission: declined at the prompt (it may be asked again) = 'denied'; the next tap asks again; denied for good = 'blocked' and the prompt is NOT shown", async () => {
    const rig = makeRig();
    rig.location.perm = { status: "undetermined" };
    rig.location.prompt = { status: "denied", canAskAgain: true };
    const first = await rig.run(E);
    await untouched(rig, first, "permission");
    expect(first).toEqual({ kind: "permission", status: "denied" });
    expect(rig.location.calls.request).toBe(1);
    await rig.run(E); // denied but still askable: a new explicit tap asks again
    expect(rig.location.calls.request).toBe(2);
    rig.location.perm = { status: "denied", canAskAgain: false };
    const blocked = await rig.run(E);
    expect(blocked).toEqual({ kind: "permission", status: "blocked" });
    expect(rig.location.calls.request).toBe(2); // not shown: the system would not show it
    expect(rig.location.calls.fix).toBe(0);
  });

  it("permission: a coarse-only grant is 'approximate' (never reaches 50 m), no fix is taken", async () => {
    const rig = makeRig();
    rig.location.perm = { status: "granted", approximate: true };
    expect(await rig.run(E)).toEqual({ kind: "permission", status: "approximate" });
    expect(rig.location.calls.fix).toBe(0);
  });

  it("location services off", async () => {
    const rig = makeRig();
    rig.location.services = false;
    await untouched(rig, await rig.run(E), "services_off");
    expect(rig.location.calls.fix).toBe(0);
  });

  it.each([
    ["timeout", { ok: false, reason: "timeout" } as const, { kind: "no_fix", reason: "timeout" }],
    ["unavailable", { ok: false, reason: "unavailable" } as const, { kind: "no_fix", reason: "unavailable" }],
    ["a non-finite coordinate", { ok: true, fix: rawFix(NOW0, { latitude: Number.NaN }) } as const, { kind: "no_fix", reason: "invalid" }],
    ["a latitude out of range", { ok: true, fix: rawFix(NOW0, { latitude: 91 }) } as const, { kind: "no_fix", reason: "invalid" }],
    ["an implausible timestamp", { ok: true, fix: rawFix(Date.UTC(2019, 0, 1)) } as const, { kind: "no_fix", reason: "invalid" }],
    ["a cached fix (older than a minute)", { ok: true, fix: rawFix(NOW0 - 61_000) } as const, { kind: "stale_fix" }],
    ["a fix from the future", { ok: true, fix: rawFix(NOW0 + 6_000) } as const, { kind: "stale_fix" }],
    ["a simulated fix", { ok: true, fix: rawFix(NOW0, { simulated: true }) } as const, { kind: "simulated" }],
    ["no accuracy reported", { ok: true, fix: rawFix(NOW0, { accuracyMeters: null }) } as const, { kind: "inaccurate", accuracyMeters: Number.POSITIVE_INFINITY }],
    ["a negative accuracy", { ok: true, fix: rawFix(NOW0, { accuracyMeters: -1 }) } as const, { kind: "inaccurate", accuracyMeters: Number.POSITIVE_INFINITY }],
    ["accuracy 51 m (the cap is 50)", { ok: true, fix: rawFix(NOW0, { accuracyMeters: 51 }) } as const, { kind: "inaccurate", accuracyMeters: 51 }],
  ])("%s: refused, and no challenge is spent, nothing is queued", async (_n, attempt, expected) => {
    const rig = makeRig();
    rig.api.online = false;
    await rig.seedPool(2, NOW0 - H);
    rig.location.fixes = [attempt];
    const o = await rig.run(E);
    expect(o).toEqual(expected);
    expect(await rig.outbox.list()).toEqual([]);
    expect(await poolUsable(rig)).toBe(2);
  });

  it("accuracy exactly 50 m is accepted (the matcher's rule: <= 50)", async () => {
    const rig = makeRig();
    rig.api.online = false;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0, { accuracyMeters: 50 }) }];
    queued(await rig.run(E));
  });

  it("a local failure inside the flow (the outbox refuses) is an outcome, not an exception", async () => {
    const rig = makeRig();
    rig.api.online = false;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    const o = await rig.run(E, { enqueueEvidence: () => Promise.reject(new Error("disk full")) });
    expect(o).toEqual({ kind: "failed", message: "disk full" });
  });

  it("the player signed out WHILE the check-in ran: the enqueue refuses and nothing is stored for anyone", async () => {
    const rig = makeRig();
    rig.api.online = false;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    rig.location.onFix = async () => {
      rig.who.user = null;
    };
    const o = await rig.run(E);
    expect(o.kind).toBe("signed_out");
    expect(await rig.outbox.list()).toEqual([]);
  });
});

describe("§4.3 user pick at a multi-course facility: one pick per facility per date", () => {
  const two = facility({ id: "fac_m", courses: [{ id: "crs_m1", holes: 18 }, { id: "crs_m2", holes: 18 }] });

  it("a second pick of a DIFFERENT course on the same facility-local date is refused (nothing prompted); the same course again, another facility, and another day are fine", async () => {
    const rig = makeRig();
    rig.api.online = false;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    queued(await rig.run(entryOf(two, 0)));
    const calls = { ...rig.location.calls };
    const refused = await rig.run(entryOf(two, 1));
    expect(refused).toEqual({ kind: "already_picked", courseId: "crs_m1" });
    expect(rig.location.calls).toEqual(calls); // refused before the permission read
    rig.clock.now = NOW0 + 1_000;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 1_000) }];
    queued(await rig.run(entryOf(two, 0))); // the same course: not a second pick
    queued(await rig.run(E)); // another facility
    rig.clock.now = NOW0 + 24 * H; // the next day
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 24 * H) }];
    const sibling = queued(await rig.run(entryOf(two, 1)));
    // the pick is the course the player chose, not the facility's first course
    expect(sibling.item.courseId).toBe("crs_m2");
    expect(payloadOf(sibling).facilityId).toBe("fac_m");
    expect(rig.enqueued.at(-1)).toMatchObject({ courseId: "crs_m2", facilityId: "fac_m" });
  });

  it("a single-course facility has no pick to guard", async () => {
    const rig = makeRig();
    rig.api.online = false;
    for (let i = 0; i < 2; i += 1) {
      rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + i) }];
      queued(await rig.run(E));
    }
  });
});

describe("wrong-course safety: the course matched is the one picked, at the facility the fix is in", () => {
  it("a fix at the OTHER facility is 'not here' for this course page (with the facility the player is at offered), and nothing is recorded", async () => {
    const a = facility({ id: "fac_a", lat: NASHVILLE.lat, lng: NASHVILLE.lng, courses: [{ id: "crs_a1", holes: 18 }] });
    const b = facility({ id: "fac_b", lat: NASHVILLE.lat + 0.02, lng: NASHVILLE.lng, courses: [{ id: "crs_b1", holes: 18 }] }); // ~2.2 km north
    const rig = makeRig();
    rig.api.online = false;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0, { latitude: NASHVILLE.lat + 0.02 }) }];
    const o = await rig.run(entryOf(a), undefined, { index: indexOf(a, b) });
    expect(o).toMatchObject({ kind: "not_here", nearby: [{ courseId: "crs_b1", facilityId: "fac_b", distanceMeters: 0 }] });
    expect((o as { distanceMeters: number }).distanceMeters).toBeGreaterThan(2000);
    expect(await rig.outbox.list()).toEqual([]);
    // and on the right page the evidence names the right course and facility
    const ok = queued(await rig.run(entryOf(b), undefined, { index: indexOf(a, b) }));
    expect(ok.item.courseId).toBe("crs_b1");
    expect(payloadOf(ok).facilityId).toBe("fac_b");
  });

  it("outside the circle plus the 50 m buffer is refused; just inside it is accepted", async () => {
    const rig = makeRig();
    rig.api.online = false;
    const metersNorth = (m: number) => NASHVILLE.lat + m / 111_195; // ~111.2 km per degree of latitude
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0, { latitude: metersNorth(480) }) }]; // 400 m circle (18 holes) + 50 m = 450 m
    expect((await rig.run(E)).kind).toBe("not_here");
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0, { latitude: metersNorth(440) }) }];
    expect((await rig.run(E)).kind).toBe("queued");
  });
});

describe("the helpers the flow is built from", () => {
  it("liveCovers: a fix is covered when receivedAt <= capturedAt <= expiresAt, edges included", () => {
    const live = { receivedAt: 1000, expiresAt: 121_000 };
    expect([999, 1000, 121_000, 121_001].map((t) => liveCovers(live, t))).toEqual([false, true, true, false]);
  });

  it("fixProblem: invalid / stale / fine", () => {
    const f = (over: Partial<{ latitude: number; longitude: number; timestamp: number }> = {}) => ({ latitude: 36, longitude: -86, timestamp: NOW0, ...over });
    expect(fixProblem(f(), NOW0)).toBeNull();
    expect(fixProblem(f({ longitude: -181 }), NOW0)).toBe("invalid");
    expect(fixProblem(f({ timestamp: Number.POSITIVE_INFINITY }), NOW0)).toBe("invalid");
    expect(fixProblem(f({ timestamp: NOW0 - CHECKIN_TIMING.maxFixAgeMs }), NOW0)).toBeNull();
    expect(fixProblem(f({ timestamp: NOW0 - CHECKIN_TIMING.maxFixAgeMs - 1 }), NOW0)).toBe("stale");
    expect(fixProblem(f({ timestamp: NOW0 + CHECKIN_TIMING.maxFixAheadMs + 1 }), NOW0)).toBe("stale");
  });
});
