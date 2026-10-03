/**
 * P4.2c: what the check-in screen sends, against what the REAL server handlers did with the same shapes (`checkin_*` entries and `vectors.checkinWindow` / `vectors.localDate` of the recorded fixture,
 * produced by `scripts/record-edge-contract.rec.ts`), and against the server's own request parser:
 *  - the body the flow builds (device-shaped fix, facility-local date from the fix's own time, the challenge's token) is byte-for-byte the request the real handler answered 200 for;
 *  - the server's parser accepts it, and its size is far below the server's cap;
 *  - the challenge WINDOW (`issued_at <= capturedAt <= expires_at`) as the server enforces it, compared with the client's `liveCovers` and the challenge store;
 *  - a live challenge taken AFTER the fix does not cover it (the recorded `liveAfterFix`), which is why the flow takes it before.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseEvidenceSubmission } from "../../../supabase/functions/_shared/evidence/request-shape.ts";
import { nobleCatalogCrypto } from "../src/catalog/crypto";
import { CatalogManager } from "../src/catalog/manager";
import { MemoryCatalogCacheStore, SqliteCatalogCacheStore } from "../src/catalog/store";
import { MemoryChallengeStore, SqliteChallengeStore, type ChallengeStore } from "../src/challenges";
import { liveCovers } from "../src/checkin";
import { buildEvidenceBody, parseEvidencePayload, toJsonValue, type EvidencePayload } from "../src/evidence";
import { SERVER_MAX_BODY_BYTES } from "../src/evidence/batch";
import { entryOf, facility, makeRig, rawFix, DEVICE, SITE_VERSION } from "./support/checkin-rig";
import { RECORDED, VECTORS, recorded, recordedRequest } from "./support/edge-fixtures";
import { openNodeSqlite } from "./support/node-sqlite";
import { CatalogPublisher, FakeCdn, makeKey } from "./support/signed-catalog";

const CHI = Date.parse("2026-06-02T04:59:30.000Z"); // 23:59:30 on 2026-06-01 in America/Chicago
const FAC = facility({ id: "fac_x", lat: 36.14671234, lng: -86.78159876, courses: [{ id: "crs_x1", holes: 18 }] });
const E = entryOf(FAC);

type Wire = Record<string, unknown>;
const fixOf = (w: Wire): Wire => w["fix"] as Wire;

/** Drives the flow with the device fix of a recorded request and returns the payload it queued. */
async function queueLike(name: string, opts: { live: boolean }): Promise<{ payload: EvidencePayload; item: Awaited<ReturnType<ReturnType<typeof makeRig>["run"]>> }> {
  const want = recordedRequest<Wire>(name);
  const f = fixOf(want);
  const rig = makeRig();
  rig.api.online = opts.live;
  rig.clock.now = CHI;
  rig.api.issueAt = () => CHI - 20_000; // a live challenge issued 20 s before the fix, as recorded
  rig.api.redeemCheckinChallenge = (req) => {
    rig.api.redeemed.push(req.challengeId);
    return Promise.resolve({ jti: f["checkinTokenJti"] as string, expiresAt: new Date(CHI + 900_000).toISOString(), attestationGrade: "unattestable" });
  };
  if (!opts.live) await rig.seedPool(1, CHI - 3600_000);
  rig.location.fixes = [{ ok: true, fix: rawFix(f["capturedAt"] as number, { latitude: f["lat"] as number, longitude: f["lng"] as number, accuracyMeters: f["accuracyMeters"] as number }) }];
  const item = await rig.run(E, { newFixId: () => f["fixId"] as string });
  if (item.kind !== "queued") throw new Error(`not queued: ${item.kind}`);
  const p = parseEvidencePayload(item.item.payload);
  if (!p.ok) throw new Error(p.message);
  return { payload: p.payload, item };
}

describe("the body the check-in builds is the request the REAL handler accepted", () => {
  it("LIVE challenge first: byte-for-byte `checkin_screen_live_first_200` (device-shaped fix, the facility-local date 2026-06-01 although UTC is 06-02, the redeemed jti)", async () => {
    const want = recordedRequest<Wire>("checkin_screen_live_first_200");
    const { payload, item } = await queueLike("checkin_screen_live_first_200", { live: true });
    const built = buildEvidenceBody({ courseId: "crs_x1", catalogVersion: SITE_VERSION }, payload);
    expect(built).toEqual({ ok: true, body: want });
    expect(recorded("checkin_screen_live_first_200").status).toBe(200);
    expect(JSON.parse(recorded("checkin_screen_live_first_200").body).data).toMatchObject({ status: "accepted", replay: false });
    expect((item as { challenge: string }).challenge).toBe("live");
  });

  it("PREFETCHED challenge: the item holds the challenge (consumed locally); once redeemed at send time its body is byte-for-byte `checkin_screen_prefetched_200`", async () => {
    const want = recordedRequest<Wire>("checkin_screen_prefetched_200");
    const { payload } = await queueLike("checkin_screen_prefetched_200", { live: false });
    const fixId = fixOf(want)["fixId"] as string;
    expect(payload.challenges[fixId]).toMatchObject({ state: "held", kind: "prefetched" });
    // what the send step does: redeem, then carry the jti
    const redeemed: EvidencePayload = { ...payload, challenges: { [fixId]: { state: "redeemed", challengeId: "c", kind: "prefetched", jti: fixOf(want)["checkinTokenJti"] as string, grade: "unattestable" } } };
    expect(buildEvidenceBody({ courseId: "crs_x1", catalogVersion: SITE_VERSION }, redeemed)).toEqual({ ok: true, body: want });
    expect(recorded("checkin_screen_prefetched_200").status).toBe(200);
  });

  it("the facility-local date rule: the same fix labelled with its UTC date is the recorded 422 local_date_mismatch, and the client never builds that label", async () => {
    const bad = recordedRequest<Wire>("checkin_422_local_date_utc");
    expect(recorded("checkin_422_local_date_utc").status).toBe(422);
    expect(JSON.parse(recorded("checkin_422_local_date_utc").body).error).toMatchObject({ code: "local_date_mismatch" });
    expect(bad["localDate"]).toBe("2026-06-02");
    const good = recordedRequest<Wire>("checkin_screen_prefetched_200");
    expect(good["localDate"]).toBe("2026-06-01");
    expect(fixOf(good)["capturedAt"]).toBe(fixOf(bad)["capturedAt"]); // the same instant
    const { payload } = await queueLike("checkin_screen_prefetched_200", { live: false });
    expect(payload.localDate).toBe("2026-06-01");
  });

  it.each(["checkin_screen_live_first_200", "checkin_screen_prefetched_200", "checkin_screen_live_after_fix_200"])("%s: the server's own request parser accepts it, and it is far below the size cap", (name) => {
    const body = recordedRequest<Wire>(name);
    expect(parseEvidenceSubmission(body).ok).toBe(true);
    expect(new TextEncoder().encode(JSON.stringify(body)).length).toBeLessThan(2_000);
    expect(new TextEncoder().encode(JSON.stringify(body)).length).toBeLessThan(SERVER_MAX_BODY_BYTES);
  });

  it("every field the client builds is in the server's whitelist: an extra key is refused by the server's parser (the 'unknown key' guard is real), and the client adds none", async () => {
    const { payload } = await queueLike("checkin_screen_live_first_200", { live: true });
    const built = buildEvidenceBody({ courseId: "crs_x1", catalogVersion: SITE_VERSION }, payload);
    if (!built.ok) throw new Error(built.message);
    expect(parseEvidenceSubmission(built.body).ok).toBe(true);
    expect(parseEvidenceSubmission({ ...built.body, attestationGrade: "attested" }).ok).toBe(false);
    expect(Object.keys(fixOf(built.body)).sort()).toEqual(["accuracyMeters", "capturedAt", "checkinTokenJti", "fixId", "foreground", "fromApp", "lat", "lng", "simulated"]);
  });

  it("the fixture's device id is the rig's (the real handler checked the body's deviceId against the account's device)", () => {
    expect(recordedRequest<Wire>("checkin_screen_live_first_200")["deviceId"]).toBe(DEVICE);
    expect(recordedRequest<Wire>("checkin_screen_live_first_200")["catalogVersion"]).toBe(SITE_VERSION);
  });

  it("the check-in screen's fixtures are all in the file (the recorder was run), and the error one is the only non-2xx", () => {
    const names = Object.keys(RECORDED).filter((k) => k.startsWith("checkin_"));
    expect(names.sort()).toEqual(["checkin_422_local_date_utc", "checkin_screen_live_after_fix_200", "checkin_screen_live_first_200", "checkin_screen_prefetched_200"]);
    expect(names.filter((n) => RECORDED[n]!.status >= 300)).toEqual(["checkin_422_local_date_utc"]);
  });
});

describe("the server's challenge window, as recorded through the real handler", () => {
  const W = VECTORS.checkinWindow;

  it("what the recording saw: prefetched and live-first fixes consumed their token; a live challenge issued AFTER the fix did not", () => {
    expect(W.prefetchedCovered.consumed).toBe(true);
    expect(W.liveFirst.consumed).toBe(true);
    expect(W.liveAfterFix.consumed).toBe(false);
  });

  it("`liveCovers` agrees with the server at every recorded edge of a LIVE challenge (120 s): 1 ms before the issue no, the issue yes, the expiry yes, 1 ms after no", () => {
    const live = W.edges.filter((e) => e.kind === "live");
    expect(live.map((e) => e.offsetFromIssueMs)).toEqual([-1, 0, 120_000, 120_001]);
    for (const e of live) expect(liveCovers({ receivedAt: e.issuedAt, expiresAt: e.expiresAt }, e.issuedAt + e.offsetFromIssueMs), `${e.offsetFromIssueMs}`).toBe(e.consumed);
  });

  it("a live challenge issued after the fix (the recorded `liveAfterFix`) never covers it, and the flow therefore takes the challenge BEFORE the fix", () => {
    // issued 2 s after the capture: the device receives it after that, so receivedAt > capturedAt
    expect(liveCovers({ receivedAt: CHI + 2_000, expiresAt: CHI + 122_000 }, CHI)).toBe(false);
    expect(W.liveAfterFix.consumed).toBe(false);
  });

  const stores: [string, () => Promise<ChallengeStore>][] = [
    ["memory", async () => new MemoryChallengeStore()],
    ["SQLite", async () => new SqliteChallengeStore(await openNodeSqlite())],
  ];
  it.each(stores)("the prefetched pool (%s) never uses a challenge the server would refuse, and uses one exactly where the server accepts (issue edge)", async (_n, make) => {
    for (const e of W.edges.filter((x) => x.kind === "prefetched")) {
      const s = await make();
      await s.insertMany("user-a", DEVICE, [{ id: "p1", nonce: "bm9uY2U", kind: "prefetched", facilityId: null, expiresAt: e.expiresAt }], e.issuedAt);
      const got = await s.consumeOne("user-a", DEVICE, e.issuedAt + e.offsetFromIssueMs, e.issuedAt + 1);
      if (got !== null) expect(e.consumed, `the client used a challenge the server refuses at ${e.offsetFromIssueMs}`).toBe(true);
      if (e.offsetFromIssueMs === -1) expect(got).toBeNull();
      if (e.offsetFromIssueMs === 0) expect(got).not.toBeNull();
      // at the very end of the 24 h the server still accepts but the client keeps a minute in hand: stricter, never looser
      if (e.offsetFromIssueMs === e.expiresAt - e.issuedAt) expect(got).toBeNull();
    }
  });
});

describe("the cached manifest signature a check-in may carry (catalog newer than the server's import)", () => {
  const key = makeKey("k-prod-a");
  const pub = new CatalogPublisher();
  let cat: Awaited<ReturnType<CatalogPublisher["emit"]>>;
  beforeAll(async () => {
    cat = await pub.emit({ version: "20260101-aaaaaaa", generatedAt: "2026-01-01T00:00:00.000Z", key, trailName: "T" });
  });
  afterAll(async () => {
    await pub.dispose();
  });

  it.each([
    ["memory", async () => new MemoryCatalogCacheStore()],
    ["SQLite", async () => new SqliteCatalogCacheStore(await openNodeSqlite())],
  ] as const)("(%s) the real manifest.sig.json of the cached catalog is returned in the evidence shape, only for ITS version", async (_n, make) => {
    const cdn = new FakeCdn();
    cdn.serve(cat);
    const m = new CatalogManager({ baseUrl: cdn.base, store: await make(), crypto: nobleCatalogCrypto, trustedKeys: [key.trusted], appVersion: "1.0.0", supportedContractMajor: 0, fetchBytes: cdn.fetchBytes, now: () => new Date("2026-02-15T12:00:00.000Z") });
    expect(await m.cachedManifestSig("20260101-aaaaaaa")).toBeNull(); // nothing cached yet
    expect((await m.refresh()).kind).toBe("updated");
    const sig = await m.cachedManifestSig("20260101-aaaaaaa");
    expect(sig).toMatchObject({ catalogVersion: "20260101-aaaaaaa", kid: "k-prod-a", contractVersion: expect.any(Number), manifestSha: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(Object.keys(sig!).sort()).toEqual(["catalogVersion", "contractVersion", "kid", "manifestSha", "sig"]);
    expect(await m.cachedManifestSig("20260201-bbbbbbb")).toBeNull();
    // and it is exactly what a payload may carry: the strict payload schema takes it
    const payload = {
      v: 1, origin: "live", deviceId: DEVICE, facilityId: "fac_x", localDate: "2026-06-01", manifestSig: sig,
      submission: { source: "foreground_checkin", fix: { fixId: "f1", lat: 1, lng: 1, accuracyMeters: 5, capturedAt: CHI, simulated: false, foreground: true, fromApp: true } },
      challenges: { f1: { state: "none", reason: "none_available" } },
    };
    expect(parseEvidencePayload(toJsonValue(payload as unknown as EvidencePayload)).ok).toBe(true);
  });
});
