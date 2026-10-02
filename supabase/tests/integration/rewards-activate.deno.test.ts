// supabase/tests/integration/rewards-activate.deno.test.ts
//
// P3f: `POST /v1/rewards/{id}/activate` — the REAL handler
// (_shared/rewards/activate-handler.ts) through the REAL `withOwnership` and
// the REAL `Repo#rewards` (privileged.ts), against the real SQL functions
// (0027) on the harness cluster tools/db/test.sh builds, in BOTH harness
// modes. Same discipline as handlers.deno.test.ts / me-handlers.deno.test.ts.
//
// ⚠ Only the VENDOR side is scripted. There are no Apple/Google credentials or
// network route in this environment, so DeviceCheck / Play Integrity are fake
// ports here (call-counting, scriptable); the one piece of attestation crypto
// that needs no vendor — App Attest assertion verification — runs for real
// against assertions this suite builds with Web Crypto (self-consistency, not
// conformance with a real iOS device).
//
// P3 AT (9), AT (5) and the §4.7.7 rewards-activate cells are mapped
// test-by-test in each test's name.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, freshUuid, insertCatalogVersion, makeActor, siteVersionFor, FAC_X, CRS_X1, NASHVILLE } from "./_helpers.ts";
import { hitRateLimitForActor, withOwnership } from "../../functions/_shared/privileged.ts";
import { enforceActivationRateLimits, handleActivation, type ActivationDeps } from "../../functions/_shared/rewards/activate-handler.ts";
import { computeRequestBinding, toBase64Url, toHex } from "../../functions/_shared/rewards/binding.ts";
import { verifyAppAttestAssertion, verifyP256WebCrypto } from "../../functions/_shared/rewards/app-attest.ts";
import type { ActivationRequest } from "../../functions/_shared/rewards/request-shape.ts";
import {
  type AndroidPort,
  type AssertionResult,
  type AttestationPorts,
  type DeviceBits,
  type IntegrityResult,
  type IosPort,
  VendorUnavailableError,
} from "../../functions/_shared/rewards/types.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleEvidenceIntake } from "../../functions/_shared/evidence/handler.ts";
import { handleMeDelete } from "../../functions/_shared/me/delete-handler.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import type { Repo } from "../../functions/_shared/types.ts";
import { buildAssertion, generateP256, sha256, toB64 } from "../unit/rewards-test-crypto.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const ADMIN = "00000000-0000-0000-0000-4000000000d0"; // seeded by helpers.sql
const CLEAR: DeviceBits = { bit0: false, bit1: false, lastUpdateMonth: null };
const BIT0: DeviceBits = { bit0: true, bit1: false, lastUpdateMonth: "2026-02" };
const BIT1: DeviceBits = { bit0: false, bit1: true, lastUpdateMonth: "2026-04" };

const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));

// ---------------------------------------------------------------------------
// Scripted vendor ports (call-counting).
// ---------------------------------------------------------------------------
interface SpyIos extends IosPort {
  calls: { verify: number; readBits: number; setBit0: number };
}
function iosPort(opts: { bits?: DeviceBits | Error; assertion?: AssertionResult | ((input: Parameters<IosPort["verifyAssertion"]>[0]) => AssertionResult); setBit0Error?: Error } = {}): SpyIos {
  const calls = { verify: 0, readBits: 0, setBit0: 0 };
  return {
    calls,
    async verifyAssertion(input) {
      calls.verify++;
      const a = opts.assertion;
      if (typeof a === "function") return a(input);
      return a ?? { ok: true, counter: input.device.attestCounter + 1 };
    },
    async readBits() {
      calls.readBits++;
      const b = opts.bits ?? CLEAR;
      if (b instanceof Error) throw b;
      return b;
    },
    async setBit0() {
      calls.setBit0++;
      if (opts.setBit0Error) throw opts.setBit0Error;
    },
  };
}
interface SpyAndroid extends AndroidPort {
  calls: { verify: number; setBit0: number };
  lastRequestHash: string | null;
}
function androidPort(result: IntegrityResult): SpyAndroid {
  const port: SpyAndroid = {
    calls: { verify: 0, setBit0: 0 },
    lastRequestHash: null,
    async verifyIntegrity(input) {
      port.calls.verify++;
      port.lastRequestHash = input.expectedRequestHash;
      return result;
    },
    async setBit0() {
      port.calls.setBit0++;
    },
  };
  return port;
}
const deps = (p: Partial<AttestationPorts>): ActivationDeps => ({ ports: { ios: null, android: null, ...p }, sha256 });

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
async function freshUser(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `rw-${label}-${uid.slice(0, 8)}`);
  return { uid, actor: makeActor(uid) };
}
type User = Awaited<ReturnType<typeof freshUser>>;

async function newDevice(u: User, platform: "ios" | "android" = "ios"): Promise<string> {
  return withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), platform)).id);
}

async function newOffer(opts: { faceValue?: number; cap?: number; status?: string } = {}): Promise<string> {
  const id = freshUuid();
  await adminSql()`set role service_role`;
  await adminSql()`
    insert into app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
    values (${id}, 'trl_t', ${FAC_X}, '{}'::jsonb, 'operator', ${opts.cap ?? 100}, ${opts.faceValue ?? 10}, current_date, current_date + 30, ${opts.status ?? "live"})`;
  return id;
}

async function newCode(u: User, o: { offerId?: string; state?: string; restsOnUnattestable?: boolean; expiresInDays?: number | null; earnedDaysAgo?: number; deviceId?: string; faceValue?: number } = {}): Promise<{ id: string; offerId: string }> {
  const offerId = o.offerId ?? (await newOffer({ faceValue: o.faceValue }));
  const id = freshUuid();
  const days = o.expiresInDays === undefined ? 20 : o.expiresInDays;
  await adminSql()`
    insert into app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at, rests_on_unattestable, activated_device_id, activated_at)
    values (${id}, ${offerId}, ${u.uid}, ${FAC_X}, ${o.state ?? "earned"}, now() - make_interval(days => ${o.earnedDaysAgo ?? 10}),
            ${days === null ? null : adminSql()`now() + make_interval(days => ${days})`}, ${o.restsOnUnattestable ?? false},
            ${o.deviceId ?? null}, ${o.deviceId ? adminSql()`now()` : null})`;
  return { id, offerId };
}

const TRAILS = ["trl_t", "trl_u", "trl_v"];
async function newEntitlement(u: User, trail: string, o: { state?: string; restsOnUnattestable?: boolean; deviceId?: string } = {}): Promise<string> {
  assert(TRAILS.includes(trail));
  const id = freshUuid();
  await adminSql()`
    insert into app.entitlement (id, user_id, kind, trail_id, state, rests_on_unattestable, activated_device_id, activated_at)
    values (${id}, ${u.uid}, 'special_marker', ${trail}, ${o.state ?? "earned"}, ${o.restsOnUnattestable ?? false}, ${o.deviceId ?? null}, ${o.deviceId ? adminSql()`now()` : null})`;
  return id;
}

/** A prior, activated reward + ledger row: what makes an account a repeat user. */
async function priorReward(u: User, deviceId: string): Promise<string> {
  const { id } = await newCode(u, { state: "issued", deviceId });
  await adminSql()`insert into app.device_reward_ledger (device_id, user_id, reward_kind, reward_id, devicecheck_token_hash) values (${deviceId}, ${u.uid}, 'offer', ${id}, 'prior')`;
  return id;
}

async function issueLive(u: User, deviceId: string): Promise<{ challengeId: string; nonce: string; nonceBytes: Uint8Array }> {
  const issued = await withOwnership(u.actor, (repo: Repo) => handleChallengeRequest({ deviceId }, repo, randomBytes, digestHex));
  const c = issued[0]!;
  const b64 = c.nonce.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
  return { challengeId: c.id, nonce: c.nonce, nonceBytes: Uint8Array.from(bin, (ch) => ch.charCodeAt(0)) };
}

async function iosReq(u: User, deviceId: string, over: Partial<{ challenge: { challengeId: string; nonce: string } }> = {}): Promise<ActivationRequest> {
  const ch = over.challenge ?? (await issueLive(u, deviceId));
  return {
    deviceId,
    platform: "ios",
    challengeId: ch.challengeId,
    nonce: ch.nonce,
    attestation: { kind: "ios", keyId: "S0VZ", assertion: "QVNTRVJU", deviceCheckToken: "REVWSUNFVE9LRU4=" },
  };
}

function activate(u: User, rewardId: string, req: ActivationRequest, d: ActivationDeps) {
  return withOwnership(u.actor, (repo: Repo) => handleActivation(rewardId, req, repo, d));
}

async function codeRow(id: string) {
  const rows = await adminSql()`select state, activated_device_id, devicecheck_token_hash, activated_at, expires_at, expiry_paused_at, reserved_amount, offer_id from app.offer_code where id = ${id}`;
  return rows[0]!;
}
async function entRow(id: string) {
  const rows = await adminSql()`select state, activated_device_id, devicecheck_token_hash, activated_at from app.entitlement where id = ${id}`;
  return rows[0]!;
}
async function ledgerFor(rewardId: string) {
  return adminSql()`select device_id, user_id, reward_kind::text as kind, devicecheck_token_hash from app.device_reward_ledger where reward_id = ${rewardId} order by at`;
}
async function signals(u: User, kind?: string) {
  return adminSql()`select kind, detail, cleared_at from app.fraud_signal where user_id = ${u.uid} ${kind ? adminSql()`and kind = ${kind}` : adminSql()``} order by created_at`;
}
async function offerReserved(offerId: string): Promise<number> {
  const rows = await adminSql()`select budget_reserved, budget_used from app.offer where id = ${offerId}`;
  return Number(rows[0]!.budget_reserved);
}
async function codeOf(p: Promise<unknown>): Promise<{ status: number; code: string } | null> {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, code: e.code };
    throw e;
  }
}

// ===========================================================================
// §4.7.7 cell: player A activates B's offer code or entitlement -> 404
// ===========================================================================
Deno.test("§4.7.7: player A activating player B's offer code or entitlement is a 404 (never 403); B's reward is untouched; no vendor is called", DT, async () => {
  const a = await freshUser("own-a");
  const b = await freshUser("own-b");
  const aDevice = await newDevice(a);
  const code = await newCode(b);
  const ent = await newEntitlement(b, "trl_t");
  for (const id of [code.id, ent, freshUuid(), "not-a-uuid"]) {
    const ios = iosPort();
    const out = await codeOf(activate(a, id, await iosReq(a, aDevice), deps({ ios })));
    assertEquals(out, { status: 404, code: "not_found" }, `id ${id}`);
    assertEquals(ios.calls, { verify: 0, readBits: 0, setBit0: 0 });
  }
  assertEquals((await codeRow(code.id)).state, "earned");
  assertEquals((await entRow(ent)).state, "earned");
  assertEquals((await codeRow(code.id)).activated_device_id, null);
  assertEquals((await ledgerFor(code.id)).length, 0);
  assertEquals((await signals(a)).length, 0);
});

Deno.test("§4.7.7: the app-review demo account is refused (403) before any reward is read, and nothing changes", DT, async () => {
  const demo = await freshUser("demo");
  await adminSql()`set role service_role`;
  await adminSql()`insert into app.app_review_demo_account (user_id) values (${demo.uid})`;
  const dev = await newDevice(demo);
  const code = await newCode(demo);
  for (const id of [code.id, freshUuid()]) {
    const ios = iosPort();
    assertEquals(await codeOf(activate(demo, id, await iosReq(demo, dev), deps({ ios }))), { status: 403, code: "forbidden" });
    assertEquals(ios.calls, { verify: 0, readBits: 0, setBit0: 0 });
  }
  assertEquals((await codeRow(code.id)).state, "earned");
});

Deno.test("§4.7.7: an offer code is the caller's own: B can activate their own, and it works through the same route", DT, async () => {
  const b = await freshUser("own-b2");
  const dev = await newDevice(b);
  const code = await newCode(b);
  const out = await activate(b, code.id, await iosReq(b, dev), deps({ ios: iosPort({ bits: CLEAR }) }));
  assertEquals(out.state, "issued");
});

// ===========================================================================
// AT (9): every §7.5 DeviceCheck / activation fixture, against real SQL
// ===========================================================================
Deno.test("AT 9: same account, second offer on the same device -> issued (bit0 set, prior reward on the ledger)", DT, async () => {
  const u = await freshUser("second-offer");
  const dev = await newDevice(u);
  await priorReward(u, dev);
  const code = await newCode(u);
  const ios = iosPort({ bits: BIT0 });
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios }));
  assertEquals(out, { id: code.id, kind: "offer_code", state: "issued", held: false, replay: false });
  const row = await codeRow(code.id);
  assertEquals(row.state, "issued");
  assertEquals(row.activated_device_id, dev);
  assert(row.devicecheck_token_hash, "the DeviceCheck token hash is recorded");
  assertEquals(row.reserved_amount, "0.00");
  assertEquals((await ledgerFor(code.id)).length, 1);
  assertEquals((await signals(u)).length, 0);
  assertEquals(ios.calls.setBit0, 0);
});

Deno.test("AT 9: same account, special marker on a second trail -> issued (redeemable)", DT, async () => {
  const u = await freshUser("second-trail");
  const dev = await newDevice(u);
  const first = await newEntitlement(u, "trl_t", { state: "redeemable", deviceId: dev });
  await adminSql()`insert into app.device_reward_ledger (device_id, user_id, reward_kind, reward_id) values (${dev}, ${u.uid}, 'special_marker', ${first})`;
  const second = await newEntitlement(u, "trl_u");
  const out = await activate(u, second, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out, { id: second, kind: "entitlement", state: "redeemable", held: false, replay: false });
  assertEquals((await entRow(second)).activated_device_id, dev);
  assertEquals((await ledgerFor(second))[0]?.kind, "special_marker");
});

Deno.test("AT 9: same account after REINSTALL -> issued (new device id and key; DeviceCheck bit0 persists; the ledger remembers the account)", DT, async () => {
  const u = await freshUser("reinstall");
  const oldInstall = await newDevice(u);
  await priorReward(u, oldInstall);
  const newInstall = await newDevice(u);
  const code = await newCode(u);
  const out = await activate(u, code.id, await iosReq(u, newInstall), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out.state, "issued");
  assertEquals((await ledgerFor(code.id))[0]?.device_id, newInstall);
});

Deno.test("AT 9: the account's OWN issued reward re-activated on a reinstalled device is itself the prior reward -> issued", DT, async () => {
  const u = await freshUser("reinstall-same-reward");
  const oldInstall = await newDevice(u);
  const code = await newCode(u);
  assertEquals((await activate(u, code.id, await iosReq(u, oldInstall), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "issued");
  const newInstall = await newDevice(u);
  const out = await activate(u, code.id, await iosReq(u, newInstall), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out.state, "issued");
  assertEquals((await signals(u)).length, 0);
});

Deno.test("AT 9: a NEW account on a bit0 device -> held_review (not refused) + fraud_signal(multi_account_device); the budget is reserved", DT, async () => {
  const u = await freshUser("new-acct-bit0");
  const dev = await newDevice(u);
  const code = await newCode(u, { faceValue: 12 });
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out, { id: code.id, kind: "offer_code", state: "held_review", held: true, replay: false });
  const row = await codeRow(code.id);
  assertEquals(row.state, "held_review");
  assertEquals(row.reserved_amount, "12.00");
  assert(row.expiry_paused_at, "the expiry clock pauses while held");
  assertEquals(await offerReserved(row.offer_id as string), 12);
  assertEquals((await ledgerFor(code.id)).length, 0);
  const sigs = await signals(u, "multi_account_device");
  assertEquals(sigs.length, 1);
  assertEquals((sigs[0]!.detail as Record<string, unknown>).rewardId, code.id);
});

Deno.test("AT 9: a HELD reward is not a received reward: an account whose only other reward is held is still a first-time user on a bit0 device (row 4)", DT, async () => {
  const u = await freshUser("held-not-prior");
  const dev = await newDevice(u);
  await newCode(u, { state: "held_review" });
  await newEntitlement(u, "trl_t", { state: "held_review" });
  const code = await newCode(u);
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(u, "multi_account_device")).length, 1);
});

Deno.test("AT 9: ANY account on a bit1 device -> held_review + a high-priority fraud_signal (with or without a prior reward)", DT, async () => {
  for (const hasPrior of [false, true]) {
    const u = await freshUser(`bit1-${hasPrior}`);
    const dev = await newDevice(u);
    if (hasPrior) await priorReward(u, dev);
    const code = await newCode(u);
    const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT1 }) }));
    assertEquals(out.state, "held_review", `prior=${hasPrior}`);
    const sigs = await signals(u, "flagged_device_activation");
    assertEquals(sigs.length, 1);
    const d = sigs[0]!.detail as Record<string, unknown>;
    assertEquals(d.priority, "high");
    assertEquals(d.deviceCheckLastUpdateMonth, "2026-04");
  }
});

Deno.test("AT 9: a reward earned by a server-side RE-SCORE reads no bits and sets no device state until activation", DT, async () => {
  const u = await freshUser("rescore");
  const dev = await newDevice(u);
  const code = await newCode(u);
  const today = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  // A catalog version inside the accepted skew window, whatever other test files in this live run
  // have inserted before this one (same approach as me-handlers.deno.test.ts).
  await adminSql()`set role service_role`;
  const maxVersionRows = await adminSql()`select coalesce(max(version), 0)::int as m from app.catalog_version`;
  const freshCatalogVersion = Number(maxVersionRows[0]?.m ?? 0) + 1000;
  await insertCatalogVersion(freshCatalogVersion, new Date(), `kid-rw-${freshUuid()}`);
  // A real score-and-upsert pass for this user (the same code path a re-score takes).
  const result = await withOwnership(u.actor, (repo: Repo) =>
    handleEvidenceIntake(
      {
        source: "foreground_checkin",
        deviceId: dev,
        facilityId: FAC_X,
        courseId: CRS_X1,
        localDate: today,
        catalogVersion: siteVersionFor(freshCatalogVersion),
        fix: { fixId: `fix_${freshUuid()}`, lat: NASHVILLE.lat, lng: NASHVILLE.lng, accuracyMeters: 10, capturedAt: Date.now(), simulated: false, foreground: true, fromApp: true },
      },
      repo,
    ),
  );
  assertEquals(result.status, "accepted");
  // The earned reward is exactly as it was: no device, no token hash, no ledger row, no verdict recorded.
  const row = await codeRow(code.id);
  assertEquals([row.state, row.activated_device_id, row.devicecheck_token_hash, row.activated_at], ["earned", null, null, null]);
  assertEquals((await ledgerFor(code.id)).length, 0);
  const dRows = await adminSql()`select devicecheck_token_hash, integrity_last from app.device where id = ${dev}`;
  assertEquals([dRows[0]!.devicecheck_token_hash, dRows[0]!.integrity_last], [null, null]);
  // ...and the table's bits are read exactly once, by the activation itself.
  const ios = iosPort({ bits: CLEAR });
  assertEquals(ios.calls.readBits, 0);
  await activate(u, code.id, await iosReq(u, dev), deps({ ios }));
  assertEquals(ios.calls.readBits, 1);
});

Deno.test("AT 9: a redemption QR from the account's SECOND device re-runs the table -> issued; a flagged second device sends it back to held_review", DT, async () => {
  const u = await freshUser("second-device");
  const d1 = await newDevice(u);
  const d2 = await newDevice(u);
  const code = await newCode(u);
  await activate(u, code.id, await iosReq(u, d1), deps({ ios: iosPort({ bits: CLEAR }) }));
  assertEquals((await codeRow(code.id)).state, "issued");

  const ios2 = iosPort({ bits: CLEAR });
  const out = await activate(u, code.id, await iosReq(u, d2), deps({ ios: ios2 }));
  assertEquals(out, { id: code.id, kind: "offer_code", state: "issued", held: false, replay: false }); // not a no-op
  assertEquals(ios2.calls.readBits, 1, "the table ran: this device's bits were read");
  assertEquals((await ledgerFor(code.id)).map((r) => r.device_id).sort(), [d1, d2].sort());
  assertEquals((await codeRow(code.id)).activated_device_id, d1, "the first activation's device is kept");

  const d3 = await newDevice(u);
  const out3 = await activate(u, code.id, await iosReq(u, d3), deps({ ios: iosPort({ bits: BIT1 }) }));
  assertEquals(out3.state, "held_review");
  const row = await codeRow(code.id);
  assertEquals(row.state, "held_review");
  assert(row.expiry_paused_at);
});

Deno.test("AT 9: a held code whose offer ends during review is honoured after approval, with its budget reserved and its FULL validity counted from approval", DT, async () => {
  const u = await freshUser("offer-ends");
  const dev = await newDevice(u);
  const code = await newCode(u, { faceValue: 15, expiresInDays: 20, earnedDaysAgo: 10 }); // a 30-day validity
  await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT1 }) }));
  const held = await codeRow(code.id);
  assertEquals(held.state, "held_review");
  assertEquals(await offerReserved(held.offer_id as string), 15);

  // The offer ENDS during review.
  await adminSql()`update app.offer set status = 'ended', valid_to = current_date - 1 where id = ${held.offer_id}`;
  const approved = await adminSql()`select app.resolve_held_offer_code(${code.id}, true, ${ADMIN}) as state`;
  assertEquals(approved[0]!.state, "issued");
  const after = await adminSql()`
    select state, expiry_paused_at, reserved_amount, (expires_at - now()) as remaining from app.offer_code where id = ${code.id}`;
  assertEquals(after[0]!.state, "issued");
  assertEquals(after[0]!.expiry_paused_at, null);
  assertEquals(after[0]!.reserved_amount, "15.00", "the reservation is kept");
  assertEquals(await offerReserved(held.offer_id as string), 15, "offer.budget_reserved still carries it — the reservation pays for the ended offer's code");
  // 30-day validity from the approval date (not the 20 days that were left when it was held).
  const secs = await adminSql()`select extract(epoch from (expires_at - now())) as s from app.offer_code where id = ${code.id}`;
  assert(Math.abs(Number(secs[0]!.s) - 30 * 86400) < 5, `expected ~30 days of validity from approval, got ${secs[0]!.s}s`);
  assertEquals((await ledgerFor(code.id)).length, 1, "approval records the activation on the ledger");
  // and the reserved budget is consumed at redemption.
  await adminSql()`select app.consume_offer_budget(${held.offer_id}, 15)`;
  const o = await adminSql()`select budget_used, budget_reserved from app.offer where id = ${held.offer_id}`;
  assertEquals([o[0]!.budget_used, o[0]!.budget_reserved], ["15.00", "0.00"]);
});

Deno.test("AT 9: reject releases the reservation", DT, async () => {
  const u = await freshUser("reject");
  const dev = await newDevice(u);
  const code = await newCode(u, { faceValue: 8 });
  await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT1 }) }));
  const offerId = (await codeRow(code.id)).offer_id as string;
  assertEquals(await offerReserved(offerId), 8);
  await adminSql()`select app.resolve_held_offer_code(${code.id}, false, ${ADMIN})`;
  assertEquals(await offerReserved(offerId), 0);
  assertEquals((await codeRow(code.id)).state, "void");
});

Deno.test("account deletion (AT 6) hands a held code's budget reservation back, in the delete transaction", DT, async () => {
  const u = await freshUser("delete-held");
  const dev = await newDevice(u);
  const code = await newCode(u, { faceValue: 9 });
  await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT1 }) }));
  const offerId = (await codeRow(code.id)).offer_id as string;
  assertEquals(await offerReserved(offerId), 9);
  await withOwnership(u.actor, (repo: Repo) => handleMeDelete(repo));
  assertEquals((await adminSql()`select count(*)::int as n from app.offer_code where id = ${code.id}`)[0]!.n, 0, "the code is gone");
  assertEquals(await offerReserved(offerId), 0, "...and its reservation was returned, not leaked");
  // a retried deletion is a no-op
  await withOwnership(u.actor, (repo: Repo) => handleMeDelete(repo));
  assertEquals(await offerReserved(offerId), 0);
});

// P3e's per-play scoring lock (Repo#play.lockForScoring = advisory namespace 1 on (user, course, date))
// is taken by every scorer BEFORE it reads or writes the play; activation takes the reward ROW lock,
// then advisory namespaces 4/5 (per user) and, when holding, the offer row. The play hold cascade
// (0017) then updates the very offer_code rows activation locks. Different lock families, no
// shared acquisition cycle — proved here by racing the two, in both orders, and requiring that
// neither deadlocks nor 503s and that the invariant (a held play only backs held rewards) holds.
async function playBackedCode(u: User, dev: string, day: number): Promise<{ codeId: string; playId: string; courseId: string; playDate: string }> {
  const code = await newCode(u);
  const playDate = new Date(Date.now() - (60 + day) * 86400_000).toISOString().slice(0, 10);
  const playId = await withOwnership(u.actor, async (repo: Repo) =>
    (await repo.play.upsertFromScore({
      courseId: CRS_X1, facilityId: FAC_X, playDate, courseDisambiguatedBy: null,
      scoreBadge: 0.6, scoreMonetary: 0.9, hardSignal: true, presenceSignal: true, money: true, heldReview: false,
      policyVersion: "v1", inputDigest: "d".repeat(64), evidenceIds: [],
    })).id);
  await adminSql()`update app.offer_code set play_id = ${playId} where id = ${code.id}`;
  return { codeId: code.id, playId, courseId: CRS_X1, playDate };
}
async function rescoreHeld(u: User, p: { courseId: string; playDate: string }): Promise<void> {
  await withOwnership(u.actor, async (repo: Repo) => {
    await repo.play.lockForScoring(p.courseId, p.playDate); // what live intake / finalize / re-score do first
    await repo.play.upsertFromScore({
      courseId: p.courseId, facilityId: FAC_X, playDate: p.playDate, courseDisambiguatedBy: null,
      scoreBadge: 0.6, scoreMonetary: 0.9, hardSignal: true, presenceSignal: true, money: true, heldReview: true,
      policyVersion: "v1", inputDigest: "e".repeat(64), evidenceIds: [],
    });
  });
}

Deno.test("P3e interplay: a re-score that HOLDS the play, racing an activation of its reward, neither deadlocks nor 503s, in either order, and ends held_review", DT, async () => {
  for (const order of ["activate-first", "rescore-first", "simultaneous"] as const) {
    const u = await freshUser(`race-scoring-${order}`);
    const dev = await newDevice(u);
    const p = await playBackedCode(u, dev, order.length);
    const req = await iosReq(u, dev);
    const act = () => activate(u, p.codeId, req, deps({ ios: iosPort({ bits: CLEAR }) }));
    const resc = () => rescoreHeld(u, p);
    const t0 = Date.now();
    let results: PromiseSettledResult<unknown>[];
    if (order === "activate-first") {
      const a = act();
      await new Promise((r) => setTimeout(r, 15));
      results = await Promise.allSettled([a, resc()]);
    } else if (order === "rescore-first") {
      const r = resc();
      await new Promise((r2) => setTimeout(r2, 15));
      results = await Promise.allSettled([r, act()]);
    } else {
      results = await Promise.allSettled([act(), resc()]);
    }
    assert(Date.now() - t0 < 4500, `${order}: took ${Date.now() - t0}ms (a lock wait would run to lock_timeout 5s)`);
    for (const r of results) assertEquals(r.status, "fulfilled", `${order}: ${JSON.stringify(r)}`);
    const row = await codeRow(p.codeId);
    assertEquals(row.state, "held_review", `${order}: a held play can only back a held reward`);
    const play = await adminSql()`select held_review from app.play where id = ${p.playId}`;
    assertEquals(play[0]!.held_review, true);
  }
});

Deno.test("P3e interplay: two scorers and an activation on the same account's different plays/rewards run together without deadlock", DT, async () => {
  const u = await freshUser("race-scoring-many");
  const dev = await newDevice(u);
  const a = await playBackedCode(u, dev, 1);
  const b = await playBackedCode(u, dev, 2);
  const free = await newCode(u);
  const outs = await Promise.allSettled([
    rescoreHeld(u, a),
    rescoreHeld(u, b),
    activate(u, free.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) })),
    activate(u, a.codeId, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) })),
  ]);
  for (const r of outs) assertEquals(r.status, "fulfilled", JSON.stringify(r));
  assertEquals((await codeRow(a.codeId)).state, "held_review");
  assertEquals((await codeRow(b.codeId)).state, "held_review");
  assertEquals((await codeRow(free.id)).state, "issued");
});

Deno.test("AT 9 precedence (G3-08): an unattestable-resting reward activated on a CLEAN device is held, not activated; an open attestation_failed signal holds the account's activations", DT, async () => {
  const u = await freshUser("precedence");
  const dev = await newDevice(u);
  const rests = await newCode(u, { restsOnUnattestable: true });
  const out = await activate(u, rests.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(u)).length, 0, "unattestable is routing, not an accusation");

  const u2 = await freshUser("precedence-2");
  const dev2 = await newDevice(u2);
  await priorReward(u2, dev2);
  await adminSql()`insert into app.fraud_signal (user_id, kind, detail) values (${u2.uid}, 'attestation_failed', '{}'::jsonb)`;
  const code2 = await newCode(u2);
  assertEquals((await activate(u2, code2.id, await iosReq(u2, dev2), deps({ ios: iosPort({ bits: BIT0 }) }))).state, "held_review");

  // a CLEARED signal no longer holds
  await adminSql()`update app.fraud_signal set cleared_at = now() where user_id = ${u2.uid}`;
  const code3 = await newCode(u2);
  assertEquals((await activate(u2, code3.id, await iosReq(u2, dev2), deps({ ios: iosPort({ bits: BIT0 }) }))).state, "issued");
});

Deno.test("AT 9: a reward whose backing play is held counts as resting on an unattestable co-signal (the scorer's hold carries into the table's row 3)", DT, async () => {
  const u = await freshUser("held-play");
  const code = await newCode(u);
  const playId = freshUuid();
  await adminSql()`insert into app.play (id, user_id, course_id, facility_id, play_date, policy_version, status, held_review) values (${playId}, ${u.uid}, ${CRS_X1}, ${FAC_X}, current_date - 50, 'v1', 'confirmed', true)`;
  // The play guard (0017) only lets a code under a held play be held_review (or terminal) — so that is the state it is in.
  await adminSql()`update app.offer_code set play_id = ${playId}, state = 'held_review' where id = ${code.id}`;
  const seen = await withOwnership(u.actor, (repo: Repo) => repo.rewards.lockOwnReward(code.id));
  assertEquals(seen?.restsOnUnattestable, true);
  assertEquals(seen?.state, "held_review");
  // and an ordinary code is not
  const plain = await newCode(u);
  assertEquals((await withOwnership(u.actor, (repo: Repo) => repo.rewards.lockOwnReward(plain.id)))?.restsOnUnattestable, false);
});

Deno.test("AT 9: a FAILED verdict raises fraud_signal(attestation_failed) at intake and the reward is held; the open signal then holds the next activation too", DT, async () => {
  const u = await freshUser("failed");
  const dev = await newDevice(u);
  const code = await newCode(u);
  const ios = iosPort({ assertion: { ok: false, grade: "failed", reason: "bad_signature_or_request_hash" }, bits: CLEAR });
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios }));
  assertEquals(out.state, "held_review");
  const sigs = await signals(u, "attestation_failed");
  assertEquals(sigs.length, 1);
  assertEquals((sigs[0]!.detail as Record<string, unknown>).reasons, ["bad_signature_or_request_hash"]);
  // A second failed activation does not stack a second open signal.
  const code2 = await newCode(u);
  await activate(u, code2.id, await iosReq(u, dev), deps({ ios }));
  assertEquals((await signals(u, "attestation_failed")).length, 1);
  // A clean activation by the same account is held by row 2.
  const code3 = await newCode(u);
  assertEquals((await activate(u, code3.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "held_review");
});

Deno.test("AT 9 / G3-08: no token -> failed on hardware that supports attestation, unattestable otherwise; neither reaches issued", DT, async () => {
  const capable = await freshUser("notoken-capable");
  const dev = await newDevice(capable);
  const c1 = await newCode(capable);
  const out = await activate(capable, c1.id, { deviceId: dev, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: true } }, deps({}));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(capable, "attestation_failed")).length, 1);

  const incapable = await freshUser("notoken-incapable");
  const dev2 = await newDevice(incapable);
  const c2 = await newCode(incapable);
  const out2 = await activate(incapable, c2.id, { deviceId: dev2, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } }, deps({}));
  assertEquals(out2.state, "held_review");
  assertEquals((await signals(incapable)).length, 0);
});

// ===========================================================================
// AT (5): body-hash binding and counter replay with the REAL assertion verifier
// ===========================================================================
const APP_ID = "TEAMID1234.com.example.golfraven";
const KEY_ID = toB64(new Uint8Array(32).fill(7));

async function registerKey(deviceId: string, counter = 5) {
  const key = await generateP256();
  await adminSql()`update app.device set attest_key_id = ${KEY_ID}, attest_public_key = ${key.publicKeyRaw}, attest_counter = ${counter} where id = ${deviceId}`;
  const fake = iosPort({ bits: CLEAR });
  const port: IosPort = {
    verifyAssertion: (input) => verifyAppAttestAssertion(input, { appId: APP_ID }, { sha256, verifyP256: verifyP256WebCrypto }),
    readBits: (t) => fake.readBits(t),
    setBit0: (t, k) => fake.setBit0(t, k),
  };
  return { key, port, fake };
}
async function signedReq(u: User, deviceId: string, key: Awaited<ReturnType<typeof generateP256>>, o: { rewardId: string; counter: number; bindRewardId?: string; bindChallenge?: Uint8Array }): Promise<ActivationRequest> {
  const ch = await issueLive(u, deviceId);
  const hash = await computeRequestBinding(sha256, { rewardId: o.bindRewardId ?? o.rewardId, deviceId, platform: "ios", challengeId: ch.challengeId }, o.bindChallenge ?? ch.nonceBytes);
  const built = await buildAssertion({ key, appId: APP_ID, counter: o.counter, clientDataHash: hash });
  return { deviceId, platform: "ios", challengeId: ch.challengeId, nonce: ch.nonce, attestation: { kind: "ios", keyId: KEY_ID, assertion: built.assertionB64, deviceCheckToken: "REVWSUNF" } };
}
async function counterOf(deviceId: string): Promise<number> {
  return Number((await adminSql()`select attest_counter from app.device where id = ${deviceId}`)[0]!.attest_counter);
}

Deno.test("AT 5: a correctly bound, monotonic assertion is attested -> issued, and the counter advances in the database", DT, async () => {
  const u = await freshUser("at5-good");
  const dev = await newDevice(u);
  const { key, port } = await registerKey(dev);
  const code = await newCode(u);
  const out = await activate(u, code.id, await signedReq(u, dev, key, { rewardId: code.id, counter: 6 }), deps({ ios: port }));
  assertEquals(out.state, "issued");
  assertEquals(await counterOf(dev), 6);
  const d = await adminSql()`select integrity_last from app.device where id = ${dev}`;
  assertEquals((d[0]!.integrity_last as Record<string, unknown>).grade, "attested");
  assertEquals(Object.keys(d[0]!.integrity_last as Record<string, unknown>).sort(), ["at", "grade"], "only grade + time are stored (the column is exported to the player)");
});

Deno.test("AT 5: a REPLAYED assertion counter is rejected (graded failed -> fraud_signal, reward held, counter not advanced)", DT, async () => {
  const u = await freshUser("at5-replay");
  const dev = await newDevice(u);
  const { key, port } = await registerKey(dev, 5);
  const c1 = await newCode(u);
  assertEquals((await activate(u, c1.id, await signedReq(u, dev, key, { rewardId: c1.id, counter: 6 }), deps({ ios: port }))).state, "issued");
  // A fresh, correctly bound assertion that REUSES counter 6.
  const c2 = await newCode(u);
  const out = await activate(u, c2.id, await signedReq(u, dev, key, { rewardId: c2.id, counter: 6 }), deps({ ios: port }));
  assertEquals(out.state, "held_review");
  assertEquals(await counterOf(dev), 6);
  const sig = (await signals(u, "attestation_failed"))[0]!;
  assertEquals((sig.detail as Record<string, unknown>).reasons, ["counter_not_monotonic"]);
});

Deno.test("AT 5: a counter that passes verification but loses the ATOMIC advance (a concurrent request moved it) is rejected too — the UPDATE is monotonic, not check-then-set", DT, async () => {
  const u = await freshUser("at5-race");
  const dev = await newDevice(u);
  const { key, port } = await registerKey(dev, 5);
  const code = await newCode(u);
  const req = await signedReq(u, dev, key, { rewardId: code.id, counter: 6 });
  const racing: IosPort = {
    ...port,
    verifyAssertion: async (input) => {
      const r = await port.verifyAssertion(input);
      await adminSql()`update app.device set attest_counter = 9 where id = ${dev}`; // another request advanced it in between
      return r;
    },
  };
  const out = await activate(u, code.id, req, deps({ ios: racing }));
  assertEquals(out.state, "held_review");
  assertEquals(await counterOf(dev), 9, "the lost race did not overwrite the newer counter with the older one");
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["counter_replay"]);
});

Deno.test("AT 5: a MISMATCHED body hash (assertion bound to another reward / another challenge) is rejected", DT, async () => {
  const u = await freshUser("at5-bodyhash");
  const dev = await newDevice(u);
  const { key, port } = await registerKey(dev, 5);
  const a = await newCode(u);
  const b = await newCode(u);
  // bound to reward B, presented for reward A
  const out = await activate(u, a.id, await signedReq(u, dev, key, { rewardId: a.id, counter: 6, bindRewardId: b.id }), deps({ ios: port }));
  assertEquals(out.state, "held_review");
  assertEquals(await counterOf(dev), 5, "a rejected assertion never advances the counter");
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["bad_signature_or_request_hash"]);
  // bound to a different challenge's bytes
  const u2 = await freshUser("at5-bodyhash-2");
  const dev2 = await newDevice(u2);
  const r2 = await registerKey(dev2, 5);
  const code2 = await newCode(u2);
  const out2 = await activate(u2, code2.id, await signedReq(u2, dev2, r2.key, { rewardId: code2.id, counter: 6, bindChallenge: new Uint8Array(32).fill(3) }), deps({ ios: r2.port }));
  assertEquals(out2.state, "held_review");
});

Deno.test("AT 5: a device with no registered App Attest key is unattestable -> held (routing, not an accusation)", DT, async () => {
  const u = await freshUser("at5-nokey");
  const dev = await newDevice(u); // no attest_public_key on record
  const code = await newCode(u);
  const port: IosPort = {
    verifyAssertion: (input) => verifyAppAttestAssertion(input, { appId: APP_ID }, { sha256, verifyP256: verifyP256WebCrypto }),
    readBits: async () => CLEAR,
    setBit0: async () => {},
  };
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios: port }));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(u)).length, 0);
});

Deno.test("AT 5 (Android): the verifier is handed base64url(SHA-256(canonical_body ‖ challenge)); a wrong requestHash verdict is failed -> held + signal", DT, async () => {
  const u = await freshUser("android-hash");
  const dev = await newDevice(u, "android");
  const code = await newCode(u);
  const ch = await issueLive(u, dev);
  const android = androidPort({ grade: "failed", reasons: ["request_hash_mismatch"], bits: null });
  const out = await activate(u, code.id, { deviceId: dev, platform: "android", challengeId: ch.challengeId, nonce: ch.nonce, attestation: { kind: "android", integrityToken: "tok.en.val" } }, deps({ android }));
  assertEquals(out.state, "held_review");
  const expected = toBase64Url(await computeRequestBinding(sha256, { rewardId: code.id, deviceId: dev, platform: "android", challengeId: ch.challengeId }, ch.nonceBytes));
  assertEquals(android.lastRequestHash, expected);
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["request_hash_mismatch"]);
});

Deno.test("Android: attested with device-recall bits runs the same table; attested with NO bits (A20) is held, never activated", DT, async () => {
  const u = await freshUser("android-bits");
  const dev = await newDevice(u, "android");
  const clean = await newCode(u);
  const ios = androidPort({ grade: "attested", bits: CLEAR });
  const ch1 = await issueLive(u, dev);
  const out = await activate(u, clean.id, { deviceId: dev, platform: "android", challengeId: ch1.challengeId, nonce: ch1.nonce, attestation: { kind: "android", integrityToken: "a.b.c" } }, deps({ android: ios }));
  assertEquals(out.state, "issued");
  assertEquals(ios.calls.setBit0, 1);

  const u2 = await freshUser("android-nobits");
  const dev2 = await newDevice(u2, "android");
  const code2 = await newCode(u2);
  const ch2 = await issueLive(u2, dev2);
  const out2 = await activate(u2, code2.id, { deviceId: dev2, platform: "android", challengeId: ch2.challengeId, nonce: ch2.nonce, attestation: { kind: "android", integrityToken: "a.b.c" } }, deps({ android: androidPort({ grade: "attested", bits: null }) }));
  assertEquals(out2.state, "held_review");
});

// ===========================================================================
// State machine, idempotency, transactions
// ===========================================================================
Deno.test("state transitions: earned -> issued; the same device again is an idempotent replay; earned -> held_review; held stays held; terminal states are 409", DT, async () => {
  const u = await freshUser("states");
  const dev = await newDevice(u);
  const code = await newCode(u);
  const ios = iosPort({ bits: CLEAR });
  assertEquals((await activate(u, code.id, await iosReq(u, dev), deps({ ios }))).state, "issued");
  const replay = await activate(u, code.id, await iosReq(u, dev), deps({ ios }));
  assertEquals(replay, { id: code.id, kind: "offer_code", state: "issued", held: false, replay: true });
  assertEquals(ios.calls.readBits, 1, "the replay read no bits");
  assertEquals((await ledgerFor(code.id)).length, 1);

  const held = await newCode(u, { state: "held_review" });
  const hOut = await activate(u, held.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }));
  assertEquals(hOut, { id: held.id, kind: "offer_code", state: "held_review", held: true, replay: true });

  for (const state of ["redeemed", "void", "expired"]) {
    const c = await newCode(u, { state });
    assertEquals(await codeOf(activate(u, c.id, await iosReq(u, dev), deps({ ios: iosPort() }))), { status: 409, code: "reward_not_activatable" }, state);
  }
  const expired = await newCode(u, { expiresInDays: -1 });
  assertEquals(await codeOf(activate(u, expired.id, await iosReq(u, dev), deps({ ios: iosPort() }))), { status: 409, code: "reward_expired" });
  const ent = await newEntitlement(u, "trl_t", { state: "redeemed" });
  assertEquals(await codeOf(activate(u, ent, await iosReq(u, dev), deps({ ios: iosPort() }))), { status: 409, code: "reward_not_activatable" });
});

Deno.test("the database refuses an `activate` that table rows 2/3 forbid, whatever the caller decided (Repo#rewards.applyActivation -> 409 reward_state_changed)", DT, async () => {
  const u = await freshUser("backstop");
  const dev = await newDevice(u);
  const code = await newCode(u, { restsOnUnattestable: true });
  const out = await codeOf(withOwnership(u.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: code.id, deviceId: dev, tokenHash: null, decision: "activate" })));
  assertEquals(out, { status: 409, code: "reward_state_changed" });
  assertEquals((await codeRow(code.id)).state, "earned");
  // A state the transition does not allow (a terminal reward) is a 409, mapped from SQLSTATE 55000.
  const redeemed = await newCode(u, { state: "redeemed" });
  assertEquals(
    await codeOf(withOwnership(u.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: redeemed.id, deviceId: dev, tokenHash: null, decision: "activate" }))),
    { status: 409, code: "reward_not_activatable" },
  );
  // ... and the ownership check inside the function: another user's id is a 404 through the Repo too.
  const other = await freshUser("backstop-other");
  const out2 = await codeOf(withOwnership(other.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: code.id, deviceId: dev, tokenHash: null, decision: "held_review" })));
  assertEquals(out2, { status: 404, code: "not_found" });
});

Deno.test("FAIL CLOSED and ATOMIC: bit0 cannot be set -> 503 and the whole transaction rolls back (reward still earned, no ledger row, challenge unused, counter unchanged)", DT, async () => {
  const u = await freshUser("rollback-setbit");
  const dev = await newDevice(u);
  const { key, port } = await registerKey(dev, 5);
  const code = await newCode(u);
  const req = await signedReq(u, dev, key, { rewardId: code.id, counter: 6 });
  const failing: IosPort = { ...port, setBit0: async () => { throw new VendorUnavailableError("apple down"); } };
  const out = await codeOf(activate(u, code.id, req, deps({ ios: failing })));
  assertEquals(out, { status: 503, code: "attestation_unavailable" });
  assertEquals((await codeRow(code.id)).state, "earned");
  assertEquals((await ledgerFor(code.id)).length, 0);
  assertEquals(await counterOf(dev), 5);
  const ch = await adminSql()`select used_at from app.checkin_challenge where id = ${req.challengeId!}`;
  assertEquals(ch[0]!.used_at, null, "the challenge consumption rolled back too, so the SAME request can be retried");
  // ...and the retry succeeds.
  assertEquals((await activate(u, code.id, req, deps({ ios: port }))).state, "issued");
});

Deno.test("FAIL CLOSED: DeviceCheck unavailable / unconfigured -> 503 and nothing is written; iOS port missing -> 503", DT, async () => {
  const u = await freshUser("failclosed");
  const dev = await newDevice(u);
  const code = await newCode(u);
  assertEquals(await codeOf(activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: new VendorUnavailableError("down") }) }))), { status: 503, code: "attestation_unavailable" });
  assertEquals(await codeOf(activate(u, code.id, await iosReq(u, dev), deps({ ios: null }))), { status: 503, code: "attestation_not_configured" });
  const row = await codeRow(code.id);
  assertEquals([row.state, row.activated_device_id], ["earned", null]);
  assertEquals((await ledgerFor(code.id)).length, 0);
  assertEquals((await signals(u)).length, 0);
});

Deno.test("a challenge is single-use and bound to its device: replaying the same request, or presenting another device's challenge, is 422", DT, async () => {
  const u = await freshUser("challenge");
  const d1 = await newDevice(u);
  const d2 = await newDevice(u);
  const a = await newCode(u);
  const b = await newCode(u);
  const ch = await issueLive(u, d1);
  assertEquals((await activate(u, a.id, await iosReq(u, d1, { challenge: ch }), deps({ ios: iosPort() }))).state, "issued");
  assertEquals(await codeOf(activate(u, b.id, await iosReq(u, d1, { challenge: ch }), deps({ ios: iosPort() }))), { status: 422, code: "challenge_not_consumable" });
  const other = await issueLive(u, d2);
  assertEquals(await codeOf(activate(u, b.id, await iosReq(u, d1, { challenge: other }), deps({ ios: iosPort() }))), { status: 422, code: "challenge_not_consumable" });
});

Deno.test("device cap and platform: a 21st device is 422; a device registered under the other platform is 422", DT, async () => {
  const u = await freshUser("devices");
  for (let i = 0; i < 20; i++) await newDevice(u);
  const code = await newCode(u);
  const out = await codeOf(activate(u, code.id, { deviceId: freshUuid(), platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } }, deps({})));
  assertEquals(out, { status: 422, code: "device_limit_exceeded" });

  const u2 = await freshUser("platform");
  const iosDev = await newDevice(u2, "ios");
  const c2 = await newCode(u2);
  assertEquals(await codeOf(activate(u2, c2.id, { deviceId: iosDev, platform: "android", attestation: { kind: "none", hardwareSupportsAttestation: false } }, deps({}))), { status: 422, code: "platform_mismatch" });
});

// ===========================================================================
// Concurrency
// ===========================================================================
Deno.test("concurrency: two simultaneous activations of one reward from the same device issue it once (one ledger row, one transition)", DT, async () => {
  const u = await freshUser("race-same");
  const dev = await newDevice(u);
  const code = await newCode(u);
  const reqs = await Promise.all([iosReq(u, dev), iosReq(u, dev)]);
  const outs = await Promise.all(reqs.map((r) => activate(u, code.id, r, deps({ ios: iosPort({ bits: CLEAR }) }))));
  assertEquals(outs.map((o) => o.state), ["issued", "issued"]);
  assertEquals(outs.filter((o) => o.replay).length, 1, "exactly one of the two did the work");
  assertEquals((await ledgerFor(code.id)).length, 1);
});

Deno.test("concurrency: two simultaneous activations from DIFFERENT devices serialise on the reward row and both run the table", DT, async () => {
  const u = await freshUser("race-two-dev");
  const d1 = await newDevice(u);
  const d2 = await newDevice(u);
  const code = await newCode(u);
  const reqs = [await iosReq(u, d1), await iosReq(u, d2)];
  const outs = await Promise.all(reqs.map((r) => activate(u, code.id, r, deps({ ios: iosPort({ bits: CLEAR }) }))));
  assertEquals(outs.map((o) => o.state), ["issued", "issued"]);
  assertEquals((await ledgerFor(code.id)).length, 2);
});

Deno.test("concurrency: simultaneous holds of two codes against an offer with room for only one reservation never over-reserve", DT, async () => {
  const u = await freshUser("race-budget");
  const dev = await newDevice(u);
  const offerId = await newOffer({ faceValue: 10, cap: 15 });
  const u2 = await freshUser("race-budget-2");
  const dev2 = await newDevice(u2);
  const c1 = await newCode(u, { offerId });
  const c2 = await newCode(u2, { offerId });
  const reqs = [await iosReq(u, dev), await iosReq(u2, dev2)];
  const outs = await Promise.all([activate(u, c1.id, reqs[0]!, deps({ ios: iosPort({ bits: BIT1 }) })), activate(u2, c2.id, reqs[1]!, deps({ ios: iosPort({ bits: BIT1 }) }))]);
  assertEquals(outs.map((o) => o.state), ["held_review", "held_review"], "never refused");
  assertEquals(await offerReserved(offerId), 10, "only one reservation fits under the cap of 15");
  const unreserved = await adminSql()`select count(*)::int as n from app.review_item where kind = 'held_offer_budget_unreserved' and subject_id in (${c1.id}, ${c2.id})`;
  assertEquals(unreserved[0]!.n, 1, "the other code is held unreserved and a human is told");
});

// ===========================================================================
// Rate limits (§4.7 item 8) — the REAL hitRateLimitForActor
// ===========================================================================
Deno.test("rate limit: 10 activation requests per user per hour — the 11th is refused", DT, async () => {
  const u = await freshUser("rl-user");
  const dev = freshUuid();
  const hit = (key: string, w: number, max: number) => hitRateLimitForActor(u.actor, key, w, max);
  const oks: boolean[] = [];
  for (let i = 0; i < 11; i++) oks.push((await enforceActivationRateLimits(hit, dev)).ok);
  assertEquals(oks.slice(0, 10).every(Boolean), true);
  assertEquals(oks[10], false);
});

Deno.test("rate limit: 20 activation requests per device per day — the 21st is refused (user bucket isolated)", DT, async () => {
  const u = await freshUser("rl-device");
  const dev = freshUuid();
  let i = 0;
  // A fresh user-bucket key every call isolates the DEVICE bucket, which goes through the real limiter untouched.
  const hit = (key: string, w: number, max: number) => hitRateLimitForActor(u.actor, key === "rewards-activate:user" ? `rewards-activate:user:${i++}` : key, w, max);
  const oks: boolean[] = [];
  for (let n = 0; n < 21; n++) oks.push((await enforceActivationRateLimits(hit, dev)).ok);
  assertEquals(oks.filter(Boolean).length, 20);
  assertEquals(oks[20], false);
  // another device is a separate bucket
  assertEquals((await enforceActivationRateLimits(hit, freshUuid())).ok, true);
});

Deno.test("rate limit: the buckets are per user (another user's activations do not count against this one)", DT, async () => {
  const a = await freshUser("rl-a");
  const b = await freshUser("rl-b");
  const dev = freshUuid();
  for (let i = 0; i < 10; i++) await enforceActivationRateLimits((k, w, m) => hitRateLimitForActor(a.actor, k, w, m), dev);
  assertEquals((await enforceActivationRateLimits((k, w, m) => hitRateLimitForActor(a.actor, k, w, m), dev)).ok, false);
  assertEquals((await enforceActivationRateLimits((k, w, m) => hitRateLimitForActor(b.actor, k, w, m), dev)).ok, true);
});

// ===========================================================================
// Entitlements through the same handler
// ===========================================================================
Deno.test("entitlements: earned -> redeemable on a clean device; bit0 with no prior -> held_review (counts as outstanding, reserves no budget)", DT, async () => {
  const u = await freshUser("ent");
  const dev = await newDevice(u);
  const e1 = await newEntitlement(u, "trl_t");
  const out = await activate(u, e1, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }));
  assertEquals(out, { id: e1, kind: "entitlement", state: "redeemable", held: false, replay: false });

  const u2 = await freshUser("ent-2");
  const dev2 = await newDevice(u2);
  const e2 = await newEntitlement(u2, "trl_u");
  const out2 = await activate(u2, e2, await iosReq(u2, dev2), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out2.state, "held_review");
  assertEquals((await signals(u2, "multi_account_device")).length, 1);
  assertEquals((await entRow(e2)).state, "held_review");
  // approval -> redeemable
  const r = await adminSql()`select app.resolve_held_entitlement(${e2}, true, ${ADMIN}) as state`;
  assertEquals(r[0]!.state, "redeemable");
});

Deno.test("the verdict recorded on the device row is grade + time only, and the token hash is stored", DT, async () => {
  const u = await freshUser("verdict-shape");
  const dev = await newDevice(u);
  const code = await newCode(u);
  await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT1 }) }));
  const d = await adminSql()`select integrity_last, devicecheck_token_hash from app.device where id = ${dev}`;
  assertEquals(Object.keys(d[0]!.integrity_last as Record<string, unknown>).sort(), ["at", "grade"]);
  assert(d[0]!.devicecheck_token_hash, "the token hash is stored on the device too");
});
