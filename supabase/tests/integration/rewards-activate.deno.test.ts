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
import { getContainedClosedSocketWrites, hitRateLimitForActor, isPostgresJsClosedSocketWrite, withOwnership } from "../../functions/_shared/privileged.ts";
import { enforceActivationRateLimits, handleActivation, type ActivationDeps } from "../../functions/_shared/rewards/activate-handler.ts";
import { computeRequestBinding, toBase64Url, toHex } from "../../functions/_shared/rewards/binding.ts";
import { computeIosActivationBinding } from "../../functions/_shared/rewards/string-binding.ts";
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
  calls: { verify: number };
  lastRequestHash: string | null;
}
function androidPort(result: IntegrityResult): SpyAndroid {
  const port: SpyAndroid = {
    calls: { verify: 0 },
    lastRequestHash: null,
    async verifyIntegrity(input) {
      port.calls.verify++;
      port.lastRequestHash = input.expectedRequestHash;
      return result;
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

async function newDevice(u: User, platform: "ios" | "android" = "ios", withKey = true): Promise<string> {
  const id = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), platform)).id);
  if (platform === "ios" && withKey) {
    // A device a scripted `ok` assertion verdict can stand on. `advanceAttestCounter` is bound to the key id the assertion was verified
    // against (LOW-1), and `deviceAttestState` hands out a key only when it is REGISTERED, so a scripted-port test needs a registered key
    // for its `ok` to mean anything — exactly as in production, where the verifier cannot say `ok` for a keyless device. (The scripted
    // port ignores the key bytes; tests that verify a real assertion call `registerKey`, which overwrites these.)
    // A placeholder key UNIQUE PER DEVICE (the install link groups accounts by an equal attest_key_id, so two devices must not share one) and BOUND
    // (0038: the key id is the base64 SHA-256 of the public key, as app.register_attest_key requires): 0x04 || SHA-256(id) || SHA-256(id + ":2").
    const enc = new TextEncoder();
    const placeholder = new Uint8Array(65);
    placeholder[0] = 4;
    placeholder.set(await sha256(enc.encode(id)), 1);
    placeholder.set(await sha256(enc.encode(id + ":2")), 33);
    const placeholderId = toB64(await sha256(placeholder));
    await adminSql()`update app.device set attest_key_id = ${placeholderId}, attest_public_key = ${placeholder}, attest_registered_at = now() where id = ${id}`;
  }
  return id;
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
  // 0051: at most ONE review account exists (unique index), so this test's account replaces whichever exists (this suite runs on its own clone of the database)
  await adminSql()`delete from app.app_review_demo_account where retired_at is null`;
  await adminSql()`insert into app.app_review_demo_account (user_id) values (${demo.uid})`;
  // 0051: the review account is DISABLED outside a submission window (it cannot even be bound), so the reward refusal is proven INSIDE one: the account can sign in and
  // still cannot receive a reward (AT 14). The window is this test's own and is removed in `finally`.
  const w = await adminSql()`insert into app.app_review_window (starts_at, ends_at, note) values (now() - interval '1 hour', now() + interval '1 hour', 'rewards-activate test') returning id`;
  try {
    const dev = await newDevice(demo);
    const code = await newCode(demo);
    for (const id of [code.id, freshUuid()]) {
      const ios = iosPort();
      assertEquals(await codeOf(activate(demo, id, await iosReq(demo, dev), deps({ ios }))), { status: 403, code: "forbidden" });
      assertEquals(ios.calls, { verify: 0, readBits: 0, setBit0: 0 });
    }
    assertEquals((await codeRow(code.id)).state, "earned");
  } finally {
    await adminSql()`delete from app.app_review_window where id = ${w[0]!.id}`;
  }
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
  assertEquals(row.reserved_amount, "10.00", "issuing an earned code that holds no reservation takes one (0027 budget model, step 2)");
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

Deno.test("capability dodge: a device with a REGISTERED App Attest key that claims it cannot attest is `failed` (+ fraud_signal), not `unattestable`", DT, async () => {
  const u = await freshUser("dodge");
  const dev = await newDevice(u); // carries a registered key
  const code = await newCode(u);
  const out = await activate(u, code.id, { deviceId: dev, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } }, deps({}));
  assertEquals(out.state, "held_review");
  const sigs = await signals(u, "attestation_failed");
  assertEquals(sigs.length, 1);
  assertEquals((sigs[0]!.detail as Record<string, unknown>).reasons, ["no_attestation_token", "device_has_attested_before"]);
});

Deno.test("capability dodge, Android (0043): a device whose ACTIVATION verdict was `attested` is `failed` when it later activates with no attestation and claims it cannot attest — even after a later `failed` verdict overwrote integrity_last", DT, async () => {
  const u = await freshUser("dodge-android");
  const dev = await newDevice(u, "android");
  // What a successful Android activation records (privileged.ts#recordDeviceVerdict), then a LATER failed verdict.
  await withOwnership(u.actor, (repo: Repo) => repo.rewards.recordDeviceVerdict(dev, { grade: "attested", tokenHash: null }));
  await withOwnership(u.actor, (repo: Repo) => repo.rewards.recordDeviceVerdict(dev, { grade: "failed", tokenHash: null }));
  const row = (await adminSql()`select integrity_last, first_attested_at from app.device where id = ${dev}`)[0]!;
  assertEquals((row.integrity_last as Record<string, unknown>).grade, "failed", "integrity_last is the LAST verdict");
  assert(row.first_attested_at !== null, "the sticky mark survived it");
  const code = await newCode(u);
  const out = await activate(u, code.id, { deviceId: dev, platform: "android", attestation: { kind: "none", hardwareSupportsAttestation: false } }, deps({}));
  assertEquals(out.state, "held_review");
  const sigs = await signals(u, "attestation_failed");
  assertEquals(sigs.length, 1);
  assertEquals((sigs[0]!.detail as Record<string, unknown>).reasons, ["no_attestation_token", "device_has_attested_before"]);
});

Deno.test("AT 9 / G3-08: no token -> failed on hardware that supports attestation, unattestable otherwise; neither reaches issued", DT, async () => {
  const capable = await freshUser("notoken-capable");
  const dev = await newDevice(capable);
  const c1 = await newCode(capable);
  const out = await activate(capable, c1.id, { deviceId: dev, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: true } }, deps({}));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(capable, "attestation_failed")).length, 1);

  const incapable = await freshUser("notoken-incapable");
  const dev2 = await newDevice(incapable, "ios", false); // a device that never registered an App Attest key: its "cannot attest" is believed
  const c2 = await newCode(incapable);
  const out2 = await activate(incapable, c2.id, { deviceId: dev2, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } }, deps({}));
  assertEquals(out2.state, "held_review");
  assertEquals((await signals(incapable)).length, 0);
});

// ===========================================================================
// AT (5): body-hash binding and counter replay with the REAL assertion verifier
// ===========================================================================
const APP_ID = "TEAMID1234.com.example.golfraven";
// The key id is DERIVED from the key (0038: the counter trigger refuses a key id that is not the base64 SHA-256 of the public key).
const keyIdOf = async (key: Awaited<ReturnType<typeof generateP256>>) => toB64(await sha256(key.publicKeyRaw));

async function registerKey(deviceId: string, counter = 5) {
  const key = await generateP256();
  // `attest_registered_at` stands in for a VERIFIED registration (0034): rewards-activate hands the assertion verifier a key
  // only when it was written by app.register_attest_key. (The real registration path is attest-key.deno.test.ts.)
  // Since 0038 the counter trigger refuses a key swap that is not a REPLACEMENT as app.register_attest_key writes it (a bound key id, counter 0, the
  // replaced key appended to the retired list, registered_at set), so a device that already carries `newDevice`'s placeholder key is
  // replaced in that shape (the old key's hash is read from the row itself, in the same statement) and the counter is then ADVANCED
  // (an increase, which is always allowed). A keyless device takes the first-registration shape. Not a weakening of the trigger.
  await adminSql()`
    update app.device set
      attest_retired_key_hashes = case when attest_key_id is null then attest_retired_key_hashes
                                       else attest_retired_key_hashes || encode(sha256(convert_to(attest_key_id, 'UTF8')), 'hex') end,
      attest_key_id = ${await keyIdOf(key)}, attest_public_key = ${key.publicKeyRaw}, attest_counter = 0, attest_registered_at = now()
    where id = ${deviceId}`;
  await adminSql()`update app.device set attest_counter = ${counter} where id = ${deviceId}`;
  const fake = iosPort({ bits: CLEAR });
  const port: IosPort = {
    verifyAssertion: (input) => verifyAppAttestAssertion(input, { appId: APP_ID }, { sha256, verifyP256: verifyP256WebCrypto }),
    readBits: (t) => fake.readBits(t),
    setBit0: (t, k) => fake.setBit0(t, k),
  };
  return { key, port, fake };
}
const SIGNED_TOKEN = "REVWSUNF";
async function signedReq(
  u: User,
  deviceId: string,
  key: Awaited<ReturnType<typeof generateP256>>,
  o: { rewardId: string; counter: number; bindRewardId?: string; bindNonce?: string; sendToken?: string },
): Promise<ActivationRequest> {
  const ch = await issueLive(u, deviceId);
  // H1: the assertion covers the SHA-256 of the DeviceCheck token the request carries.
  const hash = await computeIosActivationBinding(sha256, {
    rewardId: o.bindRewardId ?? o.rewardId,
    deviceId,
    challengeId: ch.challengeId,
    deviceCheckTokenSha256: await digestHex(new TextEncoder().encode(SIGNED_TOKEN)),
    nonce: o.bindNonce ?? ch.nonce,
  });
  const built = await buildAssertion({ key, appId: APP_ID, counter: o.counter, clientDataHash: hash });
  return { deviceId, platform: "ios", challengeId: ch.challengeId, nonce: ch.nonce, attestation: { kind: "ios", keyId: await keyIdOf(key), assertion: built.assertionB64, deviceCheckToken: o.sendToken ?? SIGNED_TOKEN } };
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
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["counter_out_of_order"]);
});

Deno.test("AT 5 (LOW-1): an assertion that loses the atomic advance to an EQUAL counter stays `counter_replay`", DT, async () => {
  const u = await freshUser("at5-race-equal");
  const dev = await newDevice(u);
  const { key, port } = await registerKey(dev, 5);
  const code = await newCode(u);
  const req = await signedReq(u, dev, key, { rewardId: code.id, counter: 6 });
  const racing: IosPort = {
    ...port,
    verifyAssertion: async (input) => {
      const r = await port.verifyAssertion(input);
      await adminSql()`update app.device set attest_counter = 6 where id = ${dev}`; // an identical request advanced it to the very same counter
      return r;
    },
  };
  assertEquals((await activate(u, code.id, req, deps({ ios: racing }))).state, "held_review");
  assertEquals(await counterOf(dev), 6);
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["counter_replay"]);
});

Deno.test("AT 5 (LOW-1): OUT-OF-ORDER assertions of one key (counter 7 committed, then 6): 7 is attested, 6 is held with `counter_out_of_order` (not a replay), the counter stays 7", DT, async () => {
  const u = await freshUser("at5-ooo");
  const dev = await newDevice(u);
  const { key, port } = await registerKey(dev, 5);
  const c7 = await newCode(u);
  const c6 = await newCode(u);
  const r7 = await signedReq(u, dev, key, { rewardId: c7.id, counter: 7 });
  const r6 = await signedReq(u, dev, key, { rewardId: c6.id, counter: 6 });
  assertEquals((await activate(u, c7.id, r7, deps({ ios: port }))).state, "issued");
  assertEquals((await activate(u, c6.id, r6, deps({ ios: port }))).state, "held_review");
  assertEquals(await counterOf(dev), 7, "strict monotonicity: the lower counter did not lower the stored one");
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["counter_out_of_order"]);
});

Deno.test("H1: a VALID assertion next to a SWAPPED DeviceCheck token is failed -> signal + held; the token's bits are never trusted and nothing is issued", DT, async () => {
  const u = await freshUser("h1-swap");
  const dev = await newDevice(u);
  const { key, port, fake } = await registerKey(dev, 5);
  const code = await newCode(u);
  const out = await activate(u, code.id, await signedReq(u, dev, key, { rewardId: code.id, counter: 6, sendToken: "T1RIRVJERVZJQ0U=" }), deps({ ios: port }));
  assertEquals(out.state, "held_review");
  assertEquals(await counterOf(dev), 5, "a failed assertion never advances the counter");
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["bad_signature_or_request_hash"]);
  assertEquals((await ledgerFor(code.id)).length, 0);
  assertEquals(fake.calls.setBit0, 0, "no vendor write on a failed verdict");
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
  const out2 = await activate(u2, code2.id, await signedReq(u2, dev2, r2.key, { rewardId: code2.id, counter: 6, bindNonce: toBase64Url(new Uint8Array(32).fill(3)) }), deps({ ios: r2.port }));
  assertEquals(out2.state, "held_review");
});

Deno.test("AT 5: a device with no registered App Attest key is unattestable -> held (routing, not an accusation)", DT, async () => {
  const u = await freshUser("at5-nokey");
  const dev = await newDevice(u, "ios", false); // no attest_public_key on record
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

// One install link per test: the substitute counts accounts across the WHOLE database, and this suite shares one.
const newLink = () => `install-link-${crypto.randomUUID()}`;
const linkHashOf = (id: string) => digestHex(new TextEncoder().encode(id));
async function androidReq(u: User, deviceId: string, installLinkId: string | null): Promise<ActivationRequest & { _nonceBytes: Uint8Array }> {
  const ch = await issueLive(u, deviceId);
  return {
    deviceId,
    platform: "android",
    challengeId: ch.challengeId,
    nonce: ch.nonce,
    ...(installLinkId !== null ? { installLinkId } : {}),
    attestation: { kind: "android", integrityToken: "tok.en.val" },
    _nonceBytes: ch.nonceBytes,
  };
}
/** Other accounts whose Android device rows carry the SAME install link. */
async function otherAccountsOnInstall(link: string, n: number, opts: { voided?: boolean } = {}): Promise<User[]> {
  const out: User[] = [];
  for (let i = 0; i < n; i++) {
    const o = await freshUser(`install-mate-${i}`);
    const d = await newDevice(o, "android");
    await adminSql()`update app.device set install_link_hash = ${await linkHashOf(link)}, fraud_voided_at = ${opts.voided && i === 0 ? adminSql()`now()` : null} where id = ${d}`;
    out.push(o);
  }
  return out;
}

Deno.test("AT 5 (Android): the verifier is handed base64url(SHA-256(canonical_body ‖ challenge)) with the install link bound in; a wrong requestHash verdict is failed -> held + signal", DT, async () => {
  const u = await freshUser("android-hash");
  const dev = await newDevice(u, "android");
  const code = await newCode(u);
  const LINK = newLink();
  const { _nonceBytes, ...req } = await androidReq(u, dev, LINK);
  const android = androidPort({ grade: "failed", reasons: ["request_hash_mismatch"] });
  const out = await activate(u, code.id, req, deps({ android }));
  assertEquals(out.state, "held_review");
  const expected = toBase64Url(await computeRequestBinding(sha256, { rewardId: code.id, deviceId: dev, platform: "android", challengeId: req.challengeId!, installLinkId: LINK }, _nonceBytes));
  assertEquals(android.lastRequestHash, expected);
  assertEquals(((await signals(u, "attestation_failed"))[0]!.detail as Record<string, unknown>).reasons, ["request_hash_mismatch"]);
});

Deno.test("AT 9 on ANDROID via the server-side substitute (A20): clean install -> issued and the install link is recorded; same account again / after reinstall -> issued", DT, async () => {
  const u = await freshUser("android-clean");
  const dev = await newDevice(u, "android");
  const code = await newCode(u);
  const LINK = newLink();
  const { _nonceBytes: _a, ...req } = await androidReq(u, dev, LINK);
  assertEquals((await activate(u, code.id, req, deps({ android: androidPort({ grade: "attested" }) }))).state, "issued");
  const d = await adminSql()`select install_link_hash from app.device where id = ${dev}`;
  assertEquals(d[0]!.install_link_hash, await linkHashOf(LINK), "the substitute's write: the hashed install link is on the device row");
  assertEquals(JSON.stringify(d[0]).includes(LINK), false, "never the raw id");
  // same account, second offer on the same install
  const second = await newCode(u);
  const { _nonceBytes: _b, ...req2 } = await androidReq(u, dev, LINK);
  assertEquals((await activate(u, second.id, req2, deps({ android: androidPort({ grade: "attested" }) }))).state, "issued");
  // reinstall: a NEW device row and a NEW install link, same account (a repeat user with one account everywhere)
  const dev2 = await newDevice(u, "android");
  const third = await newCode(u);
  const { _nonceBytes: _c, ...req3 } = await androidReq(u, dev2, "install-link-NEWINSTALL");
  assertEquals((await activate(u, third.id, req3, deps({ android: androidPort({ grade: "attested" }) }))).state, "issued");
  assertEquals((await signals(u)).length, 0);
});

Deno.test("AT 9 on ANDROID: a new account on an install seen on > 2 accounts -> held_review + multi_account_device; a repeat user there -> issued (row 5)", DT, async () => {
  const LINK = newLink();
  const mates = await otherAccountsOnInstall(LINK, 2); // this account will be the 3rd
  assertEquals(mates.length, 2);
  const u = await freshUser("android-bit0");
  const dev = await newDevice(u, "android");
  const code = await newCode(u);
  const { _nonceBytes: _n, ...req } = await androidReq(u, dev, LINK);
  const out = await activate(u, code.id, req, deps({ android: androidPort({ grade: "attested" }) }));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(u)).map((x) => x.kind), ["multi_account_device"]);
  const hd = (await adminSql()`select hold_detail from app.offer_code where id = ${code.id}`)[0]!.hold_detail as Record<string, unknown>;
  assertEquals(hd.bitsSource, "server_substitute");
  assertEquals(hd.primaryRow, 4);
  assertEquals((hd.androidInstallSignals as Record<string, unknown>).accountsOnInstall, 3);

  // a repeat user on the same install is a repeat user: row 5
  const r = await freshUser("android-bit0-repeat");
  const rdev = await newDevice(r, "android");
  await priorReward(r, rdev);
  const rcode = await newCode(r);
  const { _nonceBytes: _m, ...rreq } = await androidReq(r, rdev, LINK);
  assertEquals((await activate(r, rcode.id, rreq, deps({ android: androidPort({ grade: "attested" }) }))).state, "issued");
});

Deno.test("AT 9 on ANDROID: ANY account on an install a fraud-voided account used -> held_review + a high-priority signal (the bit1 substitute); mark_account_devices_fraud_voided produces it", DT, async () => {
  const LINK = newLink();
  const [voided] = await otherAccountsOnInstall(LINK, 1);
  const u = await freshUser("android-bit1-before");
  const dev = await newDevice(u, "android");
  const before = await newCode(u);
  const { _nonceBytes: _a, ...req0 } = await androidReq(u, dev, LINK);
  assertEquals((await activate(u, before.id, req0, deps({ android: androidPort({ grade: "attested" }) }))).state, "issued", "before the fraud decision the install is merely shared by two accounts");
  // The admin fraud decision on the OTHER account (the real function, not a fixture UPDATE).
  assertEquals((await adminSql()`select app.mark_account_devices_fraud_voided(${voided!.uid}, ${ADMIN}) as n`)[0]!.n, 1);
  const after = await newCode(u);
  const { _nonceBytes: _b, ...req1 } = await androidReq(u, dev, LINK);
  assertEquals((await activate(u, after.id, req1, deps({ android: androidPort({ grade: "attested" }) }))).state, "held_review");
  const sig = (await signals(u, "flagged_device_activation"))[0]!;
  assertEquals((sig.detail as Record<string, unknown>).priority, "high");
});

Deno.test("Android with NO install link on record (none sent, no attest key): no substitute signal -> held, never activated, never refused", DT, async () => {
  const u = await freshUser("android-nolink");
  const dev = await newDevice(u, "android");
  const code = await newCode(u);
  const { _nonceBytes: _n, ...req } = await androidReq(u, dev, null);
  const out = await activate(u, code.id, req, deps({ android: androidPort({ grade: "attested" }) }));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(u)).length, 0);
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
  const out = await codeOf(withOwnership(u.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: code.id, deviceId: dev, tokenHash: null, decision: "activate", holdDetail: null })));
  assertEquals(out, { status: 409, code: "reward_state_changed" });
  assertEquals((await codeRow(code.id)).state, "earned");
  // A state the transition does not allow (a terminal reward) is a 409, mapped from SQLSTATE 55000.
  const redeemed = await newCode(u, { state: "redeemed" });
  assertEquals(
    await codeOf(withOwnership(u.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: redeemed.id, deviceId: dev, tokenHash: null, decision: "activate", holdDetail: null }))),
    { status: 409, code: "reward_not_activatable" },
  );
  // ... and the ownership check inside the function: another user's id is a 404 through the Repo too.
  const other = await freshUser("backstop-other");
  const out2 = await codeOf(withOwnership(other.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: code.id, deviceId: dev, tokenHash: null, decision: "held_review", holdDetail: null })));
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

// ===========================================================================
// P3f gate round 1 (FAIL: H1-H3, M1-M4, LOWs) — the fixes, against real SQL
// ===========================================================================
async function resolveHeld(id: string, approve: boolean): Promise<string> {
  return (await adminSql()`select app.resolve_held_offer_code(${id}, ${approve}, ${ADMIN}) as state`)[0]!.state as string;
}
async function fullCode(id: string) {
  return (await adminSql()`select state, reserved_amount, review_cleared_at, hold_detail, issued_before_hold, expiry_paused_at, activated_device_id, expires_at from app.offer_code where id = ${id}`)[0]!;
}

Deno.test("H2 probe B: a reviewer-approved play-hold code (no device) returns to EARNED, not issued; activating it on a bit0 device with no prior reward still holds (row 4) + multi_account_device; the approval is not a 'prior reward'", DT, async () => {
  const u = await freshUser("h2-probe-b");
  const dev = await newDevice(u);
  const code = await newCode(u, { state: "held_review", faceValue: 10 }); // no device ever ran the table on it
  assertEquals(await resolveHeld(code.id, true), "earned");
  const row = await fullCode(code.id);
  assertEquals([row.state, row.activated_device_id], ["earned", null]);
  assert(row.review_cleared_at, "the review-cleared marker is set");
  assertEquals((await ledgerFor(code.id)).length, 0, "nothing was issued, so nothing on the ledger");
  assertEquals(await withOwnership(u.actor, (repo: Repo) => repo.rewards.hasPriorReward()), false, "an approved-but-never-activated reward is not a prior reward");
  // ...nor is a reward no device ever ran the table on, even in a post-activation state (the real SQL's device filter).
  await newCode(u, { state: "issued" });
  await newEntitlement(u, "trl_u", { state: "redeemable" });
  assertEquals(await withOwnership(u.actor, (repo: Repo) => repo.rewards.hasPriorReward()), false, "issued/redeemable rewards with no activated_device_id do not make a repeat user");

  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(u)).map((x) => x.kind), ["multi_account_device"]);
});

Deno.test("H2: approve-then-activate on a clean attested device -> issued: rows 2/3 were cleared for the reward, rows 1 and 4-6 ran", DT, async () => {
  const u = await freshUser("h2-approve-activate");
  const dev = await newDevice(u);
  const code = await newCode(u, { state: "held_review", restsOnUnattestable: true });
  assertEquals(await resolveHeld(code.id, true), "earned");
  const ios = iosPort({ bits: CLEAR });
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios }));
  assertEquals(out.state, "issued");
  assertEquals((await ledgerFor(code.id)).length, 1);
  assertEquals(ios.calls.setBit0, 1);
});

Deno.test("H2: a cleared reward is still held on a flagged device (row 1), when the device is unattestable, and by a signal raised AFTER the review (N3: and by one raised BEFORE it)", DT, async () => {
  const u = await freshUser("h2-still-held");
  const dev = await newDevice(u);
  const a = await newCode(u, { state: "held_review", restsOnUnattestable: true });
  await resolveHeld(a.id, true);
  assertEquals((await activate(u, a.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT1 }) }))).state, "held_review");
  assert((await signals(u, "flagged_device_activation")).length === 1);

  const u2 = await freshUser("h2-still-held-2");
  const dev2 = await newDevice(u2, "ios", false);
  const b = await newCode(u2, { state: "held_review", restsOnUnattestable: true });
  await resolveHeld(b.id, true);
  const none = await activate(u2, b.id, { deviceId: dev2, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } }, deps({}));
  assertEquals(none.state, "held_review", "an unattestable DEVICE is not cleared by a review of the reward");

  const u3 = await freshUser("h2-still-held-3");
  const dev3 = await newDevice(u3);
  const c = await newCode(u3, { state: "held_review" });
  await resolveHeld(c.id, true);
  await adminSql()`insert into app.fraud_signal (user_id, kind, detail, created_at) values (${u3.uid}, 'attestation_failed', '{}'::jsonb, now() + interval '1 hour')`;
  assertEquals((await activate(u3, c.id, await iosReq(u3, dev3), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "held_review");
});

Deno.test("H3: a play-hold CASCADE (a re-score holding the play) reserves the backing code's budget and pauses its expiry; approval keeps the reservation; reject releases it", DT, async () => {
  const u = await freshUser("h3-cascade");
  const dev = await newDevice(u);
  const offerId = await newOffer({ faceValue: 12 });
  const code = await newCode(u, { offerId });
  const p = await (async () => {
    const playDate = new Date(Date.now() - 70 * 86400_000).toISOString().slice(0, 10);
    const playId = await withOwnership(u.actor, async (repo: Repo) =>
      (await repo.play.upsertFromScore({
        courseId: CRS_X1, facilityId: FAC_X, playDate, courseDisambiguatedBy: null,
        scoreBadge: 0.6, scoreMonetary: 0.9, hardSignal: true, presenceSignal: true, money: true, heldReview: false,
        policyVersion: "v1", inputDigest: "d".repeat(64), evidenceIds: [],
      })).id);
    await adminSql()`update app.offer_code set play_id = ${playId} where id = ${code.id}`;
    return { playId, courseId: CRS_X1, playDate };
  })();
  assertEquals(await offerReserved(offerId), 0, "nothing reserved before the hold");
  await rescoreHeld(u, p);
  const held = await fullCode(code.id);
  assertEquals(held.state, "held_review");
  assertEquals(held.reserved_amount, "12.00", "the cascade reserved the code's face value (it used to write only state)");
  assert(held.expiry_paused_at, "...and paused the expiry clock");
  assertEquals(await offerReserved(offerId), 12);
  // approval keeps the reservation (the reviewer clears the play first: the 0017 guard).
  await adminSql()`update app.play set held_review = false where id = ${p.playId}`;
  assertEquals(await resolveHeld(code.id, true), "earned");
  assertEquals((await fullCode(code.id)).reserved_amount, "12.00");
  assertEquals(await offerReserved(offerId), 12, "approval does not touch the reservation");
  // ...and activation on a device finds the reservation and does not take a second.
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }));
  assertEquals(out.state, "issued");
  assertEquals(await offerReserved(offerId), 12, "idempotent against the existing reservation");

  // reject releases, once
  const offerB = await newOffer({ faceValue: 12 });
  const code2 = await newCode(u, { offerId: offerB });
  const p2date = new Date(Date.now() - 71 * 86400_000).toISOString().slice(0, 10);
  const play2 = await withOwnership(u.actor, async (repo: Repo) =>
    (await repo.play.upsertFromScore({
      courseId: CRS_X1, facilityId: FAC_X, playDate: p2date, courseDisambiguatedBy: null,
      scoreBadge: 0.6, scoreMonetary: 0.9, hardSignal: true, presenceSignal: true, money: true, heldReview: false,
      policyVersion: "v1", inputDigest: "f".repeat(64), evidenceIds: [],
    })).id);
  await adminSql()`update app.offer_code set play_id = ${play2} where id = ${code2.id}`;
  await rescoreHeld(u, { courseId: CRS_X1, playDate: p2date });
  assertEquals(await offerReserved(offerB), 12);
  await adminSql()`update app.play set held_review = false where id = ${play2}`;
  assertEquals(await resolveHeld(code2.id, false), "void");
  assertEquals(await offerReserved(offerB), 0, "reject released the rejected code's 12");
  assertEquals(await offerReserved(offerId), 12, "...and nothing of the other offer's");
  await adminSql()`update app.offer_code set state = 'void' where id = ${code2.id}`;
  assertEquals(await offerReserved(offerB), 0, "a second void releases nothing more");
});

Deno.test("H3: DELETE of a code that holds a reservation releases it (a role that can update the offer)", DT, async () => {
  const u = await freshUser("h3-delete");
  const dev = await newDevice(u);
  const code = await newCode(u, { faceValue: 7 });
  await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT1 }) }));
  const offerId = (await codeRow(code.id)).offer_id as string;
  assertEquals(await offerReserved(offerId), 7);
  await adminSql()`delete from app.offer_code where id = ${code.id}`;
  assertEquals(await offerReserved(offerId), 0);
});

Deno.test("M1 probe: account deletion racing an activation that is mid-flight (reservation taken, uncommitted) ends with budget_reserved = 0 — no leaked reservation", DT, async () => {
  const u = await freshUser("m1-delete-race");
  const dev = await newDevice(u);
  const code = await newCode(u, { faceValue: 10 });
  const offerId = (await codeRow(code.id)).offer_id as string;
  const { default: postgres } = await import("https://deno.land/x/postgresjs@v3.4.5/mod.js");
  const sess = postgres({ host: Deno.env.get("PGHOST"), port: Number(Deno.env.get("PGPORT")), username: Deno.env.get("PGUSER"), database: Deno.env.get("PGDATABASE"), max: 1, prepare: false });
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let started!: () => void;
  const hasLocks = new Promise<void>((r) => (started = r));
  // Session A: the activation's SQL, held OPEN (row locked, reservation taken, not committed).
  const sessionA = sess.begin(async (tx) => {
    await tx`set local role service_role`;
    await tx`select app.activate_offer_code(${code.id}, ${u.uid}, ${dev}, null, 'activate')`;
    started();
    await gate;
  });
  await hasLocks;
  // Session B: the account deletion, started while A is mid-flight. It must WAIT for A's lock (not skip the row).
  const deletion = withOwnership(u.actor, (repo: Repo) => handleMeDelete(repo));
  await new Promise((r) => setTimeout(r, 400));
  release();
  await sessionA;
  await deletion;
  await sess.end();
  assertEquals((await adminSql()`select count(*)::int as n from app.offer_code where id = ${code.id}`)[0]!.n, 0, "the code is gone");
  assertEquals(await offerReserved(offerId), 0, "...and the reservation the in-flight activation took was handed back, not leaked");
});

Deno.test("M1: a deadlock (SQLSTATE 40P01) surfaces as a retryable 503, never an opaque 500", DT, async () => {
  const u = await freshUser("m1-deadlock");
  const x = await newCode(u);
  const y = await newCode(u);
  const { default: postgres } = await import("https://deno.land/x/postgresjs@v3.4.5/mod.js");
  const sess = postgres({ host: Deno.env.get("PGHOST"), port: Number(Deno.env.get("PGPORT")), username: Deno.env.get("PGUSER"), database: Deno.env.get("PGDATABASE"), max: 1, prepare: false });
  let rawHoldsX!: () => void;
  const xLocked = new Promise<void>((r) => (rawHoldsX = r));
  let wHoldsY!: () => void;
  const yLocked = new Promise<void>((r) => (wHoldsY = r));
  // Raw session: locks X, then (after W holds Y) asks for Y. W: locks Y, then asks for X. The FIRST waiter
  // (W, asking for X) is the one whose deadlock check fires first, so W is the victim.
  const raw = sess.begin(async (tx) => {
    await tx`set local role service_role`;
    await tx`select 1 from app.offer_code where id = ${x.id} for update`;
    rawHoldsX();
    await yLocked;
    await new Promise((r) => setTimeout(r, 150)); // W must be waiting on X first
    await tx`select 1 from app.offer_code where id = ${y.id} for update`;
  }).catch((e) => e);
  await xLocked;
  const w = await codeOf(
    withOwnership(u.actor, async (repo: Repo) => {
      await repo.rewards.lockOwnReward(y.id);
      wHoldsY();
      await repo.rewards.lockOwnReward(x.id); // blocks on the raw session; deadlock detected
    }),
  );
  const rawResult = await raw;
  await sess.end();
  assertEquals(w, { status: 503, code: "service_unavailable" }, `the victim must be W (raw result: ${String(rawResult)})`);
});

Deno.test("M3: an ENDED offer does not block a clean activation; the issue path is idempotent against an earn-time reservation", DT, async () => {
  const u = await freshUser("m3-ended");
  const dev = await newDevice(u);
  const offerId = await newOffer({ faceValue: 10 });
  await adminSql()`update app.offer set status = 'ended', valid_to = current_date - 1 where id = ${offerId}`;
  const code = await newCode(u, { offerId });
  assertEquals((await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "issued");
  assertEquals(await offerReserved(offerId), 10);
  // earn-time reservation present: activating neither takes a second one nor releases it
  const offer2 = await newOffer({ faceValue: 10 });
  const code2 = await newCode(u, { offerId: offer2 });
  await adminSql()`update app.offer_code set reserved_amount = 10 where id = ${code2.id}`;
  await adminSql()`update app.offer set budget_reserved = 10 where id = ${offer2}`;
  assertEquals((await activate(u, code2.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT0 }) }))).state, "issued"); // row 5: prior reward exists
  assertEquals(await offerReserved(offer2), 10);
});

Deno.test("M2 probe C: first account, bit0 device, unattestable reward -> held WITH multi_account_device; the hold stores the bits, every matched row and the DeviceCheck month", DT, async () => {
  const u = await freshUser("m2-probe-c");
  const dev = await newDevice(u);
  const code = await newCode(u, { restsOnUnattestable: true });
  const out = await activate(u, code.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT0 }) }));
  assertEquals(out.state, "held_review");
  assertEquals((await signals(u)).map((x) => x.kind), ["multi_account_device"]);
  const hd = (await fullCode(code.id)).hold_detail as Record<string, unknown>;
  assertEquals(hd.matchedRows, [3, 4]);
  assertEquals(hd.primaryRow, 3);
  assertEquals(hd.bits, { bit0: true, bit1: false });
  assertEquals(hd.deviceCheckLastUpdateMonth, "2026-02");
  assertEquals(hd.platform, "ios");
});

Deno.test("LOW re-hold: a code ISSUED before a second device was flagged gets its REMAINING validity back on approval, not a fresh full term", DT, async () => {
  const u = await freshUser("rehold");
  const dev1 = await newDevice(u);
  const dev2 = await newDevice(u);
  const code = await newCode(u, { expiresInDays: 20, earnedDaysAgo: 10 }); // a 30-day term, 20 days left
  assertEquals((await activate(u, code.id, await iosReq(u, dev1), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "issued");
  assertEquals((await activate(u, code.id, await iosReq(u, dev2), deps({ ios: iosPort({ bits: BIT1 }) }))).state, "held_review");
  const held = await fullCode(code.id);
  assertEquals(held.issued_before_hold, true);
  assertEquals(await resolveHeld(code.id, true), "issued");
  const secs = Number((await adminSql()`select extract(epoch from (expires_at - now())) as s from app.offer_code where id = ${code.id}`)[0]!.s);
  assert(Math.abs(secs - 20 * 86400) < 5, `expected ~20 days remaining, got ${secs}s (a full restart would be ~30)`);
});

Deno.test("M4: Repo#rewards.androidInstallSignals / recordInstallLink against real SQL: unlinked device -> null; first writer wins; linked -> counts accounts", DT, async () => {
  const h1 = await linkHashOf(newLink());
  const h2 = await linkHashOf(newLink());
  const a = await freshUser("m4-a");
  const da = await newDevice(a, "android");
  assertEquals(await withOwnership(a.actor, (repo: Repo) => repo.rewards.androidInstallSignals(da)), null, "no link key on the row: nothing can be said");
  await withOwnership(a.actor, (repo: Repo) => repo.rewards.recordInstallLink(da, h1));
  await withOwnership(a.actor, (repo: Repo) => repo.rewards.recordInstallLink(da, h2)); // first writer wins
  assertEquals((await adminSql()`select install_link_hash from app.device where id = ${da}`)[0]!.install_link_hash, h1);
  assertEquals(await withOwnership(a.actor, (repo: Repo) => repo.rewards.androidInstallSignals(da)), { accountsOnInstall: 1, voidedAccountUsedInstall: false });
  const b = await freshUser("m4-b");
  const db = await newDevice(b, "android");
  await withOwnership(b.actor, (repo: Repo) => repo.rewards.recordInstallLink(db, h1));
  assertEquals(await withOwnership(a.actor, (repo: Repo) => repo.rewards.androidInstallSignals(da)), { accountsOnInstall: 2, voidedAccountUsedInstall: false });
  // another user cannot read or write a device that is not theirs
  assertEquals(await withOwnership(b.actor, (repo: Repo) => repo.rewards.androidInstallSignals(da)), null);
});

// ===========================================================================
// P3f gate round 2 (FAIL: N1-N5 + LOW) — against real SQL
// ===========================================================================
Deno.test("N1 probe G: cap for ONE code, two accounts activate cleanly -> the second is HELD (not issued unreserved); both books reconcile at the till; approval needs the cap raised", DT, async () => {
  const offerId = await newOffer({ faceValue: 10, cap: 10 });
  const a = await freshUser("n1-a");
  const b = await freshUser("n1-b");
  const da = await newDevice(a);
  const db = await newDevice(b);
  const ca = await newCode(a, { offerId });
  const cb = await newCode(b, { offerId });
  assertEquals((await activate(a, ca.id, await iosReq(a, da), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "issued");
  const ios = iosPort({ bits: CLEAR });
  const out = await activate(b, cb.id, await iosReq(b, db), deps({ ios }));
  assertEquals(out.state, "held_review");
  assertEquals(ios.calls.setBit0, 0, "no vendor write for a reward that is held for budget (the advisory pre-check)");
  const rowB = await fullCode(cb.id);
  assertEquals([rowB.reserved_amount, (rowB.hold_detail as Record<string, unknown>).heldFor], ["0.00", "offer_budget"]);
  assertEquals((await adminSql()`select count(*)::int as n from app.review_item where kind = 'held_offer_budget_unreserved' and subject_id = ${cb.id}`)[0]!.n, 1);
  // The DATABASE is authoritative, not just the handler's pre-check: a caller that decides "activate" directly gets a hold.
  const c = await freshUser("n1-c");
  const dc = await newDevice(c);
  const cc = await newCode(c, { offerId });
  const direct = await withOwnership(c.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: cc.id, deviceId: dc, tokenHash: null, decision: "activate", holdDetail: null }));
  assertEquals(direct.state, "held_review");
  assertEquals((await fullCode(cc.id)).reserved_amount, "0.00");
  // the till: the issued code is paid; nothing is owed to the held ones
  await adminSql()`select app.consume_offer_budget(${offerId}, 10)`;
  const o = await adminSql()`select budget_used, budget_reserved from app.offer where id = ${offerId}`;
  assertEquals([o[0]!.budget_used, o[0]!.budget_reserved], ["10.00", "0.00"]);
  // approval is refused while the cap cannot cover it...
  let code = "";
  try {
    await resolveHeld(cb.id, true);
  } catch (e) {
    code = (e as { code?: string }).code ?? "";
  }
  assertEquals(code, "23514");
  // ...and succeeds, WITH a reservation, once the cap is raised
  await adminSql()`update app.offer set budget_cap = 20 where id = ${offerId}`;
  assertEquals(await resolveHeld(cb.id, true), "issued");
  assertEquals((await fullCode(cb.id)).reserved_amount, "10.00");
  await adminSql()`select app.consume_offer_budget(${offerId}, 10)`;
});

Deno.test("N2 probe: 6 concurrent activations on ONE offer, each with a 2.4 s DeviceCheck write, all finish together with no 503 and exactly one vendor write each (no vendor I/O under the offer lock)", DT, async () => {
  const offerId = await newOffer({ faceValue: 5, cap: 1000 });
  const users = await Promise.all([1, 2, 3, 4, 5, 6].map((i) => freshUser(`n2-${i}`)));
  const prepared = await Promise.all(
    users.map(async (u) => {
      const dev = await newDevice(u);
      const code = await newCode(u, { offerId });
      const port = iosPort({ bits: CLEAR });
      const orig = port.setBit0.bind(port);
      port.setBit0 = async (t, k) => {
        await new Promise((r) => setTimeout(r, 2400));
        return orig(t, k);
      };
      return { u, dev, code, port, req: await iosReq(u, dev) };
    }),
  );
  const t0 = Date.now();
  const results = await Promise.allSettled(prepared.map((p) => activate(p.u, p.code.id, p.req, deps({ ios: p.port }))));
  const took = Date.now() - t0;
  for (const r of results) assertEquals(r.status, "fulfilled", JSON.stringify(r));
  for (const r of results) assertEquals((r as PromiseFulfilledResult<{ state: string }>).value.state, "issued");
  assert(took < 7000, `6 parallel activations took ${took}ms: the vendor calls serialised behind a lock (6 x 2.4 s would be ~14 s)`);
  for (const p of prepared) assertEquals(p.port.calls.setBit0, 1, "one vendor write per activation — no retries after a 503");
  assertEquals(await offerReserved(offerId), 30);
});

Deno.test("N3 probe E: an open attestation_failed signal holds the review-approved code AND its sibling; once the signal is cleared both activate", DT, async () => {
  const u = await freshUser("n3-e");
  const dev = await newDevice(u);
  const approved = await newCode(u, { state: "held_review" });
  const sibling = await newCode(u);
  await resolveHeld(approved.id, true);
  await adminSql()`insert into app.fraud_signal (id, user_id, kind, detail, created_at) values (${freshUuid()}, ${u.uid}, 'attestation_failed', '{}'::jsonb, now() - interval '1 hour')`;
  assertEquals((await activate(u, approved.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "held_review");
  assertEquals((await activate(u, sibling.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "held_review");
  // the DB backstop agrees, whatever the caller decided
  const approvedAgain = await newCode(u, { state: "held_review" });
  await resolveHeld(approvedAgain.id, true);
  assertEquals(
    await codeOf(withOwnership(u.actor, (repo: Repo) => repo.rewards.applyActivation({ kind: "offer_code", rewardId: approvedAgain.id, deviceId: dev, tokenHash: null, decision: "activate", holdDetail: null }))),
    { status: 409, code: "reward_state_changed" },
  );
  // signal cleared: fresh codes (the held ones now wait for a human) activate
  await adminSql()`update app.fraud_signal set cleared_at = now() where user_id = ${u.uid}`;
  assertEquals((await activate(u, approvedAgain.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: CLEAR }) }))).state, "issued");
  const fresh = await newCode(u);
  assertEquals((await activate(u, fresh.id, await iosReq(u, dev), deps({ ios: iosPort({ bits: BIT0 }) }))).state, "issued");
});

async function deleteAccount(u: User): Promise<void> {
  await withOwnership(u.actor, (repo: Repo) => handleMeDelete(repo));
}
async function tombstonesFor(link: string): Promise<{ n: number; voided: number }> {
  const h = await linkHashOf(link);
  const r = await adminSql()`select count(*)::int as n, count(*) filter (where fraud_voided_at is not null)::int as v from app.install_link_account where install_link_hash = ${h}`;
  return { n: r[0]!.n as number, voided: r[0]!.v as number };
}
async function androidActivate(u: User, dev: string, link: string, codeId: string) {
  const { _nonceBytes: _n, ...req } = await androidReq(u, dev, link);
  return activate(u, codeId, req, deps({ android: androidPort({ grade: "attested" }) }));
}

Deno.test("N4: a fraud-voided account that DELETES ITSELF still taints the install: the next account on it is held with a high-priority signal; the tombstone has no user id and outlives the delete", DT, async () => {
  const link = newLink();
  const v = await freshUser("n4-voided");
  const dv = await newDevice(v, "android");
  const cv = await newCode(v);
  assertEquals((await androidActivate(v, dv, link, cv.id)).state, "issued");
  assertEquals(await tombstonesFor(link), { n: 1, voided: 0 });
  await adminSql()`select app.mark_account_devices_fraud_voided(${v.uid}, ${ADMIN})`;
  await deleteAccount(v);
  assertEquals((await adminSql()`select count(*)::int as n from app.device where id = ${dv}`)[0]!.n, 0, "the device row is gone");
  assertEquals(await tombstonesFor(link), { n: 1, voided: 1 }, "...the tombstone and its fraud mark are not");
  const cols = await adminSql()`select column_name from information_schema.columns where table_schema = 'app' and table_name = 'install_link_account' order by 1`;
  assertEquals(cols.map((c) => c.column_name), ["account_pseudonym", "account_pseudonym_hmac_id", "first_seen_at", "fraud_voided_at", "install_link_hash"]);
  const u = await freshUser("n4-next");
  const du = await newDevice(u, "android");
  const cu = await newCode(u);
  assertEquals((await androidActivate(u, du, link, cu.id)).state, "held_review");
  assertEquals(((await signals(u, "flagged_device_activation"))[0]!.detail as Record<string, unknown>).priority, "high");
});

Deno.test("N4: after 3 accounts with deletions in between, the '> 2 accounts' count still holds: the third account (no prior reward) is held with multi_account_device", DT, async () => {
  const link = newLink();
  for (const i of [1, 2]) {
    const u = await freshUser(`n4-seq-${i}`);
    const d = await newDevice(u, "android");
    const c = await newCode(u);
    assertEquals((await androidActivate(u, d, link, c.id)).state, "issued", `account ${i}`);
    await deleteAccount(u);
  }
  assertEquals((await tombstonesFor(link)).n, 2);
  const third = await freshUser("n4-seq-3");
  const d3 = await newDevice(third, "android");
  const c3 = await newCode(third);
  assertEquals((await androidActivate(third, d3, link, c3.id)).state, "held_review");
  assertEquals((await signals(third)).map((x) => x.kind), ["multi_account_device"]);
  assertEquals((await tombstonesFor(link)).n, 3);
  // the export carries no trace of it, and the account's own export still works
  const exp = await adminSql()`select private.export_my_data(${third.uid}) as r`;
  assertEquals(JSON.stringify(exp[0]!.r).includes("install_link_account"), false);
});

Deno.test("N5: two plays whose codes sit on the same offers in OPPOSITE order, held at the same moment, never deadlock (cascade locks code(id) -> offer(id))", DT, async () => {
  const { default: postgres } = await import("https://deno.land/x/postgresjs@v3.4.5/mod.js");
  const mk = () => postgres({ host: Deno.env.get("PGHOST"), port: Number(Deno.env.get("PGPORT")), username: Deno.env.get("PGUSER"), database: Deno.env.get("PGDATABASE"), max: 1, prepare: false });
  const s1 = mk();
  const s2 = mk();
  const playFor = (u: User, round: number) =>
    withOwnership(u.actor, async (repo: Repo) =>
      (await repo.play.upsertFromScore({
        courseId: CRS_X1, facilityId: FAC_X, playDate: new Date(Date.now() - (200 + round) * 86400_000).toISOString().slice(0, 10), courseDisambiguatedBy: null,
        scoreBadge: 0.6, scoreMonetary: 0.9, hardSignal: true, presenceSignal: true, money: true, heldReview: false,
        policyVersion: "v1", inputDigest: "a".repeat(64), evidenceIds: [],
      })).id);
  try {
    for (let round = 0; round < 12; round++) {
      const offers: string[] = [];
      for (let i = 0; i < 8; i++) offers.push(await newOffer({ faceValue: 1 }));
      // A user holds one code per offer, so the two plays belong to two users; their codes cover the same
      // 8 offers, inserted (and therefore scanned) in OPPOSITE order.
      const u1 = await freshUser(`n5a-${round}`);
      const u2 = await freshUser(`n5b-${round}`);
      const p1 = await playFor(u1, round);
      const p2 = await playFor(u2, round);
      for (const [u, playId, order] of [[u1, p1, offers], [u2, p2, [...offers].reverse()]] as const) {
        for (const offerId of order) {
          const c = await newCode(u, { offerId });
          await adminSql()`update app.offer_code set play_id = ${playId} where id = ${c.id}`;
        }
      }
      const hold = (sess: ReturnType<typeof mk>, playId: string) =>
        sess.begin(async (tx) => {
          await tx`set local role service_role`;
          await tx`update app.play set held_review = true where id = ${playId}`;
        });
      const results = await Promise.allSettled([hold(s1, p1), hold(s2, p2)]);
      for (const r of results) assertEquals(r.status, "fulfilled", `round ${round}: ${JSON.stringify(r)}`);
      assertEquals((await adminSql()`select count(*)::int as n from app.offer_code where play_id in (${p1}, ${p2}) and state = 'held_review'`)[0]!.n, 16);
    }
  } finally {
    await s1.end();
    await s2.end();
  }
});

Deno.test("LOW: a transaction_timeout FATAL (connection killed mid-transaction) answers 503 and does NOT escape as an uncaught postgres.js TypeError", DT, async () => {
  // `transaction_timeout` is PostgreSQL 17+. On 16 the GUC does not exist, privileged.ts (supportsTransactionTimeout) correctly
  // never sets it, so there is no FATAL to survive: say so loudly rather than fail on a premise the server cannot meet.
  if ((await adminSql()`select 1 from pg_settings where name = 'transaction_timeout'`).length === 0) {
    console.warn("SKIPPED (not a pass): this server has no transaction_timeout GUC (PostgreSQL < 17); the FATAL this test provokes cannot happen");
    return;
  }
  const u = await freshUser("tx-timeout");
  const before = getContainedClosedSocketWrites();
  let status = 0;
  try {
    await withOwnership(u.actor, async (repo: Repo) => {
      await repo.device.countForUser();
      await new Promise((r) => setTimeout(r, 13_500)); // transaction_timeout is 12 s
      await repo.device.countForUser(); // queued onto the dead connection: postgres.js's nextWrite then hits a null socket
    });
  } catch (e) {
    if (e instanceof HttpError) status = e.status;
  }
  assertEquals(status, 503);
  // An uncaught error would fail the runner here. The write onto the dead connection happens when the operation's own 13.5 s
  // sleep ends, i.e. only a few ms after the 12 s kill + 1.5 s this test used to wait -- a margin that edge mode's slightly
  // longer set-up (role, timeouts, bind) before the sleep tipped the wrong way. Poll for the guard instead of racing it.
  for (let i = 0; i < 50 && getContainedClosedSocketWrites() <= before; i++) await new Promise((r) => setTimeout(r, 100));
  await new Promise((r) => setTimeout(r, 300));
  assert(getContainedClosedSocketWrites() > before, "the guard counted the contained write");
});

Deno.test("F20: the closed-socket guard matches ONLY the pinned postgres.js module URL (and only that exact TypeError)", DT, () => {
  const mk = (msg: string, stackFile: string, fn = "nextWrite") => {
    const e = new TypeError(msg);
    e.stack = `TypeError: ${msg}\n    at ${fn} (${stackFile}:253:22)`;
    return e;
  };
  const MSG = "Cannot read properties of null (reading 'write')";
  assertEquals(isPostgresJsClosedSocketWrite(mk(MSG, "https://deno.land/x/postgresjs@v3.4.5/src/connection.js")), true);
  assertEquals(isPostgresJsClosedSocketWrite(mk(MSG, "https://deno.land/x/postgresjs@v3.4.6/src/connection.js")), false, "another version: not ours");
  assertEquals(isPostgresJsClosedSocketWrite(mk(MSG, "file:///app/some/connection.js")), false, "same file name elsewhere");
  assertEquals(isPostgresJsClosedSocketWrite(mk(MSG, "https://deno.land/x/postgresjs@v3.4.5/src/connection.js", "other")), false, "another function");
  assertEquals(isPostgresJsClosedSocketWrite(mk("Cannot read properties of null (reading 'read')", "https://deno.land/x/postgresjs@v3.4.5/src/connection.js")), false);
  assertEquals(isPostgresJsClosedSocketWrite(new Error(MSG)), false, "not a TypeError");
});
