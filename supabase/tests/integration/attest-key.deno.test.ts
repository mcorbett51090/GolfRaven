// supabase/tests/integration/attest-key.deno.test.ts
//
// App Attest KEY REGISTRATION (`POST /v1/devices/attest-key`, 0034): the REAL handler
// (_shared/rewards/attest-key-handler.ts) and the REAL verifier (_shared/rewards/app-attest-registration.ts) through
// the REAL `withOwnership` and the REAL `Repo#attestKey` (privileged.ts), against the real SQL function
// app.register_attest_key and its trigger, on the harness cluster tools/db/test.sh builds, in BOTH harness modes.
//
// ⚠ The attestations are SYNTHETIC: built with Web Crypto against a throw-away root CA the test verifier is given in
// place of Apple's pinned one (attest-test-pki.ts). There is no iPhone, Apple account or network route in this
// environment, so this proves the server is self-consistent and fails closed, not that a real device's attestation
// verifies (`[unverified]`; docs/security/p3-money-path-requirements.md, "App Attest key registration").
//
// The last tests close the loop with rewards-activate: a device grades `attested` (and an activation is issued) only
// after a key was registered through the verified path, using the registered key's real private half to sign the
// assertion.

import { assert, assertEquals, assertNotEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, freshUuid, makeActor, FAC_X } from "./_helpers.ts";
import { loadAttestKeyVerifierConfig, withOwnership } from "../../functions/_shared/privileged.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleMeDelete } from "../../functions/_shared/me/delete-handler.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import { createAttestationVerifier, computeAttestKeyBinding } from "../../functions/_shared/rewards/app-attest-registration.ts";
import { APPLE_APP_ATTEST_ROOT_DER } from "../../functions/_shared/rewards/apple-app-attest-root.ts";
import { handleAttestKey, type AttestKeyDeps } from "../../functions/_shared/rewards/attest-key-handler.ts";
import type { AttestKeyRequest } from "../../functions/_shared/rewards/attest-key-request.ts";
import { handleActivation } from "../../functions/_shared/rewards/activate-handler.ts";
import { fromBase64UrlStrict, toHex } from "../../functions/_shared/rewards/binding.ts";
import { computeIosActivationBinding } from "../../functions/_shared/rewards/string-binding.ts";
import { verifyAppAttestAssertion, verifyP256WebCrypto } from "../../functions/_shared/rewards/app-attest.ts";
import type { DeviceBits, IosPort } from "../../functions/_shared/rewards/types.ts";
import type { Repo } from "../../functions/_shared/types.ts";
import { buildAttestation, buildTestPki, genPair, toB64, type Pair, type TestPki } from "../unit/attest-test-pki.ts";
import { buildAssertion, sha256 } from "../unit/rewards-test-crypto.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const APP_ID = "TEAMID1234.com.example.golfraven";
const CLEAR: DeviceBits = { bit0: false, bit1: false, lastUpdateMonth: null };
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));

let pki: TestPki;
async function pkiOnce(): Promise<TestPki> {
  return (pki ??= await buildTestPki({ nowMs: Date.now() }));
}
async function depsFor(over: Partial<AttestKeyDeps> = {}): Promise<AttestKeyDeps> {
  const p = await pkiOnce();
  return { verifier: createAttestationVerifier({ appId: APP_ID, environment: "production", trustAnchorDer: p.rootDer }, { sha256 }), sha256, ...over };
}

async function freshUser(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `ak-${label}-${uid.slice(0, 8)}`);
  return { uid, actor: makeActor(uid) };
}
type User = Awaited<ReturnType<typeof freshUser>>;

async function newDevice(u: User, platform: "ios" | "android" = "ios"): Promise<string> {
  return withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), platform)).id);
}

async function issueLive(u: User, deviceId: string): Promise<{ challengeId: string; nonce: string; nonceBytes: Uint8Array }> {
  const issued = await withOwnership(u.actor, (repo: Repo) => handleChallengeRequest({ deviceId }, repo, randomBytes, digestHex));
  const c = issued[0]!;
  return { challengeId: c.id, nonce: c.nonce, nonceBytes: fromBase64UrlStrict(c.nonce)! };
}

interface Built {
  req: AttestKeyRequest;
  leaf: Pair;
  keyId: string;
}
/** An attestation bound to (challenge, device, key) — valid unless `over` breaks something. */
async function buildReq(
  deviceId: string,
  ch: { challengeId: string; nonce: string; nonceBytes: Uint8Array },
  over: { leaf?: Pair; bindChallengeId?: string; environment?: "production" | "development" } = {},
): Promise<Built> {
  const leaf = over.leaf ?? (await genPair("P-256"));
  const keyId = toB64(await sha256(leaf.point));
  const clientDataHash = await computeAttestKeyBinding(sha256, { challengeId: over.bindChallengeId ?? ch.challengeId, deviceId, keyId, nonce: ch.nonce });
  const built = await buildAttestation({ pki: await pkiOnce(), appId: APP_ID, environment: over.environment ?? "production", clientDataHash, leaf });
  return { req: { deviceId, challengeId: ch.challengeId, nonce: ch.nonce, keyId, attestation: built.attestationB64 }, leaf, keyId };
}

async function register(u: User, req: AttestKeyRequest, d?: AttestKeyDeps) {
  const deps = d ?? (await depsFor());
  return withOwnership(u.actor, (repo: Repo) => handleAttestKey(req, repo, deps));
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

async function deviceRow(id: string) {
  const rows = await adminSql()`select attest_key_id, attest_public_key, attest_counter, attest_registered_at, attest_retired_key_hashes from app.device where id = ${id}`;
  return rows[0]!;
}
async function challengeUsed(id: string): Promise<boolean> {
  const rows = await adminSql()`select used_at from app.checkin_challenge where id = ${id}`;
  return rows[0]!.used_at !== null;
}
async function auditRows(deviceId: string) {
  return adminSql()`select action, actor_user_id, detail from app.audit_log where subject_id = ${deviceId} and action like 'device.attest_key_%' order by created_at, id`;
}
async function attestState(u: User, deviceId: string) {
  return withOwnership(u.actor, (repo: Repo) => repo.rewards.deviceAttestState(deviceId));
}

// ===========================================================================
// Registration
// ===========================================================================
Deno.test("registers the attested key on the caller's own device through real SQL, audits it, and hands the verifier the key", DT, async () => {
  const u = await freshUser("reg");
  const dev = await newDevice(u);
  assertEquals((await attestState(u, dev))!.attestPublicKey, null, "before registration: no key");
  const ch = await issueLive(u, dev);
  const b = await buildReq(dev, ch);
  const out = await register(u, b.req);
  assertEquals(out, { ok: true, status: 201, body: { deviceId: dev, keyId: b.keyId, replaced: false } });

  const row = await deviceRow(dev);
  assertEquals(row.attest_key_id, b.keyId);
  assertEquals(Array.from(row.attest_public_key as Uint8Array), Array.from(b.leaf.point));
  assertEquals(Number(row.attest_counter), 0);
  assert(row.attest_registered_at !== null);
  assertEquals(row.attest_retired_key_hashes, []);
  assert(await challengeUsed(ch.challengeId), "the challenge was spent");

  const state = (await attestState(u, dev))!;
  assertEquals(state.attestKeyId, b.keyId);
  assertEquals(Array.from(state.attestPublicKey!), Array.from(b.leaf.point));

  const audit = await auditRows(dev);
  assertEquals(audit.length, 1);
  assertEquals(audit[0]!.action, "device.attest_key_registered");
  assertEquals(audit[0]!.actor_user_id, u.uid);
  assert(!JSON.stringify(audit[0]!.detail).includes(b.keyId), "the audit row carries no key id");
});

Deno.test("a key written outside the verified path (no attest_registered_at) is NOT handed to the assertion verifier: unattestable, never attested", DT, async () => {
  const u = await freshUser("unregistered");
  const dev = await newDevice(u);
  const leaf = await genPair("P-256");
  await adminSql()`update app.device set attest_key_id = ${toB64(await sha256(leaf.point))}, attest_public_key = ${leaf.point} where id = ${dev}`;
  const s = (await attestState(u, dev))!;
  assertEquals(s.attestPublicKey, null);
  assertEquals(s.attestKeyId, null);
});

Deno.test("re-registration (a reinstall): a NEW key replaces the old one, the counter restarts at 0, the old key is retired, the change is audited, and the old key cannot return", DT, async () => {
  const u = await freshUser("replace");
  const dev = await newDevice(u);
  const first = await buildReq(dev, await issueLive(u, dev));
  await register(u, first.req);
  await adminSql()`update app.device set attest_counter = 40 where id = ${dev}`;

  const second = await buildReq(dev, await issueLive(u, dev));
  const out = await register(u, second.req);
  assertEquals(out, { ok: true, status: 200, body: { deviceId: dev, keyId: second.keyId, replaced: true } });
  const row = await deviceRow(dev);
  assertEquals(row.attest_key_id, second.keyId);
  assertEquals(Number(row.attest_counter), 0);
  assertEquals((row.attest_retired_key_hashes as string[]).length, 1);
  const audit = await auditRows(dev);
  assertEquals(audit.map((a) => a.action), ["device.attest_key_registered", "device.attest_key_replaced"]);
  assertEquals((audit[1]!.detail as Record<string, unknown>).counterBefore, 40);

  // The OLD key (a fresh attestation of it, bound to a fresh challenge) cannot be registered again.
  const ch = await issueLive(u, dev);
  const back = await buildReq(dev, ch, { leaf: first.leaf });
  assertEquals(await codeOf(register(u, back.req)), { status: 409, code: "key_previously_retired" });
  assertEquals((await deviceRow(dev)).attest_key_id, second.keyId);
  assertEquals(await challengeUsed(ch.challengeId), false, "the refused request rolled back, so the challenge is still unused");
});

Deno.test("registering the SAME key again is a 409 and spends nothing", DT, async () => {
  const u = await freshUser("same");
  const dev = await newDevice(u);
  const first = await buildReq(dev, await issueLive(u, dev));
  await register(u, first.req);
  await adminSql()`update app.device set attest_counter = 3 where id = ${dev}`;
  const ch = await issueLive(u, dev);
  assertEquals(await codeOf(register(u, { ...first.req, challengeId: ch.challengeId, nonce: ch.nonce })), { status: 409, code: "key_already_registered" });
  assertEquals(Number((await deviceRow(dev)).attest_counter), 3, "the counter was not reset by a repeat registration");
  assertEquals(await challengeUsed(ch.challengeId), false);
});

// ===========================================================================
// MUST-FAIL
// ===========================================================================
Deno.test("a failed attestation spends the challenge in the database and stores nothing; the same challenge cannot be tried again", DT, async () => {
  const u = await freshUser("fail");
  const dev = await newDevice(u);
  const ch = await issueLive(u, dev);
  const wrong = await buildReq(dev, ch, { bindChallengeId: freshUuid() }); // bound to another challenge id
  const out = await register(u, wrong.req);
  assertEquals(out.ok, false);
  if (!out.ok) assertEquals([out.status, out.code], [422, "attestation_rejected"]);
  assert(await challengeUsed(ch.challengeId), "a FAILED attempt still spends the challenge (the transaction committed)");
  assertEquals((await deviceRow(dev)).attest_key_id, null);
  assertEquals((await auditRows(dev)).length, 0);
  assertEquals((await adminSql()`select count(*)::int as n from app.fraud_signal where user_id = ${u.uid}`)[0]!.n, 0, "a failed registration raises no account-wide signal");
  // A good attestation on the spent challenge is refused.
  const good = await buildReq(dev, ch);
  assertEquals(await codeOf(register(u, good.req)), { status: 422, code: "challenge_not_consumable" });
  assertEquals((await deviceRow(dev)).attest_key_id, null);
});

Deno.test("a replayed challenge is refused after a success, and two concurrent requests on ONE challenge register exactly one key", DT, async () => {
  const u = await freshUser("replay");
  const dev = await newDevice(u);
  const ch = await issueLive(u, dev);
  const a = await buildReq(dev, ch);
  const b = await buildReq(dev, ch);
  const results = await Promise.allSettled([register(u, a.req), register(u, b.req)]);
  const fulfilled = results.filter((r) => r.status === "fulfilled" && (r.value as { ok: boolean }).ok);
  const rejected = results.filter((r) => r.status === "rejected");
  assertEquals(fulfilled.length, 1, "exactly one request wins the single-use challenge");
  assertEquals(rejected.length, 1);
  assertEquals(((rejected[0] as PromiseRejectedResult).reason as HttpError).code, "challenge_not_consumable");
  const row = await deviceRow(dev);
  assert(row.attest_key_id === a.keyId || row.attest_key_id === b.keyId);
  assertEquals((await auditRows(dev)).length, 1);
  // And afterwards the same challenge is simply dead.
  const c = await buildReq(dev, ch);
  assertEquals(await codeOf(register(u, c.req)), { status: 422, code: "challenge_not_consumable" });
});

Deno.test("another user's device and a nonexistent device are the same 422; the other user's device and challenge are untouched", DT, async () => {
  const a = await freshUser("own-a");
  const b = await freshUser("own-b");
  const aDev = await newDevice(a);
  const bDev = await newDevice(b);
  const aCh = await issueLive(a, aDev);
  const bCh = await issueLive(b, bDev);
  // A names B's device with A's own challenge.
  assertEquals(await codeOf(register(a, (await buildReq(bDev, aCh)).req)), { status: 422, code: "challenge_not_consumable" });
  // A names its own device with B's challenge.
  assertEquals(await codeOf(register(a, (await buildReq(aDev, bCh)).req)), { status: 422, code: "challenge_not_consumable" });
  // A names a device that does not exist.
  assertEquals(await codeOf(register(a, (await buildReq(freshUuid(), aCh)).req)), { status: 422, code: "challenge_not_consumable" });
  assertEquals((await deviceRow(bDev)).attest_key_id, null);
  assertEquals((await deviceRow(aDev)).attest_key_id, null);
  assertEquals(await challengeUsed(aCh.challengeId), false);
  assertEquals(await challengeUsed(bCh.challengeId), false);
  // The controls: each user can register its own.
  assertEquals((await register(a, (await buildReq(aDev, aCh)).req)).ok, true);
  assertEquals((await register(b, (await buildReq(bDev, bCh)).req)).ok, true);
});

Deno.test("an Android device cannot register an App Attest key (422 platform_mismatch); unconfigured is a 503 that spends nothing", DT, async () => {
  const u = await freshUser("android");
  const dev = await newDevice(u, "android");
  const ch = await issueLive(u, dev);
  assertEquals(await codeOf(register(u, (await buildReq(dev, ch)).req)), { status: 422, code: "platform_mismatch" });
  const ios = await newDevice(u);
  const ch2 = await issueLive(u, ios);
  const deps = await depsFor({ verifier: null });
  assertEquals(await codeOf(register(u, (await buildReq(ios, ch2)).req, deps)), { status: 503, code: "attestation_not_configured" });
  assertEquals(await challengeUsed(ch2.challengeId), false);
  assertEquals((await deviceRow(ios)).attest_key_id, null);
});

Deno.test("two concurrent registrations of DIFFERENT keys on one device serialise on the row lock: one 'registered', one 'replaced', one key current, one retired", DT, async () => {
  const u = await freshUser("race");
  const dev = await newDevice(u);
  const a = await buildReq(dev, await issueLive(u, dev));
  const b = await buildReq(dev, await issueLive(u, dev));
  const [ra, rb] = await Promise.all([register(u, a.req), register(u, b.req)]);
  assert(ra.ok && rb.ok);
  const replaced = [ra, rb].filter((r) => r.ok && r.body.replaced).length;
  assertEquals(replaced, 1);
  const row = await deviceRow(dev);
  assert([a.keyId, b.keyId].includes(row.attest_key_id as string));
  assertEquals((row.attest_retired_key_hashes as string[]).length, 1);
  assertEquals(Number(row.attest_counter), 0);
  assertEquals((await auditRows(dev)).length, 2);
});

Deno.test("the row lock is real: a second registration that starts while the first is uncommitted WAITS, then sees the first (registered + replaced, never two 'registered')", DT, async () => {
  const u = await freshUser("rowlock");
  const dev = await newDevice(u);
  const a = await genPair("P-256");
  const b = await genPair("P-256");
  const keyOf = async (pair: Pair) => toB64(await sha256(pair.point));
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const pA = withOwnership(u.actor, async (repo: Repo) => {
    const r = await repo.attestKey.register({ deviceId: dev, keyId: await keyOf(a), publicKey: a.point });
    await gate; // hold the transaction (and the row lock) open
    return r;
  });
  await sleep(300); // A has written and is still uncommitted
  const pB = withOwnership(u.actor, async (repo: Repo) => repo.attestKey.register({ deviceId: dev, keyId: await keyOf(b), publicKey: b.point }));
  await sleep(500); // B is blocked on the row lock (correct) or has already read a stale row (the bug)
  release();
  const results = await Promise.all([pA, pB]);
  assertEquals([...results].sort(), ["registered", "replaced"]);
  assertEquals((await deviceRow(dev)).attest_key_id, await keyOf(b));
  assertEquals(((await deviceRow(dev)).attest_retired_key_hashes as string[]).length, 1);
});

Deno.test("a database P0002 (no such device for this caller) is the documented no-oracle 422 challenge_not_consumable, never a 404 — a nonexistent id and ANOTHER user's id alike", DT, async () => {
  const u = await freshUser("p0002");
  const other = await freshUser("p0002-other");
  const foreignDev = await newDevice(other);
  const leaf = await genPair("P-256");
  const keyId = toB64(await sha256(leaf.point));
  // Straight to the repo (the handler's own-device read would have answered first): the SQL function raises P0002.
  const answer = (deviceId: string) =>
    withOwnership(u.actor, (repo: Repo) => repo.attestKey.register({ deviceId, keyId, publicKey: leaf.point })).then(
      () => null,
      (e: unknown) => (e instanceof HttpError ? { status: e.status, code: e.code } : { thrown: String(e) }),
    );
  const nonexistent = await answer(freshUuid());
  const foreign = await answer(foreignDev);
  assertEquals(nonexistent, { status: 422, code: "challenge_not_consumable" });
  assertEquals(foreign, nonexistent, "another user's device is indistinguishable from a nonexistent one");
  assertEquals((await deviceRow(foreignDev)).attest_key_id, null, "and nothing was written to the foreign device");
});

Deno.test("the database refuses what the verifier would never send: a key id that is not the hash of the key, a rolled-back counter", DT, async () => {
  const u = await freshUser("db");
  const dev = await newDevice(u);
  const leaf = await genPair("P-256");
  const other = await genPair("P-256");
  const code = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      return null;
    } catch (e) {
      return (e as { code?: string }).code ?? "?";
    }
  };
  // Straight to the repo: the handler would have refused first.
  const direct = (keyId: string, key: Uint8Array) => withOwnership(u.actor, (repo: Repo) => repo.attestKey.register({ deviceId: dev, keyId, publicKey: key }));
  assertEquals(await direct(toB64(await sha256(leaf.point)), other.point).then(() => null, (e: unknown) => (e as HttpError).code), "attestation_rejected");
  assertEquals((await deviceRow(dev)).attest_key_id, null);
  await direct(toB64(await sha256(leaf.point)), leaf.point);
  await adminSql()`update app.device set attest_counter = 9 where id = ${dev}`;
  assertEquals(await code(() => adminSql()`update app.device set attest_counter = 2 where id = ${dev}`), "23514");
  assertEquals(Number((await deviceRow(dev)).attest_counter), 9);
});

Deno.test("deleting the account deletes its key and redacts the audit rows", DT, async () => {
  const u = await freshUser("delete");
  const dev = await newDevice(u);
  await register(u, (await buildReq(dev, await issueLive(u, dev))).req);
  await withOwnership(u.actor, (repo: Repo) => handleMeDelete(repo));
  assertEquals((await adminSql()`select count(*)::int as n from app.device where id = ${dev}`)[0]!.n, 0);
  const audit = await adminSql()`select actor_user_id from app.audit_log where subject_id = ${dev} and action = 'device.attest_key_registered'`;
  assertEquals(audit.length, 1);
  assertEquals(audit[0]!.actor_user_id, null);
});

// ===========================================================================
// Configuration: the loader in privileged.ts
// ===========================================================================
Deno.test("loadAttestKeyVerifierConfig: null unless EVERY variable is present and sane; the trust anchor is the pinned Apple root, never configuration", DT, () => {
  const names = ["GR_APPLE_TEAM_ID", "GR_APPLE_BUNDLE_ID", "GR_APPLE_APPATTEST_ENV"];
  const saved = names.map((n) => Deno.env.get(n));
  const set = (team?: string, bundle?: string, env?: string) => {
    for (const [n, v] of [[names[0]!, team], [names[1]!, bundle], [names[2]!, env]] as const) {
      if (v === undefined) Deno.env.delete(n);
      else Deno.env.set(n, v);
    }
  };
  try {
    set();
    assertEquals(loadAttestKeyVerifierConfig(), null, "nothing set");
    set("TEAMID1234", "com.example.app", undefined);
    assertEquals(loadAttestKeyVerifierConfig(), null, "no environment");
    set("TEAMID1234", undefined, "production");
    assertEquals(loadAttestKeyVerifierConfig(), null, "no bundle id");
    set(undefined, "com.example.app", "production");
    assertEquals(loadAttestKeyVerifierConfig(), null, "no team id");
    set("TEAMID1234", "com.example.app", "staging");
    assertEquals(loadAttestKeyVerifierConfig(), null, "an unknown environment is not a default");
    set("TEAM ID", "com.example.app", "production");
    assertEquals(loadAttestKeyVerifierConfig(), null, "whitespace in an id");
    set("  ", "com.example.app", "production");
    assertEquals(loadAttestKeyVerifierConfig(), null, "a blank id");
    set("TEAMID1234", "com.example.app", "production");
    const prod = loadAttestKeyVerifierConfig()!;
    assertEquals(prod.appId, "TEAMID1234.com.example.app");
    assertEquals(prod.environment, "production");
    assertEquals(Array.from(prod.trustAnchorDer), Array.from(APPLE_APP_ATTEST_ROOT_DER), "the anchor is the PINNED root");
    set("TEAMID1234", "com.example.app", "development");
    assertEquals(loadAttestKeyVerifierConfig()!.environment, "development");
    // No variable can change the anchor: setting plausible names changes nothing.
    Deno.env.set("GR_APPLE_APPATTEST_ROOT", "AAAA");
    Deno.env.set("GR_APPLE_TRUST_ANCHOR", "AAAA");
    assertEquals(Array.from(loadAttestKeyVerifierConfig()!.trustAnchorDer), Array.from(APPLE_APP_ATTEST_ROOT_DER));
    Deno.env.delete("GR_APPLE_APPATTEST_ROOT");
    Deno.env.delete("GR_APPLE_TRUST_ANCHOR");
  } finally {
    names.forEach((n, i) => (saved[i] === undefined ? Deno.env.delete(n) : Deno.env.set(n, saved[i]!)));
  }
});

Deno.test("a verifier built from the PRODUCTION wiring (pinned Apple root) rejects an attestation chained to a test root", DT, async () => {
  const u = await freshUser("prodroot");
  const dev = await newDevice(u);
  const ch = await issueLive(u, dev);
  const b = await buildReq(dev, ch);
  const prodVerifier = createAttestationVerifier({ appId: APP_ID, environment: "production", trustAnchorDer: APPLE_APP_ATTEST_ROOT_DER }, { sha256 });
  const out = await register(u, b.req, await depsFor({ verifier: prodVerifier }));
  assertEquals(out.ok, false);
  assertEquals((await deviceRow(dev)).attest_key_id, null);
});

// ===========================================================================
// The loop with rewards-activate: attested requires a REGISTERED key
// ===========================================================================
async function newOfferAndCode(u: User): Promise<string> {
  const offerId = freshUuid();
  await adminSql()`set role service_role`;
  await adminSql()`
    insert into app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
    values (${offerId}, 'trl_t', ${FAC_X}, '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live')`;
  const id = freshUuid();
  await adminSql()`
    insert into app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at)
    values (${id}, ${offerId}, ${u.uid}, ${FAC_X}, 'earned', now() - interval '10 days', now() + interval '20 days')`;
  return id;
}

function realIosPort(): IosPort {
  return {
    verifyAssertion: (input) => verifyAppAttestAssertion(input, { appId: APP_ID }, { sha256, verifyP256: verifyP256WebCrypto }),
    readBits: async () => CLEAR,
    setBit0: async () => {},
  };
}

const TOKEN = "REVWSUNF";
async function signedActivation(u: User, deviceId: string, rewardId: string, key: { keyId: string; leaf: Pair }, counter: number) {
  const ch = await issueLive(u, deviceId);
  const hash = await computeIosActivationBinding(sha256, { rewardId, deviceId, challengeId: ch.challengeId, deviceCheckTokenSha256: await digestHex(new TextEncoder().encode(TOKEN)), nonce: ch.nonce });
  const built = await buildAssertion({ key: { privateKey: key.leaf.privateKey, publicKeyRaw: key.leaf.point }, appId: APP_ID, counter, clientDataHash: hash });
  return { deviceId, platform: "ios" as const, challengeId: ch.challengeId, nonce: ch.nonce, attestation: { kind: "ios" as const, keyId: key.keyId, assertion: built.assertionB64, deviceCheckToken: TOKEN } };
}
const activate = (u: User, rewardId: string, req: Awaited<ReturnType<typeof signedActivation>>) =>
  withOwnership(u.actor, (repo: Repo) => handleActivation(rewardId, req, repo, { ports: { ios: realIosPort(), android: null }, sha256 }));

Deno.test("end to end: before registration an iOS activation is held (unattestable); after a verified registration the SAME device grades attested and the reward is issued", DT, async () => {
  const u = await freshUser("e2e");
  const dev = await newDevice(u);
  const leaf = await genPair("P-256");
  const keyId = toB64(await sha256(leaf.point));

  // Before: no registered key. The activation carries a (real) assertion signed by a key the server has never seen.
  const code1 = await newOfferAndCode(u);
  const before = await activate(u, code1, await signedActivation(u, dev, code1, { keyId, leaf }, 1));
  assertEquals(before.state, "held_review", "no registered key -> unattestable -> held");
  const grade = (await adminSql()`select integrity_last from app.device where id = ${dev}`)[0]!.integrity_last as { grade: string };
  assertEquals(grade.grade, "unattestable");
  assertEquals((await adminSql()`select count(*)::int as n from app.fraud_signal where user_id = ${u.uid} and kind = 'attestation_failed'`)[0]!.n, 0, "unattestable is not failed: no account-wide signal");

  // Register the key through the verified path.
  const reg = await register(u, (await buildReq(dev, await issueLive(u, dev), { leaf })).req);
  assertEquals(reg.ok && reg.body.keyId, keyId);

  // After: the same device, a fresh reward, an assertion signed by the registered key.
  const code2 = await newOfferAndCode(u);
  const after = await activate(u, code2, await signedActivation(u, dev, code2, { keyId, leaf }, 1));
  assertEquals(after.state, "issued", "a registered key -> attested -> issued");
  assertEquals(Number((await deviceRow(dev)).attest_counter), 1, "the assertion counter advanced");
  const grade2 = (await adminSql()`select integrity_last from app.device where id = ${dev}`)[0]!.integrity_last as { grade: string };
  assertEquals(grade2.grade, "attested");
});

Deno.test("end to end: after a REINSTALL the new key's assertions verify from counter 1 (the counter restarted), and the OLD key's assertions are graded failed", DT, async () => {
  const u = await freshUser("e2e-reinstall");
  const dev = await newDevice(u);
  const oldLeaf = await genPair("P-256");
  const oldKeyId = toB64(await sha256(oldLeaf.point));
  await register(u, (await buildReq(dev, await issueLive(u, dev), { leaf: oldLeaf })).req);
  // The old install advanced its counter well past the new install's first assertions.
  const c0 = await newOfferAndCode(u);
  assertEquals((await activate(u, c0, await signedActivation(u, dev, c0, { keyId: oldKeyId, leaf: oldLeaf }, 25))).state, "issued");
  assertEquals(Number((await deviceRow(dev)).attest_counter), 25);

  const newLeaf = await genPair("P-256");
  const newKeyId = toB64(await sha256(newLeaf.point));
  const replaced = await register(u, (await buildReq(dev, await issueLive(u, dev), { leaf: newLeaf })).req);
  assertEquals(replaced.ok && replaced.body.replaced, true);
  assertEquals(Number((await deviceRow(dev)).attest_counter), 0);

  // The new key, counter 1 (< the old key's 25): verifies, because the counter restarted with the key.
  const c1 = await newOfferAndCode(u);
  assertEquals((await activate(u, c1, await signedActivation(u, dev, c1, { keyId: newKeyId, leaf: newLeaf }, 1))).state, "issued");
  // The OLD key's assertion (a captured one, even with a high counter): the key id no longer matches -> failed -> signal, held.
  const c2 = await newOfferAndCode(u);
  const out = await activate(u, c2, await signedActivation(u, dev, c2, { keyId: oldKeyId, leaf: oldLeaf }, 99));
  assertEquals(out.state, "held_review");
  const sig = (await adminSql()`select detail from app.fraud_signal where user_id = ${u.uid} and kind = 'attestation_failed'`)[0]!.detail as { reasons: string[] };
  assertEquals(sig.reasons, ["key_id_mismatch"]);
  assertNotEquals(Number((await deviceRow(dev)).attest_counter), 99, "the old key's counter was never accepted");
});

// ===========================================================================
// The race: a key replacement that commits DURING an in-flight activation (LOW-1)
// ===========================================================================
// `deviceAttestState` reads the device row without a lock, then the verifier runs (no database), then
// `advanceAttestCounter` writes. Under READ COMMITTED a registration that commits in that window changes the row the
// UPDATE lands on. This test makes the window deterministic: an IosPort whose `verifyAssertion` runs the REAL verifier
// against the state the handler read (key K1, counter 41, so the assertion is genuinely valid), and THEN commits a
// replacement K2 through the real register path (its own transaction, its own connection) before returning the ok
// verdict. Both EDGE_DB_MODEs run this file, so it covers both statements `advanceAttestCounter` can issue.
Deno.test("race: a key replacement that commits while an activation is in flight does not let the RETIRED key's assertion issue the reward, and the new key does not inherit its counter", DT, async () => {
  const u = await freshUser("race");
  const dev = await newDevice(u);
  const k1 = await genPair("P-256");
  const k1Id = toB64(await sha256(k1.point));
  const k2 = await genPair("P-256");
  const k2Id = toB64(await sha256(k2.point));
  await register(u, (await buildReq(dev, await issueLive(u, dev), { leaf: k1 })).req);

  // K1 has advanced to 40 on an earlier activation; the in-flight one presents 41.
  const c0 = await newOfferAndCode(u);
  assertEquals((await activate(u, c0, await signedActivation(u, dev, c0, { keyId: k1Id, leaf: k1 }, 40))).state, "issued");
  assertEquals(Number((await deviceRow(dev)).attest_counter), 40);

  // Everything the replacement needs is built BEFORE the activation starts, so the only thing the port does is commit it.
  const replacement = await buildReq(dev, await issueLive(u, dev), { leaf: k2 });
  const code = await newOfferAndCode(u);
  const inFlight = await signedActivation(u, dev, code, { keyId: k1Id, leaf: k1 }, 41);

  const raced: { committed: Awaited<ReturnType<typeof register>> | null } = { committed: null };
  const racingPort: IosPort = {
    ...realIosPort(),
    verifyAssertion: async (input) => {
      const verdict = await verifyAppAttestAssertion(input, { appId: APP_ID }, { sha256, verifyP256: verifyP256WebCrypto });
      assertEquals(verdict.ok && verdict.counter, 41, "precondition: the K1 assertion verifies against the state the handler read");
      raced.committed = await register(u, replacement.req); // commits K2 / counter 0 / K1 retired, in its own transaction
      return verdict;
    },
  };
  const out = await withOwnership(u.actor, (repo: Repo) => handleActivation(code, inFlight, repo, { ports: { ios: racingPort, android: null }, sha256 }));

  const committed = raced.committed;
  assert(committed !== null && committed.ok && committed.body.replaced === true, "precondition: the replacement committed during the activation");
  // The retired key's assertion did NOT issue the reward: fail closed (held), with the replay-class reason.
  assertEquals(out.state, "held_review", "a retired key's assertion must not be graded attested");
  const reward = (await adminSql()`select state from app.offer_code where id = ${code}`)[0]!;
  assertNotEquals(reward.state, "issued");
  assertEquals((await adminSql()`select count(*)::int as n from app.device_reward_ledger where reward_id = ${code}`)[0]!.n, 0, "the retired key's assertion earned no ledger row (nothing was received)");
  const sig = (await adminSql()`select detail from app.fraud_signal where user_id = ${u.uid} and kind = 'attestation_failed'`)[0]!.detail as { reasons: string[] };
  assertEquals(sig.reasons, ["counter_replay"]);

  // The new key did NOT inherit the retired key's counter: it is still 0 and K2's very next assertion (counter 1) verifies.
  const row = await deviceRow(dev);
  assertEquals(row.attest_key_id, k2Id);
  assertEquals(Number(row.attest_counter), 0, "K2 starts from 0, not from K1's 41");
  // (The failed outcome raised the account's attestation_failed signal, which holds the account's next activation by design; a reviewer
  // clearing it is what lets the next one through, so clear it as one would and then show K2's own first assertion issues.)
  await adminSql()`update app.fraud_signal set cleared_at = now() where user_id = ${u.uid} and kind = 'attestation_failed' and cleared_at is null`;
  const next = await newOfferAndCode(u);
  assertEquals((await activate(u, next, await signedActivation(u, dev, next, { keyId: k2Id, leaf: k2 }, 1))).state, "issued", "K2 counter 1 verifies: nothing was inherited");
  assertEquals(Number((await deviceRow(dev)).attest_counter), 1);
});
