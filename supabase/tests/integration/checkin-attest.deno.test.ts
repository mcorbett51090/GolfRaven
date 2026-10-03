// supabase/tests/integration/checkin-attest.deno.test.ts
//
// `checkin-token` with a PRESENTED attestation (build plan §4.5 G3-08): the REAL handler (_shared/checkin/token-handler.ts) through the REAL
// `withOwnership` and the REAL `Repo` (privileged.ts), against the harness cluster tools/db/test.sh builds, in BOTH harness modes. What only a
// real database can show, and the unit tests (checkin-token-attestation.test.ts, a fake Repo) cannot:
//   - the atomic counter advance (`app.device`'s 0032/0034 trigger and the `attest_key_id`-bound UPDATE) runs as `edge_actor` for the check-in path;
//   - the `fraud_signal(attestation_failed)` insert, and its one-open-per-account dedupe, run as `edge_actor`;
//   - a vendor error throws out of `withOwnership`, which ROLLS BACK: the challenge is NOT consumed, nothing is issued, no signal is raised,
//     and the same challenge redeems on retry.
//
// ⚠ iOS assertions are synthetic (Web Crypto, this repo's own format reading); the Android port is scripted (no Google route here).

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, freshUuid, makeActor } from "./_helpers.ts";
import { withOwnership } from "../../functions/_shared/privileged.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleTokenRequest, type CheckinAttestationDeps } from "../../functions/_shared/checkin/token-handler.ts";
import type { TokenRequest } from "../../functions/_shared/checkin/token-request-shape.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import { verifyP256WebCrypto } from "../../functions/_shared/rewards/app-attest.ts";
import { computeCheckinAndroidBinding, fromBase64UrlStrict, toBase64Url, toHex } from "../../functions/_shared/rewards/binding.ts";
import { computeIosActivationBinding, computeIosCheckinBinding } from "../../functions/_shared/rewards/string-binding.ts";
import { VendorUnavailableError, type AndroidPort } from "../../functions/_shared/rewards/types.ts";
import { buildIosAssertionPort, type VerificationPorts } from "../../functions/_shared/rewards/verification-ports.ts";
import type { Repo } from "../../functions/_shared/types.ts";
import { buildAssertion, generateP256, sha256, toB64, type TestKey } from "../unit/rewards-test-crypto.ts";
import { createAttestationVerifier, computeAttestKeyBinding } from "../../functions/_shared/rewards/app-attest-registration.ts";
import { handleAttestKey, type AttestKeyDeps } from "../../functions/_shared/rewards/attest-key-handler.ts";
import { buildAttestation, buildTestPki, genPair, type Pair, type TestPki } from "../unit/attest-test-pki.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const APP_ID = "TEAMID1234.com.example.golfraven";
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));
const keyIdOf = async (key: TestKey) => toB64(await sha256(key.publicKeyRaw));

async function freshUser(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `ck-${label}-${uid.slice(0, 8)}`);
  return { uid, actor: makeActor(uid) };
}
type User = Awaited<ReturnType<typeof freshUser>>;

/** An iOS device with a REGISTERED key (`attest_registered_at` set, as app.register_attest_key writes it) at `counter`. */
async function deviceWithKey(u: User, counter = 5): Promise<{ id: string; key: TestKey }> {
  const id = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "ios")).id);
  const key = await generateP256();
  await adminSql()`
    update app.device set attest_key_id = ${await keyIdOf(key)}, attest_public_key = ${key.publicKeyRaw}, attest_counter = 0, attest_registered_at = now()
    where id = ${id}`;
  await adminSql()`update app.device set attest_counter = ${counter} where id = ${id}`;
  return { id, key };
}

async function issue(u: User, deviceId: string) {
  const [c] = await withOwnership(u.actor, (repo: Repo) => handleChallengeRequest({ deviceId }, repo, randomBytes, digestHex));
  return { id: c!.id, nonce: c!.nonce, nonceBytes: fromBase64UrlStrict(c!.nonce)! };
}

const iosDeps = (u: User): CheckinAttestationDeps => ({ userId: u.uid, ports: { ios: buildIosAssertionPort(APP_ID, { sha256, verifyP256: verifyP256WebCrypto }), android: null }, sha256 });

async function iosReq(u: User, deviceId: string, key: TestKey, ch: { id: string; nonce: string }, counter: number, hash?: Uint8Array): Promise<TokenRequest> {
  const clientDataHash = hash ?? (await computeIosCheckinBinding(sha256, { challengeId: ch.id, deviceId, nonce: ch.nonce, userId: u.uid }));
  const built = await buildAssertion({ key, appId: APP_ID, counter, clientDataHash });
  return { challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: true, attestation: { platform: "ios", keyId: await keyIdOf(key), assertion: built.assertionB64 } };
}

const redeem = (u: User, body: TokenRequest, deps: CheckinAttestationDeps) => withOwnership(u.actor, (repo: Repo) => handleTokenRequest(body, repo, digestHex, deps));
const counterOf = async (deviceId: string) => Number((await adminSql()`select attest_counter from app.device where id = ${deviceId}`)[0]!.attest_counter);
const signals = (u: User) => adminSql()`select kind, detail, cleared_at from app.fraud_signal where user_id = ${u.uid} and kind = 'attestation_failed' order by created_at`;
const tokenRows = (u: User) => adminSql()`select jti, attestation_grade, challenge_id, device_id from app.checkin_token where user_id = ${u.uid}`;
const usedAt = async (challengeId: string) => (await adminSql()`select used_at from app.checkin_challenge where id = ${challengeId}`)[0]!.used_at;
async function codeOf(p: Promise<unknown>): Promise<{ status: number; code: string } | null> {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, code: e.code };
    throw e;
  }
}

Deno.test("checkin-attest: a valid assertion is `attested`; the counter advances in the database; an attested token row is written; no signal", DT, async () => {
  const u = await freshUser("good");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const out = await redeem(u, await iosReq(u, dev.id, dev.key, ch, 6), iosDeps(u));
  assertEquals(out.attestationGrade, "attested");
  assertEquals(await counterOf(dev.id), 6);
  const rows = await tokenRows(u);
  assertEquals(rows.length, 1);
  assertEquals(rows[0]!.attestation_grade, "attested");
  assertEquals(rows[0]!.device_id, dev.id);
  assertEquals((await signals(u)).length, 0);
  assert((await usedAt(ch.id)) !== null);
});

Deno.test("checkin-attest: a replayed counter is `failed`, opens ONE fraud_signal (deduped while open), and the counter does not move", DT, async () => {
  const u = await freshUser("replay");
  const dev = await deviceWithKey(u, 5);
  for (let i = 0; i < 2; i++) {
    const ch = await issue(u, dev.id);
    const out = await redeem(u, await iosReq(u, dev.id, dev.key, ch, 5), iosDeps(u));
    assertEquals(out.attestationGrade, "failed");
    assertEquals("rekey" in out, false, "a counter replay is not a key-identity problem: no hint");
  }
  assertEquals(await counterOf(dev.id), 5);
  const sigs = await signals(u);
  assertEquals(sigs.length, 1);
  const detail = sigs[0]!.detail as Record<string, unknown>;
  assertEquals(detail.reasons, ["counter_not_monotonic"]);
  assertEquals(detail.source, "checkin-token");
  assertEquals((await tokenRows(u)).map((r) => r.attestation_grade), ["failed", "failed"]);
});

Deno.test("checkin-attest: an assertion over the reward-ACTIVATION binding is `failed` at check-in (purpose separation) and spends the challenge", DT, async () => {
  const u = await freshUser("purpose");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const hash = await computeIosActivationBinding(sha256, { rewardId: freshUuid(), deviceId: dev.id, challengeId: ch.id, deviceCheckTokenSha256: "ab".repeat(32), nonce: ch.nonce });
  const out = await redeem(u, await iosReq(u, dev.id, dev.key, ch, 6, hash), iosDeps(u));
  assertEquals(out.attestationGrade, "failed");
  assertEquals(await counterOf(dev.id), 5);
  assertEquals(((await signals(u))[0]!.detail as Record<string, unknown>).reasons, ["bad_signature_or_request_hash"]);
  assert((await usedAt(ch.id)) !== null, "a failed attempt spends its challenge");
});

Deno.test("checkin-attest: another user's registered key is `failed` at check-in and leaves that user's counter alone", DT, async () => {
  const a = await freshUser("owner-a");
  const b = await freshUser("owner-b");
  const devA = await deviceWithKey(a, 5);
  const devB = await deviceWithKey(b, 40);
  const ch = await issue(a, devA.id);
  const out = await redeem(a, await iosReq(a, devA.id, devB.key, ch, 41), iosDeps(a));
  assertEquals(out.attestationGrade, "failed");
  assertEquals(out.rekey, true, "the presented key is not the one registered for this device");
  assertEquals(((await signals(a))[0]!.detail as Record<string, unknown>).reasons, ["key_id_mismatch"]);
  assertEquals(await counterOf(devB.id), 40);
  assertEquals(await counterOf(devA.id), 5);
});

Deno.test("checkin-attest: a counter that verifies but loses the ATOMIC advance (a concurrent request moved it) is `failed`, not `attested`", DT, async () => {
  const u = await freshUser("race");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const real = buildIosAssertionPort(APP_ID, { sha256, verifyP256: verifyP256WebCrypto });
  const racing: VerificationPorts = {
    android: null,
    ios: {
      verifyAssertion: async (input) => {
        const r = await real.verifyAssertion(input);
        await adminSql()`update app.device set attest_counter = 9 where id = ${dev.id}`; // another request advanced it in between
        return r;
      },
    },
  };
  const out = await redeem(u, await iosReq(u, dev.id, dev.key, ch, 6), { ...iosDeps(u), ports: racing });
  assertEquals(out.attestationGrade, "failed");
  assertEquals(await counterOf(dev.id), 9);
  assertEquals(((await signals(u))[0]!.detail as Record<string, unknown>).reasons, ["counter_out_of_order"]);
});

Deno.test("checkin-attest: a counter that loses the atomic advance to an EQUAL one stays `counter_replay`", DT, async () => {
  const u = await freshUser("race-equal");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const real = buildIosAssertionPort(APP_ID, { sha256, verifyP256: verifyP256WebCrypto });
  const racing: VerificationPorts = {
    android: null,
    ios: {
      verifyAssertion: async (input) => {
        const r = await real.verifyAssertion(input);
        await adminSql()`update app.device set attest_counter = 6 where id = ${dev.id}`; // an identical request advanced it to the very same counter
        return r;
      },
    },
  };
  const out = await redeem(u, await iosReq(u, dev.id, dev.key, ch, 6), { ...iosDeps(u), ports: racing });
  assertEquals(out.attestationGrade, "failed");
  assertEquals(await counterOf(dev.id), 6);
  assertEquals(((await signals(u))[0]!.detail as Record<string, unknown>).reasons, ["counter_replay"]);
});

Deno.test("checkin-attest (LOW-1): OUT-OF-ORDER assertions of one key, 7 committed then 6: 7 is `attested`, 6 is `failed` with `counter_out_of_order` (an honest race, not a replay), the counter stays 7", DT, async () => {
  const u = await freshUser("ooo");
  const dev = await deviceWithKey(u, 5);
  const c6 = await issue(u, dev.id);
  const c7 = await issue(u, dev.id);
  const r6 = await iosReq(u, dev.id, dev.key, c6, 6);
  const r7 = await iosReq(u, dev.id, dev.key, c7, 7);
  assertEquals((await redeem(u, r7, iosDeps(u))).attestationGrade, "attested");
  assertEquals((await redeem(u, r6, iosDeps(u))).attestationGrade, "failed");
  assertEquals(await counterOf(dev.id), 7);
  const sigs = await signals(u);
  assertEquals(sigs.length, 1);
  assertEquals((sigs[0]!.detail as Record<string, unknown>).reasons, ["counter_out_of_order"]);
  // the same on the other path: the lost advance race, with the verifier having read the counter BEFORE 7 committed, is covered above (race).
});

Deno.test("checkin-attest: no attestation on a device with no registered key is graded as before (claim true -> failed + signal; false -> unattestable)", DT, async () => {
  const u = await freshUser("none");
  const dev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "ios")).id); // never registered a key
  const c1 = await issue(u, dev);
  const out1 = await redeem(u, { challengeId: c1.id, nonce: c1.nonce, hardwareSupportsAttestation: false }, iosDeps(u));
  assertEquals(out1.attestationGrade, "unattestable");
  assertEquals((await signals(u)).length, 0);
  const c2 = await issue(u, dev);
  const out2 = await redeem(u, { challengeId: c2.id, nonce: c2.nonce, hardwareSupportsAttestation: true }, iosDeps(u));
  assertEquals(out2.attestationGrade, "failed");
  assertEquals((await signals(u)).length, 1);
});

Deno.test("checkin-attest: a vendor outage is a 503 that ROLLS BACK: the challenge is not consumed, nothing is issued, no signal; the same challenge redeems on retry", DT, async () => {
  const u = await freshUser("outage");
  const dev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "android")).id);
  const ch = await issue(u, dev);
  const down: AndroidPort = {
    async verifyIntegrity() {
      throw new VendorUnavailableError("Play Integrity answered 503");
    },
  };
  const seen: string[] = [];
  const up: AndroidPort = {
    async verifyIntegrity(input) {
      seen.push(input.expectedRequestHash);
      return { grade: "attested" };
    },
  };
  const body: TokenRequest = { challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: true, attestation: { platform: "android", integrityToken: "TOKEN.abc" } };
  const deps = (android: AndroidPort): CheckinAttestationDeps => ({ userId: u.uid, ports: { ios: null, android }, sha256 });

  assertEquals(await codeOf(redeem(u, body, deps(down))), { status: 503, code: "attestation_unavailable" });
  assertEquals(await usedAt(ch.id), null, "the challenge was not consumed (the transaction rolled back)");
  assertEquals((await tokenRows(u)).length, 0);
  assertEquals((await signals(u)).length, 0);

  const out = await redeem(u, body, deps(up));
  assertEquals(out.attestationGrade, "attested");
  assertEquals(seen, [toBase64Url(await computeCheckinAndroidBinding(sha256, { challengeId: ch.id, deviceId: dev, userId: u.uid }, ch.nonceBytes))]);
  assertEquals((await tokenRows(u)).map((r) => r.attestation_grade), ["attested"]);
});

Deno.test("checkin-attest: an unconfigured platform is a 503 before anything is consumed", DT, async () => {
  const u = await freshUser("unconf");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const req = await iosReq(u, dev.id, dev.key, ch, 6);
  assertEquals(await codeOf(redeem(u, req, { userId: u.uid, ports: { ios: null, android: null }, sha256 })), { status: 503, code: "attestation_not_configured" });
  assertEquals(await usedAt(ch.id), null);
  assertEquals((await tokenRows(u)).length, 0);
});

// ---------------------------------------------------------------------------
// idempotent redemption, the no-attestation rule, and the consumeForFix window — against the real database
// ---------------------------------------------------------------------------
Deno.test("checkin-attest: a repeat redemption returns the ORIGINAL token (same jti, expiry, grade); no second token, no counter move, no new signal; a different nonce stays challenge_used", DT, async () => {
  const u = await freshUser("idem");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const req = await iosReq(u, dev.id, dev.key, ch, 6);
  const first = await redeem(u, req, iosDeps(u));
  assertEquals(first.attestationGrade, "attested");
  const again = await redeem(u, req, iosDeps(u)); // the SAME assertion and counter: not a replay failure, it never reaches the verifier
  assertEquals(again, first);
  assertEquals(await counterOf(dev.id), 6);
  assertEquals((await tokenRows(u)).length, 1);
  assertEquals((await signals(u)).length, 0);
  const other = toBase64Url(randomBytes(32));
  assertEquals(await codeOf(redeem(u, { ...req, nonce: other }, iosDeps(u))), { status: 422, code: "challenge_used" });
  // another account cannot read it back
  const thief = await freshUser("idem-thief");
  assertEquals(await codeOf(redeem(thief, req, iosDeps(thief))), { status: 404, code: "not_found" });
});

Deno.test("checkin-attest: a repeat of a `failed` redemption stays `failed` (never upgraded by a valid assertion in the repeat) and raises no second signal", DT, async () => {
  const u = await freshUser("idem-failed");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const first = await redeem(u, await iosReq(u, dev.id, dev.key, ch, 5), iosDeps(u)); // replayed counter
  assertEquals(first.attestationGrade, "failed");
  const again = await redeem(u, await iosReq(u, dev.id, dev.key, ch, 6), iosDeps(u));
  assertEquals(again, first);
  assertEquals(await counterOf(dev.id), 5);
  assertEquals((await signals(u)).length, 1);
});

Deno.test("checkin-attest: a repeat after the token expired (or was consumed) is challenge_used", DT, async () => {
  const u = await freshUser("idem-expired");
  const dev = await deviceWithKey(u, 5);
  const ch = await issue(u, dev.id);
  const body: TokenRequest = { challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: false };
  const noKey = { userId: u.uid, ports: { ios: null, android: null }, sha256 } as CheckinAttestationDeps;
  const first = await redeem(u, body, noKey);
  assertEquals(first.attestationGrade, "failed"); // a registered key + no attestation (the rule below)
  assertEquals(await redeem(u, body, noKey), first);
  await adminSql()`update app.checkin_token set consumed_at = now() where jti = ${first.jti}`;
  assertEquals(await codeOf(redeem(u, body, noKey)), { status: 422, code: "challenge_used" });
  const u2 = await freshUser("idem-expired2");
  const dev2 = await deviceWithKey(u2, 5);
  const ch2 = await issue(u2, dev2.id);
  const b2: TokenRequest = { challengeId: ch2.id, nonce: ch2.nonce, hardwareSupportsAttestation: false };
  await redeem(u2, b2, noKey);
  await adminSql()`update app.checkin_token set expires_at = now() - interval '1 second', issued_at = now() - interval '16 minutes' where user_id = ${u2.uid}`;
  assertEquals(await codeOf(redeem(u2, b2, noKey)), { status: 422, code: "challenge_used" });
});

Deno.test("checkin-attest: the no-attestation rule — a device with a registered key is `failed` whatever it claims; a keyless device keeps `unattestable`", DT, async () => {
  const u = await freshUser("dodge");
  const keyed = await deviceWithKey(u, 5);
  const keyless = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "ios")).id);
  const none = { userId: u.uid, ports: { ios: null, android: null }, sha256 } as CheckinAttestationDeps;
  const c1 = await issue(u, keyed.id);
  assertEquals((await redeem(u, { challengeId: c1.id, nonce: c1.nonce, hardwareSupportsAttestation: false }, none)).attestationGrade, "failed");
  assertEquals((await signals(u)).length, 1);
  const c2 = await issue(u, keyless);
  assertEquals((await redeem(u, { challengeId: c2.id, nonce: c2.nonce, hardwareSupportsAttestation: false }, none)).attestationGrade, "unattestable");
  // Android: an attested token on the device makes a later no-attestation request `failed`
  const andDev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "android")).id);
  const ok: AndroidPort = { verifyIntegrity: async () => ({ grade: "attested" }) };
  const c3 = await issue(u, andDev);
  const att: TokenRequest = { challengeId: c3.id, nonce: c3.nonce, hardwareSupportsAttestation: true, attestation: { platform: "android", integrityToken: "T" } };
  assertEquals((await redeem(u, att, { userId: u.uid, ports: { ios: null, android: ok }, sha256 })).attestationGrade, "attested");
  const c4 = await issue(u, andDev);
  assertEquals((await redeem(u, { challengeId: c4.id, nonce: c4.nonce, hardwareSupportsAttestation: false }, none)).attestationGrade, "failed");
});

Deno.test("checkin-attest (NIT-2): the no-attestation `failed` path opens ONE signal per account (not one per request), in the same `reasons` vocabulary as activation", DT, async () => {
  const u = await freshUser("dedupe");
  const keyed = await deviceWithKey(u, 5);
  const none = { userId: u.uid, ports: { ios: null, android: null }, sha256 } as CheckinAttestationDeps;
  for (let i = 0; i < 3; i++) {
    const c = await issue(u, keyed.id);
    assertEquals((await redeem(u, { challengeId: c.id, nonce: c.nonce, hardwareSupportsAttestation: i === 1 }, none)).attestationGrade, "failed");
  }
  assertEquals((await tokenRows(u)).length, 3, "every request still issued its (failed) token");
  const sigs = await signals(u);
  assertEquals(sigs.length, 1, "...but they share one open signal");
  assertEquals(sigs[0]!.detail, { challengeId: sigs[0]!.detail.challengeId, deviceId: keyed.id, platform: null, reasons: ["no_attestation_token", "device_has_attested_before"], source: "checkin-token" });
  // clearing it lets the next failure open a new one
  await adminSql()`update app.fraud_signal set cleared_at = now() where user_id = ${u.uid} and kind = 'attestation_failed'`;
  const c4 = await issue(u, keyed.id);
  assertEquals((await redeem(u, { challengeId: c4.id, nonce: c4.nonce, hardwareSupportsAttestation: true }, none)).attestationGrade, "failed");
  const after = await signals(u);
  assertEquals(after.length, 2);
  assertEquals(after.filter((x) => x.cleared_at === null).length, 1);
});

Deno.test("checkin-attest (NIT-3, 0043): an Android device whose ACTIVATION verdict was `attested` (no attested token at all) is `failed` when it sends no attestation and claims it cannot attest, even after a later `failed` verdict; another device of the account is not evidence", DT, async () => {
  const u = await freshUser("android-activation");
  const dev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "android")).id);
  const other = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "android")).id);
  const none = { userId: u.uid, ports: { ios: null, android: null }, sha256 } as CheckinAttestationDeps;
  // control: before any verdict the claim is believed
  const c0 = await issue(u, dev);
  assertEquals((await redeem(u, { challengeId: c0.id, nonce: c0.nonce, hardwareSupportsAttestation: false }, none)).attestationGrade, "unattestable");
  // an attested activation verdict (privileged.ts#recordDeviceVerdict), then a later failed one that overwrites integrity_last
  await withOwnership(u.actor, (repo: Repo) => repo.rewards.recordDeviceVerdict(dev, { grade: "attested", tokenHash: null }));
  await withOwnership(u.actor, (repo: Repo) => repo.rewards.recordDeviceVerdict(dev, { grade: "failed", tokenHash: null }));
  assertEquals((await tokenRows(u)).filter((r) => r.attestation_grade === "attested").length, 0, "the only evidence is the activation's");
  const c1 = await issue(u, dev);
  assertEquals((await redeem(u, { challengeId: c1.id, nonce: c1.nonce, hardwareSupportsAttestation: false }, none)).attestationGrade, "failed");
  const sigs = await signals(u);
  assertEquals(sigs.length, 1);
  assertEquals((sigs[0]!.detail as Record<string, unknown>).reasons, ["no_attestation_token", "device_has_attested_before"]);
  // the account's OTHER device never attested: its claim is believed (the account-level rule is not applied)
  const c2 = await issue(u, other);
  assertEquals((await redeem(u, { challengeId: c2.id, nonce: c2.nonce, hardwareSupportsAttestation: false }, none)).attestationGrade, "unattestable");
  // another account sees nothing of this device
  const b = await freshUser("android-activation-b");
  assertEquals(await withOwnership(b.actor, (repo: Repo) => repo.rewards.hasAttestedVerdictOnDevice(dev)), false);
  assertEquals(await withOwnership(u.actor, (repo: Repo) => repo.rewards.hasAttestedVerdictOnDevice(dev)), true);
  assertEquals(await withOwnership(u.actor, (repo: Repo) => repo.rewards.hasAttestedVerdictOnDevice(other)), false);
});

Deno.test("checkin-attest: consumeForFix clamps to the CHALLENGE's window — a fix captured hours before the redemption of a prefetched challenge is accepted (the token's own 15 min window would refuse it)", DT, async () => {
  const u = await freshUser("window");
  const dev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "android")).id);
  const ch = await issue(u, dev);
  // a prefetched challenge issued 5 h ago, valid for the rest of its 24 h
  await adminSql()`update app.checkin_challenge set kind = 'prefetched', issued_at = now() - interval '5 hours', expires_at = now() + interval '19 hours' where id = ${ch.id}`;
  const none = { userId: u.uid, ports: { ios: null, android: null }, sha256 } as CheckinAttestationDeps;
  const tok = await redeem(u, { challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: false }, none);
  const capturedHoursAgo = Date.now() - 4 * 60 * 60_000; // before the TOKEN existed, inside the challenge window
  const consumed = await withOwnership(u.actor, (repo: Repo) => repo.checkinToken.consumeForFix(tok.jti, dev, capturedHoursAgo));
  assert(consumed !== null, "the real statement accepts a fix inside the challenge's window");
  assertEquals(consumed!.challengeKind, "prefetched");
  // ...and one captured BEFORE the challenge was issued is refused
  const ch2 = await issue(u, dev);
  await adminSql()`update app.checkin_challenge set kind = 'prefetched', issued_at = now() - interval '5 hours', expires_at = now() + interval '19 hours' where id = ${ch2.id}`;
  const tok2 = await redeem(u, { challengeId: ch2.id, nonce: ch2.nonce, hardwareSupportsAttestation: false }, none);
  assertEquals(await withOwnership(u.actor, (repo: Repo) => repo.checkinToken.consumeForFix(tok2.jti, dev, Date.now() - 6 * 60 * 60_000)), null);
});

// ---------------------------------------------------------------------------
// stale App Attest key recovery: the `rekey` hint, and the replacement it points at (devices-attest-key), against the real database
// ---------------------------------------------------------------------------
let pki: TestPki;
const pkiOnce = async (): Promise<TestPki> => (pki ??= await buildTestPki({ nowMs: Date.now() }));
async function registrationDeps(): Promise<AttestKeyDeps> {
  const p = await pkiOnce();
  return { verifier: createAttestationVerifier({ appId: APP_ID, environment: "production", trustAnchorDer: p.rootDer }, { sha256 }), sha256 };
}
/** Registers `leaf` as the device's key through the REAL handler (a verified synthetic attestation bound to a fresh live challenge), as `devices-attest-key` does. */
async function registerKey(u: User, deviceId: string, leaf: Pair) {
  const ch = await issue(u, deviceId);
  const keyId = toB64(await sha256(leaf.point));
  const clientDataHash = await computeAttestKeyBinding(sha256, { challengeId: ch.id, deviceId, keyId, nonce: ch.nonce });
  const built = await buildAttestation({ pki: await pkiOnce(), appId: APP_ID, environment: "production", clientDataHash, leaf });
  const deps = await registrationDeps();
  return withOwnership(u.actor, (repo: Repo) => handleAttestKey({ deviceId, challengeId: ch.id, nonce: ch.nonce, keyId, attestation: built.attestationB64 }, repo, deps));
}
const asKey = (leaf: Pair): TestKey => ({ privateKey: leaf.privateKey, publicKeyRaw: leaf.point });
const deviceKeyRow = async (deviceId: string) => (await adminSql()`select attest_key_id, attest_counter, attest_retired_key_hashes from app.device where id = ${deviceId}`)[0]!;
const openSignalCount = async (u: User) => (await signals(u)).filter((s) => s.cleared_at === null).length;

Deno.test("checkin-attest (rekey): register key A, present key B -> `failed` + `rekey: true` (signal raised, challenge spent, counter untouched); re-register B (replaced) -> the next check-in is `attested`", DT, async () => {
  const u = await freshUser("rekey");
  const dev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "ios")).id);
  const leafA = await genPair("P-256");
  const leafB = await genPair("P-256");
  const keyA = asKey(leafA);
  const keyB = asKey(leafB);

  const first = await registerKey(u, dev, leafA);
  assert(first.ok && first.status === 201 && first.body.replaced === false, "key A registered");
  const ch0 = await issue(u, dev);
  const ok0 = await redeem(u, await iosReq(u, dev, keyA, ch0, 1), iosDeps(u));
  assertEquals(ok0.attestationGrade, "attested");
  assertEquals("rekey" in ok0, false);
  assertEquals(await counterOf(dev), 1);

  // The client's local key is B (the server holds A): graded `failed`, but now it can tell why.
  const ch1 = await issue(u, dev);
  const stale = await redeem(u, await iosReq(u, dev, keyB, ch1, 1), iosDeps(u));
  assertEquals(stale.attestationGrade, "failed");
  assertEquals(stale.rekey, true);
  assertEquals(Object.keys(stale).sort(), ["attestationGrade", "expiresAt", "jti", "rekey"]);
  assertEquals(await counterOf(dev), 1, "a failed assertion never advances the counter");
  assert((await usedAt(ch1.id)) !== null, "the failed attempt spent its challenge");
  const sigs = await signals(u);
  assertEquals(sigs.length, 1, "the fraud signal is still raised");
  assertEquals((sigs[0]!.detail as Record<string, unknown>).reasons, ["key_id_mismatch"]);
  assertEquals((await tokenRows(u)).map((r) => r.attestation_grade), ["attested", "failed"]);

  // The recovery: devices-attest-key replaces the key on the caller's OWN device; the counter restarts at 0.
  const replaced = await registerKey(u, dev, leafB);
  assert(replaced.ok && replaced.status === 200 && replaced.body.replaced === true, "key B replaced key A");
  const row = await deviceKeyRow(dev);
  assertEquals(row.attest_key_id, toB64(await sha256(leafB.point)));
  assertEquals(Number(row.attest_counter), 0);
  assertEquals((row.attest_retired_key_hashes as string[]).length, 1);

  // The very next check-in with B (counter 1, below A's old counter is irrelevant: new key, new counter) is attested, and carries no hint.
  const ch2 = await issue(u, dev);
  const recovered = await redeem(u, await iosReq(u, dev, keyB, ch2, 1), iosDeps(u));
  assertEquals(recovered.attestationGrade, "attested");
  assertEquals("rekey" in recovered, false);
  assertEquals(await counterOf(dev), 1);
  assertEquals(await openSignalCount(u), 1, "the signal stays open until a reviewer clears it (recovery does not hide the evidence)");

  // The retired key is now the stale one, and cannot come back.
  const ch3 = await issue(u, dev);
  const old = await redeem(u, await iosReq(u, dev, keyA, ch3, 9), iosDeps(u));
  assertEquals(old.attestationGrade, "failed");
  assertEquals(old.rekey, true);
  const back = await registerKey(u, dev, leafA).then(() => null, (e: unknown) => (e instanceof HttpError ? { status: e.status, code: e.code } : e));
  assertEquals(back, { status: 409, code: "key_previously_retired" });
});

Deno.test("checkin-attest (rekey): NO key registered but an assertion presented -> `unattestable` + `rekey: true`, no signal; registering a key then makes the same device `attested`", DT, async () => {
  const u = await freshUser("rekey-nokey");
  const dev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "ios")).id);
  const leaf = await genPair("P-256");
  const ch1 = await issue(u, dev);
  const out = await redeem(u, await iosReq(u, dev, asKey(leaf), ch1, 1), iosDeps(u));
  assertEquals(out.attestationGrade, "unattestable");
  assertEquals(out.rekey, true);
  assertEquals((await signals(u)).length, 0, "an unattestable answer raises no signal, as before");
  const reg = await registerKey(u, dev, leaf);
  assert(reg.ok && reg.status === 201 && reg.body.replaced === false, "a first registration, not a replacement");
  const ch2 = await issue(u, dev);
  const after = await redeem(u, await iosReq(u, dev, asKey(leaf), ch2, 1), iosDeps(u));
  assertEquals(after.attestationGrade, "attested");
  assertEquals("rekey" in after, false);
});

Deno.test("checkin-attest (rekey): ABSENT on counter out-of-order, a bad signature, a wrong purpose, a wrong rpId and a no-attestation `failed`, against the real database", DT, async () => {
  const u = await freshUser("rekey-absent");
  const dev = await deviceWithKey(u, 5);
  const absent = (out: object, label: string) => assertEquals("rekey" in out, false, label);

  const lower = await redeem(u, await iosReq(u, dev.id, dev.key, await issue(u, dev.id), 4), iosDeps(u));
  assertEquals(lower.attestationGrade, "failed");
  absent(lower, "out of order");

  const other = await generateP256();
  const ch = await issue(u, dev.id);
  const hash = await computeIosCheckinBinding(sha256, { challengeId: ch.id, deviceId: dev.id, nonce: ch.nonce, userId: u.uid });
  const forged = await buildAssertion({ key: other, appId: APP_ID, counter: 6, clientDataHash: hash });
  const signedByAnother = await redeem(u, { challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: true, attestation: { platform: "ios", keyId: await keyIdOf(dev.key), assertion: forged.assertionB64 } }, iosDeps(u));
  assertEquals(signedByAnother.attestationGrade, "failed");
  absent(signedByAnother, "registered key id, signature by another key");

  const ch2 = await issue(u, dev.id);
  const wrongPurpose = await computeIosActivationBinding(sha256, { rewardId: freshUuid(), deviceId: dev.id, challengeId: ch2.id, deviceCheckTokenSha256: "ab".repeat(32), nonce: ch2.nonce });
  const wp = await redeem(u, await iosReq(u, dev.id, dev.key, ch2, 6, wrongPurpose), iosDeps(u));
  assertEquals(wp.attestationGrade, "failed");
  absent(wp, "wrong purpose");

  const ch3 = await issue(u, dev.id);
  const rpHash = await computeIosCheckinBinding(sha256, { challengeId: ch3.id, deviceId: dev.id, nonce: ch3.nonce, userId: u.uid });
  const wrongRp = await buildAssertion({ key: dev.key, appId: "OTHERTEAM.com.evil.app", counter: 6, clientDataHash: rpHash });
  const rp = await redeem(u, { challengeId: ch3.id, nonce: ch3.nonce, hardwareSupportsAttestation: true, attestation: { platform: "ios", keyId: await keyIdOf(dev.key), assertion: wrongRp.assertionB64 } }, iosDeps(u));
  assertEquals(rp.attestationGrade, "failed");
  absent(rp, "rpId mismatch");

  const ch4 = await issue(u, dev.id);
  const none = await redeem(u, { challengeId: ch4.id, nonce: ch4.nonce, hardwareSupportsAttestation: true }, iosDeps(u));
  assertEquals(none.attestationGrade, "failed");
  absent(none, "no attestation");
  assertEquals(await counterOf(dev.id), 5);
});
