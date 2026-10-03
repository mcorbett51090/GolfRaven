/**
 * Records `test/fixtures/edge-contract.json` entries for the EVIDENCE lane (P4.2b-1) by running the REAL server handlers:
 *   supabase/functions/_shared/evidence/handler.ts           (POST /v1/evidence)
 *   supabase/functions/_shared/evidence/batch-handler.ts     (POST /v1/evidence/batch; the REAL `handleEvidenceBatchIntake`)
 *   supabase/functions/_shared/checkin/challenge-handler.ts  (POST /v1/checkin/challenge)
 *   supabase/functions/_shared/checkin/token-handler.ts      (POST /v1/checkin/token; since P4.2b-2 also WITH an attestation block, see below)
 *   supabase/functions/_shared/rewards/attest-key-handler.ts (POST /v1/devices/attest-key: App Attest key registration)
 *   supabase/functions/_shared/me/offline-seed-handler.ts    (POST /v1/me/offline-seed: the offline TOTP seed; P4.2b-3b)
 *   supabase/functions/_shared/rewards/activate-handler.ts   (POST /v1/rewards/{id}/activate: reward activation; P4.2b-3b)
 *   supabase/functions/_shared/evidence/source-ref.ts, rewards/binding.ts, rewards/string-binding.ts, rewards/app-attest-registration.ts
 * behind the real envelope code (`_shared/http.ts` handleRequest / okResponse / HttpError), over the server's own unit-test fakes
 * (`supabase/tests/unit/fake-repo.ts`). The only thing replaced is `_shared/privileged.ts` (it needs a live Postgres): `hitRateLimitForActor`
 * and `withOwnershipBatch` are swapped for their in-memory equivalents, so `handleEvidenceBatchIntake` itself runs unmodified.
 * The small bodies of each `<function>/index.ts` (rate-limit pre-checks, status mapping, `maxBodyBytes`) are replicated below exactly as those files
 * write them.
 *
 * OFFLINE SEED + ACTIVATION (P4.2b-3b): `offlineseed_*` entries come from the REAL `handleOfflineSeedRequest` over the server's in-memory offline-code repo (the seed is the independent
 * reference derivation under a TEST key held in the server's test code, never a production secret) and `activate_*` entries from the REAL `handleActivation` (decision table, challenge
 * consumption, the strict request parser, the 503 mapping, the idempotent short-circuits) over the in-memory rewards repo, with the same SCRIPTED Apple / Google ports as below. `vectors.offlineCode`
 * holds codes the server's own `totp.ts` computed for the recorded seed, so the mobile TOTP is compared with the server's output, not only with its own re-derivation.
 *
 * ATTESTATION (P4.2b-2): the check-in and key-registration handlers verify an Apple / Google artifact through PORTS (`VerificationPorts`, `AttestationRegistrationVerifier`).
 * No Apple chain or Google decode is available here, so those ports are SCRIPTED: each accepts an artifact if and only if it is the base64url of the exact hash the REAL
 * binding code computed for the REAL challenge (an assertion / registration attestation = base64url(clientDataHash); an integrity token = "it-" + the requestHash the handler
 * expects). Everything else (the binding functions, the strict request parser, the grading table, the counter advance, the 503 mapping, the "attested before" rule, challenge
 * consumption) is the server's own code. So a recorded request proves the client's binding bytes against the server's, and a recorded answer is the server's real answer for it;
 * what is NOT proven is Apple's / Google's own verification (`[unverified]`: no device, no credentials). The one database behaviour the in-memory fake lacks, the
 * rollback of the handler's transaction when it throws (a 503 leaves the challenge unconsumed), is emulated in `tokenEndpoint` and says so there.
 *
 * HOW TO RUN (from the repo root; needs `pnpm install`):
 *   pnpm --filter @golfraven/rules exec vitest run --config ../../apps/mobile/scripts/record-edge-contract.vitest.config.ts            # verify: fails if the committed fixture differs
 *   RECORD_EDGE_CONTRACT=1 pnpm --filter @golfraven/rules exec vitest run --config ../../apps/mobile/scripts/record-edge-contract.vitest.config.ts   # rewrite
 * Everything is deterministic (fixed clock, fixed random bytes, a fixed Ed25519 seed), so a verify run after a recording is clean and a server
 * change that alters a wire shape makes it fail. Existing entries of the file are kept byte for byte; this script owns only the keys it writes
 * (`OWNED_PREFIXES` below, plus `vectors`).
 */
import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { FAKE_DEVICE_ID, fakeHitRateLimitForActor, makeFakeRepo, makeFakeState, type FakeState } from "../../../supabase/tests/unit/fake-repo.ts";

// --- the in-memory stand-in for privileged.ts (hoisted by vitest) -----------------------------------------------------------------------------
const hoisted = vi.hoisted(() => ({ current: { state: null as unknown, makeRepo: null as unknown } }));
vi.mock("../../../supabase/functions/_shared/privileged.ts", () => ({
  hitRateLimitForActor: async (actor: { uid: string }, bucketKey: string, windowSeconds: number, max: number) => {
    const { fakeHitRateLimitForActor: hit } = await import("../../../supabase/tests/unit/fake-repo.ts");
    return hit(hoisted.current.state as FakeState, actor.uid, bucketKey, windowSeconds, max);
  },
  withOwnershipBatch: async (actor: { uid: string }, n: number, perItem: (repo: unknown, i: number) => Promise<unknown>) => {
    const { makeFakeRepo: mk } = await import("../../../supabase/tests/unit/fake-repo.ts");
    const out: Array<{ ok: true; value: unknown } | { ok: false; error: unknown }> = [];
    for (let i = 0; i < n; i += 1) {
      try {
        out.push({ ok: true, value: await perItem(mk(hoisted.current.state as FakeState, actor.uid), i) });
      } catch (error) {
        out.push({ ok: false, error });
      }
    }
    return out;
  },
}));

import { handleChallengeRequest, RATE_LIMIT_PER_USER_HOUR as CHALLENGE_RATE } from "../../../supabase/functions/_shared/checkin/challenge-handler.ts";
import { seedDevice, seedReward, rewardsState } from "../../../supabase/tests/unit/fake-rewards-repo.ts";
import { offlineState } from "../../../supabase/tests/unit/fake-offline-code-repo.ts";
import { handleOfflineSeedRequest, parseOfflineSeedRequest } from "../../../supabase/functions/_shared/me/offline-seed-handler.ts";
import { OFFLINE_CODE_STEP_SECONDS, OFFLINE_SEED_REVEAL_BUCKET, OFFLINE_SEED_REVEAL_PER_HOUR, OFFLINE_SEED_ROTATE_BUCKET, OFFLINE_SEED_ROTATE_PER_HOUR } from "../../../supabase/functions/_shared/offline-code/params.ts";
import { base32Decode, hotp, stepOf } from "../../../supabase/functions/_shared/offline-code/totp.ts";
import { enforceActivationRateLimits, handleActivation } from "../../../supabase/functions/_shared/rewards/activate-handler.ts";
import { extractRewardId, parseActivationBody } from "../../../supabase/functions/_shared/rewards/request-shape.ts";
import { fakeAttestDevices, seedAttestDevice } from "../../../supabase/tests/unit/fake-attest-key-repo.ts";
import { enforceAttestKeyRateLimits, handleAttestKey } from "../../../supabase/functions/_shared/rewards/attest-key-handler.ts";
import { parseAttestKeyBody } from "../../../supabase/functions/_shared/rewards/attest-key-request.ts";
import type { AttestationRegistrationVerifier } from "../../../supabase/functions/_shared/rewards/app-attest-registration.ts";
import { type AndroidPort, type AttestationPorts, type IosPort, VendorUnavailableError } from "../../../supabase/functions/_shared/rewards/types.ts";
import type { VerificationPorts } from "../../../supabase/functions/_shared/rewards/verification-ports.ts";
import { checkinAndroidBoundBodyBytes, computeCheckinAndroidBinding, fromBase64UrlStrict } from "../../../supabase/functions/_shared/rewards/binding.ts";
import { computeIosCheckinBinding, iosCheckinChallengeString } from "../../../supabase/functions/_shared/rewards/string-binding.ts";
import { handleTokenRequest } from "../../../supabase/functions/_shared/checkin/token-handler.ts";
import { parseTokenBody } from "../../../supabase/functions/_shared/checkin/token-request-shape.ts";
import { handleEvidenceBatchIntake, MAX_BATCH_ITEMS_PER_REQUEST } from "../../../supabase/functions/_shared/evidence/batch-handler.ts";
import { computeInputHash, handleEvidenceIntake, planEvidenceRateLimitChecks } from "../../../supabase/functions/_shared/evidence/handler.ts";
import { deriveSourceRef } from "../../../supabase/functions/_shared/evidence/source-ref.ts";
import { canonicalStringify, MANIFEST_DOMAIN } from "../../../supabase/functions/_shared/catalog/manifest-artifact.ts";
import { Errors, errorResponse, handleRequest, MAX_BODY_BYTES, okResponse } from "../../../supabase/functions/_shared/http.ts";
import { boundBodyBytes, canonicalJson, computeRequestBinding, toBase64Url, toHex } from "../../../supabase/functions/_shared/rewards/binding.ts";
import { computeAttestKeyBinding, attestKeyChallengeString } from "../../../supabase/functions/_shared/rewards/app-attest-registration.ts";
import { computeIosActivationBinding, iosActivationChallengeString } from "../../../supabase/functions/_shared/rewards/string-binding.ts";

const FIXTURE = fileURLToPath(new URL("../test/fixtures/edge-contract.json", import.meta.url));
const OWNED_PREFIXES = ["challenge_", "token_", "evidence_", "batch_", "attestkey_", "offlineseed_", "activate_"];
const UID = "user-a";
/** The account the offline-seed entries are recorded for: the seed derivation names the account by UUID (as every real account id is). */
const OFFLINE_UID = "11111111-aaaa-4aaa-8aaa-111111111111";
const CURRENT = "20260520-a000001";
const NEWER = "20260601-b000002";

interface Entry {
  status: number;
  body: string;
  request?: unknown;
}

// --- determinism ------------------------------------------------------------------------------------------------------------------------------
let rbCounter = 0;
const randomBytes = (n: number): Uint8Array => Uint8Array.from({ length: n }, (_, i) => (rbCounter * 31 + i * 7 + 13) & 255);
const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
const digestHex = async (bytes: Uint8Array): Promise<string> => toHex(await sha256(bytes));

function fresh(uid: string = UID): { state: FakeState; repo: ReturnType<typeof makeFakeRepo> } {
  const state = makeFakeState();
  hoisted.current.state = state;
  if (uid !== UID) state.devices.set(FAKE_DEVICE_ID, { id: FAKE_DEVICE_ID, userId: uid }); // the default device belongs to `user-a`; give it to this account
  return { state, repo: makeFakeRepo(state, uid) };
}

async function toEntry(res: Response, request?: unknown): Promise<Entry> {
  const e: Entry = { status: res.status, body: await res.text() };
  if (request !== undefined) e.request = request;
  return e;
}

// --- the index.ts bodies, replicated ----------------------------------------------------------------------------------------------------------
async function challengeEndpoint(state: FakeState, repo: ReturnType<typeof makeFakeRepo>, body: Record<string, unknown>): Promise<Entry> {
  const res = await handleRequest(async () => {
    const rl = await fakeHitRateLimitForActor(state, UID, "checkin-challenge:user", 3600, CHALLENGE_RATE);
    if (!rl.ok) return Errors.tooManyRequests("checkin-challenge rate limit exceeded", rl.retryAfterSeconds).toResponse();
    const challenges = await handleChallengeRequest(body as never, repo, (n) => { rbCounter += 1; return randomBytes(n); }, digestHex);
    return okResponse(201, { challenges });
  });
  return toEntry(res, body);
}

/** checkin-token/index.ts: the strict body parse (UUID challenge id, unknown keys refused at the top level and inside the attestation block, the two
 * attestation shapes), then the handler with the attestation ports exactly as the entrypoint builds them. By default no platform is configured, so a request
 * that carries an attestation block answers 503 `attestation_not_configured`; the attestation scenarios below pass SCRIPTED ports (see the header). */
const NO_PORTS: VerificationPorts = { ios: null, android: null };
async function tokenEndpoint(repo: ReturnType<typeof makeFakeRepo>, body: Record<string, unknown>, ports: VerificationPorts = NO_PORTS): Promise<Entry> {
  // The ONE emulation of the database here: the real entrypoint runs the handler inside `withOwnership`, a transaction, and a thrown error (the 503s) ROLLS IT BACK, so the
  // challenge the handler consumed is not consumed (proved against real Postgres by supabase/tests/integration/checkin-attest.deno.test.ts: "the challenge was not consumed
  // (the transaction rolled back)"). The in-memory fake has no transaction, so the consumption is undone here when the handler throws, and only then.
  const state = hoisted.current.state as FakeState;
  const usedBefore = new Map([...state.challenges].map(([id, c]) => [id, c.usedAt]));
  const res = await handleRequest(async () => {
    const parsed = parseTokenBody(body);
    if (!parsed.ok) throw Errors.badRequest("invalid checkin-token request", parsed.issues);
    return okResponse(201, await handleTokenRequest(parsed.value, repo, digestHex, { userId: UID, ports, sha256 }));
  });
  if (res.status === 503) for (const [id, usedAt] of usedBefore) state.challenges.get(id)!.usedAt = usedAt;
  return toEntry(res, body);
}

/** devices-attest-key/index.ts: 503 before anything when no verifier is configured, the strict parse, the two rate limits, then the handler; a verification failure is
 * RETURNED by the handler (the transaction commits with the challenge consumed), everything else is thrown. */
async function attestKeyEndpoint(state: FakeState, repo: ReturnType<typeof makeFakeRepo>, body: Record<string, unknown>, verifier: AttestationRegistrationVerifier | null): Promise<Entry> {
  const res = await handleRequest(async () => {
    if (!verifier) return errorResponse(503, "attestation_not_configured", "App Attest key registration is not available on this deployment");
    const parsed = parseAttestKeyBody(body);
    if (!parsed.ok) throw Errors.badRequest("invalid attest-key request", parsed.issues);
    const limit = await enforceAttestKeyRateLimits((bucketKey, windowSeconds, max) => fakeHitRateLimitForActor(state, UID, bucketKey, windowSeconds, max), parsed.value.deviceId);
    if (!limit.ok) return Errors.tooManyRequests("devices-attest-key rate limit exceeded", limit.retryAfterSeconds).toResponse();
    const outcome = await handleAttestKey(parsed.value, repo, { verifier, sha256 });
    return outcome.ok ? okResponse(outcome.status, outcome.body) : errorResponse(outcome.status, outcome.code, outcome.message);
  });
  return toEntry(res, body);
}

/** me-offline-seed/index.ts: the strict parse, the reveal limit (and, for a rotation, the rotation limit) BEFORE the handler, then the handler; the answer is `no-store`. */
async function offlineSeedEndpoint(state: FakeState, repo: ReturnType<typeof makeFakeRepo>, body: unknown, uid: string = OFFLINE_UID): Promise<Entry> {
  const res = await handleRequest(async () => {
    const parsed = parseOfflineSeedRequest(body);
    const reveal = await fakeHitRateLimitForActor(state, uid, OFFLINE_SEED_REVEAL_BUCKET, 3_600, OFFLINE_SEED_REVEAL_PER_HOUR);
    if (!reveal.ok) return Errors.tooManyRequests("me-offline-seed rate limit exceeded", reveal.retryAfterSeconds).toResponse();
    if (parsed.rotate === true) {
      const rotate = await fakeHitRateLimitForActor(state, uid, OFFLINE_SEED_ROTATE_BUCKET, 3_600, OFFLINE_SEED_ROTATE_PER_HOUR);
      if (!rotate.ok) return Errors.tooManyRequests("me-offline-seed rotation rate limit exceeded", rotate.retryAfterSeconds).toResponse();
    }
    return okResponse(200, await handleOfflineSeedRequest(parsed, repo), { "cache-control": "no-store" });
  });
  return toEntry(res, body);
}

/** rewards-activate/index.ts: the reward id from the PATH only, the strict body parse, the two rate limits BEFORE the transaction, then `handleActivation`. The one emulation of the database,
 * as in `tokenEndpoint`: the real entrypoint runs the handler inside `withOwnership`, a transaction, and ANY thrown error rolls it back, so a challenge the handler consumed before it threw
 * (the 503s) is not consumed. The in-memory fake has no transaction, so the consumption is undone here when the handler throws. */
async function activateEndpoint(state: FakeState, repo: ReturnType<typeof makeFakeRepo>, path: string, body: unknown, ports: AttestationPorts): Promise<Entry> {
  const usedBefore = new Map([...state.challenges].map(([id, c]) => [id, c.usedAt]));
  const res = await handleRequest(async () => {
    const rewardId = extractRewardId(path);
    if (!rewardId) return Errors.notFound("no such reward").toResponse();
    const parsed = parseActivationBody(body);
    if (!parsed.ok) throw Errors.badRequest("invalid activation request", parsed.issues);
    const limit = await enforceActivationRateLimits((bucketKey, windowSeconds, max) => fakeHitRateLimitForActor(state, UID, bucketKey, windowSeconds, max), parsed.value.deviceId);
    if (!limit.ok) return Errors.tooManyRequests("rewards-activate rate limit exceeded", limit.retryAfterSeconds).toResponse();
    return okResponse(200, await handleActivation(rewardId, parsed.value, repo, { ports, sha256 }));
  });
  if (res.status >= 400) for (const [id, usedAt] of usedBefore) state.challenges.get(id)!.usedAt = usedAt;
  return toEntry(res, body);
}

// --- scripted vendor ports (see the header) -----------------------------------------------------------------------------------------------------
const PUBLIC_KEY = new Uint8Array(65).fill(4);
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
/** Accepts an integrity token iff it is "it-" + the requestHash the handler computed from ITS binding of the challenge. */
const scriptedAndroid: AndroidPort = { verifyIntegrity: async ({ integrityToken, expectedRequestHash }) => (integrityToken === `it-${expectedRequestHash}` ? { grade: "attested" } : { grade: "failed", reasons: ["request_hash_mismatch"] }) };
const unavailableAndroid: AndroidPort = { verifyIntegrity: async () => { throw new VendorUnavailableError("scripted vendor outage"); } };
/** Accepts an iOS assertion iff it is base64url(clientDataHash) for the registered key; the counter is 1, then 2, ... (the handler's own atomic advance decides). */
const scriptedIos = (counter: () => number): NonNullable<VerificationPorts["ios"]> => ({
  verifyAssertion: async ({ assertionB64, keyId, clientDataHash, device }) =>
    device.attestKeyId === keyId && assertionB64 === toBase64Url(clientDataHash) ? { ok: true, counter: counter() } : { ok: false, grade: "failed", reason: "scripted_hash_mismatch" },
});
/** The activation iOS port: accepts an assertion iff it is base64url(clientDataHash) for the registered key (counter 1, 2, ... as the handler's own atomic advance decides), and models the two DeviceCheck
 * bits: `readBits` answers the current ones, `setBit0` (row 6) sets bit0, so a second activation on the same device sees a "repeat user" device exactly as the real vendor would. */
const scriptedActivationIos = (counter: () => number, bits: { bit0: boolean; bit1: boolean; lastUpdateMonth: string | null }): IosPort => ({
  verifyAssertion: async ({ assertionB64, keyId, clientDataHash, device }) =>
    device.attestKeyId === keyId && assertionB64 === toBase64Url(clientDataHash) ? { ok: true, counter: counter() } : { ok: false, grade: "failed", reason: "scripted_hash_mismatch" },
  readBits: async () => ({ ...bits }),
  setBit0: async () => {
    bits.bit0 = true;
  },
});
/** Accepts a key attestation iff it is base64url(clientDataHash) (the registration binding the REAL handler computes). */
const scriptedRegistrationVerifier: AttestationRegistrationVerifier = {
  verify: async ({ attestationB64, keyId, clientDataHash }) => (attestationB64 === toBase64Url(clientDataHash) ? { ok: true, keyId, publicKeyRaw: PUBLIC_KEY.slice() } : { ok: false, reason: "scripted_hash_mismatch" as never }),
};

async function evidenceEndpoint(state: FakeState, repo: ReturnType<typeof makeFakeRepo>, body: unknown): Promise<Entry> {
  const res = await handleRequest(async () => {
    const { checks } = planEvidenceRateLimitChecks(body);
    for (const check of checks) {
      const rl = await fakeHitRateLimitForActor(state, UID, check.bucketKey, check.windowSeconds, check.max);
      if (!rl.ok) return Errors.tooManyRequests("evidence rate limit exceeded", rl.retryAfterSeconds).toResponse();
    }
    const result = await handleEvidenceIntake(body, repo);
    return okResponse(result.status === "queued_catalog" ? 202 : 200, result);
  });
  return toEntry(res, body);
}

async function batchEndpoint(body: unknown): Promise<Entry> {
  const res = await handleRequest(async () => {
    if (typeof body !== "object" || body === null || !Array.isArray((body as Record<string, unknown>).items)) return Errors.badRequest('body must be {"items": [...]}').toResponse();
    const items = (body as { items: unknown[] }).items;
    if (items.length === 0) return Errors.badRequest("items must be non-empty").toResponse();
    if (items.length > MAX_BATCH_ITEMS_PER_REQUEST) return Errors.badRequest(`items must be at most ${MAX_BATCH_ITEMS_PER_REQUEST} per request`).toResponse();
    const { results } = await handleEvidenceBatchIntake({ uid: UID } as never, items);
    return okResponse(200, { results, maxBodyBytes: MAX_BODY_BYTES });
  });
  // The 101-item request is not stored (it is only the loop count); every other request is.
  return toEntry(res, (body as { items?: unknown[] })?.items && (body as { items: unknown[] }).items.length > 20 ? undefined : body);
}

// --- bodies -----------------------------------------------------------------------------------------------------------------------------------
const T0 = Date.parse("2026-06-01T12:00:00.000Z");
const CHECKIN_VECTOR_BODY = { challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", userId: "uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuu" };
const CHECKIN_VECTOR_NONCE = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"; // base64url of the bytes 1..32
const fix = (id: string, extra: Record<string, unknown> = {}, at = T0): Record<string, unknown> => ({
  fixId: id, lat: 36.1467, lng: -86.7816, accuracyMeters: 10, capturedAt: at, simulated: false, foreground: true, fromApp: true, ...extra,
});
const common = { deviceId: FAKE_DEVICE_ID, facilityId: "fac_x", courseId: "crs_x1", localDate: "2026-06-01", catalogVersion: CURRENT };
const checkin = (id: string, extra: Record<string, unknown> = {}, over: Record<string, unknown> = {}): Record<string, unknown> => ({ source: "foreground_checkin", ...common, fix: fix(id, extra), ...over });
const dwell = (a: string, b: string, ja: string, jb: string): Record<string, unknown> => ({
  source: "foreground_dwell", ...common,
  checkinFix: fix(a, { checkinTokenJti: ja }), checkoutFix: fix(b, { checkinTokenJti: jb }, T0 + 4 * 3600_000), apartMinutes: 240,
});
const selfReport: Record<string, unknown> = { source: "self_report", ...common, localDate: "2026-05-20" };
const healthWorkout: Record<string, unknown> = { source: "health_workout", ...common, localDate: "2026-05-22" };

function signingKey(): { kid: string; publicKeyB64Url: string; sign: (payload: string) => string } {
  const seed = Buffer.alloc(32, 7);
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const x = createPublicKey(priv).export({ format: "jwk" }).x as string;
  return { kid: "k1", publicKeyB64Url: x, sign: (payload) => nodeSign(null, Buffer.from(payload, "utf8"), priv).toString("base64") };
}

async function record(): Promise<{ responses: Record<string, Entry>; vectors: Record<string, unknown> }> {
  const r: Record<string, Entry> = {};

  // ---------------- challenges ----------------
  {
    const { state, repo } = fresh();
    r.challenge_live_201 = await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID });
  }
  {
    const { state, repo } = fresh();
    r.challenge_prefetch_3_201 = await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 3 });
  }
  {
    const { state, repo } = fresh();
    r.challenge_prefetch_10_201 = await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 10 });
    r.challenge_prefetch_429_full = await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 1 });
  }
  {
    const { state, repo } = fresh();
    await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 8 });
    r.challenge_prefetch_partial_201 = await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 8 });
  }
  {
    const { state, repo } = fresh();
    r.challenge_400_prefetch_over_cap = await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 11 });
  }

  // ---------------- tokens + evidence (one connected flow) ----------------
  const { state, repo } = fresh();
  const issued = JSON.parse((await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 4 })).body).data.challenges as Array<{ id: string; nonce: string }>;
  const redeem = async (c: { id: string; nonce: string }): Promise<Entry> => tokenEndpoint(repo, { challengeId: c.id, nonce: c.nonce, hardwareSupportsAttestation: false });
  r.token_201_unattestable = await redeem(issued[0]!);
  const jti = JSON.parse(r.token_201_unattestable.body).data.jti as string;
  // A repeat redemption of the SAME challenge with the SAME nonce while the token is valid is idempotent (token-handler.ts): the original jti, expiry and grade, 201.
  r.token_201_idempotent_replay = await redeem(issued[0]!);
  // A REAL challenge_used: the challenge is spent and this request does not present its nonce (another challenge's nonce stands for "not the same request").
  r.token_422_challenge_used = await tokenEndpoint(repo, { challengeId: issued[0]!.id, nonce: issued[3]!.nonce, hardwareSupportsAttestation: false });
  r.token_400_unknown_key = await tokenEndpoint(repo, { challengeId: issued[1]!.id, nonce: issued[1]!.nonce, hardwareSupportsAttestation: false, deviceId: FAKE_DEVICE_ID });
  r.token_400_not_a_uuid = await tokenEndpoint(repo, { challengeId: "chal_1", nonce: issued[1]!.nonce, hardwareSupportsAttestation: false });
  r.token_422_not_consumable_wrong_nonce = await tokenEndpoint(repo, { challengeId: issued[1]!.id, nonce: (issued[1]!.nonce[0] === "A" ? "B" : "A") + issued[1]!.nonce.slice(1), hardwareSupportsAttestation: false });
  r.token_404_not_found = await tokenEndpoint(repo, { challengeId: "00000000-0000-4000-8000-0000000009ff", nonce: issued[1]!.nonce, hardwareSupportsAttestation: false });
  r.token_201_failed_grade = await tokenEndpoint(repo, { challengeId: issued[2]!.id, nonce: issued[2]!.nonce, hardwareSupportsAttestation: true });
  {
    const e = fresh();
    const [c] = JSON.parse((await challengeEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 1 })).body).data.challenges as Array<{ id: string; nonce: string }>;
    e.state.now = new Date(e.state.now.getTime() + 25 * 3600_000);
    r.token_422_challenge_expired = await tokenEndpoint(e.repo, { challengeId: c!.id, nonce: c!.nonce, hardwareSupportsAttestation: false });
  }

  // evidence flow continues on `state`/`repo` (clock back where it was, the token above was issued at T0)
  r.evidence_accepted_with_challenge = await evidenceEndpoint(state, repo, checkin("fixA1", { checkinTokenJti: jti }));
  r.evidence_accepted_replay = await evidenceEndpoint(state, repo, checkin("fixA1", { checkinTokenJti: jti }));
  r.evidence_accepted_no_challenge = await evidenceEndpoint(state, repo, checkin("fixB2"));
  r.evidence_accepted_unknown_jti = await evidenceEndpoint(state, repo, checkin("fixC3", { checkinTokenJti: "jti_does_not_exist" }));
  r.evidence_409_conflict = await evidenceEndpoint(state, repo, checkin("fixB2", { accuracyMeters: 500 }));
  r.evidence_accepted_self_report = await evidenceEndpoint(state, repo, selfReport);
  r.evidence_accepted_health_workout = await evidenceEndpoint(state, repo, healthWorkout);
  r.evidence_400_unknown_key = await evidenceEndpoint(state, repo, { ...checkin("fixD4"), bogus: true });
  r.evidence_400_rejected_source = await evidenceEndpoint(state, repo, { ...selfReport, source: "file_import" });
  r.evidence_422_unknown_id = await evidenceEndpoint(state, repo, checkin("fixE5", {}, { facilityId: "fac_ghost" }));
  r.evidence_422_local_date_mismatch = await evidenceEndpoint(state, repo, checkin("fixF6", {}, { localDate: "2026-06-02" }));
  {
    // two more tokens, both fixes of one dwell
    const c3 = issued[3]!;
    const extra = JSON.parse((await challengeEndpoint(state, repo, { deviceId: FAKE_DEVICE_ID, prefetchCount: 1 })).body).data.challenges as Array<{ id: string; nonce: string }>;
    const j1 = JSON.parse((await redeem(c3)).body).data.jti as string;
    const j2 = JSON.parse((await redeem(extra[0]!)).body).data.jti as string;
    r.evidence_accepted_dwell_two_challenges = await evidenceEndpoint(state, repo, dwell("fixG7", "fixH8", j1, j2));
  }

  // catalog skew
  {
    const e = fresh();
    for (let i = 0; i < 6; i += 1) {
      e.state.catalogVersions.set(10 + i, { version: 10 + i, siteVersion: `2026060${i + 1}-c00000${i}`, publishedAt: "2026-06-01T00:00:00.000Z", contractVersion: "v1", sha256: "x", kid: "k1" });
    }
    r.evidence_422_catalog_stale = await evidenceEndpoint(e.state, e.repo, checkin("fixS1"));
  }
  {
    const e = fresh();
    r.evidence_422_catalog_forged = await evidenceEndpoint(e.state, e.repo, checkin("fixS2", {}, { catalogVersion: NEWER }));
  }
  {
    const e = fresh();
    const key = signingKey();
    e.state.signingKeys.set(key.kid, { kid: key.kid, publicKeyB64Url: key.publicKeyB64Url, revokedAt: null });
    const manifestSha = "0123456789abcdef".repeat(4);
    const payload = MANIFEST_DOMAIN + canonicalStringify({ catalogVersion: NEWER, contractVersion: 1, kid: key.kid, manifestSha });
    const body = checkin("fixQ1", {}, { catalogVersion: NEWER, manifestSig: { kid: key.kid, contractVersion: 1, sig: key.sign(payload), manifestSha } });
    r.evidence_202_queued_catalog = await evidenceEndpoint(e.state, e.repo, body);
    r.evidence_202_queued_catalog_replay = await evidenceEndpoint(e.state, e.repo, body);
    // the drain aged the row out (7 days): the replay answers 200 needs_attention (handler.ts `EvidenceIntakeNeedsAttention`)
    for (const row of e.state.evidence.values()) (row as { status: string }).status = "needs_attention";
    r.evidence_200_needs_attention_replay = await evidenceEndpoint(e.state, e.repo, body);
  }
  {
    const e = fresh();
    let last: Entry | null = null;
    for (let i = 0; i < 61; i += 1) last = await evidenceEndpoint(e.state, e.repo, checkin(`fixR${i}`));
    r.evidence_429_rate_limited = last!;
    r.evidence_429_rate_limited.request = checkin("fixR60");
  }

  // ---------------- check-in attestation + App Attest key registration (P4.2b-2) ----------------
  // The challenges below draw from the same deterministic counter as everything after them; restore it at the end so the `vectors` (and the batch entries) keep the values they
  // had before this section existed (the diff of a re-recording then shows only what is new).
  const rbBeforeAttestation = rbCounter;
  const challengesOf = async (e: { state: FakeState; repo: ReturnType<typeof makeFakeRepo> }, body: Record<string, unknown>): Promise<Array<{ id: string; nonce: string }>> =>
    JSON.parse((await challengeEndpoint(e.state, e.repo, body)).body).data.challenges as Array<{ id: string; nonce: string }>;
  const androidToken = async (c: { id: string; nonce: string }): Promise<string> =>
    `it-${toBase64Url(await computeCheckinAndroidBinding(sha256, { challengeId: c.id, deviceId: FAKE_DEVICE_ID, userId: UID }, fromBase64UrlStrict(c.nonce)!))}`;
  const androidBody = (c: { id: string; nonce: string }, integrityToken: string): Record<string, unknown> => ({ challengeId: c.id, nonce: c.nonce, hardwareSupportsAttestation: true, attestation: { platform: "android", integrityToken } });
  {
    const e = fresh();
    const [c1, c2, c3] = await challengesOf(e, { deviceId: FAKE_DEVICE_ID, prefetchCount: 3 });
    // No Play configuration on the deployment: 503 before the challenge is touched.
    r.token_503_attestation_not_configured = await tokenEndpoint(e.repo, androidBody(c1!, "it-whatever"));
    // Play Integrity unreachable: 503, the transaction rolls back, the challenge is NOT consumed ...
    r.token_503_attestation_unavailable = await tokenEndpoint(e.repo, androidBody(c1!, await androidToken(c1!)), { ios: null, android: unavailableAndroid });
    // ... so the SAME challenge redeems once the vendor is back: a valid attestation over the check-in binding is `attested`.
    r.token_201_attested_android = await tokenEndpoint(e.repo, androidBody(c1!, await androidToken(c1!)), { ios: null, android: scriptedAndroid });
    // The no-attestation rule: this device has now shown it can attest, so a token-less request is `failed` whatever it claims (and raises the fraud signal) ...
    r.token_201_failed_attested_before_no_token = await tokenEndpoint(e.repo, { challengeId: c2!.id, nonce: c2!.nonce, hardwareSupportsAttestation: false }, { ios: null, android: scriptedAndroid });
    // ... and a token over the WRONG binding is `failed` too.
    r.token_201_failed_wrong_binding_android = await tokenEndpoint(e.repo, androidBody(c3!, "it-not-the-binding"), { ios: null, android: scriptedAndroid });
  }
  /** The device a first-ever iOS install has: known to the account, platform still UNKNOWN (0042), no key. Both fakes keep a device table of their own. */
  const seedUnknownDevice = (state: FakeState): void => {
    seedDevice(state, { id: FAKE_DEVICE_ID, userId: UID, platform: null });
    seedAttestDevice(state, { id: FAKE_DEVICE_ID, userId: UID, platform: null });
  };
  {
    // iOS: register a key (LIVE challenge, key id bound), then redeem a check-in with an assertion over the check-in binding.
    const e = fresh();
    seedUnknownDevice(e.state);
    const keyId = b64(await sha256(PUBLIC_KEY));
    const [live] = await challengesOf(e, { deviceId: FAKE_DEVICE_ID });
    const regBody = async (c: { id: string; nonce: string }, att?: string): Promise<Record<string, unknown>> => ({
      deviceId: FAKE_DEVICE_ID, challengeId: c.id, nonce: c.nonce, keyId,
      attestation: att ?? toBase64Url(await computeAttestKeyBinding(sha256, { challengeId: c.id, deviceId: FAKE_DEVICE_ID, keyId, nonce: c.nonce })),
    });
    r.attestkey_503_not_configured = await attestKeyEndpoint(e.state, e.repo, await regBody(live!), null);
    r.attestkey_201_registered = await attestKeyEndpoint(e.state, e.repo, await regBody(live!), scriptedRegistrationVerifier);
    // The same key again (an earlier request was applied and its answer lost): 409, nothing consumed.
    r.attestkey_409_already_registered = await attestKeyEndpoint(e.state, e.repo, await regBody(live!), scriptedRegistrationVerifier);
    // The fake rewards repo keeps its own device table: copy the key the REAL registration handler just stored, so the check-in verifier sees a registered key.
    const stored = fakeAttestDevices(e.state).get(FAKE_DEVICE_ID)!;
    expect(stored.keyId, "the real registration handler recorded the key").toBe(keyId);
    // copy what the REAL handler stored (key id, public key, registration time), not a constant of this script
    Object.assign(rewardsState(e.state).deviceAttest.get(FAKE_DEVICE_ID)!, { attestKeyId: stored.keyId, attestPublicKey: stored.publicKey });
    let counter = 0;
    const ports: VerificationPorts = { ios: scriptedIos(() => (counter += 1)), android: null };
    const [c1, c2] = await challengesOf(e, { deviceId: FAKE_DEVICE_ID, prefetchCount: 2 });
    const iosBody = async (c: { id: string; nonce: string }, assertion?: string): Promise<Record<string, unknown>> => ({
      challengeId: c.id, nonce: c.nonce, hardwareSupportsAttestation: true,
      attestation: { platform: "ios", keyId, assertion: assertion ?? toBase64Url(await computeIosCheckinBinding(sha256, { challengeId: c.id, deviceId: FAKE_DEVICE_ID, userId: UID, nonce: c.nonce })) },
    });
    r.token_201_attested_ios = await tokenEndpoint(e.repo, await iosBody(c1!), ports);
    r.token_201_failed_wrong_binding_ios = await tokenEndpoint(e.repo, await iosBody(c2!, toBase64Url(new Uint8Array(32).fill(9))), ports);
  }
  {
    const e = fresh();
    seedUnknownDevice(e.state);
    const keyId = b64(await sha256(PUBLIC_KEY));
    const [live] = await challengesOf(e, { deviceId: FAKE_DEVICE_ID });
    // The registration attestation does not verify: one generic 422, the challenge is spent, nothing is registered, no fraud signal.
    r.attestkey_422_rejected = await attestKeyEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID, challengeId: live!.id, nonce: live!.nonce, keyId, attestation: toBase64Url(new Uint8Array(32).fill(1)) }, scriptedRegistrationVerifier);
    // A PREFETCHED challenge cannot register a key (live only), and a spent live one cannot be used again.
    const [pre] = await challengesOf(e, { deviceId: FAKE_DEVICE_ID, prefetchCount: 1 });
    r.attestkey_422_challenge_not_consumable = await attestKeyEndpoint(
      e.state, e.repo,
      { deviceId: FAKE_DEVICE_ID, challengeId: pre!.id, nonce: pre!.nonce, keyId, attestation: toBase64Url(await computeAttestKeyBinding(sha256, { challengeId: pre!.id, deviceId: FAKE_DEVICE_ID, keyId, nonce: pre!.nonce })) },
      scriptedRegistrationVerifier,
    );
  }

  rbCounter = rbBeforeAttestation;

  // ---------------- offline seed + reward activation (P4.2b-3b) ----------------
  // Same discipline as above: the deterministic counter is restored at the end, so the batch entries and the pre-existing `vectors` keep the values they had.
  const rbBeforeP42b3b = rbCounter;
  const OTHER_ACCOUNT_DEVICE = "99999999-9999-4999-8999-999999999999";
  let offlineSeedB32 = "";
  {
    const e = fresh(OFFLINE_UID);
    e.state.devices.set(OTHER_ACCOUNT_DEVICE, { id: OTHER_ACCOUNT_DEVICE, userId: "user-b" });
    r.offlineseed_200 = await offlineSeedEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID });
    if (r.offlineseed_200.status !== 200) throw new Error(`offline seed recording: ${r.offlineseed_200.status} ${r.offlineseed_200.body}`);
    offlineSeedB32 = JSON.parse(r.offlineseed_200.body).data.seed as string;
    // Re-provisioning returns the SAME seed (a reinstall that lost the secure store recovers); a rotation returns a NEW seed and the next version.
    r.offlineseed_200_same_seed_again = await offlineSeedEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID });
    r.offlineseed_200_rotate = await offlineSeedEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID, rotate: true });
    // Another account's device and a device that does not exist are the SAME 404 (no oracle on device ids; the endpoint never creates a device).
    r.offlineseed_404_foreign_device = await offlineSeedEndpoint(e.state, e.repo, { deviceId: OTHER_ACCOUNT_DEVICE });
    r.offlineseed_404_unknown_device = await offlineSeedEndpoint(e.state, e.repo, { deviceId: "00000000-0000-4000-8000-0000000009ee" });
    r.offlineseed_400_unknown_key = await offlineSeedEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID, rotation: true });
    r.offlineseed_400_not_a_uuid = await offlineSeedEndpoint(e.state, e.repo, { deviceId: "device-1" });
  }
  {
    const e = fresh(OFFLINE_UID);
    let last: Entry | null = null;
    for (let i = 0; i <= OFFLINE_SEED_REVEAL_PER_HOUR; i += 1) last = await offlineSeedEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID });
    r.offlineseed_429_reveal_limit = last!;
  }
  {
    const e = fresh(OFFLINE_UID);
    let last: Entry | null = null;
    for (let i = 0; i <= OFFLINE_SEED_ROTATE_PER_HOUR; i += 1) last = await offlineSeedEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID, rotate: true });
    r.offlineseed_429_rotate_limit = last!;
  }
  {
    const e = fresh(OFFLINE_UID);
    offlineState(e.state).key = null; // the server's derivation key is not provisioned yet (Postgres 55000)
    r.offlineseed_503_not_provisioned = await offlineSeedEndpoint(e.state, e.repo, { deviceId: FAKE_DEVICE_ID });
  }

  {
    const R1 = "aaaaaaaa-0000-4000-8000-000000000001";
    const R2 = "aaaaaaaa-0000-4000-8000-000000000002";
    const R3 = "aaaaaaaa-0000-4000-8000-000000000003";
    const R_OTHER = "bbbbbbbb-0000-4000-8000-000000000001";
    const DCT = "REVWSUNFLVRPS0VO"; // a DeviceCheck token stand-in: any base64 text (the scripted port reads bits without looking at it)
    const LINK = "0123456789abcdef"; // the Android install link id (the SSAID shape: 16 hex characters)
    const IOS_KEY = b64(await sha256(PUBLIC_KEY));
    const pathOf = (id: string): string => `/functions/v1/rewards-activate/${id}`;
    type Challenge = { id: string; nonce: string };
    const world = (platform: "ios" | "android", keyed = true) => {
      const e = fresh();
      seedDevice(e.state, { id: FAKE_DEVICE_ID, userId: UID, platform, ...(platform === "ios" ? { attestKeyId: keyed ? IOS_KEY : null, attestPublicKey: keyed ? PUBLIC_KEY.slice() : null } : {}) });
      return e;
    };
    const live = async (e: { state: FakeState; repo: ReturnType<typeof makeFakeRepo> }): Promise<Challenge> => (await challengesOf(e, { deviceId: FAKE_DEVICE_ID }))[0]!;
    const iosBody = async (rewardId: string, c: Challenge, over: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
      const dctSha = toHex(await sha256(new TextEncoder().encode(DCT)));
      const hash = await computeIosActivationBinding(sha256, { rewardId, deviceId: FAKE_DEVICE_ID, challengeId: c.id, deviceCheckTokenSha256: dctSha, nonce: c.nonce });
      return { deviceId: FAKE_DEVICE_ID, platform: "ios", challengeId: c.id, nonce: c.nonce, attestation: { kind: "ios", keyId: IOS_KEY, assertion: toBase64Url(hash), deviceCheckToken: DCT }, ...over };
    };
    const androidBody = async (rewardId: string, c: Challenge, link: string | null = LINK): Promise<Record<string, unknown>> => {
      const bound = { rewardId, deviceId: FAKE_DEVICE_ID, platform: "android" as const, challengeId: c.id, ...(link !== null ? { installLinkId: link } : {}) };
      const hash = await computeRequestBinding(sha256, bound, fromBase64UrlStrict(c.nonce)!);
      return { deviceId: FAKE_DEVICE_ID, platform: "android", challengeId: c.id, nonce: c.nonce, ...(link !== null ? { installLinkId: link } : {}), attestation: { kind: "android", integrityToken: `it-${toBase64Url(hash)}` } };
    };
    const noneBody = (platform: "ios" | "android", claim = false, over: Record<string, unknown> = {}): Record<string, unknown> => ({
      deviceId: FAKE_DEVICE_ID,
      platform,
      ...(platform === "android" ? { installLinkId: LINK } : {}),
      attestation: { kind: "none", hardwareSupportsAttestation: claim, ...(platform === "ios" ? { deviceCheckToken: DCT } : {}) },
      ...over,
    });
    const iosPorts = (bits: { bit0: boolean; bit1: boolean; lastUpdateMonth: string | null }): { ports: AttestationPorts } => {
      let counter = 0;
      return { ports: { ios: scriptedActivationIos(() => (counter += 1), bits), android: null } };
    };
    const earn = (e: { state: FakeState }, id: string, kind: "offer_code" | "entitlement", over: Record<string, unknown> = {}): void => void seedReward(e.state, { id, userId: UID, kind, ...over });
    const clean = (): { bit0: boolean; bit1: boolean; lastUpdateMonth: string | null } => ({ bit0: false, bit1: false, lastUpdateMonth: null });

    // ---- iOS: the attested path, idempotence, the second reward of a repeat user ----
    {
      const e = world("ios");
      const { ports } = iosPorts(clean());
      earn(e, R1, "offer_code");
      earn(e, R2, "entitlement");
      r.activate_200_issued_ios = await activateEndpoint(e.state, e.repo, pathOf(R1), await iosBody(R1, await live(e)), ports);
      // A repeat of the same activation on the same device: nothing is verified or written (`replay: true`), and it is a 200, not a 409.
      r.activate_200_replay_already_active = await activateEndpoint(e.state, e.repo, pathOf(R1), await iosBody(R1, await live(e)), ports);
      // The first activation set bit0 (row 6); a second reward on that device is a repeat user (row 5), an entitlement becomes `redeemable`.
      r.activate_200_redeemable_ios_entitlement = await activateEndpoint(e.state, e.repo, pathOf(R2), await iosBody(R2, await live(e)), ports);
    }
    // ---- iOS: held_review in its several ways (never an error) ----
    {
      const e = world("ios");
      earn(e, R3, "offer_code");
      const { ports } = iosPorts({ bit0: true, bit1: false, lastUpdateMonth: "2026-02" });
      r.activate_200_held_review_bit0_new_account = await activateEndpoint(e.state, e.repo, pathOf(R3), await iosBody(R3, await live(e)), ports);
      r.activate_200_held_replay = await activateEndpoint(e.state, e.repo, pathOf(R3), await iosBody(R3, await live(e)), ports);
    }
    {
      const e = world("ios");
      earn(e, R3, "offer_code");
      const { ports } = iosPorts({ bit0: false, bit1: true, lastUpdateMonth: "2026-04" });
      r.activate_200_held_review_bit1 = await activateEndpoint(e.state, e.repo, pathOf(R3), await iosBody(R3, await live(e)), ports);
    }
    {
      // A device that never registered an App Attest key and says (truthfully) that it cannot attest: `unattestable`, held for a human.
      const e = world("ios", false);
      earn(e, R3, "offer_code");
      r.activate_200_held_unattestable_none_ios = await activateEndpoint(e.state, e.repo, pathOf(R3), noneBody("ios"), iosPorts(clean()).ports);
    }
    {
      // What the client must NEVER send: "I can attest" with no token. The server grades it `failed` and raises a fraud signal; the reward is held.
      const e = world("ios", false);
      earn(e, R3, "offer_code");
      r.activate_200_held_failed_claim_without_token = await activateEndpoint(e.state, e.repo, pathOf(R3), noneBody("ios", true), iosPorts(clean()).ports);
    }
    {
      // ... and a device that HAS a registered key cannot say "cannot attest" either: the server's own evidence wins, `failed` + fraud signal.
      const e = world("ios", true);
      earn(e, R3, "offer_code");
      r.activate_200_held_failed_attested_before_no_token = await activateEndpoint(e.state, e.repo, pathOf(R3), noneBody("ios"), iosPorts(clean()).ports);
    }
    // ---- Android ----
    {
      const e = world("android");
      earn(e, R1, "offer_code");
      const ports: AttestationPorts = { ios: null, android: scriptedAndroid };
      r.activate_200_issued_android = await activateEndpoint(e.state, e.repo, pathOf(R1), await androidBody(R1, await live(e)), ports);
    }
    {
      // No install link id: the server has no substitute signal for the persistent bits, so the reward is held (the "no persistent signal" row), never activated.
      const e = world("android");
      earn(e, R1, "offer_code");
      r.activate_200_held_android_no_install_link = await activateEndpoint(e.state, e.repo, pathOf(R1), await androidBody(R1, await live(e), null), { ios: null, android: scriptedAndroid });
    }
    {
      const e = world("android");
      earn(e, R1, "offer_code");
      r.activate_200_held_unattestable_none_android = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("android"), { ios: null, android: scriptedAndroid });
    }
    {
      const e = world("android");
      earn(e, R1, "offer_code");
      const c = await live(e);
      // Play Integrity unreachable: 503, the transaction rolls back, nothing changed and the challenge is NOT consumed ...
      r.activate_503_attestation_unavailable = await activateEndpoint(e.state, e.repo, pathOf(R1), await androidBody(R1, c), { ios: null, android: unavailableAndroid });
      // ... so the same request goes through once the vendor is back.
      r.activate_200_issued_android_after_503 = await activateEndpoint(e.state, e.repo, pathOf(R1), await androidBody(R1, c), { ios: null, android: scriptedAndroid });
    }
    {
      const e = world("android");
      earn(e, R1, "offer_code");
      r.activate_503_attestation_not_configured = await activateEndpoint(e.state, e.repo, pathOf(R1), await androidBody(R1, await live(e)), { ios: null, android: null });
    }
    // ---- refusals ----
    {
      const e = world("ios", false);
      earn(e, R1, "offer_code", { state: "redeemed" });
      r.activate_409_not_activatable = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("ios"), iosPorts(clean()).ports);
    }
    {
      const e = world("ios", false);
      earn(e, R1, "offer_code", { expiresAt: new Date(e.state.now.getTime() - 24 * 3600_000).toISOString() });
      r.activate_409_expired = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("ios"), iosPorts(clean()).ports);
    }
    {
      const e = world("ios", false);
      seedReward(e.state, { id: R_OTHER, userId: "user-b", kind: "offer_code" });
      r.activate_404_foreign_reward = await activateEndpoint(e.state, e.repo, pathOf(R_OTHER), noneBody("ios"), iosPorts(clean()).ports);
      r.activate_404_unknown_reward = await activateEndpoint(e.state, e.repo, pathOf("cccccccc-0000-4000-8000-0000000000ff"), noneBody("ios"), iosPorts(clean()).ports);
      r.activate_404_unparseable_path = await activateEndpoint(e.state, e.repo, "/functions/v1/rewards-activate", noneBody("ios"), iosPorts(clean()).ports);
    }
    {
      const e = world("ios", false);
      earn(e, R1, "offer_code");
      rewardsState(e.state).demoAccounts.add(UID);
      r.activate_403_demo_account = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("ios"), iosPorts(clean()).ports);
    }
    {
      const e = world("ios", false);
      earn(e, R1, "offer_code");
      r.activate_422_platform_mismatch = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("android"), { ios: null, android: scriptedAndroid });
    }
    {
      const e = world("ios", false);
      earn(e, R1, "offer_code");
      for (let i = 1; i < 20; i += 1) seedDevice(e.state, { id: `dddddddd-0000-4000-8000-${String(i).padStart(12, "0")}`, userId: UID, platform: "ios" });
      // 20 devices are on record (the cap), and this one is new.
      r.activate_422_device_limit = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("ios", false, { deviceId: "eeeeeeee-0000-4000-8000-000000000001" }), iosPorts(clean()).ports);
    }
    {
      const e = world("ios");
      earn(e, R1, "offer_code");
      earn(e, R2, "entitlement");
      const { ports } = iosPorts(clean());
      const c = await live(e);
      await activateEndpoint(e.state, e.repo, pathOf(R1), await iosBody(R1, c), ports); // consumes the single-use live challenge
      // A live challenge is single-use (and lasts 120 s): the same one cannot carry a second activation.
      r.activate_422_challenge_not_consumable = await activateEndpoint(e.state, e.repo, pathOf(R2), await iosBody(R2, c), ports);
    }
    {
      const e = world("ios", false);
      earn(e, R1, "offer_code");
      e.state.rateLimits.set(`${UID}:rewards-activate:user`, 10); // 10 an hour per account: the next hit is the 11th
      r.activate_429_rate_limited = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("ios"), iosPorts(clean()).ports);
    }
    {
      const e = world("ios", false);
      earn(e, R1, "offer_code");
      const { ports } = iosPorts(clean());
      // the reward id belongs in the PATH only
      r.activate_400_reward_id_in_body = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("ios", false, { rewardId: R1 }), ports);
      r.activate_400_install_link_on_ios = await activateEndpoint(e.state, e.repo, pathOf(R1), noneBody("ios", false, { installLinkId: LINK }), ports);
      r.activate_400_attestation_without_challenge = await activateEndpoint(e.state, e.repo, pathOf(R1), { deviceId: FAKE_DEVICE_ID, platform: "android", attestation: { kind: "android", integrityToken: "it-whatever" } }, ports);
    }
  }
  rbCounter = rbBeforeP42b3b;

  // ---------------- batch (the REAL handleEvidenceBatchIntake) ----------------
  {
    const e = fresh();
    const items = [
      { ...selfReport, localDate: "2026-05-10" },
      { ...healthWorkout, localDate: "2026-05-12" },
      { ...selfReport, localDate: "2026-05-10" }, // a byte-for-byte replay inside the batch
      { ...selfReport, localDate: "2026-05-11", facilityId: "fac_ghost" }, // 422 unknown_id
      { ...selfReport, source: "file_import", localDate: "2026-05-13" }, // 400 bad_request
      { ...selfReport, localDate: "2026-02-01" }, // 422 local_date_out_of_window
    ];
    r.batch_200_mixed = await batchEndpoint({ items });
    r.batch_400_too_many = await batchEndpoint({ items: Array.from({ length: MAX_BATCH_ITEMS_PER_REQUEST + 1 }, () => selfReport) });
    r.batch_400_not_items = await batchEndpoint({ nope: [] });
    // the per-item daily cap (2,000): exhausting it makes later items `rate_limited` (item-level, still HTTP 200)
    e.state.rateLimits.set(`${UID}:evidence-batch:user`, 1999);
    r.batch_200_rate_limited_item = await batchEndpoint({ items: [{ ...selfReport, localDate: "2026-05-14" }, { ...selfReport, localDate: "2026-05-15" }] });
  }

  // ---------------- vectors ----------------
  const samples: Record<string, Record<string, unknown>> = {
    checkin: checkin("fixV1", { checkinTokenJti: "jti_1" }) as Record<string, unknown>,
    dwell: dwell("fixV2", "fixV3", "jti_2", "jti_3"),
    self_report: selfReport,
    health_workout: healthWorkout,
    self_report_reordered_keys: Object.fromEntries(Object.entries(selfReport).reverse()),
  };
  const sourceRefs: Record<string, unknown> = {};
  for (const [name, body] of Object.entries(samples)) {
    const { checks, submission } = planEvidenceRateLimitChecks(body);
    void checks;
    sourceRefs[name] = { request: body, sourceRef: await deriveSourceRef(submission), inputHash: await computeInputHash(submission) };
  }
  const nonce = toBase64Url(randomBytes(32));
  const uuid = (n: number): string => `${"0123456789abcdef"[n]!.repeat(8)}-1111-4111-8111-${"0123456789ab"[n % 12]!.repeat(12)}`;
  const body = { rewardId: uuid(1), deviceId: uuid(2), platform: "android" as const, challengeId: uuid(3), installLinkId: "0123456789abcdef" };
  const challengeBytes = randomBytes(32);
  const dct = "a".repeat(64);
  const ios = { rewardId: uuid(1), deviceId: uuid(2), challengeId: uuid(3), deviceCheckTokenSha256: dct, nonce };
  const keyId = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq=";
  const reg = { challengeId: uuid(3), deviceId: uuid(2), keyId, nonce };
  const vectors = {
    sourceRefs,
    binding: {
      androidRequestBinding: {
        body,
        challengeBase64Url: toBase64Url(challengeBytes),
        canonicalBodyUtf8: new TextDecoder().decode(boundBodyBytes(body)),
        canonicalBodyHex: toHex(boundBodyBytes(body)),
        hashHex: toHex(await computeRequestBinding(sha256, body, challengeBytes)),
      },
      androidRequestBindingNoInstallLink: {
        body: { ...body, installLinkId: undefined },
        challengeBase64Url: toBase64Url(challengeBytes),
        hashHex: toHex(await computeRequestBinding(sha256, { rewardId: body.rewardId, deviceId: body.deviceId, platform: "android", challengeId: body.challengeId }, challengeBytes)),
      },
      iosActivation: { body: ios, challengeString: iosActivationChallengeString(ios), hashHex: toHex(await computeIosActivationBinding(sha256, ios)) },
      iosAttestKey: { body: reg, challengeString: attestKeyChallengeString(reg), hashHex: toHex(await computeAttestKeyBinding(sha256, reg)) },
      // The check-in binding (P4.2b-2), for the fixed inputs of docs/security/p3-money-path-requirements.md (the newest section, "check-in attestation"): the server's own output.
      checkin: {
        body: CHECKIN_VECTOR_BODY,
        nonce: CHECKIN_VECTOR_NONCE,
        ios: { challengeString: iosCheckinChallengeString({ ...CHECKIN_VECTOR_BODY, nonce: CHECKIN_VECTOR_NONCE }), clientDataHashHex: toHex(await computeIosCheckinBinding(sha256, { ...CHECKIN_VECTOR_BODY, nonce: CHECKIN_VECTOR_NONCE })) },
        android: {
          canonicalBodyUtf8: new TextDecoder().decode(checkinAndroidBoundBodyBytes(CHECKIN_VECTOR_BODY)),
          requestHash: toBase64Url(await computeCheckinAndroidBinding(sha256, CHECKIN_VECTOR_BODY, fromBase64UrlStrict(CHECKIN_VECTOR_NONCE)!)),
        },
      },
      canonicalJsonSample: { input: { b: [2, { z: 1, a: "x" }], a: null, c: true }, output: canonicalJson({ b: [2, { z: 1, a: "x" }], a: null, c: true }) },
    },
  };
  // The offline code, as the SERVER's own `totp.ts` computes it for the recorded seed (`responses.offlineseed_200`): the mobile TOTP is compared with these (a second, independent check
  // of the same function lives in `test/offline-code-totp.test.ts`, which imports the server module directly).
  const seedBytes = base32Decode(offlineSeedB32);
  const codeAtStep = async (step: number): Promise<string> => hotp(seedBytes, step);
  const offlineTimes = [0, 1, 599, 600, 601, 1_790_000_000, 1_790_000_399, 1_790_000_400, 1_790_000_999, 1_790_001_000];
  let leadingZeroStep = 0;
  while ((await codeAtStep(leadingZeroStep))[0] !== "0") leadingZeroStep += 1;
  (vectors as Record<string, unknown>).offlineCode = {
    seedFrom: "responses.offlineseed_200.body (data.seed)",
    stepSeconds: OFFLINE_CODE_STEP_SECONDS,
    times: await Promise.all(offlineTimes.map(async (unixSeconds) => ({ unixSeconds, step: stepOf(unixSeconds), code: await codeAtStep(stepOf(unixSeconds)) }))),
    leadingZero: { step: leadingZeroStep, unixSeconds: leadingZeroStep * OFFLINE_CODE_STEP_SECONDS, code: await codeAtStep(leadingZeroStep) },
  };
  // `undefined` must not leak into the JSON (`installLinkId: undefined` above is dropped by stringify)
  return { responses: r, vectors };
}

describe("record the evidence-lane edge contract from the real handlers", () => {
  it("matches (or, with RECORD_EDGE_CONTRACT=1, rewrites) test/fixtures/edge-contract.json", async () => {
    const { responses, vectors } = await record();
    const file = JSON.parse(readFileSync(FIXTURE, "utf8")) as { _provenance: string; [k: string]: unknown; responses: Record<string, Entry> };
    const kept = Object.fromEntries(Object.entries(file.responses).filter(([k]) => !OWNED_PREFIXES.some((p) => k.startsWith(p))));
    const next = {
      ...file,
      _provenance_p42b1:
        "Evidence-lane entries (keys starting challenge_, token_, evidence_, batch_, attestkey_) and `vectors` were recorded 2026-10-03 by apps/mobile/scripts/record-edge-contract.rec.ts, which runs the REAL handlers (evidence, evidence-batch (handleEvidenceBatchIntake unmodified), checkin-challenge, checkin-token, devices-attest-key) and the real binding / source-ref code over the server's own fakes; the Apple / Google verification PORTS are scripted (accept exactly the base64url of the binding the real code computed; see the script's header), behind the real envelope (http.ts). Only privileged.ts is replaced by in-memory rate limits and savepoint-less per-item isolation. Each entry carries the `request` that produced it, so the client's request builders are compared with bodies the real parser accepted or refused. Re-run the script (see its header) after any server change; with no RECORD_EDGE_CONTRACT it fails when the fixture is stale.",
      _provenance_p42b3b:
        "Entries starting offlineseed_ and activate_ (and `vectors.offlineCode`) were recorded by the same script (P4.2b-3b) from the REAL handlers: me-offline-seed (handleOfflineSeedRequest, over the server's in-memory offline-code repo; the seed is the server test suite's independent reference derivation under its TEST key, not a production secret) and rewards-activate (handleActivation, parseActivationBody, extractRewardId, enforceActivationRateLimits, over the in-memory rewards repo) with the scripted Apple / Google ports described above. Only privileged.ts is replaced (in-memory rate limits) and, as for checkin-token, the rollback of the handler's transaction on a thrown error is emulated. `vectors.offlineCode` holds codes the server's totp.ts computed.",
      responses: { ...kept, ...responses },
      vectors: JSON.parse(JSON.stringify(vectors)),
    };
    const text = JSON.stringify(next, null, 2) + "\n";
    if (process.env["RECORD_EDGE_CONTRACT"] === "1") writeFileSync(FIXTURE, text);
    else expect(text, "the committed fixture is stale: re-run with RECORD_EDGE_CONTRACT=1 and review the diff").toBe(readFileSync(FIXTURE, "utf8"));
    // a few sanity checks that the recording saw what it set out to see
    expect(responses.evidence_accepted_with_challenge!.status).toBe(200);
    expect(responses.evidence_202_queued_catalog!.status).toBe(202);
    expect(responses.evidence_422_catalog_stale!.status).toBe(422);
    expect(responses.evidence_409_conflict!.status).toBe(409);
    expect(responses.evidence_429_rate_limited!.status).toBe(429);
    expect(responses.batch_200_mixed!.status).toBe(200);
    expect([responses.token_503_attestation_not_configured!.status, responses.token_503_attestation_unavailable!.status]).toEqual([503, 503]);
    expect(JSON.parse(responses.token_201_attested_android!.body).data.attestationGrade).toBe("attested");
    expect(JSON.parse(responses.token_201_attested_ios!.body).data.attestationGrade).toBe("attested");
    expect(JSON.parse(responses.token_201_failed_attested_before_no_token!.body).data.attestationGrade).toBe("failed");
    expect(responses.attestkey_201_registered!.status).toBe(201);
    // P4.2b-3b: what the recording must have seen
    expect(responses.offlineseed_200!.status).toBe(200);
    expect(JSON.parse(responses.offlineseed_200_same_seed_again!.body).data.seed).toBe(JSON.parse(responses.offlineseed_200!.body).data.seed);
    expect(JSON.parse(responses.offlineseed_200_rotate!.body).data).toMatchObject({ seedVersion: 2 });
    expect([responses.offlineseed_404_foreign_device!.status, responses.offlineseed_404_unknown_device!.status, responses.offlineseed_400_unknown_key!.status, responses.offlineseed_429_reveal_limit!.status, responses.offlineseed_503_not_provisioned!.status]).toEqual([404, 404, 400, 429, 503]);
    expect(JSON.parse(responses.activate_200_issued_ios!.body).data).toMatchObject({ state: "issued", held: false, replay: false });
    expect(JSON.parse(responses.activate_200_replay_already_active!.body).data).toMatchObject({ state: "issued", replay: true });
    expect(JSON.parse(responses.activate_200_redeemable_ios_entitlement!.body).data).toMatchObject({ kind: "entitlement", state: "redeemable", held: false });
    expect(JSON.parse(responses.activate_200_held_review_bit0_new_account!.body).data).toMatchObject({ state: "held_review", held: true, replay: false });
    expect(JSON.parse(responses.activate_200_issued_android!.body).data).toMatchObject({ state: "issued", held: false });
    expect(JSON.parse(responses.activate_200_held_android_no_install_link!.body).data).toMatchObject({ state: "held_review", held: true });
    expect(JSON.parse(responses.activate_200_issued_android_after_503!.body).data).toMatchObject({ state: "issued" });
    expect([responses.activate_409_not_activatable!.status, responses.activate_409_expired!.status, responses.activate_404_foreign_reward!.status, responses.activate_403_demo_account!.status, responses.activate_422_platform_mismatch!.status, responses.activate_422_device_limit!.status, responses.activate_422_challenge_not_consumable!.status, responses.activate_429_rate_limited!.status, responses.activate_503_attestation_unavailable!.status, responses.activate_503_attestation_not_configured!.status]).toEqual([409, 409, 404, 403, 422, 422, 422, 429, 503, 503]);
    expect(responses.attestkey_409_already_registered!.status).toBe(409);
    void errorResponse;
  });
});
