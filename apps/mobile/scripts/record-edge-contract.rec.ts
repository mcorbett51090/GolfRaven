/**
 * Records `test/fixtures/edge-contract.json` entries for the EVIDENCE lane (P4.2b-1) by running the REAL server handlers:
 *   supabase/functions/_shared/evidence/handler.ts           (POST /v1/evidence)
 *   supabase/functions/_shared/evidence/batch-handler.ts     (POST /v1/evidence/batch; the REAL `handleEvidenceBatchIntake`)
 *   supabase/functions/_shared/checkin/challenge-handler.ts  (POST /v1/checkin/challenge)
 *   supabase/functions/_shared/checkin/token-handler.ts      (POST /v1/checkin/token)
 *   supabase/functions/_shared/evidence/source-ref.ts, rewards/binding.ts, rewards/string-binding.ts, rewards/app-attest-registration.ts
 * behind the real envelope code (`_shared/http.ts` handleRequest / okResponse / HttpError), over the server's own unit-test fakes
 * (`supabase/tests/unit/fake-repo.ts`). The only thing replaced is `_shared/privileged.ts` (it needs a live Postgres): `hitRateLimitForActor`
 * and `withOwnershipBatch` are swapped for their in-memory equivalents, so `handleEvidenceBatchIntake` itself runs unmodified.
 * The small bodies of each `<function>/index.ts` (rate-limit pre-checks, status mapping, `maxBodyBytes`) are replicated below exactly as those files
 * write them.
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
const OWNED_PREFIXES = ["challenge_", "token_", "evidence_", "batch_"];
const UID = "user-a";
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

function fresh(): { state: FakeState; repo: ReturnType<typeof makeFakeRepo> } {
  const state = makeFakeState();
  hoisted.current.state = state;
  return { state, repo: makeFakeRepo(state, UID) };
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
 * attestation shapes), then the handler with the attestation ports exactly as the entrypoint builds them. No platform is configured here, so a request
 * that carries an attestation block would answer 503 `attestation_not_configured`; the recorded requests carry none. */
async function tokenEndpoint(repo: ReturnType<typeof makeFakeRepo>, body: Record<string, unknown>): Promise<Entry> {
  const res = await handleRequest(async () => {
    const parsed = parseTokenBody(body);
    if (!parsed.ok) throw Errors.badRequest("invalid checkin-token request", parsed.issues);
    return okResponse(201, await handleTokenRequest(parsed.value, repo, digestHex, { userId: UID, ports: { ios: null, android: null }, sha256 }));
  });
  return toEntry(res, body);
}

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
      canonicalJsonSample: { input: { b: [2, { z: 1, a: "x" }], a: null, c: true }, output: canonicalJson({ b: [2, { z: 1, a: "x" }], a: null, c: true }) },
    },
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
        "Evidence-lane entries (keys starting challenge_, token_, evidence_, batch_) and `vectors` were recorded 2026-10-03 by apps/mobile/scripts/record-edge-contract.rec.ts, which runs the REAL handlers (evidence, evidence-batch (handleEvidenceBatchIntake unmodified), checkin-challenge, checkin-token) and the real binding / source-ref code over the server's own fakes, behind the real envelope (http.ts). Only privileged.ts is replaced by in-memory rate limits and savepoint-less per-item isolation. Each entry carries the `request` that produced it, so the client's request builders are compared with bodies the real parser accepted or refused. Re-run the script (see its header) after any server change; with no RECORD_EDGE_CONTRACT it fails when the fixture is stale.",
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
    void errorResponse;
  });
});
