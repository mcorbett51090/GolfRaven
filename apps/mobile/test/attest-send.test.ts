/**
 * P4.2b-2: how the evidence send reacts to the redeemer (`src/evidence/send.ts`): a vendor 503 keeps the SAME held challenge for a retry; a deferral is counted on the
 * challenge and bounded; the bound drops the challenge (no token-less request, no fraud signal). Then end to end through the real HTTP client over the RECORDED answers.
 */
import { describe, expect, it } from "vitest";
import { createHttpApiClient } from "../src/api";
import { ATTEST_MAX_DEFERRALS, AttestationDeferred, NativeRedeemer, AttestStateStore, KeyedMutex, NativeAttestor } from "../src/attest";
import { evidencePenaltyApplies, parseEvidencePayload, sendEvidenceItem, type SendDeps } from "../src/evidence";
import { applyAnswer, createItem, type OutboxItem, type ServerAnswer } from "../src/outbox";
import { MemorySecureStore } from "../src/secure";
import { recorded, scriptedFetch, type Step } from "./support/edge-fixtures";
import { FakeNativeAttestModule } from "./support/fake-native-attest";
import { T0, itemFor, wireOf } from "./support/evidence";
import { apiError, jwt } from "./support/fakes";

const NONCE = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
const CREDS = { userId: "user-a", accessToken: jwt({ sub: "user-a" }) };
const BASE = "https://p.supabase.co/functions/v1";

function held(over: Record<string, unknown> = {}): OutboxItem {
  const base = itemFor(wireOf("evidence_accepted_no_challenge"), 1);
  const p = JSON.parse(JSON.stringify(base.payload)) as { challenges: Record<string, unknown> };
  const k = Object.keys(p.challenges)[0]!;
  p.challenges[k] = { state: "held", challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", nonce: NONCE, kind: "prefetched", expiresAt: T0 + 20 * 3600_000, ...over };
  return { ...createItem({ id: "ev1", sourceRef: "r", ownerUserId: "user-a", courseId: base.courseId, catalogVersion: base.catalogVersion, payload: p as never }, T0), status: "sent" };
}
const challengeOf = (item: OutboxItem) => {
  const parsed = parseEvidencePayload(item.payload);
  if (!parsed.ok) throw new Error(parsed.message);
  return Object.values(parsed.payload.challenges)[0]!;
};
const OK_POST: ServerAnswer = { kind: "response", status: 200, code: "accepted" } as never;

function deps(redeem: SendDeps["redeem"], persisted: unknown[] = [], posts: unknown[] = []): SendDeps {
  return {
    now: () => T0,
    redeem,
    post: async (body) => {
      posts.push(body);
      return OK_POST;
    },
    persistPayload: async (_item, payload) => {
      persisted.push(payload);
    },
  };
}

describe("a vendor 503 (attestation_unavailable / attestation_not_configured) keeps the SAME held challenge: a retry, never a dead letter", () => {
  it.each(["attestation_unavailable", "attestation_not_configured"])("%s", async (code) => {
    const item = held();
    const seen: string[] = [];
    const posts: unknown[] = [];
    const persisted: unknown[] = [];
    const d = deps(async (req) => {
      seen.push(req.challengeId);
      throw apiError("unavailable", 503, code);
    }, persisted, posts);
    const answer = await sendEvidenceItem(d, item, CREDS);
    expect(answer).toEqual({ kind: "response", status: 503, code });
    expect(posts).toEqual([]); // the evidence was not sent
    expect(persisted).toEqual([]); // the payload was not rewritten: the challenge is untouched
    expect(answer).not.toHaveProperty("payload");
    // the outbox reads it as a retry, not a dead letter
    const next = applyAnswer(item, answer, T0, () => 0.5);
    expect(next.status).toBe("retry");
    expect(challengeOf(next)).toMatchObject({ state: "held", challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" });
    // the retry redeems the same challenge again
    await sendEvidenceItem(d, next, CREDS);
    expect(seen).toEqual(["cccccccc-cccc-4ccc-8ccc-cccccccccccc", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"]);
  });

  it("the redeemer is told the device the challenge was issued to (the payload's deviceId) and the owner's credentials", async () => {
    let got: unknown;
    await sendEvidenceItem(
      deps(async (req, creds) => {
        got = { req, creds };
        throw apiError("unavailable", 503, "attestation_unavailable");
      }),
      held(),
      CREDS,
    );
    expect(got).toEqual({ req: { challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", nonce: NONCE, deviceId: "11111111-1111-4111-8111-111111111111" }, creds: CREDS });
  });
});

describe("an attestation that cannot be produced now is a counted, bounded deferral; the bound drops the challenge", () => {
  it("each deferral: a retry answer (never a dead letter), the challenge stays `held` with the count, the count is persisted before the answer", async () => {
    let item = held();
    const persisted: unknown[] = [];
    const posts: unknown[] = [];
    const d = deps(() => Promise.reject(new AttestationDeferred("integrity_token_unavailable")), persisted, posts);
    for (let n = 1; n <= ATTEST_MAX_DEFERRALS; n += 1) {
      const answer = await sendEvidenceItem(d, item, CREDS);
      expect(answer.kind, `attempt ${n}`).toBe("network_error");
      const next = applyAnswer(item, answer, T0, () => 0.5);
      expect(next.status, `attempt ${n}`).toBe("retry");
      expect(challengeOf(next), `attempt ${n}`).toMatchObject({ state: "held", attestDeferrals: n, challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" });
      expect(persisted, `attempt ${n}`).toHaveLength(n);
      item = { ...next, status: "sent" }; // the runner marks it `sent` again before the next attempt
    }
    expect(posts).toEqual([]); // nothing was ever sent token-less, and no evidence went without its challenge yet
  });

  it(`after ${ATTEST_MAX_DEFERRALS} deferrals the next local failure DROPS the challenge: the fix goes with no challenge (x0.6, no co-signal), and no token-less redemption is ever made`, async () => {
    const item = held({ attestDeferrals: ATTEST_MAX_DEFERRALS });
    const persisted: unknown[] = [];
    const posts: { fix: { checkinTokenJti?: string } }[] = [];
    let redeems = 0;
    const d = deps(async () => {
      redeems += 1;
      throw new AttestationDeferred("integrity_token_unavailable");
    }, persisted, posts as unknown[]);
    const answer = await sendEvidenceItem(d, item, CREDS);
    expect(redeems).toBe(1);
    expect(posts).toHaveLength(1);
    expect(posts[0]!.fix).not.toHaveProperty("checkinTokenJti");
    expect(answer).toMatchObject({ kind: "response", status: 200 });
    const after = parseEvidencePayload((answer as unknown as { payload: never }).payload);
    expect(after.ok && Object.values(after.payload.challenges)[0]).toEqual({ state: "none", reason: "attestation_unavailable" });
    expect(after.ok && evidencePenaltyApplies(after.payload)).toBe(true);
    expect(persisted).toHaveLength(1);
  });

  it("the count is read from the stored payload, so it survives a restart: 7 deferrals + 1 more = 8, still held", async () => {
    const item = held({ attestDeferrals: ATTEST_MAX_DEFERRALS - 1 });
    const answer = await sendEvidenceItem(deps(() => Promise.reject(new AttestationDeferred("x"))), item, CREDS);
    expect(answer.kind).toBe("network_error");
    expect(challengeOf(applyAnswer(item, answer, T0, () => 0.5))).toMatchObject({ state: "held", attestDeferrals: ATTEST_MAX_DEFERRALS });
  });

  it("a deferral stops BEFORE the evidence is sent and leaves any fix already redeemed in this item untouched (a dwell: one fix redeemed, the next deferred)", async () => {
    const base = itemFor(wireOf("evidence_accepted_dwell_two_challenges"), 2);
    const p = JSON.parse(JSON.stringify(base.payload)) as { challenges: Record<string, Record<string, unknown>> };
    const [k1, k2] = Object.keys(p.challenges) as [string, string];
    p.challenges[k1] = { state: "held", challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01", nonce: NONCE, kind: "prefetched", expiresAt: T0 + 3600_000 };
    p.challenges[k2] = { state: "held", challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02", nonce: NONCE, kind: "prefetched", expiresAt: T0 + 3600_000 };
    const item = { ...createItem({ id: "ev2", sourceRef: "r2", ownerUserId: "user-a", courseId: base.courseId, catalogVersion: base.catalogVersion, payload: p as never }, T0), status: "sent" as const };
    let n = 0;
    const posts: unknown[] = [];
    const answer = await sendEvidenceItem(
      deps(async (req) => {
        n += 1;
        if (n === 2) throw new AttestationDeferred("assertion_unavailable");
        return { jti: `jti_${req.challengeId.slice(-2)}`, expiresAt: "x", attestationGrade: "attested" as const };
      }, [], posts),
      item,
      CREDS,
    );
    expect(posts).toEqual([]);
    const after = parseEvidencePayload((answer as unknown as { payload: never }).payload);
    expect(after.ok && after.payload.challenges[k1]).toMatchObject({ state: "redeemed", jti: "jti_01", grade: "attested" });
    expect(after.ok && after.payload.challenges[k2]).toMatchObject({ state: "held", attestDeferrals: 1 });
  });
});

describe("end to end: the real HTTP client, the native redeemer over a fake module, the RECORDED server answers", () => {
  function client(platform: "ios" | "android", steps: Step[], opts: { fetch?: Parameters<typeof createHttpApiClient>[0]["fetch"] } = {}) {
    const module = new FakeNativeAttestModule();
    const secure = new MemorySecureStore();
    const state = new AttestStateStore(secure);
    const attestor = new NativeAttestor(module, platform, platform === "android" ? "123456789012" : null);
    const redeemer = new NativeRedeemer({ attestor, state, locks: new KeyedMutex({ holdTimeoutMs: 60_000 }) });
    const f = scriptedFetch(...steps);
    const api = createHttpApiClient({
      baseUrl: BASE,
      fetch: opts.fetch ?? f.fetch,
      getAccessToken: () => Promise.reject(new Error("the evidence client must never fetch its own token")),
      rng: () => 0.5,
      sleep: () => Promise.resolve(),
      now: () => T0,
      redeemer,
    });
    return { api, seen: f.seen, module, state };
  }
  const fn = (u: string) => u.split("/").pop();

  it("Android: the recorded 503 attestation_unavailable leaves the challenge held; the retry sends the SAME challenge and nonce with an attestation and is graded `attested`; the fact is remembered", async () => {
    const { api, seen, state } = client("android", [{ respond: "token_503_attestation_unavailable" }, { respond: "token_201_attested_android" }, { respond: "evidence_accepted_with_challenge" }]);
    const item = held();
    const first = await api.submitEvidence(item, CREDS);
    expect(first).toMatchObject({ kind: "response", status: 503, code: "attestation_unavailable" });
    expect(applyAnswer(item, first, T0, () => 0.5).status).toBe("retry");
    expect(first).not.toHaveProperty("payload"); // nothing about the challenge changed
    const second = await api.submitEvidence(item, CREDS);
    expect(second).toMatchObject({ kind: "response", status: 200 });
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-token", "checkin-token", "evidence"]);
    type Tok = { challengeId: string; nonce: string; hardwareSupportsAttestation: boolean; attestation: { platform: string } };
    const a = seen[0]!.body as Tok;
    const b = seen[1]!.body as Tok;
    expect([a.challengeId, a.nonce]).toEqual([b.challengeId, b.nonce]);
    expect([a.hardwareSupportsAttestation, b.hardwareSupportsAttestation]).toEqual([true, true]);
    expect([a.attestation.platform, b.attestation.platform]).toEqual(["android", "android"]);
    expect(Object.keys(a).sort()).toEqual(["attestation", "challengeId", "hardwareSupportsAttestation", "nonce"]);
    expect(await state.hasAttestedAndroid("user-a", "11111111-1111-4111-8111-111111111111")).toBe(true);
    expect(((seen[2]!.body as { fix: { checkinTokenJti?: string } }).fix.checkinTokenJti)).toBe(JSON.parse(recorded("token_201_attested_android").body).data.jti);
  });

  it("Android, attested before + Play Integrity failing locally: NO token-less request reaches the server (the recorded rule would grade it `failed`); the item retries", async () => {
    const { api, seen, module } = client("android", [{ respond: "token_201_attested_android" }, { respond: "evidence_accepted_with_challenge" }]);
    await api.submitEvidence(held(), CREDS); // attested -> remembered
    seen.length = 0;
    module.always.integrityToken = { ok: false, code: "unavailable", message: "Play services updating" };
    const item = held({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" });
    const answer = await api.submitEvidence(item, CREDS);
    expect(answer.kind).toBe("network_error");
    expect(seen).toEqual([]); // nothing was sent
    expect(JSON.parse(recorded("token_201_failed_attested_before_no_token").body).data.attestationGrade).toBe("failed"); // what a token-less request would have been graded
    expect(applyAnswer(item, answer, T0, () => 0.5).status).toBe("retry");
  });

  it("iOS first need, all over the wire: live challenge -> devices-attest-key (strict body) -> checkin-token with the assertion -> evidence; the key is kept", async () => {
    const { api, seen, state } = client("ios", [{ respond: "challenge_live_201" }, { respond: "attestkey_201_registered" }, { respond: "token_201_attested_ios" }, { respond: "evidence_accepted_with_challenge" }]);
    const answer = await api.submitEvidence(held(), CREDS);
    expect(answer).toMatchObject({ kind: "response", status: 200 });
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-challenge", "devices-attest-key", "checkin-token", "evidence"]);
    expect(seen[0]!.body).toEqual({ deviceId: "11111111-1111-4111-8111-111111111111" }); // a LIVE challenge: no prefetchCount
    expect(Object.keys(seen[1]!.body as object).sort()).toEqual(["attestation", "challengeId", "deviceId", "keyId", "nonce"]);
    const tok = seen[2]!.body as { hardwareSupportsAttestation: boolean; attestation: { platform: string; keyId: string; assertion: string } };
    expect(tok.hardwareSupportsAttestation).toBe(true);
    expect(Object.keys(tok.attestation).sort()).toEqual(["assertion", "keyId", "platform"]);
    expect(tok.attestation.keyId).toBe((seen[1]!.body as { keyId: string }).keyId);
    expect(await state.getIosKey("user-a", "11111111-1111-4111-8111-111111111111")).toMatchObject({ state: "registered", keyId: tok.attestation.keyId });
    for (const s of seen) expect(s.headers["Authorization"]).toBe(`Bearer ${CREDS.accessToken}`); // always the owner's token
  });

  it.each([
    ["attestkey_409_already_registered", "the server already holds this key (an earlier request was applied, its answer lost): treated as registered, the check-in proceeds attested"],
  ])("iOS registration answer %s: %s", async (name) => {
    const { api, seen, state } = client("ios", [{ respond: "challenge_live_201" }, { respond: name }, { respond: "token_201_attested_ios" }, { respond: "evidence_accepted_with_challenge" }]);
    const answer = await api.submitEvidence(held(), CREDS);
    expect(answer).toMatchObject({ kind: "response", status: 200 });
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-challenge", "devices-attest-key", "checkin-token", "evidence"]);
    expect(await state.getIosKey("user-a", "11111111-1111-4111-8111-111111111111")).toMatchObject({ state: "registered" });
  });

  it("iOS registration answer attestkey_422_rejected (the real handler's generic 422): nothing is registered, the record is cleared, and the check-in goes token-less with the claim FALSE (the server grades `unattestable`, not `failed`)", async () => {
    expect(recorded("attestkey_422_rejected").status).toBe(422);
    const { api, seen, state } = client("ios", [{ respond: "challenge_live_201" }, { respond: "attestkey_422_rejected" }, { respond: "token_201_unattestable" }, { respond: "evidence_accepted_with_challenge" }]);
    const answer = await api.submitEvidence(held(), CREDS);
    expect(answer).toMatchObject({ kind: "response", status: 200 });
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-challenge", "devices-attest-key", "checkin-token", "evidence"]);
    expect(seen[2]!.body).toEqual({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", nonce: NONCE, hardwareSupportsAttestation: false });
    expect(await state.getIosKey("user-a", "11111111-1111-4111-8111-111111111111")).toBeNull();
  });

  it("iOS registration answer attestkey_503_not_configured: a retry with the held challenge untouched (not a refusal of the challenge), the key stays `pending`", async () => {
    const { api, seen, state } = client("ios", [{ respond: "challenge_live_201" }, { respond: "attestkey_503_not_configured" }]);
    const item = held();
    const answer = await api.submitEvidence(item, CREDS);
    expect(answer).toMatchObject({ kind: "response", status: 503, code: "attestation_not_configured" });
    expect(applyAnswer(item, answer, T0, () => 0.5).status).toBe("retry");
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-challenge", "devices-attest-key"]); // no checkin-token request, no evidence
    expect(await state.getIosKey("user-a", "11111111-1111-4111-8111-111111111111")).toEqual({ state: "pending" });
  });

  it("iOS registration answer attestkey_422_challenge_not_consumable is about the LIVE registration challenge: a counted deferral of the check-in, never `none / unusable` for the held challenge", async () => {
    expect(recorded("attestkey_422_challenge_not_consumable").status).toBe(422);
    const { api } = client("ios", [{ respond: "challenge_live_201" }, { respond: "attestkey_422_challenge_not_consumable" }]);
    const item = held();
    const answer = await api.submitEvidence(item, CREDS);
    expect(answer.kind).toBe("network_error");
    expect(challengeOf(applyAnswer(item, answer, T0, () => 0.5))).toMatchObject({ state: "held", attestDeferrals: 1 });
  });

  it("iOS, two concurrent check-ins through the real client: strictly sequential end to end (the second assertion waits for the first checkin-token answer)", async () => {
    const log: string[] = [];
    const gates: Array<() => void> = [];
    const module = new FakeNativeAttestModule();
    const push = module.events.push.bind(module.events);
    module.events.push = (...e) => {
      for (const ev of e) log.push(`native:${ev.op}`);
      return push(...e);
    };
    const secure = new MemorySecureStore();
    const state = new AttestStateStore(secure);
    const attestor = new NativeAttestor(module, "ios", null);
    const redeemer = new NativeRedeemer({ attestor, state, locks: new KeyedMutex({ holdTimeoutMs: 60_000 }) });
    // the key is already registered
    await state.setIosKey("user-a", "11111111-1111-4111-8111-111111111111", { state: "registered", keyId: (await attestor.generateKey()).kind === "ok" ? [...module.keys][0]! : "" });
    log.length = 0;
    const fetch: Parameters<typeof createHttpApiClient>[0]["fetch"] = async (url) => {
      const name = fn(url)!;
      log.push(`http:${name}:start`);
      if (name === "checkin-token") await new Promise<void>((r) => gates.push(r));
      log.push(`http:${name}:end`);
      const r = recorded(name === "checkin-token" ? "token_201_attested_ios" : "evidence_accepted_with_challenge");
      return new Response(r.body, { status: r.status, headers: { "content-type": "application/json" } });
    };
    const api = createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: () => Promise.reject(new Error("no")), rng: () => 0.5, sleep: () => Promise.resolve(), now: () => T0, redeemer });
    const i1 = held({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" });
    const i2 = { ...held({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), id: "ev2", sourceRef: "r2" };
    const p1 = api.submitEvidence(i1, CREDS);
    const p2 = api.submitEvidence(i2, CREDS);
    for (let i = 0; i < 100; i += 1) await Promise.resolve();
    expect(log).toEqual(["native:generateAssertion", "http:checkin-token:start"]); // the second has not asserted
    gates.shift()!();
    for (let i = 0; i < 100; i += 1) await Promise.resolve();
    expect(log.indexOf("http:checkin-token:end")).toBeLessThan(log.lastIndexOf("native:generateAssertion"));
    expect(log.filter((l) => l === "native:generateAssertion")).toHaveLength(2);
    gates.shift()!();
    await Promise.all([p1, p2]);
    // never two checkin-token requests in flight at once
    let inFlight = 0;
    let max = 0;
    for (const l of log) {
      if (l === "http:checkin-token:start") inFlight += 1;
      if (l === "http:checkin-token:end") inFlight -= 1;
      max = Math.max(max, inFlight);
    }
    expect(max).toBe(1);
  });

  it("the live path (ChallengeManager.tryLive -> redeemCheckinChallenge) goes through the same redeemer, bound to the device the challenge was issued to", async () => {
    const { api, seen } = client("android", [{ respond: "token_201_attested_android" }]);
    const t = await api.redeemCheckinChallenge({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", nonce: NONCE, deviceId: "11111111-1111-4111-8111-111111111111" }, CREDS);
    expect(t.attestationGrade).toBe("attested");
    expect(seen).toHaveLength(1);
    expect(seen[0]!.body).toMatchObject({ hardwareSupportsAttestation: true, attestation: { platform: "android" } });
  });
});
