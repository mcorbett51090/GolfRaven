/**
 * P4.2b-1: the evidence request bodies and the server's answers, against what the REAL handlers produced (`fixtures/edge-contract.json`, recorded by
 * `scripts/record-edge-contract.rec.ts`). The server wins over the plan table: a new or replayed play is `200 accepted` (not 201 / 409 duplicate).
 */
import { describe, expect, it } from "vitest";
import { createHttpApiClient, type ApiClient } from "../src/api";
import { answerFromHttp, answersFromBatchHttp, BATCH_CODE_STATUS } from "../src/api/evidence-answer";
import { UnattestableAttestor } from "../src/attest";
import {
  buildEvidenceBody,
  deriveEvidenceSourceRef,
  evidenceInputHash,
  evidencePenaltyApplies,
  eventTimeMs,
  parseEvidencePayload,
  toJsonValue,
  type EvidencePayload,
} from "../src/evidence";
import { applyAnswer, classifyAnswer, createItem, type EvidenceCredentials, type OutboxItem, type ServerAnswer } from "../src/outbox";
import { RECORDED, VECTORS, recorded, scriptedFetch, type Step } from "./support/edge-fixtures";
import { T0, itemFor, payloadFromWire, wireOf } from "./support/evidence";

const BASE = "https://proj.supabase.co/functions/v1";
const CREDS: EvidenceCredentials = { userId: "user-a", accessToken: "token-A" };

function client(steps: Step[], over: { now?: () => number; persist?: (i: OutboxItem, p: unknown) => Promise<void> } = {}) {
  const { fetch, seen } = scriptedFetch(...steps);
  const sleeps: number[] = [];
  const tokenFetches: (string | null)[] = [];
  const api: ApiClient = createHttpApiClient({
    baseUrl: BASE,
    fetch,
    // The client must never fetch a token for evidence: if it does, the test sees it.
    getAccessToken: (o) => {
      tokenFetches.push(o?.forceRefresh ? "refresh" : "plain");
      return Promise.resolve("WRONG-TOKEN-FROM-GETACCESSTOKEN");
    },
    rng: () => 0.5,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    attestor: new UnattestableAttestor(),
    ...(over.now ? { now: over.now } : {}),
    ...(over.persist ? { persistEvidencePayload: over.persist as never } : {}),
  });
  return { api, seen, sleeps, tokenFetches };
}

describe("the request body is exactly what the server's parser accepted", () => {
  const CASES = [
    "evidence_accepted_no_challenge",
    "evidence_accepted_with_challenge",
    "evidence_accepted_self_report",
    "evidence_accepted_health_workout",
    "evidence_accepted_dwell_two_challenges",
    "evidence_202_queued_catalog",
  ];
  it.each(CASES)("%s: the body built from the payload equals the recorded request", (name) => {
    const wire = wireOf(name);
    expect(recorded(name).status === 200 || recorded(name).status === 202).toBe(true); // the server accepted exactly this body
    const item = itemFor(wire, 1);
    const parsed = parseEvidencePayload(item.payload);
    expect(parsed.ok).toBe(true);
    const built = buildEvidenceBody(item, (parsed as { ok: true; payload: EvidencePayload }).payload);
    expect(built).toEqual({ ok: true, body: wire });
  });

  it("the whitelist: no key the server would reject, courseId present (never null), no trust fact anywhere", () => {
    const body = (buildEvidenceBody(itemFor(wireOf("evidence_accepted_with_challenge"), 1), payloadFromWire(wireOf("evidence_accepted_with_challenge"))) as { ok: true; body: Record<string, unknown> }).body;
    expect(Object.keys(body).sort()).toEqual(["catalogVersion", "courseId", "deviceId", "facilityId", "fix", "localDate", "source"]);
    expect(Object.keys(body["fix"] as object).sort()).toEqual(["accuracyMeters", "capturedAt", "checkinTokenJti", "fixId", "foreground", "fromApp", "lat", "lng", "simulated"]);
    expect(JSON.stringify(body)).not.toMatch(/attestation|grade|verificationTier|geometryKind|insideBuffer|holes|"challenge"|null/);
  });

  it("courseId and catalogVersion come from the ITEM (a re-match rewrites them), and a manifestSig for another version is not sent", () => {
    const wire = wireOf("evidence_202_queued_catalog");
    const item = { ...itemFor(wire, 1), courseId: "crs_other", catalogVersion: "20260520-a000001" } as OutboxItem;
    const body = (buildEvidenceBody(item, payloadFromWire(wire)) as { ok: true; body: Record<string, unknown> }).body;
    expect(body["courseId"]).toBe("crs_other");
    expect(body["catalogVersion"]).toBe("20260520-a000001");
    expect(body).not.toHaveProperty("manifestSig"); // it signs 20260601-b000002, not this version
  });

  it("an item with no course or no catalog version cannot be sent; a fix that still holds a challenge is not sent without it", () => {
    const wire = wireOf("evidence_accepted_no_challenge");
    expect(buildEvidenceBody({ courseId: null, catalogVersion: "20260520-a000001" }, payloadFromWire(wire))).toMatchObject({ ok: false, code: "no_course" });
    expect(buildEvidenceBody({ courseId: "crs_x1", catalogVersion: null }, payloadFromWire(wire))).toMatchObject({ ok: false, code: "no_catalog_version" });
    const p = payloadFromWire(wire);
    const fixId = (wire["fix"] as { fixId: string }).fixId;
    p.challenges[fixId] = { state: "held", challengeId: "c", nonce: "n", kind: "prefetched", expiresAt: T0 + 1000 };
    expect(buildEvidenceBody({ courseId: "crs_x1", catalogVersion: "20260520-a000001" }, p)).toMatchObject({ ok: false, code: "invalid_payload" });
  });

  it("a payload that is not exactly an EvidencePayload is refused (strict keys, one challenge per fix, import carries no fix)", () => {
    const good = toJsonValue(payloadFromWire(wireOf("evidence_accepted_no_challenge")));
    expect(parseEvidencePayload(good).ok).toBe(true);
    expect(parseEvidencePayload({ dev: true }).ok).toBe(false);
    expect(parseEvidencePayload({ ...(good as object), extra: 1 }).ok).toBe(false);
    expect(parseEvidencePayload({ ...(good as object), challenges: {} }).ok).toBe(false);
    expect(parseEvidencePayload({ ...(good as object), origin: "import" }).ok).toBe(false);
    expect(parseEvidencePayload({ ...(good as object), deviceId: "not-a-uuid" }).ok).toBe(false);
    expect(parseEvidencePayload(null).ok).toBe(false);
  });
});

describe("canonicalisation: source_ref and input_hash equal the server's own output", () => {
  for (const [name, v] of Object.entries(VECTORS.sourceRefs)) {
    it(`${name}`, () => {
      expect(deriveEvidenceSourceRef(v.request)).toBe(v.sourceRef);
      expect(evidenceInputHash(v.request)).toBe(v.inputHash);
    });
  }
  it("key order never matters; the whole content does", () => {
    expect(VECTORS.sourceRefs["self_report"]!.inputHash).toBe(VECTORS.sourceRefs["self_report_reordered_keys"]!.inputHash);
    expect(VECTORS.sourceRefs["self_report"]!.inputHash).not.toBe(VECTORS.sourceRefs["health_workout"]!.inputHash);
  });
});

describe("every recorded server answer -> the §7.6 outbox transition (real http client, fake fetch)", () => {
  const send = async (name: string | Step, over: Parameters<typeof client>[1] = {}) => {
    const { api, seen, sleeps, tokenFetches } = client([typeof name === "string" ? { respond: name } : name], over);
    const item = createItem({ ...itemFor(wireOf("evidence_accepted_no_challenge"), 1) }, T0);
    const sentItem = { ...item, status: "sent" as const, attempts: 1 };
    const answer = await api.submitEvidence(sentItem, CREDS);
    const after = applyAnswer(sentItem, answer, T0 + 10, () => 0);
    return { answer, after, seen, sleeps, tokenFetches };
  };

  const TABLE: [string, ServerAnswer, string, Record<string, unknown>][] = [
    ["evidence_accepted_no_challenge", { kind: "response", status: 200, code: "accepted" }, "accepted", {}],
    ["evidence_accepted_replay", { kind: "response", status: 200, code: "accepted" }, "accepted", {}],
    ["evidence_202_queued_catalog", { kind: "response", status: 202, code: "queued_catalog" }, "queued", {}],
    ["evidence_200_needs_attention_replay", { kind: "response", status: 200, code: "needs_attention" }, "needs_attention", { reason: "queue_expired" }],
    ["evidence_422_catalog_stale", { kind: "response", status: 422, code: "catalog_stale" }, "pending", { rematch: true }],
    ["evidence_429_rate_limited", { kind: "response", status: 429, code: "rate_limited", retryAfterSeconds: 3600 }, "retry", {}],
    ["err_500_internal", { kind: "response", status: 500, code: "internal_error" }, "retry", {}],
    ["err_503_service_unavailable", { kind: "response", status: 503, code: "service_unavailable" }, "retry", {}],
    ["evidence_409_conflict", { kind: "response", status: 409, code: "evidence_conflict" }, "needs_attention", { reason: "rejected" }],
    ["evidence_400_unknown_key", { kind: "response", status: 400, code: "bad_request" }, "needs_attention", { reason: "rejected" }],
    ["evidence_422_unknown_id", { kind: "response", status: 422, code: "unknown_id" }, "needs_attention", { reason: "rejected" }],
    ["evidence_422_catalog_forged", { kind: "response", status: 422, code: "catalog_forged" }, "needs_attention", { reason: "rejected" }],
    ["evidence_422_local_date_mismatch", { kind: "response", status: 422, code: "local_date_mismatch" }, "needs_attention", { reason: "rejected" }],
    ["err_403_forbidden", { kind: "response", status: 403, code: "forbidden" }, "needs_attention", { reason: "rejected" }],
    ["err_413_payload_too_large", { kind: "response", status: 413, code: "payload_too_large" }, "needs_attention", { reason: "rejected" }],
    ["err_401_unauthorized", { kind: "response", status: 401, code: "unauthorized" }, "retry", {}],
  ];
  it.each(TABLE)("%s", async (name, expected, status, extra) => {
    const { answer, after } = await send(name);
    expect(answer).toEqual(expected);
    expect(after).toMatchObject({ status, lastServerCode: expected.kind === "response" ? expected.code : null, ...extra });
  });

  it("the server's code is kept VERBATIM on the item for a dead letter", async () => {
    expect((await send("evidence_409_conflict")).after.lastServerCode).toBe("evidence_conflict");
    expect((await send("evidence_422_unknown_id")).after.lastServerCode).toBe("unknown_id");
  });

  it("a 429's wait comes from the body's retryAfterSeconds (the server sends no header) and is a floor on the backoff", async () => {
    const { after } = await send("evidence_429_rate_limited");
    expect(after.nextAttemptAt).toBeGreaterThanOrEqual(T0 + 10 + 3600_000);
    const hdr = await send({ status: 429, body: recorded("err_429_rate_limited").body, headers: { "retry-after": "90" } });
    expect(hdr.answer).toMatchObject({ retryAfterSeconds: 90 });
  });

  it("a network failure, a gateway page and a body that is not the contract's", async () => {
    const net = await send({ network: "connection reset" });
    expect(net.answer.kind).toBe("network_error");
    expect(net.after.status).toBe("retry");
    const gw = await send({ status: 502, body: "<html>bad gateway</html>" });
    expect(gw.answer).toEqual({ kind: "response", status: 502, code: undefined });
    expect(gw.after.status).toBe("retry");
    const odd = await send({ status: 200, body: "<html>captive portal</html>" });
    expect(odd.answer).toEqual({ kind: "response", status: 200, code: undefined });
    expect(odd.after).toMatchObject({ status: "needs_attention", reason: "unexpected_status" }); // visible, never silently "accepted"
    const unknownStatus = await send({ status: 200, body: JSON.stringify({ data: { status: "deferred", evidenceId: "x" } }) });
    expect(unknownStatus.after).toMatchObject({ status: "needs_attention", reason: "unexpected_status" });
  });

  it("the plan's own spellings are still understood: 201, and 409 duplicate", () => {
    expect(classifyAnswer({ kind: "response", status: 201 })).toEqual({ to: "accepted" });
    expect(classifyAnswer({ kind: "response", status: 409, code: "duplicate" })).toEqual({ to: "accepted" });
    expect(classifyAnswer({ kind: "response", status: 409, code: "evidence_conflict" })).toMatchObject({ to: "needs_attention" });
  });

  it("server vs plan, pinned: the real handlers answer 200 (not 201) for a new play and for a replay, 202 for a queued one", () => {
    expect(recorded("evidence_accepted_with_challenge").status).toBe(200);
    expect(JSON.parse(recorded("evidence_accepted_replay").body).data.replay).toBe(true);
    expect(recorded("evidence_accepted_replay").status).toBe(200);
    expect(recorded("evidence_202_queued_catalog").status).toBe(202);
  });
});

describe("evidence is NOT retried by the http client (the outbox owns retries; source_ref makes its replays safe)", () => {
  const item = (): OutboxItem => ({ ...itemFor(wireOf("evidence_accepted_no_challenge"), 1), status: "sent" });
  it.each<[string, Step]>([
    ["500", { respond: "err_500_internal" }],
    ["503", { respond: "err_503_service_unavailable" }],
    ["429", { respond: "evidence_429_rate_limited" }],
    ["network", { network: "reset" }],
    ["502 gateway", { status: 502, body: "x" }],
  ])("%s: exactly one request, no sleep, no backoff", async (_n, step) => {
    const { api, seen, sleeps } = client([step]);
    await api.submitEvidence(item(), CREDS);
    expect(seen).toHaveLength(1);
    expect(sleeps).toEqual([]);
  });

  it("an idempotent call still retries (the policy was not weakened for the others)", async () => {
    const { api, seen } = client([{ respond: "err_500_internal" }, { respond: "list_single" }]);
    await api.listSignInMethods();
    expect(seen).toHaveLength(2);
  });

  it("a hung request ends as a network_error answer, still one request", async () => {
    const { fetch, seen } = scriptedFetch({ hang: true });
    const api = createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: () => Promise.resolve("x"), policy: { timeoutMs: 5 } });
    const a = await api.submitEvidence(item(), CREDS);
    expect(a.kind).toBe("network_error");
    expect(seen).toHaveLength(1);
  });
});

describe("the bearer is credentials.accessToken, and only that", () => {
  it("POST evidence carries the credentials' token; the client never asks the auth service for one (not even after a 401)", async () => {
    const { api, seen, tokenFetches } = client([{ respond: "evidence_accepted_no_challenge" }, { respond: "err_401_unauthorized" }]);
    const item: OutboxItem = { ...itemFor(wireOf("evidence_accepted_no_challenge"), 1), status: "sent" };
    await api.submitEvidence(item, CREDS);
    await api.submitEvidence(item, { userId: "user-a", accessToken: "token-A2" });
    expect(seen.map((s) => s.headers["Authorization"])).toEqual(["Bearer token-A", "Bearer token-A2"]);
    expect(seen.every((s) => s.url === `${BASE}/evidence` && s.method === "POST" && s.redirect === "error" && s.credentials === "omit")).toBe(true);
    expect(tokenFetches).toEqual([]); // a 401 is an ANSWER (the runner refreshes for the item's owner), never a silent refresh of whoever is signed in
  });

  it("the check-in endpoints take explicit credentials too (no refresh, a 401 surfaces)", async () => {
    const { api, seen, tokenFetches } = client([{ respond: "err_401_unauthorized" }]);
    await expect(api.requestCheckinChallenges({ deviceId: "11111111-1111-4111-8111-111111111111", prefetchCount: 3 }, CREDS)).rejects.toMatchObject({ kind: "unauthenticated" });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.headers["Authorization"]).toBe("Bearer token-A");
    expect(tokenFetches).toEqual([]);
  });
});

describe("a local defect is a dead letter, not a retry and not a request", () => {
  it("an item whose payload is not an evidence submission is 'unsendable' with no request", async () => {
    const { api, seen } = client([{ respond: "evidence_accepted_no_challenge" }]);
    const bad: OutboxItem = { ...createItem({ id: "x", sourceRef: "dev:1", ownerUserId: "user-a", courseId: "crs_x1", catalogVersion: "20260520-a000001", payload: { dev: true } }, T0), status: "sent" };
    const a = await api.submitEvidence(bad, CREDS);
    expect(a).toMatchObject({ kind: "unsendable", code: "invalid_payload" });
    expect(seen).toEqual([]);
    expect(applyAnswer(bad, a, T0 + 1, () => 0)).toMatchObject({ status: "needs_attention", reason: "unsendable", lastServerCode: "invalid_payload", lastHttpStatus: null });
  });
});

describe("the evidence item records that it has no challenge (the x0.6 penalty path)", () => {
  it("none -> penalty flagged; redeemed or held -> not", () => {
    const wire = wireOf("evidence_accepted_no_challenge");
    expect(evidencePenaltyApplies(payloadFromWire(wire))).toBe(true);
    expect(evidencePenaltyApplies(payloadFromWire(wireOf("evidence_accepted_with_challenge")))).toBe(false);
    expect(evidencePenaltyApplies(payloadFromWire(wireOf("evidence_accepted_self_report")))).toBe(false); // no fix, no challenge to miss
  });
  it("event time: a fix's capture time; a date-only play's local date at midnight UTC", () => {
    expect(eventTimeMs(payloadFromWire(wireOf("evidence_accepted_no_challenge")))).toBe(Date.parse("2026-06-01T12:00:00.000Z"));
    expect(eventTimeMs(payloadFromWire(wireOf("evidence_accepted_self_report")))).toBe(Date.parse("2026-05-20T00:00:00Z"));
  });
});

describe("batch answers: one HTTP 200, a result per item (recorded from the real handleEvidenceBatchIntake)", () => {
  const raw = (name: string) => ({ status: recorded(name).status, headers: new Headers(), text: recorded(name).body });

  it("batch_200_mixed -> one §7.6 answer per item, in request order", () => {
    const a = answersFromBatchHttp(raw("batch_200_mixed"), 6);
    expect(a).toEqual([
      { kind: "response", status: 200, code: "accepted" },
      { kind: "response", status: 200, code: "accepted" },
      { kind: "response", status: 200, code: "accepted" }, // the in-batch replay
      { kind: "response", status: 422, code: "unknown_id" },
      { kind: "response", status: 400, code: "bad_request" },
      { kind: "response", status: 422, code: "local_date_out_of_window" },
    ]);
    expect(a.map((x) => classifyAnswer(x).to)).toEqual(["accepted", "accepted", "accepted", "needs_attention", "needs_attention", "needs_attention"]);
  });

  it("the item-level daily cap is a retry; the code is kept, and so is the server's wait hint (error.details.retryAfterSeconds, the single endpoint's 429 shape)", () => {
    const a = answersFromBatchHttp(raw("batch_200_rate_limited_item"), 2);
    expect(a[0]).toEqual({ kind: "response", status: 200, code: "accepted" });
    expect(a[1]).toEqual({ kind: "response", status: 429, code: "rate_limited", retryAfterSeconds: 86400 });
    expect(classifyAnswer(a[1]!)).toEqual({ to: "retry", retryAfterSeconds: 86400 });
    // the recorded item really carries the hint (the fixture, not this mapping, is the evidence)
    const item = (JSON.parse(recorded("batch_200_rate_limited_item").body) as { data: { results: Array<{ error?: { details?: unknown } }> } }).data.results[1]!;
    expect(item.error?.details).toEqual({ retryAfterSeconds: 86400 });
    // the single endpoint's 429 hint is read the same way
    expect(answerFromHttp({ status: recorded("evidence_429_rate_limited").status, headers: new Headers(), text: recorded("evidence_429_rate_limited").body })).toMatchObject({ status: 429, retryAfterSeconds: 3600 });
  });

  it("an item error with no usable hint carries none (a missing, non-numeric, zero or negative details value is ignored); other item errors never gain one", () => {
    const one = (error: unknown) => answersFromBatchHttp({ status: 200, headers: new Headers(), text: JSON.stringify({ data: { results: [{ index: 0, ok: false, error }] } }) }, 1)[0];
    expect(one({ code: "rate_limited", message: "m" })).toEqual({ kind: "response", status: 429, code: "rate_limited" });
    expect(one({ code: "rate_limited", message: "m", details: { retryAfterSeconds: "soon" } })).toEqual({ kind: "response", status: 429, code: "rate_limited" });
    expect(one({ code: "rate_limited", message: "m", details: { retryAfterSeconds: 0 } })).toEqual({ kind: "response", status: 429, code: "rate_limited" });
    expect(one({ code: "rate_limited", message: "m", details: { retryAfterSeconds: 90 } })).toEqual({ kind: "response", status: 429, code: "rate_limited", retryAfterSeconds: 90 });
    expect(one({ code: "unknown_id", message: "m" })).toEqual({ kind: "response", status: 422, code: "unknown_id" });
  });

  it("a whole-request failure is every item's answer; a 200 that is not the contract's is a retry for every item", () => {
    expect(answersFromBatchHttp(raw("batch_400_too_many"), 2)).toEqual([
      { kind: "response", status: 400, code: "bad_request" },
      { kind: "response", status: 400, code: "bad_request" },
    ]);
    expect(answersFromBatchHttp({ status: 200, headers: new Headers(), text: "<html>" }, 2).map((x) => x.kind)).toEqual(["network_error", "network_error"]);
    expect(answersFromBatchHttp({ status: 200, headers: new Headers(), text: JSON.stringify({ data: { results: [{ index: 0, ok: true, result: { status: "accepted" } }, { index: 0, ok: false, error: { code: "x" } }, { index: 9, ok: true, result: { status: "accepted" } }] } }) }, 2)).toEqual([
      { kind: "response", status: 200, code: "accepted" }, // the first mention wins; a duplicate index and an out-of-range index are ignored
      { kind: "network_error", message: "evidence-batch: no result for this item" },
    ]);
  });

  it("queued_catalog inside a batch is the 202 pair; an unknown error code is a dead letter (422), never a retry", () => {
    const one = (item: unknown) => answersFromBatchHttp({ status: 200, headers: new Headers(), text: JSON.stringify({ data: { results: [item] } }) }, 1)[0];
    expect(one({ index: 0, ok: true, result: { status: "queued_catalog" } })).toEqual({ kind: "response", status: 202, code: "queued_catalog" });
    expect(one({ index: 0, ok: false, error: { code: "something_new" } })).toEqual({ kind: "response", status: 422, code: "something_new" });
    expect(one({ index: 0, ok: false, error: { code: "catalog_stale" } })).toMatchObject({ status: 422 });
  });

  it("the code->status table is pinned to the server's Errors.* statuses", () => {
    expect(BATCH_CODE_STATUS).toMatchObject({ bad_request: 400, evidence_conflict: 409, catalog_stale: 422, rate_limited: 429, internal_error: 500, service_unavailable: 503 });
  });

  it("answerFromHttp unit: success body without a status string gives no code", () => {
    expect(answerFromHttp({ status: 200, headers: new Headers(), text: "{}" })).toEqual({ kind: "response", status: 200, code: undefined });
    expect(Object.keys(RECORDED).filter((k) => k.startsWith("batch_"))).toHaveLength(4);
  });
});

describe("check-in token redemption answers (recorded from the real checkin-token handler)", () => {
  const redeemWith = async (name: string) => {
    const { api } = client([{ respond: name }]);
    return api.redeemCheckinChallenge({ challengeId: "00000000-0000-4000-8000-000000000001", nonce: "AAAA", hardwareSupportsAttestation: false }, CREDS);
  };

  it("an idempotent replay (the first response was lost) has exactly the shape of a first redemption and carries the SAME token", async () => {
    const first = await redeemWith("token_201_unattestable");
    const replay = await redeemWith("token_201_idempotent_replay");
    expect(replay).toEqual(first);
    expect(recorded("token_201_idempotent_replay").status).toBe(201);
    expect(JSON.parse(recorded("token_201_idempotent_replay").body)).toEqual(JSON.parse(recorded("token_201_unattestable").body));
    // the same request was recorded for both: this is the replay of that very redemption
    expect((recorded("token_201_idempotent_replay").request as { nonce: string; challengeId: string })).toEqual(recorded("token_201_unattestable").request);
  });

  it("a REAL challenge_used (the nonce is not the one presented the first time) is a refusal the client drops: ApiError rejected 422 challenge_used", async () => {
    expect(JSON.parse(recorded("token_422_challenge_used").body).error.code).toBe("challenge_used"); // the scenario still records what its name says
    await expect(redeemWith("token_422_challenge_used")).rejects.toMatchObject({ kind: "rejected", status: 422, code: "challenge_used" });
  });

  it("the recorded token requests are the strict shape the server accepts: UUID challenge id, no unknown key; the two 400s are what the server says about a violation", () => {
    for (const name of ["token_201_unattestable", "token_201_idempotent_replay", "token_201_failed_grade", "token_422_challenge_used"]) {
      const req = recorded(name).request as Record<string, unknown>;
      expect(Object.keys(req).sort(), name).toEqual(["challengeId", "hardwareSupportsAttestation", "nonce"]);
      expect(req["challengeId"], name).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    }
    expect(JSON.parse(recorded("token_400_unknown_key").body).error.details).toEqual([{ path: "deviceId", message: "unrecognised field" }]);
    expect(JSON.parse(recorded("token_400_not_a_uuid").body).error.details).toEqual([{ path: "challengeId", message: "must be a UUID" }]);
  });
});
