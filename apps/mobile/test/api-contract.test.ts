/**
 * The real `ApiClient` against the RECORDED shapes of the server handlers (`fixtures/edge-contract.json`; see its `_provenance`): every
 * success shape, every error status, zod rejecting unexpected shapes, the request each method makes, and the retry/timeout policy.
 */
import { describe, expect, it } from "vitest";
import { ApiError, HTTP_POLICY, backoffMs, createHttpApiClient, createUnconfiguredApi, retryAfterSecondsFrom, type ApiClient, type HttpApiOptions } from "../src/api";
import { RECORDED, recorded, scriptedFetch, type Step } from "./support/edge-fixtures";

const BASE = "https://proj.supabase.co/functions/v1";

function client(steps: Step[], over: Partial<HttpApiOptions> = {}) {
  const { fetch, seen } = scriptedFetch(...steps);
  const sleeps: number[] = [];
  const tokens: (string | null)[] = [];
  const api = createHttpApiClient({
    baseUrl: BASE,
    fetch,
    getAccessToken: (o) => {
      const t = o?.forceRefresh ? "token-refreshed" : "token-1";
      tokens.push(t);
      return Promise.resolve(t);
    },
    rng: () => 0.5,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    ...over,
  });
  return { api, seen, sleeps, tokens };
}

async function failure(p: Promise<unknown>): Promise<ApiError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof ApiError) return e;
    throw e;
  }
  throw new Error("expected an ApiError, got success");
}

describe("success shapes (recorded from the server handlers)", () => {
  it("GET me-signin-methods", async () => {
    const { api, seen } = client([{ respond: "list_multi" }]);
    const methods = await api.listSignInMethods();
    expect(methods.map((m) => [m.provider, m.canUnlink, m.isPrivateRelay])).toEqual([
      ["email", true, false],
      ["google", true, false],
    ]);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ url: `${BASE}/me-signin-methods`, method: "GET", redirect: "error", credentials: "omit" });
    expect(seen[0]!.headers["Authorization"]).toBe("Bearer token-1");
    expect(seen[0]!.body).toBeUndefined();
  });

  it("POST link: created / idempotent / relay / proven_account (methods null)", async () => {
    const req = { provider: "apple" as const, identityToken: "a.b.c", authorizationCode: "code", nonce: "n".repeat(43) };
    expect(await client([{ respond: "link_self_created" }]).api.linkSignInMethod(req)).toMatchObject({ linked: { created: true, isPrivateRelay: false }, linkedTo: "self" });
    expect(await client([{ respond: "link_self_idempotent" }]).api.linkSignInMethod(req)).toMatchObject({ linked: { created: false } });
    expect(await client([{ respond: "link_self_relay" }]).api.linkSignInMethod(req)).toMatchObject({ linked: { isPrivateRelay: true } });
    expect(await client([{ respond: "link_proven_account" }]).api.linkSignInMethod({ ...req, emailProof: { code: "123456" } })).toEqual({
      linked: { provider: "apple", created: true, isPrivateRelay: false },
      linkedTo: "proven_account",
      methods: null,
    });
  });

  it("POST unlink", async () => {
    const r = await client([{ respond: "unlink_ok" }]).api.unlinkSignInMethod("apple");
    expect(r.methods).toHaveLength(1);
    expect(r.revocation[0]).toMatchObject({ provider: "apple", status: "revoked" });
  });

  it("DELETE me-delete", async () => {
    const { api, seen } = client([{ respond: "delete_ok" }]);
    const r = await api.deleteAccount();
    expect(r).toMatchObject({ authUserDeleted: true, authUserAlreadyGone: false });
    expect(r.signinProvidersRevoked.map((x) => x.status)).toEqual(["revoked", "queued_for_retry"]);
    expect(seen[0]).toMatchObject({ url: `${BASE}/me-delete`, method: "DELETE" });
  });

  it("GET me-export", async () => {
    const { api, seen } = client([{ respond: "export_ok" }]);
    const r = await api.exportData();
    expect(r.userId).toBe("aaaaaaaa-0000-4000-8000-000000000001");
    expect(Object.keys(r.data)).toContain("device");
    expect(seen[0]).toMatchObject({ url: `${BASE}/me-export`, method: "GET" });
  });

  it("POST me-push-token", async () => {
    const { api, seen } = client([{ respond: "push_ok" }]);
    const r = await api.registerPushToken({ deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "ExponentPushToken[b]", platform: "android" });
    expect(r.deviceId).toBe("22222222-2222-4222-8222-222222222222");
    expect(seen[0]).toMatchObject({
      url: `${BASE}/me-push-token`,
      method: "POST",
      body: { deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "ExponentPushToken[b]", platform: "android" },
    });
    expect(seen[0]!.headers["Content-Type"]).toBe("application/json");
  });
});

describe("the request bodies are exactly the server's wire shapes (request-shape.ts)", () => {
  it("link: action/provider/identityToken/authorizationCode/nonce, and emailProof ONLY when given", async () => {
    const a = client([{ respond: "link_self_created" }]);
    await a.api.linkSignInMethod({ provider: "apple", identityToken: "a.b.c", authorizationCode: "code", nonce: "n".repeat(43) });
    expect(a.seen[0]!.body).toEqual({ action: "link", provider: "apple", identityToken: "a.b.c", authorizationCode: "code", nonce: "n".repeat(43) });
    const b = client([{ respond: "link_proven_account" }]);
    await b.api.linkSignInMethod({ provider: "apple", identityToken: "a.b.c", authorizationCode: "code", nonce: "n".repeat(43), emailProof: { code: "123456" } });
    expect(b.seen[0]!.body).toEqual({ action: "link", provider: "apple", identityToken: "a.b.c", authorizationCode: "code", nonce: "n".repeat(43), emailProof: { code: "123456" } });
  });

  it("unlink: { action, provider } and nothing else (the server rejects unknown keys)", async () => {
    const a = client([{ respond: "unlink_ok" }]);
    await a.api.unlinkSignInMethod("apple");
    expect(a.seen[0]!.body).toEqual({ action: "unlink", provider: "apple" });
  });

  it("push token: platform omitted when unknown", async () => {
    const a = client([{ respond: "push_ok" }]);
    await a.api.registerPushToken({ deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "ExponentPushToken[b]" });
    expect(a.seen[0]!.body).toEqual({ deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "ExponentPushToken[b]" });
  });
});

describe("every error status maps to an ApiError (recorded bodies)", () => {
  const table: [string, string, number, string | null][] = [
    ["err_400_bad_request", "rejected", 400, "bad_request"],
    ["err_401_unauthorized", "unauthenticated", 401, "unauthorized"],
    ["err_403_forbidden", "forbidden", 403, "forbidden"],
    ["err_404_not_found", "not_found", 404, "not_found"],
    ["err_405_method_not_allowed", "rejected", 405, "method_not_allowed"],
    ["err_413_payload_too_large", "rejected", 413, "payload_too_large"],
    ["err_415_unsupported_media_type", "rejected", 415, "unsupported_media_type"],
    ["err_429_rate_limited", "rate_limited", 429, "rate_limited"],
    ["err_500_internal", "server", 500, "internal_error"],
    ["err_503_service_unavailable", "unavailable", 503, "service_unavailable"],
    ["link_409_email_proof_required", "conflict", 409, "email_proof_required"],
    ["link_409_provider_already_linked", "conflict", 409, "provider_already_linked"],
    ["link_409_email_proof_mismatch", "conflict", 409, "email_proof_mismatch"],
    ["link_409_email_belongs_to_another_account", "conflict", 409, "email_belongs_to_another_account"],
    ["link_422_email_proof_invalid", "rejected", 422, "email_proof_invalid"],
    ["link_422_invalid_identity_token", "rejected", 422, "invalid_identity_token"],
    ["link_422_authorization_code_rejected", "rejected", 422, "authorization_code_rejected"],
    ["link_422_authorization_code_mismatch", "rejected", 422, "authorization_code_mismatch"],
    ["link_429_proof_rate_limited", "rate_limited", 429, "rate_limited"],
    ["link_501_google", "not_supported", 501, "provider_not_supported"],
    ["link_502_upstream_unavailable", "unavailable", 502, "upstream_unavailable"],
    ["link_503_provider_not_configured", "unavailable", 503, "provider_not_configured"],
    ["unlink_422_last_sign_in_method", "rejected", 422, "last_sign_in_method"],
    ["unlink_404_not_linked", "not_found", 404, "not_found"],
    ["push_422_device_limit_exceeded", "rejected", 422, "device_limit_exceeded"],
    ["push_400_bad_token", "rejected", 400, "bad_request"],
  ];
  it.each(table)("%s => %s (%i, %s)", async (name, kind, status, code) => {
    expect(recorded(name).status).toBe(status);
    // a non-idempotent call, so no retry noise; the mapping does not depend on the endpoint
    const { api } = client([{ respond: name }]);
    const e = await failure(api.unlinkSignInMethod("apple"));
    expect([e.kind, e.status, e.code]).toEqual([kind, status, code]);
  });

  it("the table covers every recorded error fixture", () => {
    // The evidence lane's fixtures (challenge_ / token_ / evidence_ / batch_) are covered by `evidence-wire.test.ts`, the key-registration ones (attestkey_) by `attest-send.test.ts`, the offline-seed ones (offlineseed_) by `offline-code-manager.test.ts` the reward-activation ones (activate_) by `rewards-activation.test.ts` and the check-in screen's (checkin_) by `checkin-wire.test.ts`, the marker scan's (markerscan_, P5.1a S2a) by `marker-scan-wire.test.ts`, and receipts multipart (receipts_, P5 §56) by `receipts-wire.test.ts`.
    const errorFixtures = Object.entries(RECORDED).filter(([k, r]) => r.status >= 400 && !/^(challenge|token|evidence|batch|attestkey|offlineseed|activate|checkin|markerscan|receipts)_/.test(k)).map(([k]) => k);
    expect(table.map((t) => t[0]).sort()).toEqual(errorFixtures.sort());
  });

  it("details survive: attemptsRemaining and retryAfterSeconds", async () => {
    const a = await failure(client([{ respond: "link_422_email_proof_invalid" }]).api.linkSignInMethod({ provider: "apple", identityToken: "a.b.c", authorizationCode: "c", nonce: "n".repeat(43) }));
    expect(a.details).toEqual({ attemptsRemaining: 4 });
    const b = await failure(client([{ respond: "link_429_proof_rate_limited" }]).api.unlinkSignInMethod("apple"));
    expect(b.retryAfterSeconds).toBe(3600);
  });

  it("a non-JSON failure body (a gateway page) is mapped by status alone", async () => {
    const e = await failure(client([{ status: 502, body: "<html>Bad gateway</html>" }, { status: 502, body: "<html>Bad gateway</html>" }, { status: 502, body: "<html>" }]).api.deleteAccount());
    expect([e.kind, e.status, e.code]).toEqual(["unavailable", 502, null]);
  });

  it("a Retry-After header is honoured as well as the body's retryAfterSeconds", () => {
    expect(retryAfterSecondsFrom(new Response("", { headers: { "retry-after": "30" } }), undefined)).toBe(30);
    expect(retryAfterSecondsFrom(new Response(""), { retryAfterSeconds: 7 })).toBe(7);
    expect(retryAfterSecondsFrom(new Response("", { headers: { "retry-after": "Wed, 21 Oct 2026 07:28:00 GMT" } }), undefined)).toBeNull();
    expect(retryAfterSecondsFrom(new Response(""), { retryAfterSeconds: -1 })).toBeNull();
  });
});

describe("zod rejects unexpected shapes (bad_response, never a partial success)", () => {
  const bad = (body: unknown, status = 200): Step => ({ status, body: typeof body === "string" ? body : JSON.stringify(body) });
  const cases: [string, Step, (a: ApiClient) => Promise<unknown>][] = [
    ["methods missing", bad({ data: {} }), (a) => a.listSignInMethods()],
    ["methods wrong type", bad({ data: { methods: "email" } }), (a) => a.listSignInMethods()],
    ["canUnlink not a boolean", bad({ data: { methods: [{ provider: "email", linkedAt: "x", isPrivateRelay: false, canUnlink: "yes" }] } }), (a) => a.listSignInMethods()],
    ["no data envelope", bad({ methods: [] }), (a) => a.listSignInMethods()],
    ["data null", bad({ data: null }), (a) => a.listSignInMethods()],
    ["not JSON", bad("<html>ok</html>"), (a) => a.listSignInMethods()],
    ["empty body", bad(""), (a) => a.exportData()],
    ["linkedTo outside the enum", bad({ data: { linked: { provider: "apple", created: true, isPrivateRelay: false }, linkedTo: "elsewhere", methods: null } }), (a) => a.linkSignInMethod({ provider: "apple", identityToken: "a.b.c", authorizationCode: "c", nonce: "n".repeat(43) })],
    ["link of another provider", bad({ data: { linked: { provider: "google", created: true, isPrivateRelay: false }, linkedTo: "self", methods: [] } }), (a) => a.linkSignInMethod({ provider: "apple", identityToken: "a.b.c", authorizationCode: "c", nonce: "n".repeat(43) })],
    ["delete without a userId", bad({ data: { deletedAt: "x", authUserDeleted: true, authUserAlreadyGone: false, signinProvidersRevoked: [], connectorsRevoked: [] } }), (a) => a.deleteAccount()],
    ["revocation status outside the enum", bad({ data: { methods: [], revocation: [{ queueId: "q", provider: "apple", status: "maybe" }] } }), (a) => a.unlinkSignInMethod("apple")],
    ["export data is not an object", bad({ data: { generatedAt: "x", userId: "u", data: [] } }), (a) => a.exportData()],
    ["push result without updatedAt", bad({ data: { deviceId: "d" } }), (a) => a.registerPushToken({ deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "t" })],
    ["201 is not the contract's 200", bad({ data: { methods: [] } }, 201), (a) => a.listSignInMethods()],
    ["204", bad("", 204), (a) => a.listSignInMethods()],
  ];
  it.each(cases)("%s", async (_name, step, call) => {
    // `steps` repeat their last entry, so a retry of an idempotent call sees the same body
    const { api } = client([step]);
    const e = await failure(call(api));
    expect(e.kind).toBe("bad_response");
  });

  it("unknown EXTRA fields are ignored (the server may add fields without breaking an installed app)", async () => {
    const body = JSON.parse(recorded("list_single").body) as { data: { methods: Record<string, unknown>[] } };
    body.data.methods[0]!["futureField"] = 1;
    const methods = await client([{ status: 200, body: JSON.stringify(body) }]).api.listSignInMethods();
    expect(methods).toHaveLength(1);
    expect("futureField" in methods[0]!).toBe(false);
  });
});

describe("auth: bearer token, one forced refresh on 401", () => {
  it("no token => unauthenticated, and NO request is made", async () => {
    const { fetch, seen } = scriptedFetch({ respond: "list_single" });
    const api = createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: () => Promise.resolve(null) });
    const e = await failure(api.listSignInMethods());
    expect(e.kind).toBe("unauthenticated");
    expect(seen).toEqual([]);
  });

  it("a 401 forces ONE refresh and repeats the request with the new token", async () => {
    const { api, seen, tokens } = client([{ respond: "err_401_unauthorized" }, { respond: "list_single" }]);
    expect(await api.listSignInMethods()).toHaveLength(1);
    expect(seen.map((s) => s.headers["Authorization"])).toEqual(["Bearer token-1", "Bearer token-refreshed"]);
    expect(tokens).toEqual(["token-1", "token-refreshed"]);
  });

  it("a second 401 is unauthenticated (no refresh loop), for a non-idempotent call too", async () => {
    const { api, seen } = client([{ respond: "err_401_unauthorized" }]);
    const e = await failure(api.unlinkSignInMethod("apple"));
    expect(e.kind).toBe("unauthenticated");
    expect(seen).toHaveLength(2); // original + one refreshed repeat
  });

  it("a refresh that yields no token (signed out meanwhile) is unauthenticated", async () => {
    const { fetch } = scriptedFetch({ respond: "err_401_unauthorized" });
    const api = createHttpApiClient({ baseUrl: BASE, fetch, getAccessToken: (o) => Promise.resolve(o?.forceRefresh ? null : "t") });
    expect((await failure(api.exportData())).kind).toBe("unauthenticated");
  });

  it("a token provider that throws (offline refresh) is a network failure, not 'signed out'", async () => {
    const { fetch } = scriptedFetch({ respond: "list_single" });
    const api = createHttpApiClient({
      baseUrl: BASE,
      fetch,
      getAccessToken: () => Promise.reject(new Error("refresh failed: offline")),
    });
    expect((await failure(api.listSignInMethods())).kind).toBe("network");
  });
});

describe("retry policy (consistent with the outbox: 429 / 5xx / network are the retryable class), idempotent calls only", () => {
  it("GET: a network failure then success => 2 attempts with a backoff in between", async () => {
    const { api, seen, sleeps } = client([{ network: "offline" }, { respond: "list_single" }]);
    expect(await api.listSignInMethods()).toHaveLength(1);
    expect(seen).toHaveLength(2);
    expect(sleeps).toHaveLength(1);
    expect(sleeps[0]).toBeGreaterThanOrEqual(HTTP_POLICY.backoffBaseMs / 2);
  });

  it("GET: 503 three times => the 503 is surfaced after maxAttempts", async () => {
    const { api, seen } = client([{ respond: "err_503_service_unavailable" }]);
    const e = await failure(api.exportData());
    expect([e.kind, seen.length]).toEqual(["unavailable", HTTP_POLICY.maxAttempts]);
  });

  it("500 is retried too (an outbox-style 5xx)", async () => {
    const { api, seen } = client([{ respond: "err_500_internal" }, { respond: "export_ok" }]);
    await api.exportData();
    expect(seen).toHaveLength(2);
  });

  it("DELETE me and the push-token upsert are idempotent server-side, so they are retried", async () => {
    const d = client([{ network: "offline" }, { respond: "delete_ok" }]);
    await d.api.deleteAccount();
    expect(d.seen).toHaveLength(2);
    const p = client([{ respond: "err_503_service_unavailable" }, { respond: "push_ok" }]);
    await p.api.registerPushToken({ deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "t" });
    expect(p.seen).toHaveLength(2);
  });

  it("link and unlink are NEVER retried (a single-use authorization code, counted OTP attempts, a second unlink is a 404)", async () => {
    for (const step of [{ network: "offline" }, { respond: "err_503_service_unavailable" }, { respond: "err_500_internal" }, { respond: "link_502_upstream_unavailable" }] as Step[]) {
      const a = client([step, { respond: "list_single" }]);
      await failure(a.api.linkSignInMethod({ provider: "apple", identityToken: "a.b.c", authorizationCode: "c", nonce: "n".repeat(43) }));
      expect(a.seen).toHaveLength(1);
      const b = client([step, { respond: "list_single" }]);
      await failure(b.api.unlinkSignInMethod("apple"));
      expect(b.seen).toHaveLength(1);
    }
  });

  it("4xx other than 429 are never retried", async () => {
    for (const name of ["err_403_forbidden", "err_404_not_found", "err_413_payload_too_large", "link_409_email_proof_required", "unlink_422_last_sign_in_method"]) {
      const { api, seen } = client([{ respond: name }, { respond: "list_single" }]);
      await failure(api.listSignInMethods());
      expect(seen, name).toHaveLength(1);
    }
  });

  it("429 with a short Retry-After is retried after at least that long; a long one (the daily export cap) is surfaced, not slept through", async () => {
    const short = client([{ status: 429, body: JSON.stringify({ error: { code: "rate_limited", message: "x", details: { retryAfterSeconds: 3 } } }) }, { respond: "export_ok" }]);
    await short.api.exportData();
    expect(short.seen).toHaveLength(2);
    expect(short.sleeps[0]).toBeGreaterThanOrEqual(3000);

    const long = client([{ respond: "err_429_rate_limited" }]); // retryAfterSeconds 7200
    const e = await failure(long.api.exportData());
    expect([e.kind, e.retryAfterSeconds, long.seen.length, long.sleeps.length]).toEqual(["rate_limited", 7200, 1, 0]);
  });

  it("backoffMs: jittered exponential, capped, Retry-After is a floor", () => {
    const p = HTTP_POLICY;
    expect(backoffMs(1, () => 0, p, null)).toBe(p.backoffBaseMs / 2);
    expect(backoffMs(1, () => 1, p, null)).toBe(p.backoffBaseMs);
    expect(backoffMs(2, () => 1, p, null)).toBe(p.backoffBaseMs * 2);
    expect(backoffMs(20, () => 1, p, null)).toBe(p.backoffCapMs);
    expect(backoffMs(1, () => 0, p, 3)).toBe(3000);
  });

  it("a request that never answers is aborted at the timeout and reported as a network failure (idempotent calls retry it)", async () => {
    const { api, seen } = client([{ hang: true }, { respond: "list_single" }], { policy: { timeoutMs: 15 } });
    expect(await api.listSignInMethods()).toHaveLength(1);
    expect(seen).toHaveLength(2);
    const stuck = client([{ hang: true }], { policy: { timeoutMs: 10, maxAttempts: 1 } });
    const e = await failure(stuck.api.listSignInMethods());
    expect(e.kind).toBe("network");
    expect(e.message).toMatch(/timed out/);
  });
});

describe("the rest of the interface", () => {
  it("no server endpoint exists yet for policy / plays / achievements / programmes: the client answers the compiled default and 'nothing', with no request", async () => {
    const { api, seen } = client([{ respond: "list_single" }]);
    expect(await api.getPolicy()).toEqual({ minAge: 16 });
    expect(await api.listPlays()).toEqual([]);
    expect(await api.listAchievements()).toEqual([]);
    expect(await api.listTrailProgrammes()).toEqual({});
    expect(seen).toEqual([]);
  });

  it("the unconfigured API (a release build with no server config) refuses every network call with not_configured and invents nothing", async () => {
    const api = createUnconfiguredApi();
    for (const call of [
      () => api.listSignInMethods(),
      () => api.linkSignInMethod({ provider: "apple", identityToken: "a.b.c", authorizationCode: "c", nonce: "n".repeat(43) }),
      () => api.unlinkSignInMethod("apple"),
      () => api.deleteAccount(),
      () => api.exportData(),
      () => api.registerPushToken({ deviceId: "d", expoToken: "t" }),
    ]) {
      expect((await failure(call())).kind).toBe("not_configured");
    }
    expect(await api.listPlays()).toEqual([]);
    expect((await api.submitEvidence({} as never, {} as never)).kind).toBe("network_error");
  });
});
