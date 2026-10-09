/**
 * The pre-session routes of the API client (docs/security/partner-auth-design.md 6.1, S1.5): `accept/start`, `accept/verify` and the first `POST credentials`.
 * They carry no bearer (there is no session yet); the last one OPENS the first session, whose token is then held exactly as a sign-in's is.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi, INVITES_FUNCTION, PARTNER_FUNCTIONS, type PartnerApi } from "../src/api/client";
import { isPartnerApiError } from "../src/api/errors";
import type { EnrolmentChallenge, RegistrationJson } from "../src/api/types";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { jsonResponse, stubFetch, VALID_TOKEN, type Recorded } from "./support/stub-fetch";

const BASE = "https://api.example.test/functions/v1";
const INVITE = `gr_inv_${"A".repeat(43)}`;
const ENROLMENT = `gr_enr_${"B".repeat(43)}`;
const CHALLENGE = "A".repeat(43) + ".1893456000." + "B".repeat(43);
const REF = "00000000-0000-4000-8000-0000000000b1";
const USER = "00000000-0000-4000-8000-0000000000a1";
const CREDENTIAL: RegistrationJson = { id: "Y3JlZA", rawId: "Y3JlZA", type: "public-key", response: { clientDataJSON: "e30", attestationObject: "e30" } };
const verifyBody = (kind: "invite" | "enrolment") => ({ options: { challenge: "x" }, challengeToken: CHALLENGE, expiresAt: "2030-01-01T00:05:00Z", userId: USER, refKind: kind, refId: REF, orgId: "o", role: "staff" });
const CHALLENGE_OBJ: EnrolmentChallenge = { options: {}, challengeToken: CHALLENGE, expiresAt: "2030-01-01T00:05:00Z", userId: USER, refKind: "invite", refId: REF };

function happy(call: Recorded): Response {
  const route = call.url.slice(`${BASE}/`.length);
  switch (route) {
    case "partner-invites/invites/accept/start":
    case "partner-invites/enrolments/accept/start":
      return jsonResponse(200, { data: { requested: true } });
    case "partner-invites/invites/accept/verify":
      return jsonResponse(200, { data: verifyBody("invite") });
    case "partner-invites/enrolments/accept/verify":
      return jsonResponse(200, { data: verifyBody("enrolment") });
    case "partner-invites/credentials":
      return jsonResponse(201, { data: { token: VALID_TOKEN, expiresAt: "2030-01-01T08:00:00Z", aal: 1, enrolmentUntil: "2030-01-01T00:15:00Z" } });
    case "partner-session/sign-out":
      return jsonResponse(200, { data: { signedOut: true } });
    default:
      return jsonResponse(404, { error: { code: "not_found", message: "not found" } });
  }
}

function make(responder: (c: Recorded) => Response | Promise<Response> = happy) {
  const s = stubFetch(responder);
  const api = createPartnerApi({ baseUrl: BASE, fetch: s.fetch });
  return { api, calls: s.calls };
}
const err = async (p: Promise<unknown>) => {
  const e = await p.catch((x: unknown) => x);
  if (!isPartnerApiError(e)) throw new Error(`expected a PartnerApiError, got ${String(e)}`);
  return e;
};

let spies: StorageSpies;
beforeEach(() => {
  spies = installStorageSpies();
});
afterEach(() => spies.restore());

describe("the partner function list (the CSP's connect-src and the bearer allow-list are one list)", () => {
  it("names the three partner functions, so partner-invites and partner-members are path-scoped in connect-src", () => {
    expect([...PARTNER_FUNCTIONS]).toEqual(["partner-session", "partner-invites", "partner-members"]);
    expect(INVITES_FUNCTION).toBe("partner-invites");
  });
});

describe("accept/start and accept/verify (no session, no bearer)", () => {
  it.each([
    ["invite", INVITE, "invites"],
    ["enrolment", ENROLMENT, "enrolments"],
  ] as const)("%s: POSTs { token } to partner-invites/%s/accept/start with exactly Content-Type, and no bearer", async (kind, token, base) => {
    const { api, calls } = make();
    await api.acceptStart(kind, token);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${BASE}/partner-invites/${base}/accept/start`);
    expect(calls[0]!.init.method).toBe("POST");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ token });
    expect(calls[0]!.headerKeys).toEqual(["Content-Type"]);
    expect(calls[0]!.init).toMatchObject({ credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
    expect(api.hasSession()).toBe(false);
  });

  it("verify returns the ceremony's options and the binding, and checks the kind it got is the kind it asked for", async () => {
    const { api, calls } = make();
    const c = await api.acceptVerify("invite", { token: INVITE, code: "123456" });
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ token: INVITE, code: "123456" });
    expect(c).toEqual({ options: { challenge: "x" }, challengeToken: CHALLENGE, expiresAt: "2030-01-01T00:05:00Z", userId: USER, refKind: "invite", refId: REF });
    expect(Object.keys(c)).not.toContain("role"); // only the binding: the page needs no more
    const e = await err(make((call) => (call.url.endsWith("/invites/accept/verify") ? jsonResponse(200, { data: verifyBody("enrolment") }) : happy(call))).api.acceptVerify("invite", { token: INVITE, code: "123456" }));
    expect(e.kind).toBe("malformed_response");
  });

  it("a start answer that is not the constant { requested: true } is malformed", async () => {
    expect((await err(make(() => jsonResponse(200, { data: {} })).api.acceptStart("invite", INVITE))).kind).toBe("malformed_response");
  });

  it.each([
    ["the one 403 (a wrong code, a dead token ...)", 403, "accept_refused", "forbidden"],
    ["existing_member_sign_in", 409, "existing_member_sign_in", "conflict"],
    ["recover_required", 409, "recover_required", "conflict"],
    ["an expired enrolment", 410, "expired", "gone"],
    ["a refused argument", 422, "invalid_argument", "unprocessable"],
    ["a malformed body", 400, "bad_request", "bad_request"],
    ["a rate limit", 429, "rate_limited", "rate_limited"],
  ] as const)("%s maps to kind %s with the server's closed code", async (_name, status, code, kind) => {
    const { api } = make(() => jsonResponse(status, { error: { code, message: "m" } }));
    const e = await err(api.acceptVerify("invite", { token: INVITE, code: "123456" }));
    expect([e.kind, e.status, e.code]).toEqual([kind, status, code]);
  });

  it("never touches a storage API or the console", async () => {
    const { api } = make();
    await api.acceptStart("invite", INVITE);
    await api.acceptVerify("invite", { token: INVITE, code: "123456" });
    expect(spies.calls).toEqual([]);
  });
});

describe("registerFirst: the first credential opens the first session", () => {
  it("POSTs { userId, refKind, refId, challengeToken, credential } to partner-invites/credentials with no bearer, keeps the token inside the client and does not return it", async () => {
    const { api, calls } = make();
    const r = await api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL });
    expect(r).toEqual({ expiresAt: "2030-01-01T08:00:00Z", aal: 1, enrolmentUntil: "2030-01-01T00:15:00Z" });
    expect(JSON.stringify(r)).not.toContain("gr_ps_");
    expect(calls[0]!.url).toBe(`${BASE}/partner-invites/credentials`);
    expect(calls[0]!.headerKeys).toEqual(["Content-Type"]);
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ userId: USER, refKind: "invite", refId: REF, challengeToken: CHALLENGE, credential: CREDENTIAL });
    expect(api.hasSession()).toBe(true);
    expect(spies.calls).toEqual([]);
  });

  it("the held token is then the bearer of session calls, exactly as after a sign-in", async () => {
    const { api, calls } = make((c) => (c.url.endsWith("/partner-session/sign-out") ? jsonResponse(200, { data: { signedOut: true } }) : happy(c)));
    await api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL });
    await api.signOut();
    expect(calls.at(-1)!.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
    expect(api.hasSession()).toBe(false);
  });

  it("a session already held refuses a second registration before any request", async () => {
    const { api, calls } = make();
    await api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL });
    const before = calls.length;
    expect((await err(api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL }))).code).toBe("session_exists");
    expect(calls).toHaveLength(before);
  });

  it.each([
    ["no token", { expiresAt: "x", aal: 1, enrolmentUntil: "y" }],
    ["a token of the wrong shape", { token: "gr_ps_short", expiresAt: "x", aal: 1, enrolmentUntil: "y" }],
    ["no enrolment window", { token: VALID_TOKEN, expiresAt: "x", aal: 1 }],
    ["no aal", { token: VALID_TOKEN, expiresAt: "x", enrolmentUntil: "y" }],
  ])("a 201 with %s is malformed and no session is held", async (_name, data) => {
    const { api } = make((c) => (c.url.endsWith("/credentials") ? jsonResponse(201, { data }) : happy(c)));
    expect((await err(api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL }))).kind).toBe("malformed_response");
    expect(api.hasSession()).toBe(false);
  });

  it("a cancel while the request is on the wire revokes the session it opened instead of holding it", async () => {
    const ctl = new AbortController();
    const { api, calls } = make((c) => {
      if (c.url.endsWith("/credentials")) ctl.abort();
      return happy(c);
    });
    expect((await err(api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL }, { signal: ctl.signal }))).kind).toBe("aborted");
    expect(api.hasSession()).toBe(false);
    const revoke = calls.at(-1)!;
    expect(revoke.url).toBe(`${BASE}/partner-session/sign-out`);
    expect(revoke.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
  });

  it.each([
    [403, "registration_refused", "forbidden"],
    [409, "credential_exists", "conflict"],
    [410, "expired", "gone"],
  ] as const)("a refused registration (%i %s) is kind %s and holds no session", async (status, code, kind) => {
    const { api } = make((c) => (c.url.endsWith("/credentials") ? jsonResponse(status, { error: { code, message: "m" } }) : happy(c)));
    const e = await err(api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL }));
    expect([e.kind, e.code]).toEqual([kind, code]);
    expect(api.hasSession()).toBe(false);
  });
});

describe("the bearer never goes to a pre-session route, and call() still guards the allow-list", () => {
  it("no pre-session request carries Authorization even when a session is held", async () => {
    const { api, calls } = make();
    await api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL });
    calls.length = 0;
    await api.acceptStart("invite", INVITE);
    expect(calls[0]!.headers["authorization"]).toBeUndefined();
  });

  it("partner-invites is a function a session call may reach (invite list / create later), partner-attest is not", async () => {
    const { api } = make((c) => (c.url.endsWith("/partner-invites/invites") ? jsonResponse(200, { data: { invites: [] } }) : happy(c)));
    await api.registerFirst({ challenge: CHALLENGE_OBJ, credential: CREDENTIAL });
    await expect(api.call("GET", "partner-invites", "invites")).resolves.toEqual({ invites: [] });
    expect((await err((api as PartnerApi).call("GET", "partner-attest", "x"))).kind).toBe("bad_request");
  });
});
