// supabase/tests/unit/partner-members-handler.test.ts
//
// The `partner-members` handler (docs/security/partner-auth-design.md 4.5, 6.4, 6.5, 8, 22.4; PA-15, PA-16, PA-22, PA-25; slice S1.5), against the in-memory ports of partner-fakes.ts. What is decided HERE: the
// route table with `{id}` segments, the Origin / bearer / media-type / strict-body order, that every route is a session route, the status-to-HTTP maps (42501 is a 403 that rolls back, a returned refusal is a
// status that COMMITS), that a recovery or enrolment token reaches the database only as its hash and the person only once, and the second-credential order (rate limit, relying party, the wrapper with no session
// transaction open, then the A2 definer). The reach rule itself is the database's: supabase/tests/matrix/32_partner_invites_enrolment.sql.

import { describe, expect, it } from "vitest";
import { CREDENTIAL_BUCKET, CREDENTIAL_PER_MEMBER_PER_HOUR, handlePartnerMembersRequest } from "../../functions/_shared/partner/members-handler.ts";
import { uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { authed, bytes, challengeToken, CRED_ROW_ID, fnReq, makeFakes, ORG_ID, ORIGIN, registrationCredentialJson, SESSION_TOKEN, sha256Hex, TARGET_ID, TOKEN_ID, USER_ID } from "./partner-fakes.ts";

const FN = "partner-members";
type F = ReturnType<typeof makeFakes>;
const call = (f: F, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}) =>
  handlePartnerMembersRequest(fnReq(FN, method, path, init), f.membersDeps);
const post = (f: F, path: string, body: unknown = {}) => call(f, "POST", path, { headers: authed(), body });
const text = async (res: Response) => await res.text();
const idx = (f: F, c: string) => f.calls.indexOf(c);
const lastTx = (f: F) => f.tx[f.tx.length - 1];

const ROUTES: Array<[string, string, unknown]> = [
  ["POST", `members/${TARGET_ID}/revoke`, { orgId: ORG_ID }],
  ["POST", `members/${TARGET_ID}/recover`, {}],
  ["POST", `members/${TARGET_ID}/pin-reset`, {}],
  ["POST", `members/${TARGET_ID}/totp-reset`, {}],
  ["POST", `orgs/${ORG_ID}/sessions/revoke-all`, {}],
  ["POST", "admin/enrolments", { userId: TARGET_ID }],
  ["POST", "credentials/options", {}],
  ["POST", "credentials", { challengeToken: challengeToken(), credential: registrationCredentialJson() }],
  ["GET", "credentials", undefined],
  ["DELETE", `credentials/${CRED_ROW_ID}`, undefined],
];

describe("routing, Origin, bearer and body order: every route is a session route", () => {
  it("OPTIONS from the allowed origin is 204 and touches NO port (PA-10)", async () => {
    const f = makeFakes();
    for (const [, path] of ROUTES) {
      const res = await call(f, "OPTIONS", path, { headers: { origin: ORIGIN, "access-control-request-method": "POST" } });
      expect(res.status, path).toBe(204);
    }
    expect(f.calls).toEqual([]);
  });

  it("a foreign Origin is 403 BEFORE routing for every route, with no CORS header and no port touched", async () => {
    const f = makeFakes();
    for (const [method, path, body] of ROUTES) {
      const res = await call(f, method, path, { headers: { origin: "https://evil.example.test", authorization: `Bearer ${SESSION_TOKEN}` }, body });
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
    }
    expect(f.calls).toEqual([]);
  });

  it("no bearer, a Supabase-shaped JWT, another scheme and a malformed token are the ONE 401 for every route, with no port touched", async () => {
    const f = makeFakes();
    const jwtShaped = ["aaa", "bbb", "ccc"].join(".");
    for (const [method, path, body] of ROUTES) {
      for (const authorization of [undefined, `Bearer ${jwtShaped}`, `Basic ${SESSION_TOKEN}`, `Bearer ${SESSION_TOKEN}x`]) {
        const headers: Record<string, string> = { origin: ORIGIN };
        if (authorization !== undefined) headers.authorization = authorization;
        const res = await call(f, method, path, { headers, body });
        expect(res.status, `${method} ${path} ${authorization}`).toBe(401);
      }
    }
    expect(f.calls).toEqual([]);
  });

  it("an unknown route and an id that is not a uuid are 404; a wrong method is 405 with Allow; all before any port", async () => {
    const f = makeFakes();
    for (const path of ["no-such-route", "members/not-a-uuid/revoke", `members/${TARGET_ID}/nope`, "credentials/not-a-uuid", `orgs/${ORG_ID}/sessions`, `members/${TARGET_ID}/revoke/x`]) {
      expect((await post(f, path)).status, path).toBe(404);
    }
    for (const [method, path, allow] of [["GET", `members/${TARGET_ID}/revoke`, "POST"], ["PATCH", "credentials", "GET, POST"], ["POST", `credentials/${CRED_ROW_ID}`, "DELETE"], ["GET", "credentials/options", "POST"]] as const) {
      const res = await call(f, method, path, { headers: authed(), body: method === "POST" ? {} : undefined });
      expect(res.status, `${method} ${path}`).toBe(405);
      expect(res.headers.get("allow")).toBe(allow);
    }
    expect(f.calls).toEqual([]);
  });

  it("the media type must be exactly application/json (415) and a route that takes no field takes exactly {} (400 otherwise)", async () => {
    const f = makeFakes();
    for (const [method, path] of ROUTES.filter(([m]) => m === "POST")) {
      const res = await call(f, method, path, { headers: authed({ "content-type": "text/plain; x=application/json" }), raw: "{}" });
      expect(res.status, path).toBe(415);
    }
    for (const path of [`members/${TARGET_ID}/recover`, `members/${TARGET_ID}/pin-reset`, `members/${TARGET_ID}/totp-reset`, "credentials/options"]) {
      expect((await post(f, path, { extra: 1 })).status, path).toBe(400);
    }
    expect(f.calls).toEqual([]);
  });
});

describe("POST members/{id}/revoke (class A2, one membership)", () => {
  it("ok: 200 and the target and org reach the definer; the transaction commits", async () => {
    const f = makeFakes();
    const res = await post(f, `members/${TARGET_ID.toUpperCase()}/revoke`, { orgId: ORG_ID });
    expect(res.status).toBe(200);
    expect(f.rec.memberRevoke).toEqual([{ target: TARGET_ID, org: ORG_ID }]);
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("not_found is 404 and commits; outside the reach rule (42501) is 403 and rolls back; acting on oneself (22023) is 422", async () => {
    const nf = makeFakes({ memberRevoke: "not_found" });
    expect((await post(nf, `members/${TARGET_ID}/revoke`, { orgId: ORG_ID })).status).toBe(404);
    expect(lastTx(nf)).toEqual({ kind: "session", committed: true });
    const refused = makeFakes({ authorityRefusedIn: "memberRevoke" });
    expect((await post(refused, `members/${TARGET_ID}/revoke`, { orgId: ORG_ID })).status).toBe(403);
    expect(lastTx(refused)).toEqual({ kind: "session", committed: false });
    expect((await post(makeFakes({ invalidArgumentIn: "memberRevoke" }), `members/${TARGET_ID}/revoke`, { orgId: ORG_ID })).status).toBe(422);
  });

  it("the body names one org and nothing else (400)", async () => {
    const f = makeFakes();
    for (const body of [{}, { orgId: "x" }, { orgId: ORG_ID, role: "staff" }, []]) expect((await post(f, `members/${TARGET_ID}/revoke`, body)).status).toBe(400);
    expect(f.calls).toEqual([]);
  });
});

describe("POST members/{id}/recover (class A2): the recovery token", () => {
  it("201: a gr_enr_ token once, with its link; the database sees only the SHA-256; commits", async () => {
    const f = makeFakes();
    const res = await post(f, `members/${TARGET_ID}/recover`);
    expect(res.status).toBe(201);
    const { data } = JSON.parse(await text(res));
    expect(data.token).toMatch(/^gr_enr_[A-Za-z0-9_-]{43}$/);
    expect(data).toEqual({ tokenId: TOKEN_ID, expiresAt: "2030-01-02T12:00:00.000Z", token: data.token, enrolUrl: `${ORIGIN}/enrol#${data.token}` });
    expect(f.rec.memberRecover).toEqual([{ target: TARGET_ID, hash: await sha256Hex(data.token) }]);
    expect(JSON.stringify(f.calls)).not.toContain(data.token);
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("no_email is 409 and returns no token; 42501 is 403 (the reach rule: a person the actor cannot cover is never told apart from any other)", async () => {
    const f = makeFakes({ memberRecover: { status: "no_email", tokenId: null, expiresAt: null } });
    const res = await post(f, `members/${TARGET_ID}/recover`);
    expect(res.status).toBe(409);
    expect(await text(res)).not.toContain("gr_enr_");
    const r = makeFakes({ authorityRefusedIn: "memberRecover" });
    expect((await post(r, `members/${TARGET_ID}/recover`)).status).toBe(403);
  });

  it("with no configured origin the answer is 503 BEFORE the definer: a recovery is never done with no way to deliver it", async () => {
    const f = makeFakes({}, null);
    const res = await call(f, "POST", `members/${TARGET_ID}/recover`, { headers: { authorization: `Bearer ${SESSION_TOKEN}` }, body: {} });
    expect(res.status).toBe(503);
    expect(f.tx).toEqual([]);
  });
});

describe("pin-reset, totp-reset, revoke-all, admin/enrolments", () => {
  it("pin-reset: ok 200, unset 409; both commit; 42501 is 403", async () => {
    const ok = makeFakes();
    expect((await post(ok, `members/${TARGET_ID}/pin-reset`)).status).toBe(200);
    expect(ok.rec.pinReset).toEqual([TARGET_ID]);
    const unset = makeFakes({ pinReset: "unset" });
    expect((await post(unset, `members/${TARGET_ID}/pin-reset`)).status).toBe(409);
    expect(lastTx(unset)).toEqual({ kind: "session", committed: true });
    expect((await post(makeFakes({ authorityRefusedIn: "pinReset" }), `members/${TARGET_ID}/pin-reset`)).status).toBe(403);
  });

  it("totp-reset: ok 200, unset 409, and the A3 refusal is 403", async () => {
    const f = makeFakes();
    expect((await post(f, `members/${TARGET_ID}/totp-reset`)).status).toBe(200);
    expect(f.totpResetTargets).toEqual([TARGET_ID]);
    expect((await post(makeFakes({ totpReset: { status: "unset" } }), `members/${TARGET_ID}/totp-reset`)).status).toBe(409);
  });

  it("revoke-all: createdAfter is optional, a real UTC instant is passed normalised, anything else is 400; the counts come back; not_found is 404", async () => {
    const f = makeFakes();
    const ok = await post(f, `orgs/${ORG_ID}/sessions/revoke-all`, { createdAfter: "2030-01-01T10:00:00Z" });
    expect(ok.status).toBe(200);
    expect(JSON.parse(await text(ok)).data).toEqual({ revokedSessions: 3, revokedCredentials: 1 });
    await post(f, `orgs/${ORG_ID}/sessions/revoke-all`, {});
    await post(f, `orgs/${ORG_ID}/sessions/revoke-all`, { createdAfter: null });
    expect(f.rec.revokeAll).toEqual([{ org: ORG_ID, createdAfter: "2030-01-01T10:00:00.000Z" }, { org: ORG_ID, createdAfter: null }, { org: ORG_ID, createdAfter: null }]);
    const bad = makeFakes();
    for (const createdAfter of ["yesterday", "2030-02-30T00:00:00Z", "2030-01-01", "2030-01-01T10:00:00+02:00", 5]) {
      expect((await post(bad, `orgs/${ORG_ID}/sessions/revoke-all`, { createdAfter })).status, String(createdAfter)).toBe(400);
    }
    expect(bad.calls).toEqual([]);
    expect((await post(makeFakes({ revokeAll: { status: "not_found", sessions: 0, credentials: 0 } }), `orgs/${ORG_ID}/sessions/revoke-all`)).status).toBe(404);
  });

  it("revoke-all: an org the actor has no scope over is 403 and a future time (22023) is 422, both rolled back", async () => {
    const f = makeFakes({ authorityRefusedIn: "orgSessionsRevokeAll" });
    expect((await post(f, `orgs/${ORG_ID}/sessions/revoke-all`)).status).toBe(403);
    expect(lastTx(f)).toEqual({ kind: "session", committed: false });
    expect((await post(makeFakes({ invalidArgumentIn: "orgSessionsRevokeAll" }), `orgs/${ORG_ID}/sessions/revoke-all`, { createdAfter: "2099-01-01T00:00:00Z" })).status).toBe(422);
  });

  it("admin/enrolments: 201 with a gr_enr_ token once (hash only to the database); a non-uuid target is 400; 42501 is 403", async () => {
    const f = makeFakes();
    const res = await post(f, "admin/enrolments", { userId: TARGET_ID });
    expect(res.status).toBe(201);
    const { data } = JSON.parse(await text(res));
    expect(f.rec.adminEnrol).toEqual([{ target: TARGET_ID, hash: await sha256Hex(data.token) }]);
    expect(data.enrolUrl).toBe(`${ORIGIN}/enrol#${data.token}`);
    expect((await post(makeFakes(), "admin/enrolments", { userId: "x" })).status).toBe(400);
    expect((await post(makeFakes({ authorityRefusedIn: "adminEnrolmentIssue" }), "admin/enrolments", { userId: TARGET_ID })).status).toBe(403);
  });
});

describe("credentials of a signed-in person", () => {
  it("GET lists the person's credentials (never a key or an id's bytes)", async () => {
    const view = { id: CRED_ROW_ID, label: "iPad", note: null, createdAt: "2030-01-01T00:00:00.000Z", lastUsedAt: null, revokedAt: null, backupEligible: true, backupState: false };
    const f = makeFakes({ credentialList: [view] });
    const res = await call(f, "GET", "credentials", { headers: authed() });
    expect(res.status).toBe(200);
    expect(JSON.parse(await text(res)).data).toEqual({ credentials: [view] });
  });

  it("POST credentials/options: the member bucket first (10 an hour), then the A2 definer; options are built for THIS person with the credentials they hold excluded", async () => {
    const f = makeFakes();
    const res = await post(f, "credentials/options");
    expect(res.status).toBe(200);
    const { data } = JSON.parse(await text(res));
    expect(data.challengeToken).toMatch(/^[A-Za-z0-9_-]{43}\.\d+\.[A-Za-z0-9_-]{43}$/);
    expect(f.rateLimitHits).toEqual([{ hash: await sha256Hex(SESSION_TOKEN), bucket: CREDENTIAL_BUCKET, windowSeconds: 3600, max: CREDENTIAL_PER_MEMBER_PER_HOUR }]);
    expect(idx(f, "db.hitRateLimit")).toBeLessThan(idx(f, "session.credentialOptions"));
    const req = f.rec.registrationOptions[0]!;
    expect(req.userHandle).toEqual(uuidToBytes(USER_ID));
    expect(req.userName).toBe("staff@example.test");
    expect(req.challenge).toEqual(bytes(32, 15));
    expect(req.excludeCredentialIds).toEqual([bytes(32, 17)]);
  });

  it("options: too_many is 409 (and commits); the member bucket exhausted is 429 with Retry-After and no transaction; a drifting origin is 503 with no options built", async () => {
    const many = makeFakes({ credentialOptions: { status: "too_many" } });
    expect((await post(many, "credentials/options")).status).toBe(409);
    expect(many.calls).not.toContain("registration.options");
    expect(lastTx(many)).toEqual({ kind: "session", committed: true });
    const limited = makeFakes({ rateLimitOk: false });
    const res = await post(limited, "credentials/options");
    expect(res.status).toBe(429);
    expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(limited.tx).toEqual([]);
    const drift = makeFakes({ credentialOptions: { status: "ok", challenge: { nonce: bytes(32, 1), exp: 4_000_000_000, mac: bytes(32, 2) }, rp: { rpId: "partners.example.test", origin: "https://other.example.test" }, excludeCredentialIds: [] } });
    expect((await post(drift, "credentials/options")).status).toBe(503);
    expect(drift.calls).not.toContain("registration.options");
  });

  it("options: the A2 refusal (no fresh PIN grant or reauth) is 403 and nothing is built", async () => {
    const f = makeFakes({ authorityRefusedIn: "credentialOptions" });
    expect((await post(f, "credentials/options")).status).toBe(403);
    expect(f.calls).not.toContain("registration.options");
  });

  const body = () => ({ challengeToken: challengeToken(), credential: registrationCredentialJson() });

  it("POST credentials: rate limit, the relying party in its own transaction, the wrapper with NO session transaction open, and only then the A2 definer", async () => {
    const f = makeFakes();
    const res = await post(f, "credentials", body());
    expect(res.status).toBe(201);
    expect(JSON.parse(await text(res)).data).toEqual({ credentialId: CRED_ROW_ID });
    const order = ["db.hitRateLimit", "db.withMint", "mint.rpConfig", "registration.verify", "db.withSession", "session.credentialRegister"].map((c) => idx(f, c));
    expect(order.every((i) => i >= 0)).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(f.rec.credentialRegister).toHaveLength(1);
    expect(f.rec.credentialRegister[0]).toMatchObject({ nonce: bytes(32, 1), exp: Math.floor(f.membersDeps.nowMs() / 1000) + 100, mac: bytes(32, 2), publicKey: bytes(77, 6), transports: ["internal"] });
    expect(f.rec.registrationVerify[0]!.expectedChallenge).toEqual(bytes(32, 1));
    expect(f.tx).toEqual([{ kind: "mint", committed: true }, { kind: "session", committed: true }]);
  });

  it("a ceremony the wrapper refuses is 403 and never opens the session transaction (the A2 grant is not spent on it)", async () => {
    const f = makeFakes({ registration: { ok: false } });
    const res = await post(f, "credentials", body());
    expect(res.status).toBe(403);
    expect(f.calls).not.toContain("db.withSession");
  });

  it("an expired challenge is 410 before the relying party is read; a drifting origin is 503 before the wrapper", async () => {
    const f = makeFakes();
    const res = await post(f, "credentials", { ...body(), challengeToken: challengeToken(Math.floor(f.membersDeps.nowMs() / 1000) - 1) });
    expect(res.status).toBe(410);
    expect(f.calls).not.toContain("db.withMint");
    const drift = makeFakes({ rp: { rpId: "partners.example.test", origin: "https://other.example.test" } });
    expect((await post(drift, "credentials", body())).status).toBe(503);
    expect(drift.calls).not.toContain("registration.verify");
  });

  it("COMMIT ON EVERY STATUS: each refusal of the definer is mapped and commits", async () => {
    const expected: Record<string, [number, string]> = {
      bad_challenge: [403, "registration_refused"],
      expired: [410, "expired"],
      too_many: [409, "too_many"],
      credential_in_use: [409, "credential_in_use"],
      replayed: [403, "registration_refused"],
    };
    for (const [status, [http, code]] of Object.entries(expected)) {
      const f = makeFakes({ credentialRegister: { status, credentialId: null } });
      const res = await post(f, "credentials", body());
      expect(res.status, status).toBe(http);
      expect(JSON.parse(await text(res)).error.code, status).toBe(code);
      expect(lastTx(f), status).toEqual({ kind: "session", committed: true });
    }
  });

  it("the body is strict: a missing credential, a non-canonical base64url, unknown keys and an enrolment-mode body (userId, refKind) are 400", async () => {
    const f = makeFakes();
    for (const b of [{ challengeToken: challengeToken() }, { ...body(), userId: USER_ID }, { ...body(), refKind: "invite" }, { ...body(), challengeToken: "x" }, { ...body(), credential: registrationCredentialJson({}, { attestationObject: "A" }) }]) {
      expect((await post(f, "credentials", b)).status).toBe(400);
    }
    expect(f.calls).toEqual([]);
  });

  it("DELETE credentials/{id}: ok 200, not_found 404, already_revoked 409; each commits; 10 an hour; 42501 is 403", async () => {
    for (const [status, http] of [["ok", 200], ["not_found", 404], ["already_revoked", 409]] as const) {
      const f = makeFakes({ credentialRevoke: status });
      const res = await call(f, "DELETE", `credentials/${CRED_ROW_ID}`, { headers: authed() });
      expect(res.status, status).toBe(http);
      expect(f.rec.credentialRevoke).toEqual([CRED_ROW_ID]);
      expect(lastTx(f)).toEqual({ kind: "session", committed: true });
      expect(f.rateLimitHits[0]).toMatchObject({ bucket: CREDENTIAL_BUCKET, windowSeconds: 3600, max: 10 });
    }
    const limited = makeFakes({ rateLimitOk: false });
    expect((await call(limited, "DELETE", `credentials/${CRED_ROW_ID}`, { headers: authed() })).status).toBe(429);
    expect(limited.tx).toEqual([]);
    expect((await call(makeFakes({ authorityRefusedIn: "credentialRevoke" }), "DELETE", `credentials/${CRED_ROW_ID}`, { headers: authed() })).status).toBe(403);
  });
});

describe("errors never carry database text, and a dead session is the ONE 401", () => {
  it("an unexpected error is a constant 500 with the transaction rolled back", async () => {
    const f = makeFakes({ throwIn: "memberRevoke" });
    const res = await post(f, `members/${TARGET_ID}/revoke`, { orgId: ORG_ID });
    expect(res.status).toBe(500);
    expect(await text(res)).not.toContain("secret database text");
    expect(lastTx(f)).toEqual({ kind: "session", committed: false });
  });

  it("a session the binder refuses is 401 on every route that reaches the database", async () => {
    for (const [method, path, body] of ROUTES) {
      const f = makeFakes({ bindRefused: true });
      const res = await call(f, method, path, { headers: authed(), body });
      expect(res.status, `${method} ${path}`).toBe(401);
    }
  });
});
