// supabase/tests/unit/partner-invites-handler.test.ts
//
// The `partner-invites` handler (docs/security/partner-auth-design.md 4.5, 6.1, 8, 22.4; PA-14, PA-17, PA-23; slice S1.5), against the in-memory ports of partner-fakes.ts. What is decided HERE, by the pure
// handler: the route table and the Origin / bearer / media-type / strict-body order, the CONSTANT body of accept/start, the closing of the GoTrue session AFTER the accept definer (never before, on every path),
// COMMIT ON EVERY STATUS, the status-to-HTTP maps, the one 403 that hides every refusal before the mailbox is proved, and that a token reaches the database only as its hash. What needs a real database is
// supabase/tests/matrix/32_partner_invites_enrolment.sql.

import { describe, expect, it } from "vitest";
import { handlePartnerInvitesRequest, ACCEPT_START_PER_TOKEN_PER_HOUR, ACCEPT_VERIFY_PER_TOKEN_PER_HOUR, INVITE_CREATE_BUCKET, INVITE_CREATE_PER_EMAIL_PER_DAY, INVITE_CREATE_PER_MEMBER_PER_DAY } from "../../functions/_shared/partner/invites-handler.ts";
import { uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { authed, bytes, challengeToken, ENROLMENT_TOKEN, enrolCredentialBody, fnReq, INVITE_ID, INVITE_TOKEN, makeFakes, ORG_ID, ORIGIN, OTP_CODE, registrationCredentialJson, SESSION_TOKEN, sha256Hex, USER_ID } from "./partner-fakes.ts";

const FN = "partner-invites";
const call = (f: ReturnType<typeof makeFakes>, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}) =>
  handlePartnerInvitesRequest(fnReq(FN, method, path, init), f.invitesDeps);
const anon = { origin: ORIGIN };
const text = async (res: Response) => await res.text();
const json = async (res: Response): Promise<{ data?: Record<string, unknown>; error?: { code: string; message: string } }> => JSON.parse(await res.text());
const idx = (f: ReturnType<typeof makeFakes>, c: string) => f.calls.indexOf(c);

const createBody = { orgId: ORG_ID, role: "staff", email: "  New.Staff@Example.TEST " };

describe("routing, Origin, bearer and body order", () => {
  const sessionRoutes: Array<[string, string, unknown]> = [
    ["POST", "invites", createBody],
    ["GET", "invites", undefined],
    ["DELETE", `invites/${INVITE_ID}`, undefined],
    ["POST", "invites/accept", { token: INVITE_TOKEN }],
  ];
  const openRoutes: Array<[string, unknown]> = [
    ["invites/accept/start", { token: INVITE_TOKEN }],
    ["invites/accept/verify", { token: INVITE_TOKEN, code: OTP_CODE }],
    ["enrolments/accept/start", { token: ENROLMENT_TOKEN }],
    ["enrolments/accept/verify", { token: ENROLMENT_TOKEN, code: OTP_CODE }],
    ["credentials", enrolCredentialBody()],
  ];

  it("OPTIONS from the allowed origin is 204 for every route and touches NO port (PA-10)", async () => {
    const f = makeFakes();
    for (const path of ["invites", `invites/${INVITE_ID}`, "invites/accept/start", "credentials", "no-such-route"]) {
      const res = await call(f, "OPTIONS", path, { headers: { origin: ORIGIN, "access-control-request-method": "POST" } });
      expect(res.status, path).toBe(204);
      expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    }
    expect(f.calls).toEqual([]);
  });

  it("a foreign Origin is 403 BEFORE routing, for every route and method, with no CORS header and no port touched", async () => {
    const f = makeFakes();
    for (const [method, path] of [...sessionRoutes.map(([m, p]) => [m, p] as const), ...openRoutes.map(([p]) => ["POST", p] as const), ["POST", "no-such-route"] as const]) {
      const res = await call(f, method, path, { headers: { origin: "https://evil.example.test", authorization: `Bearer ${SESSION_TOKEN}` }, body: method === "POST" ? {} : undefined });
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
      expect((await json(res)).error).toEqual({ code: "forbidden", message: "origin not allowed" });
    }
    expect(f.calls).toEqual([]);
  });

  it("an unknown route is 404, a path id that is not a uuid is 404, and a wrong method is 405 with Allow (nothing touched)", async () => {
    const f = makeFakes();
    expect((await call(f, "POST", "no-such-route", { headers: authed(), body: {} })).status).toBe(404);
    expect((await call(f, "DELETE", "invites/not-a-uuid", { headers: authed() })).status).toBe(404);
    expect((await call(f, "DELETE", `invites/${INVITE_ID}/extra`, { headers: authed() })).status).toBe(404);
    for (const [method, path, allow] of [["PUT", "invites", "GET, POST"], ["POST", `invites/${INVITE_ID}`, "DELETE"], ["GET", "invites/accept/start", "POST"], ["GET", "credentials", "POST"], ["DELETE", "invites/accept", "POST"]] as const) {
      const res = await call(f, method, path, { headers: authed(), body: method === "POST" ? {} : undefined });
      expect(res.status, `${method} ${path}`).toBe(405);
      expect(res.headers.get("allow")).toBe(allow);
    }
    expect(f.calls).toEqual([]);
  });

  it("the session routes need a gr_ps_ bearer: none, a Supabase-shaped JWT, a wrong scheme and a malformed token are the ONE 401, with no port touched", async () => {
    const f = makeFakes();
    const jwtShaped = ["aaa", "bbb", "ccc"].join(".");
    for (const [method, path, body] of sessionRoutes) {
      for (const authorization of [undefined, `Bearer ${jwtShaped}`, `Basic ${SESSION_TOKEN}`, `Bearer ${SESSION_TOKEN}x`]) {
        const headers: Record<string, string> = { origin: ORIGIN };
        if (authorization !== undefined) headers.authorization = authorization;
        const res = await call(f, method, path, { headers, body });
        expect(res.status, `${method} ${path} ${authorization}`).toBe(401);
        expect((await json(res)).error?.code).toBe("unauthenticated");
      }
    }
    expect(f.calls).toEqual([]);
  });

  it("a POST body must be exactly application/json (415 before the body is read) and strictly shaped (400, unknown keys refused)", async () => {
    const f = makeFakes();
    for (const [path] of openRoutes) {
      const res = await call(f, "POST", path, { headers: { ...anon, "content-type": "text/plain; x=application/json" }, raw: "{}" });
      expect(res.status, path).toBe(415);
    }
    for (const [path, body] of openRoutes) {
      const res = await call(f, "POST", path, { headers: anon, body: { ...(body as object), extra: 1 } });
      expect(res.status, `${path} with an extra key`).toBe(400);
    }
    expect(f.calls).toEqual([]);
  });
});

describe("POST invites (class A2)", () => {
  it("201: the token comes back once with its link; the database sees only the SHA-256, the address normalised, and the transaction commits", async () => {
    const f = makeFakes();
    const res = await call(f, "POST", "invites", { headers: authed(), body: createBody });
    expect(res.status).toBe(201);
    const { data } = await json(res);
    const token = data!.token as string;
    expect(token).toMatch(/^gr_inv_[A-Za-z0-9_-]{43}$/);
    expect(data).toEqual({ inviteId: INVITE_ID, expiresAt: "2030-01-04T12:00:00.000Z", token, inviteUrl: `${ORIGIN}/invite#${token}` });
    expect(f.rec.inviteCreate).toEqual([{ orgId: ORG_ID, role: "staff", email: "new.staff@example.test", tokenHash: await sha256Hex(token) }]);
    expect(JSON.stringify(f.calls)).not.toContain(token);
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("design 8: 20 a day per inviter (a member bucket) and 3 a day per invitee address (a system bucket keyed on the address's hash), both hit BEFORE the request transaction", async () => {
    const f = makeFakes();
    await call(f, "POST", "invites", { headers: authed(), body: createBody });
    expect(f.rateLimitHits).toEqual([{ hash: await sha256Hex(SESSION_TOKEN), bucket: INVITE_CREATE_BUCKET, windowSeconds: 86_400, max: INVITE_CREATE_PER_MEMBER_PER_DAY }]);
    expect(f.rec.systemHits).toEqual([{ bucket: `partner-invite-email:${await sha256Hex("new.staff@example.test")}`, windowSeconds: 86_400, max: INVITE_CREATE_PER_EMAIL_PER_DAY }]);
    expect(f.calls.indexOf("db.hitRateLimit")).toBeLessThan(f.calls.indexOf("db.hitSystemRateLimit"));
    expect(f.calls.indexOf("db.hitSystemRateLimit")).toBeLessThan(f.calls.indexOf("db.withSession"));
    expect(f.rec.systemHits[0]!.bucket.length).toBeLessThanOrEqual(128);
  });

  it("429 with Retry-After when either bucket is exhausted: no token is minted and no transaction opens", async () => {
    for (const over of [{ rateLimitOk: false }, { systemRateLimitOk: false }]) {
      const f = makeFakes(over);
      const res = await call(f, "POST", "invites", { headers: authed(), body: createBody });
      expect(res.status).toBe(429);
      expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
      expect(f.newTokens.invite).toEqual([]);
      expect(f.tx).toEqual([]);
    }
  });

  it("an address already holding an active membership is 409, and the refusal commits (no token in the body)", async () => {
    const f = makeFakes({ inviteCreate: { status: "already_member", inviteId: null, expiresAt: null } });
    const res = await call(f, "POST", "invites", { headers: authed(), body: createBody });
    expect(res.status).toBe(409);
    const raw = await text(res);
    expect(JSON.parse(raw).error.code).toBe("already_member");
    expect(raw).not.toContain("gr_inv_");
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("42501 (outside the inviter's reach) is 403 and rolls back; 22023 is 422; a dead session is the ONE 401", async () => {
    const refused = makeFakes({ authorityRefusedIn: "inviteCreate" });
    const r1 = await call(refused, "POST", "invites", { headers: authed(), body: createBody });
    expect(r1.status).toBe(403);
    expect(refused.tx).toEqual([{ kind: "session", committed: false }]);
    expect((await call(makeFakes({ invalidArgumentIn: "inviteCreate" }), "POST", "invites", { headers: authed(), body: createBody })).status).toBe(422);
    const dead = makeFakes({ bindRefused: true });
    expect((await call(dead, "POST", "invites", { headers: authed(), body: createBody })).status).toBe(401);
  });

  it("the body is strict: sponsor and any other role, a malformed address, a non-uuid org and missing fields are 400 and touch nothing", async () => {
    const f = makeFakes();
    for (const body of [{ ...createBody, role: "sponsor" }, { ...createBody, role: "admin" }, { ...createBody, email: "no-at-sign" }, { ...createBody, email: "a b@example.test" }, { ...createBody, orgId: "x" }, { orgId: ORG_ID, role: "staff" }, {}]) {
      expect((await call(f, "POST", "invites", { headers: authed(), body })).status, JSON.stringify(body)).toBe(400);
    }
    expect(f.calls).toEqual([]);
  });

  it("no configured origin: 503 with nothing written (the link cannot be built)", async () => {
    const f = makeFakes({}, null);
    const res = await call(f, "POST", "invites", { headers: { authorization: `Bearer ${SESSION_TOKEN}` }, body: createBody });
    expect(res.status).toBe(503);
    expect(f.tx).toEqual([]);
  });
});

describe("GET invites and DELETE invites/{id}", () => {
  it("GET passes the optional orgId, returns the views, and a query it does not know is 400", async () => {
    const view = { id: INVITE_ID, orgId: ORG_ID, role: "staff", facilityId: "fac-1", inviteeEmail: "a@example.test", invitedBy: USER_ID, createdAt: "2030-01-01T00:00:00.000Z", expiresAt: "2030-01-04T00:00:00.000Z", acceptedAt: null, revokedAt: null, attempts: 2 };
    const f = makeFakes({ inviteList: [view] });
    const res = await call(f, "GET", `invites?orgId=${ORG_ID.toUpperCase()}`, { headers: authed() });
    expect(res.status).toBe(200);
    expect((await json(res)).data).toEqual({ invites: [view] });
    expect(f.rec.inviteList).toEqual([ORG_ID]);
    await call(f, "GET", "invites", { headers: authed() });
    expect(f.rec.inviteList).toEqual([ORG_ID, null]);
    for (const q of ["?org=1", "?orgId=nope", `?orgId=${ORG_ID}&orgId=${ORG_ID}`]) expect((await call(f, "GET", `invites${q}`, { headers: authed() })).status, q).toBe(400);
  });

  it("DELETE: ok 200, not_found 404, already_accepted / already_revoked 409; every status commits", async () => {
    for (const [status, http, code] of [["ok", 200, undefined], ["not_found", 404, "not_found"], ["already_accepted", 409, "invite_accepted"], ["already_revoked", 409, "invite_revoked"]] as const) {
      const f = makeFakes({ inviteRevoke: status });
      const res = await call(f, "DELETE", `invites/${INVITE_ID}`, { headers: authed() });
      expect(res.status, status).toBe(http);
      if (code !== undefined) expect((await json(res)).error?.code).toBe(code);
      expect(f.rec.inviteRevoke).toEqual([INVITE_ID]);
      expect(f.tx).toEqual([{ kind: "session", committed: true }]);
    }
  });
});

describe("POST invites/accept (branch E, class A2)", () => {
  it("ok: 200 with the org and role; the invite token reaches the database only as its SHA-256", async () => {
    const f = makeFakes();
    const res = await call(f, "POST", "invites/accept", { headers: authed(), body: { token: INVITE_TOKEN } });
    expect(res.status).toBe(200);
    expect((await json(res)).data).toEqual({ orgId: ORG_ID, role: "staff" });
    expect(f.rec.inviteAcceptMember).toEqual([await sha256Hex(INVITE_TOKEN)]);
    expect(JSON.stringify(f.calls)).not.toContain(INVITE_TOKEN);
  });

  it("every refusal that costs an attempt (unknown, locked, a forwarded link's other mailbox, unconfirmed) is ONE 403, and each COMMITS the attempt count (PA-14)", async () => {
    const bodies = new Set<string>();
    for (const status of ["not_found", "locked", "email_mismatch", "email_unconfirmed"] as const) {
      const f = makeFakes({ inviteMemberAccept: { status, orgId: null, role: null } });
      const res = await call(f, "POST", "invites/accept", { headers: authed(), body: { token: INVITE_TOKEN } });
      expect(res.status, status).toBe(403);
      bodies.add(await text(res));
      expect(f.tx, status).toEqual([{ kind: "session", committed: true }]);
    }
    expect(bodies.size).toBe(1);
  });

  it("already_member is 409; a token of the wrong kind or shape is 400 with nothing touched", async () => {
    const f = makeFakes({ inviteMemberAccept: { status: "already_member", orgId: null, role: null } });
    expect((await call(f, "POST", "invites/accept", { headers: authed(), body: { token: INVITE_TOKEN } })).status).toBe(409);
    const g = makeFakes();
    for (const token of [ENROLMENT_TOKEN, INVITE_TOKEN.slice(0, -1), "x", 5]) expect((await call(g, "POST", "invites/accept", { headers: authed(), body: { token } })).status).toBe(400);
    expect(g.calls).toEqual([]);
  });
});

describe.each([
  { kind: "invite", prefix: "invites", token: INVITE_TOKEN, otpPort: "invite" as const, other: ENROLMENT_TOKEN, sendCall: "inviteOtp.send" },
  { kind: "enrolment", prefix: "enrolments", token: ENROLMENT_TOKEN, otpPort: "enrolment" as const, other: INVITE_TOKEN, sendCall: "enrolmentOtp.send" },
])("$prefix/accept/start: a CONSTANT answer ($kind token)", ({ kind, prefix, token, otpPort, other, sendCall }) => {
  const start = (f: ReturnType<typeof makeFakes>, body: unknown = { token }) => call(f, "POST", `${prefix}/accept/start`, { headers: anon, body });
  const emailOf = (f: ReturnType<typeof makeFakes>) => (otpPort === "invite" ? f.state.inviteEmail : f.state.enrolmentEmail);

  it("a live token: the code is sent to the address ON the record (never one from the body), 3 a token an hour, with no transaction open", async () => {
    const f = makeFakes();
    const res = await start(f);
    expect(res.status).toBe(200);
    expect((await json(res)).data).toEqual({ requested: true });
    expect(f.rec.otpSentTo).toEqual([{ port: otpPort, email: emailOf(f) }]);
    expect(f.rec.systemHits).toEqual([{ bucket: `partner-${kind}-start:${await sha256Hex(token)}`, windowSeconds: 3600, max: ACCEPT_START_PER_TOKEN_PER_HOUR }]);
    expect(f.openTxAtOtpCall).toEqual([0]);
    expect(f.calls).toContain(sendCall);
  });

  it("an address in the body is refused (400): a token holder cannot redirect the code", async () => {
    const f = makeFakes();
    expect((await start(f, { token, email: "attacker@example.test" })).status).toBe(400);
    expect(f.calls).toEqual([]);
  });

  it("an unknown token, a rate-limited token and a mailer failure answer the SAME bytes as a live token (no existence oracle), and an unknown token sends nothing and hits no bucket", async () => {
    const live = await text(await start(makeFakes()));
    const unknown = makeFakes(kind === "invite" ? { inviteEmail: null } : { enrolmentEmail: null });
    expect(await text(await start(unknown))).toBe(live);
    expect(unknown.rec.otpSentTo).toEqual([]);
    expect(unknown.rec.systemHits).toEqual([]);
    const limited = makeFakes({ systemRateLimitOk: false });
    const rl = await start(limited);
    expect(rl.status).toBe(200);
    expect(await text(rl)).toBe(live);
    expect(limited.rec.otpSentTo).toEqual([]);
    const broken = makeFakes({ otpSendThrows: true });
    const br = await start(broken);
    expect(br.status).toBe(200);
    expect(await text(br)).toBe(live);
  });

  it("a malformed token or one of the other kind is 400 (its shape is public, so this says nothing about any record)", async () => {
    const f = makeFakes();
    for (const t of [other, "gr_inv_short", "", 7]) expect((await start(f, { token: t })).status).toBe(400);
    expect(f.calls).toEqual([]);
  });
});

describe("invites/accept/verify: verifyOtp, THEN the accept definer, THEN the GoTrue session is closed (branch N)", () => {
  const verify = (f: ReturnType<typeof makeFakes>, over: Record<string, unknown> = {}) =>
    call(f, "POST", "invites/accept/verify", { headers: anon, body: { token: INVITE_TOKEN, code: OTP_CODE, ...over } });

  it("ok: the register challenge and the create options come back; the order is lookup, bucket, verifyOtp, accept, closeSession, options", async () => {
    const f = makeFakes();
    const res = await verify(f);
    expect(res.status).toBe(200);
    const { data } = await json(res);
    expect(data).toMatchObject({ userId: USER_ID, refKind: "invite", refId: INVITE_ID, orgId: ORG_ID, role: "staff" });
    expect(data!.challengeToken).toMatch(/^[A-Za-z0-9_-]{43}\.\d+\.[A-Za-z0-9_-]{43}$/);
    expect(data!.options).toBeDefined();
    expect(f.rec.otpVerifiedBy).toEqual([{ port: "invite", email: "invitee@example.test", code: OTP_CODE }]);
    expect(f.rec.accepts).toEqual([{ kind: "invite", hash: await sha256Hex(INVITE_TOKEN), userId: USER_ID, gotrueSessionId: "22222222-2222-2222-2222-222222222222" }]);
    const order = ["mint.inviteEmailForToken", "db.hitSystemRateLimit", "inviteOtp.verify", "mint.inviteAccept", "inviteOtp.closeSession", "registration.options"].map((c) => idx(f, c));
    expect(order.every((i) => i >= 0)).toBe(true);
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(f.rec.registrationOptions[0]).toMatchObject({ userName: "invitee@example.test", excludeCredentialIds: [] });
    expect(f.rec.registrationOptions[0]!.userHandle).toEqual(uuidToBytes(USER_ID));
    expect(f.rec.registrationOptions[0]!.challenge).toEqual(bytes(32, 11));
    expect(f.rec.systemHits[0]).toEqual({ bucket: `partner-invite-verify:${await sha256Hex(INVITE_TOKEN)}`, windowSeconds: 3600, max: ACCEPT_VERIFY_PER_TOKEN_PER_HOUR });
  });

  it("the vendor is called with NO database transaction open (verifyOtp and the sign-out)", async () => {
    const f = makeFakes();
    await verify(f);
    expect(f.openTxAtOtpCall.length).toBeGreaterThan(0);
    expect(f.openTxAtOtpCall.every((n) => n === 0)).toBe(true);
    expect(f.otpClosed.count).toBe(1);
  });

  it("COMMIT ON EVERY STATUS: each refusal the definer returns commits its transaction (the attempt count), and the GoTrue session is closed AFTER it", async () => {
    for (const status of ["not_found", "locked", "email_mismatch", "email_unconfirmed", "session_stale", "existing_member_sign_in", "recover_required"] as const) {
      const f = makeFakes({ inviteAccept: { status, accepted: null } });
      const res = await verify(f);
      expect([403, 409], status).toContain(res.status);
      expect(f.tx.filter((t) => t.kind === "mint").every((t) => t.committed), status).toBe(true);
      expect(f.tx.filter((t) => t.kind === "mint")).toHaveLength(2); // the address lookup, then the accept
      expect(idx(f, "mint.inviteAccept"), status).toBeLessThan(idx(f, "inviteOtp.closeSession"));
      expect(f.otpClosed.count, status).toBe(1);
      expect(f.calls, status).not.toContain("registration.options");
    }
  });

  it("existing_member_sign_in and recover_required are the ONLY two statuses told apart (409, to the owner of the mailbox); the rest are the one 403", async () => {
    const seen: Record<string, [number, string | undefined]> = {};
    for (const status of ["not_found", "locked", "email_mismatch", "email_unconfirmed", "session_stale", "existing_member_sign_in", "recover_required"] as const) {
      const res = await verify(makeFakes({ inviteAccept: { status, accepted: null } }));
      seen[status] = [res.status, (await json(res)).error?.code];
    }
    expect(seen.existing_member_sign_in).toEqual([409, "existing_member_sign_in"]);
    expect(seen.recover_required).toEqual([409, "recover_required"]);
    for (const status of ["not_found", "locked", "email_mismatch", "email_unconfirmed", "session_stale"]) expect(seen[status], status).toEqual([403, "accept_refused"]);
  });

  it("NO ORACLE: an unknown token, a wrong code, a rate-limited token, a GoTrue session without an id and every refusal of the definer answer the SAME 403 bytes", async () => {
    const bodies: string[] = [];
    const cases: Array<ReturnType<typeof makeFakes>> = [
      makeFakes({ inviteEmail: null }),
      makeFakes({ otpVerifyOk: false }),
      makeFakes({ systemRateLimitOk: false }),
      makeFakes({ otpSessionId: null }),
      makeFakes({ inviteAccept: { status: "not_found", accepted: null } }),
      makeFakes({ inviteAccept: { status: "email_mismatch", accepted: null } }),
      makeFakes({ inviteAccept: { status: "locked", accepted: null } }),
    ];
    for (const f of cases) {
      const res = await verify(f);
      expect(res.status).toBe(403);
      bodies.push(await text(res));
    }
    expect(new Set(bodies).size).toBe(1);
  });

  it("an unknown token touches neither the code check nor the accept definer; a wrong code never reaches the definer and has no session to close", async () => {
    const unknown = makeFakes({ inviteEmail: null });
    await verify(unknown);
    expect(unknown.calls).toEqual(["db.withMint", "mint.inviteEmailForToken"]);
    const wrong = makeFakes({ otpVerifyOk: false });
    await verify(wrong);
    expect(wrong.calls).not.toContain("mint.inviteAccept");
    expect(wrong.otpClosed.count).toBe(0);
  });

  it("a GoTrue session with no id is refused without calling the definer, and the session is still closed", async () => {
    const f = makeFakes({ otpSessionId: null });
    expect((await verify(f)).status).toBe(403);
    expect(f.calls).not.toContain("mint.inviteAccept");
    expect(f.otpClosed.count).toBe(1);
  });

  it("an unexpected error in the definer rolls back, answers a constant 500 with no database text, and STILL closes the GoTrue session", async () => {
    const f = makeFakes({ throwIn: "inviteAccept" });
    const res = await verify(f);
    expect(res.status).toBe(500);
    expect(await text(res)).not.toContain("secret database text");
    expect(f.tx.filter((t) => t.kind === "mint").map((t) => t.committed)).toEqual([true, false]);
    expect(f.otpClosed.count).toBe(1);
  });

  it("a configured origin that disagrees with the database's is a 503 before the definer runs (nothing counted), and the session is closed", async () => {
    const f = makeFakes({ rp: { rpId: "partners.example.test", origin: "https://other.example.test" } });
    const res = await verify(f);
    expect(res.status).toBe(503);
    expect(f.calls).not.toContain("mint.inviteAccept");
    expect(f.otpClosed.count).toBe(1);
  });

  it("the code is 6 to 10 digits and nothing else is accepted (400, nothing touched)", async () => {
    const f = makeFakes();
    for (const code of ["12345", "12345678901", "abcdef", "", 123456]) expect((await verify(f, { code })).status, String(code)).toBe(400);
    expect(f.calls).toEqual([]);
  });
});

describe("enrolments/accept/verify (recovery and admin tokens)", () => {
  const verify = (f: ReturnType<typeof makeFakes>) => call(f, "POST", "enrolments/accept/verify", { headers: anon, body: { token: ENROLMENT_TOKEN, code: OTP_CODE } });

  it("ok: the same order, the person's own address, and the purpose in the response", async () => {
    const f = makeFakes();
    const res = await verify(f);
    expect(res.status).toBe(200);
    expect((await json(res)).data).toMatchObject({ userId: USER_ID, refKind: "enrolment", purpose: "recover" });
    expect(f.rec.otpVerifiedBy).toEqual([{ port: "enrolment", email: "staff@example.test", code: OTP_CODE }]);
    expect(f.rec.accepts[0]).toMatchObject({ kind: "enrolment", hash: await sha256Hex(ENROLMENT_TOKEN) });
    expect(idx(f, "mint.enrolmentAccept")).toBeLessThan(idx(f, "enrolmentOtp.closeSession"));
    expect(f.rec.systemHits[0]!.bucket).toBe(`partner-enrolment-verify:${await sha256Hex(ENROLMENT_TOKEN)}`);
  });

  it("existing_member_sign_in is 409; refused and every other status are the one 403; all commit", async () => {
    for (const [status, http] of [["existing_member_sign_in", 409], ["refused", 403], ["locked", 403], ["email_mismatch", 403], ["session_stale", 403], ["not_found", 403]] as const) {
      const f = makeFakes({ enrolmentAccept: { status, accepted: null } });
      const res = await verify(f);
      expect(res.status, status).toBe(http);
      expect(f.tx.filter((t) => t.kind === "mint").every((t) => t.committed)).toBe(true);
      expect(f.otpClosed.count).toBe(1);
    }
  });

  it("a recover token uses the account-must-exist OTP: the invite OTP port is never called", async () => {
    const f = makeFakes();
    await verify(f);
    expect(f.calls.filter((c) => c.startsWith("inviteOtp."))).toEqual([]);
  });
});

describe("POST credentials, enrolment mode: the first credential and the first session", () => {
  const post = (f: ReturnType<typeof makeFakes>, body: unknown = enrolCredentialBody(), headers: Record<string, string> = anon) => call(f, "POST", "credentials", { headers, body });

  it("201: the wrapper verifies FIRST, then register_first; the session token is returned once and only its hash reaches the database; the transaction commits", async () => {
    const f = makeFakes();
    const res = await post(f);
    expect(res.status).toBe(201);
    const { data } = await json(res);
    const token = data!.token as string;
    expect(token).toMatch(/^gr_ps_[A-Za-z0-9_-]{43}$/);
    expect(data).toEqual({ token, expiresAt: "2030-01-01T20:00:00.000Z", aal: 1, enrolmentUntil: "2030-01-01T12:15:00.000Z" });
    expect(f.rec.registerFirst).toHaveLength(1);
    const input = f.rec.registerFirst[0]!;
    expect(input).toMatchObject({ sessionTokenHash: await sha256Hex(token), userId: USER_ID, refKind: 1, refId: INVITE_ID });
    expect(input.nonce).toEqual(bytes(32, 1));
    expect(input.mac).toEqual(bytes(32, 2));
    expect(input.attestationObject).toEqual(bytes(120, 8));
    expect(input.credentialId).toEqual(f.state.registration.ok ? f.state.registration.credentialId : null);
    expect(input.publicKey).toEqual(bytes(77, 6));
    expect(input.transports).toEqual(["internal"]);
    expect(idx(f, "registration.verify")).toBeLessThan(idx(f, "mint.registerFirst"));
    expect(f.rec.registrationVerify[0]!.expectedChallenge).toEqual(bytes(32, 1));
    expect(JSON.stringify(f.calls)).not.toContain(token);
    expect(f.tx).toEqual([{ kind: "mint", committed: true }]);
  });

  it("an enrolment-token acceptance is ref kind 2; a bearer, if one is sent, is ignored (the route needs none)", async () => {
    const f = makeFakes();
    const res = await post(f, enrolCredentialBody({ refKind: "enrolment" }), { ...anon, authorization: `Bearer ${SESSION_TOKEN}` });
    expect(res.status).toBe(201);
    expect(f.rec.registerFirst[0]!.refKind).toBe(2);
  });

  it("an expired challenge is 410 before any port is touched", async () => {
    const f = makeFakes();
    const res = await post(f, enrolCredentialBody({ challengeToken: challengeToken(Math.floor(f.deps.nowMs() / 1000) - 1) }));
    expect(res.status).toBe(410);
    expect(f.calls).toEqual([]);
  });

  it("a ceremony the wrapper refuses is 403 and never reaches register_first (nothing is burned)", async () => {
    const f = makeFakes({ registration: { ok: false } });
    const res = await post(f);
    expect(res.status).toBe(403);
    const raw = await text(res);
    expect(JSON.parse(raw).error.code).toBe("registration_refused");
    expect(f.calls).not.toContain("mint.registerFirst");
    expect(raw).not.toContain("gr_ps_");
  });

  it("COMMIT ON EVERY STATUS: each refusal of register_first is mapped, commits, and never carries a token", async () => {
    const expected: Record<string, [number, string]> = {
      bad_challenge: [403, "registration_refused"],
      replayed: [403, "registration_refused"],
      not_accepted: [403, "registration_refused"],
      bad_attestation: [403, "registration_refused"],
      expired: [410, "expired"],
      accept_expired: [410, "expired"],
      credential_exists: [409, "credential_exists"],
      other_membership: [409, "other_membership"],
      already_registered: [409, "already_registered"],
      credential_in_use: [409, "credential_in_use"],
    };
    for (const [status, [http, code]] of Object.entries(expected)) {
      const f = makeFakes({ registerFirst: { status, credentialId: null, aal: null, expiresAt: null, enrolmentUntil: null } });
      const res = await post(f);
      expect(res.status, status).toBe(http);
      const raw = await text(res);
      expect(JSON.parse(raw).error.code, status).toBe(code);
      expect(raw, status).not.toContain("gr_ps_");
      expect(f.tx, status).toEqual([{ kind: "mint", committed: true }]);
    }
  });

  it("the body is strict: a wrong ref kind, ids that are not uuids, a non-canonical credential and unknown keys are 400 and touch nothing", async () => {
    const f = makeFakes();
    const bad: unknown[] = [
      enrolCredentialBody({ refKind: "token" }),
      enrolCredentialBody({ userId: "x" }),
      enrolCredentialBody({ refId: 5 }),
      enrolCredentialBody({ challengeToken: "nope" }),
      enrolCredentialBody({ credential: registrationCredentialJson({}, { attestationObject: "AA" }) }),
      enrolCredentialBody({ credential: registrationCredentialJson({ type: "password" }) }),
      enrolCredentialBody({ credential: registrationCredentialJson({}, { clientDataJSON: "not base64url!" }) }),
      enrolCredentialBody({ credential: registrationCredentialJson({ rawId: "AAAA" }) }),
      enrolCredentialBody({ credential: registrationCredentialJson({ extra: true }) }),
      enrolCredentialBody({ credential: registrationCredentialJson({}, { transports: "internal" }) }),
      { ...enrolCredentialBody(), pop_jkt: "x" },
    ];
    for (const body of bad) expect((await post(f, body)).status).toBe(400);
    expect(f.calls).toEqual([]);
  });

  it("the browser's convenience copies (authenticatorData, publicKey, publicKeyAlgorithm) are accepted and dropped: the wrapper is handed only what it reads", async () => {
    const f = makeFakes();
    const res = await post(f, enrolCredentialBody({ credential: registrationCredentialJson({}, { authenticatorData: "AAAA", publicKey: "AAAA", publicKeyAlgorithm: -7 }) }));
    expect(res.status).toBe(201);
    expect(Object.keys(f.rec.registrationVerify[0]!.response.response).sort()).toEqual(["attestationObject", "clientDataJSON", "transports"]);
  });

  it("an unexpected error rolls back and answers a constant 500; a disagreeing origin is a 503 before the wrapper runs", async () => {
    const boom = makeFakes({ throwIn: "registerFirst" });
    const res = await post(boom);
    expect(res.status).toBe(500);
    expect(await text(res)).not.toContain("secret database text");
    expect(boom.tx).toEqual([{ kind: "mint", committed: false }]);
    const drift = makeFakes({ rp: { rpId: "partners.example.test", origin: "https://other.example.test" } });
    expect((await post(drift)).status).toBe(503);
    expect(drift.calls).not.toContain("registration.verify");
  });
});
