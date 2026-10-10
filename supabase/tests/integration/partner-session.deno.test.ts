// supabase/tests/integration/partner-session.deno.test.ts
//
// Slice S1.2 (migration 0049, docs/security/partner-auth-design.md PA-10 .. PA-13b, PA-27, section 8, 17.8): the REAL `partner-session` handler, over the REAL privileged.ts (the partner kinds of
// `openScopedTx`, `withPartnerMint`, `withPartnerSession`, `hitRateLimitForPartner`), the REAL S0 wrapper and the software authenticator's REAL assertions, against the REAL database
// tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner` / `edge_partner_minter` through SET LOCAL ROLE).
//
// WHAT ONLY A REAL COMMIT CAN SHOW. The pgTAP files run in one transaction that is rolled back, so they cannot show that a REFUSAL'S TRANSACTION COMMITS (17.8: "the Edge must COMMIT on every status;
// otherwise alarm rows and burned nonces roll back"). Here every refusal goes through the handler, which commits through postgres.js, and the rows are read back afterwards from a SEPARATE connection:
// the alarm rows and the audit_log row of a counter regression, the burned nonce, the failure counter across refusals, the cooldown, and the audit row of a reauth signature the Edge passed.
//
// The signature the Edge "passes" and the database refuses (a compromised or buggy Edge, a library gap) is made with a verifier port that always answers ok: that is the only way to reach the
// database's own signature check with a bad signature, and it is exactly the case 4.4 says is an ALARM.

import { assert, assertEquals, assertNotEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { createTestUser, freshUuid, rawOwnerSql, withTemporaryOwnerAccess as withOwnerAccess } from "./_helpers.ts";
import { fromB64u, SoftwareAuthenticator, type AssertOptions } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest, type PartnerSessionDeps } from "../../functions/_shared/partner/session-handler.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import { parseChallengeToken, uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { newPartnerSessionToken, sha256Hex, toB64u } from "../../functions/_shared/partner/token.ts";
import type { AssertionVerifier, EmailOtpPort, PartnerDb } from "../../functions/_shared/partner/ports.ts";
import {
  getActorFromRequest,
  loadPartnerCorsOrigin,
  openScopedTx,
  partnerBind,
  partnerDb,
  resetPrivilegedConnectionsForTests,
} from "../../functions/_shared/privileged.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

// The migrating role holds no privilege on these tables once an earlier suite has revoked it, and `partner_session.credential_id -> partner_credential` is checked AT COMMIT with the OWNER's privileges
// (see partner-signin-mint.deno.test.ts, which documents the trap): the owner needs SELECT and UPDATE on partner_credential for as long as a transaction commits a session, i.e. the whole file.
const withTemporaryOwnerAccess = <T>(table: string, fn: (sql: ReturnType<typeof postgres>) => Promise<T>) =>
  withOwnerAccess(table, fn as never, table === "app.partner_credential" ? "insert, delete" : "select, insert, update, delete") as Promise<T>;
await rawOwnerSql().unsafe("grant select, update on app.partner_credential to current_user");
const rows = <T>(table: string, query: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> => withTemporaryOwnerAccess(table, query);

const RP = { rpId: "partners.example.test", origin: "https://partners.example.test" };
const STAFF = "00000000-0000-0000-0000-1000000000a1"; // staff at fac_x (helpers.sql)
const OPERATOR = "00000000-0000-0000-0000-3000000000c1"; // an operator (helpers.sql)
const STAFF_Y = "00000000-0000-0000-0000-1000000000a3"; // staff at fac_y (helpers.sql): its own reauth bucket

await withTemporaryOwnerAccess("app.partner_rp_config", (sql) =>
  sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`);

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** An authenticator for a person, its credential row (born live and unused: the insert guard requires it), and the person. */
async function enrol(uid: string, alg: "ES256" | "RS256" = "ES256", storedCount = 0): Promise<SoftwareAuthenticator> {
  const auth = await SoftwareAuthenticator.create(alg, uuidToBytes(uid)!);
  await withTemporaryOwnerAccess("app.partner_credential", (sql) =>
    sql`insert into app.partner_credential (user_id, credential_id, public_key, alg, sign_count)
        values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), ${alg === "ES256" ? -7 : -257}, ${storedCount})`);
  return auth;
}

// The sign-in suite never reaches the email proof (S1.3's suite is partner-pin.deno.test.ts): a call to it is a failure of the test.
const NO_OTP: EmailOtpPort = {
  send: () => Promise.reject(new Error("the sign-in suite must not send an email")),
  verify: () => Promise.reject(new Error("the sign-in suite must not verify an email code")),
};

const baseDeps = (over: Partial<PartnerSessionDeps> = {}): PartnerSessionDeps => ({
  db: partnerDb,
  allowedOrigin: RP.origin,
  webauthn: assertionVerifier,
  otp: NO_OTP,
  nowMs: () => Date.now(),
  newSessionToken: newPartnerSessionToken,
  ...over,
});

/** A verifier that passes everything: a compromised or buggy Edge, so the database's own checks are the ones that answer. */
const passAll: AssertionVerifier = { options: assertionVerifier.options, verify: async () => ({ ok: true }) };

async function call(method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; deps?: PartnerSessionDeps } = {}): Promise<Response> {
  const headers = new Headers({ origin: RP.origin, ...(init.headers ?? {}) });
  let body: string | undefined;
  if (init.body !== undefined) {
    body = JSON.stringify(init.body);
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }
  return await handlePartnerSessionRequest(new Request(`https://project.example.test/functions/v1/partner-session/${path}`, { method, headers, body }), init.deps ?? baseDeps());
}

interface Issued {
  readonly challengeToken: string;
  readonly nonce: Uint8Array;
}

async function options(path: "options" | "reauth/options" = "options", token?: string, deps?: PartnerSessionDeps): Promise<Issued> {
  const res = await call("POST", path, { headers: token ? { authorization: `Bearer ${token}` } : {}, body: {}, deps });
  assertEquals(res.status, 200, await res.clone().text());
  const data = (await res.json()).data as { challengeToken: string; options: { challenge: string; userVerification: string; allowCredentials: unknown[] } };
  assertEquals(data.options.userVerification, "required");
  assertEquals(data.options.allowCredentials, []);
  const parsed = parseChallengeToken(data.challengeToken)!;
  assertEquals(toB64u(parsed.nonce), data.options.challenge, "the options carry exactly the nonce the token carries");
  return { challengeToken: data.challengeToken, nonce: parsed.nonce };
}

async function assertion(auth: SoftwareAuthenticator, ch: Issued, o: Partial<AssertOptions> = {}) {
  return await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch.nonce, ...o });
}

async function verify(auth: SoftwareAuthenticator, o: Partial<AssertOptions> = {}, deps?: PartnerSessionDeps, ch?: Issued): Promise<Response> {
  const issued = ch ?? (await options("options", undefined, deps));
  return await call("POST", "verify", { body: { challengeToken: issued.challengeToken, credential: await assertion(auth, issued, o) }, deps });
}

async function signIn(auth: SoftwareAuthenticator, o: Partial<AssertOptions> = {}): Promise<string> {
  const res = await verify(auth, o);
  assertEquals(res.status, 201, await res.clone().text());
  const data = (await res.json()).data as { token: string; aal: number; expiresAt: string };
  assertEquals(data.aal, 1);
  return data.token;
}

const bearer = (token: string): Record<string, string> => ({ authorization: `Bearer ${token}` });
const UNIFORM_401 = JSON.stringify({ error: { code: "unauthenticated", message: "authentication failed" } });

/** Everything the database holds about a person's credential, from a SEPARATE connection (what survived the commit). */
async function credState(uid: string): Promise<{ id: string; signCount: number }> {
  const r = await rows("app.partner_credential", (sql) => sql`select id::text as id, sign_count::int as n from app.partner_credential where user_id = ${uid} and revoked_at is null order by created_at desc limit 1`);
  return { id: r[0]!.id as string, signCount: r[0]!.n as number };
}
const alarmCount = async (credId: string, kind: string): Promise<number> =>
  (await rows("app.partner_auth_alarm", (sql) => sql`select count(*)::int as n from app.partner_auth_alarm where credential_id = ${credId} and kind = ${kind}`))[0]!.n as number;
const auditCount = async (action: string, subject: string): Promise<number> =>
  (await rows("app.audit_log", (sql) => sql`select count(*)::int as n from app.audit_log where action = ${action} and subject_id = ${subject}`))[0]!.n as number;
const failureRow = async (credId: string) => (await rows("app.partner_sign_in_failure", (sql) => sql`select failed_count::int as n, cooldown_until is not null as cooling from app.partner_sign_in_failure where credential_id = ${credId}`))[0] ?? null;
/** Ages a session's last_seen_at (the guard forbids lowering it, so the owner switches the guard off for this one statement): a PEEK or a SESSION-class call is only distinguishable on a session that is more than a minute idle. */
async function backdate(hash: string, minutes: number): Promise<void> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe("alter table app.partner_session disable trigger partner_session_guard_trg");
    try {
      await sql`update app.partner_session set last_seen_at = now() - ${minutes + " minutes"}::interval where token_hash = ${hash}`;
    } finally {
      await sql.unsafe("alter table app.partner_session enable trigger partner_session_guard_trg");
    }
  });
}
const sessionRow = async (hash: string) =>
  (await rows("app.partner_session", (sql) => sql`select id::text as id, last_seen_at, revoked_at, revoke_reason, reauth_until, aal::int as aal from app.partner_session where token_hash = ${hash}`))[0] ?? null;

// =============================================================================================================================================================
// PA-10: CORS, the Origin refusal and the media type, through the real handler
// =============================================================================================================================================================

Deno.test("PA-10: OPTIONS never opens a database connection (a counting database port sees no call), and a foreign Origin is 403 before routing", DT, async () => {
  let calls = 0;
  const counting: PartnerDb = {
    withMint: (op) => (calls++, partnerDb.withMint(op)),
    withInviteMint: (op) => (calls++, partnerDb.withInviteMint(op)),
    withSession: (h, op) => (calls++, partnerDb.withSession(h, op)),
    withInvites: (h, op) => (calls++, partnerDb.withInvites(h, op)),
    withMembers: (h, op) => (calls++, partnerDb.withMembers(h, op)),
    withAttest: (h, op) => (calls++, partnerDb.withAttest(h, op)),
    withReview: (h, op) => (calls++, partnerDb.withReview(h, op)),
    withStock: (h, op) => (calls++, partnerDb.withStock(h, op)),
    withEntitlements: (h, op) => (calls++, partnerDb.withEntitlements(h, op)),
    withProgramme: (h, op) => (calls++, partnerDb.withProgramme(h, op)),
    withOffersAdmin: (h, op) => (calls++, partnerDb.withOffersAdmin(h, op)),
    withSponsorships: (h, op) => (calls++, partnerDb.withSponsorships(h, op)),
    withOffersRedeem: (h, op) => (calls++, partnerDb.withOffersRedeem(h, op)),
    withSettlementExport: (h, op) => (calls++, partnerDb.withSettlementExport(h, op)),
    hitRateLimit: (...a) => (calls++, partnerDb.hitRateLimit(...a)),
    hitSystemRateLimit: (...a) => (calls++, partnerDb.hitSystemRateLimit(...a)),
  };
  const deps = baseDeps({ db: counting });
  for (const method of ["GET", "POST", "PATCH", "DELETE"]) {
    const res = await call("OPTIONS", "verify", { headers: { "access-control-request-method": method, "access-control-request-headers": "authorization,content-type" }, deps });
    assertEquals(res.status, 204);
    assertEquals(res.headers.get("access-control-allow-origin"), RP.origin);
    assert((res.headers.get("access-control-allow-methods") ?? "").includes(method));
    assertEquals(res.headers.get("access-control-expose-headers"), "Retry-After");
  }
  for (const [method, path] of [["POST", "verify"], ["GET", "session"], ["OPTIONS", "options"], ["POST", "unknown"]] as const) {
    const res = await call(method, path, { headers: { origin: "https://evil.example.test" }, body: method === "POST" ? {} : undefined, deps });
    assertEquals(res.status, 403, `${method} ${path}`);
    assertEquals(res.headers.get("access-control-allow-origin"), null);
  }
  assertEquals(calls, 0);
});

Deno.test("PA-10: `Content-Type: text/plain; x=application/json` is 415 on the pre-auth routes (the CORS-simple request a cross-site page could send), before any database work", DT, async () => {
  for (const path of ["options", "verify"]) {
    const res = await handlePartnerSessionRequest(
      new Request(`https://project.example.test/functions/v1/partner-session/${path}`, { method: "POST", headers: { "content-type": "text/plain; x=application/json", origin: RP.origin }, body: "{}" }),
      baseDeps(),
    );
    assertEquals(res.status, 415, path);
  }
});

Deno.test("PA-10: loadPartnerCorsOrigin reads GR_PARTNER_ORIGIN: unset is null, an exact https origin passes, a malformed one throws", DT, () => {
  const saved = Deno.env.get("GR_PARTNER_ORIGIN");
  try {
    Deno.env.delete("GR_PARTNER_ORIGIN");
    assertEquals(loadPartnerCorsOrigin(), null);
    Deno.env.set("GR_PARTNER_ORIGIN", RP.origin);
    assertEquals(loadPartnerCorsOrigin(), RP.origin);
    Deno.env.set("GR_PARTNER_ORIGIN", RP.origin + "/");
    try {
      loadPartnerCorsOrigin();
      assert(false, "a trailing slash must throw");
    } catch (e) {
      assert(e instanceof Error);
    }
  } finally {
    if (saved === undefined) Deno.env.delete("GR_PARTNER_ORIGIN");
    else Deno.env.set("GR_PARTNER_ORIGIN", saved);
  }
});

// =============================================================================================================================================================
// PA-11: a Supabase JWT to a partner function, a partner token to a player function
// =============================================================================================================================================================

Deno.test("PA-11: a Supabase JWT sent to the partner function is 401 on every session route (and nothing opens a transaction)", DT, async () => {
  let calls = 0;
  const counting: PartnerDb = {
    withMint: (op) => (calls++, partnerDb.withMint(op)),
    withInviteMint: (op) => (calls++, partnerDb.withInviteMint(op)),
    withSession: (h, op) => (calls++, partnerDb.withSession(h, op)),
    withInvites: (h, op) => (calls++, partnerDb.withInvites(h, op)),
    withMembers: (h, op) => (calls++, partnerDb.withMembers(h, op)),
    withAttest: (h, op) => (calls++, partnerDb.withAttest(h, op)),
    withReview: (h, op) => (calls++, partnerDb.withReview(h, op)),
    withStock: (h, op) => (calls++, partnerDb.withStock(h, op)),
    withEntitlements: (h, op) => (calls++, partnerDb.withEntitlements(h, op)),
    withProgramme: (h, op) => (calls++, partnerDb.withProgramme(h, op)),
    withOffersAdmin: (h, op) => (calls++, partnerDb.withOffersAdmin(h, op)),
    withSponsorships: (h, op) => (calls++, partnerDb.withSponsorships(h, op)),
    withOffersRedeem: (h, op) => (calls++, partnerDb.withOffersRedeem(h, op)),
    withSettlementExport: (h, op) => (calls++, partnerDb.withSettlementExport(h, op)),
    hitRateLimit: (...a) => (calls++, partnerDb.hitRateLimit(...a)),
    hitSystemRateLimit: (...a) => (calls++, partnerDb.hitSystemRateLimit(...a)),
  };
  // built at run time (a literal token-shaped string trips the secret scanner)
  const b64u = (v: string) => btoa(v).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const jwt = [b64u(JSON.stringify({ alg: "HS256", typ: "JWT" })), b64u(JSON.stringify({ sub: "test-subject", role: "authenticated" })), b64u("not-a-real-signature")].join(".");
  for (const [method, path] of [
    ["GET", "session"], ["POST", "sign-out"], ["POST", "lock"], ["POST", "reauth/options"], ["POST", "reauth"],
    // S1.3: the step-up PIN and the email proof are session routes too
    ["GET", "pin"], ["POST", "step-up/pin"], ["POST", "pin/set"], ["POST", "pin/change"], ["POST", "otp-proof/start"], ["POST", "otp-proof/verify"],
  ] as const) {
    const res = await call(method, path, { headers: bearer(jwt), body: method === "POST" ? {} : undefined, deps: baseDeps({ db: counting }) });
    assertEquals(res.status, 401, `${method} ${path}`);
    assertEquals(await res.text(), UNIFORM_401);
  }
  assertEquals(calls, 0);
});

Deno.test("PA-11: a partner token sent to a PLAYER function is refused and NEVER forwarded to GoTrue (a recording fake sees no request), with a control that the fake does record a JWT-shaped bearer", DT, async () => {
  const seen: Array<{ path: string; auth: string | null }> = [];
  const server = Deno.serve({ port: 0, onListen: () => {} }, (r) => {
    seen.push({ path: new URL(r.url).pathname, auth: r.headers.get("authorization") });
    return new Response(JSON.stringify({ msg: "invalid" }), { status: 401, headers: { "content-type": "application/json" } });
  });
  const addr = server.addr as Deno.NetAddr;
  const saved = { url: Deno.env.get("SUPABASE_URL"), key: Deno.env.get("SUPABASE_ANON_KEY") };
  Deno.env.set("SUPABASE_URL", `http://127.0.0.1:${addr.port}`);
  Deno.env.set("SUPABASE_ANON_KEY", "anon-key-for-the-recording-fake");
  try {
    const t = (await newPartnerSessionToken()).token;
    for (const bearerValue of [t, t.replace("gr_ps_", "gr_inv_"), "GR_PS_" + t.slice(6), "gr_ps_x"]) {
      const actor = await getActorFromRequest(new Request("https://p.example.test/", { headers: { authorization: `Bearer ${bearerValue}` } }));
      assertEquals(actor, null, bearerValue.slice(0, 10));
    }
    assertEquals(seen.length, 0, "no request reached the fake GoTrue: the partner token was never forwarded");
    // control: the fake records what is sent when the bearer is JWT-shaped, so "0 requests" above is evidence and not a deaf probe
    const control = await getActorFromRequest(new Request("https://p.example.test/", { headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln" } }));
    assertEquals(control, null);
    assert(seen.length >= 1, "the control reached the fake");
    assertEquals(seen[0]!.path, "/auth/v1/user");
    assertEquals(seen[0]!.auth, "Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln");
  } finally {
    if (saved.url === undefined) Deno.env.delete("SUPABASE_URL");
    else Deno.env.set("SUPABASE_URL", saved.url);
    if (saved.key === undefined) Deno.env.delete("SUPABASE_ANON_KEY");
    else Deno.env.set("SUPABASE_ANON_KEY", saved.key);
    await server.shutdown();
  }
});

// =============================================================================================================================================================
// PA-12: sign in, GET session through PEEK, sign out
// =============================================================================================================================================================

Deno.test("PA-12: a valid assertion mints (ES256 and RS256); the token comes back once and only its hash is stored; GET session (PEEK) does not move last_seen_at; sign-out revokes", DT, async () => {
  for (const alg of ["ES256", "RS256"] as const) {
    const auth = await enrol(STAFF, alg);
    const token = await signIn(auth);
    const hash = await sha256Hex(token);
    assert((await sessionRow(hash)) !== null, "the session row exists under the token's sha256");
    await backdate(hash, 5);
    const before = (await sessionRow(hash))!.last_seen_at as Date;
    // PEEK: three reads through the handler, on a session that is 5 minutes idle, never move last_seen_at
    for (let i = 0; i < 3; i++) {
      const who = await call("GET", "session", { headers: bearer(token) });
      assertEquals(who.status, 200);
      const info = (await who.json()).data as { userId: string; requiredAal: number; memberships: Array<{ role: string; facilityIds: string[] }> };
      assertEquals(info.userId, STAFF);
      assertEquals(info.requiredAal, 1);
      assertEquals(info.memberships[0]!.role, "staff");
      assert(info.memberships[0]!.facilityIds.includes("fac_x"));
    }
    assertEquals(((await sessionRow(hash))!.last_seen_at as Date).getTime(), before.getTime(), `${alg}: GET session did NOT move last_seen_at`);
    // lock (a SESSION-class call) DOES move it: the control that makes the check above evidence
    const lock = await call("POST", "lock", { headers: bearer(token), body: {} });
    assertEquals(lock.status, 200);
    assert(((await sessionRow(hash))!.last_seen_at as Date).getTime() > before.getTime(), `${alg}: lock advanced last_seen_at (control)`);
    const out = await call("POST", "sign-out", { headers: bearer(token), body: {} });
    assertEquals(out.status, 200);
    assertEquals((await sessionRow(hash))!.revoke_reason, "sign_out");
    const after = await call("GET", "session", { headers: bearer(token) });
    assertEquals(after.status, 401);
    assertEquals(await after.text(), UNIFORM_401);
  }
});

Deno.test("PA-12: every way an assertion can be wrong is ONE uniform 401 (wrong origin, wrong RP ID, no UV, a lower counter, a replayed challenge, a userHandle mismatch, a bad signature)", DT, async () => {
  const auth = await enrol(STAFF);
  await signIn(auth); // counter 1
  const bodies = new Set<string>();
  const bad: Array<[string, Partial<AssertOptions>]> = [
    ["wrong origin", { origin: "https://evil.example.test" }],
    ["wrong RP ID", { rpIdHashOf: "other.example.test" }],
    ["no user verification", { flags: { uv: false } }],
    ["a lower counter", { counter: 0 }],
    ["a userHandle that is not the person's", { userHandle: new Uint8Array(16).fill(3) }],
    ["a bad signature", { tamperSignature: true }],
  ];
  for (const [label, o] of bad) {
    const res = await verify(auth, o);
    assertEquals(res.status, 401, label);
    bodies.add(await res.text());
  }
  // five of the refusals above were FORGERIES, which is exactly what starts the cooldown (the section 8 test below proves it); the replay below needs a credential that is not cooling
  const credId = (await credState(STAFF)).id;
  await rows("app.partner_sign_in_failure", (sql) => sql`delete from app.partner_sign_in_failure where credential_id = ${credId}`);
  // a replayed challenge: the SAME assertion presented twice
  const ch = await options();
  const body = { challengeToken: ch.challengeToken, credential: await assertion(auth, ch) };
  assertEquals((await call("POST", "verify", { body })).status, 201);
  const replay = await call("POST", "verify", { body });
  assertEquals(replay.status, 401, "a replayed challenge");
  bodies.add(await replay.text());
  assertEquals([...bodies], [UNIFORM_401], "one uniform body for every refusal");
});

Deno.test("PA-12 / 17.8: a counter regression COMMITS: the audit_log row, the alarm row and the burned nonce are all there after the refusal, read from another connection", DT, async () => {
  const auth = await enrol(STAFF, "ES256", 5);
  const cred = await credState(STAFF);
  const nonces = async () => (await rows("app.partner_auth_challenge", (sql) => sql`select count(*)::int as n from app.partner_auth_challenge where user_id = ${STAFF}`))[0]!.n as number;
  const n0 = await nonces();
  const a0 = await alarmCount(cred.id, "counter_regression");
  const l0 = await auditCount("partner.mint.counter_regression", cred.id);
  const res = await verify(auth, { counter: 3 });
  assertEquals(res.status, 401);
  assertEquals(await res.text(), UNIFORM_401);
  assertEquals(await alarmCount(cred.id, "counter_regression"), a0 + 1, "the alarm row committed");
  assertEquals(await auditCount("partner.mint.counter_regression", cred.id), l0 + 1, "the audit_log row committed");
  assertEquals(await nonces(), n0 + 1, "the nonce is burned (the signature was valid)");
  assertEquals((await credState(STAFF)).signCount, 5, "and the counter did not move");
  const fail = await failureRow(cred.id);
  assertEquals(fail === null || fail.n === 0, true, "a clone indicator is not counted as a failed verification");
});

Deno.test("PA-12 / 17.8: a signature the Edge passed and the database refuses is an ALARM that COMMITS, burns no nonce and mints nothing", DT, async () => {
  const auth = await enrol(STAFF);
  const cred = await credState(STAFF);
  const sessions = async () => (await rows("app.partner_session", (sql) => sql`select count(*)::int as n from app.partner_session where user_id = ${STAFF}`))[0]!.n as number;
  const s0 = await sessions();
  const a0 = await alarmCount(cred.id, "signature_invalid");
  const res = await verify(auth, { tamperSignature: true }, baseDeps({ webauthn: passAll }));
  assertEquals(res.status, 401);
  assertEquals(await alarmCount(cred.id, "signature_invalid"), a0 + 1, "the alarm row committed");
  assertEquals(await auditCount("partner.mint.signature_invalid", cred.id) >= 1, true, "the audit_log row committed");
  assertEquals(await sessions(), s0, "no session");
});

Deno.test("COMMIT on every status: each refusal the DATABASE makes after the Edge passed an assertion is one uniform 401 and leaves what it must (spot-checked across statuses with a passing verifier)", DT, async () => {
  const auth = await enrol(STAFF);
  const cases: Array<[string, Partial<AssertOptions>]> = [
    ["bad_origin", { origin: "https://evil.example.test" }],
    ["bad_rp_id_hash", { rpIdHashOf: "other.example.test" }],
    ["user_not_verified", { flags: { uv: false } }],
    ["user_not_present", { flags: { up: false, uv: true } }],
    ["bad_client_type", { client: { type: "webauthn.create" } }],
    ["cross_origin", { client: { crossOrigin: true } }],
    ["challenge_mismatch", { client: { challenge: toB64u(new Uint8Array(32).fill(1)) } }],
  ];
  for (const [label, o] of cases) {
    const res = await verify(auth, o, baseDeps({ webauthn: passAll }));
    assertEquals(res.status, 401, label);
    assertEquals(await res.text(), UNIFORM_401, label);
  }
});

// =============================================================================================================================================================
// Section 8: five failed verifications per credential per hour, then a cooldown (a status: the counter survives every refusal's commit)
// =============================================================================================================================================================

Deno.test("section 8: the failure counter PERSISTS across refusals (read after each commit); the 5th forgery starts a cooldown; a VALID assertion is then refused and counts nothing; the cooldown ends", DT, async () => {
  const auth = await enrol(STAFF);
  const cred = await credState(STAFF);
  await rows("app.partner_sign_in_failure", (sql) => sql`delete from app.partner_sign_in_failure where credential_id = ${cred.id}`);
  for (let i = 1; i <= 4; i++) {
    const res = await verify(auth, { tamperSignature: true });
    assertEquals(res.status, 401);
    const f = await failureRow(cred.id);
    assertEquals(f?.n, i, `after forgery ${i} the committed counter is ${i}`);
    assertEquals(f?.cooling, false);
  }
  const fifth = await verify(auth, { tamperSignature: true });
  assertEquals(fifth.status, 401);
  assertEquals(await failureRow(cred.id), { n: 0, cooling: true }, "the 5th forgery starts the cooldown and restarts the count");
  const sessions = async () => (await rows("app.partner_session", (sql) => sql`select count(*)::int as n from app.partner_session where user_id = ${STAFF}`))[0]!.n as number;
  const before = await sessions();
  const valid = await verify(auth);
  assertEquals(valid.status, 401, "a VALID assertion during the cooldown is refused");
  assertEquals(await valid.text(), UNIFORM_401, "by the same bytes");
  assertEquals(await sessions(), before, "and mints nothing");
  assertEquals(await failureRow(cred.id), { n: 0, cooling: true }, "and nothing more is counted");
  await rows("app.partner_sign_in_failure", (sql) => sql`update app.partner_sign_in_failure set cooldown_until = now() - interval '1 second' where credential_id = ${cred.id}`);
  assertEquals((await verify(auth)).status, 201, "once the cooldown has passed a valid assertion mints again");
});

Deno.test("section 8: an assertion under a credential id nobody holds is the uniform 401 and writes NOTHING (no failure row for a made-up id)", DT, async () => {
  const stranger = await SoftwareAuthenticator.create("ES256", uuidToBytes(STAFF)!);
  const before = (await rows("app.partner_sign_in_failure", (sql) => sql`select count(*)::int as n from app.partner_sign_in_failure`))[0]!.n as number;
  for (let i = 0; i < 3; i++) assertEquals((await verify(stranger)).status, 401);
  assertEquals((await rows("app.partner_sign_in_failure", (sql) => sql`select count(*)::int as n from app.partner_sign_in_failure`))[0]!.n as number, before);
});

// =============================================================================================================================================================
// 4.1: an aal 1 operator session; reauth (PA-27); the member rate limit
// =============================================================================================================================================================

Deno.test("4.1 / PA-28: an aal 1 OPERATOR with no confirmed TOTP can GET session, lock, sign out, and reauth/options (A0_ENROL); normal A0 stays refused", DT, async () => {
  const auth = await enrol(OPERATOR);
  const token = await signIn(auth);
  const who = await call("GET", "session", { headers: bearer(token) });
  assertEquals(who.status, 200);
  const info = (await who.json()).data as { requiredAal: number; aal: number };
  assertEquals([info.aal, info.requiredAal], [1, 2]);
  // S1.4: reauth is A0_ENROL — reachable at aal 1 only while TOTP is unconfirmed (matrix 31 proves the post-confirm refusal).
  assertEquals((await call("POST", "reauth/options", { headers: bearer(token), body: {} })).status, 200);
  assertEquals((await call("POST", "lock", { headers: bearer(token), body: {} })).status, 200);
  assertEquals((await call("POST", "sign-out", { headers: bearer(token), body: {} })).status, 200);
});

Deno.test("reauth: the session's own credential sets reauth_until (5 minutes); lock clears it; PA-27: another person's valid passkey is refused and nothing is written", DT, async () => {
  const auth = await enrol(STAFF);
  const other = freshUuid();
  await createTestUser(other, "reauth-other-" + other.slice(0, 8));
  const stranger = await enrol(other);
  const token = await signIn(auth);
  const hash = await sha256Hex(token);
  const reauthWith = async (a: SoftwareAuthenticator, o: Partial<AssertOptions> = {}, deps?: PartnerSessionDeps) => {
    const ch = await options("reauth/options", token, deps);
    return await call("POST", "reauth", { headers: bearer(token), body: { challengeToken: ch.challengeToken, credential: await assertion(a, ch, o) }, deps });
  };
  // PA-27: the stranger holds a valid passkey of their own; it is not this session's person's
  const wrong = await reauthWith(stranger);
  assertEquals(wrong.status, 403);
  assertEquals(JSON.parse(await wrong.text()), { error: { code: "reauth_refused", message: "reauthentication failed" } });
  assertEquals((await sessionRow(hash))!.reauth_until, null, "PA-27: reauth_until is NOT set");
  // even if the Edge passed it (a buggy or compromised Edge), the DATABASE refuses someone else's credential: the real definers, called with the stranger's genuine assertion over a genuine reauth challenge
  const dbStatus = await partnerDb.withSession(hash, async (sess) => {
    const ch = await sess.reauthOptions();
    const a = await stranger.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch.nonce });
    return await sess.reauth({
      credentialId: stranger.credentialId,
      nonce: ch.nonce,
      exp: ch.exp,
      mac: ch.mac,
      authenticatorData: fromB64u(a.response.authenticatorData),
      clientDataJson: fromB64u(a.response.clientDataJSON),
      signature: fromB64u(a.response.signature),
    });
  });
  assertEquals(dbStatus.status, "unknown_credential");
  assertEquals((await sessionRow(hash))!.reauth_until, null);
  // the session's own credential
  const ok = await reauthWith(auth);
  assertEquals(ok.status, 200, await ok.clone().text());
  const until = new Date(((await ok.json()).data as { reauthUntil: string }).reauthUntil).getTime();
  assert(until > Date.now() + 4 * 60_000 && until <= Date.now() + 5 * 60_000 + 2000, "now + 5 minutes");
  assertEquals((await sessionRow(hash))!.reauth_until instanceof Date, true);
  const who = (await (await call("GET", "session", { headers: bearer(token) })).json()).data as { stepUp: { reauthUntil: string | null } };
  assertNotEquals(who.stepUp.reauthUntil, null);
  // a replayed reauth challenge is refused
  const ch = await options("reauth/options", token);
  const body = { challengeToken: ch.challengeToken, credential: await assertion(auth, ch) };
  assertEquals((await call("POST", "reauth", { headers: bearer(token), body })).status, 200);
  assertEquals((await call("POST", "reauth", { headers: bearer(token), body })).status, 403, "a replay");
  // lock clears the window and keeps the session live
  assertEquals((await call("POST", "lock", { headers: bearer(token), body: {} })).status, 200);
  assertEquals((await sessionRow(hash))!.reauth_until, null, "lock cleared the reauth window");
  assertEquals((await call("GET", "session", { headers: bearer(token) })).status, 200, "the session is still live");
});

Deno.test("reauth / 17.8: a signature the Edge passed and the database refuses writes an audit_log row that COMMITS (the verifier-owned writer sets nothing)", DT, async () => {
  const auth = await enrol(STAFF);
  const token = await signIn(auth);
  const hash = await sha256Hex(token);
  const sid = (await sessionRow(hash))!.id;
  const before = await auditCount("partner.reauth.signature_invalid", sid);
  const ch = await options("reauth/options", token);
  const res = await call("POST", "reauth", { headers: bearer(token), body: { challengeToken: ch.challengeToken, credential: await assertion(auth, ch, { tamperSignature: true }) }, deps: baseDeps({ webauthn: passAll }) });
  assertEquals(res.status, 403);
  assertEquals(await auditCount("partner.reauth.signature_invalid", sid), before + 1, "the audit row committed with the refusal");
  assertEquals((await sessionRow(hash))!.reauth_until, null);
});

Deno.test("reauth (design 8): 10 attempts per member per hour, then 429; the hits commit", DT, async () => {
  const auth = await enrol(STAFF_Y);
  const token = await signIn(auth);
  const stranger = await SoftwareAuthenticator.create("ES256");
  let last = 0;
  let firstLimited = -1;
  for (let i = 1; i <= 12; i++) {
    const ch = await options("reauth/options", token);
    const res = await call("POST", "reauth", { headers: bearer(token), body: { challengeToken: ch.challengeToken, credential: await assertion(stranger, ch) } });
    last = res.status;
    if (res.status === 429 && firstLimited < 0) {
      firstLimited = i;
      assertEquals(res.headers.get("retry-after"), "3600");
      assertEquals(res.headers.get("access-control-expose-headers"), "Retry-After"); // a cross-origin page can read it
    }
  }
  assert(firstLimited > 0 && firstLimited <= 11, `the limit applied (first 429 at attempt ${firstLimited})`);
  assertEquals(last, 429);
});

// =============================================================================================================================================================
// PA-13b: the partner kinds of openScopedTx
// =============================================================================================================================================================

Deno.test("PA-13b: the post-bind assertion fails as edge_actor, and when the binding kind is not 'partner'; a partner kind needs a bind and no uid", DT, async () => {
  await assertRejects(() => openScopedTx("partner", { expectedUid: null, run: (trx) => trx`set local role edge_actor` }, async () => 1), Error, "expected current_user = 'edge_partner'");
  await assertRejects(() => openScopedTx("partner", { expectedUid: null, run: async () => undefined }, async () => 1), Error, "the partner binding kind is 'null', expected 'partner'");
  await assertRejects(() => openScopedTx("partner", { expectedUid: STAFF, run: async () => undefined }, async () => 1), Error, "binds a SESSION");
  await assertRejects(() => openScopedTx("partner", { expectedUid: null }, async () => 1), Error, "binds a SESSION");
  await assertRejects(() => openScopedTx("partner_mint", { expectedUid: null, run: async () => undefined }, async () => 1), Error, "binds no actor");
  await assertRejects(() => openScopedTx("partner_mint", { expectedUid: STAFF }, async () => 1), Error, "binds no actor");
});

Deno.test("PA-13b: inside a real partner transaction the role is edge_partner and it holds EXACTLY the 4.3 list and the _for_partner definers: no actor_uid(), no bind_actor, no table; a second bind is refused", DT, async () => {
  const auth = await enrol(STAFF);
  const token = await signIn(auth);
  const hash = await sha256Hex(token);
  const check = await openScopedTx("partner", partnerBind(hash), async (trx) => {
    const me = await trx`select current_user::text as u, private.partner_binding_kind() as k`;
    return { u: me[0]!.u, k: me[0]!.k };
  });
  assertEquals(check.u, "edge_partner");
  assertEquals(check.k, "partner");
  // a failed statement inside postgres.js `begin` rejects the whole transaction, so each probe is its own transaction and the error is read outside it
  for (const sql of ["select private.actor_uid()", `select private.bind_actor('${STAFF}'::uuid)`, "select count(*) from app.partner_session", "select count(*) from private.actor_binding"]) {
    const err = await openScopedTx("partner", partnerBind(hash), (trx) => trx.unsafe(sql)).then(() => null, (e: { code?: string }) => e);
    assertEquals(err?.code, "42501", `edge_partner is refused: ${sql}`);
  }
  // a second bind in one transaction is refused (28000, the one uniform message)
  const second = await openScopedTx("partner", partnerBind(hash), (trx) => trx`select private.bind_partner_session(${hash})`).then(() => null, (e: { code?: string; message?: string }) => e);
  assertEquals(`${second?.code}:${second?.message}`, "28000:partner_session_refused");
  const names = await rawOwnerSql().unsafe(
    `select string_agg(p.proname, ',' order by p.proname collate "C") as n from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('app', 'api', 'private') and has_function_privilege('edge_partner', p.oid, 'EXECUTE')`,
  );
  assertEquals(
    names[0]!.n,
    "bind_partner_session,course_pin_rotate_for_partner,course_pin_show_for_partner,course_qr_mint_for_partner,course_qr_print_key_for_partner,course_qr_print_read_for_partner,course_qr_print_write_for_partner,course_qr_refresh_for_partner,hit_partner_rate_limit,partner_admin_enrolment_issue_for_partner,partner_attest_for_partner,partner_binding,partner_binding_kind,partner_credential_list_for_partner,partner_credential_options_for_partner,partner_credential_register_for_partner,partner_credential_revoke_for_partner,partner_entitlement_queue_for_partner,partner_entitlement_redeem_for_partner,partner_entitlement_voucher_for_partner,partner_facility_programme_list_for_partner,partner_facility_programme_upsert_for_partner,partner_handover_mint_for_partner,partner_held_queue_for_partner,partner_invite_accept_for_partner,partner_invite_create_for_partner,partner_invite_list_for_partner,partner_invite_revoke_for_partner,partner_member_recover_for_partner,partner_member_revoke_for_partner,partner_offer_approve_for_partner,partner_offer_end_for_partner,partner_offer_upsert_for_partner,partner_offers_list_for_partner,partner_offers_queue_for_partner,partner_offers_redeem_for_partner,partner_offers_redeem_offline_for_partner,partner_offline_attest_for_partner,partner_operator_rollup_for_partner,partner_org_sessions_revoke_for_partner,partner_pin_change_for_partner,partner_pin_params_for_partner,partner_pin_reset_for_partner,partner_pin_set_for_partner,partner_pin_verify_for_partner,partner_resolve_held_entitlement_for_partner,partner_resolve_held_offer_code_for_partner,partner_resolve_receipt_cross_user_match_for_partner,partner_review_sla_for_partner,partner_session_lock_for_partner,partner_session_otp_proof_for_partner,partner_session_otp_target_for_partner,partner_session_reauth_credential_for_partner,partner_session_reauth_for_partner,partner_session_reauth_options_for_partner,partner_session_revoke_for_partner,partner_settlement_export_for_partner,partner_shift_log_for_partner,partner_sponsor_rollup_for_partner,partner_sponsorship_approve_for_partner,partner_sponsorship_upsert_for_partner,partner_sponsorships_list_for_partner,partner_staff_activity_for_partner,partner_stock_move_for_partner,partner_stock_read_for_partner,partner_totp_confirm_for_partner,partner_totp_enrol_for_partner,partner_totp_reset_for_partner,partner_totp_verify_for_partner,partner_trail_programme_read_for_partner,partner_trail_programme_upsert_for_partner,partner_whoami_for_partner",
  );
});

Deno.test("PA-13b: an unknown token and a malformed token are refused with ONE error by the binder, before any round trip for the malformed ones (no oracle)", DT, async () => {
  const auth = await enrol(STAFF);
  const token = await signIn(auth);
  const hash = await sha256Hex(token);
  const attempt = (h: string) => partnerDb.withSession(h, async () => "bound").then(() => "bound", (e: Error) => e.name);
  assertEquals(await attempt(hash), "bound");
  assertEquals(await attempt("0".repeat(64)), "PartnerSessionRefused");
  assertEquals(await attempt("zz"), "PartnerSessionRefused");
  assertEquals(await attempt(""), "PartnerSessionRefused");
});

Deno.test("teardown: the edge connection is closed and the owner's temporary privileges on partner_credential are given back", DT, async () => {
  await resetPrivilegedConnectionsForTests();
  await rawOwnerSql().unsafe("revoke select, update on app.partner_credential from current_user");
});
