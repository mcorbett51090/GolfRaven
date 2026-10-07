// supabase/tests/integration/partner-pin.deno.test.ts
//
// Slice S1.3 (migration 0052, docs/security/partner-auth-design.md 6.3, PA-18, PA-19, PA-21): the REAL `partner-session` handler with its step-up PIN and email-proof routes, over the REAL privileged.ts
// (`withPartnerSession`, `hitRateLimitForPartner`), the REAL contract module (PBKDF2 in this process, as the browser will), REAL sessions minted by the REAL mint from the software authenticator's REAL
// assertions, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY A REAL COMMIT CAN SHOW. The pgTAP file (28_partner_pin_step_up.sql) runs inside one rolled-back transaction, so it cannot show the claim 17.8 and the 0020 lesson are about: that a REFUSAL'S
// TRANSACTION COMMITS. Here every wrong PIN goes through the handler, which commits through postgres.js, and the counters, the lock and the audit rows are read back afterwards from a SEPARATE connection.
// It also shows the ORDER of the email proof for real: the GoTrue session verifyOtp created is closed only AFTER the proof is visible to another connection.
//
// The email OTP (GoTrue) is a recording fake that creates a REAL `auth.sessions` row for the proven person, as verifyOtp does, and deletes it when the handler closes it; the database checks that row.

import { assert, assertEquals, assertNotEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, freshUuid, rawOwnerSql, withTemporaryOwnerAccess as withOwnerAccess } from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest, type PartnerSessionDeps } from "../../functions/_shared/partner/session-handler.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import { parseChallengeToken, uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { newPartnerSessionToken, sha256Hex, toB64u, toHex } from "../../functions/_shared/partner/token.ts";
import { derivePinKey, derivePinKeyB64u, MIN_ITERATIONS, newPinSalt } from "../../functions/_shared/partner/pin-contract.ts";
import type { EmailOtpPort } from "../../functions/_shared/partner/ports.ts";
import { partnerDb, resetPrivilegedConnectionsForTests } from "../../functions/_shared/privileged.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

// partner_session.credential_id -> partner_credential is checked AT COMMIT with the OWNER's privileges (see partner-signin-mint.deno.test.ts): the owner needs SELECT and UPDATE on partner_credential
// for as long as a transaction commits a session, i.e. the whole file.
// The same trap for the new members' orgs: partner_scope and partner_member reference partner_org through a DEFERRED foreign key, whose commit-time check runs with the owner's privileges (a `permission denied
// for table partner_org` that the driver does not even report on the statement): the owner holds SELECT and UPDATE on partner_org for the whole file, and the per-statement access below never revokes them.
const HELD = new Set(["app.partner_credential", "app.partner_org"]);
const withTemporaryOwnerAccess = <T>(table: string, fn: (sql: ReturnType<typeof postgres>) => Promise<T>) =>
  withOwnerAccess(table, fn as never, HELD.has(table) ? "insert, delete" : "select, insert, update, delete") as Promise<T>;
await rawOwnerSql().unsafe("grant select, update on app.partner_credential, app.partner_org to current_user");
const rows = <T>(table: string, query: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> => withTemporaryOwnerAccess(table, query);

const RP = { rpId: "partners.example.test", origin: "https://partners.example.test" };
const CODE = "123456";
const ITER = MIN_ITERATIONS; // the floor: real PBKDF2, 210,000 rounds

await withTemporaryOwnerAccess("app.partner_rp_config", (sql) =>
  sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`);

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
// the email OTP: GoTrue's verifyOtp creates a session for the proven person; the handler closes it after the proof. A recording fake that does exactly that, against the real auth.sessions table.
// -------------------------------------------------------------------------------------------------------------------------------------------------------------
interface FakeOtp {
  readonly port: EmailOtpPort;
  readonly events: string[];
  readonly sent: string[];
  readonly closed: string[];
  /** for each close: was the proof ALREADY visible to a second connection when the GoTrue session was closed? */
  readonly proofVisibleAtClose: boolean[];
  /** make the next verify return this GoTrue session id instead of a new one (a reused session) */
  reuse: string | null;
  /** age (seconds) of the GoTrue session the next verify creates (a stale session) */
  ageSeconds: number;
  lastSessionId: string | null;
}
function makeOtp(tokenHashOf: () => string): FakeOtp {
  const o: FakeOtp = {
    port: undefined as unknown as EmailOtpPort,
    events: [],
    sent: [],
    closed: [],
    proofVisibleAtClose: [],
    reuse: null,
    ageSeconds: 0,
    lastSessionId: null,
  };
  const port: EmailOtpPort = {
    async send(email) {
      o.events.push("send");
      o.sent.push(email);
    },
    async verify(email, code) {
      o.events.push("verify");
      if (code !== CODE) return { ok: false as const };
      const sql = adminSql();
      const u = await sql`select id::text as id from auth.users where lower(email) = ${email}`;
      const uid = u[0]!.id as string;
      const sid = o.reuse ?? freshUuid();
      await sql`insert into auth.sessions (id, user_id, created_at) values (${sid}, ${uid}, clock_timestamp() - ${o.ageSeconds + " seconds"}::interval) on conflict (id) do nothing`;
      o.lastSessionId = sid;
      return {
        ok: true as const,
        userId: uid,
        sessionId: sid,
        async closeSession() {
          o.events.push("close");
          const proof = await rows("app.partner_session", (q) => q`select (otp_proof_until is not null) as p from app.partner_session where token_hash = ${tokenHashOf()}`);
          o.proofVisibleAtClose.push(proof[0]?.p === true);
          o.closed.push(sid);
          await sql`delete from auth.sessions where id = ${sid}`;
        },
      };
    },
  };
  return Object.assign(o, { port });
}

const NO_OTP: EmailOtpPort = {
  send: () => Promise.reject(new Error("unexpected email send")),
  verify: () => Promise.reject(new Error("unexpected email verify")),
};

const deps = (otp: EmailOtpPort = NO_OTP, over: Partial<PartnerSessionDeps> = {}): PartnerSessionDeps => ({
  db: partnerDb,
  allowedOrigin: RP.origin,
  webauthn: assertionVerifier,
  otp,
  nowMs: () => Date.now(),
  newSessionToken: newPartnerSessionToken,
  ...over,
});

async function call(method: string, path: string, init: { token?: string; body?: unknown; deps?: PartnerSessionDeps } = {}): Promise<Response> {
  const headers = new Headers({ origin: RP.origin });
  if (init.token) headers.set("authorization", `Bearer ${init.token}`);
  let body: string | undefined;
  if (init.body !== undefined) {
    body = JSON.stringify(init.body);
    headers.set("content-type", "application/json");
  }
  return await handlePartnerSessionRequest(new Request(`https://project.example.test/functions/v1/partner-session/${path}`, { method, headers, body }), init.deps ?? deps());
}
const data = async <T>(res: Response): Promise<T> => (await res.json()).data as T;
const errCode = async (res: Response): Promise<string> => (await res.json()).error?.code as string;

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
// people: a new staff member at fac_x (own org), a credential, a session minted by the real mint
// -------------------------------------------------------------------------------------------------------------------------------------------------------------
interface Member {
  readonly uid: string;
  readonly email: string;
  token: string;
  hash: string;
}

async function enrol(uid: string): Promise<SoftwareAuthenticator> {
  const auth = await SoftwareAuthenticator.create("ES256", uuidToBytes(uid)!);
  await withTemporaryOwnerAccess("app.partner_credential", (sql) =>
    sql`insert into app.partner_credential (user_id, credential_id, public_key, alg, sign_count) values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), -7, 0)`);
  return auth;
}

async function signInWith(auth: SoftwareAuthenticator): Promise<string> {
  const o = await call("POST", "options", { body: {} });
  const d = await data<{ challengeToken: string }>(o);
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: parsed.nonce });
  const res = await call("POST", "verify", { body: { challengeToken: d.challengeToken, credential: cred } });
  assertEquals(res.status, 201, await res.clone().text());
  return (await data<{ token: string }>(res)).token;
}

let seq = 0;
async function newMember(label: string): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  const tag = `${label}${seq}`;
  await createTestUser(uid, `pin-${tag}`);
  const org = freshUuid();
  await withTemporaryOwnerAccess("app.partner_org", (sql) => sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"pin org " + tag})`);
  await withTemporaryOwnerAccess("app.partner_scope", (sql) => sql`insert into app.partner_scope (org_id, facility_id) values (${org}, 'fac_x')`);
  await withTemporaryOwnerAccess("app.partner_member", (sql) => sql`insert into app.partner_member (user_id, org_id, role) values (${uid}, ${org}, 'staff')`);
  const auth = await enrol(uid);
  const token = await signInWith(auth);
  return { uid, email: `pin-${tag}@integration.test`, token, hash: await sha256Hex(token) };
}
async function extraSession(m: Member): Promise<{ token: string; hash: string }> {
  const token = await signInWith(await enrol(m.uid));
  return { token, hash: await sha256Hex(token) };
}

const pinRow = async (uid: string) =>
  (await rows("app.partner_pin", (sql) => sql`select encode(verifier, 'hex') as verifier, encode(salt, 'hex') as salt, iterations::int as iterations, failed_count::int as failed_count, failed_today::int as failed_today,
    next_attempt_at, locked_at, must_change from app.partner_pin where user_id = ${uid}`))[0] ?? null;
const sessionRow = async (hash: string) =>
  (await rows("app.partner_session", (sql) => sql`select pin_grant_until, otp_proof_until, otp_proof_gotrue_session_id::text as gsid from app.partner_session where token_hash = ${hash}`))[0] ?? null;
const auditActions = async (uid: string): Promise<string[]> =>
  (await rows("app.audit_log", (sql) => sql`select action from app.audit_log where subject_id = ${uid} and action like 'partner.pin.%' order by created_at, action`)).map((r) => r.action as string);
const clearBackoff = (uid: string) =>
  rows("app.partner_pin", (sql) => sql`update app.partner_pin set next_attempt_at = clock_timestamp() - interval '1 second' where user_id = ${uid}`);

/** the pepper the database holds (the shim's), read from a separate connection, to compute the verifier INDEPENDENTLY in this process */
async function pepper(): Promise<Uint8Array<ArrayBuffer>> {
  const r = await rawOwnerSql()`select decrypted_secret as s from vault.decrypted_secrets where name = 'partner_pin_pepper'`;
  return new TextEncoder().encode(r[0]!.s as string);
}
async function expectedVerifier(uid: string, derived: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", await pepper(), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const msg = new Uint8Array([...new TextEncoder().encode("golfraven/partner-pin/v1"), 0, ...uuidToBytes(uid)!, ...derived]);
  return hex(new Uint8Array(await crypto.subtle.sign("HMAC", key, msg)));
}

/** prove the mailbox (the real OTP routes, the fake GoTrue) and return the fake */
async function proveMailbox(m: Member, otp: FakeOtp): Promise<void> {
  const start = await call("POST", "otp-proof/start", { token: m.token, body: {}, deps: deps(otp.port) });
  assertEquals(start.status, 200, await start.clone().text());
  const res = await call("POST", "otp-proof/verify", { token: m.token, body: { code: CODE }, deps: deps(otp.port) });
  assertEquals(res.status, 200, await res.clone().text());
}

async function setPin(m: Member, pin: string, salt = newPinSalt(), iterations = ITER): Promise<Response> {
  return await call("POST", "pin/set", { token: m.token, body: { derived: await derivePinKeyB64u(pin, salt, iterations), salt: toB64u(salt), iterations } });
}

/** GET pin, then derive exactly as the browser will, then POST step-up/pin */
async function stepUp(m: Member, pin: string): Promise<Response> {
  const p = await data<{ state: string; salt?: string; iterations?: number }>(await call("GET", "pin", { token: m.token }));
  assertEquals(p.state, "ok");
  const salt = Uint8Array.from(atob(p.salt!.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (p.salt!.length % 4)) % 4)), (c) => c.charCodeAt(0));
  return await call("POST", "step-up/pin", { token: m.token, body: { derived: await derivePinKeyB64u(pin, salt, p.iterations!) } });
}

// =============================================================================================================================================================
// The lifecycle, end to end, through the real contract: prove the mailbox, set, verify
// =============================================================================================================================================================

Deno.test("PA-21 / PA-18: a PIN is set only after an email proof (a passkey session alone is refused); the stored verifier equals an INDEPENDENT HMAC of the browser-derived key; the PIN itself is never stored or sent", DT, async () => {
  const m = await newMember("life");
  const initial = await data<{ state: string }>(await call("GET", "pin", { token: m.token }));
  assertEquals(initial, { state: "unset" });
  // a passkey-only session (and even a passkey reauth) cannot set a PIN
  const refused = await setPin(m, "7391");
  assertEquals(refused.status, 403, "no enrolment window and no email proof: refused");
  assertEquals(await pinRow(m.uid), null, "and nothing was written");
  // the email proof: the code goes to the member's OWN address (from the database), the response does not name it, and GoTrue is never called inside a transaction
  const otp = makeOtp(() => m.hash);
  const start = await call("POST", "otp-proof/start", { token: m.token, body: {}, deps: deps(otp.port) });
  assertEquals(start.status, 200);
  const startText = await start.text();
  assertEquals(JSON.parse(startText), { data: { sent: true } });
  assert(!startText.includes(m.email), "the response does not carry the address");
  assertEquals(otp.sent, [m.email], "the code goes to the member's own mailbox, taken from the database");
  // a wrong code is the ONE 403 and records nothing
  const wrong = await call("POST", "otp-proof/verify", { token: m.token, body: { code: "999999" }, deps: deps(otp.port) });
  assertEquals(wrong.status, 403);
  assertEquals(await errCode(wrong), "otp_refused");
  assertEquals((await sessionRow(m.hash))!.otp_proof_until, null);
  assertEquals(otp.closed.length, 0, "a refused code made no GoTrue session");
  // the right code: the proof is recorded, bound to the GoTrue session, THEN the GoTrue session is closed
  const ok = await call("POST", "otp-proof/verify", { token: m.token, body: { code: CODE }, deps: deps(otp.port) });
  assertEquals(ok.status, 200, await ok.clone().text());
  const row = (await sessionRow(m.hash))!;
  assert(row.otp_proof_until instanceof Date && row.otp_proof_until.getTime() > Date.now() + 9 * 60_000 && row.otp_proof_until.getTime() <= Date.now() + 10 * 60_000 + 2000, "now + 10 minutes");
  assertEquals(row.gsid, otp.lastSessionId, "bound to the GoTrue session verifyOtp created");
  assertEquals(otp.closed, [otp.lastSessionId], "the GoTrue session was closed");
  assertEquals(otp.proofVisibleAtClose, [true], "... and only AFTER the proof was visible to another connection (the order E19 uses)");
  assertEquals(otp.events, ["send", "verify", "verify", "close"]);
  // now the PIN: derived in this process exactly as the browser will, sent as bytes, never as the PIN
  const salt = newPinSalt();
  const derived = await derivePinKey("7391", salt, ITER);
  const set = await call("POST", "pin/set", { token: m.token, body: { derived: toB64u(derived), salt: toB64u(salt), iterations: ITER } });
  assertEquals(set.status, 200, await set.clone().text());
  const stored = (await pinRow(m.uid))!;
  assertEquals(stored.verifier, await expectedVerifier(m.uid, derived), "the stored verifier equals an independent HMAC-SHA256(pepper, label || user || derived)");
  assertEquals(stored.salt, hex(salt));
  assertEquals(stored.iterations, ITER);
  assertNotEquals(stored.verifier, toHex(derived), "the verifier is not the derived key");
  assertEquals(await auditActions(m.uid), ["partner.pin.set"]);
  // GET pin returns what the browser needs to derive the same bytes, and the correct PIN verifies
  const params = await data<{ state: string; salt: string; iterations: number; retryAfterSeconds: number }>(await call("GET", "pin", { token: m.token }));
  assertEquals(params, { state: "ok", salt: toB64u(salt), iterations: ITER, retryAfterSeconds: 0 });
  const good = await stepUp(m, "7391");
  assertEquals(good.status, 200, await good.clone().text());
  const grant = (await sessionRow(m.hash))!.pin_grant_until as Date;
  assert(grant.getTime() > Date.now() + 55_000 && grant.getTime() <= Date.now() + 60_000 + 2000, "the single-use grant is now + 60 s, on THIS session");
  // a second PIN set on a live PIN is refused (change needs the current PIN)
  const again = await setPin(m, "5028");
  assertEquals(again.status, 409);
  assertEquals(await errCode(again), "pin_already_set");
  assertEquals((await pinRow(m.uid))!.verifier, stored.verifier, "unchanged");
  // the PIN never appears anywhere the database wrote
  const dump = JSON.stringify(await rows("app.partner_pin", (sql) => sql`select * from app.partner_pin where user_id = ${m.uid}`));
  assert(!dump.includes("7391"), "the PIN is not in the row");
});

Deno.test("PA-21: a CHANGE needs the email proof AND the current PIN: a wrong current key is a COMMITTED status; the right one replaces the verifier; the old key is dead", DT, async () => {
  const m = await newMember("chg");
  await proveMailbox(m, makeOtp(() => m.hash));
  assertEquals((await setPin(m, "7391")).status, 200);
  const salt = newPinSalt();
  const change = (current: string, next: string, s = salt) =>
    (async () => call("POST", "pin/change", { token: m.token, body: { currentDerived: current, derived: await derivePinKeyB64u(next, s, ITER), salt: toB64u(s), iterations: ITER } }))();
  const p = await data<{ salt: string; iterations: number }>(await call("GET", "pin", { token: m.token }));
  const curSalt = Uint8Array.from(atob(p.salt.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (p.salt.length % 4)) % 4)), (c) => c.charCodeAt(0));
  const wrongRes = await change(await derivePinKeyB64u("0482", curSalt, p.iterations), "5028");
  assertEquals(wrongRes.status, 403);
  assertEquals(await errCode(wrongRes), "pin_wrong");
  assertEquals((await pinRow(m.uid))!.failed_count, 1, "the wrong CURRENT key was counted and the count COMMITTED (read from another connection)");
  const okRes = await change(await derivePinKeyB64u("7391", curSalt, p.iterations), "5028");
  assertEquals(okRes.status, 200, await okRes.clone().text());
  assertEquals((await pinRow(m.uid))!.failed_count, 0);
  assertEquals((await pinRow(m.uid))!.verifier, await expectedVerifier(m.uid, await derivePinKey("5028", salt, ITER)));
  assertEquals((await stepUp(m, "7391")).status, 403, "the old PIN is dead");
  assertEquals((await stepUp(m, "5028")).status, 200, "the new PIN verifies");
});

// =============================================================================================================================================================
// PA-18: the counters COMMIT with every refusal; 5 consecutive failures lock; the 6th, correct attempt is refused; the lock survives a new session
// =============================================================================================================================================================

Deno.test("PA-18 / 0020: wrong keys are returned statuses, so the counters, the backoff, the lock and the audit rows COMMIT; the sixth (correct) attempt is still refused; the lock survives a new session and cannot be set away", DT, async () => {
  const m = await newMember("lock");
  await proveMailbox(m, makeOtp(() => m.hash));
  assertEquals((await setPin(m, "7391")).status, 200);
  const wrong = () => stepUp(m, "0482");
  for (let i = 1; i <= 2; i++) {
    const r = await wrong();
    assertEquals(r.status, 403, `failure ${i}`);
    assertEquals(await errCode(r), "pin_wrong");
    assertEquals((await pinRow(m.uid))!.failed_count, i, `after ${i} refusals the counter is there, read from another connection: it committed`);
  }
  const third = await wrong();
  assertEquals(third.status, 403);
  assertEquals((await pinRow(m.uid))!.failed_count, 3);
  assert((await pinRow(m.uid))!.next_attempt_at instanceof Date, "the 30 s backoff committed");
  // a CORRECT key inside the backoff is refused without being evaluated
  const inBackoff = await stepUp(m, "7391");
  assertEquals(inBackoff.status, 429);
  assertEquals(await errCode(inBackoff), "pin_backoff");
  assert(Number(inBackoff.headers.get("retry-after")) >= 20 && Number(inBackoff.headers.get("retry-after")) <= 30, "Retry-After is the whole seconds left of the 30 s backoff that the third failure started (not the 1 s floor)");
  assertEquals((await pinRow(m.uid))!.failed_count, 3, "a refused-for-backoff attempt is not counted");
  await clearBackoff(m.uid);
  assertEquals((await wrong()).status, 403); // 4th: 5 minutes
  await clearBackoff(m.uid);
  const fifth = await wrong();
  assertEquals(fifth.status, 403);
  assertEquals(await errCode(fifth), "pin_locked", "the 5th consecutive failure LOCKS");
  const locked = (await pinRow(m.uid))!;
  assert(locked.locked_at instanceof Date, "locked_at committed");
  assertEquals(locked.failed_count, 5);
  // the sixth attempt, with the CORRECT PIN, is still refused
  const params = await data<{ state: string }>(await call("GET", "pin", { token: m.token }));
  assertEquals(params, { state: "locked" }, "GET pin: refused while locked, no salt");
  const sixthDerived = await derivePinKeyB64u("7391", Uint8Array.from((locked.salt as string).match(/../g)!, (h) => parseInt(h, 16)), locked.iterations as number);
  const sixth = await call("POST", "step-up/pin", { token: m.token, body: { derived: sixthDerived } });
  assertEquals(sixth.status, 403);
  assertEquals(await errCode(sixth), "pin_locked");
  assertEquals((await sessionRow(m.hash))!.pin_grant_until, null, "no grant for a locked PIN");
  // the audit rows committed: four wrong keys and one lock; the refused attempts on the locked PIN wrote none
  assertEquals((await auditActions(m.uid)).filter((a) => a === "partner.pin.wrong").length, 4);
  assertEquals((await auditActions(m.uid)).filter((a) => a === "partner.pin.locked").length, 1);
  // the lock survives a NEW session (another credential, another token)
  const second = await extraSession(m);
  const viaNew = await call("POST", "step-up/pin", { token: second.token, body: { derived: sixthDerived } });
  assertEquals(viaNew.status, 403);
  assertEquals(await errCode(viaNew), "pin_locked");
  // and a lock cannot be set away: not even with a fresh email proof (only a manager's reset clears it: S1.5)
  const m2 = { ...m, token: second.token, hash: second.hash };
  await proveMailbox(m2, makeOtp(() => second.hash));
  const setAway = await setPin(m2, "5028");
  assertEquals(setAway.status, 403);
  assertEquals(await errCode(setAway), "pin_locked");
  assertEquals((await pinRow(m.uid))!.locked_at instanceof Date, true, "still locked");
});

Deno.test("PA-18: after a reset (must_change) the old key is dead, a coworker's passkey session cannot set the new PIN, and an email proof can; the lock and the counters clear", DT, async () => {
  const m = await newMember("reset");
  await proveMailbox(m, makeOtp(() => m.hash));
  assertEquals((await setPin(m, "7391")).status, 200);
  // a reset (S1.5's definer is not built: the writer is the owner here, as the manager's definer will be a role of its own)
  await rows("app.partner_pin", (sql) => sql`update app.partner_pin set must_change = true, failed_count = 0 where user_id = ${m.uid}`);
  const p = await data<{ state: string }>(await call("GET", "pin", { token: m.token }));
  assertEquals(p, { state: "must_change" });
  // the coworker: a valid passkey session of the member, no proof (the proof was spent on a window that has since... use a fresh session, which carries none)
  const coworker = await extraSession(m);
  const noProof = await call("POST", "pin/set", { token: coworker.token, body: { derived: await derivePinKeyB64u("5028", newPinSalt(), ITER), salt: toB64u(newPinSalt()), iterations: ITER } });
  assertEquals(noProof.status, 403, "a passkey session alone cannot set the new PIN");
  assertEquals((await pinRow(m.uid))!.must_change, true);
  const mc = await call("POST", "step-up/pin", { token: m.token, body: { derived: await derivePinKeyB64u("7391", newPinSalt(), ITER) } });
  assertEquals(mc.status, 409);
  assertEquals(await errCode(mc), "pin_must_change");
  // with an email proof
  const cw = { ...m, token: coworker.token, hash: coworker.hash };
  await proveMailbox(cw, makeOtp(() => coworker.hash));
  assertEquals((await setPin(cw, "5028")).status, 200);
  const row = (await pinRow(m.uid))!;
  assertEquals([row.must_change, row.failed_count, row.locked_at], [false, 0, null]);
  assertEquals((await stepUp(cw, "5028")).status, 200);
  assertEquals((await stepUp(cw, "7391")).status, 403, "the pre-reset PIN is dead");
});

// =============================================================================================================================================================
// the email proof: limits, a stale or reused GoTrue session, the order
// =============================================================================================================================================================

Deno.test("OTP proof (design 8): 3 codes a member an hour, then 429 and no mail; 5 attempts a member an hour, then 429 even for the right code", DT, async () => {
  const m = await newMember("otplim");
  const otp = makeOtp(() => m.hash);
  for (let i = 1; i <= 3; i++) assertEquals((await call("POST", "otp-proof/start", { token: m.token, body: {}, deps: deps(otp.port) })).status, 200, `send ${i}`);
  const fourth = await call("POST", "otp-proof/start", { token: m.token, body: {}, deps: deps(otp.port) });
  assertEquals(fourth.status, 429);
  assert(fourth.headers.get("retry-after") !== null);
  assertEquals(otp.sent.length, 3, "the fourth request sent nothing");
  for (let i = 1; i <= 5; i++) assertEquals((await call("POST", "otp-proof/verify", { token: m.token, body: { code: "000000" }, deps: deps(otp.port) })).status, 403, `attempt ${i}`);
  const sixth = await call("POST", "otp-proof/verify", { token: m.token, body: { code: CODE }, deps: deps(otp.port) });
  assertEquals(sixth.status, 429, "the 6th attempt of the hour is refused even with the right code");
  assertEquals((await sessionRow(m.hash))!.otp_proof_until, null);
});

Deno.test("OTP proof: a GoTrue session older than a minute is refused (and still closed); one GoTrue session proves at most ONE proof (a second session of the member is refused, the UNIQUE index) and is still closed", DT, async () => {
  const m = await newMember("otpbind");
  const stale = makeOtp(() => m.hash);
  stale.ageSeconds = 300;
  const r1 = await call("POST", "otp-proof/verify", { token: m.token, body: { code: CODE }, deps: deps(stale.port) });
  assertEquals(r1.status, 403);
  assertEquals((await sessionRow(m.hash))!.otp_proof_until, null, "a stale GoTrue session records nothing");
  assertEquals(stale.closed.length, 1, "and it is still closed");
  // reuse: the first session proves; a second session of the same member presents the SAME GoTrue session id
  const first = makeOtp(() => m.hash);
  assertEquals((await call("POST", "otp-proof/verify", { token: m.token, body: { code: CODE }, deps: deps(first.port) })).status, 200);
  const gs = first.lastSessionId!;
  const other = await extraSession(m);
  const reuse = makeOtp(() => other.hash);
  await adminSql()`insert into auth.sessions (id, user_id, created_at) values (${gs}, ${m.uid}, clock_timestamp()) on conflict (id) do nothing`;
  reuse.reuse = gs;
  const r2 = await call("POST", "otp-proof/verify", { token: other.token, body: { code: CODE }, deps: deps(reuse.port) });
  assertEquals(r2.status, 403, "the same GoTrue session cannot prove a second proof");
  assertEquals(await errCode(r2), "otp_refused");
  assertEquals((await sessionRow(other.hash))!.otp_proof_until, null);
  assertEquals(reuse.closed.length, 1, "closed on this path too");
  await adminSql()`delete from auth.sessions where id = ${gs}`;
});

// =============================================================================================================================================================
// deploy faults and the shape of the request
// =============================================================================================================================================================

Deno.test("a missing PIN pepper is a deploy fault: 503 with no detail, never a pass, and the lockout counter does not move", DT, async () => {
  const m = await newMember("nopepper");
  await proveMailbox(m, makeOtp(() => m.hash));
  assertEquals((await setPin(m, "7391")).status, 200);
  const sql = rawOwnerSql();
  const saved = await sql`select id::text as id, name, secret from vault.secrets where name = 'partner_pin_pepper'`;
  assertEquals(saved.length, 1);
  await sql`delete from vault.secrets where name = 'partner_pin_pepper'`;
  try {
    const res = await stepUp(m, "7391");
    assertEquals(res.status, 503);
    const text = await res.text();
    assert(!/pepper|vault|secret/i.test(text), "no detail in the answer");
    assertEquals((await pinRow(m.uid))!.failed_count, 0);
  } finally {
    await sql`insert into vault.secrets (id, name, secret) values (${saved[0]!.id as string}, 'partner_pin_pepper', ${saved[0]!.secret as string})`;
  }
  assertEquals((await stepUp(m, "7391")).status, 200, "restored");
});

Deno.test("the request carries the derived key, never the PIN: a PIN-shaped value is a 400 before any database work, whatever the route", DT, async () => {
  const m = await newMember("shape");
  for (const [path, body] of [
    ["step-up/pin", { derived: "7391" }],
    ["step-up/pin", { pin: "7391" }],
    ["pin/set", { derived: "7391", salt: "AAAAAAAAAAAAAAAAAAAAAA", iterations: ITER }],
    ["pin/set", { pin: "7391", salt: "AAAAAAAAAAAAAAAAAAAAAA", iterations: ITER }],
    ["pin/change", { currentDerived: "1234", derived: "7391", salt: "AAAAAAAAAAAAAAAAAAAAAA", iterations: ITER }],
  ] as const) {
    assertEquals((await call("POST", path, { token: m.token, body })).status, 400, `${path} ${JSON.stringify(body)}`);
  }
  assertEquals((await pinRow(m.uid)), null);
});

Deno.test("a dead (signed-out) session is the ONE 401 on the new routes", DT, async () => {
  const m = await newMember("dead");
  await call("POST", "sign-out", { token: m.token, body: {} });
  for (const [method, path, body] of [["GET", "pin", undefined], ["POST", "step-up/pin", { derived: toB64u(new Uint8Array(32)) }], ["POST", "otp-proof/start", {}]] as const) {
    const res = await call(method, path, { token: m.token, body });
    assertEquals(res.status, 401, path);
    assertEquals(await errCode(res), "unauthenticated");
  }
});

Deno.test("teardown: the edge connection is closed and the owner's temporary privileges on partner_credential are given back", DT, async () => {
  await resetPrivilegedConnectionsForTests();
  await rawOwnerSql().unsafe("revoke select, update on app.partner_credential, app.partner_org from current_user");
});
