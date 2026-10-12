// supabase/tests/integration/partner-totp.deno.test.ts
//
// 0108 (docs/security/partner-auth-design.md §122): the partner TOTP's ceiling on CONSECUTIVE failures, through the REAL `partner-session` handler and the REAL privileged.ts (`withPartnerSession`), with REAL
// sessions minted by the REAL mint from the software authenticator's REAL assertions, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner`
// through SET LOCAL ROLE). The pgTAP file (86_partner_totp_hard_lock.sql) proves the database half inside one rolled-back transaction; what only this file can show is the half in between:
//   * privileged.ts accepts the status `hard_locked` (its allow-list of TOTP statuses would otherwise turn it into a 500 "returned no usable status"),
//   * the handler answers it 403 `totp_hard_locked` with NO Retry-After, while the ordinary 15-minute lock keeps its 403 `totp_locked` + `Retry-After: 900`,
//   * every refusal's transaction COMMITS (the 0020 lesson): the count, the hard lock, the audit row and the alarm are read back from a SEPARATE connection.
//
// The person is an admin (needs no membership to be authorised for step-up/totp). Her TOTP is seeded confirmed; the code is computed IN THIS PROCESS from the Vault key by an independent HMAC and the
// contract module's RFC 4226 HOTP, not by the function under test. The 15-minute wait is simulated by moving locked_until into the past.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, freshUuid, rawOwnerSql, withTemporaryOwnerAccess as withOwnerAccess } from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest, type PartnerSessionDeps } from "../../functions/_shared/partner/session-handler.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import { parseChallengeToken, uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { newPartnerSessionToken, sha256Hex } from "../../functions/_shared/partner/token.ts";
import { hotpSha1 } from "../../functions/_shared/partner/totp-contract.ts";
import type { EmailOtpPort } from "../../functions/_shared/partner/ports.ts";
import { partnerDb } from "../../functions/_shared/privileged.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

// partner_session.credential_id -> partner_credential is checked AT COMMIT with the OWNER's privileges (see partner-signin-mint.deno.test.ts): the owner holds SELECT and UPDATE on partner_credential for
// as long as a transaction commits a session, i.e. the whole file.
const HELD = new Set(["app.partner_credential"]);
const withTemporaryOwnerAccess = <T>(table: string, fn: (sql: ReturnType<typeof postgres>) => Promise<T>) =>
  withOwnerAccess(table, fn as never, HELD.has(table) ? "insert, delete" : "select, insert, update, delete") as Promise<T>;
await rawOwnerSql().unsafe("grant select, update on app.partner_credential to current_user");
const rows = <T>(table: string, query: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> => withTemporaryOwnerAccess(table, query);

const RP = { rpId: "partners.example.test", origin: "https://partners.example.test" };

await withTemporaryOwnerAccess("app.partner_rp_config", (sql) =>
  sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`);

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const NO_OTP: EmailOtpPort = {
  send: () => Promise.reject(new Error("unexpected email send")),
  verify: () => Promise.reject(new Error("unexpected email verify")),
};
const deps = (): PartnerSessionDeps => ({
  db: partnerDb,
  allowedOrigin: RP.origin,
  webauthn: assertionVerifier,
  otp: NO_OTP,
  nowMs: () => Date.now(),
  newSessionToken: newPartnerSessionToken,
});

async function call(method: string, path: string, init: { token?: string; body?: unknown } = {}): Promise<Response> {
  const headers = new Headers({ origin: RP.origin });
  if (init.token) headers.set("authorization", `Bearer ${init.token}`);
  let body: string | undefined;
  if (init.body !== undefined) {
    body = JSON.stringify(init.body);
    headers.set("content-type", "application/json");
  }
  return await handlePartnerSessionRequest(new Request(`https://project.example.test/functions/v1/partner-session/${path}`, { method, headers, body }), deps());
}
const data = async <T>(res: Response): Promise<T> => (await res.json()).data as T;
const errCode = async (res: Response): Promise<string> => (await res.json()).error?.code as string;

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
// people: an admin (no membership needed), a credential, a session minted by the real mint
// -------------------------------------------------------------------------------------------------------------------------------------------------------------
interface Person {
  readonly uid: string;
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
async function newAdmin(label: string): Promise<Person> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `totp-${label}${seq}`);
  await adminSql()`insert into app.admin_user (user_id) values (${uid})`;
  const token = await signInWith(await enrol(uid));
  return { uid, token, hash: await sha256Hex(token) };
}
async function extraSession(p: Person): Promise<Person> {
  const token = await signInWith(await enrol(p.uid));
  return { uid: p.uid, token, hash: await sha256Hex(token) };
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
// the TOTP: the seed and the codes, computed here
// -------------------------------------------------------------------------------------------------------------------------------------------------------------
async function seedOf(uid: string, version: number): Promise<Uint8Array> {
  const r = await rawOwnerSql()`select decrypted_secret as s from vault.decrypted_secrets where name = 'partner_totp_key'`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(r[0]!.s as string), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const ver = new Uint8Array(4);
  new DataView(ver.buffer).setInt32(0, version);
  const msg = new Uint8Array([...new TextEncoder().encode("golfraven/partner-totp/v1"), 0, ...uuidToBytes(uid)!, ...ver]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
}
const stepNow = (): number => Math.floor(Date.now() / 30_000);
const codeAt = async (uid: string, delta: number): Promise<string> => await hotpSha1(await seedOf(uid, 1), stepNow() + delta);
/** a code valid for none of the steps now-3 .. now+3 (the window is now-1 .. now+1), so a step boundary mid-test cannot make it right */
async function wrongCode(uid: string): Promise<string> {
  const bad = new Set<string>();
  for (let d = -3; d <= 3; d++) bad.add(await codeAt(uid, d));
  for (let n = 0; ; n++) {
    const c = String(n).padStart(6, "0");
    if (!bad.has(c)) return c;
  }
}

const seedTotp = (uid: string) =>
  rows("app.partner_totp", (sql) => sql`insert into app.partner_totp (user_id, seed_version, enrolled_at, confirmed_at, failed_count, created_at) values (${uid}, 1, clock_timestamp(), clock_timestamp(), 0, clock_timestamp())`);
const totpRow = async (uid: string) =>
  (await rows("app.partner_totp", (sql) => sql`select consecutive_failed::int as consecutive_failed, failed_count::int as failed_count, hard_locked_at, locked_until, last_step::text as last_step
    from app.partner_totp where user_id = ${uid}`))[0] ?? null;
const waitOutLock = (uid: string) =>
  rows("app.partner_totp", (sql) => sql`update app.partner_totp set locked_until = clock_timestamp() - interval '1 second' where user_id = ${uid} and locked_until is not null and locked_until > clock_timestamp()`);
const sessionRow = async (hash: string) =>
  (await rows("app.partner_session", (sql) => sql`select aal::int as aal, mfa_until from app.partner_session where token_hash = ${hash}`))[0] ?? null;
const auditCount = async (uid: string, action: string): Promise<number> =>
  Number((await rows("app.audit_log", (sql) => sql`select count(*)::int as n from app.audit_log where subject_id = ${uid} and action = ${action}`))[0]!.n);
const alarmCount = async (uid: string, kind: string): Promise<number> =>
  Number((await rows("app.partner_auth_alarm", (sql) => sql`select count(*)::int as n from app.partner_auth_alarm where kind = ${kind} and bucket_key = ${uid}`))[0]!.n);

const stepUp = (p: Person, code: string): Promise<Response> => call("POST", "step-up/totp", { token: p.token, body: { code } });

/** `n` wrong codes in a row, every lock waited out; returns the (status, error code, Retry-After) of each */
async function failRun(p: Person, n: number): Promise<string[]> {
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    const r = await stepUp(p, await wrongCode(p.uid));
    out.push(`${r.status}:${await errCode(r)}:${r.headers.get("retry-after") ?? "-"}`);
    await waitOutLock(p.uid);
  }
  return out;
}
const NINETEEN = Array.from({ length: 19 }, (_, i) => ((i + 1) % 5 === 0 ? "403:totp_locked:900" : "403:totp_wrong:-"));

// =============================================================================================================================================================
// 0108 (§122)
// =============================================================================================================================================================

Deno.test("0108: 19 consecutive wrong codes across three 15-minute locks are counted (the lock no longer erases the count), a success clears it, 19 more are still no hard lock; the 20th answers 403 totp_hard_locked with NO Retry-After", DT, async () => {
  const p = await newAdmin("count");
  await seedTotp(p.uid);
  assertEquals(await failRun(p, 19), NINETEEN, "failures 1-4 are totp_wrong; the 5th, 10th and 15th are the 15-minute lock: 403 totp_locked with Retry-After 900 (unchanged)");
  const afterNineteen = (await totpRow(p.uid))!;
  assertEquals([afterNineteen.consecutive_failed, afterNineteen.failed_count, afterNineteen.hard_locked_at], [19, 4, null], "the count survived three locks, committed (read from another connection)");
  // a success clears the count
  const ok = await stepUp(p, await codeAt(p.uid, 0));
  assertEquals(ok.status, 200, await ok.clone().text());
  assertEquals((await totpRow(p.uid))!.consecutive_failed, 0, "a SUCCESS clears the consecutive count");
  assertEquals((await sessionRow(p.hash))!.aal, 2, "and raised the session");
  // 19 more are plain failures again: 38 in all, no hard lock
  assertEquals(await failRun(p, 19), NINETEEN);
  assertEquals((await totpRow(p.uid))!.consecutive_failed, 19);
  assertEquals((await totpRow(p.uid))!.hard_locked_at, null);
  // the 20th
  const hard = await stepUp(p, await wrongCode(p.uid));
  assertEquals(hard.status, 403);
  assertEquals(await errCode(hard), "totp_hard_locked");
  assertEquals(hard.headers.get("retry-after"), null, "time does not clear a hard lock: no Retry-After");
  const row = (await totpRow(p.uid))!;
  assertEquals(row.consecutive_failed, 20);
  assert(row.hard_locked_at instanceof Date, "hard_locked_at committed");
  assertEquals(await auditCount(p.uid, "partner.totp.hard_locked"), 1, "ONE alertable hard-lock audit row");
  assertEquals(await alarmCount(p.uid, "totp_hard_locked"), 1, "ONE operator alarm");
  assertEquals(await auditCount(p.uid, "partner.totp.wrong"), 32, "the 32 plain failures wrote their rows; the 20th wrote none besides the hard-lock row");
});

Deno.test("0108: on a hard-locked TOTP a CORRECT code is refused and not evaluated, from the same session and a new one, with no further audit row and no further alarm", DT, async () => {
  const p = await newAdmin("refuse");
  await seedTotp(p.uid);
  await failRun(p, 20);
  const locked = (await totpRow(p.uid))!;
  assertEquals(locked.consecutive_failed, 20);
  assert(locked.hard_locked_at instanceof Date);
  await waitOutLock(p.uid); // only the hard lock is left now
  const before = JSON.stringify(await totpRow(p.uid));
  // the right code for the next step (not a replay of anything), then for this one and the last one
  for (const delta of [1, 0, -1]) {
    const r = await stepUp(p, await codeAt(p.uid, delta));
    assertEquals([r.status, await errCode(r), r.headers.get("retry-after")], [403, "totp_hard_locked", null], `a correct code (step ${delta >= 0 ? "+" : ""}${delta}) is refused`);
  }
  assertEquals(JSON.stringify(await totpRow(p.uid)), before, "nothing moved: last_step is NULL, the counters and hard_locked_at are what they were (the code was not evaluated)");
  const s = (await sessionRow(p.hash))!;
  assertEquals([s.aal, s.mfa_until], [1, null], "the session was not raised");
  // a NEW session of the same person is refused the same way
  const other = await extraSession(p);
  const viaNew = await stepUp(other, await codeAt(p.uid, 1));
  assertEquals([viaNew.status, await errCode(viaNew)], [403, "totp_hard_locked"], "the hard lock is on the person, not the session");
  assertEquals((await sessionRow(other.hash))!.aal, 1);
  // a wrong code answers the same (not totp_wrong, not totp_locked)
  const wrong = await stepUp(p, await wrongCode(p.uid));
  assertEquals(await errCode(wrong), "totp_hard_locked");
  assertEquals(await auditCount(p.uid, "partner.totp.hard_locked"), 1, "refusals wrote no further hard-lock audit row");
  assertEquals(await alarmCount(p.uid, "totp_hard_locked"), 1, "... and raised no further alarm");
  assertEquals(await auditCount(p.uid, "partner.totp.wrong") + await auditCount(p.uid, "partner.totp.locked"), 16 + 3, "... and no wrong / locked rows after the 20th (16 wrongs and 3 locks came before it)");
});
