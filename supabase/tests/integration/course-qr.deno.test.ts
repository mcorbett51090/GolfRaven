// supabase/tests/integration/course-qr.deno.test.ts
//
// Slice S2b (migration 0055, docs/security/partner-auth-design.md 6.3, 12.1 S2a/S2b, AT(19), PA-26): the REAL `course-qr` and `qr-print` handlers over the REAL privileged.ts (`courseQrDb` =
// `withPartnerSession`, `hitRateLimitForPartner`), REAL sessions minted by the REAL partner-session mint from the software authenticator's REAL assertions, REAL Ed25519 keys generated in this process
// and provisioned in the Vault stand-in, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY A REAL COMMIT AND A REAL DRIVER CAN SHOW (the pgTAP file, 33_course_qr_staff.sql, runs inside one rolled-back transaction, and the unit suites use an in-memory port):
//   * the token the handler hands out VERIFIES in the player lane's format.ts under the public key the DATABASE holds, and its nonce hash and `iat` are the committed row's;
//   * the PIN grant is consumed by a COMMITTED mint and GIVEN BACK by a refused one (no programme, a seed that is not the registered key's): the rollback goes through postgres.js, not through a fake;
//   * a refresh does not advance last_seen_at after a real commit (PA-26), and a session idle past its limit cannot use it to come back;
//   * the PIN the staff screen shows equals an INDEPENDENT HMAC computed here from the Vault pepper, and rotating changes it and logs the epoch through the 0046 trigger;
//   * qr-print registers a signature `verifyPrintedQr` accepts under the key row the database inserted, and printing again changes nothing;
//   * no response or committed row carries the Vault seed.

import { assert, assertEquals, assertNotEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { createTestUser, freshUuid, rawOwnerSql } from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { base64UrlEncode, parsePrintedQr, parseRotatingToken, verifyPrintedQr, verifyRotatingToken } from "../../functions/_shared/course-qr/format.ts";
import { handleCourseQrRequest, type CourseQrDeps } from "../../functions/_shared/partner/course-qr-handler.ts";
import { publicKeyOfSeed } from "../../functions/_shared/partner/course-qr-signer.ts";
import { handleQrPrintRequest } from "../../functions/_shared/partner/qr-print-handler.ts";
import { handlePartnerSessionRequest, type PartnerSessionDeps } from "../../functions/_shared/partner/session-handler.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import { parseChallengeToken, uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { newPartnerSessionToken, sha256Hex } from "../../functions/_shared/partner/token.ts";
import type { EmailOtpPort } from "../../functions/_shared/partner/ports.ts";
import { courseQrDb, openScopedTx, partnerDb, userBind } from "../../functions/_shared/privileged.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
/** Runs `fn` as the connecting owner with a TEMPORARY `FOR ALL` policy on `schemaTable` (FORCE RLS leaves the table's owner with no row access otherwise), dropped again afterwards. A POLICY ONLY: unlike
 * `_helpers.ts#withTemporaryOwnerAccess` it never GRANTs or REVOKEs, because under HARNESS_MODE=restricted the connecting role OWNS the table and a `REVOKE ... FROM current_user` would strip the owner's own
 * privileges (the first draft of this file did, and the marker-scan suite that runs after it failed with `permission denied for table course_qr_key`: the trap marker-scan.deno.test.ts already documents). */
async function withTemporaryOwnerAccess<T>(schemaTable: string, fn: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> {
  const sql = rawOwnerSql();
  const name = `s2b_course_qr_temp_${schemaTable.replace(/\W/g, "_")}`;
  await sql.unsafe(`create policy ${name} on ${schemaTable} for all to current_user using (true) with check (true)`);
  try {
    return await fn(sql as never);
  } finally {
    await sql.unsafe(`drop policy if exists ${name} on ${schemaTable}`);
  }
}
// the deferred foreign keys of a session commit are checked with the OWNER's privileges: a grant to the owner of what it already owns is a no-op that makes the file independent of an earlier file's revoke
await rawOwnerSql().unsafe("grant select, update on app.partner_credential, app.partner_org to current_user");
const rows = <T>(table: string, query: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> => withTemporaryOwnerAccess(table, query);

const RP = { rpId: "partners.example.test", origin: "https://partners.example.test" };
const LINK_ORIGIN = "https://golfraven.example.test";
const FAC = "fac_x";
const OTHER_FAC = "fac_y";
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

await withTemporaryOwnerAccess("app.partner_rp_config", (sql) =>
  sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`);

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
// the keys: real Ed25519 seeds, provisioned the way an operator does (Vault secret `<kid>:<seed>` and the PUBLIC key row), and a pepper if none is there
// -------------------------------------------------------------------------------------------------------------------------------------------------------------
const ROT_KID = "kidrot-it";
const PRT_KID = "kidprt-it";
const rotSeed = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
const prtSeed = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
const rotPublic = await publicKeyOfSeed(rotSeed);
const prtPublic = await publicKeyOfSeed(prtSeed);
const owner = () => rawOwnerSql();
const createdPepper = (await owner()`select 1 from vault.secrets where name = 'course_pin_pepper'`).length === 0;
if (createdPepper) await owner()`insert into vault.secrets (name, secret) values ('course_pin_pepper', ${"integration-course-pin-pepper-" + "x".repeat(20)})`;
await owner()`delete from vault.secrets where name in ('course_qr_signing_key_rotating_token', 'course_qr_signing_key_printed_qr')`;
await owner()`insert into vault.secrets (name, secret) values ('course_qr_signing_key_rotating_token', ${ROT_KID + ":" + rotSeed}), ('course_qr_signing_key_printed_qr', ${PRT_KID + ":" + prtSeed})`;
await withTemporaryOwnerAccess("app.course_qr_key", (sql) => sql`insert into app.course_qr_key (purpose, kid, public_key_b64url) values ('rotating_token', ${ROT_KID}, ${rotPublic})`);
// fac_x takes both variants for this file (restored at the end)
const originalModes = await rows("app.facility_programme", (sql) => sql`select trail_id, qr_mode::text as qr_mode from app.facility_programme where facility_id = ${FAC} order by trail_id`);
const setQrMode = (mode: string) => rows("app.facility_programme", (sql) => sql`update app.facility_programme set qr_mode = ${mode}::app.qr_mode where facility_id = ${FAC}`);
await setQrMode("both");

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
// the handlers, over the real database
// -------------------------------------------------------------------------------------------------------------------------------------------------------------
const NO_OTP: EmailOtpPort = { send: () => Promise.reject(new Error("unexpected email send")), verify: () => Promise.reject(new Error("unexpected email verify")) };
const sessionDeps: PartnerSessionDeps = { db: partnerDb, allowedOrigin: RP.origin, webauthn: assertionVerifier, otp: NO_OTP, nowMs: () => Date.now(), newSessionToken: newPartnerSessionToken };
const cqDeps = (over: Partial<CourseQrDeps> = {}): CourseQrDeps => ({ db: courseQrDb, allowedOrigin: RP.origin, linkOrigin: LINK_ORIGIN, randomNonce: () => crypto.getRandomValues(new Uint8Array(16)), ...over });

async function sessionCall(method: string, path: string, body?: unknown): Promise<Response> {
  const headers = new Headers({ origin: RP.origin });
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handlePartnerSessionRequest(new Request(`https://project.example.test/functions/v1/partner-session/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), sessionDeps);
}
async function cq(method: string, path: string, token: string, body?: unknown, over: Partial<CourseQrDeps> = {}): Promise<Response> {
  const headers = new Headers({ origin: RP.origin, authorization: `Bearer ${token}` });
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handleCourseQrRequest(new Request(`https://project.example.test/functions/v1/course-qr/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), cqDeps(over));
}
async function qp(method: string, query: string, token: string, body?: unknown): Promise<Response> {
  const headers = new Headers({ origin: RP.origin, authorization: `Bearer ${token}` });
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handleQrPrintRequest(new Request(`https://project.example.test/functions/v1/qr-print${query}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), {
    db: courseQrDb,
    allowedOrigin: RP.origin,
    linkOrigin: LINK_ORIGIN,
  });
}
const data = async <T>(res: Response): Promise<T> => (await res.json()).data as T;
const errCode = async (res: Response): Promise<string> => (await res.json()).error?.code as string;

// -------------------------------------------------------------------------------------------------------------------------------------------------------------
// people: a staff member at fac_x or an operator of trl_t (which fac_x is on), a credential and a session minted by the real mint
// -------------------------------------------------------------------------------------------------------------------------------------------------------------
interface Member {
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
  const o = await sessionCall("POST", "options", {});
  const d = await data<{ challengeToken: string }>(o);
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: parsed.nonce });
  const res = await sessionCall("POST", "verify", { challengeToken: d.challengeToken, credential: cred });
  assertEquals(res.status, 201, await res.clone().text());
  return (await data<{ token: string }>(res)).token;
}
let seq = 0;
async function newMember(label: string, kind: "staff" | "operator" = "staff", facility = FAC): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `cq-${label}${seq}`);
  const org = freshUuid();
  await withTemporaryOwnerAccess("app.partner_org", (sql) => sql`insert into app.partner_org (id, kind, name) values (${org}, ${kind === "operator" ? "operator" : "facility"}, ${"cq org " + label + seq})`);
  if (kind === "operator") await withTemporaryOwnerAccess("app.partner_scope", (sql) => sql`insert into app.partner_scope (org_id, trail_id) values (${org}, 'trl_t')`);
  else await withTemporaryOwnerAccess("app.partner_scope", (sql) => sql`insert into app.partner_scope (org_id, facility_id) values (${org}, ${facility})`);
  await withTemporaryOwnerAccess("app.partner_member", (sql) => sql`insert into app.partner_member (user_id, org_id, role) values (${uid}, ${org}, ${kind})`);
  const token = await signInWith(await enrol(uid));
  return { uid, token, hash: await sha256Hex(token) };
}

/** Step-up state a session cannot be BORN with: the guard is off for the seeding only (the pgTAP file does the same). */
async function seedStep(m: Member, cols: { pinGrantS?: number; reauthS?: number; mfaS?: number; aal?: number; seenAgoS?: number }): Promise<void> {
  await withTemporaryOwnerAccess("app.partner_session", async (sql) => {
    await sql.unsafe("alter table app.partner_session disable trigger partner_session_guard_trg");
    try {
      if (cols.pinGrantS !== undefined) await sql`update app.partner_session set pin_grant_until = clock_timestamp() + ${cols.pinGrantS} * interval '1 second' where token_hash = ${m.hash}`;
      if (cols.reauthS !== undefined) await sql`update app.partner_session set reauth_until = clock_timestamp() + ${cols.reauthS} * interval '1 second' where token_hash = ${m.hash}`;
      if (cols.mfaS !== undefined) await sql`update app.partner_session set mfa_until = clock_timestamp() + ${cols.mfaS} * interval '1 second' where token_hash = ${m.hash}`;
      if (cols.aal !== undefined) await sql`update app.partner_session set aal = ${cols.aal} where token_hash = ${m.hash}`;
      if (cols.seenAgoS !== undefined) await sql`update app.partner_session set last_seen_at = clock_timestamp() - ${cols.seenAgoS} * interval '1 second' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe("alter table app.partner_session enable trigger partner_session_guard_trg");
    }
  });
}
const sessionRow = async (m: Member) =>
  (await rows("app.partner_session", (sql) => sql`select pin_grant_until, last_seen_at, reauth_until from app.partner_session where token_hash = ${m.hash}`))[0]!;
const tokenRows = async (uid: string) =>
  await rows("app.course_qr_token", (sql) => sql`select nonce_hash, facility_id, kid, issued_by_staff::text as issued_by, issued_at, expires_at, used_at from app.course_qr_token where issued_by_staff = ${uid} order by issued_at`);

/** The PIN an INDEPENDENT implementation derives (the database's is private.course_pin_derive): LPAD((first 4 bytes of HMAC-SHA256(pepper, label 0x00 facility 0x00 date 0x00 epoch BE32) as uint32) mod 10000, 4) */
async function expectedPin(facility: string, tz: string, epoch: number): Promise<string> {
  const pepper = (await owner()`select decrypted_secret as s from vault.decrypted_secrets where name = 'course_pin_pepper'`)[0]!.s as string;
  const date = new Date().toLocaleDateString("en-CA", { timeZone: tz });
  const enc = new TextEncoder();
  const msg = new Uint8Array([...enc.encode("golfraven/course-pin/v1"), 0, ...enc.encode(facility), 0, ...enc.encode(date), 0, (epoch >>> 24) & 255, (epoch >>> 16) & 255, (epoch >>> 8) & 255, epoch & 255]);
  const key = await crypto.subtle.importKey("raw", enc.encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const n = ((mac[0]! * 2 ** 24) + (mac[1]! << 16) + (mac[2]! << 8) + mac[3]!) % 10000;
  return String(n).padStart(4, "0");
}
const currentEpoch = async (): Promise<number> =>
  Number((await rows("app.facility_programme", (sql) => sql`select max(pin_epoch)::int as e from app.facility_programme where facility_id = ${FAC}`))[0]!.e);

// =============================================================================================================================================================
// Marker sold
// =============================================================================================================================================================

Deno.test("AT(19) / S2b: Marker sold: the COMMITTED token verifies in the player lane's format.ts under the database's public key; its hash and iat are the row's; the PIN grant is spent; the seed is nowhere", DT, async () => {
  const m = await newMember("mint");
  await seedStep(m, { pinGrantS: 50 });
  const res = await cq("POST", "tokens", m.token, { facilityId: FAC });
  assertEquals(res.status, 201, await res.clone().text());
  const text = await res.clone().text();
  assert(!text.includes(rotSeed), "the Vault seed is not in the response");
  const d = await data<{ token: string; nonceHash: string; kid: string; issuedAt: string; expiresAt: string; link: string }>(res);
  const parsed = parseRotatingToken(d.token);
  assert(parsed !== null, "format.ts parses it");
  const publicRow = (await rows("app.course_qr_key", (sql) => sql`select public_key_b64url from app.course_qr_key where purpose = 'rotating_token' and kid = ${ROT_KID}`))[0]!;
  assertEquals(publicRow.public_key_b64url, rotPublic);
  assert(await verifyRotatingToken(parsed!, publicRow.public_key_b64url as string), "the signature verifies under the key the DATABASE holds");
  const [row] = await tokenRows(m.uid);
  assertEquals(await tokenRows(m.uid).then((r) => r.length), 1);
  assertEquals(row!.nonce_hash, d.nonceHash);
  assertEquals(row!.nonce_hash, hex(new Uint8Array(await crypto.subtle.digest("SHA-256", parsed!.claims.nonce.slice().buffer))), "the row's hash is the SHA-256 of the token's nonce");
  assertEquals(Math.floor((row!.issued_at as Date).getTime() / 1000), parsed!.claims.iat, "the row's issued_at IS the token's iat");
  assertEquals((row!.issued_at as Date).getTime() % 1000, 0, "truncated to the second");
  assertEquals((row!.expires_at as Date).getTime() - (row!.issued_at as Date).getTime(), 120_000);
  assertEquals([row!.facility_id, row!.kid, row!.used_at], [FAC, ROT_KID, null]);
  assertEquals(d.link, `${LINK_ORIGIN}/q/m#${d.token}`);
  assertEquals((await sessionRow(m)).pin_grant_until, null, "the committed mint SPENT the PIN grant");
  const second = await cq("POST", "tokens", m.token, { facilityId: FAC });
  assertEquals(second.status, 403, "one PIN, one token");
  assertEquals((await tokenRows(m.uid)).length, 1);
  assert(!JSON.stringify(await rows("app.audit_log", (sql) => sql`select detail from app.audit_log where actor_user_id = ${m.uid}`)).includes(rotSeed));
});

Deno.test("AT(19): the scan the PLAYER lane runs consumes exactly the row the staff lane committed (single use)", DT, async () => {
  const m = await newMember("scan");
  await seedStep(m, { pinGrantS: 50 });
  const d = await data<{ token: string; nonceHash: string; kid: string }>(await cq("POST", "tokens", m.token, { facilityId: FAC }));
  const player = freshUuid();
  await createTestUser(player, "cq-player");
  const scan = async (): Promise<string[]> => {
    const r = await openScopedTx("actor", userBind(player), (trx) =>
      trx`select o_result from private.marker_scan_for_actor(${FAC}, 'rotating', ${d.nonceHash}, ${d.kid}, null, now(), null, null, null)`);
    return [...new Set(r.map((x) => String(x.o_result)))];
  };
  assertEquals(await scan(), ["accepted"]);
  assertEquals(await scan(), ["qr_used"]);
  assert((await tokenRows(m.uid))[0]!.used_at !== null, "the committed row is the one the scan used");
});

Deno.test("S2b: a refused mint ROLLS BACK through the real driver: no programme, and a seed that is not the registered key's, each leave the PIN grant and no token row", DT, async () => {
  const m = await newMember("rollback");
  await seedStep(m, { pinGrantS: 50 });
  await setQrMode("static_pin");
  try {
    const res = await cq("POST", "tokens", m.token, { facilityId: FAC });
    assertEquals(res.status, 409, await res.clone().text());
    assertEquals(await errCode(res), "no_programme");
    assertNotEquals((await sessionRow(m)).pin_grant_until, null, "the PIN grant was given back");
    assertEquals((await tokenRows(m.uid)).length, 0);
  } finally {
    await setQrMode("both");
  }
  // the registered public key is some OTHER key: the Edge's self-verification fails AFTER the row was written and the grant consumed inside the transaction: all of it rolls back
  const wrong = await publicKeyOfSeed(base64UrlEncode(crypto.getRandomValues(new Uint8Array(32))));
  await withTemporaryOwnerAccess("app.course_qr_key", (sql) => sql`insert into app.course_qr_key (purpose, kid, public_key_b64url) values ('rotating_token', 'kidrot-wrong', ${wrong})`);
  await owner()`update vault.secrets set secret = ${"kidrot-wrong:" + rotSeed} where name = 'course_qr_signing_key_rotating_token'`;
  try {
    const res = await cq("POST", "tokens", m.token, { facilityId: FAC });
    assertEquals(res.status, 503, await res.clone().text());
    assertEquals(await res.json(), { error: { code: "service_unavailable", message: "partner service is not available" } });
    assertNotEquals((await sessionRow(m)).pin_grant_until, null, "the PIN grant was given back");
    assertEquals((await tokenRows(m.uid)).length, 0, "and no token row was committed");
  } finally {
    await owner()`update vault.secrets set secret = ${ROT_KID + ":" + rotSeed} where name = 'course_qr_signing_key_rotating_token'`;
    await withTemporaryOwnerAccess("app.course_qr_key", (sql) => sql`delete from app.course_qr_key where kid = 'kidrot-wrong'`);
  }
  // a key that is revoked mints nothing at all (55000 -> a bare 503) and the grant is still there
  await withTemporaryOwnerAccess("app.course_qr_key", (sql) => sql`update app.course_qr_key set revoked_at = now() where purpose = 'rotating_token' and kid = ${ROT_KID}`);
  try {
    const res = await cq("POST", "tokens", m.token, { facilityId: FAC });
    assertEquals(res.status, 503);
    assertNotEquals((await sessionRow(m)).pin_grant_until, null);
  } finally {
    await withTemporaryOwnerAccess("app.course_qr_key", (sql) => sql`update app.course_qr_key set revoked_at = null where purpose = 'rotating_token' and kid = ${ROT_KID}`);
  }
});

Deno.test("AT(19): staff at fac_x CANNOT mint, read the PIN, rotate or refresh at fac_y: 403 on every route, nothing written, the grant untouched", DT, async () => {
  const m = await newMember("scope");
  await seedStep(m, { pinGrantS: 50, reauthS: 200 });
  assertEquals((await cq("POST", "tokens", m.token, { facilityId: OTHER_FAC })).status, 403);
  assertEquals((await cq("GET", `pin?facilityId=${OTHER_FAC}`, m.token)).status, 403);
  assertEquals((await cq("POST", "pin/rotate", m.token, { facilityId: OTHER_FAC })).status, 403);
  assertEquals((await cq("POST", "tokens/refresh", m.token, { facilityId: OTHER_FAC, nonceHash: "a".repeat(64) })).status, 403);
  assertEquals((await tokenRows(m.uid)).length, 0);
  assertNotEquals((await sessionRow(m)).pin_grant_until, null);
});

Deno.test("PA-26: the refresh reports the state of one's OWN token, creates nothing and never advances last_seen_at after a real commit; an idle-expired session cannot use it to come back", DT, async () => {
  const m = await newMember("refresh");
  await seedStep(m, { pinGrantS: 50 });
  const minted = await data<{ nonceHash: string }>(await cq("POST", "tokens", m.token, { facilityId: FAC }));
  await seedStep(m, { seenAgoS: 600 });
  const before = (await sessionRow(m)).last_seen_at as Date;
  const r1 = await cq("POST", "tokens/refresh", m.token, { facilityId: FAC, nonceHash: minted.nonceHash });
  assertEquals(r1.status, 200, await r1.clone().text());
  const body = await data<{ state: string; secondsLeft: number }>(r1);
  assertEquals(body.state, "live");
  assert(body.secondsLeft > 100 && body.secondsLeft <= 120);
  await cq("POST", "tokens/refresh", m.token, { facilityId: FAC, nonceHash: minted.nonceHash });
  assertEquals(((await sessionRow(m)).last_seen_at as Date).getTime(), before.getTime(), "two refreshes did not move last_seen_at");
  assertEquals((await tokenRows(m.uid)).length, 1, "and created no token");
  // control: an ordinary A0 call (today's PIN) does advance it
  assertEquals((await cq("GET", `pin?facilityId=${FAC}`, m.token)).status, 200);
  assert(((await sessionRow(m)).last_seen_at as Date).getTime() > before.getTime(), "control: an ordinary call advances idle");
  // another person's nonce is `unknown`, the same answer as one that does not exist
  const other = await newMember("refresh-other");
  const alien = await data<{ state: string }>(await cq("POST", "tokens/refresh", other.token, { facilityId: FAC, nonceHash: minted.nonceHash }));
  assertEquals(alien.state, "unknown");
  // a session idle past its 30 minutes is dead: the refresh cannot revive it (the binder refuses it: the one 401)
  await seedStep(m, { seenAgoS: 1900 });
  assertEquals((await cq("POST", "tokens/refresh", m.token, { facilityId: FAC, nonceHash: minted.nonceHash })).status, 401);
});

// =============================================================================================================================================================
// Today's PIN and Rotate PIN
// =============================================================================================================================================================

Deno.test("S2b: the PIN the staff screen shows equals an INDEPENDENT HMAC of the Vault pepper; Rotate PIN (A2) raises pin_epoch only, changes the PIN and the 0046 trigger logs the epoch; one PIN, one rotation", DT, async () => {
  const m = await newMember("pin");
  const epoch0 = await currentEpoch();
  const shown = await data<{ pin: string; pinEpoch: number; localDate: string; validUntil: string }>(await cq("GET", `pin?facilityId=${FAC}`, m.token));
  assertEquals(shown.pin, await expectedPin(FAC, "America/Chicago", epoch0), "the displayed PIN is the independent derivation");
  assertEquals(shown.pinEpoch, epoch0);
  assertEquals(shown.localDate, new Date().toLocaleDateString("en-CA", { timeZone: "America/Chicago" }));
  // without a fresh PIN and passkey the rotation is refused
  assertEquals((await cq("POST", "pin/rotate", m.token, { facilityId: FAC })).status, 403);
  assertEquals(await currentEpoch(), epoch0);
  await seedStep(m, { pinGrantS: 50, reauthS: 200 });
  const rotated = await cq("POST", "pin/rotate", m.token, { facilityId: FAC });
  assertEquals(rotated.status, 200, await rotated.clone().text());
  assertEquals((await data<{ pinEpoch: number }>(rotated)).pinEpoch, epoch0 + 1);
  assertEquals(await currentEpoch(), epoch0 + 1);
  const log = await rows("app.course_pin_epoch_log", (sql) => sql`select pin_epoch::int as e, previous_epoch::int as p from app.course_pin_epoch_log where facility_id = ${FAC} and pin_epoch = ${epoch0 + 1}`);
  assertEquals(log.length, 1, "the trigger logged the rotation");
  assertEquals(log[0]!.p, epoch0);
  const after = await data<{ pin: string }>(await cq("GET", `pin?facilityId=${FAC}`, m.token));
  assertEquals(after.pin, await expectedPin(FAC, "America/Chicago", epoch0 + 1));
  assertNotEquals(after.pin, shown.pin);
  assertEquals((await cq("POST", "pin/rotate", m.token, { facilityId: FAC })).status, 403, "the PIN grant was single use");
  assertEquals((await rows("app.audit_log", (sql) => sql`select count(*)::int as n from app.audit_log where actor_user_id = ${m.uid} and action = 'partner.course_pin.rotate'`))[0]!.n, 1);
});

// =============================================================================================================================================================
// qr-print
// =============================================================================================================================================================

Deno.test("S2b: qr-print (A3): an operator with a fresh TOTP signs and registers the printed QR; the signature verifies under the public key row the database inserted; printing again changes nothing; staff cannot print", DT, async () => {
  const op = await newMember("operator", "operator");
  // aal 1 (no TOTP): refused outright
  assertEquals((await qp("POST", "", op.token, { facilityId: FAC })).status, 403);
  await seedStep(op, { aal: 2, mfaS: 200 });
  assertEquals((await qp("GET", `?facilityId=${FAC}`, op.token)).status, 404, "nothing printed yet");
  const res = await qp("POST", "", op.token, { facilityId: FAC });
  assertEquals(res.status, 201, await res.clone().text());
  const text = await res.clone().text();
  assert(!text.includes(prtSeed), "the Vault seed is not in the response");
  const d = await data<{ qrKid: string; sig: string; link: string; changed: boolean }>(res);
  assertEquals([d.qrKid, d.changed], [PRT_KID, true]);
  const keyRow = (await rows("app.course_qr_key", (sql) => sql`select public_key_b64url from app.course_qr_key where purpose = 'printed_qr' and kid = ${PRT_KID}`))[0]!;
  assertEquals(keyRow.public_key_b64url, prtPublic, "the database inserted the PUBLIC key row from the Vault seed");
  const parsed = parsePrintedQr(d.qrKid, d.sig);
  assert(parsed !== null);
  assert(await verifyPrintedQr(parsed!, FAC, keyRow.public_key_b64url as string), "the registered signature verifies under the database's key for fac_x");
  assert(!(await verifyPrintedQr(parsed!, OTHER_FAC, keyRow.public_key_b64url as string)), "and is useless for fac_y");
  assertEquals(d.link, `${LINK_ORIGIN}/q/f/facility-x#${d.qrKid}.${d.sig}`);
  const reg = (await rows("app.facility_qr", (sql) => sql`select qr_kid, sig, revoked_at from app.facility_qr where facility_id = ${FAC}`))[0]!;
  assertEquals([reg.qr_kid, reg.sig, reg.revoked_at], [PRT_KID, d.sig, null]);
  const again = await qp("POST", "", op.token, { facilityId: FAC });
  assertEquals(again.status, 200);
  assertEquals((await data<{ changed: boolean; sig: string }>(again)).changed, false);
  const read = await data<{ qrKid: string; sig: string; revoked: boolean }>(await qp("GET", `?facilityId=${FAC}`, op.token));
  assertEquals([read.qrKid, read.sig, read.revoked], [PRT_KID, d.sig, false]);
  assertEquals((await rows("app.audit_log", (sql) => sql`select count(*)::int as n from app.audit_log where actor_user_id = ${op.uid} and action = 'partner.course_qr.print'`))[0]!.n, 1, "one audit row for two prints");
  assertEquals((await qp("POST", "", op.token, { facilityId: OTHER_FAC })).status, 403, "an operator of trl_t has no scope at fac_y");
  const staff = await newMember("print-staff");
  assertEquals((await qp("POST", "", staff.token, { facilityId: FAC })).status, 403);
});

Deno.test("teardown: the programme modes, the keys, the registered QR and the temporary policies are gone", DT, async () => {
  for (const r of originalModes) await rows("app.facility_programme", (sql) => sql`update app.facility_programme set qr_mode = ${r.qr_mode as string}::app.qr_mode where trail_id = ${r.trail_id as string} and facility_id = ${FAC}`);
  await withTemporaryOwnerAccess("app.facility_qr", (sql) => sql`delete from app.facility_qr where facility_id = ${FAC}`);
  await withTemporaryOwnerAccess("app.course_qr_key", (sql) => sql`delete from app.course_qr_key where kid in (${ROT_KID}, ${PRT_KID})`);
  await owner()`delete from vault.secrets where name in ('course_qr_signing_key_rotating_token', 'course_qr_signing_key_printed_qr')`;
  if (createdPepper) await owner()`delete from vault.secrets where name = 'course_pin_pepper'`;
});
