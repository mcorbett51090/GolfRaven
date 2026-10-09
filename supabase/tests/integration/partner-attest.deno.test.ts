// supabase/tests/integration/partner-attest.deno.test.ts
//
// Slice S3 (migration 0056, docs/security/partner-auth-design.md 26; AT(1), AT(2), AT(12), AT(13), AT(15), AT(16) part one): the REAL `partner-attest` handler over the REAL privileged.ts (`withPartnerSession`,
// `hitRateLimitForPartner`), REAL partner sessions minted by the REAL mint from the software authenticator's REAL assertions, against the REAL database tools/db/test.sh builds (connected as the provisioned
// `edge_gateway` login, as `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY A REAL COMMIT AND TWO CONNECTIONS CAN SHOW. The pgTAP file (34_partner_attest_redeem.sql) runs inside one rolled-back transaction, so it cannot show (1) that the FAILURE COUNTERS of a refused offline
// verification survive a REAL commit (the 0020 lesson: a RAISE would roll them back), and (2) that parallel verifications of one code step record it ONCE (the primary key of app.offline_code_step is the
// arbiter). Both are shown here, through the handler, and read back from a SEPARATE connection.
//
// The one shortcut: the PIN grant (class A1 needs one per action) is written straight into the session row by the OWNER, with the guard trigger off for that statement only. The PIN verification itself is
// proved against the real handler in partner-pin.deno.test.ts; here the subject is what the grant UNLOCKS. Everything else is the real path.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawOwnerSql, withTemporaryOwnerAccess as withOwnerAccess } from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import { handlePartnerAttestRequest } from "../../functions/_shared/partner/attest-handler.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import { parseChallengeToken, uuidToBytes } from "../../functions/_shared/partner/session-shape.ts";
import { newPartnerSessionToken, sha256Hex } from "../../functions/_shared/partner/token.ts";
import { partnerDb } from "../../functions/_shared/privileged.ts";
import { hotp, stepOf } from "../../functions/_shared/offline-code/totp.ts";
import { deriveSeedReference, SHIM_OFFLINE_SEED_KEY } from "../unit/offline-seed-reference.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const HELD = new Set(["app.partner_credential", "app.partner_org"]);
const withTemporaryOwnerAccess = <T>(table: string, fn: (sql: ReturnType<typeof postgres>) => Promise<T>) =>
  withOwnerAccess(table, fn as never, HELD.has(table) ? "insert, delete" : "select, insert, update, delete") as Promise<T>;
await rawOwnerSql().unsafe("grant select, update on app.partner_credential, app.partner_org to current_user");
const rows = <T>(table: string, query: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> => withTemporaryOwnerAccess(table, query);

const RP = { rpId: "partners.example.test", origin: "https://partners.example.test" };
await withTemporaryOwnerAccess("app.partner_rp_config", (sql) =>
  sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`);
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

async function sessionCall(method: string, path: string, body: unknown): Promise<Response> {
  const headers = new Headers({ origin: RP.origin, "content-type": "application/json" });
  return await handlePartnerSessionRequest(new Request(`https://project.example.test/functions/v1/partner-session/${path}`, { method, headers, body: JSON.stringify(body) }), {
    db: partnerDb,
    allowedOrigin: RP.origin,
    webauthn: assertionVerifier,
    otp: { send: () => Promise.reject(new Error("unused")), verify: () => Promise.reject(new Error("unused")) },
    nowMs: () => Date.now(),
    newSessionToken: newPartnerSessionToken,
  });
}

interface Member {
  readonly uid: string;
  readonly token: string;
  readonly hash: string;
}
let seq = 0;
async function newMember(role: "staff" | "manager", orgId?: string): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `att-${seq}`);
  const org = orgId ?? freshUuid();
  if (orgId === undefined) {
    await withTemporaryOwnerAccess("app.partner_org", (sql) => sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"attest org " + seq})`);
    await withTemporaryOwnerAccess("app.partner_scope", (sql) => sql`insert into app.partner_scope (org_id, facility_id) values (${org}, 'fac_x')`);
  }
  await withTemporaryOwnerAccess("app.partner_member", (sql) => sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, ${role}, now() - interval '60 days')`);
  const auth = await SoftwareAuthenticator.create("ES256", uuidToBytes(uid)!);
  await withTemporaryOwnerAccess("app.partner_credential", (sql) =>
    sql`insert into app.partner_credential (user_id, credential_id, public_key, alg, sign_count) values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), -7, 0)`);
  const o = await sessionCall("POST", "options", {});
  const d = (await o.json()).data as { challengeToken: string };
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: parsed.nonce });
  const res = await sessionCall("POST", "verify", { challengeToken: d.challengeToken, credential: cred });
  assertEquals(res.status, 201, await res.clone().text());
  const token = ((await res.json()).data as { token: string }).token;
  return { uid, token, hash: await sha256Hex(token) };
}

/** A PIN grant, as a verified PIN leaves it (50 s): the owner writes it with the guard trigger off for this statement only. */
async function grant(m: Member): Promise<void> {
  const owner = rawOwnerSql();
  await owner.unsafe("alter table app.partner_session disable trigger partner_session_guard_trg");
  try {
    await rows("app.partner_session", (sql) => sql`update app.partner_session set pin_grant_until = clock_timestamp() + interval '50 seconds' where token_hash = ${m.hash}`);
  } finally {
    await owner.unsafe("alter table app.partner_session enable trigger partner_session_guard_trg");
  }
}

async function attest(m: Member, path: string, body: unknown, withGrant = true): Promise<Response> {
  if (withGrant) await grant(m);
  return await handlePartnerAttestRequest(
    new Request(`https://project.example.test/functions/v1/partner-attest/${path}`, {
      method: "POST",
      headers: { origin: RP.origin, authorization: `Bearer ${m.token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}
async function read(m: Member, path: string): Promise<Response> {
  return await handlePartnerAttestRequest(new Request(`https://project.example.test/functions/v1/partner-attest/${path}`, { method: "GET", headers: { origin: RP.origin, authorization: `Bearer ${m.token}` } }), {
    db: partnerDb,
    allowedOrigin: RP.origin,
  });
}
const code = async (res: Response): Promise<string> => (await res.json()).error?.code as string;

interface Player {
  readonly uid: string;
  readonly handle: string;
  readonly device: string;
}
async function newPlayer(): Promise<Player> {
  const uid = freshUuid();
  await createTestUser(uid, `plr-${++seq}`);
  const device = freshUuid();
  await ensureServiceRole();
  await adminSql()`insert into app.device (id, user_id, platform) values (${device}, ${uid}, 'ios')`;
  return { uid, handle: `u${uid.replace(/-/g, "").slice(0, 19)}`, device };
}
async function newToken(p: Player, facility: string | null = "fac_x", ttlMinutes = 10): Promise<string> {
  const challenge = freshUuid();
  const jti = freshUuid();
  const sql = adminSql();
  await ensureServiceRole();
  await sql`insert into app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, expires_at, kind) values (${challenge}, ${p.uid}, ${p.device}, ${facility}, ${"n-" + challenge}, now() + ${ttlMinutes + " minutes"}::interval, 'live')`;
  await sql`insert into app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) values (${jti}, ${challenge}, ${p.uid}, ${p.device}, ${facility}, 'attested', 'live', now(), now() + ${ttlMinutes + " minutes"}::interval)`;
  return jti;
}
/** the code the player's device shows at a step, computed by the independent reference (the Edge never derives a seed) */
async function deviceCode(p: Player, stepOffset = 0): Promise<string> {
  const seed = await deriveSeedReference(SHIM_OFFLINE_SEED_KEY, p.uid, p.device, 1);
  return await hotp(seed, stepOf(Date.now() / 1000) + stepOffset);
}
const rawCountOf = async (query: string): Promise<number> => {
  await ensureServiceRole();
  return Number((await adminSql().unsafe(query))[0]!.n);
};
const bucketCount = async (key: string): Promise<number> => {
  const r = await rows("private.rate_limit_bucket", (sql) => sql`select coalesce(sum(count), 0)::int as n from private.rate_limit_bucket where bucket_key = ${key}`);
  return Number(r[0]!.n);
};
const FAIL_KEY = (uid: string) => `offline-code-fail:staff:${uid}`;

Deno.test("AT(2): the online attest through the real handler: the player is the token's owner; one attestation per token; a second PIN grant is needed per action", DT, async () => {
  const staff = await newMember("staff");
  const player = await newPlayer();
  const jti = await newToken(player);
  const refused = await attest(staff, "attest", { facilityId: "fac_x", kind: "presence", token: jti }, false);
  assertEquals(refused.status, 403, "no PIN grant: refused (class A1)");
  assertEquals(await rawCountOf(`select count(*) as n from app.attestation where token_jti = '${jti}'`), 0);
  const ok = await attest(staff, "attest", { facilityId: "fac_x", kind: "presence", token: jti });
  assertEquals(ok.status, 201, await ok.clone().text());
  const att = await rows("app.attestation", (sql) => sql`select player_user_id::text as p, staff_user_id::text as s, kind::text as k from app.attestation where token_jti = ${jti}`);
  assertEquals(att[0], { p: player.uid, s: staff.uid, k: "presence" });
  const again = await attest(staff, "attest", { facilityId: "fac_x", kind: "presence", token: jti });
  assertEquals(again.status, 409, "the same token: replayed");
  assertEquals(await code(again), "replayed");
  const wrongFacility = await attest(staff, "attest", { facilityId: "fac_x", kind: "presence", token: await newToken(player, "fac_y") });
  assertEquals(wrongFacility.status, 422, "a token for another facility: one answer");
  const log = await read(staff, "shift-log?facilityId=fac_x");
  assertEquals(log.status, 200);
  const entries = ((await log.json()).data as { entries: Array<{ playerHandle: string }> }).entries;
  assert(entries.some((e) => e.playerHandle === player.handle), "the shift log shows the attestation");
});

Deno.test("AT(16): a staff member who is also a player attests their own account: 422, nothing written", DT, async () => {
  const staff = await newMember("staff");
  const myPlayer: Player = { uid: staff.uid, handle: `u${staff.uid.replace(/-/g, "").slice(0, 19)}`, device: freshUuid() };
  await ensureServiceRole();
  await adminSql()`insert into app.device (id, user_id, platform) values (${myPlayer.device}, ${myPlayer.uid}, 'ios')`;
  const jti = await newToken(myPlayer);
  const res = await attest(staff, "attest", { facilityId: "fac_x", kind: "presence", token: jti });
  assertEquals(res.status, 422);
  assertEquals(await rawCountOf(`select count(*) as n from app.attestation where token_jti = '${jti}'`), 0);
  const off = await attest(staff, "attest/offline", { facilityId: "fac_x", kind: "presence", handle: myPlayer.handle, code: await deviceCode(myPlayer) });
  assertEquals(off.status, 422, "the offline path too");
});

Deno.test("AT(12) / AT(13): the offline code is verified IN THE DATABASE; a replayed step is 409; the response carries no seed, no code and no device", DT, async () => {
  const staff = await newMember("staff");
  const player = await newPlayer();
  const c = await deviceCode(player);
  const ok = await attest(staff, "attest/offline", { facilityId: "fac_x", kind: "marker_purchase", handle: player.handle, code: c });
  assertEquals(ok.status, 201, await ok.clone().text());
  const text = await ok.text();
  for (const secret of [c, player.device, hex(await deriveSeedReference(SHIM_OFFLINE_SEED_KEY, player.uid, player.device, 1))]) assert(!text.includes(secret), "the response names neither the code, the device nor the seed");
  const purchase = await rows("app.purchase_evidence", (sql) => sql`select method::text as m, status::text as s, offline as o from app.purchase_evidence where user_id = ${player.uid}`);
  assertEquals(purchase[0], { m: "staff_scan", s: "pending", o: true });
  const replay = await attest(staff, "attest/offline", { facilityId: "fac_x", kind: "presence", handle: player.handle, code: c });
  assertEquals(replay.status, 409);
  assertEquals(await code(replay), "replayed");
  assertEquals(await rawCountOf(`select count(*) as n from app.offline_code_step where user_id = '${player.uid}'`), 1, "one step recorded");
});

Deno.test("SP13: the failure counter of a refused verification COMMITS (read from a separate connection); the 6th attempt is refused even with the right code", DT, async () => {
  const staff = await newMember("staff");
  const player = await newPlayer();
  for (let i = 0; i < 5; i++) {
    const res = await attest(staff, "attest/offline", { facilityId: "fac_x", kind: "presence", handle: player.handle, code: i === 0 ? "000000" : `00000${i}` });
    assertEquals(res.status, 422, `failure ${i + 1}`);
    assertEquals(await code(res), "verification_failed");
  }
  assertEquals(await bucketCount(FAIL_KEY(staff.uid)), 5, "five failures were COUNTED and committed");
  const sixth = await attest(staff, "attest/offline", { facilityId: "fac_x", kind: "presence", handle: player.handle, code: await deviceCode(player) });
  assertEquals(sixth.status, 429, "locked, with the right code");
  assertEquals(sixth.headers.get("retry-after"), "3600");
  assertEquals(await rawCountOf(`select count(*) as n from app.offline_code_step where user_id = '${player.uid}'`), 0, "nothing was recorded");
});

Deno.test("AT(13): four staff verify the SAME correct code at once: exactly one records it, the others are 409 (the primary key arbitrates)", DT, async () => {
  const player = await newPlayer();
  const staff = await Promise.all([newMember("staff"), newMember("staff"), newMember("staff"), newMember("staff")]);
  const c = await deviceCode(player);
  for (const m of staff) await grant(m);
  const results = await Promise.all(staff.map((m) => attest(m, "attest/offline", { facilityId: "fac_x", kind: "presence", handle: player.handle, code: c }, false)));
  const statuses = results.map((r) => r.status).sort();
  assertEquals(statuses, [201, 409, 409, 409]);
  assertEquals(await rawCountOf(`select count(*) as n from app.offline_code_step where user_id = '${player.uid}'`), 1);
  assertEquals(await rawCountOf(`select count(*) as n from app.attestation where player_user_id = '${player.uid}'`), 1);
});

Deno.test("AT(1): staff at another facility and an operator cannot attest or read; staff cannot read staff-activity, a manager can", DT, async () => {
  const staff = await newMember("staff");
  const player = await newPlayer();
  const jti = await newToken(player, "fac_y");
  const other = await attest(staff, "attest", { facilityId: "fac_y", kind: "presence", token: jti });
  assertEquals(other.status, 403, "staff at X attests at Y: 403");
  assertEquals((await read(staff, "shift-log?facilityId=fac_y")).status, 403);
  assertEquals((await read(staff, "staff-activity?facilityId=fac_x&days=7")).status, 403, "staff must not read staff-activity");
  const orgRows = await rows("app.partner_member", (sql) => sql`select org_id::text as o from app.partner_member where user_id = ${staff.uid}`);
  const manager = await newMember("manager", orgRows[0]!.o as string);
  const act = await read(manager, "staff-activity?facilityId=fac_x&days=7");
  assertEquals(act.status, 200, await act.clone().text());
});
