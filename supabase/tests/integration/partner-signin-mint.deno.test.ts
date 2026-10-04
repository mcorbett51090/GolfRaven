// supabase/tests/integration/partner-signin-mint.deno.test.ts
//
// S1.1b (migration 0048, docs/security/partner-auth-design.md PA-7 / PA-8 / PA-9): the partner sign-in mint, driven from OUTSIDE the database by an INDEPENDENT signer.
//
// The pgTAP files sign with a signer written in SQL on top of the verifier's own arithmetic. That proves the verifier accepts what the verifier's own maths produces, which is
// the weakest cross-check there is. This suite closes the loop with the one signer the database did not write: the software authenticator (supabase/tests/deno-unit/
// software-authenticator.ts) signs with Web Crypto (ES256 on P-256, RS256 = RSASSA-PKCS1-v1_5 / SHA-256 with a 2048-bit key and e = 65537), and the bytes go to the mint exactly as the
// Edge would send them: connected as the provisioned `edge_gateway` login, `SET LOCAL ROLE edge_partner_minter`, then `private.partner_challenge_issue_sign_in()` and
// `private.partner_session_mint(...)`. Every key and every credential id is generated when the test runs; nothing here is a secret.
//
// Not exercised here (and why): the Edge caller of the mint is a later slice (privileged.ts has no partner scope yet), so this file speaks to the database directly as the role that
// slice will use; the 60-per-hour limit, the HMAC vectors and the atomicity of the refusals are pgTAP (26_partner_signin_mint.sql); the 12-way concurrency is
// tools/db/test-partner-serialisation.sh.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { createTestUser, freshUuid, withTemporaryOwnerAccess } from "./_helpers.ts";
import { fromB64u, SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { verifyAssertion, type RpConfig, WebAuthnRefusal } from "../../functions/_shared/partner/webauthn.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

const RP: RpConfig = { rpId: "partners.example.test", origin: "https://partners.example.test" };

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
async function sha256hex(s: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
}

// the edge connection, exactly as privileged.ts opens it (a host-less URL, PGHOST / PGPORT / PGPASSWORD from the environment)
const edge = postgres(Deno.env.get("GOLFRAVEN_EDGE_DB_URL")!, { max: 1, prepare: false });

interface Challenge {
  nonce: Uint8Array;
  exp: string;
  mac: Uint8Array;
}

async function issue(): Promise<Challenge> {
  return await edge.begin(async (trx) => {
    await trx`set local role edge_partner_minter`;
    const r = (await trx`select encode(o_nonce, 'hex') as n, o_exp::text as e, encode(o_mac, 'hex') as m from private.partner_challenge_issue_sign_in()`)[0]!;
    return { nonce: Uint8Array.from((r.n as string).match(/../g)!, (h) => parseInt(h, 16)), exp: r.e as string, mac: Uint8Array.from((r.m as string).match(/../g)!, (h) => parseInt(h, 16)) };
  }) as Challenge;
}

interface Presented {
  credentialId: Uint8Array;
  nonce: Uint8Array;
  exp: string;
  mac: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
}

async function mint(p: Presented, tokenLabel = crypto.randomUUID()): Promise<{ status: string; sessionId: string | null; aal: number | null }> {
  const th = await sha256hex("token:" + tokenLabel);
  return await edge.begin(async (trx) => {
    await trx`set local role edge_partner_minter`;
    const r = (await trx`select o_status::text as s, o_session_id::text as sid, o_aal::int as aal from private.partner_session_mint(
      ${th}::text, decode(${hex(p.credentialId)}::text, 'hex'), decode(${hex(p.nonce)}::text, 'hex'), ${p.exp}::bigint, decode(${hex(p.mac)}::text, 'hex'),
      decode(${hex(p.authenticatorData)}::text, 'hex'), decode(${hex(p.clientDataJSON)}::text, 'hex'), decode(${hex(p.signature)}::text, 'hex'))`)[0]!;
    return { status: r.s as string, sessionId: (r.sid as string | null) ?? null, aal: (r.aal as number | null) ?? null };
  }) as { status: string; sessionId: string | null; aal: number | null };
}

/** An authenticator, its person and its credential row (born live and unused, as the insert guard requires). */
async function enrol(alg: "ES256" | "RS256"): Promise<{ auth: SoftwareAuthenticator; uid: string }> {
  const auth = await SoftwareAuthenticator.create(alg);
  const uid = freshUuid();
  await createTestUser(uid, "mint-" + uid.slice(0, 8));
  await withTemporaryOwnerAccess("app.partner_credential", (sql) =>
    sql`insert into app.partner_credential (user_id, credential_id, public_key, alg) values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), ${alg === "ES256" ? -7 : -257})`);
  return { auth, uid };
}

interface Build {
  counter?: number;
  flags?: { up?: boolean; uv?: boolean };
  origin?: string;
  rpIdHashOf?: string;
  tamperSignature?: boolean;
  client?: Record<string, unknown>;
}

/** One assertion over a challenge the database just issued, as the browser would hand it over. */
async function assertion(auth: SoftwareAuthenticator, ch: Challenge, b: Build = {}): Promise<{ presented: Presented; response: Awaited<ReturnType<SoftwareAuthenticator["assert"]>> }> {
  const response = await auth.assert({
    rpId: RP.rpId,
    origin: b.origin ?? RP.origin,
    challenge: ch.nonce,
    counter: b.counter,
    flags: b.flags,
    rpIdHashOf: b.rpIdHashOf,
    tamperSignature: b.tamperSignature,
    client: b.client,
  });
  return {
    response,
    presented: {
      credentialId: auth.credentialId,
      nonce: ch.nonce,
      exp: ch.exp,
      mac: ch.mac,
      authenticatorData: fromB64u(response.response.authenticatorData),
      clientDataJSON: fromB64u(response.response.clientDataJSON),
      signature: fromB64u(response.response.signature),
    },
  };
}

async function libraryAccepts(auth: SoftwareAuthenticator, ch: Challenge, response: Awaited<ReturnType<SoftwareAuthenticator["assert"]>>, storedCount: number): Promise<boolean> {
  try {
    await verifyAssertion({ rp: RP, response, expectedChallenge: ch.nonce, credential: { id: auth.id, publicKey: auth.cosePublicKey, signCount: storedCount }, expectedUserHandle: auth.userHandle });
    return true;
  } catch (e) {
    if (e instanceof WebAuthnRefusal) return false;
    throw e;
  }
}

async function rows<T>(table: string, query: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> {
  return await withTemporaryOwnerAccess(table, query as never) as T;
}

// the relying party, as ops writes it at deploy (this suite runs on its own copy of the database)
await withTemporaryOwnerAccess("app.partner_rp_config", (sql) =>
  sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`);

Deno.test("mint: a Web Crypto ES256 assertion over a database-issued challenge mints a session, the library agrees, and the counter advances", DT, async () => {
  const { auth, uid } = await enrol("ES256");
  const ch = await issue();
  assertEquals(ch.nonce.length, 32);
  const { presented, response } = await assertion(auth, ch);
  assert(await libraryAccepts(auth, ch, response, 0), "the wrapper (the library) accepts the same assertion");
  const r = await mint(presented);
  assertEquals(r.status, "ok");
  assert(r.sessionId !== null);
  assertEquals(r.aal, 1);
  const s = await rows("app.partner_session", (sql) => sql`select user_id::text as u, mint_kind::text as k, aal::int as aal from app.partner_session where id = ${r.sessionId}`);
  assertEquals(s[0]!.u, uid);
  assertEquals(s[0]!.k, "sign_in");
  const c = await rows("app.partner_credential", (sql) => sql`select sign_count::int as n, last_used_at is not null as used from app.partner_credential where user_id = ${uid}`);
  assertEquals(c[0]!.n, 1);
  assertEquals(c[0]!.used, true);
});

Deno.test("mint: a Web Crypto RS256 (2048-bit, e = 65537) assertion mints too, and the library agrees", DT, async () => {
  for (let i = 0; i < 3; i++) {
    const { auth } = await enrol("RS256");
    const ch = await issue();
    const { presented, response } = await assertion(auth, ch);
    assert(await libraryAccepts(auth, ch, response, 0));
    assertEquals((await mint(presented)).status, "ok", "RS256 assertion " + i);
  }
});

Deno.test("mint: 24 independent ES256 keys all verify in the database (DER with a leading zero byte, short r or s and the rest of what random signatures produce)", DT, async () => {
  for (let i = 0; i < 24; i++) {
    const { auth } = await enrol("ES256");
    const ch = await issue();
    const { presented } = await assertion(auth, ch);
    assertEquals((await mint(presented)).status, "ok", "ES256 key " + i);
  }
});

Deno.test("mint: a tampered signature is refused by the database AND the library, writes no session and no used nonce, and raises an alarm that survives the refusal", DT, async () => {
  const { auth, uid } = await enrol("ES256");
  const ch = await issue();
  const { presented, response } = await assertion(auth, ch, { tamperSignature: true });
  assertEquals(await libraryAccepts(auth, ch, response, 0), false);
  const r = await mint(presented);
  assertEquals(r.status, "signature_invalid");
  assertEquals(r.sessionId, null);
  const n = await rows("app.partner_session", (sql) => sql`select count(*)::int as n from app.partner_session where user_id = ${uid}`);
  assertEquals(n[0]!.n, 0);
  const used = await rows("app.partner_auth_challenge", (sql) => sql`select count(*)::int as n from app.partner_auth_challenge where user_id = ${uid}`);
  assertEquals(used[0]!.n, 0, "a refused signature burns no nonce");
  const alarms = await rows("app.partner_auth_alarm", (sql) =>
    sql`select count(*)::int as n from app.partner_auth_alarm a join app.partner_credential c on c.id = a.credential_id where c.user_id = ${uid} and a.kind = 'signature_invalid'`);
  assertEquals(alarms[0]!.n, 1, "the alarm committed with the refusal");
  const c = await rows("app.partner_credential", (sql) => sql`select sign_count::int as n from app.partner_credential where user_id = ${uid}`);
  assertEquals(c[0]!.n, 0, "the counter did not move");
});

Deno.test("mint: a replayed assertion is refused, the second presentation of a used challenge mints nothing", DT, async () => {
  const { auth, uid } = await enrol("ES256");
  const ch = await issue();
  const { presented } = await assertion(auth, ch);
  assertEquals((await mint(presented)).status, "ok");
  assertEquals((await mint(presented)).status, "replayed");
  const n = await rows("app.partner_session", (sql) => sql`select count(*)::int as n from app.partner_session where user_id = ${uid}`);
  assertEquals(n[0]!.n, 1);
});

Deno.test("mint: a counter that does not strictly increase is refused (equal and lower), and an alarm is raised", DT, async () => {
  const { auth, uid } = await enrol("ES256");
  const first = await assertion(auth, await issue(), { counter: 5 });
  assertEquals((await mint(first.presented)).status, "ok");
  const ch2 = await issue();
  const same = await assertion(auth, ch2, { counter: 5 });
  assertEquals((await mint(same.presented)).status, "counter_regression");
  const ch3 = await issue();
  const lower = await assertion(auth, ch3, { counter: 3 });
  assertEquals((await mint(lower.presented)).status, "counter_regression");
  const c = await rows("app.partner_credential", (sql) => sql`select sign_count::int as n from app.partner_credential where user_id = ${uid}`);
  assertEquals(c[0]!.n, 5);
  const alarms = await rows("app.partner_auth_alarm", (sql) =>
    sql`select count(*)::int as n from app.partner_auth_alarm a join app.partner_credential c on c.id = a.credential_id where c.user_id = ${uid} and a.kind = 'counter_regression'`);
  assertEquals(alarms[0]!.n, 1, "one alarm for the credential in this minute (the two refusals share a bucket)");
  const ok = await assertion(auth, await issue(), { counter: 6 });
  assertEquals((await mint(ok.presented)).status, "ok", "and a higher counter still mints");
});

Deno.test("mint: the structural refusals, each from an assertion that is otherwise valid and signed over its own bytes", DT, async () => {
  const cases: Array<[string, Build, string]> = [
    ["wrong origin", { origin: "https://evil.example.test" }, "bad_origin"],
    ["wrong RP ID hash", { rpIdHashOf: "other.example.test" }, "bad_rp_id_hash"],
    ["user not verified", { flags: { uv: false } }, "user_not_verified"],
    ["user not present", { flags: { up: false, uv: true } }, "user_not_present"],
    ["a registration-type clientDataJSON", { client: { type: "webauthn.create" } }, "bad_client_type"],
    ["crossOrigin true", { client: { crossOrigin: true } }, "cross_origin"],
  ];
  for (const [label, build, want] of cases) {
    const { auth, uid } = await enrol("ES256");
    const ch = await issue();
    const { presented } = await assertion(auth, ch, build);
    const r = await mint(presented);
    assertEquals(r.status, want, label);
    const n = await rows("app.partner_session", (sql) => sql`select count(*)::int as n from app.partner_session where user_id = ${uid}`);
    assertEquals(n[0]!.n, 0, label + ": no session");
  }
});

Deno.test("mint: a challenge the database did not issue (a tampered MAC or expiry) is refused before anything else", DT, async () => {
  const { auth } = await enrol("ES256");
  const ch = await issue();
  const badMac = { ...ch, mac: Uint8Array.from(ch.mac, (b, i) => (i === 3 ? b ^ 1 : b)) };
  const a = await assertion(auth, badMac);
  assertEquals((await mint(a.presented)).status, "bad_challenge");
  const ch2 = await issue();
  const badExp = { ...ch2, exp: (BigInt(ch2.exp) + 1n).toString() };
  const b = await assertion(auth, badExp);
  assertEquals((await mint(b.presented)).status, "bad_challenge");
});

Deno.test("mint: an unknown credential is a status, not an error", DT, async () => {
  const { auth } = await enrol("ES256");
  const ch = await issue();
  const { presented } = await assertion(auth, ch);
  const r = await mint({ ...presented, credentialId: crypto.getRandomValues(new Uint8Array(32)) });
  assertEquals(r.status, "unknown_credential");
});

Deno.test("teardown: the edge connection is closed", DT, async () => {
  await edge.end({ timeout: 1 });
});
