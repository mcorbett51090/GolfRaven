// supabase/tests/integration/signin-methods.deno.test.ts
//
// O12: `me-signin-methods` and the DELETE /v1/me provider-grant revocation — the REAL handlers (_shared/signin/, _shared/me/
// delete-orchestrator.ts) over the REAL privileged.ts Repo and the REAL 0035 definers, against the harness cluster tools/db/test.sh
// builds (same discipline as handlers.deno.test.ts / me-handlers.deno.test.ts: the Deno suite is what catches what a fake Repo
// cannot). Only the OUTSIDE world is synthetic: a synthetic Apple (a run-time-generated RSA key, a fake JWKS served through an
// injected `fetch`, identity tokens minted here) and a scripted email-OTP verifier. No secret exists anywhere in this file.
//
// Edge role PR4a (0039) adds the proof-bound cross-account link: the OTP-proven flow now runs in BOTH modes (the scripted verifier stamps
// auth.users.last_sign_in_at the way GoTrue is believed to), and the cells named "PR4a" prove the single-use proof against the real definers.
//
// Edge role PR #35 (0041) hardens it: the proof is MINTED by the dedicated role edge_signin_minter (an edge_system transaction can no longer mint), is bound to the
// GoTrue SESSION verifyOtp created (a row of auth.sessions that the scripted verifier inserts, and that `closeSession` removes after the mint), and the address / subject
// are normalised and hashed only in the database. The cells named "PR35" prove those against the real definers.
//
// What this proves that the vitest suite (same scenarios, fake Repo) cannot: the SQLSTATE -> HTTP mapping of the real definers,
// the real Vault KEK path (private.get_signin_token_kek, real envelope round trip through bytea columns), the real advisory-lock
// serialisation of concurrent unlinks, the real durable queue (a revocation row that survives the account's deletion), and the
// ordering "the provider is told BEFORE the provider rows are deleted" observed from inside the revoke call.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, makeActor, rawCount } from "./_helpers.ts";
import { hitRateLimitForActor, isServiceRoleBearer, loadAppleSiwaConfig, makeEmailOtpVerifier, openScopedTx, type OtpAuthClient, purgeSigninEmailProofs, type Repo, sessionIdOfAccessToken, signinEmailProofs, signinOtpFailuresFor, signinRevocationDb, withOwnership } from "../../functions/_shared/privileged.ts";
import { handleLinkProvider, handleListMethods, handleUnlinkProvider, type SigninDeps } from "../../functions/_shared/signin/methods-handler.ts";
import { orchestrateMeDelete } from "../../functions/_shared/me/delete-orchestrator.ts";
import { runRevocations, type RevocationDeps } from "../../functions/_shared/signin/revocation.ts";
import { buildSigninPorts } from "../../functions/_shared/signin/production.ts";
import { APPLE_JWKS_URL } from "../../functions/_shared/signin/apple-id-token.ts";
import { APPLE_REVOKE_URL, APPLE_TOKEN_URL } from "../../functions/_shared/signin/apple-client.ts";
import { decryptToken, encryptToken } from "../../functions/_shared/signin/envelope.ts";
import { sha256Hex } from "../../functions/_shared/signin/bytes.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import type { LinkRequest } from "../../functions/_shared/signin/request-shape.ts";
import type { EmailOtpVerifier } from "../../functions/_shared/signin/types.ts";
import type { AppleSecretConfig } from "../../functions/_shared/signin/apple-client-secret.ts";
import { CLIENT_ID, TEAM_ID, fakeFetch, json, jwksBody, makeP8, makeRsaKey, mintIdentityToken as mintFixed, type TokenOverrides, type TestRsaKey } from "../unit/signin-test-helpers.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const RAW_NONCE = "raw-nonce-0123456789";
const RUN = freshUuid().slice(0, 8);
const KEK_ID = `d${freshUuid().replace(/-/g, "").slice(0, 10)}`;

const PGHOST = Deno.env.get("PGHOST")!;
const PGPORT = Deno.env.get("PGPORT")!;
const PGUSER = Deno.env.get("PGUSER")!;
const PGDATABASE = Deno.env.get("PGDATABASE")!;

/** The unit helper mints against a FIXED clock; these tests run against the REAL clock (the production ports use Date.now()). */
const mintIdentityToken = (key: TestRsaKey, sub: string, o: TokenOverrides = {}) => {
  const nowSec = Math.floor(Date.now() / 1000);
  return mintFixed(key, sub, { ...o, claims: { iat: nowSec - 30, exp: nowSec + 600, ...o.claims } });
};

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────────────────────────
let appleKey: TestRsaKey;
let cfg: AppleSecretConfig;

async function setupOnce() {
  if (appleKey) return;
  appleKey = await makeRsaKey("apple-kid-it");
  const p8 = await makeP8();
  cfg = { teamId: TEAM_ID, clientId: CLIENT_ID, keyId: "KEYIDINTEG", privateKeyPem: p8.pem };
  await ensureServiceRole();
  const kek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  await adminSql()`insert into vault.secrets (name, secret, created_at) values (${"siwa_token_kek_" + KEK_ID}, ${kek}, now() + interval '1 day') on conflict (name) do nothing`;
}

/** A connection that can act as private_definer (the only role with any privilege on the revocation queue). */
async function asDefiner<T>(fn: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> {
  const sql = postgres({ host: PGHOST, port: Number(PGPORT), username: PGUSER, database: PGDATABASE, max: 1, prepare: false });
  try {
    return (await sql.begin(async (trx: ReturnType<typeof postgres>) => {
      await trx`set local role private_definer`;
      return fn(trx);
    })) as T;
  } finally {
    await sql.end({ timeout: 1 });
  }
}

interface AppleScript {
  /** The grants Apple hands out, in order. */
  nextRefreshToken: string;
  nextSubject: string;
  revoked: string[];
  revokeStatus: number;
  onRevoke?: (token: string) => Promise<void>;
}

function appleWorld(script: AppleScript) {
  const f = fakeFetch({
    [`GET ${APPLE_JWKS_URL}`]: () => json(200, jwksBody(appleKey)),
    [`POST ${APPLE_TOKEN_URL}`]: async () => json(200, { refresh_token: script.nextRefreshToken, id_token: await mintIdentityToken(appleKey, script.nextSubject, { omit: ["nonce"] }) }),
    [`POST ${APPLE_REVOKE_URL}`]: async (_u, init) => {
      const token = new URLSearchParams(init.body).get("token")!;
      script.revoked.push(token);
      if (script.onRevoke) await script.onRevoke(token);
      return script.revokeStatus === 200 ? new Response("", { status: 200 }) : json(script.revokeStatus, {});
    },
  });
  return { ports: buildSigninPorts(cfg, { fetch: f.fetch, nowMs: () => Date.now() }), calls: f.calls };
}

function depsFor(uid: string, world: ReturnType<typeof appleWorld>, otp: EmailOtpVerifier | null = null, log: Array<Record<string, unknown>> = []): SigninDeps {
  const actor = makeActor(uid);
  return {
    withRepo: (op) => withOwnership(actor, (repo) => op(repo.signin)),
    otpFailures: signinOtpFailuresFor(actor),
    apple: world.ports.apple,
    emailOtp: otp,
    emailProofs: signinEmailProofs(),
    revocation: { db: signinRevocationDb, apple: world.ports.apple, google: world.ports.google, log: (e) => log.push(e) },
    log: (e) => log.push(e),
  };
}

/** What GoTrue leaves behind when verifyOtp succeeds: the proven account has just signed in (`auth.users.last_sign_in_at`). The proof minter
 * corroborates the OTP against exactly this. `[unverified: real GoTrue is believed to stamp it; the harness stamps it by hand]` */
async function stampSignIn(uid: string, secondsAgo = 0): Promise<void> {
  await ensureServiceRole();
  await adminSql()`update auth.users set last_sign_in_at = clock_timestamp() - make_interval(secs => ${secondsAgo}::int) where id = ${uid}`;
}

/** What a verifier script says: a wrong code, or a correct one for this account. */
type OtpScript = { ok: false } | { ok: true; userId: string };

/** What GoTrue's verifyOtp leaves in auth.sessions for the proven account (0041, (b)); the harness inserts it by hand. `[unverified: real GoTrue creates it]` */
async function newSession(uid: string, secondsAgo = 0): Promise<string> {
  await ensureServiceRole();
  const id = freshUuid();
  await adminSql()`insert into auth.sessions (id, user_id, created_at) values (${id}, ${uid}, clock_timestamp() - make_interval(secs => ${secondsAgo}::int))`;
  return id;
}
const sessionExists = async (id: string): Promise<boolean> => (await rawCount(`select count(*) as n from auth.sessions where id = '${id}'`)) === 1;

/** The failure counter's bucket key (0041, L2): the TARGET ACCOUNT, not a spelling of its address. */
const otpKey = (targetUid: string): Promise<string> => sha256Hex(`signin-otp-target:${targetUid}`);

/** A scripted verifier that behaves like GoTrue: a `res.ok` proof also stamps the proven account's sign-in AND creates its session (the one the proof will be
 * bound to), and hands the caller a `closeSession` that deletes exactly that session, the way a scope-local sign-out does. `stamp = false` is a verifier that
 * "verified" with no sign-in and no session behind it. `sessionIds` / `signouts` record what it created and what was signed out. */
const gotrueLike = (res: OtpScript, calls: string[], stamp = true, sessionIds: string[] = [], signouts: string[] = []): EmailOtpVerifier => ({
  async verify(email) {
    calls.push(email);
    if (!res.ok) return { ok: false };
    let sid: string = freshUuid(); // with stamp = false: a session id that does not exist
    if (stamp) {
      await stampSignIn(res.userId);
      sid = await newSession(res.userId);
    }
    sessionIds.push(sid);
    return {
      ok: true,
      userId: res.userId,
      sessionId: sid,
      async closeSession() {
        signouts.push(sid);
        await adminSql()`delete from auth.sessions where id = ${sid}`;
      },
    };
  },
});

const ENVELOPE = () => ({ ciphertext: new Uint8Array(40).fill(7), dekWrapped: new Uint8Array(70).fill(9), kekId: KEK_ID });

/** Proof rows of an account, as private_definer through the account-deletion window (the only way a definer can list them). */
type ProofRow = Record<string, string | boolean>;
const proofRows = (uid: string): Promise<ProofRow[]> =>
  asDefiner(async (sql) => {
    await sql`select set_config('app.delete_my_data.target_user_id', ${uid}, true)`;
    return (await sql`select id, caller_user_id, target_user_id, provider, email_hash, sub_hash, consumed_at is not null as consumed, expires_at > now() as live, expires_at <= created_at + interval '10 minutes' as capped from private.signin_email_proof where caller_user_id = ${uid} or target_user_id = ${uid} order by created_at, id`) as unknown as ProofRow[];
  });

async function newUser(label: string, extraIdentities: Array<{ provider: string; subject: string }> = []) {
  const uid = freshUuid();
  await createTestUser(uid, `signin-${label}-${uid.slice(0, 8)}`);
  const email = `signin-${label}-${uid.slice(0, 8)}@integration.test`;
  await adminSql()`insert into auth.identities (provider_id, user_id, identity_data, provider) values (${email}, ${uid}, ${JSON.stringify({ email, email_verified: true })}::jsonb, 'email')`;
  for (const i of extraIdentities) {
    await adminSql()`insert into auth.identities (provider_id, user_id, identity_data, provider) values (${i.subject}, ${uid}, ${JSON.stringify({ email })}::jsonb, ${i.provider})`;
  }
  return { uid, email };
}

const linkReq = async (over: Partial<LinkRequest> = {}): Promise<LinkRequest> => ({
  action: "link",
  provider: "apple",
  identityToken: await mintIdentityToken(appleKey, "sub-default", { rawNonce: RAW_NONCE }),
  authorizationCode: "code-1",
  nonce: RAW_NONCE,
  ...over,
});

async function linkAs(uid: string, sub: string, over: { email?: string | null; refresh: string; world?: ReturnType<typeof appleWorld>; script?: AppleScript }) {
  const script: AppleScript = over.script ?? { nextRefreshToken: over.refresh, nextSubject: sub, revoked: [], revokeStatus: 200 };
  const world = over.world ?? appleWorld(script);
  const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, ...(over.email === null ? { omit: ["email", "email_verified"] } : over.email ? { claims: { email: over.email } } : {}) });
  return { script, world, result: await handleLinkProvider(await linkReq({ identityToken: token }), uid, depsFor(uid, world)) };
}

async function httpError(p: Promise<unknown>): Promise<HttpError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof HttpError) return e;
    throw e;
  }
  throw new Error("expected an HttpError");
}

const identityCount = (uid: string) => rawCount(`select count(*) as n from auth.identities where user_id = '${uid}'`);
const tokenCount = (uid: string) => rawCount(`select count(*) as n from app.signin_provider_token where user_id = '${uid}'`);

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Deno.test("link: Apple links to the caller; the refresh token is stored ENVELOPE-ENCRYPTED and decrypts only with the Vault KEK", DT, async () => {
  await setupOnce();
  const u = await newUser("link");
  const { result, script } = await linkAs(u.uid, `apple-sub-link-${RUN}`, { email: u.email, refresh: "r.integration-refresh-1" });
  assertEquals(result.linkedTo, "self");
  assertEquals(result.linked.created, true);
  assertEquals(result.methods!.map((m) => m.provider).sort(), ["apple", "email"]);
  assertEquals(script.revoked, []);
  assertEquals(await identityCount(u.uid), 2);

  // the stored row: ciphertext + wrapped DEK + kek id, no plaintext anywhere
  const rows = await adminSql()`select refresh_token_ciphertext, dek_wrapped, kek_id from app.signin_provider_token where user_id = ${u.uid} and provider = 'apple'`;
  assertEquals(rows.length, 1);
  const row = rows[0]!;
  const ct = new Uint8Array(row.refresh_token_ciphertext);
  assert(!new TextDecoder("latin1").decode(ct).includes("integration-refresh"), "the plaintext refresh token must not appear in the stored ciphertext");
  assertEquals(row.kek_id, KEK_ID, "the NEWEST Vault KEK wraps a new DEK");
  // decrypt exactly as the revocation runner will: KEK from the real definer, envelope from the real row
  const kekRows = await adminSql()`select o_kek_id, o_kek_b64 from private.get_signin_token_kek(${KEK_ID}::text)`;
  const raw = Uint8Array.from(atob(kekRows[0]!.o_kek_b64), (c) => c.charCodeAt(0));
  const plain = await decryptToken({ ciphertext: ct, dekWrapped: new Uint8Array(row.dek_wrapped), kekId: row.kek_id }, "apple", { kekId: KEK_ID, key: raw });
  assertEquals(plain, "r.integration-refresh-1");

  const list = await handleListMethods(depsFor(u.uid, appleWorld({ nextRefreshToken: "", nextSubject: "", revoked: [], revokeStatus: 200 })));
  assertEquals(list.methods.length, 2);
  assertEquals(list.methods.every((m) => m.canUnlink), true);
});

Deno.test("link: a re-capture of the SAME identity is idempotent and queues the superseded token for revocation", DT, async () => {
  await setupOnce();
  const u = await newUser("recapture");
  await linkAs(u.uid, `apple-sub-rc-${RUN}`, { email: u.email, refresh: "r.first" });
  const second = await linkAs(u.uid, `apple-sub-rc-${RUN}`, { email: u.email, refresh: "r.second" });
  assertEquals(second.result.linked.created, false);
  assertEquals(await identityCount(u.uid), 2);
  assertEquals(await tokenCount(u.uid), 1);
  // the queued row is the OLD envelope (its fingerprint is not the live row's), pending, source 'replaced'
  const live = await adminSql()`select md5(refresh_token_ciphertext) as fp from app.signin_provider_token where user_id = ${u.uid} and provider = 'apple'`;
  const old = await asDefiner(async (sql) => await sql`select token_fingerprint, status, source from private.signin_revocation_queue where source = 'replaced' and status = 'pending' and provider = 'apple'`);
  assert(old.length >= 1, "the superseded refresh token must be queued for revocation");
  assert(old.every((r) => r.token_fingerprint !== live[0]!.fp), "the queue holds the superseded envelope, never the live one");
});

Deno.test("link: Apple UNCONFIGURED (any of the four GR_APPLE_* values absent or blank) -> 503, never a fallback", DT, async () => {
  const keys = ["GR_APPLE_TEAM_ID", "GR_APPLE_SIWA_CLIENT_ID", "GR_APPLE_SIWA_KEY_ID", "GR_APPLE_SIWA_PRIVATE_KEY"];
  const saved = keys.map((k) => [k, Deno.env.get(k)] as const);
  try {
    for (const k of keys) Deno.env.delete(k);
    assertEquals(loadAppleSiwaConfig(), null);
    // partially set is still unconfigured
    Deno.env.set("GR_APPLE_TEAM_ID", "T");
    Deno.env.set("GR_APPLE_SIWA_CLIENT_ID", "C");
    Deno.env.set("GR_APPLE_SIWA_KEY_ID", "K");
    assertEquals(loadAppleSiwaConfig(), null, "three of four is not configured");
    Deno.env.set("GR_APPLE_SIWA_PRIVATE_KEY", "   ");
    assertEquals(loadAppleSiwaConfig(), null, "a blank key is not configured");
    const ports = buildSigninPorts(loadAppleSiwaConfig(), { fetch: fakeFetch({}).fetch, nowMs: () => Date.now() });
    assertEquals(ports.apple, null);
    const u = await newUser("unconfigured");
    const deps: SigninDeps = { ...depsFor(u.uid, { ports, calls: [] }), apple: null };
    const e = await httpError(handleLinkProvider(await linkReq(), u.uid, deps));
    assertEquals([e.status, e.code], [503, "provider_not_configured"]);
    assertEquals(await identityCount(u.uid), 1, "nothing was linked");
    // and a fully-set environment is read as configured
    Deno.env.set("GR_APPLE_SIWA_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----");
    assertEquals(loadAppleSiwaConfig()?.keyId, "K");
  } finally {
    for (const [k, v] of saved) v === undefined ? Deno.env.delete(k) : Deno.env.set(k, v);
  }
});

Deno.test("link: an Apple email that matches ANOTHER account is never auto-linked (real auth.users lookup); nothing is written", DT, async () => {
  await setupOnce();
  const alice = await newUser("al");
  const bob = await newUser("bo");
  const script: AppleScript = { nextRefreshToken: "r.should-not-exist", nextSubject: `apple-sub-collide-${RUN}`, revoked: [], revokeStatus: 200 };
  const world = appleWorld(script);
  const token = await mintIdentityToken(appleKey, `apple-sub-collide-${RUN}`, { rawNonce: RAW_NONCE, claims: { email: bob.email.toUpperCase() } });
  const e = await httpError(handleLinkProvider(await linkReq({ identityToken: token }), alice.uid, depsFor(alice.uid, world)));
  // the answer is a proof request (the 501 an edge-mode runtime used to answer here is gone, 0039)
  assertEquals([e.status, e.code], [409, "email_proof_required"]);
  assertEquals(await identityCount(alice.uid), 1);
  assertEquals(await identityCount(bob.uid), 1);
  assertEquals(await rawCount(`select count(*) as n from auth.identities where provider = 'apple' and provider_id = 'apple-sub-collide-${RUN}'`), 0);
  assertEquals(world.calls.filter((c) => c.url === APPLE_TOKEN_URL).length, 0, "no authorization code was exchanged");
});

Deno.test("link: with a valid email-OTP proof the identity goes to the account whose mailbox was proven; failed proofs are counted per target email (5/hour)", DT, async () => {
  await setupOnce();
  const alice = await newUser("pa");
  const bob = await newUser("pb");
  // A verifier that behaves like GoTrue: a correct code also stamps the proven account's sign-in (what the edge-mode proof minter corroborates).
  const mk = (res: OtpScript, calls: string[]): EmailOtpVerifier => gotrueLike(res, calls);
  const sub = `apple-sub-proof-${freshUuid().slice(0, 8)}`;

  // five wrong proofs
  for (let i = 0; i < 5; i++) {
    const script: AppleScript = { nextRefreshToken: "r.p", nextSubject: sub, revoked: [], revokeStatus: 200 };
    const world = appleWorld(script);
    const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: bob.email } });
    const e = await httpError(handleLinkProvider({ ...(await linkReq({ identityToken: token })), emailProof: { code: "000000" } }, alice.uid, depsFor(alice.uid, world, mk({ ok: false }, []))));
    assertEquals([e.status, e.code], [422, "email_proof_invalid"]);
  }
  const hash = await otpKey(bob.uid);
  assertEquals(await signinOtpFailuresFor(makeActor(alice.uid)).peek(hash), 5);
  assertEquals(await identityCount(bob.uid), 1, "no wrong proof linked anything");

  // the sixth attempt is refused even with a CORRECT proof, and the verifier is never called
  const calls: string[] = [];
  const script6: AppleScript = { nextRefreshToken: "r.p", nextSubject: sub, revoked: [], revokeStatus: 200 };
  const world6 = appleWorld(script6);
  const token6 = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: bob.email } });
  const e6 = await httpError(handleLinkProvider({ ...(await linkReq({ identityToken: token6 })), emailProof: { code: "123456" } }, alice.uid, depsFor(alice.uid, world6, mk({ ok: true, userId: bob.uid }, calls))));
  assertEquals([e6.status, e6.code], [429, "rate_limited"]);
  assertEquals(calls, []);

  // a DIFFERENT target address is unaffected: Carol proves her own mailbox and Apple is linked to Carol, not to the caller
  const carol = await newUser("pc");
  const csub = `apple-sub-carol-${freshUuid().slice(0, 8)}`;
  const scriptC: AppleScript = { nextRefreshToken: "r.carol", nextSubject: csub, revoked: [], revokeStatus: 200 };
  const worldC = appleWorld(scriptC);
  const tokenC = await mintIdentityToken(appleKey, csub, { rawNonce: RAW_NONCE, claims: { email: carol.email } });
  const ok = await handleLinkProvider({ ...(await linkReq({ identityToken: tokenC })), emailProof: { code: "654321" } }, alice.uid, depsFor(alice.uid, worldC, mk({ ok: true, userId: carol.uid }, [])));
  assertEquals(ok.linkedTo, "proven_account");
  assertEquals(ok.methods, null);
  assertEquals(await rawCount(`select count(*) as n from auth.identities where user_id = '${carol.uid}' and provider = 'apple'`), 1);
  assertEquals(await rawCount(`select count(*) as n from auth.identities where user_id = '${alice.uid}' and provider = 'apple'`), 0);
  assertEquals(await tokenCount(carol.uid), 1);
  assertEquals(await tokenCount(alice.uid), 0);
});

Deno.test("link: an Apple identity that belongs to ANOTHER account is never moved (23505 -> 409) and the grant minted for it is revoked", DT, async () => {
  await setupOnce();
  const owner = await newUser("own", [{ provider: "apple", subject: `apple-sub-owned-${RUN}` }]);
  const intruder = await newUser("int");
  const script: AppleScript = { nextRefreshToken: "r.intruder-grant", nextSubject: `apple-sub-owned-${RUN}`, revoked: [], revokeStatus: 200 };
  const world = appleWorld(script);
  const token = await mintIdentityToken(appleKey, `apple-sub-owned-${RUN}`, { rawNonce: RAW_NONCE, omit: ["email", "email_verified"] });
  const e = await httpError(handleLinkProvider(await linkReq({ identityToken: token }), intruder.uid, depsFor(intruder.uid, world)));
  assertEquals([e.status, e.code], [409, "identity_conflict"]);
  assertEquals(await rawCount(`select count(*) as n from auth.identities where provider = 'apple' and provider_id = 'apple-sub-owned-${RUN}' and user_id = '${owner.uid}'`), 1);
  assertEquals(await tokenCount(intruder.uid), 0);
  assertEquals(script.revoked, ["r.intruder-grant"], "the stray grant was revoked rather than left live and unrecorded");
});

Deno.test("link: a DIFFERENT Apple ID on the same account is 409 provider_already_linked; the KEK missing is 503 kek_unavailable and revokes the grant", DT, async () => {
  await setupOnce();
  const u = await newUser("two");
  await linkAs(u.uid, `apple-sub-two-a-${RUN}`, { email: u.email, refresh: "r.two-a" });
  const second = await httpError(linkAs(u.uid, `apple-sub-two-b-${RUN}`, { email: u.email, refresh: "r.two-b" }));
  assertEquals([second.status, second.code], [409, "provider_already_linked"]);

  const v = await newUser("nokek");
  await adminSql()`update vault.secrets set name = ${"disabled_" + KEK_ID} where name = ${"siwa_token_kek_" + KEK_ID}`;
  try {
    const script: AppleScript = { nextRefreshToken: "r.nokek", nextSubject: `apple-sub-nokek-${RUN}`, revoked: [], revokeStatus: 200 };
    const err = await httpError(linkAs(v.uid, `apple-sub-nokek-${RUN}`, { email: null, refresh: "r.nokek", script }));
    assertEquals([err.status, err.code], [503, "kek_unavailable"]);
    assertEquals(script.revoked, ["r.nokek"]);
    assertEquals(await identityCount(v.uid), 1);
  } finally {
    await adminSql()`update vault.secrets set name = ${"siwa_token_kek_" + KEK_ID} where name = ${"disabled_" + KEK_ID}`;
  }
});

Deno.test("unlink: only while another method remains (422), never someone else's (404), and the Apple grant is revoked with the right token", DT, async () => {
  await setupOnce();
  const a = await newUser("ul");
  const b = await newUser("ub", [{ provider: "google", subject: `g-${freshUuid().slice(0, 8)}` }]);
  await linkAs(a.uid, `apple-sub-ul-${RUN}`, { email: a.email, refresh: "r.unlink-token" });
  const script: AppleScript = { nextRefreshToken: "", nextSubject: "", revoked: [], revokeStatus: 200 };
  const world = appleWorld(script);
  const deps = depsFor(a.uid, world);

  // another account's method through this account: 404, and B's identity is untouched
  const notMine = await httpError(handleUnlinkProvider({ action: "unlink", provider: "google" }, deps));
  assertEquals(notMine.status, 404);
  assertEquals(await rawCount(`select count(*) as n from auth.identities where user_id = '${b.uid}' and provider = 'google'`), 1);

  // apple unlinks while email remains: grant revoked at Apple with the DECRYPTED token, identity and grant row gone
  const r = await handleUnlinkProvider({ action: "unlink", provider: "apple" }, deps);
  assertEquals(script.revoked, ["r.unlink-token"]);
  assertEquals(r.revocation.map((o) => o.status), ["revoked"]);
  assertEquals(r.methods.map((m) => m.provider), ["email"]);
  assertEquals(await tokenCount(a.uid), 0);
  assertEquals(await identityCount(a.uid), 1);

  // the last method
  const last = await httpError(handleUnlinkProvider({ action: "unlink", provider: "email" }, deps));
  assertEquals([last.status, last.code], [422, "last_sign_in_method"]);
  assertEquals(await identityCount(a.uid), 1);
});

Deno.test("unlink: a failing Apple revoke does not undo the unlink: the row stays queued with its envelope and the retry (drain) revokes it later", DT, async () => {
  await setupOnce();
  const u = await newUser("ulf");
  await linkAs(u.uid, `apple-sub-ulf-${RUN}`, { email: u.email, refresh: "r.retry-me" });
  const script: AppleScript = { nextRefreshToken: "", nextSubject: "", revoked: [], revokeStatus: 503 };
  const world = appleWorld(script);
  const r = await handleUnlinkProvider({ action: "unlink", provider: "apple" }, depsFor(u.uid, world));
  assertEquals(r.methods.map((m) => m.provider), ["email"]);
  assertEquals(r.revocation.map((o) => [o.status, o.error]), [["queued_for_retry", "revoke_5xx"]]);
  const qid = r.revocation[0]!.queueId;
  const row = await asDefiner(async (sql) => (await sql`select status, attempts, last_error, refresh_token_ciphertext is not null as has_material, next_attempt_at > now() as backed_off from private.signin_revocation_queue where id = ${qid}`)[0]!);
  assertEquals([row.status, row.attempts, row.last_error, row.has_material, row.backed_off], ["pending", 1, "revoke_5xx", true, true]);

  // not due yet: a drain run does nothing; once due, Apple answers 200 and the row closes
  const drainDeps: RevocationDeps = { db: signinRevocationDb, apple: world.ports.apple, google: world.ports.google, log: () => {} };
  assertEquals((await runRevocations(drainDeps, { ids: [qid] })).length, 0);
  await asDefiner(async (sql) => await sql`update private.signin_revocation_queue set next_attempt_at = now() - interval '1 minute' where id = ${qid}`);
  script.revokeStatus = 200;
  const done = await runRevocations(drainDeps, { ids: [qid] });
  assertEquals(done.map((o) => o.status), ["revoked"]);
  assertEquals(script.revoked, ["r.retry-me", "r.retry-me"]);
  const closed = await asDefiner(async (sql) => (await sql`select status, refresh_token_ciphertext is null and dek_wrapped is null and kek_id is null as wiped from private.signin_revocation_queue where id = ${qid}`)[0]!);
  assertEquals([closed.status, closed.wiped], ["revoked", true]);
});

Deno.test("claim: a queue row another worker is holding is SKIPPED, never waited for (FOR UPDATE SKIP LOCKED)", DT, async () => {
  await setupOnce();
  const u = await newUser("skip");
  await linkAs(u.uid, `apple-sub-skip-${RUN}`, { email: u.email, refresh: "r.skip-me" });
  const world = appleWorld({ nextRefreshToken: "", nextSubject: "", revoked: [], revokeStatus: 503 });
  const r = await handleUnlinkProvider({ action: "unlink", provider: "apple" }, depsFor(u.uid, world));
  const qid = r.revocation[0]!.queueId;
  await asDefiner(async (sql) => await sql`update private.signin_revocation_queue set next_attempt_at = now() - interval '1 minute' where id = ${qid}`);
  // worker A holds the row (its transaction is open); worker B claims through the real privileged path and must not block on it
  await asDefiner(async (sql) => {
    await sql`select id from private.signin_revocation_queue where id = ${qid} for update`;
    const t0 = Date.now();
    const got = await signinRevocationDb.claim([qid], 5, 60);
    assertEquals(got.length, 0, "the row held by another worker is not claimed");
    assert(Date.now() - t0 < 3000, `the claim returned in ${Date.now() - t0} ms: it did not wait for the lock`);
  });
  // once the other worker is done with it, it is claimable again
  const after = await signinRevocationDb.claim([qid], 5, 60);
  assertEquals(after.length, 1);
});

Deno.test("unlink: concurrent unlinks of a two-method account leave exactly one method (advisory lock, no read-modify-write race)", DT, async () => {
  await setupOnce();
  for (let round = 0; round < 3; round++) {
    const u = await newUser(`race${round}`);
    await linkAs(u.uid, `apple-sub-race-${round}-${freshUuid().slice(0, 6)}`, { email: u.email, refresh: `r.race-${round}` });
    const world = appleWorld({ nextRefreshToken: "", nextSubject: "", revoked: [], revokeStatus: 200 });
    const settled = await Promise.allSettled([
      handleUnlinkProvider({ action: "unlink", provider: "email" }, depsFor(u.uid, world)),
      handleUnlinkProvider({ action: "unlink", provider: "apple" }, depsFor(u.uid, world)),
    ]);
    assertEquals(settled.filter((s) => s.status === "fulfilled").length, 1, "exactly one of the two unlinks may win");
    const loser = settled.find((s) => s.status === "rejected") as PromiseRejectedResult;
    assert(loser.reason instanceof HttpError && loser.reason.status === 422, "the loser is the 422 last_sign_in_method");
    assertEquals(await identityCount(u.uid), 1, "an account is never left with zero methods");
  }
});

Deno.test("DELETE /v1/me: the provider is told BEFORE the provider rows are deleted; the queue row survives the deletion", DT, async () => {
  await setupOnce();
  const u = await newUser("del");
  await linkAs(u.uid, `apple-sub-del-${RUN}`, { email: u.email, refresh: "r.delete-token" });
  let grantRowsWhenApplePolled = -1;
  const script: AppleScript = {
    nextRefreshToken: "",
    nextSubject: "",
    revoked: [],
    revokeStatus: 200,
    onRevoke: async () => {
      grantRowsWhenApplePolled = await tokenCount(u.uid);
    },
  };
  const world = appleWorld(script);
  const log: Array<Record<string, unknown>> = [];
  const out = await orchestrateMeDelete({
    withRepo: (op) => withOwnership(makeActor(u.uid), op),
    revocation: { db: signinRevocationDb, apple: world.ports.apple, google: world.ports.google, log: (e) => log.push(e) },
  });
  assertEquals(script.revoked, ["r.delete-token"], "Apple's revoke endpoint was called with the stored (decrypted) token");
  assertEquals(grantRowsWhenApplePolled, 1, "at the moment Apple was called the grant row still existed: revocation precedes deletion");
  assertEquals(out.signinProvidersRevoked.map((o) => [o.provider, o.status]), [["apple", "revoked"]]);
  assertEquals(await tokenCount(u.uid), 0, "the grant row is deleted afterwards");
  assertEquals(await rawCount(`select count(*) as n from app.profile where user_id = '${u.uid}'`), 0, "the account's personal rows are gone");
  assert(log.some((e) => e.event === "signin_revocation" && e.outcome === "revoked"));
  const q = await asDefiner(async (sql) => (await sql`select status, source from private.signin_revocation_queue where id = ${out.signinProvidersRevoked[0]!.queueId}`)[0]!);
  assertEquals([q.status, q.source], ["revoked", "account_delete"]);
});

Deno.test("DELETE /v1/me: a FAILED revocation still deletes the account, queues the retry with the envelope, logs it, and the retry later revokes it", DT, async () => {
  await setupOnce();
  const u = await newUser("delf");
  await linkAs(u.uid, `apple-sub-delf-${RUN}`, { email: u.email, refresh: "r.delete-fail-token" });
  const script: AppleScript = { nextRefreshToken: "", nextSubject: "", revoked: [], revokeStatus: 500 };
  const world = appleWorld(script);
  const log: Array<Record<string, unknown>> = [];
  const out = await orchestrateMeDelete({
    withRepo: (op) => withOwnership(makeActor(u.uid), op),
    revocation: { db: signinRevocationDb, apple: world.ports.apple, google: world.ports.google, log: (e) => log.push(e) },
  });
  // the deletion completed
  assertEquals(await rawCount(`select count(*) as n from app.profile where user_id = '${u.uid}'`), 0);
  assertEquals(await tokenCount(u.uid), 0);
  // the failure is reported, logged, and durably queued with everything the retry needs and NO user id
  const o = out.signinProvidersRevoked[0]!;
  assertEquals([o.status, o.error], ["queued_for_retry", "revoke_5xx"]);
  assert(log.some((e) => e.event === "signin_revocation" && e.outcome === "retry" && e.error === "revoke_5xx"), "the failure is logged");
  assert(!JSON.stringify(log).includes("delete-fail-token"), "the token is never logged");
  const q = await asDefiner(async (sql) => (await sql`select status, attempts, refresh_token_ciphertext is not null as has_material, expires_at > now() + interval '71 hours' as window_ok from private.signin_revocation_queue where id = ${o.queueId}`)[0]!);
  assertEquals([q.status, q.attempts, q.has_material, q.window_ok], ["pending", 1, true, true]);
  // retry after the backoff, Apple healthy again
  await asDefiner(async (sql) => await sql`update private.signin_revocation_queue set next_attempt_at = now() - interval '1 second' where id = ${o.queueId}`);
  script.revokeStatus = 200;
  const retried = await runRevocations({ db: signinRevocationDb, apple: world.ports.apple, google: world.ports.google, log: () => {} }, { ids: [o.queueId] });
  assertEquals(retried.map((r) => r.status), ["revoked"]);
  assertEquals(script.revoked, ["r.delete-fail-token", "r.delete-fail-token"]);

  // a retry of the WHOLE delete request on the already-deleted account is a clean no-op
  const again = await orchestrateMeDelete({
    withRepo: (op) => withOwnership(makeActor(u.uid), op),
    revocation: { db: signinRevocationDb, apple: world.ports.apple, google: world.ports.google, log: () => {} },
  });
  assertEquals(again.signinProvidersRevoked, []);
});

Deno.test("DELETE /v1/me: Apple UNCONFIGURED never blocks the deletion; the grant is queued as not_configured_apple", DT, async () => {
  await setupOnce();
  const u = await newUser("delu");
  await linkAs(u.uid, `apple-sub-delu-${RUN}`, { email: u.email, refresh: "r.unconfigured-token" });
  const out = await orchestrateMeDelete({
    withRepo: (op) => withOwnership(makeActor(u.uid), op),
    revocation: { db: signinRevocationDb, apple: null, google: null, log: () => {} },
  });
  assertEquals(await rawCount(`select count(*) as n from app.profile where user_id = '${u.uid}'`), 0);
  assertEquals(out.signinProvidersRevoked.map((o) => [o.status, o.error]), [["queued_for_retry", "not_configured_apple"]]);
});

Deno.test("the OTP failure counter and the 10/user/h linking limit are real and per-key", DT, async () => {
  await setupOnce();
  const u = await newUser("rl");
  const counter = signinOtpFailuresFor(makeActor(u.uid));
  const h = await sha256Hex(`otp-${freshUuid()}@x.test`);
  for (let i = 1; i <= 5; i++) assertEquals((await counter.reserve(h))?.used, i);
  assertEquals(await counter.reserve(h), null, "the cap is 5 and the sixth is refused");
  assertEquals(await counter.peek(h), 5);
  assertEquals(await counter.peek(await sha256Hex(`other-${freshUuid()}@x.test`)), 0);

  const actor = makeActor(u.uid);
  for (let i = 1; i <= 10; i++) assertEquals((await hitRateLimitForActor(actor, "me-signin-methods:user", 3600, 10)).ok, true, `hit ${i} is within 10/user/h`);
  const eleventh = await hitRateLimitForActor(actor, "me-signin-methods:user", 3600, 10);
  assertEquals(eleventh.ok, false);
  const other = await newUser("rl2");
  assertEquals((await hitRateLimitForActor(makeActor(other.uid), "me-signin-methods:user", 3600, 10)).ok, true, "another user's bucket is independent");
});

Deno.test("the revocation drain authenticates by the service-role key only (constant-time bearer compare)", DT, () => {
  const saved = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  try {
    Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-only-bearer-value-0123456789");
    const req = (auth: string | null) => new Request("http://x.test/", { method: "POST", headers: auth === null ? {} : { Authorization: auth } });
    assertEquals(isServiceRoleBearer(req("Bearer test-only-bearer-value-0123456789")), true);
    for (const bad of [null, "", "Bearer ", "Bearer wrong", "bearer test-only-bearer-value-012345678", "Bearer test-only-bearer-value-01234567890", "Basic test-only-bearer-value-0123456789", "test-only-bearer-value-0123456789"]) {
      assertEquals(isServiceRoleBearer(req(bad)), false, `rejects ${JSON.stringify(bad)}`);
    }
    Deno.env.delete("SUPABASE_SERVICE_ROLE_KEY");
    assertEquals(isServiceRoleBearer(req("Bearer ")), false, "an unset key admits nobody, not even an empty bearer");
  } finally {
    if (saved === undefined) Deno.env.delete("SUPABASE_SERVICE_ROLE_KEY");
    else Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", saved);
  }
});

// ── round 2 (security gate F3-F7) ──────────────────────────────────────────────────────────────────────────────────────
Deno.test("F3: 20 PARALLEL wrong email proofs reach the verifier exactly 5 times (the attempt is reserved atomically, not read then written)", DT, async () => {
  await setupOnce();
  const alice = await newUser("f3a");
  const bob = await newUser("f3b");
  let verifierCalls = 0;
  const slow: EmailOtpVerifier = {
    async verify() {
      verifierCalls++;
      await new Promise((r) => setTimeout(r, 25)); // a real network round trip: the window a check-then-act counter loses
      return { ok: false };
    },
  };
  const sub = `apple-sub-f3-${freshUuid().slice(0, 8)}`;
  const attempt = async () => {
    const script: AppleScript = { nextRefreshToken: "r.f3", nextSubject: sub, revoked: [], revokeStatus: 200 };
    const world = appleWorld(script);
    const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: bob.email } });
    return httpError(handleLinkProvider({ ...(await linkReq({ identityToken: token })), emailProof: { code: "000000" } }, alice.uid, depsFor(alice.uid, world, slow)));
  };
  const results = await Promise.all(Array.from({ length: 20 }, attempt));
  assertEquals(verifierCalls, 5, "no more than 5 wrong proofs ever reach the verifier");
  assertEquals(results.filter((e) => e.status === 422).length, 5);
  assertEquals(results.filter((e) => e.status === 429).length, 15);
  assertEquals(await signinOtpFailuresFor(makeActor(alice.uid)).peek(await otpKey(bob.uid)), 5);
  assertEquals(await identityCount(bob.uid), 1, "nothing was linked");
});

Deno.test("F3: a SUCCESSFUL proof gives its attempt back; a transport failure is not a failure", DT, async () => {
  await setupOnce();
  const u = await newUser("f3c");
  const counter = signinOtpFailuresFor(makeActor(u.uid));
  const h = await sha256Hex(`f3-${freshUuid()}@x.test`);
  const first = await counter.reserve(h);
  assertEquals(first?.used, 1);
  await counter.release(h, first!.windowStart);
  assertEquals(await counter.peek(h), 0);
  let last = first;
  for (let i = 1; i <= 5; i++) {
    last = await counter.reserve(h);
    assertEquals(last?.used, i);
  }
  assertEquals(await counter.reserve(h), null, "the sixth is refused and takes nothing");
  assertEquals(await counter.peek(h), 5);
  await counter.release(h, last!.windowStart);
  assertEquals((await counter.reserve(h))?.used, 5, "a released attempt can be taken again");
});

Deno.test("L2: a release names the window the attempt was reserved in; releasing an OLDER window (the hour rolled over) does not refund the current one", DT, async () => {
  await setupOnce();
  const u = await newUser("l2");
  const counter = signinOtpFailuresFor(makeActor(u.uid));
  const h = await sha256Hex(`l2-${freshUuid()}@x.test`);
  const a = await counter.reserve(h);
  const b = await counter.reserve(h);
  assertEquals([a?.used, b?.used], [1, 2]);
  assertEquals(a!.windowStart, b!.windowStart, "both attempts are charged to the same hour window");
  const win = Date.parse(a!.windowStart);
  assertEquals(win % 3_600_000, 0, "the window is hour-aligned");
  // the reservation was taken in the PREVIOUS hour (as if the proof straddled the top of the hour): this window is not the current one
  const prev = new Date(win - 3_600_000).toISOString();
  await counter.release(h, prev);
  assertEquals(await counter.peek(h), 2, "the current window was NOT refunded by a release that names an older one");
  await counter.release(h, a!.windowStart);
  assertEquals(await counter.peek(h), 1, "a release naming the window it was reserved in does refund it");
  // the database refuses a window no reserve could have returned
  let code: unknown = null;
  try {
    await counter.release(h, new Date(win + 1_000).toISOString());
  } catch (e) {
    code = (e as { code?: unknown } | null)?.code;
  }
  assertEquals(code, "22023", "a window that is not hour-aligned is refused");
});

Deno.test("F4: the repo REFUSES to link or store a grant for ANOTHER account, called directly on the repo (mustBeSelf: only a proof links another account)", DT, async () => {
  await setupOnce();
  const alice = await newUser("f4a");
  const bob = await newUser("f4b");
  const input = { provider: "apple" as const, subject: `apple-sub-f4-${freshUuid().slice(0, 8)}`, email: null, emailVerified: false, isPrivateRelay: false };
  const env = { ciphertext: new Uint8Array(40).fill(7), dekWrapped: new Uint8Array(70).fill(9), kekId: KEK_ID };
  const link = await httpError(withOwnership(makeActor(alice.uid), (repo) => repo.signin.linkIdentity(bob.uid, input)));
  assertEquals([link.status, link.code], [403, "cross_account_link_requires_proof"]);
  const store = await httpError(withOwnership(makeActor(alice.uid), (repo) => repo.signin.storeToken(bob.uid, "apple", env)));
  assertEquals([store.status, store.code], [403, "cross_account_link_requires_proof"]);
  assertEquals(await identityCount(bob.uid), 1, "nothing was linked to Bob");
  assertEquals(await tokenCount(bob.uid), 0, "no grant was stored for Bob");
  // linking to SELF still works
  assertEquals(await withOwnership(makeActor(alice.uid), (repo) => repo.signin.linkIdentity(alice.uid, input)), true);
});

/** A GoTrue-shaped access token: a JWT whose payload carries `session_id`. The signature part is filler: the code reads the claim only (the database verifies the id). */
const fakeAccessToken = (claims: Record<string, unknown>): string => {
  const b64u = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u(claims)}.c2lnbmF0dXJl`;
};

Deno.test("F5 / PR35: verifyOtp's session is signed out (scope local) only when the CALLER closes it; its id is the access token's session_id claim; a failed sign-out does not fail the proof", DT, async () => {
  const calls: string[] = [];
  const SID = "22222222-2222-4222-8222-222222222222";
  const mk = (over: { verifyError?: { status?: number }; user?: { id?: string } | null; signOutThrows?: boolean; token?: unknown }): OtpAuthClient => ({
    auth: {
      async verifyOtp(args) {
        calls.push(`verifyOtp:${args.email}:${args.type}`);
        const token = over.token === undefined ? fakeAccessToken({ session_id: SID, sub: "x" }) : (over.token as string);
        return { data: over.verifyError ? null : { user: over.user === undefined ? { id: "11111111-1111-4111-8111-111111111111" } : over.user, session: { access_token: token } }, error: over.verifyError ?? null };
      },
      async signOut(opts) {
        calls.push(`signOut:${opts.scope}`);
        if (over.signOutThrows) throw new Error("network");
        return { error: null };
      },
    },
  });
  const ok = await makeEmailOtpVerifier(() => mk({})).verify("a@x.test", "123456");
  assert(ok.ok);
  assertEquals([ok.userId, ok.sessionId], ["11111111-1111-4111-8111-111111111111", SID], "the session id is the access token's session_id claim");
  assertEquals(calls, ["verifyOtp:a@x.test:email"], "the session is still OPEN when verify returns: the proof is bound to it, so it cannot be signed out before the mint");
  await ok.closeSession();
  assertEquals(calls, ["verifyOtp:a@x.test:email", "signOut:local"], "closeSession signs out that session, locally");
  calls.length = 0;
  const thrown = await makeEmailOtpVerifier(() => mk({ signOutThrows: true })).verify("a@x.test", "123456");
  assert(thrown.ok);
  await thrown.closeSession(); // does not throw
  assertEquals(calls, ["verifyOtp:a@x.test:email", "signOut:local"], "a sign-out that fails does not fail the proof (closeSession never throws)");
  calls.length = 0;
  assertEquals(await makeEmailOtpVerifier(() => mk({ verifyError: { status: 400 } })).verify("a@x.test", "000000"), { ok: false });
  assertEquals(calls, ["verifyOtp:a@x.test:email"], "a refused code created no session: nothing to sign out");
  let transport = false;
  try {
    await makeEmailOtpVerifier(() => mk({ verifyError: { status: 500 } })).verify("a@x.test", "000000");
  } catch {
    transport = true;
  }
  assert(transport, "a 5xx is a transport failure (thrown, so it is not counted against the address)");
  // a successful verify that names no user still ends the session it created before it fails
  calls.length = 0;
  let noUser = false;
  try {
    await makeEmailOtpVerifier(() => mk({ user: null })).verify("a@x.test", "123456");
  } catch {
    noUser = true;
  }
  assert(noUser);
  assertEquals(calls, ["verifyOtp:a@x.test:email", "signOut:local"]);
  // a token with no usable session_id claim yields a null session id (the handler then refuses to mint) and the session is still closable
  calls.length = 0;
  const bad = await makeEmailOtpVerifier(() => mk({ token: "not-a-jwt" })).verify("a@x.test", "123456");
  assert(bad.ok);
  assertEquals(bad.sessionId, null);
  await bad.closeSession();
  assertEquals(calls, ["verifyOtp:a@x.test:email", "signOut:local"]);
});

Deno.test("PR35: sessionIdOfAccessToken reads the session_id claim of a JWT and nothing else (base64url, padding, a non-uuid, a missing claim, garbage, a non-string)", () => {
  const SID = "33333333-3333-4333-8333-333333333333";
  assertEquals(sessionIdOfAccessToken(fakeAccessToken({ session_id: SID })), SID);
  assertEquals(sessionIdOfAccessToken(fakeAccessToken({ session_id: SID.toUpperCase() })), SID, "lower-cased");
  // base64url characters (- and _) and a payload whose length needs padding
  assertEquals(sessionIdOfAccessToken(fakeAccessToken({ session_id: SID, note: "??>>~~" })), SID);
  assertEquals(sessionIdOfAccessToken(fakeAccessToken({ session_id: "not-a-uuid" })), null);
  assertEquals(sessionIdOfAccessToken(fakeAccessToken({ session_id: 42 })), null);
  assertEquals(sessionIdOfAccessToken(fakeAccessToken({ sub: "x" })), null, "no claim");
  for (const junk of ["", "a.b", "a.b.c.d", "a..c", "a.%%%.c", `x.${btoa("not json")}.y`, undefined, null, 7, {}]) assertEquals(sessionIdOfAccessToken(junk), null, String(junk));
});

Deno.test("F6: a grant stored while the deletion is revoking at Apple (a racing link) is queued inside the delete transaction and revoked, never deleted unqueued", DT, async () => {
  await setupOnce();
  const u = await newUser("f6");
  await linkAs(u.uid, `apple-sub-f6-${RUN}`, { email: u.email, refresh: "r.f6-first" });
  const actor = makeActor(u.uid);
  const googleRevoked: string[] = [];
  const appleRevoked: string[] = [];
  let injected = false;
  const out = await orchestrateMeDelete({
    withRepo: (op) => withOwnership(actor, op),
    revocation: {
      db: signinRevocationDb,
      apple: {
        async revokeRefreshToken(t) {
          appleRevoked.push(t);
          if (injected) return;
          injected = true; // the racing link: stored AFTER the first enqueue, BEFORE the delete transaction
          await withOwnership(actor, async (repo) => {
            await repo.signin.linkIdentity(u.uid, { provider: "google", subject: `g-sub-f6-${RUN}`, email: null, emailVerified: false, isPrivateRelay: false });
            await repo.signin.storeToken(u.uid, "google", await encryptToken("g.f6-late-grant", "google", await repo.signin.currentKek()));
          });
        },
      },
      google: { revokeToken: async (t) => void googleRevoked.push(t) },
      log: () => {},
    },
  });
  assert(injected, "the race was actually injected");
  assertEquals(appleRevoked, ["r.f6-first"]);
  assertEquals(googleRevoked, ["g.f6-late-grant"], "the late grant reached Google");
  assertEquals(await tokenCount(u.uid), 0);
  assertEquals(out.signinProvidersRevoked.map((o) => [o.provider, o.status]).sort(), [["apple", "revoked"], ["google", "revoked"]]);
});

Deno.test("F6: the enqueue inside the delete transaction holds the per-account lock: a link started meanwhile waits for the commit", DT, async () => {
  await setupOnce();
  const u = await newUser("f6l");
  const actor = makeActor(u.uid);
  const order: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let started!: () => void;
  const inLock = new Promise<void>((r) => (started = r));
  const deleting = withOwnership(actor, async (repo) => {
    await repo.signin.enqueueRevocations(); // takes the account lock, held to the end of THIS transaction
    started();
    await gate;
    order.push("delete-tx-commits");
  });
  await inLock;
  const linking = withOwnership(actor, async (repo) => {
    await repo.signin.linkIdentity(u.uid, { provider: "google", subject: `g-sub-f6l-${RUN}`, email: null, emailVerified: false, isPrivateRelay: false });
    order.push("link-done");
  });
  await new Promise((r) => setTimeout(r, 400));
  assertEquals(order, [], "the link is still waiting on the lock");
  release();
  await deleting;
  await linking;
  assertEquals(order, ["delete-tx-commits", "link-done"]);
});

// ── edge role PR4a (0039): the proof-bound cross-account link ────────────────────────────────────────────────────────────
/** A caller (Alice) with a target (Bob) whose mailbox the proof is about; Bob has just signed in per GoTrue's stamp. */
async function proofPair(label: string) {
  const alice = await newUser(`${label}a`);
  const bob = await newUser(`${label}b`);
  await stampSignIn(bob.uid);
  return { alice, bob };
}
const oneProof = async (uid: string) => {
  const rows = await proofRows(uid);
  assertEquals(rows.length, 1, "exactly one proof row");
  return rows[0]!;
};
const proofInput = (sub: string, email: string) => ({ provider: "apple" as const, subject: sub, email, emailVerified: true, isPrivateRelay: false });
const asCaller = <T>(uid: string, f: (signin: Repo["signin"]) => Promise<T>) => withOwnership(makeActor(uid), (repo) => f(repo.signin));

Deno.test("PR4a: the OTP-proven link works in BOTH modes end to end: it lands on the proven account (identity AND grant), the caller gains nothing, the proof is consumed, and its stored token decrypts", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr4a1");
  const sub = `apple-sub-pr4a1-${RUN}`;
  const calls: string[] = [];
  const script: AppleScript = { nextRefreshToken: "r.pr4a1", nextSubject: sub, revoked: [], revokeStatus: 200 };
  const world = appleWorld(script);
  const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: bob.email } });
  const out = await handleLinkProvider({ ...(await linkReq({ identityToken: token })), emailProof: { code: "123456" } }, alice.uid, depsFor(alice.uid, world, gotrueLike({ ok: true, userId: bob.uid }, calls)));
  assertEquals([out.linkedTo, out.methods], ["proven_account", null]);
  assertEquals(calls, [bob.email]);
  assertEquals(await rawCount(`select count(*) as n from auth.identities where user_id = '${bob.uid}' and provider = 'apple' and provider_id = '${sub}'`), 1, "the identity is on the PROVEN account");
  assertEquals(await tokenCount(bob.uid), 1, "the grant is stored for the proven account");
  assertEquals(await identityCount(alice.uid), 1, "the caller's methods are untouched");
  assertEquals(await tokenCount(alice.uid), 0, "no grant was stored for the caller");
  assertEquals(script.revoked, [], "a successful link revokes nothing");
  // the token Bob now holds really is the one Apple minted
  const row = (await adminSql()`select refresh_token_ciphertext, dek_wrapped, kek_id from app.signin_provider_token where user_id = ${bob.uid} and provider = 'apple'`)[0]!;
  const raw = Uint8Array.from(atob((await adminSql()`select o_kek_b64 from private.get_signin_token_kek(${KEK_ID}::text)`)[0]!.o_kek_b64), (c) => c.charCodeAt(0));
  assertEquals(await decryptToken({ ciphertext: new Uint8Array(row.refresh_token_ciphertext), dekWrapped: new Uint8Array(row.dek_wrapped), kekId: row.kek_id }, "apple", { kekId: KEK_ID, key: raw }), "r.pr4a1");
  // exactly one proof, between these two accounts, hashed, capped at 10 minutes, and consumed by the link
  const p = await oneProof(bob.uid);
  assertEquals([p.caller_user_id, p.target_user_id, p.provider, p.consumed, p.capped], [alice.uid, bob.uid, "apple", true, true]);
  assertEquals(p.email_hash, await sha256Hex(bob.email));
  assertEquals(p.sub_hash, await sha256Hex(`apple:${sub}`));
  assertEquals((await proofRows(alice.uid)).length, 1, "the same single row, seen from the caller's side");
});

Deno.test("PR4a: a REPLAYED proof is refused (single use), by the caller it was issued to, through the real repo", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr4a2");
  const sub = `apple-sub-pr4a2-${RUN}`;
  const pid = await signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: bob.uid, email: bob.email, provider: "apple", subject: sub, sessionId: await newSession(bob.uid) });
  assertEquals(await asCaller(alice.uid, (r) => r.linkIdentityWithProof(pid, proofInput(sub, bob.email), ENVELOPE())), true);
  assertEquals(await identityCount(bob.uid), 2);
  const replay = await httpError(asCaller(alice.uid, (r) => r.linkIdentityWithProof(pid, proofInput(sub, bob.email), ENVELOPE())));
  assertEquals([replay.status, replay.code], [409, "email_proof_refused"]);
  assertEquals(await identityCount(bob.uid), 2, "the replay linked nothing");
  assertEquals((await oneProof(bob.uid)).consumed, true);
});

Deno.test("PR4a: a proof minted for Apple sub A can NOT link sub B (nor another provider, nor another address); sub A still links afterwards", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr4a3");
  const subA = `apple-sub-pr4a3a-${RUN}`;
  const subB = `apple-sub-pr4a3b-${RUN}`;
  const pid = await signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: bob.uid, email: bob.email, provider: "apple", subject: subA, sessionId: await newSession(bob.uid) });
  for (const [label, input] of [
    ["another subject", proofInput(subB, bob.email)],
    ["another provider", { ...proofInput(subA, bob.email), provider: "google" as const }],
    ["another address", proofInput(subA, alice.email)],
  ] as const) {
    const e = await httpError(asCaller(alice.uid, (r) => r.linkIdentityWithProof(pid, input, ENVELOPE())));
    assertEquals([e.status, e.code], [409, "email_proof_refused"], label);
  }
  assertEquals(await rawCount(`select count(*) as n from auth.identities where provider_id in ('${subA}', '${subB}')`), 0, "none of the refused links created an identity");
  assertEquals(await tokenCount(bob.uid), 0);
  assertEquals((await oneProof(bob.uid)).consumed, false, "a refusal does not burn the proof");
  assertEquals(await asCaller(alice.uid, (r) => r.linkIdentityWithProof(pid, proofInput(subA, bob.email), ENVELOPE())), true, "the proof's own identity links");
});

Deno.test("PR4a: a proof is redeemable only by the caller it was issued to; the target cannot redeem it for itself and a stranger cannot", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr4a4");
  const mallory = await newUser("pr4a4m");
  const sub = `apple-sub-pr4a4-${RUN}`;
  const pid = await signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: bob.uid, email: bob.email, provider: "apple", subject: sub, sessionId: await newSession(bob.uid) });
  for (const who of [mallory.uid, bob.uid]) {
    const e = await httpError(asCaller(who, (r) => r.linkIdentityWithProof(pid, proofInput(sub, bob.email), ENVELOPE())));
    assertEquals([e.status, e.code], [409, "email_proof_refused"]);
  }
  assertEquals(await rawCount(`select count(*) as n from auth.identities where provider_id = '${sub}'`), 0);
  assertEquals(await asCaller(alice.uid, (r) => r.linkIdentityWithProof(pid, proofInput(sub, bob.email), ENVELOPE())), true);
});

Deno.test("PR4a: an EXPIRED proof is refused (the row is fabricated through the only writer's own INSERT window: the minter never writes one)", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr4a5");
  const sub = `apple-sub-pr4a5-${RUN}`;
  // a proof that expired 10 minutes ago, written as private_definer with the INSERT window open on its id (the minter would never write it)
  const pid = freshUuid();
  await asDefiner(async (sql) => {
    await sql`select set_config('app.signin.proof_id', ${pid}, true)`;
    await sql`insert into private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at)
              values (${pid}, ${alice.uid}, ${bob.uid}, ${await sha256Hex(bob.email)}, 'apple', ${await sha256Hex(`apple:${sub}`)}, now() - interval '15 minutes', now() - interval '10 minutes')`;
  });
  const e = await httpError(asCaller(alice.uid, (r) => r.linkIdentityWithProof(pid, proofInput(sub, bob.email), ENVELOPE())));
  assertEquals([e.status, e.code], [409, "email_proof_refused"]);
  assertEquals(await rawCount(`select count(*) as n from auth.identities where provider_id = '${sub}'`), 0);
});

Deno.test("PR4a: the minter refuses when GoTrue shows no sign-in for the target (a verifier that 'verified' without a session), and the handler answers 409 before any code is exchanged", DT, async () => {
  await setupOnce();
  const alice = await newUser("pr4a6a");
  const bob = await newUser("pr4a6b"); // never signed in: last_sign_in_at is NULL
  const sub = `apple-sub-pr4a6-${RUN}`;
  const script: AppleScript = { nextRefreshToken: "r.pr4a6", nextSubject: sub, revoked: [], revokeStatus: 200 };
  const world = appleWorld(script);
  const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: bob.email } });
  const calls: string[] = [];
  const e = await httpError(handleLinkProvider({ ...(await linkReq({ identityToken: token })), emailProof: { code: "123456" } }, alice.uid, depsFor(alice.uid, world, gotrueLike({ ok: true, userId: bob.uid }, calls, false))));
  assertEquals([e.status, e.code], [409, "email_proof_refused"]);
  assertEquals(calls, [bob.email], "the verifier ran");
  assertEquals(world.calls.filter((c) => c.url === APPLE_TOKEN_URL).length, 0, "no authorization code was exchanged");
  assertEquals((await proofRows(bob.uid)).length, 0, "no proof was minted");
  assertEquals(await identityCount(bob.uid), 1);
  assertEquals(await signinOtpFailuresFor(makeActor(alice.uid)).peek(await otpKey(bob.uid)), 0, "the OTP attempt was given back (the code itself was fine)");
  // a stale stamp (the target signed in 10 minutes ago) is no corroboration either
  await stampSignIn(bob.uid, 600);
  const e2 = await httpError(signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: bob.uid, email: bob.email, provider: "apple", subject: sub, sessionId: await newSession(bob.uid) }));
  assertEquals([e2.status, e2.code], [409, "email_proof_refused"]);
  // ... and neither is the wrong address for the target
  await stampSignIn(bob.uid);
  const e3 = await httpError(signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: bob.uid, email: alice.email, provider: "apple", subject: sub, sessionId: await newSession(bob.uid) }));
  assertEquals([e3.status, e3.code], [409, "email_proof_refused"]);
  // ... nor an account that does not exist (it vanished between the lookup and the mint): the same refusal, not a "not linked" 404
  const e4 = await httpError(signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: freshUuid(), email: bob.email, provider: "apple", subject: sub, sessionId: await newSession(bob.uid) }));
  assertEquals([e4.status, e4.code], [409, "email_proof_refused"]);
  assertEquals((await proofRows(bob.uid)).length, 0);
});

Deno.test("PR4a: CONCURRENT redemption of one proof yields exactly one link and one refusal (per-account advisory lock + FOR UPDATE), repeated", DT, async () => {
  await setupOnce();
  for (let round = 0; round < 3; round++) {
    const { alice, bob } = await proofPair(`pr4a7r${round}`);
    const sub = `apple-sub-pr4a7-${round}-${RUN}`;
    const pid = await signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: bob.uid, email: bob.email, provider: "apple", subject: sub, sessionId: await newSession(bob.uid) });
    const attempts = await Promise.allSettled(Array.from({ length: 4 }, () => asCaller(alice.uid, (r) => r.linkIdentityWithProof(pid, proofInput(sub, bob.email), ENVELOPE()))));
    assertEquals(attempts.filter((a) => a.status === "fulfilled").length, 1, "exactly one redemption wins");
    for (const a of attempts) {
      if (a.status === "rejected") assert(a.reason instanceof HttpError && a.reason.status === 409 && a.reason.code === "email_proof_refused", "every loser is the 409 refusal");
    }
    assertEquals(await rawCount(`select count(*) as n from auth.identities where provider = 'apple' and provider_id = '${sub}'`), 1, "exactly one identity");
    assertEquals(await tokenCount(bob.uid), 1, "exactly one grant");
  }
});

Deno.test("PR4a / PR35: the F5 sign-out still happens in the full proven flow, AFTER the mint (the proof is bound to that session): verifyOtp, the mint, then signOut(local) of exactly that session; the link lands on the proven account", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr4a8");
  const sub = `apple-sub-pr4a8-${RUN}`;
  const events: string[] = [];
  let sessionId = "";
  const client: OtpAuthClient = {
    auth: {
      async verifyOtp(args) {
        events.push(`verifyOtp:${args.email}`);
        await stampSignIn(bob.uid); // GoTrue's session issue stamps the sign-in ...
        sessionId = await newSession(bob.uid); // ... and creates the session whose id is in the access token
        return { data: { user: { id: bob.uid }, session: { access_token: fakeAccessToken({ session_id: sessionId }) } }, error: null };
      },
      async signOut(opts) {
        events.push(`signOut:${opts.scope}:${(await sessionExists(sessionId)) ? "session-present" : "session-gone"}`);
        await adminSql()`delete from auth.sessions where id = ${sessionId}`; // what GoTrue's scope-local logout does
        return { error: null };
      },
    },
  };
  const script: AppleScript = { nextRefreshToken: "r.pr4a8", nextSubject: sub, revoked: [], revokeStatus: 200 };
  const world = appleWorld(script);
  const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: bob.email } });
  const deps = depsFor(alice.uid, world, makeEmailOtpVerifier(() => client));
  const realMinter = deps.emailProofs!;
  deps.emailProofs = {
    async record(input) {
      events.push(`mint:${input.sessionId === sessionId ? "the-verifyOtp-session" : "OTHER-SESSION"}`);
      return realMinter.record(input);
    },
  };
  const out = await handleLinkProvider({ ...(await linkReq({ identityToken: token })), emailProof: { code: "123456" } }, alice.uid, deps);
  assertEquals(out.linkedTo, "proven_account");
  assertEquals(events, [`verifyOtp:${bob.email}`, "mint:the-verifyOtp-session", "signOut:local:session-present"], "the mint saw the session; the sign-out came after it and named that session");
  assertEquals(await sessionExists(sessionId), false, "the session is gone afterwards");
  assertEquals(await rawCount(`select count(*) as n from auth.identities where user_id = '${bob.uid}' and provider_id = '${sub}'`), 1);
  assertEquals((await oneProof(bob.uid)).consumed, true);
});

// ── edge role PR #35 (0041): the dedicated minter, the session binding, one normalisation ────────────────────────────────

const pgCode = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (e) {
    return String((e as { code?: unknown } | null)?.code);
  }
  return "no error";
};

Deno.test("PR35 L1: a mint attempted from inside an edge_system transaction (the drain / queue / import / retention lanes) is REFUSED, with a perfectly valid argument set", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr35a");
  const sid = await newSession(bob.uid);
  // the very arguments the real minter would use, from a lane that is edge_system (any of them: drain, queue, import, retention-purge)
  const code = await pgCode(
    openScopedTx("system", { expectedUid: null }, (trx) => trx`select private.signin_record_email_proof(${alice.uid}::uuid, ${bob.uid}::uuid, ${bob.email}, 'apple', ${"pr35a-" + RUN}, ${sid}::uuid)`),
  );
  assertEquals(code, "42501", "permission denied: EXECUTE was moved to edge_signin_minter");
  assertEquals((await proofRows(bob.uid)).length, 0, "no proof was minted");
  // ... and the same arguments through the real minter path work (the control: the refusal above was the ROLE, not the arguments)
  const pid = await signinEmailProofs().record({ callerUserId: alice.uid, targetUserId: bob.uid, email: bob.email, provider: "apple", subject: `pr35a-${RUN}`, sessionId: sid });
  assert(pid.length === 36);
  assertEquals((await proofRows(bob.uid)).length, 1);
  // the system lanes cannot even see the session ids: edge_system has no privilege on auth.sessions
  assertEquals(await pgCode(openScopedTx("system", { expectedUid: null }, (trx) => trx`select id from auth.sessions limit 1`)), "42501");
  // an actor-bound (per-user) transaction cannot mint either
  const actorCode = await pgCode(
    openScopedTx("actor", { expectedUid: alice.uid, run: (trx) => trx`select private.bind_actor(${alice.uid}::uuid)` }, (trx) => trx`select private.signin_record_email_proof(${alice.uid}::uuid, ${bob.uid}::uuid, ${bob.email}, 'apple', ${"pr35a2-" + RUN}, ${sid}::uuid)`),
  );
  assertEquals(actorCode, "42501");
});

Deno.test("PR35 L1: the signin_mint transaction runs as edge_signin_minter and can do nothing else; a bound actor / a bind inside it is refused before the operation runs", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr35b");
  const who = await openScopedTx("signin_mint", { expectedUid: null }, async (trx) => (await trx`select current_user::text as u`)[0]!.u);
  assertEquals(who, "edge_signin_minter");
  for (const [label, run] of [
    ["read the proof table", (trx: Parameters<Parameters<typeof openScopedTx>[2]>[0]) => trx`select count(*) from private.signin_email_proof`],
    ["read auth.sessions", (trx: Parameters<Parameters<typeof openScopedTx>[2]>[0]) => trx`select count(*) from auth.sessions`],
    ["read auth.users", (trx: Parameters<Parameters<typeof openScopedTx>[2]>[0]) => trx`select count(*) from auth.users`],
    ["read app.play", (trx: Parameters<Parameters<typeof openScopedTx>[2]>[0]) => trx`select count(*) from app.play`],
    ["purge proofs", (trx: Parameters<Parameters<typeof openScopedTx>[2]>[0]) => trx`select private.purge_signin_email_proofs()`],
    ["bind an actor", (trx: Parameters<Parameters<typeof openScopedTx>[2]>[0]) => trx`select private.bind_actor(${alice.uid}::uuid)`],
    ["call a system function", (trx: Parameters<Parameters<typeof openScopedTx>[2]>[0]) => trx`select private.hit_system_rate_limit('pr35', interval '1 minute', 5)`],
  ] as const) {
    assertEquals(await pgCode(openScopedTx("signin_mint", { expectedUid: null }, async (trx) => await run(trx))), "42501", label);
  }
  // the kind binds no actor: a bind passed to it is refused before anything runs (the mint definer refuses inside a bound transaction anyway)
  let ran = false;
  const err = await openScopedTx("signin_mint", { expectedUid: alice.uid, run: (trx) => trx`select 1` }, async () => {
    ran = true;
  }).catch((e: unknown) => e as Error);
  assert(err instanceof Error && /binds no actor/.test(err.message), "refused");
  assertEquals(ran, false);
  assertEquals((await proofRows(bob.uid)).length, 0);
});

Deno.test("PR35 (b): the mint refuses without a FRESH session of the TARGET with that id; a session mints one proof only; the refusals mint nothing", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr35c");
  const carol = await newUser("pr35cc");
  const base = { callerUserId: alice.uid, targetUserId: bob.uid, email: bob.email, provider: "apple" as const, subject: `pr35c-${RUN}` };
  const refused = async (sessionId: string, label: string) => {
    const e = await httpError(signinEmailProofs().record({ ...base, sessionId }));
    assertEquals([e.status, e.code], [409, "email_proof_refused"], label);
  };
  await refused(freshUuid(), "a session id that does not exist (an injected mint cannot guess the victim's)");
  await refused(await newSession(carol.uid), "a real, fresh session of ANOTHER account");
  await refused(await newSession(bob.uid, 600), "the target's own session from 10 minutes ago");
  await refused(await newSession(bob.uid, -600), "a session dated 10 minutes in the future");
  assertEquals((await proofRows(bob.uid)).length, 0, "none of the refusals minted a proof");
  const good = await newSession(bob.uid);
  await signinEmailProofs().record({ ...base, sessionId: good });
  await refused(good, "the same session a second time (one session, one proof)");
  assertEquals((await proofRows(bob.uid)).length, 1);
  // a malformed id never reaches the database
  const e = await httpError(signinEmailProofs().record({ ...base, sessionId: "not-a-uuid" }));
  assertEquals([e.status, e.code], [409, "email_proof_refused"]);
});

Deno.test("PR35 (b): the verifyOtp session is signed out on EVERY path of the handler (a successful link, a mint the database refuses, an address that changed hands), and its id is never logged", DT, async () => {
  await setupOnce();
  const run = async (label: string, how: { otherAccount?: boolean; staleStampAfterVerify?: boolean }, expectCode: string | null) => {
    const { alice, bob } = await proofPair(`pr35d${label}`);
    const stranger = how.otherAccount ? await newUser(`pr35d${label}x`) : null;
    const sessionIds: string[] = [];
    const signouts: string[] = [];
    const log: Array<Record<string, unknown>> = [];
    const sub = `apple-sub-pr35d-${label}-${RUN}`;
    const world = appleWorld({ nextRefreshToken: `r.pr35d.${label}`, nextSubject: sub, revoked: [], revokeStatus: 200 });
    const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: bob.email } });
    const inner = gotrueLike({ ok: true, userId: stranger?.uid ?? bob.uid }, [], true, sessionIds, signouts);
    const verifier: EmailOtpVerifier = {
      async verify(email, code) {
        const out = await inner.verify(email, code);
        // the target's GoTrue sign-in stamp goes stale under the verifier: the database will refuse to mint
        if (how.staleStampAfterVerify) await stampSignIn(bob.uid, 600);
        return out;
      },
    };
    const out = await handleLinkProvider({ ...(await linkReq({ identityToken: token })), emailProof: { code: "123456" } }, alice.uid, depsFor(alice.uid, world, verifier, log)).then(
      () => null,
      (e: unknown) => e as HttpError,
    );
    assertEquals(out?.code ?? null, expectCode, label);
    assertEquals(sessionIds.length, 1, `${label}: verifyOtp created one session`);
    assertEquals(signouts, sessionIds, `${label}: exactly that session was signed out`);
    assertEquals(await sessionExists(sessionIds[0]!), false, `${label}: and it is gone`);
    assert(!JSON.stringify(log).includes(sessionIds[0]!), `${label}: the session id is never logged`);
    if (expectCode !== null) assertEquals((await proofRows(bob.uid)).length, 0, `${label}: no proof was minted`);
  };
  await run("ok", {}, null);
  await run("hands", { otherAccount: true }, "email_proof_mismatch");
  await run("stale", { staleStampAfterVerify: true }, "email_proof_refused");
});

Deno.test("PR35 L2: ONE normalisation, in the database: the mint and the redemption agree with lower(btrim()) for case, spaces, tab, NBSP, em space, newline, U+0130, plus tags and a trailing dot (JavaScript hashes nothing)", DT, async () => {
  await setupOnce();
  const spellings: Array<[string, (e: string) => string]> = [
    ["upper case", (e) => e.toUpperCase()],
    ["surrounding spaces", (e) => `   ${e}  `],
    ["a tab", (e) => `\t${e}\t`],
    ["a no-break space", (e) => `\u00a0${e}\u00a0`],
    ["an em space", (e) => `${e}\u2003`],
    ["a newline", (e) => `${e}\n`],
    ["a plus tag", (e) => e.replace("@", "+tag@")],
    ["U+0130 for an i", (e) => e.replace("i", "\u0130")],
    ["a trailing dot", (e) => `${e}.`],
  ];
  let n = 0;
  for (const [label, spell] of spellings) {
    n++;
    // MINT: accepted exactly when the database says the variant is the target's address (a fresh pair, so one Apple identity per account is never in the way)
    const m = await proofPair(`pr35e${n}m`);
    const variant = spell(m.bob.email);
    const dbSame = async (v: string): Promise<boolean> => (await adminSql()`select lower(btrim(${v})) = lower(btrim(${m.bob.email})) as s`)[0]!.s as boolean;
    const sameMint = await dbSame(variant);
    const sub = `pr35e-${n}-${RUN}`;
    const mint = signinEmailProofs().record({ callerUserId: m.alice.uid, targetUserId: m.bob.uid, email: variant, provider: "apple", subject: sub, sessionId: await newSession(m.bob.uid) });
    if (!sameMint) {
      const e = await httpError(mint);
      assertEquals([e.status, e.code], [409, "email_proof_refused"], `mint with ${label}: the database says it is another address`);
      assertEquals((await proofRows(m.bob.uid)).length, 0);
    } else {
      const pid = await mint;
      const row = await oneProof(m.bob.uid);
      assertEquals(row.email_hash, await sha256Hex(m.bob.email), `mint with ${label}: the stored hash is sha256 of the target's own normalised address`);
      // REDEEM with the SAME variant the proof was minted for: links (one rule on both sides)
      assertEquals(await asCaller(m.alice.uid, (r) => r.linkIdentityWithProof(pid, proofInput(sub, variant), ENVELOPE())), true, `link with ${label}`);
      assertEquals(await rawCount(`select count(*) as n from auth.identities where user_id = '${m.bob.uid}' and provider_id = '${sub}'`), 1, `${label}: linked to the target`);
    }
    // REDEEM with the variant a proof for the CANONICAL address was minted for: judged by the same expression
    const r = await proofPair(`pr35e${n}r`);
    const rv = spell(r.bob.email);
    const rsub = `pr35e-${n}-r-${RUN}`;
    const rpid = await signinEmailProofs().record({ callerUserId: r.alice.uid, targetUserId: r.bob.uid, email: r.bob.email, provider: "apple", subject: rsub, sessionId: await newSession(r.bob.uid) });
    const sameRedeem = (await adminSql()`select lower(btrim(${rv})) = lower(btrim(${r.bob.email})) as s`)[0]!.s as boolean;
    const outcome = await asCaller(r.alice.uid, (repo) => repo.linkIdentityWithProof(rpid, proofInput(rsub, rv), ENVELOPE())).then(
      () => "linked",
      (e: unknown) => `${(e as HttpError).status}:${(e as HttpError).code}`,
    );
    assertEquals(outcome, sameRedeem ? "linked" : "409:email_proof_refused", `redeem with ${label}: agrees with the database's own comparison`);
  }
});

Deno.test("PR35 L2: through the handler, an Apple address the database treats as another address is NOT the proof path (a direct link to the caller) and one it treats as the same IS (to the target). The claim is trimmed / lower-cased once at parse time (apple-id-token.ts); every comparison after it is the database's", DT, async () => {
  await setupOnce();
  for (const [label, spell] of [
    ["upper case", (e: string) => e.toUpperCase()],
    ["a tab", (e: string) => `\t${e}`],
    ["a plus tag", (e: string) => e.replace("@", "+x@")],
    ["U+0130", (e: string) => e.replace("i", "\u0130")],
  ] as const) {
    const key = label.replace(/\W/g, "");
    const { alice, bob } = await proofPair(`pr35f${key}`);
    const claim = spell(bob.email);
    // what the handler hands the database: the parse-time normalisation of the claim; the database's rule decides from there
    const parsed = claim.trim().toLowerCase();
    const same = (await adminSql()`select lower(btrim(${parsed})) = lower(${bob.email}) as s`)[0]!.s as boolean;
    const sub = `apple-sub-pr35f-${key}-${RUN}`;
    const world = appleWorld({ nextRefreshToken: "r.pr35f", nextSubject: sub, revoked: [], revokeStatus: 200 });
    const token = await mintIdentityToken(appleKey, sub, { rawNonce: RAW_NONCE, claims: { email: claim } });
    const calls: string[] = [];
    const out = await handleLinkProvider({ ...(await linkReq({ identityToken: token })), emailProof: { code: "123456" } }, alice.uid, depsFor(alice.uid, world, gotrueLike({ ok: true, userId: bob.uid }, calls)));
    assertEquals(out.linkedTo, same ? "proven_account" : "self", `${label}: the database decides`);
    assertEquals(calls.length, same ? 1 : 0, `${label}: the OTP verifier ran only on the proof path`);
    assertEquals(await rawCount(`select count(*) as n from auth.identities where provider_id = '${sub}' and user_id = '${same ? bob.uid : alice.uid}'`), 1, label);
  }
});

Deno.test("PR4a: the proof rows are deleted with the account (delete_my_data) as caller or as target, and purged an hour past expiry; a live proof of others survives both", DT, async () => {
  await setupOnce();
  const { alice, bob } = await proofPair("pr4a9");
  const carol = await newUser("pr4a9c");
  await stampSignIn(carol.uid);
  const dave = await newUser("pr4a9d");
  const mint = async (caller: string, target: { uid: string; email: string }, sub: string) => signinEmailProofs().record({ callerUserId: caller, targetUserId: target.uid, email: target.email, provider: "apple", subject: `${sub}-${RUN}`, sessionId: await newSession(target.uid) });
  await mint(alice.uid, bob, "pr4a9-ab");
  await stampSignIn(alice.uid);
  await mint(dave.uid, alice, "pr4a9-da");
  await mint(dave.uid, carol, "pr4a9-dc");
  assertEquals((await proofRows(alice.uid)).length, 2, "alice is a party to two proofs");
  await withOwnership(makeActor(alice.uid), (repo) => repo.me.deleteMyData());
  assertEquals((await proofRows(alice.uid)).length, 0, "both of alice's proofs went with her account (as caller and as target)");
  assertEquals((await proofRows(carol.uid)).length, 1, "a proof between two OTHER accounts is untouched");
  assertEquals((await proofRows(bob.uid)).length, 0, "(bob's only proof was alice's)");
  // the purge: an hour past expiry only
  const stale = freshUuid();
  await asDefiner(async (sql) => {
    await sql`select set_config('app.signin.proof_id', ${stale}, true)`;
    await sql`insert into private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at)
              values (${stale}, ${dave.uid}, ${carol.uid}, ${await sha256Hex(carol.email)}, 'apple', ${await sha256Hex("apple:stale-" + RUN)}, now() - interval '3 hours', now() - interval '2 hours 55 minutes')`;
  });
  assertEquals((await proofRows(carol.uid)).length, 2);
  assert((await purgeSigninEmailProofs()) >= 1, "the purge removed the stale proof");
  const left = await proofRows(carol.uid);
  assertEquals(left.length, 1, "only the live proof is left");
  assertEquals(left[0]!.live, true);
});

Deno.test("cleanup: the throw-away KEK is removed", DT, async () => {
  await ensureServiceRole();
  await adminSql()`delete from vault.secrets where name in (${"siwa_token_kek_" + KEK_ID}, ${"disabled_" + KEK_ID})`;
  assertEquals(await rawCount(`select count(*) as n from vault.secrets where name like 'siwa\\_token\\_kek\\_${KEK_ID}%'`), 0);
});
