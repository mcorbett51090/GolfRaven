// supabase/tests/integration/marker-scan.deno.test.ts
//
// P5.1a S2a: the player lane of the course QR against the REAL database. The REAL handler (_shared/course-qr/scan-handler.ts), the REAL `withOwnership` and `Repo` (privileged.ts: every call is
// `SET LOCAL ROLE edge_actor` + a bound actor), the REAL check-in challenge -> token flow, the REAL Vault-keyed PIN derivation (private.course_pin_derive, which no TypeScript can reach) and
// the REAL single-use / counter / advisory-lock behaviour, in the harness cluster tools/db/test.sh builds, in BOTH harness modes.
//
// What only a real database can show, and the unit tests (a fake Repo) cannot:
//   - the PIN the database derives equals the INDEPENDENT reference below (a scan with the reference's PIN is accepted, one with its neighbour is not);
//   - a forged QR's fraud_signal COMMITS, a wrong PIN's counter COMMITS, while every other refusal ROLLS BACK (the check-in token the scan consumed is not spent);
//   - a rotating token is single-use under real concurrency (N parallel scans: exactly one purchase); the 5-per-user cap holds under parallel guesses; the 30-per-facility cap rotates the PIN;
//   - the fix is counted ONCE (one foreground_checkin evidence row), and a purchase never writes a play;
//   - edge_actor cannot read the key table, the alarm table or the derivation core.
//
// Keys and the pepper are generated AT RUN TIME (never literals). The Ed25519 keys go into app.course_qr_key through the temporary-owner-policy helper (the table has no policy for the harness
// role); the pepper into the Vault stand-in. Both are removed again by the last test. Every test builds its OWN facility (so the PIN counters and the 30-failure rotation of one test never touch another's).

import { assert, assertEquals, assertNotEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, makeActor, NASHVILLE, rawCount, rawOwnerSql } from "./_helpers.ts";
import { openScopedTx, userBind, withOwnership } from "../../functions/_shared/privileged.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.ts";
import { handleMarkerScan, type MarkerScanOutcome } from "../../functions/_shared/course-qr/scan-handler.ts";
import { parseMarkerScanBody } from "../../functions/_shared/course-qr/request-shape.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import type { Repo } from "../../functions/_shared/types.ts";
import { generateTestSigningKey, mintPrintedQrSig, mintRotatingToken, type TestSigningKey } from "../unit/course-qr-test-keys.ts";
import { base64UrlEncode } from "../../functions/_shared/course-qr/format.ts";
import type postgres from "postgres";

type TxSql = postgres.TransactionSql;
const DT = { sanitizeOps: false, sanitizeResources: false };
/** Runs `fn` as the connecting owner with a TEMPORARY `FOR ALL` policy on `schemaTable` (FORCE RLS leaves the table's owner with no row access otherwise), dropped again afterwards. A POLICY ONLY: unlike
 * `_helpers.ts#withTemporaryOwnerAccess` it never GRANTs or REVOKEs, because under HARNESS_MODE=restricted the connecting role OWNS the table and a `REVOKE ... FROM current_user` would strip the owner's
 * own privileges (a first draft of this file did, and every later test that deletes an account failed with `permission denied for table checkin_token`). */
async function withOwnerPolicy<T>(schemaTable: string, fn: (sql: ReturnType<typeof rawOwnerSql>) => Promise<T>): Promise<T> {
  const sql = rawOwnerSql();
  const name = `s2a_marker_scan_temp_${schemaTable.replace(/\W/g, "_")}`;
  await sql.unsafe(`create policy ${name} on ${schemaTable} for all to current_user using (true) with check (true)`);
  try {
    return await fn(sql);
  } finally {
    await sql.unsafe(`drop policy if exists ${name} on ${schemaTable}`);
  }
}

const STAFF = "00000000-0000-0000-0000-1000000000a1"; // helpers.sql: staff-x
const TZ = "America/Chicago";
const enc = new TextEncoder();
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256Hex = async (b: Uint8Array) => toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b.slice().buffer)));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------------------------------------------------------
// the run-time environment: keys, pepper, an independent PIN derivation
// ---------------------------------------------------------------------------------------------------------------------------------------------

interface Env {
  rot: TestSigningKey;
  rotKid: string;
  prt: TestSigningKey;
  prtKid: string;
  pepper: string;
}
let envPromise: Promise<Env> | null = null;

function env(): Promise<Env> {
  envPromise ??= (async () => {
    const suffix = freshUuid().slice(0, 8);
    const e: Env = {
      rot: await generateTestSigningKey(),
      rotKid: `s2ar${suffix}`,
      prt: await generateTestSigningKey(),
      prtKid: `s2ap${suffix}`,
      // >= 32 bytes, built at run time
      pepper: `${freshUuid()}${freshUuid()}`,
    };
    await withOwnerPolicy("app.course_qr_key", async (sql) => {
      await sql`insert into app.course_qr_key (purpose, kid, public_key_b64url) values ('rotating_token', ${e.rotKid}, ${e.rot.publicKeyB64Url})`;
      await sql`insert into app.course_qr_key (purpose, kid, public_key_b64url) values ('printed_qr', ${e.prtKid}, ${e.prt.publicKeyB64Url})`;
    });
    await rawOwnerSql()`insert into vault.secrets (name, secret) values ('course_pin_pepper', ${e.pepper})`;
    return e;
  })();
  return envPromise;
}

/** The reference derivation (the same one supabase/tests/unit/course-qr-pin-vector.test.ts pins), over WebCrypto, sharing nothing with the SQL. */
async function referencePin(pepper: string, facilityId: string, localDate: string, epoch: number): Promise<string> {
  const e = new Uint8Array(4);
  new DataView(e.buffer).setUint32(0, epoch);
  const parts = [enc.encode("golfraven/course-pin/v1"), new Uint8Array([0]), enc.encode(facilityId), new Uint8Array([0]), enc.encode(localDate), new Uint8Array([0]), e];
  const message = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    message.set(p, at);
    at += p.length;
  }
  const key = await crypto.subtle.importKey("raw", enc.encode(pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  return String(new DataView(mac.buffer).getUint32(0) % 10000).padStart(4, "0");
}
const wrongOf = (pin: string, by = 1) => String((Number(pin) + by) % 10000).padStart(4, "0");
const localDateOf = (ms: number) => new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(ms));

// ---------------------------------------------------------------------------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------------------------------------------------------------------------

interface Shop {
  fac: string;
  trails: string[];
}

/** A facility with a polygon course (so a fix at NASHVILLE is a co-signal), a printed QR, and a live `any_purchase` programme on `trailCount` trails. */
async function createShop(label: string, qrMode: "rotating" | "static_pin" | "both" = "both", trailCount = 1): Promise<Shop> {
  const e = await env();
  await ensureServiceRole();
  const sql = adminSql();
  const s = freshUuid().slice(0, 8);
  const fac = `fac_s2d_${label}_${s}`;
  const trails = Array.from({ length: trailCount }, (_, i) => `trl_s2d_${label}_${s}_${i}`);
  const course = `crs_s2d_${label}_${s}`;
  await sql`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${fac}, 'facility', 'verified', 1), (${course}, 'course', 'verified', 1)`;
  for (const t of trails) await sql`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${t}, 'trail', 'verified', 1)`;
  await sql`insert into app.catalog_facility (id, slug, name, region, tz, catalog_version) values (${fac}, ${"s2d-" + label + "-" + s}, ${"S2D " + label}, 'US-TN', ${TZ}, 1)`;
  const d = 0.001;
  await sql`
    insert into app.catalog_course (id, facility_id, name, verification_status, geometry_kind, boundary, catalog_version)
    values (${course}, ${fac}, ${"S2D " + course}, 'play-verified', 'polygon',
      ST_SetSRID(ST_MakePolygon(ST_MakeLine(ARRAY[
        ST_MakePoint(${NASHVILLE.lng - d}, ${NASHVILLE.lat - d}), ST_MakePoint(${NASHVILLE.lng + d}, ${NASHVILLE.lat - d}),
        ST_MakePoint(${NASHVILLE.lng + d}, ${NASHVILLE.lat + d}), ST_MakePoint(${NASHVILLE.lng - d}, ${NASHVILLE.lat + d}),
        ST_MakePoint(${NASHVILLE.lng - d}, ${NASHVILLE.lat - d})
      ])), 4326), 1)`;
  for (const t of trails) {
    await sql`insert into app.catalog_trail (id, slug, name, catalog_version) values (${t}, ${"s2d-" + t}, ${"S2D " + t}, 1)`;
    await sql`insert into app.trail_programme (trail_id, status, marker_source) values (${t}, 'live', 'any_purchase')`;
    await sql`insert into app.facility_programme (trail_id, facility_id, participation, qr_mode) values (${t}, ${fac}, 'accepted', ${qrMode})`;
  }
  await sql`insert into app.facility_qr (facility_id, qr_kid, sig) values (${fac}, ${e.prtKid}, ${"printed-" + s})`;
  return { fac, trails };
}

async function freshPlayer(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `ms-${label}-${uid.slice(0, 8)}`);
  return { uid, actor: makeActor(uid), deviceId: freshUuid() };
}
type Player = Awaited<ReturnType<typeof freshPlayer>>;

/** POST /v1/checkin/challenge + /token for `shop`, as the real handlers do; then (a test fixture, raw) the token's grade is set. Returns the `jti`. */
async function checkinToken(p: Player, shop: Shop, grade: "attested" | "unattestable" | "failed" = "attested"): Promise<string> {
  const [challenge] = await withOwnership(p.actor, (repo: Repo) => handleChallengeRequest({ deviceId: p.deviceId, facilityId: shop.fac }, repo, randomBytes, sha256Hex));
  const token = await withOwnership(p.actor, (repo: Repo) => handleTokenRequest({ challengeId: challenge!.id, nonce: challenge!.nonce, hardwareSupportsAttestation: false }, repo, sha256Hex));
  if (grade !== token.attestationGrade) {
    await withOwnerPolicy("app.checkin_token", (sql) => sql`update app.checkin_token set attestation_grade = ${grade} where jti = ${token.jti}`);
  }
  await sleep(15); // the fix is captured AFTER the challenge was issued (the challenge window's lower bound is its issue time)
  return token.jti;
}

let fixSeq = 0;
function fixOf(over: Record<string, unknown> = {}) {
  fixSeq += 1;
  return { fixId: `s2dfix${freshUuid().replace(/-/g, "").slice(0, 16)}${fixSeq}`, lat: NASHVILLE.lat, lng: NASHVILLE.lng, accuracyMeters: 8, capturedAt: Date.now(), simulated: false, foreground: true, fromApp: true, ...over };
}

/** A check-in token AND a fix captured after its challenge was issued (the order matters: the fix must fall inside the challenge window). */
async function withFix(p: Player, shop: Shop, grade: "attested" | "unattestable" | "failed" = "attested", over: Record<string, unknown> = {}) {
  const jti = await checkinToken(p, shop, grade);
  return { fix: fixOf(over), jti };
}

/** A token the staff lane would have written (S2b mints; here the row and the signature are made directly). Issued NOW unless `ageSec` says otherwise. */
async function rotatingToken(shop: Shop, o: { ageSec?: number; key?: TestSigningKey; kid?: string } = {}): Promise<{ token: string; hash: string; issuedAtMs: number }> {
  const e = await env();
  const iat = Math.floor(Date.now() / 1000) - (o.ageSec ?? 0);
  const minted = await mintRotatingToken({ key: o.key ?? e.rot, kid: o.kid ?? e.rotKid, facilityId: shop.fac, iat });
  const hash = await sha256Hex(minted.nonce);
  await ensureServiceRole();
  await adminSql()`
    insert into app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
    values (${hash}, ${shop.fac}, ${STAFF}, ${o.kid ?? e.rotKid}, ${new Date(iat * 1000).toISOString()}, ${new Date((iat + 120) * 1000).toISOString()})`;
  return { token: minted.token, hash, issuedAtMs: iat * 1000 };
}

async function printedQr(shop: Shop, pin: string, key?: TestSigningKey) {
  const e = await env();
  return { variant: "static_pin", kid: e.prtKid, sig: await mintPrintedQrSig(key ?? e.prt, shop.fac, e.prtKid), pin };
}

function scan(p: Player, shop: Shop, o: { qr?: unknown; fix?: Record<string, unknown>; jti?: string }): Promise<MarkerScanOutcome> {
  const parsed = parseMarkerScanBody({ facilityId: shop.fac, ...(o.qr ? { qr: o.qr } : {}), ...(o.fix ? { fix: o.fix, deviceId: p.deviceId } : {}), ...(o.jti ? { jti: o.jti } : {}) });
  if (!parsed.ok) throw new Error(`test body invalid: ${JSON.stringify(parsed.issues)}`);
  return withOwnership(p.actor, (repo: Repo) => handleMarkerScan(parsed.value, repo, { sha256Hex }));
}
async function httpError(p: Promise<unknown>): Promise<HttpError | null> {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return e;
    throw e;
  }
}
function ok(o: MarkerScanOutcome) {
  if (o.kind !== "ok") throw new Error(`expected an ok outcome, got a committed refusal: ${o.error.code}`);
  return o;
}

async function purchases(uid: string) {
  await ensureServiceRole();
  return await adminSql()`
    select pe.id, pe.trail_id, pe.method, pe.qr_variant, pe.status, pe.cosignal, pe.local_date::text as local_date, mc.status as credit_status
    from app.purchase_evidence pe left join app.marker_credit mc on mc.purchase_evidence_id = pe.id
    where pe.user_id = ${uid} order by pe.trail_id`;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// rotating token (Q1)
// ---------------------------------------------------------------------------------------------------------------------------------------------

Deno.test("Q1 with a qualifying fix: a valid purchase, a credited credit, ONE foreground_checkin evidence row for the fix, no play, the token consumed", DT, async () => {
  const shop = await createShop("q1", "both", 2); // two trails: one purchase and one credit per trail
  const p = await freshPlayer("q1");
  const t = await rotatingToken(shop);
  const jti = await checkinToken(p, shop);
  const fix = fixOf();
  const res = ok(await scan(p, shop, { qr: { variant: "rotating", token: t.token }, fix, jti }));
  assertEquals(res.status, 201);
  assertEquals(res.body.outcome, "credited");
  assertEquals(res.body.cosignal, "counted");
  assertEquals(res.body.purchases.length, 2);
  const rows = await purchases(p.uid);
  assertEquals(rows.length, 2);
  for (const r of rows) {
    assertEquals([r.method, r.qr_variant, r.status, r.credit_status], ["course_qr", "rotating", "valid", "credited"]);
    assertEquals(r.cosignal?.fixId, fix.fixId);
  }
  // the fix is counted ONCE, as facility-level foreground_checkin evidence
  const ev = await adminSql()`select source, source_ref, facility_id, course_id, attestation_grade, status from app.evidence where user_id = ${p.uid}`;
  assertEquals(ev.length, 1);
  assertEquals([ev[0]!.source, ev[0]!.source_ref, ev[0]!.facility_id, ev[0]!.course_id, ev[0]!.attestation_grade, ev[0]!.status], ["foreground_checkin", `fix:${fix.fixId}`, shop.fac, null, "attested", "accepted"]);
  // the purchase never scored as a play
  assertEquals(await rawCount(`select count(*)::int as n from app.play where user_id = '${p.uid}'`), 0);
  // the token: single-use, consumed by this user; the check-in token consumed
  const tok = await adminSql()`select used_by_user, used_at from app.course_qr_token where nonce_hash = ${t.hash}`;
  assertEquals(tok[0]!.used_by_user, p.uid);
  assert(tok[0]!.used_at !== null);
  assertEquals(await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${jti}' and consumed_at is not null`), 1);
});

Deno.test("0051 (review MEDIUM-1): the app-review account's scan, with a qualifying fix, is 403 forbidden and writes NO purchase and NO credit; the refused request rolls back (the check-in token stays unspent); an ordinary player's identical scan is accepted", DT, async () => {
  const shop = await createShop("rev", "both", 2);
  const r = await freshPlayer("rev"); // the review account
  const n = await freshPlayer("rev-n"); // an ordinary player, the control
  await ensureServiceRole();
  await adminSql()`delete from app.app_review_demo_account where retired_at is null`; // at most ONE review account exists
  await adminSql()`insert into app.app_review_demo_account (user_id) values (${r.uid})`;
  const w = await adminSql()`insert into app.app_review_window (starts_at, ends_at, note) values (now() - interval '1 hour', now() + interval '1 hour', 'marker-scan test') returning id`;
  try {
    const t = await rotatingToken(shop);
    const jti = await checkinToken(r, shop);
    const err = await httpError(scan(r, shop, { qr: { variant: "rotating", token: t.token }, fix: fixOf(), jti }));
    assertEquals([err?.status, err?.code], [403, "forbidden"]);
    assertEquals((await purchases(r.uid)).length, 0, "no purchase and no credit for the review account");
    assertEquals(await rawCount(`select count(*)::int as n from app.marker_credit where user_id = '${r.uid}'`), 0);
    assertEquals(await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${jti}' and consumed_at is not null`), 0, "the refusal rolled the request back: the check-in token is unspent");
    assertEquals(await rawCount(`select count(*)::int as n from app.course_qr_token where nonce_hash = '${t.hash}' and used_at is not null`), 0, "and the QR token is unspent");
    // the co-signal intake (no QR) is refused the same way
    const jti2 = await checkinToken(r, shop);
    const err2 = await httpError(scan(r, shop, { fix: fixOf(), jti: jti2 }));
    assertEquals([err2?.status, err2?.code], [403, "forbidden"]);
    // control: an ordinary player's scan of a fresh token at the same shop is accepted
    const t2 = await rotatingToken(shop);
    const res = ok(await scan(n, shop, { qr: { variant: "rotating", token: t2.token }, ...(await withFix(n, shop)) }));
    assertEquals(res.body.outcome, "credited");
  } finally {
    await adminSql()`delete from app.app_review_window where id = ${w[0]!.id}`;
  }
});

Deno.test("Q1 replay: the same token again is 409 qr_used, and the refused request ROLLED BACK (the second check-in token is unspent, no second evidence row)", DT, async () => {
  const shop = await createShop("q1r");
  const a = await freshPlayer("q1r-a");
  const b = await freshPlayer("q1r-b");
  const t = await rotatingToken(shop);
  ok(await scan(a, shop, { qr: { variant: "rotating", token: t.token }, ...(await withFix(a, shop)) }));
  const jtiB = await checkinToken(b, shop);
  const second = fixOf();
  const err = await httpError(scan(b, shop, { qr: { variant: "rotating", token: t.token }, fix: second, jti: jtiB }));
  assertEquals([err?.status, err?.code], [409, "qr_used"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${jtiB}' and consumed_at is not null`), 0, "the refused scan did not spend B's check-in token");
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where source_ref = 'fix:${second.fixId}'`), 0, "...nor leave an evidence row");
  assertEquals((await purchases(b.uid)).length, 0);
});

Deno.test("Q1: a token more than 120 s from the FIX time is 422 qr_expired; no fix is `pending`, and a later qualifying fix inside the window completes it (AT(19), AT(3))", DT, async () => {
  const shop = await createShop("q1w");
  const p = await freshPlayer("q1w");
  // an old token and a fresh fix: expired, judged against the fix
  const old = await rotatingToken(shop, { ageSec: 600 });
  const err = await httpError(scan(p, shop, { qr: { variant: "rotating", token: old.token }, ...(await withFix(p, shop)) }));
  assertEquals([err?.status, err?.code], [422, "qr_expired"]);
  // no fix at all: a pending purchase and a pending credit, never credited
  const t = await rotatingToken(shop);
  const pending = ok(await scan(p, shop, { qr: { variant: "rotating", token: t.token } }));
  assertEquals([pending.status, pending.body.outcome, pending.body.cosignal], [201, "pending", "none"]);
  let rows = await purchases(p.uid);
  assertEquals([rows[0]!.status, rows[0]!.credit_status], ["pending", "pending"]);
  assertEquals(rows[0]!.cosignal?.awaiting !== undefined, true, "the awaiting window is the seam S3's offline-code purchase uses too");
  // the co-signal intake: only a fix, inside the +-120 s of the token's issue time
  const jti = await checkinToken(p, shop);
  const fix = fixOf();
  const done = ok(await scan(p, shop, { fix, jti }));
  assertEquals([done.status, done.body.outcome, done.body.cosignal], [200, "credited", "counted"]);
  rows = await purchases(p.uid);
  assertEquals(rows.length, 1);
  assertEquals([rows[0]!.status, rows[0]!.credit_status], ["valid", "credited"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where user_id = '${p.uid}' and source_ref = 'fix:${fix.fixId}'`), 1, "the fix is counted once");
  // a second intake finds nothing pending
  const again = await httpError(scan(p, shop, { ...(await withFix(p, shop)) }));
  assertEquals([again?.status, again?.code], [422, "no_pending_purchase"]);
});

Deno.test("Q1 with an `unattestable` fix is `held_review`; a SIMULATED fix, or one far from the facility, is no co-signal (pending, no evidence row)", DT, async () => {
  const shop = await createShop("q1g");
  const a = await freshPlayer("q1g-a");
  const held = ok(await scan(a, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, ...(await withFix(a, shop, "unattestable")) }));
  assertEquals(held.body.outcome, "held_review");
  const rowsA = await purchases(a.uid);
  assertEquals([rowsA[0]!.status, rowsA[0]!.credit_status], ["held_review", "held_review"]);
  const b = await freshPlayer("q1g-b");
  const sim = ok(await scan(b, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, ...(await withFix(b, shop, "attested", { simulated: true })) }));
  assertEquals([sim.body.outcome, sim.body.cosignal], ["pending", "none"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where user_id = '${b.uid}'`), 0);
  // a fix FAR from the facility (the real PostGIS containment, polygon + 50 m) is no co-signal either
  const c = await freshPlayer("q1g-c");
  const far = ok(await scan(c, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, ...(await withFix(c, shop, "attested", { lat: NASHVILLE.lat + 0.05 })) }));
  assertEquals([far.body.outcome, far.body.cosignal], ["pending", "none"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where user_id = '${c.uid}'`), 0);
  // ... and one just OUTSIDE the polygon edge (~0.001 deg is ~111 m: the square's half-side) but inside the 50 m buffer is a co-signal
  const d = await freshPlayer("q1g-d");
  const edge = ok(await scan(d, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, ...(await withFix(d, shop, "attested", { lat: NASHVILLE.lat + 0.001 + 0.0002 })) }));
  assertEquals([edge.body.outcome, edge.body.cosignal], ["credited", "counted"]);
});

Deno.test("a FORGED rotating token: 422 invalid_qr, the fraud_signal COMMITS, the real token is untouched; an unknown kid is the same, and a genuine token for ANOTHER facility is a plain 422 (no second signal)", DT, async () => {
  const shop = await createShop("forge");
  const p = await freshPlayer("forge");
  const real = await rotatingToken(shop);
  const attacker = await generateTestSigningKey();
  const e = await env();
  const forged = (await mintRotatingToken({ key: attacker, kid: e.rotKid, facilityId: shop.fac, iat: Math.floor(Date.now() / 1000) })).token;
  const out = await scan(p, shop, { qr: { variant: "rotating", token: forged } });
  assertEquals(out.kind, "refused");
  if (out.kind === "refused") assertEquals([out.error.status, out.error.code], [422, "invalid_qr"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.fraud_signal where user_id = '${p.uid}' and kind = 'course_qr_forged'`), 1, "the forgery's signal committed");
  assertEquals(await rawCount(`select count(*)::int as n from app.course_qr_token where nonce_hash = '${real.hash}' and used_at is not null`), 0);
  assertEquals((await purchases(p.uid)).length, 0);
  // an unknown kid
  const unknown = (await mintRotatingToken({ key: e.rot, kid: "no_such_kid", facilityId: shop.fac, iat: Math.floor(Date.now() / 1000) })).token;
  assertEquals((await scan(p, shop, { qr: { variant: "rotating", token: unknown } })).kind, "refused");
  // a genuine token minted for ANOTHER facility is a mismatch (422), not a forgery: no second signal
  const other = await createShop("forge-o");
  const wrongFac = await rotatingToken(other);
  const mismatch = await httpError(scan(p, shop, { qr: { variant: "rotating", token: wrongFac.token } }));
  assertEquals([mismatch?.status, mismatch?.code], [422, "invalid_qr"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.fraud_signal where user_id = '${p.uid}' and kind = 'course_qr_forged'`), 2);
});

Deno.test("Q1 concurrency: the same token scanned by 6 players at once yields exactly ONE purchase (single use under a real race)", DT, async () => {
  const shop = await createShop("q1c");
  const t = await rotatingToken(shop);
  const players = await Promise.all(Array.from({ length: 6 }, (_, i) => freshPlayer(`q1c-${i}`)));
  const jtis: string[] = [];
  for (const p of players) jtis.push(await checkinToken(p, shop)); // sequential: the grade fixture takes a temporary table policy, one at a time
  const results = await Promise.allSettled(players.map((p, i) => scan(p, shop, { qr: { variant: "rotating", token: t.token }, fix: fixOf(), jti: jtis[i] })));
  const accepted = results.filter((r) => r.status === "fulfilled");
  const refused = results.filter((r) => r.status === "rejected") as PromiseRejectedResult[];
  assertEquals(accepted.length, 1, "exactly one scan won the token");
  assertEquals(refused.length, 5);
  for (const r of refused) assertEquals([(r.reason as HttpError).status, (r.reason as HttpError).code], [409, "qr_used"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.purchase_evidence where facility_id = '${shop.fac}'`), 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.course_qr_token where nonce_hash = '${t.hash}' and used_at is not null`), 1);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// printed QR + daily PIN (Q2)
// ---------------------------------------------------------------------------------------------------------------------------------------------

Deno.test("Q2: the database's PIN equals the independent reference (today's PIN is accepted; the neighbour is a counted wrong PIN)", DT, async () => {
  const e = await env();
  const shop = await createShop("q2", "static_pin");
  const p = await freshPlayer("q2");
  const fix = fixOf();
  const date = localDateOf(fix.capturedAt);
  const pin = await referencePin(e.pepper, shop.fac, date, 0);
  // wrong first: refused AND committed (a counted failure), nothing recorded
  const wrongJti = await checkinToken(p, shop);
  const wrong = await scan(p, shop, { qr: await printedQr(shop, wrongOf(pin)), fix, jti: wrongJti });
  assertEquals(wrong.kind, "refused");
  if (wrong.kind === "refused") assertEquals([wrong.error.status, wrong.error.code], [422, "invalid_pin"]);
  assertEquals((await purchases(p.uid)).length, 0);
  assertEquals(await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${wrongJti}' and consumed_at is not null`), 0, "a wrong PIN is refused BEFORE the check-in token is consumed");
  // right: accepted, credited with a qualifying fix
  const jti = await checkinToken(p, shop);
  const good = ok(await scan(p, shop, { qr: await printedQr(shop, pin), fix: fixOf(), jti }));
  assertEquals([good.status, good.body.outcome], [201, "credited"]);
  const rows = await purchases(p.uid);
  assertEquals([rows[0]!.method, rows[0]!.qr_variant, rows[0]!.status], ["course_qr", "static_pin", "valid"]);
  assertEquals(rows[0]!.local_date, date);
  // the same account scanning the same facility's printed QR again the same day is a duplicate (one purchase per user per facility per local day)
  const dup = await httpError(scan(p, shop, { qr: await printedQr(shop, pin), ...(await withFix(p, shop)) }));
  assertEquals([dup?.status, dup?.code], [409, "duplicate_scan"]);
  // yesterday's PIN and another facility's PIN are wrong
  const q = await freshPlayer("q2-b");
  const yday = await referencePin(e.pepper, shop.fac, localDateOf(fix.capturedAt - 86_400_000), 0);
  assertEquals((await scan(q, shop, { qr: await printedQr(shop, yday) })).kind, "refused");
  const other = await createShop("q2o", "static_pin");
  assertEquals((await scan(q, shop, { qr: await printedQr(shop, await referencePin(e.pepper, other.fac, date, 0)) })).kind, "refused");
});

Deno.test("Q2: a FORGED printed-QR signature is 422 + fraud_signal (committed), and never reaches the PIN counters; the QR of facility X presented for Y is the same", DT, async () => {
  const shop = await createShop("q2f", "static_pin");
  const other = await createShop("q2f-o", "static_pin");
  const p = await freshPlayer("q2f");
  const e = await env();
  const pin = await referencePin(e.pepper, shop.fac, localDateOf(Date.now()), 0);
  const attacker = await generateTestSigningKey();
  const forged = await scan(p, shop, { qr: await printedQr(shop, pin, attacker) });
  assertEquals(forged.kind, "refused");
  if (forged.kind === "refused") assertEquals([forged.error.status, forged.error.code], [422, "invalid_qr"]);
  // X's genuine signature presented for Y
  const xForY = { ...(await printedQr(other, pin)), pin };
  assertEquals((await scan(p, shop, { qr: xForY })).kind, "refused");
  assertEquals(await rawCount(`select count(*)::int as n from app.fraud_signal where user_id = '${p.uid}' and kind = 'course_qr_forged'`), 2);
  // six forged scans are not six wrong PINs: the player's PIN is still not locked
  const good = ok(await scan(p, shop, { qr: await printedQr(shop, pin) }));
  assertEquals([good.status, good.body.outcome], [201, "pending"]);
});

Deno.test("Q2 race: the SAME player scanning the same printed QR 6 times at once records ONE purchase; the rest are 409 duplicate_scan (the unique index closes the race)", DT, async () => {
  const e = await env();
  const shop = await createShop("q2d", "static_pin");
  const p = await freshPlayer("q2d");
  const pin = await referencePin(e.pepper, shop.fac, localDateOf(Date.now()), 0);
  const qr = await printedQr(shop, pin);
  const results = await Promise.allSettled(Array.from({ length: 6 }, () => scan(p, shop, { qr })));
  assertEquals(results.filter((r) => r.status === "fulfilled").length, 1);
  for (const r of results) if (r.status === "rejected") assertEquals([(r.reason as HttpError).status, (r.reason as HttpError).code], [409, "duplicate_scan"]);
  assertEquals((await purchases(p.uid)).length, 1);
});

Deno.test("Q2 race at the database: the SAME player scanning one shop 8 times at once (gate + record in one transaction each) records ONE purchase; the rest are `duplicate` (the PIN gate's advisory lock serialises them)", DT, async () => {
  // The unique index (user, trail, ref) stays as the backstop; since the scan REQUIRES the PIN gate's proof, whose per-user advisory lock is held to the commit, a same-player race is serialised before it.
  const e = await env();
  const shop = await createShop("q2r", "static_pin");
  const p = await freshPlayer("q2r");
  const pin = await referencePin(e.pepper, shop.fac, localDateOf(Date.now()), 0);
  const input = { facilityId: shop.fac, variant: "static_pin" as const, nonceHash: null, qrKid: e.prtKid, pin, at: new Date(), cosignal: null };
  const results = await Promise.allSettled(
    Array.from({ length: 8 }, () =>
      withOwnership(p.actor, async (repo: Repo) => {
        const gate = await repo.markerScan.attemptPin({ facilityId: shop.fac, pin, at: input.at });
        assertEquals(gate.result, "ok");
        return repo.markerScan.record(input);
      }),
    ),
  );
  let accepted = 0;
  for (const r of results) {
    assertEquals(r.status, "fulfilled", r.status === "rejected" ? String((r.reason as Error).message) : "");
    if (r.status === "fulfilled") {
      if (r.value.status === "accepted") accepted += 1;
      else assertEquals(r.value.status, "duplicate");
    }
  }
  assertEquals(accepted, 1);
  assertEquals((await purchases(p.uid)).length, 1);
});

Deno.test("Q2 caps: a user's SIXTH wrong PIN at a facility in a day is 429 (even a correct PIN is then refused); parallel guesses cannot get past 5", DT, async () => {
  const e = await env();
  const shop = await createShop("q2c", "static_pin");
  const date = localDateOf(Date.now());
  const pin = await referencePin(e.pepper, shop.fac, date, 0);
  // sequential: 5 wrong -> 422 each, the 6th (a CORRECT pin) -> 429
  const p = await freshPlayer("q2c");
  for (let i = 0; i < 5; i++) {
    const r = await scan(p, shop, { qr: await printedQr(shop, wrongOf(pin, 1 + i)) });
    assertEquals(r.kind === "refused" && r.error.status, 422, `attempt ${i + 1}`);
  }
  const sixth = await scan(p, shop, { qr: await printedQr(shop, pin) });
  assertEquals(sixth.kind === "refused" && sixth.error.status, 429);
  assertEquals((await purchases(p.uid)).length, 0);
  // another account at the same facility is unaffected
  const other = await freshPlayer("q2c-b");
  assertEquals(ok(await scan(other, shop, { qr: await printedQr(shop, pin) })).status, 201);
  // parallel: 9 simultaneous wrong guesses by one account -> exactly 5 are counted wrong (422) and 4 are locked (429)
  const racer = await freshPlayer("q2c-r");
  const outs = await Promise.all(Array.from({ length: 9 }, async (_, i) => scan(racer, shop, { qr: await printedQr(shop, wrongOf(pin, 100 + i)) })));
  const codes = outs.map((o) => (o.kind === "refused" ? o.error.status : 0));
  assertEquals(codes.filter((c) => c === 422).length, 5);
  assertEquals(codes.filter((c) => c === 429).length, 4);
});

Deno.test("Q2 caps: 30 wrong PINs at one facility in a day ROTATE its PIN (epoch + 1) and raise an operator alarm; the old PIN is then wrong and the new one right", DT, async () => {
  const e = await env();
  const shop = await createShop("q2k", "static_pin");
  const date = localDateOf(Date.now());
  const pin0 = await referencePin(e.pepper, shop.fac, date, 0);
  const pin1 = await referencePin(e.pepper, shop.fac, date, 1);
  assertNotEquals(pin0, pin1);
  // 6 players x 5 wrong guesses (each below the per-user cap) = 30 failures at the facility; every guess is a distinct value that is neither epoch's PIN
  const guesses: string[] = [];
  for (let k = 1; guesses.length < 30; k++) {
    const g = wrongOf(pin0, k);
    if (g !== pin0 && g !== pin1) guesses.push(g);
  }
  const players = await Promise.all(Array.from({ length: 6 }, (_, i) => freshPlayer(`q2k-${i}`)));
  await Promise.all(
    players.map(async (p, pi) => {
      for (let i = 0; i < 5; i++) {
        const r = await scan(p, shop, { qr: await printedQr(shop, guesses[pi * 5 + i]!) });
        assertEquals(r.kind, "refused");
      }
    }),
  );
  const prog = await adminSql()`select max(pin_epoch)::int as epoch from app.facility_programme where facility_id = ${shop.fac}`;
  assertEquals(prog[0]!.epoch, 1, "the PIN rotated");
  const alarm = await adminSql()`select pin_epoch_before, pin_epoch_after, failures from app.course_pin_alarm where facility_id = ${shop.fac}`;
  assertEquals(alarm.length, 1);
  assertEquals([alarm[0]!.pin_epoch_before, alarm[0]!.pin_epoch_after, alarm[0]!.failures], [0, 1, 30]);
  // the staff's printed-PIN screen of this facility now shows epoch 1: a fresh player with the OLD PIN is refused, with the NEW PIN accepted
  const late = await freshPlayer("q2k-late");
  assertEquals((await scan(late, shop, { qr: await printedQr(shop, pin0) })).kind, "refused");
  assertEquals(ok(await scan(late, shop, { qr: await printedQr(shop, pin1) })).status, 201);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// what edge_actor can and cannot reach; the pepper's absence
// ---------------------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------------------
// the gate's follow-ups: M1 (a rotation must not break a queued scan), M2 (the co-signal is read back), L1, L5, L6
// ---------------------------------------------------------------------------------------------------------------------------------------------

Deno.test("M1 end to end: a printed-QR scan CAPTURED before a rotation and uploaded after it is accepted and counts NOTHING against the honest player; the same old PIN tried now is a wrong guess", DT, async () => {
  const e = await env();
  const shop = await createShop("m1", "static_pin");
  const honest = await freshPlayer("m1h");
  const jti = await checkinToken(honest, shop);
  const fix = fixOf(); // captured now, BEFORE the rotation below
  const pin0 = await referencePin(e.pepper, shop.fac, localDateOf(fix.capturedAt), 0);
  await sleep(60);
  // six other accounts, five wrong guesses each: the 30th rotates the PIN
  const guesses: string[] = [];
  for (let k = 1; guesses.length < 30; k++) {
    const g = wrongOf(pin0, k);
    if (g !== pin0) guesses.push(g);
  }
  const players = await Promise.all(Array.from({ length: 6 }, (_, i) => freshPlayer(`m1-${i}`)));
  await Promise.all(players.map(async (p, pi) => {
    for (let i = 0; i < 5; i++) await scan(p, shop, { qr: await printedQr(shop, guesses[pi * 5 + i]!) });
  }));
  const epoch = await adminSql()`select max(pin_epoch)::int as epoch from app.facility_programme where facility_id = ${shop.fac}`;
  assertEquals(epoch[0]!.epoch, 1, "the PIN rotated");
  assertEquals(await rawCount(`select count(*)::int as n from app.course_pin_epoch_log where facility_id = '${shop.fac}' and pin_epoch = 1 and previous_epoch = 0`), 1, "and the rotation is logged");
  // the honest upload, after the rotation: the PIN displayed when the fix was taken (epoch 0)
  const res = ok(await scan(honest, shop, { qr: await printedQr(shop, pin0), fix, jti }));
  assertEquals([res.status, res.body.outcome], [201, "credited"]);
  assertEquals(await rawCount(`select count(*)::int as n from private.rate_limit_bucket where bucket_key like 'marker-scan:pin-fail:u:${honest.uid}:%'`), 0, "nothing was counted against the honest player");
  // the same OLD PIN tried now (no fix: the instant is now, epoch 1 is live) is a wrong guess
  const late = await freshPlayer("m1-late");
  const wrong = await scan(late, shop, { qr: await printedQr(shop, pin0) });
  assertEquals(wrong.kind, "refused");
  assertEquals(await rawCount(`select count(*)::int as n from private.rate_limit_bucket where bucket_key like 'marker-scan:pin-fail:u:${late.uid}:%'`), 1, "a rotated-out PIN tried now IS counted");
});

Deno.test("L6: a co-signal that arrives BEFORE the staff row exists is 422 no_pending_purchase and rolled back; the SAME request succeeds once the row exists (the client retries until the 7-day bound)", DT, async () => {
  const shop = await createShop("l6", "both");
  const p = await freshPlayer("l6");
  const jti = await checkinToken(p, shop);
  const fix = fixOf();
  const early = await httpError(scan(p, shop, { fix, jti }));
  assertEquals([early?.status, early?.code], [422, "no_pending_purchase"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${jti}' and consumed_at is not null`), 0, "the refused intake did not spend the check-in token");
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where source_ref = 'fix:${fix.fixId}'`), 0, "nor leave an evidence row");
  // later, S3's staff lane records the offline-code purchase (pending, with its +-10 minute window around the code's step and the 7-day deadline)
  const iso = (ms: number) => new Date(ms).toISOString();
  await ensureServiceRole();
  const sql = adminSql();
  const awaiting = { awaiting: { from: iso(fix.capturedAt - 10 * 60_000), to: iso(fix.capturedAt + 10 * 60_000), until: iso(Date.now() + 7 * 86_400_000) } };
  const [row] = await sql`
    insert into app.purchase_evidence (user_id, facility_id, trail_id, method, ref_id, offline, cosignal, local_date, status)
    values (${p.uid}, ${shop.fac}, ${shop.trails[0]!}, 'staff_scan', ${"offline:" + p.deviceId + ":1:1"}, true, ${sql.json(awaiting)}, ${localDateOf(fix.capturedAt)}, 'pending') returning id`;
  await sql`insert into app.marker_credit (user_id, trail_id, facility_id, purchase_evidence_id, status) values (${p.uid}, ${shop.trails[0]!}, ${shop.fac}, ${row!.id}, 'pending')`;
  const retried = ok(await scan(p, shop, { fix, jti }));
  assertEquals([retried.status, retried.body.outcome, retried.body.cosignal], [200, "credited", "counted"]);
  const rows = await purchases(p.uid);
  assertEquals([rows[0]!.method, rows[0]!.status, rows[0]!.credit_status], ["staff_scan", "valid", "credited"]);
});

Deno.test("L1 end to end: a photographed rotating token cannot be burned days later (no fix, or a simulated one dated inside its window): qr_expired, token unspent", DT, async () => {
  const shop = await createShop("l1");
  const p = await freshPlayer("l1");
  const old = await rotatingToken(shop, { ageSec: 3 * 86_400 });
  const none = await httpError(scan(p, shop, { qr: { variant: "rotating", token: old.token } }));
  assertEquals([none?.status, none?.code], [422, "qr_expired"]);
  const jti = await checkinToken(p, shop);
  const fabricated = await httpError(scan(p, shop, { qr: { variant: "rotating", token: old.token }, fix: fixOf({ capturedAt: old.issuedAtMs + 20_000, simulated: true }), jti }));
  assertEquals([fabricated?.status, fabricated?.code], [422, "qr_expired"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.course_qr_token where nonce_hash = '${old.hash}' and used_at is not null`), 0);
  assertEquals((await purchases(p.uid)).length, 0);
  // and at the database: no co-signal and a time far from now is refused outright
  const e = await env();
  const t = await rotatingToken(shop);
  const direct = await httpError(withOwnership(p.actor, (repo: Repo) => repo.markerScan.record({ facilityId: shop.fac, variant: "rotating", nonceHash: t.hash, qrKid: e.rotKid, pin: null, at: new Date(Date.now() - 86_400_000), cosignal: null })));
  assertEquals(direct?.code, "invalid_scan");
});

Deno.test("a check-in token that does not fit the fix (already spent, another device's, or a fix captured before its challenge) is NO co-signal: the scan is `pending`, never a refusal, and the read-only check consumed nothing", DT, async () => {
  const shop = await createShop("peek");
  const p = await freshPlayer("peek");
  // 1. a token a first scan already spent
  const jti = await checkinToken(p, shop);
  ok(await scan(p, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, fix: fixOf(), jti }));
  const spent = ok(await scan(p, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, fix: fixOf(), jti }));
  assertEquals([spent.status, spent.body.outcome, spent.body.cosignal], [201, "pending", "none"]);
  // 2. another device's token (the same account): the token is bound to its own device
  const q = await freshPlayer("peek-b");
  const jtiB = await checkinToken(q, shop);
  const otherDevice = freshUuid();
  await withOwnership(q.actor, (repo: Repo) => repo.device.ensureOwn(otherDevice, "android"));
  const wrongDevice = ok(await scan({ ...q, deviceId: otherDevice }, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, fix: fixOf(), jti: jtiB }));
  assertEquals([wrongDevice.body.outcome, wrongDevice.body.cosignal], ["pending", "none"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${jtiB}' and consumed_at is not null`), 0, "the unconsumed token of the right device is untouched");
  // 3. a fix captured an hour BEFORE the challenge was issued (outside its window)
  const r = await freshPlayer("peek-c");
  const jtiC = await checkinToken(r, shop);
  const early = ok(await scan(r, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token }, fix: fixOf({ capturedAt: Date.now() - 3_600_000 }), jti: jtiC }));
  assertEquals([early.body.outcome, early.body.cosignal], ["pending", "none"]);
  assertEquals(await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${jtiC}' and consumed_at is not null`), 0);
});

Deno.test("L5: the scan definer is never an uncounted PIN oracle: a printed-QR record() without the PIN gate's proof in the same transaction is refused, with a right or a wrong PIN", DT, async () => {
  const e = await env();
  const shop = await createShop("l5", "static_pin");
  const p = await freshPlayer("l5");
  const pin = await referencePin(e.pepper, shop.fac, localDateOf(Date.now()), 0);
  for (const guess of [pin, wrongOf(pin)]) {
    let code = "no error";
    try {
      await withOwnership(p.actor, (repo: Repo) => repo.markerScan.record({ facilityId: shop.fac, variant: "static_pin", nonceHash: null, qrKid: e.prtKid, pin: guess, at: new Date(), cosignal: null }));
    } catch (err) {
      code = String((err as { code?: unknown }).code);
    }
    assertEquals(code, "42501");
  }
  assertEquals(await rawCount(`select count(*)::int as n from private.rate_limit_bucket where bucket_key like 'marker-scan:pin-fail:u:${p.uid}:%'`), 0);
});

Deno.test("the PIN proof is empty at rest: a COMMITTED printed-QR scan, and a COMMITTED PIN gate with no scan after it, leave no row of private.course_pin_proof (read back as the owner; the probe is proven able to see a row)", DT, async () => {
  const e = await env();
  const shop = await createShop("proof", "static_pin");
  const a = await freshPlayer("proof-a");
  const b = await freshPlayer("proof-b");
  const pin = await referencePin(e.pepper, shop.fac, localDateOf(Date.now()), 0);
  const count = () => withOwnerPolicy("private.course_pin_proof", async (sql) => (await sql`select count(*)::int as n from private.course_pin_proof`)[0]!.n as number);
  // the control: the owner connection CAN see (and here plants and removes) a row, so a zero below is not a blind probe
  const planted = await withOwnerPolicy("private.course_pin_proof", async (sql) => {
    await sql`insert into private.course_pin_proof (backend_pid, xact, actor_uid, facility_id, local_date, pin_at) values (0, '1'::xid8, ${a.uid}, ${shop.fac}, current_date, now())`;
    const n = (await sql`select count(*)::int as n from private.course_pin_proof`)[0]!.n as number;
    await sql`delete from private.course_pin_proof where backend_pid = 0`;
    return n;
  });
  assertEquals(planted, 1, "control: the probe sees a planted row");
  assertEquals(await count(), 0);
  // a PIN gate that passes and COMMITS, with nothing after it
  const gate = await withOwnership(a.actor, (repo: Repo) => repo.markerScan.attemptPin({ facilityId: shop.fac, pin, at: new Date() }));
  assertEquals(gate.result, "ok");
  assertEquals(await count(), 0, "a committed gate with no scan after it left no proof");
  // a committed scan (gate + scan in one request transaction), by another player on the same pooled connections
  ok(await scan(b, shop, { qr: await printedQr(shop, pin) }));
  assertEquals((await purchases(b.uid)).length, 1);
  assertEquals(await count(), 0, "a committed scan left no proof");
  // and a refused scan (rolled back by the handler) leaves none either
  const refused = await httpError(scan(b, shop, { qr: await printedQr(shop, pin) }));
  assertEquals(refused?.code, "duplicate_scan");
  assertEquals(await count(), 0, "a refused scan left no proof");
});

Deno.test("M2: the database reads the co-signal back: an invented evidence id is cosignal_invalid, and a real evidence row cannot back a second scan (cosignal_used)", DT, async () => {
  const e = await env();
  const shop = await createShop("m2");
  const p = await freshPlayer("m2");
  const t1 = await rotatingToken(shop);
  const t2 = await rotatingToken(shop);
  const invented = await withOwnership(p.actor, (repo: Repo) =>
    repo.markerScan.record({ facilityId: shop.fac, variant: "rotating", nonceHash: t1.hash, qrKid: e.rotKid, pin: null, at: new Date(), cosignal: { grade: "attested", fixId: "invented-fix", evidenceId: freshUuid() } }));
  assertEquals(invented.status, "cosignal_invalid");
  // a real, counted fix backs the first scan ...
  const jti = await checkinToken(p, shop);
  const fix = fixOf();
  ok(await scan(p, shop, { qr: { variant: "rotating", token: t1.token }, fix, jti }));
  const ev = await adminSql()`select id from app.evidence where user_id = ${p.uid} and source_ref = ${"fix:" + fix.fixId}`;
  // ... and the SAME evidence row offered for a second scan is refused by the database
  const reused = await withOwnership(p.actor, (repo: Repo) =>
    repo.markerScan.record({ facilityId: shop.fac, variant: "rotating", nonceHash: t2.hash, qrKid: e.rotKid, pin: null, at: new Date(fix.capturedAt), cosignal: { grade: "attested", fixId: fix.fixId, evidenceId: ev[0]!.id as string } }));
  assertEquals(reused.status, "cosignal_used");
  // another account's evidence row is not the actor's: invalid
  const other = await freshPlayer("m2o");
  const stolen = await withOwnership(other.actor, (repo: Repo) =>
    repo.markerScan.record({ facilityId: shop.fac, variant: "rotating", nonceHash: t2.hash, qrKid: e.rotKid, pin: null, at: new Date(fix.capturedAt), cosignal: { grade: "attested", fixId: fix.fixId, evidenceId: ev[0]!.id as string } }));
  assertEquals(stolen.status, "cosignal_invalid");
});

Deno.test("as the real edge_actor: the key table, the alarm table, the purchase table and the PIN derivation core are out of reach", DT, async () => {
  await env();
  const p = await freshPlayer("iso");
  const code = async (run: (trx: TxSql) => Promise<unknown>): Promise<string> => {
    try {
      await openScopedTx("actor", userBind(p.uid), run);
    } catch (e) {
      return String((e as { code?: unknown }).code);
    }
    return "no error";
  };
  assertEquals(await code((trx) => trx`select count(*) from app.course_qr_key`), "42501");
  assertEquals(await code((trx) => trx`select count(*) from app.course_pin_alarm`), "42501");
  assertEquals(await code((trx) => trx`select count(*) from app.purchase_evidence`), "42501");
  assertEquals(await code((trx) => trx`select count(*) from app.marker_credit`), "42501");
  assertEquals(await code((trx) => trx`select count(*) from app.course_qr_token`), "42501");
  assertEquals(await code((trx) => trx`select private.course_pin_derive('fac_x', current_date, 0)`), "42501");
  assertEquals(await code((trx) => trx`select decrypted_secret from vault.decrypted_secrets where name = 'course_pin_pepper'`), "42501");
  assertEquals(await code((trx) => trx`insert into app.course_qr_key (purpose, kid, public_key_b64url) values ('rotating_token', 'x', ${base64UrlEncode(randomBytes(32))})`), "42501");
  assertEquals(await code((trx) => trx`update app.course_qr_token set used_at = now() where false`), "42501", "no direct write to the token table either");
  // control: the wrapper itself answers (the public-key lookup returns a key without any table grant)
  const e = await env();
  const found = await openScopedTx("actor", userBind(p.uid), (trx) => trx`select o_public_key_b64url, o_revoked from private.course_qr_public_key_for_actor(${e.rotKid}, 'rotating_token')`);
  assertEquals([found.length, found[0]!.o_public_key_b64url, found[0]!.o_revoked], [1, e.rot.publicKeyB64Url, false]);
});

Deno.test("no pepper in Vault: a printed-QR scan is 503 course_pin_unavailable (the rotating-token lane is unaffected), then cleanup of the keys and the pepper", DT, async () => {
  const e = await env();
  const shop = await createShop("nopep");
  const p = await freshPlayer("nopep");
  await rawOwnerSql()`delete from vault.secrets where name = 'course_pin_pepper'`;
  try {
    const err = await httpError(scan(p, shop, { qr: await printedQr(shop, "1234") }));
    assertEquals([err?.status, err?.code], [503, "course_pin_unavailable"]);
    const q1 = ok(await scan(p, shop, { qr: { variant: "rotating", token: (await rotatingToken(shop)).token } }));
    assertEquals(q1.status, 201, "Q1 needs no pepper");
  } finally {
    await rawOwnerSql()`delete from vault.secrets where name = 'course_pin_pepper'`;
    await withOwnerPolicy("app.course_qr_key", (sql) => sql`delete from app.course_qr_key where kid in (${e.rotKid}, ${e.prtKid})`);
  }
});
