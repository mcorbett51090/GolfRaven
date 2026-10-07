// supabase/tests/integration/retention-purge.deno.test.ts
//
// Edge role PR4b (E5, launch-blocking): the independent retention schedule, `retention-purge`. The REAL handler over the REAL privileged.ts steps
// (`retentionPurgeSteps`, `hitSystemRateLimit`, `isServiceRoleBearer`) against the harness cluster, as edge_system. Proved here:
//   1. it purges EACH class (fix coordinates, install-link tombstones, sign-in email proofs, finished revocation rows and, since 0040, consumed-nonce
//      tombstones and rate-limit windows) and keeps what is not yet past retention (a young row of each class, a PENDING revocation row however old,
//      a live nonce tombstone, a current-window rate-limit row); the `<uid>:me-delete:user` bucket delete_my_data keeps is removed once its window passed;
//   2. it is BOUNDED per run (a batch limit, a batch cap) and a second run finishes the job;
//   3. it refuses a bad bearer (and an absent service-role key) before it touches anything, rate limit included;
//   4. it is idempotent and safe to run concurrently: overlapping runs never double-count, never deadlock, and a step another run holds is skipped;
//   5. one class failing does not stop the others (needs a superuser harness to revoke a grant);
//   6. the rate limit (12 per hour) holds;
//   7. (0040) the four SQL-bounded steps clear a backlog larger than one batch over several batches, a full batch is exactly RETENTION_DEFINER_BATCH_ROWS,
//      and the catalog import's own purge calls honour the same per-step try-lock;
//   8. (PR4b gate LOW-2) an empty service-role key admits nobody, even a bearer that only SEEMS empty (NBSP, U+3000) after normalisation.
// The pure contract (ordering, truncation, busy, failure codes, no database text on the wire) is supabase/tests/unit/retention-purge-handler.test.ts.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawCount, rawOwnerSql } from "./_helpers.ts";
import { hitSystemRateLimit, isServiceRoleBearer, resetPrivilegedConnectionsForTests, RETENTION_DEFINER_BATCH_ROWS, retentionPurgeSteps, retentionStepLockKeys, withSystemCatalogImport } from "../../functions/_shared/privileged.ts";
import { handleRetentionPurgeRequest, type RetentionDeps, RETENTION_RATE_BUCKET, MAX_BATCHES_PER_STEP } from "../../functions/_shared/retention/purge-handler.ts";
import { sha256Hex } from "../../functions/_shared/signin/bytes.ts";
import { facilityShard, freshSiteVersion, giveCoursePolygon, ids, mint, newPublisher, newUser, seedDwellAndScore } from "./_publisher.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const PGHOST = Deno.env.get("PGHOST")!;
const PGPORT = Number(Deno.env.get("PGPORT"));
const PGUSER = Deno.env.get("PGUSER")!;
const PGDATABASE = Deno.env.get("PGDATABASE")!;
const KEY = `retention-purge-test-${crypto.randomUUID()}`; // random per run: nothing key-shaped is committed

/** One test with the scheduler's bearer in the environment (the way the deployed function gets it); everything is put back afterwards. */
function retentionTest(name: string, fn: () => void | Promise<void>): void {
  Deno.test(name, DT, async () => {
    const saved = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", KEY);
    try {
      await fn();
    } finally {
      if (saved === undefined) Deno.env.delete("SUPABASE_SERVICE_ROLE_KEY");
      else Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", saved);
      await resetPrivilegedConnectionsForTests();
    }
  });
}

const post = (bearer: string | null = KEY) => new Request("https://x.test/retention-purge", { method: "POST", headers: bearer === null ? {} : { authorization: `Bearer ${bearer}` } });

/** The real wiring of retention-purge/index.ts, with overridable parts. */
function realDeps(over: Partial<RetentionDeps> = {}): RetentionDeps {
  return { isAuthorized: isServiceRoleBearer, hitRateLimit: hitSystemRateLimit, steps: retentionPurgeSteps(), nowMs: () => Date.now(), log: () => undefined, ...over };
}
/** The same, with the rate limit out of the way (only the cells about the rate limit use the real one). */
const unlimited = async () => ({ ok: true, count: 1 });

type StepRow = { name: string; status: string; purged: number; batches: number; error?: string };
async function run(deps: RetentionDeps, req: Request = post()): Promise<{ status: number; steps: StepRow[]; complete: boolean | undefined; raw: unknown }> {
  const res = await handleRetentionPurgeRequest(req, deps);
  const json = await res.json();
  const data = res.status === 200 ? json.data : json.error?.details;
  return { status: res.status, steps: data?.steps ?? [], complete: data?.complete, raw: json };
}
const stepOf = (r: { steps: StepRow[] }, name: string): StepRow => r.steps.find((s) => s.name === name)!;

function rawHarness() {
  return postgres({ host: PGHOST, port: PGPORT, username: PGUSER, database: PGDATABASE, max: 1, prepare: false });
}
async function isSuperuserHarness(): Promise<boolean> {
  const raw = rawHarness();
  try {
    return Boolean((await raw`select rolsuper from pg_roles where rolname = session_user`)[0]?.rolsuper);
  } finally {
    await raw.end({ timeout: 1 });
  }
}
/** A connection that can act as private_definer (the only role with any privilege on the sign-in proof and revocation tables). */
async function asDefiner<T>(fn: (sql: ReturnType<typeof postgres>) => Promise<T>): Promise<T> {
  const sql = rawHarness();
  try {
    return (await sql.begin(async (trx: ReturnType<typeof postgres>) => {
      await trx`set local role private_definer`;
      return fn(trx);
    })) as T;
  } finally {
    await sql.end({ timeout: 1 });
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// seeding
// ---------------------------------------------------------------------------------------------------------------------------------------------

/** Two evidence rows that keep raw fix coordinates at a STUB course (so a young row keeps them), the FIRST of them aged 31 days. */
async function seedFixCoords(): Promise<{ aged: string; young: string }> {
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "stub", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "unverified", [{ id: i.k, name: "E5 purge K", holes: 18 }]),
  });
  await giveCoursePolygon(i.k);
  const user = await newUser("e5-coords");
  await seedDwellAndScore(user, i.fac, i.k, "unverified", { withCoords: true });
  await seedDwellAndScore(user, i.fac, i.k, "unverified", { withCoords: true });
  await ensureServiceRole();
  const rows = await adminSql()`select id from app.evidence where user_id = ${user.uid} and integrity ? 'fixCoords' order by created_at, id`;
  assertEquals(rows.length, 2, "two evidence rows carry raw coordinates");
  const aged = rows[0]!.id as string;
  const young = rows[1]!.id as string;
  await adminSql()`update app.evidence set created_at = now() - interval '31 days' where id = ${aged}`;
  return { aged, young };
}
const hasCoords = async (id: string) => (await adminSql()`select integrity ? 'fixCoords' as has from app.evidence where id = ${id}`)[0]!.has as boolean;

/** An install-link tombstone first seen `months` months ago (a fresh account's pseudonym; no live row for it). */
async function seedTombstone(months: number): Promise<string> {
  await ensureServiceRole();
  const uid = freshUuid();
  await createTestUser(uid, `e5-tomb-${uid.slice(0, 8)}`);
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(freshUuid())))].map((x) => x.toString(16).padStart(2, "0")).join("");
  await adminSql()`
    insert into app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id, first_seen_at)
    select ${hash}, a.pseudonym, a.key_id, now() - make_interval(months => ${months}::int) from private.account_pseudonyms(${uid}::uuid) a where a.preferred`;
  return hash;
}
const tombstoneCount = (hash: string) => rawCount(`select count(*)::int as n from app.install_link_account where install_link_hash = '${hash}'`);
const agedTombstones = () => rawCount(`select count(*)::int as n from app.install_link_account where first_seen_at < now() - interval '24 months'`);

/** A sign-in email proof (private; a definer-only table): `live` expires in 5 minutes, otherwise it expired 2 h 55 min ago. */
async function seedProof(live: boolean): Promise<string> {
  const caller = await newUser("e5-proof-c");
  const target = await newUser("e5-proof-t");
  const id = freshUuid();
  const sub = await sha256Hex(`apple:e5-${id}`);
  const email = await sha256Hex(`e5-${id}@example.test`);
  await asDefiner(async (sql) => {
    await sql`select set_config('app.signin.proof_id', ${id}, true)`;
    if (live) {
      await sql`insert into private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at)
                values (${id}, ${caller.uid}, ${target.uid}, ${email}, 'apple', ${sub}, now(), now() + interval '5 minutes')`;
    } else {
      await sql`insert into private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at)
                values (${id}, ${caller.uid}, ${target.uid}, ${email}, 'apple', ${sub}, now() - interval '3 hours', now() - interval '2 hours 55 minutes')`;
    }
  });
  return id;
}
const proofExists = (id: string) => asDefiner(async (sql) => {
  await sql`select set_config('app.signin.proof_id', ${id}, true)`;
  return (await sql`select 1 from private.signin_email_proof where id = ${id}`).length === 1;
});

/** A revocation-queue row: finished (`revoked`) `daysAgo` days ago, or PENDING (never purged, however old; its 72 h expiry is the drain's claim). */
async function seedQueueRow(kind: { finishedDaysAgo: number } | "pending"): Promise<string> {
  const id = freshUuid();
  await asDefiner(async (sql) => {
    if (kind === "pending") {
      await sql`insert into private.signin_revocation_queue (id, provider, source, token_fingerprint, refresh_token_ciphertext, dek_wrapped, kek_id, status, created_at, expires_at)
                values (${id}, 'apple', 'unlink', ${"e5-" + id}, decode('01', 'hex'), decode('02', 'hex'), 'e5-kek', 'pending', now() - interval '100 days', now() + interval '1 hour')`;
    } else {
      await sql`insert into private.signin_revocation_queue (id, provider, source, token_fingerprint, status, created_at, completed_at)
                values (${id}, 'apple', 'unlink', ${"e5-" + id}, 'revoked', now() - make_interval(days => ${kind.finishedDaysAgo}::int + 1), now() - make_interval(days => ${kind.finishedDaysAgo}::int))`;
    }
  });
  return id;
}
const queueRowExists = (id: string) => asDefiner(async (sql) => (await sql`select 1 from private.signin_revocation_queue where id = ${id}`).length === 1);

/** A consumed-nonce tombstone (service_role may INSERT and SELECT it, nothing else): `expired` = 8 days past its source expiry, otherwise 1 hour past it. */
async function seedNonce(expired: boolean): Promise<string> {
  await ensureServiceRole();
  const hash = `e5-nonce-${freshUuid()}`;
  await adminSql()`insert into private.consumed_nonce (nonce_hash, source, consumed_at, expires_at)
                   values (${hash}, 'checkin_challenge', now() - interval '31 days', now() - make_interval(hours => ${expired ? 192 : 1}::int))`;
  return hash;
}
const nonceExists = async (hash: string) => (await rawCount(`select count(*)::int as n from private.consumed_nonce where nonce_hash = '${hash}'`)) === 1;

/** A rate-limit bucket (private_definer is the only role with a policy on it): its window started `daysAgo` days ago (0 = the current window). */
async function seedBucket(key: string, daysAgo: number): Promise<void> {
  await asDefiner(async (sql) => {
    await sql`insert into private.rate_limit_bucket (bucket_key, window_start, count) values (${key}, now() - make_interval(days => ${daysAgo}::int), 1)`;
  });
}
const bucketExists = (key: string) => asDefiner(async (sql) => (await sql`select 1 from private.rate_limit_bucket where bucket_key = ${key}`).length === 1);

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 1. each class
// ---------------------------------------------------------------------------------------------------------------------------------------------

retentionTest("E5: one run purges EACH retention class past its retention, and keeps what is not (a young row of each; a pending revocation row however old)", async () => {
  const coords = await seedFixCoords();
  const oldTomb = await seedTombstone(25);
  const youngTomb = await seedTombstone(23);
  const staleProof = await seedProof(false);
  const liveProof = await seedProof(true);
  const oldQueue = await seedQueueRow({ finishedDaysAgo: 40 });
  const youngQueue = await seedQueueRow({ finishedDaysAgo: 5 });
  const pendingQueue = await seedQueueRow("pending");
  const oldNonce = await seedNonce(true);
  const liveNonce = await seedNonce(false);
  const oldBucketKey = `e5-bucket-old-${freshUuid()}`;
  const liveBucketKey = `e5-bucket-live-${freshUuid()}`;
  await seedBucket(oldBucketKey, 3);
  await seedBucket(liveBucketKey, 0);
  // controls: everything is there before the run
  assertEquals(await hasCoords(coords.aged), true);
  assertEquals(await tombstoneCount(oldTomb), 1);
  assertEquals(await proofExists(staleProof), true);
  assertEquals(await queueRowExists(oldQueue), true);
  assertEquals(await nonceExists(oldNonce), true);
  assertEquals(await bucketExists(oldBucketKey), true);

  const r = await run(realDeps());
  assertEquals(r.status, 200, JSON.stringify(r.raw));
  assertEquals(r.steps.map((s) => s.name), ["fix_coords", "install_link_tombstones", "signin_email_proofs", "signin_revocation_queue", "consumed_nonce", "rate_limit_buckets"]);
  for (const s of r.steps) assert(s.purged >= 1, `${s.name} purged something: ${JSON.stringify(s)}`);
  assertEquals(r.complete, true);

  // purged: past retention
  assertEquals(await hasCoords(coords.aged), false, "the 31-day-old row lost its raw fix coordinates");
  assertEquals(await tombstoneCount(oldTomb), 0, "the 25-month-old tombstone is gone");
  assertEquals(await proofExists(staleProof), false, "the proof an hour past its expiry is gone");
  assertEquals(await queueRowExists(oldQueue), false, "the revocation row finished 40 days ago is gone");
  assertEquals(await nonceExists(oldNonce), false, "the tombstone 8 days past its expiry is gone (0040: the nonce purge is a retention step)");
  assertEquals(await bucketExists(oldBucketKey), false, "the rate-limit window that started 3 days ago is gone (0040: the bucket purge is a retention step)");
  // kept: not past retention
  assertEquals(await hasCoords(coords.young), true, "a young row at a re-pickable (stub) course keeps its coordinates");
  assertEquals(await tombstoneCount(youngTomb), 1, "the 23-month-old tombstone is kept");
  assertEquals(await proofExists(liveProof), true, "a live proof is kept");
  assertEquals(await queueRowExists(youngQueue), true, "a revocation row finished 5 days ago is kept");
  assertEquals(await queueRowExists(pendingQueue), true, "a PENDING revocation row is never purged, however old");
  assertEquals(await nonceExists(liveNonce), true, "a tombstone only an hour past its expiry is kept (the floor is 7 days)");
  assertEquals(await bucketExists(liveBucketKey), true, "a current-window rate-limit row is kept");
  // the evidence row itself survives: only the coordinates went
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where id = '${coords.aged}'`), 1);
});

retentionTest("E5: running it AGAIN removes nothing and still succeeds (idempotent)", async () => {
  const again = await run(realDeps({ hitRateLimit: unlimited }));
  assertEquals(again.status, 200);
  for (const s of again.steps) assertEquals([s.status, s.purged], ["done", 0], s.name);
  assertEquals(again.complete, true);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 2. bounded
// ---------------------------------------------------------------------------------------------------------------------------------------------

retentionTest("E5: a run is BOUNDED (a batch limit, a batch cap): with a batch of 1 row it purges exactly MAX_BATCHES_PER_STEP tombstones and reports `truncated`; the next run finishes", async () => {
  const seeded: string[] = [];
  for (let k = 0; k < MAX_BATCHES_PER_STEP + 3; k++) seeded.push(await seedTombstone(30));
  const agedBefore = await agedTombstones();
  assert(agedBefore >= MAX_BATCHES_PER_STEP + 3, "control: more aged rows exist than one capped run may remove");

  const first = await run(realDeps({ hitRateLimit: unlimited, steps: retentionPurgeSteps(1) }));
  assertEquals(first.status, 200);
  const t1 = stepOf(first, "install_link_tombstones");
  assertEquals([t1.status, t1.purged, t1.batches], ["truncated", MAX_BATCHES_PER_STEP, MAX_BATCHES_PER_STEP], "exactly the cap, one row per batch");
  assertEquals(await agedTombstones(), agedBefore - MAX_BATCHES_PER_STEP, "the database agrees: that many rows went and no more");
  assertEquals(first.complete, false);

  // the next run continues where it stopped, and finishes
  const second = await run(realDeps({ hitRateLimit: unlimited, steps: retentionPurgeSteps(1000) }));
  const t2 = stepOf(second, "install_link_tombstones");
  assertEquals([t2.status, t2.purged], ["done", agedBefore - MAX_BATCHES_PER_STEP]);
  assertEquals(await agedTombstones(), 0);
  for (const h of seeded) assertEquals(await tombstoneCount(h), 0);
});

retentionTest("E5: the retention bounds are the DATABASE's: a batch limit the definer refuses fails that step (22023) and the others still run", async () => {
  const spy = console.error;
  console.error = () => undefined; // the handler logs each failing step server-side; keep the test output clean
  let r;
  try {
    r = await run(realDeps({ hitRateLimit: unlimited, steps: retentionPurgeSteps(0) }));
  } finally {
    console.error = spy;
  }
  assertEquals(r.status, 500);
  assertEquals(stepOf(r, "fix_coords").error, "22023");
  assertEquals(stepOf(r, "install_link_tombstones").error, "22023");
  assertEquals(stepOf(r, "signin_email_proofs").status, "done", "the unbatched classes ran");
  assertEquals(stepOf(r, "signin_revocation_queue").status, "done");
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 3. authentication
// ---------------------------------------------------------------------------------------------------------------------------------------------

retentionTest("E5: a bad bearer is 401 BEFORE anything is touched: no purge, and not even a rate-limit hit", async () => {
  const oldTomb = await seedTombstone(26);
  await ensureServiceRole();
  const bucketBefore = await rawCount(`select coalesce(sum(count), 0)::int as n from private.rate_limit_bucket where bucket_key = 'system:${RETENTION_RATE_BUCKET}'`);
  for (const bearer of [null, "wrong", KEY + "x", KEY.slice(0, -1), "", "Bearer"]) {
    const r = await run(realDeps(), bearer === null ? post(null) : bearer === "Bearer" ? new Request("https://x.test/", { method: "POST", headers: { authorization: KEY } }) : post(bearer));
    assertEquals(r.status, 401, `bearer ${JSON.stringify(bearer)}`);
  }
  assertEquals(await tombstoneCount(oldTomb), 1, "nothing was purged by any of them");
  assertEquals(await rawCount(`select coalesce(sum(count), 0)::int as n from private.rate_limit_bucket where bucket_key = 'system:${RETENTION_RATE_BUCKET}'`), bucketBefore, "no rate-limit hit either");
  // the right bearer works, and clears it
  assertEquals((await run(realDeps({ hitRateLimit: unlimited }))).status, 200);
  assertEquals(await tombstoneCount(oldTomb), 0);
});

retentionTest("E5: with NO service-role key in the environment, nothing authenticates (an empty key is never a valid bearer)", async () => {
  Deno.env.delete("SUPABASE_SERVICE_ROLE_KEY");
  for (const bearer of ["", KEY, "undefined"]) {
    const r = await run(realDeps(), post(bearer));
    assertEquals(r.status, 401, `bearer ${JSON.stringify(bearer)}`);
  }
});

/** A request whose Authorization header is exactly `value`. Deno's Headers refuse a value that is not a ByteString (U+3000 throws), so a value the
 * real class cannot carry is handed over as the same two members the code under test reads: this is a test of the COMPARISON, which must not rest on
 * the transport having already refused the byte. */
function requestWithAuthorization(value: string): Request {
  try {
    return new Request("https://x.test/retention-purge", { method: "POST", headers: { authorization: value } });
  } catch {
    return { method: "POST", headers: { get: (name: string) => (name.toLowerCase() === "authorization" ? value : null) } } as unknown as Request;
  }
}

// PR4b gate LOW-2: removing the `key === ""` guard in isServiceRoleBearer survived the mutation run. With an EMPTY configured key, a bearer that only LOOKS empty
// (header normalisation strips space, tab, CR and LF but not NBSP / U+3000; the code's own .trim() then strips those) compared "" to "" and would have admitted
// anyone. Each shape is asserted against the function and through the whole handler, with the key unset AND set to the empty string.
for (const configured of ["unset", "empty"] as const) {
  retentionTest(`E5/LOW-2: with the service-role key ${configured === "unset" ? "unset" : "set to the empty string"}, a bearer that trims to "" (NBSP, U+3000, ...) is 401, never admitted`, async () => {
    if (configured === "unset") Deno.env.delete("SUPABASE_SERVICE_ROLE_KEY");
    else Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "");
    const oldTomb = await seedTombstone(33);
    const shapes = ["\u00a0", "\u3000", "\u00a0\u3000", "\u2003", "\ufeff", "\u00a0\u00a0\u00a0"];
    for (const shape of shapes) {
      const auth = `Bearer ${shape}`;
      // the control that makes this a test of the guard: after the comparison's own trim the presented token IS the (empty) configured key
      assertEquals(auth.slice(auth.indexOf(" ") + 1).trim(), "", `control: ${JSON.stringify(shape)} trims to the empty string, equal to the empty key`);
      assertEquals(isServiceRoleBearer(requestWithAuthorization(auth)), false, `isServiceRoleBearer admitted ${JSON.stringify(auth)}`);
      const r = await run(realDeps(), requestWithAuthorization(auth));
      assertEquals(r.status, 401, `the handler admitted ${JSON.stringify(auth)}`);
    }
    assertEquals(isServiceRoleBearer(requestWithAuthorization("Bearer ")), false, "a plain empty bearer too");
    assertEquals(await tombstoneCount(oldTomb), 1, "nothing was purged by any of them");
    // the control the other way: the real key admits, and clears it
    Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", KEY);
    assertEquals((await run(realDeps({ hitRateLimit: unlimited }))).status, 200);
    assertEquals(await tombstoneCount(oldTomb), 0);
  });
}

retentionTest("E5/LOW-2 control: with a real key configured the same function admits exactly that key (so the cells above are not vacuously false)", () => {
  assertEquals(isServiceRoleBearer(requestWithAuthorization(`Bearer ${KEY}`)), true);
  assertEquals(isServiceRoleBearer(requestWithAuthorization(`Bearer \u00a0`)), false);
  assertEquals(isServiceRoleBearer(requestWithAuthorization(`Bearer ${KEY}x`)), false);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 1b. 0040: the two hygiene steps in the real flow, and the `<uid>:me-delete:user` bucket delete_my_data keeps
// ---------------------------------------------------------------------------------------------------------------------------------------------

retentionTest("0040: the bucket private.delete_my_data KEEPS (<uid>:me-delete:user) is removed by the purge once its window is more than a day past, and not before", async () => {
  await ensureServiceRole();
  const uid = freshUuid();
  await createTestUser(uid, `e5-del-${uid.slice(0, 8)}`);
  const meDelete = `${uid}:me-delete:user`;
  // the real shapes: the account hits its me-delete limit and an evidence limit (the same function the Edge runtime reaches through hit_actor_rate_limit), then deletes itself
  await adminSql()`select private.hit_rate_limit(${meDelete}, interval '1 day', 5)`;
  await adminSql()`select private.hit_rate_limit(${uid + ":evidence"}, interval '1 hour', 60)`;
  await adminSql()`select private.delete_my_data(${uid}::uuid)`;
  assertEquals(await bucketExists(meDelete), true, "control: delete_my_data kept the me-delete bucket (so a retry of the deletion stays limited)");
  assertEquals(await bucketExists(`${uid}:evidence`), false, "control: ... and removed every other bucket of the account");

  const during = await run(realDeps({ hitRateLimit: unlimited }));
  assertEquals(during.status, 200);
  assertEquals(await bucketExists(meDelete), true, "a purge while its window is current keeps it");

  await asDefiner(async (sql) => {
    await sql`update private.rate_limit_bucket set window_start = now() - interval '1 day 23 hours' where bucket_key = ${meDelete}`;
  });
  assertEquals(stepOf(await run(realDeps({ hitRateLimit: unlimited })), "rate_limit_buckets").status, "done");
  assertEquals(await bucketExists(meDelete), true, "a day after its window ended it is still kept (windows are purged 2 days after they START)");

  await asDefiner(async (sql) => {
    await sql`update private.rate_limit_bucket set window_start = now() - interval '2 days 1 hour' where bucket_key = ${meDelete}`;
  });
  const after = await run(realDeps({ hitRateLimit: unlimited }));
  assert(stepOf(after, "rate_limit_buckets").purged >= 1, JSON.stringify(stepOf(after, "rate_limit_buckets")));
  assertEquals(await bucketExists(meDelete), false, "once its window is more than a day past the purge removes it: the 'nightly sweep' the requirements assumed is this step");
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 2b. 0040: the four SQL-bounded steps (a constant inside each definer) clear a backlog larger than one batch
// ---------------------------------------------------------------------------------------------------------------------------------------------

/** 5003 expired rows of each of the four classes the definers bound themselves (one more batch than RETENTION_DEFINER_BATCH_ROWS holds), plus one LIVE row of each. */
async function seedBacklog(): Promise<{ liveProof: string; livePending: string; liveNonce: string; liveBucket: string }> {
  await ensureServiceRole();
  const caller = await newUser("e5-bl-c");
  const target = await newUser("e5-bl-t");
  const n = RETENTION_DEFINER_BATCH_ROWS + 3;
  const tag = freshUuid().slice(0, 8);
  const liveProof = await seedProof(true);
  const livePending = await seedQueueRow("pending");
  const liveNonce = await seedNonce(false);
  const liveBucket = `e5-live-${tag}`;
  await seedBucket(liveBucket, 0);
  await adminSql()`insert into private.consumed_nonce (nonce_hash, source, consumed_at, expires_at)
                   select ${"e5-bl-" + tag + "-"} || g, 'checkin_challenge', now() - interval '12 days', now() - interval '10 days' from generate_series(1, ${n}::int) g`;
  await asDefiner(async (sql) => {
    await sql`insert into private.rate_limit_bucket (bucket_key, window_start, count) select ${"e5-bl-" + tag + ":"} || g, now() - interval '5 days', 1 from generate_series(1, ${n}::int) g`;
    await sql`insert into private.signin_revocation_queue (provider, source, token_fingerprint, status, created_at, completed_at)
              select 'apple', 'unlink', ${"e5-bl-" + tag + "-"} || g, 'revoked', now() - interval '50 days', now() - interval '40 days' from generate_series(1, ${n}::int) g`;
    // a proof is written one row at a time (its INSERT policy names the row's id in a GUC): a loop inside the database
    await sql.unsafe(`do $d$ declare v uuid; begin
        for i in 1..${n} loop
          v := gen_random_uuid();
          perform set_config('app.signin.proof_id', v::text, true);
          insert into private.signin_email_proof (id, caller_user_id, target_user_id, provider, email_hash, sub_hash, created_at, expires_at)
          values (v, '${caller.uid}', '${target.uid}', 'apple', repeat('a', 64), repeat('b', 64), now() - interval '3 hours', now() - interval '170 minutes');
        end loop;
        perform set_config('app.signin.proof_id', '', true);
      end $d$`);
  });
  // No ANALYZE here, deliberately. The S1.1b slice added one because the 0040 purges (`DELETE ... WHERE id IN (SELECT ... LIMIT 5000)`) ran in O(n^2) when pg_class held stale statistics (a vacuum that could
  // not truncate leaves "148 pages, 0 tuples"). Since 0050 the definers take their batch once and no longer depend on the plan, so the suite does not depend on which state autovacuum left the template
  // database in; the cell "0050: stale planner statistics ..." below builds exactly that state on purpose and pins it.
  return { liveProof, livePending, liveNonce, liveBucket };
}

const BOUNDED_CLASSES = ["signin_email_proofs", "signin_revocation_queue", "consumed_nonce", "rate_limit_buckets"] as const;

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 2c. 0050 (S1.1b gate L-4): the batched purges do not depend on the planner's statistics
// ---------------------------------------------------------------------------------------------------------------------------------------------

const STALE_TABLES = ["private.signin_email_proof", "private.signin_revocation_queue", "private.consumed_nonce", "private.rate_limit_bucket"] as const;

/**
 * Put the four backlog tables into the state the S1.1b gate found them in, WITHOUT an ANALYZE: load a backlog, delete it, VACUUM (TRUNCATE false) (a vacuum that could not truncate, made deterministic:
 * the pages stay, pg_class says "N pages, 0 tuples"), then load the backlog again. The planner now estimates 5003 fresh rows as one row. Autovacuum is switched off on the four tables for the duration
 * so it cannot repair the statistics under the test; the returned function puts that back.
 */
async function makeStatsStale(): Promise<() => Promise<void>> {
  const owner = rawOwnerSql();
  for (const t of STALE_TABLES) await owner.unsafe(`alter table ${t} set (autovacuum_enabled = false)`);
  const restore = async () => {
    for (const t of STALE_TABLES) await owner.unsafe(`alter table ${t} reset (autovacuum_enabled)`);
  };
  try {
    await seedBacklog();
    await asDefiner(async (sql) => {
      await sql`delete from private.consumed_nonce where coalesce(expires_at, consumed_at) < now() - interval '7 days'`;
      await sql`delete from private.rate_limit_bucket where window_start < now() - interval '2 days'`;
      await sql`delete from private.signin_revocation_queue where status <> 'pending' and completed_at < now() - interval '30 days'`;
      await sql`select set_config('app.signin.proof_purge', 'on', true)`;
      await sql`delete from private.signin_email_proof where expires_at < now() - interval '1 hour'`;
    });
    await owner.unsafe(`vacuum (truncate false) ${STALE_TABLES.join(", ")}`);
    await seedBacklog();
    return restore;
  } catch (e) {
    await restore();
    throw e;
  }
}

/** The 0040 / 0041 statement shapes, verbatim, as private_definer (the role the definers run as). Each is the whole body of the purge, which is a single DELETE. */
const OLD_PURGE_SHAPES: Record<(typeof BOUNDED_CLASSES)[number], string> = {
  consumed_nonce: `delete from private.consumed_nonce n where n.nonce_hash in (select s.nonce_hash from private.consumed_nonce s where coalesce(s.expires_at, s.consumed_at) < now() - interval '7 days' limit 5000)`,
  rate_limit_buckets: `delete from private.rate_limit_bucket b where (b.bucket_key, b.window_start) in (select s.bucket_key, s.window_start from private.rate_limit_bucket s where s.window_start < now() - interval '2 days' limit 5000)`,
  signin_email_proofs: `delete from private.signin_email_proof p where p.id in (select s.id from private.signin_email_proof s where s.expires_at < now() - interval '1 hour' order by s.expires_at, s.id limit 5000)`,
  signin_revocation_queue: `delete from private.signin_revocation_queue q where q.id in (select s.id from private.signin_revocation_queue s where s.status <> 'pending' and s.completed_at < now() - interval '30 days' limit 5000)`,
};
const STALE_BUDGET_MS = 1000;
class StatementFinished extends Error {}

retentionTest("0050: with STALE planner statistics (no ANALYZE) each batched purge is fast, and the 0040 statement shape is NOT (positive control); the whole backlog is still cleared", async () => {
  const restore = await makeStatsStale();
  try {
    // the precondition: the planner really is misled (a test that passed because autovacuum had repaired the statistics would prove nothing)
    for (const t of STALE_TABLES) {
      const [schema, rel] = t.split(".");
      const stat = await rawCount(`select c.reltuples::int as n from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = '${schema}' and c.relname = '${rel}'`);
      assert(stat < 1000, `${t} is estimated at ${stat} tuples (the 5003 loaded rows must be unaccounted for): the statistics are not stale`);
    }
    // positive control: the old shape cannot finish inside the budget on these statistics. (Each runs in its own transaction and is rolled back whatever happens.)
    for (const name of BOUNDED_CLASSES) {
      const outcome = await asDefiner(async (sql) => {
        await sql.unsafe(`set local statement_timeout = '${STALE_BUDGET_MS}ms'`);
        if (name === "signin_email_proofs") await sql`select set_config('app.signin.proof_purge', 'on', true)`;
        const t0 = Date.now();
        try {
          await sql.unsafe(OLD_PURGE_SHAPES[name]);
        } catch (e) {
          if ((e as { code?: string }).code === "57014") return "cancelled"; // the statement timeout: the transaction is aborted and ends in a rollback
          throw e;
        }
        throw new StatementFinished(`finished in ${Date.now() - t0} ms`); // never commit the old shape's deletes
      }).catch((e) => (e instanceof StatementFinished ? e.message : `error ${String(e)}`));
      assertEquals(outcome, "cancelled", `positive control: the 0040 shape of ${name} was not cancelled inside ${STALE_BUDGET_MS} ms on stale statistics (${outcome}), so this fixture no longer reproduces the pathology`);
    }
    // the 0050 definers: one full batch of each, timed
    const steps = retentionPurgeSteps();
    for (const name of BOUNDED_CLASSES) {
      const st = steps.find((x) => x.name === name)!;
      const t0 = Date.now();
      const n = await st.runBatch();
      const ms = Date.now() - t0;
      console.log(`0050 stale statistics: ${name} removed ${n} rows in ${ms} ms`);
      assertEquals(n, RETENTION_DEFINER_BATCH_ROWS, `${name}: a full batch`);
      assert(ms < STALE_BUDGET_MS, `${name} took ${ms} ms on stale statistics (budget ${STALE_BUDGET_MS} ms)`);
    }
    const r = await run(realDeps({ hitRateLimit: unlimited }));
    for (const name of BOUNDED_CLASSES) assertEquals(stepOf(r, name).status, "done", `${name}: ${JSON.stringify(stepOf(r, name))}`);
  } finally {
    await restore();
  }
});

retentionTest("0040: a backlog larger than one batch is cleared over SEVERAL batches by one run, for each of the four SQL-bounded steps; a live row of each survives", async () => {
  const live = await seedBacklog();
  const r = await run(realDeps({ hitRateLimit: unlimited }));
  assertEquals(r.status, 200, JSON.stringify(r.raw));
  for (const name of BOUNDED_CLASSES) {
    const st = stepOf(r, name);
    assertEquals(st.status, "done", `${name}: ${JSON.stringify(st)}`);
    assert(st.purged >= RETENTION_DEFINER_BATCH_ROWS + 3, `${name} cleared the whole backlog: ${JSON.stringify(st)}`);
    assert(st.batches >= 2, `${name} needed more than one batch: ${JSON.stringify(st)}`);
  }
  assertEquals(await proofExists(live.liveProof), true, "the live proof survived every batch");
  assertEquals(await queueRowExists(live.livePending), true, "the old pending revocation row survived every batch");
  assertEquals(await nonceExists(live.liveNonce), true, "the live tombstone survived every batch");
  assertEquals(await bucketExists(live.liveBucket), true, "the current-window bucket survived every batch");
  // nothing expired is left, in any of the four tables
  assertEquals(await rawCount(`select count(*)::int as n from private.consumed_nonce where coalesce(expires_at, consumed_at) < now() - interval '7 days'`), 0);
  const left = await asDefiner(async (sql) => ({
    buckets: Number((await sql`select count(*)::int as n from private.rate_limit_bucket where window_start < now() - interval '2 days'`)[0]!.n),
    finished: Number((await sql`select count(*)::int as n from private.signin_revocation_queue where status <> 'pending' and completed_at < now() - interval '30 days'`)[0]!.n),
    proofs: Number((await sql`select count(*)::int as n from private.signin_email_proof where expires_at < now() - interval '1 hour'`)[0]!.n),
  }));
  assertEquals(left, { buckets: 0, finished: 0, proofs: 0 });
});

retentionTest("0040: a FULL batch of each SQL-bounded step is exactly RETENTION_DEFINER_BATCH_ROWS (the TypeScript constant and the constant inside each definer cannot drift apart)", async () => {
  await seedBacklog();
  assertEquals(RETENTION_DEFINER_BATCH_ROWS, 5000);
  const steps = retentionPurgeSteps();
  for (const name of BOUNDED_CLASSES) {
    const st = steps.find((x) => x.name === name)!;
    assertEquals(st.batchLimit, RETENTION_DEFINER_BATCH_ROWS, `${name}'s batchLimit is the definer's bound`);
    assertEquals(await st.runBatch(), RETENTION_DEFINER_BATCH_ROWS, `${name}: a batch against a larger backlog removes exactly that many rows`);
  }
  // leave the database clean for the cells after this one
  const r = await run(realDeps({ hitRateLimit: unlimited }));
  for (const name of BOUNDED_CLASSES) assertEquals(stepOf(r, name).status, "done");
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 4b. PR4c (NIT): the catalog import's own fix-coordinate / tombstone purge takes the SAME per-step try-lock as the retention steps
// ---------------------------------------------------------------------------------------------------------------------------------------------

/** Another session holding a retention step's advisory lock until released, exactly as a concurrent run's batch would. */
async function holdStepLock(name: Parameters<typeof retentionStepLockKeys>[0]): Promise<() => Promise<void>> {
  const [k1, k2] = retentionStepLockKeys(name);
  const other = rawHarness();
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let held!: () => void;
  const heldSignal = new Promise<void>((r) => (held = r));
  const holder = other.begin(async (trx: ReturnType<typeof postgres>) => {
    await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
    held();
    await gate;
  });
  await heldSignal;
  return async () => {
    release();
    await holder;
    await other.end({ timeout: 1 });
  };
}

retentionTest("PR4c: the import's own fix-coordinate purge skips (0 rows, no waiting) while the retention step's lock is held, and runs once it is released; the tombstone purge likewise", async () => {
  const coords = await seedFixCoords();
  const oldTomb = await seedTombstone(31);

  const releaseCoords = await holdStepLock("fix_coords");
  try {
    const t0 = Date.now();
    assertEquals(await withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeFixCoords(30, 5000)), 0, "skipped while the retention step holds its lock");
    assert(Date.now() - t0 < 4000, "the import's purge did not wait for the lock holder");
    assertEquals(await hasCoords(coords.aged), true, "and removed nothing");
    // a different step's lock is not held: the tombstone purge is unaffected
    assert((await withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeInstallLinkTombstones(100000))) >= 1, "the other step's purge ran");
    assertEquals(await tombstoneCount(oldTomb), 0);
  } finally {
    await releaseCoords();
  }
  assert((await withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeFixCoords(30, 5000))) >= 1, "released: the import's purge removes the coordinates");
  assertEquals(await hasCoords(coords.aged), false);
  assertEquals(await hasCoords(coords.young), true, "and only the aged row's");

  const tomb2 = await seedTombstone(32);
  const releaseTombs = await holdStepLock("install_link_tombstones");
  try {
    assertEquals(await withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeInstallLinkTombstones(100000)), 0, "the tombstone purge skips while ITS step's lock is held");
    assertEquals(await tombstoneCount(tomb2), 1);
  } finally {
    await releaseTombs();
  }
  assert((await withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeInstallLinkTombstones(100000))) >= 1);
  assertEquals(await tombstoneCount(tomb2), 0);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 4. concurrency
// ---------------------------------------------------------------------------------------------------------------------------------------------

retentionTest("E5: concurrent runs are safe: 6 overlapping runs over aged rows never fail, never double-count, and between them remove exactly what was aged", async () => {
  for (let round = 0; round < 2; round++) {
    for (let k = 0; k < 6; k++) await seedTombstone(27);
    const coords = await seedFixCoords();
    const agedBefore = await agedTombstones();
    assert(agedBefore >= 6);
    const runs = await Promise.all(Array.from({ length: 6 }, () => run(realDeps({ hitRateLimit: unlimited }))));
    for (const r of runs) {
      assertEquals(r.status, 200, `a concurrent run failed: ${JSON.stringify(r.raw)}`);
      for (const s of r.steps) assert(s.status === "done" || s.status === "busy", `${s.name}: ${s.status}`);
    }
    const sum = (name: string) => runs.reduce((n, r) => n + stepOf(r, name).purged, 0);
    assertEquals(sum("install_link_tombstones"), agedBefore, "every aged tombstone was removed exactly once across the runs (no double count)");
    assertEquals(await agedTombstones(), 0);
    assertEquals(await hasCoords(coords.aged), false);
    assertEquals(await hasCoords(coords.young), true, "and nothing that was not past retention went");
    assert(sum("fix_coords") >= 1);
  }
});

retentionTest("E5: a step another run HOLDS is skipped (busy), not waited for, and the other steps run; once released the next run does it", async () => {
  const oldTomb = await seedTombstone(28);
  const [k1, k2] = retentionStepLockKeys("install_link_tombstones");
  const other = rawHarness();
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let held!: () => void;
  const heldSignal = new Promise<void>((r) => (held = r));
  // session B: a transaction that holds the step's lock, exactly as a concurrent run's batch would
  const holder = other.begin(async (trx: ReturnType<typeof postgres>) => {
    await trx`select pg_advisory_xact_lock(${k1}, ${k2})`;
    held();
    await gate;
  });
  await heldSignal;
  try {
    const t0 = Date.now();
    const r = await run(realDeps({ hitRateLimit: unlimited }));
    assert(Date.now() - t0 < 4000, "the run did not wait for the lock holder");
    assertEquals(r.status, 200);
    assertEquals(stepOf(r, "install_link_tombstones"), { name: "install_link_tombstones", status: "busy", purged: 0, batches: 0 });
    assertEquals(r.complete, false);
    assertEquals(stepOf(r, "signin_email_proofs").status, "done", "the other steps ran");
    assertEquals(await tombstoneCount(oldTomb), 1, "the held step purged nothing");
  } finally {
    release();
    await holder;
    await other.end({ timeout: 1 });
  }
  const after = await run(realDeps({ hitRateLimit: unlimited }));
  assertEquals(stepOf(after, "install_link_tombstones").status, "done");
  assertEquals(await tombstoneCount(oldTomb), 0);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 5. one class failing
// ---------------------------------------------------------------------------------------------------------------------------------------------

retentionTest("E5: one class failing does not stop the others: with EXECUTE revoked from edge_system on the tombstone purge, that step fails (42501, a 500) and the rest purge", async () => {
  if (!(await isSuperuserHarness())) {
    console.log("E5 failure-isolation cell: skipped (the harness role is not a superuser; HARNESS_MODE=superuser runs it)");
    return;
  }
  const oldTomb = await seedTombstone(29);
  const staleProof = await seedProof(false);
  const raw = rawHarness();
  try {
    await raw.unsafe("revoke execute on function private.purge_install_link_tombstones(int) from edge_system");
    const spy = console.error;
    console.error = () => undefined; // the handler logs the failing step's error server-side; keep the test output clean
    try {
      const r = await run(realDeps({ hitRateLimit: unlimited }));
      assertEquals(r.status, 500);
      assertEquals(stepOf(r, "install_link_tombstones").status, "failed");
      assertEquals(stepOf(r, "install_link_tombstones").error, "42501");
      assertEquals(stepOf(r, "signin_email_proofs").status, "done");
      assertEquals(await proofExists(staleProof), false, "a later class was purged despite the earlier failure");
      assertEquals(await tombstoneCount(oldTomb), 1, "the failed class purged nothing");
    } finally {
      console.error = spy;
    }
  } finally {
    await raw.unsafe("grant execute on function private.purge_install_link_tombstones(int) to edge_system");
    await raw.end({ timeout: 1 });
  }
  assertEquals(stepOf(await run(realDeps({ hitRateLimit: unlimited })), "install_link_tombstones").status, "done");
  assertEquals(await tombstoneCount(oldTomb), 0, "restored: the next run purges it");
});

retentionTest("0040: without the owner-approved EXECUTE grant a hygiene step FAILS (42501) and every other step still runs: the grant is what the step needs, and nothing else substitutes for it", async () => {
  if (!(await isSuperuserHarness())) {
    console.log("0040 grant cell: skipped (the harness role is not a superuser; HARNESS_MODE=superuser runs it)");
    return;
  }
  const oldNonce = await seedNonce(true);
  const oldBucketKey = `e5-bucket-grant-${freshUuid()}`;
  await seedBucket(oldBucketKey, 4);
  const raw = rawHarness();
  try {
    await raw.unsafe("revoke execute on function private.purge_consumed_nonce() from edge_system");
    await raw.unsafe("revoke execute on function private.purge_rate_limit_buckets() from edge_system");
    const spy = console.error;
    console.error = () => undefined;
    try {
      const r = await run(realDeps({ hitRateLimit: unlimited }));
      assertEquals(r.status, 500);
      for (const name of ["consumed_nonce", "rate_limit_buckets"]) assertEquals([stepOf(r, name).status, stepOf(r, name).error], ["failed", "42501"], name);
      for (const name of ["fix_coords", "install_link_tombstones", "signin_email_proofs", "signin_revocation_queue"]) assertEquals(stepOf(r, name).status, "done", `${name} still ran`);
      assertEquals(await nonceExists(oldNonce), true, "nothing was purged without the grant");
      assertEquals(await bucketExists(oldBucketKey), true);
    } finally {
      console.error = spy;
    }
  } finally {
    await raw.unsafe("grant execute on function private.purge_consumed_nonce() to edge_system");
    await raw.unsafe("grant execute on function private.purge_rate_limit_buckets() to edge_system");
    await raw.end({ timeout: 1 });
  }
  const after = await run(realDeps({ hitRateLimit: unlimited }));
  assertEquals(after.status, 200);
  assertEquals(await nonceExists(oldNonce), false, "restored: the next run purges both");
  assertEquals(await bucketExists(oldBucketKey), false);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// 6. the rate limit (LAST: it uses the hour's whole budget)
// ---------------------------------------------------------------------------------------------------------------------------------------------

retentionTest("E5: the rate limit holds: 12 runs an hour, then 429 with a retry hint (a real system bucket)", async () => {
  const statuses: number[] = [];
  let retry: unknown;
  for (let n = 0; n < 15; n++) {
    const res = await handleRetentionPurgeRequest(post(), realDeps({ steps: [] }));
    statuses.push(res.status);
    if (res.status === 429) {
      retry = (await res.json()).error.details;
      break;
    }
  }
  assert(statuses.includes(429), `a 429 within 15 runs: ${statuses.join(",")}`);
  assert(statuses.indexOf(429) <= 12, `at most 12 runs were let through this hour (earlier cells used some): ${statuses.join(",")}`);
  assertEquals(retry, { retryAfterSeconds: 3600 });
});
