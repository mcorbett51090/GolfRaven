// supabase/tests/integration/retention-purge.deno.test.ts
//
// Edge role PR4b (E5, launch-blocking): the independent retention schedule, `retention-purge`. The REAL handler over the REAL privileged.ts steps
// (`retentionPurgeSteps`, `hitSystemRateLimit`, `isServiceRoleBearer`) against the harness cluster, as edge_system. Proved here:
//   1. it purges EACH class (fix coordinates, install-link tombstones, sign-in email proofs, finished revocation rows) and keeps what is not yet
//      past retention (a young row of each class, and a PENDING revocation row however old);
//   2. it is BOUNDED per run (a batch limit, a batch cap) and a second run finishes the job;
//   3. it refuses a bad bearer (and an absent service-role key) before it touches anything, rate limit included;
//   4. it is idempotent and safe to run concurrently: overlapping runs never double-count, never deadlock, and a step another run holds is skipped;
//   5. one class failing does not stop the others (needs a superuser harness to revoke a grant);
//   6. the rate limit (12 per hour) holds.
// The pure contract (ordering, truncation, busy, failure codes, no database text on the wire) is supabase/tests/unit/retention-purge-handler.test.ts.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawCount } from "./_helpers.ts";
import { hitSystemRateLimit, isServiceRoleBearer, resetPrivilegedConnectionsForTests, retentionPurgeSteps, retentionStepLockKeys } from "../../functions/_shared/privileged.ts";
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
  // controls: everything is there before the run
  assertEquals(await hasCoords(coords.aged), true);
  assertEquals(await tombstoneCount(oldTomb), 1);
  assertEquals(await proofExists(staleProof), true);
  assertEquals(await queueRowExists(oldQueue), true);

  const r = await run(realDeps());
  assertEquals(r.status, 200, JSON.stringify(r.raw));
  assertEquals(r.steps.map((s) => s.name), ["fix_coords", "install_link_tombstones", "signin_email_proofs", "signin_revocation_queue"]);
  for (const s of r.steps) assert(s.purged >= 1, `${s.name} purged something: ${JSON.stringify(s)}`);
  assertEquals(r.complete, true);

  // purged: past retention
  assertEquals(await hasCoords(coords.aged), false, "the 31-day-old row lost its raw fix coordinates");
  assertEquals(await tombstoneCount(oldTomb), 0, "the 25-month-old tombstone is gone");
  assertEquals(await proofExists(staleProof), false, "the proof an hour past its expiry is gone");
  assertEquals(await queueRowExists(oldQueue), false, "the revocation row finished 40 days ago is gone");
  // kept: not past retention
  assertEquals(await hasCoords(coords.young), true, "a young row at a re-pickable (stub) course keeps its coordinates");
  assertEquals(await tombstoneCount(youngTomb), 1, "the 23-month-old tombstone is kept");
  assertEquals(await proofExists(liveProof), true, "a live proof is kept");
  assertEquals(await queueRowExists(youngQueue), true, "a revocation row finished 5 days ago is kept");
  assertEquals(await queueRowExists(pendingQueue), true, "a PENDING revocation row is never purged, however old");
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
