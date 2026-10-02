// supabase/tests/integration/catalog-drain-resilience.deno.test.ts
//
// P3e round 2 gate, against REAL Postgres through the REAL handlers:
//   NEW-1 (BLOCKER): a drain that runs BEFORE the covering import never
//     kills queued rows — a claim of a not-yet-imported version stays
//     `queued_catalog` across drains and only the 7-day timer ends it
//     (`needs_attention`, never `unknown_id`). (See the note below on why the
//     validly-signed variant is proven at unit level.)
//   NEW-2 (HIGH): a transient error (here a REAL lock timeout: a second
//     session holds the row's lock for 7 s) leaves the row queued.
//   NEW-3 (HIGH): replaying a terminal row never 500s.
//   LOW: a terminal row keeps no queued submission (queued_input and the
//     claimed_* columns are cleared).
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { withDelegatedActor, withOwnership, withSystemCatalogImport } from "../../functions/_shared/privileged.ts";
import { drainQueuedCatalog } from "../../functions/_shared/catalog/drain-orchestrator.ts";
import { makeDrainReadRepo } from "../../functions/_shared/catalog/drain-read-repo.ts";
import { handleEvidenceIntake } from "../../functions/_shared/evidence/handler.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawCount } from "./_helpers.ts";
import { facilityShard, ids, mint, newPublisher } from "./_publisher.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const drainRepo = makeDrainReadRepo(withSystemCatalogImport);
const drain = () => drainQueuedCatalog(drainRepo, withDelegatedActor, 500);

const todayChicago = () => new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

type Actor = { uid: string; role: "authenticated" };
async function newUser(label: string): Promise<Actor> {
  const uid = freshUuid();
  await createTestUser(uid, `drain-${label}-${uid.slice(0, 8)}`);
  return { uid, role: "authenticated" };
}

const statusOf = async (id: string) => {
  await ensureServiceRole();
  const rows = await adminSql()`select status, queued_input, claimed_facility_id, claimed_course_id, claimed_catalog_version from app.evidence where id = ${id}`;
  return rows[0]!;
};

// NOTE on the BLOCKER test below: it needs a VALIDLY SIGNED claim of a version
// that is newer than the cluster's current import yet not "far future" (> now +
// 1 day). The harness seeds its baseline `catalog_version` at 2030-01-02
// (`siteVersionFor(1)`) — and the other integration files insert 2030-dated
// fixtures — so in this shared cluster nothing within the 1-day bound is newer
// than "current". Re-dating the seed itself would push every other test's
// `SEED_SITE_VERSION` claim more than 5 RELEASES behind (each file imports its
// own versions, which would then sort ABOVE the seed). So the test shifts the
// 2027+ fixture versions into the past for its own duration and restores them
// in `finally` (nothing else runs concurrently: Deno runs the files in order).

/** Moves every `site_version` dated 2027 or later back 1000 years (order preserved) and returns the undo. */
async function shiftFutureVersionsIntoPast(): Promise<() => Promise<void>> {
  await ensureServiceRole();
  const rows = await adminSql()`select version, site_version from app.catalog_version where site_version >= '2027'`;
  for (const r of rows) await adminSql()`update app.catalog_version set site_version = ${String(Number((r.site_version as string).slice(0, 4)) - 1000) + (r.site_version as string).slice(4)} where version = ${r.version}`;
  return async () => {
    await ensureServiceRole();
    for (const r of rows) await adminSql()`update app.catalog_version set site_version = ${r.site_version} where version = ${r.version}`;
  };
}

Deno.test("NEW-1 (BLOCKER, real Postgres): a validly SIGNED claim of a newer, not-yet-imported version is queued; drains WITHOUT the import leave the rows queued (never unknown_id); once V is imported they resolve", DT, async () => {
  const restore = await shiftFutureVersionsIntoPast();
  try {
    const i = ids();
    const pub = await newPublisher();
    const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10).replace(/-/g, "");
    const V = `${tomorrow}-${freshUuid().replace(/-/g, "").slice(0, 7)}`;
    const cur = await adminSql()`select site_version from app.catalog_version where site_version is not null order by site_version desc, version desc limit 1`;
    assert(!cur[0] || (cur[0].site_version as string) < V, `precondition: V (${V}) must be newer than the cluster's current import (${cur[0]?.site_version})`);

    // V's release, built and signed but NOT imported. The claim is the REAL manifestSig a client would lift from its manifest.sig.json.
    const release = await pub.build(V, {
      "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(V) }, [i.k]: { id: i.k, status: "verified", transitions: mint(V) } } },
      "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Newer K", holes: 18 }]),
    });
    const users = [await newUser("v1"), await newUser("v2")];
    const ids2: string[] = [];
    for (const u of users) {
      const r = await withOwnership(u, (repo) => handleEvidenceIntake({ source: "self_report", deviceId: freshUuid(), facilityId: i.fac, courseId: i.k, localDate: todayChicago(), catalogVersion: V, manifestSig: release.manifestSig }, repo));
      assertEquals(r.status, "queued_catalog", "a validly signed newer claim is queued (202)");
      ids2.push((r as { evidenceId: string }).evidenceId);
    }

    // The drain runs after EVERY import (failed ones included) — here with V never imported. The OLD code
    // classified this claim `ok`, looked the ids up against the OLDER import, missed, and ended both rows unknown_id.
    for (let pass = 0; pass < 2; pass++) {
      const res = await drain();
      assertEquals(res.unknownId, 0, `pass ${pass}: ${JSON.stringify(res)}`);
      for (const id of ids2) assertEquals((await statusOf(id)).status, "queued_catalog", `pass ${pass}: stays queued`);
    }

    // Now V is imported (it carries the ids): the same rows resolve.
    await pub.apply(release);
    const after = await drain();
    assert(after.resolved >= 2, `after the covering import both rows resolve: ${JSON.stringify(after)}`);
    for (const id of ids2) assertEquals((await statusOf(id)).status, "accepted");
    for (const u of users) assertEquals(await rawCount(`select count(*)::int as n from app.play where user_id = '${u.uid}' and course_id = '${i.k}'`), 1);
  } finally {
    await restore();
  }
});

Deno.test("NEW-1/NEW-3/LOW: drains before the covering import leave a not-yet-imported claim queued; it ages out to needs_attention (never unknown_id) with its queued submission cleared; replaying terminal rows never 500s", DT, async () => {
  const claimedVersion = "20991231-" + freshUuid().replace(/-/g, "").slice(0, 7); // newer than anything imported
  const user = await newUser("ageout");
  await ensureServiceRole();
  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${user.uid}, 'ios')`;
  const facilityId = `fac_ghost_${freshUuid().replace(/-/g, "").slice(0, 12)}`;
  const queuedInput = { source: "self_report", deviceId, facilityId, localDate: todayChicago(), catalogVersion: claimedVersion };
  const ins = await adminSql()`
    insert into app.evidence (user_id, source, source_ref, input_hash, status, device_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, local_date)
    values (${user.uid}, 'self_report', ${"age-" + freshUuid()}, ${"m".repeat(64)}, 'queued_catalog', ${deviceId}, ${facilityId}, null, ${claimedVersion}, ${adminSql().json(queuedInput)}, ${todayChicago()})
    returning id`;
  const id = ins[0]!.id as string;

  // The drain runs after EVERY import (including failed ones): repeatedly,
  // with the claimed version never imported, NOTHING may go terminal.
  for (let pass = 0; pass < 2; pass++) {
    await drain();
    assertEquals((await statusOf(id)).status, "queued_catalog", `pass ${pass}: still queued`);
  }

  // 7 days on, covering import STILL not run: needs_attention — and a
  // terminal row keeps no queued submission (raw coordinates included).
  await adminSql()`update app.evidence set created_at = now() - interval '8 days' where id = ${id}`;
  await drain();
  const row = await statusOf(id);
  assertEquals(row.status, "needs_attention");
  assertEquals(row.queued_input, null);
  assertEquals(row.claimed_facility_id, null);
  assertEquals(row.claimed_course_id, null);
  assertEquals(row.claimed_catalog_version, null);

  // NEW-3: replay of a terminal row. Build a real accepted row through the
  // live handler, then rewrite it into the shape a drain leaves behind.
  const cur = await adminSql()`select site_version from app.catalog_version where site_version is not null order by site_version desc, version desc limit 1`;
  const body = { source: "self_report", deviceId: freshUuid(), facilityId: "fac_y", courseId: "crs_y1", localDate: todayChicago(), catalogVersion: cur[0]!.site_version as string };
  const first = await withOwnership(user, (repo) => handleEvidenceIntake(body, repo));
  assertEquals(first.status, "accepted");
  const evId = (first as { evidenceId: string }).evidenceId;

  await adminSql()`update app.evidence set status = 'needs_attention', facility_id = null, course_id = null, catalog_version = null where id = ${evId}`;
  const replayNA = await withOwnership(user, (repo) => handleEvidenceIntake(body, repo));
  assertEquals(replayNA, { status: "needs_attention", evidenceId: evId }, "a needs_attention replay is a stored-state result, never a 500");

  await adminSql()`update app.evidence set status = 'unknown_id' where id = ${evId}`;
  let thrown: unknown = null;
  try {
    await withOwnership(user, (repo) => handleEvidenceIntake(body, repo));
  } catch (err) {
    thrown = err;
  }
  assert(thrown !== null, "replay of an unknown_id row must reject");
  assertEquals((thrown as { status: number }).status, 422);
  assertEquals((thrown as { code: string }).code, "unknown_id");
});

Deno.test("NEW-2: a transient error (a REAL lock timeout — another session holds the row's lock for 7 s) leaves the row queued, even though the covering import already ran; the next healthy pass resolves it", DT, async () => {
  const user = await newUser("lock");
  await ensureServiceRole();
  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${user.uid}, 'ios')`;
  const cur = await adminSql()`select site_version from app.catalog_version where site_version is not null order by site_version desc, version desc limit 1`;
  const claimed = cur[0]!.site_version as string; // the covering import has run: the OLD code turned a throw into unknown_id here
  const queuedInput = { source: "self_report", deviceId, facilityId: "fac_y", courseId: "crs_y1", localDate: todayChicago(), catalogVersion: claimed };
  const ins = await adminSql()`
    insert into app.evidence (user_id, source, source_ref, input_hash, status, device_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, local_date)
    values (${user.uid}, 'self_report', ${"lock-" + freshUuid()}, ${"l".repeat(64)}, 'queued_catalog', ${deviceId}, 'fac_y', 'crs_y1', ${claimed}, ${adminSql().json(queuedInput)}, ${todayChicago()})
    returning id`;
  const id = ins[0]!.id as string;

  // A second session holds the row for 7 s (> the 5 s lock_timeout).
  const holder = adminSql().begin(async (trx) => {
    await trx`select id from app.evidence where id = ${id} for update`;
    await sleep(7000);
  });
  await sleep(800);
  const during = await drain();
  assert(during.errored >= 1, `the lock timeout must surface as an errored row, got ${JSON.stringify(during)}`);
  assertEquals((await statusOf(id)).status, "queued_catalog", "a transient error never makes the row terminal");
  await holder;

  const after = await drain();
  assert(after.resolved >= 1, `once the lock is released the row resolves, got ${JSON.stringify(after)}`);
  assertEquals((await statusOf(id)).status, "accepted");
  assertEquals(await rawCount(`select count(*)::int as n from app.play where user_id = '${user.uid}' and course_id = 'crs_y1'`), 1);
});
