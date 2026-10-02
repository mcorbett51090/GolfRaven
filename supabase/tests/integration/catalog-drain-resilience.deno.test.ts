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
import { withOwnership, withSystemCatalogImport } from "../../functions/_shared/privileged.ts";
import { drainQueuedCatalog } from "../../functions/_shared/catalog/drain-orchestrator.ts";
import { makeDrainReadRepo } from "../../functions/_shared/catalog/drain-read-repo.ts";
import { handleEvidenceIntake } from "../../functions/_shared/evidence/handler.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawCount } from "./_helpers.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const drainRepo = makeDrainReadRepo(withSystemCatalogImport);
const drain = () => drainQueuedCatalog(drainRepo, withOwnership, 500);

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

// NOTE on NEW-1: its BLOCKER path needs a VALIDLY SIGNED claim of a version that
// is newer than the cluster's current import yet not "far future" (> now + 1
// day). The harness seeds its baseline `catalog_version` at 2030-01-02
// (`siteVersionFor(1)`), so nothing within the 1-day bound can be newer than
// "current" in this shared cluster. That exact path is therefore proven at
// unit level with a real Ed25519 signature (drain-orchestrator.test.ts, "NEW-1")
// and by a mutation proof; this test covers what the real database adds: a
// drain before the covering import never makes a not-yet-judged row terminal
// (only the 7-day timer does, as needs_attention), a terminal row is cleared,
// and replaying a terminal row never 5xx.
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
