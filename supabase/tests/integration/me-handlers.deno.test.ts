// supabase/tests/integration/me-handlers.deno.test.ts
//
// P3d: DELETE /v1/me, GET /v1/me/export, POST /v1/me/push-token — the
// REAL handlers (_shared/me/{delete,export,push-token}-handler.ts)
// against a REAL Repo built by the REAL privileged.ts, against the
// harness cluster tools/db/test.sh builds (same discipline as
// handlers.deno.test.ts/repo.deno.test.ts — see those files' own
// headers). Also covers P3c gate PASS follow-up 13 ("503 after a
// successful commit") end to end, against a REAL held Postgres lock from
// a SECOND session.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createCourseWithPolygonAtFacX, createTestUser, freshUuid, insertCatalogVersion, makeActor, rawCount, FAC_X, NASHVILLE } from "./_helpers.ts";
import { withOwnership } from "../../functions/_shared/privileged.ts";
import { handleMeDelete } from "../../functions/_shared/me/delete-handler.ts";
import { handleMeExport } from "../../functions/_shared/me/export-handler.ts";
import { handlePushTokenRequest } from "../../functions/_shared/me/push-token-handler.ts";
import { handleEvidenceIntake } from "../../functions/_shared/evidence/handler.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import type { Repo } from "../../functions/_shared/types.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => {
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
};

async function withFreshUser(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `me-${label}-${uid.slice(0, 8)}`);
  return { uid, actor: makeActor(uid) };
}

// ─────────────────────────────────────────────────────────────────────────
// GET /v1/me/export
// ─────────────────────────────────────────────────────────────────────────
Deno.test("me-export: returns only the caller's own evidence/device/push_token rows, never another actor's", DT, async () => {
  const a = await withFreshUser("export-a");
  const b = await withFreshUser("export-b");

  const sourceRef = `me-export-${freshUuid()}`;
  const aDeviceId = await withOwnership(a.actor, async (repo: Repo) => {
    const device = await repo.device.ensureOwn(null, "ios");
    await repo.evidence.insertIdempotent({
      sourceRef,
      inputHash: `hash-${sourceRef}`,
      source: "self_report",
      facilityId: FAC_X,
      courseId: null,
      startedAt: null,
      endedAt: null,
      localDate: "2026-06-01",
      summary: {},
      integrity: {},
      cosignal: {},
      attestationGrade: "unattestable",
      matcherVersion: null,
      catalogVersion: 1,
      status: "accepted",
      deviceId: device.id,
    });
    await repo.pushToken.upsert(device.id, "ExponentPushToken[me-export-a]");
    return device.id;
  });

  const exportA = await withOwnership(a.actor, (repo: Repo) => handleMeExport(repo, a.uid));
  const exportB = await withOwnership(b.actor, (repo: Repo) => handleMeExport(repo, b.uid));

  assertEquals(exportA.userId, a.uid);
  const evidenceA = exportA.data.evidence as Array<Record<string, unknown>>;
  assert(evidenceA.some((r) => r.source_ref === sourceRef), "actor A's export must include her own evidence row");
  assert(evidenceA.every((r) => r.user_id === a.uid), "every evidence row in A's export must carry A's own user_id");

  const deviceA = exportA.data.device as Array<Record<string, unknown>>;
  assert(deviceA.some((r) => r.id === aDeviceId), "actor A's export must include her own device row");

  const pushTokenA = exportA.data.push_token as Array<Record<string, unknown>>;
  assert(pushTokenA.some((r) => r.device_id === aDeviceId), "actor A's export must include her own push_token row");

  const evidenceB = exportB.data.evidence as Array<Record<string, unknown>>;
  assert(!evidenceB.some((r) => r.source_ref === sourceRef), "actor B's export must NEVER include actor A's evidence row");
});

// ─────────────────────────────────────────────────────────────────────────
// DELETE /v1/me — AT 6: personal rows gone, push tokens gone, retry is
// idempotent, cross-user isolation.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("me-delete: removes evidence/device/push_token rows, and a retry is idempotent", DT, async () => {
  const a = await withFreshUser("delete-a");
  const b = await withFreshUser("delete-b");

  const sourceRef = `me-delete-${freshUuid()}`;
  await withOwnership(a.actor, async (repo: Repo) => {
    const device = await repo.device.ensureOwn(null, "ios");
    await repo.evidence.insertIdempotent({
      sourceRef,
      inputHash: `hash-${sourceRef}`,
      source: "self_report",
      facilityId: FAC_X,
      courseId: null,
      startedAt: null,
      endedAt: null,
      localDate: "2026-06-01",
      summary: {},
      integrity: {},
      cosignal: {},
      attestationGrade: "unattestable",
      matcherVersion: null,
      catalogVersion: 1,
      status: "accepted",
      deviceId: device.id,
    });
    await repo.pushToken.upsert(device.id, "ExponentPushToken[me-delete-a]");
  });
  // A second account's own row, to prove cross-user isolation below.
  const bSourceRef = `me-delete-b-${freshUuid()}`;
  await withOwnership(b.actor, async (repo: Repo) => {
    const device = await repo.device.ensureOwn(null, "ios");
    await repo.evidence.insertIdempotent({
      sourceRef: bSourceRef,
      inputHash: `hash-${bSourceRef}`,
      source: "self_report",
      facilityId: FAC_X,
      courseId: null,
      startedAt: null,
      endedAt: null,
      localDate: "2026-06-01",
      summary: {},
      integrity: {},
      cosignal: {},
      attestationGrade: "unattestable",
      matcherVersion: null,
      catalogVersion: 1,
      status: "accepted",
      deviceId: device.id,
    });
  });

  const before = await rawCount(`select count(*)::int as n from app.evidence where source_ref = '${sourceRef}'`);
  assertEquals(before, 1, "precondition: actor A's evidence row exists before deletion");

  const first = await withOwnership(a.actor, (repo: Repo) => handleMeDelete(repo));
  assertEquals(first.userId, a.uid);

  const afterEvidence = await rawCount(`select count(*)::int as n from app.evidence where source_ref = '${sourceRef}'`);
  assertEquals(afterEvidence, 0, "actor A's evidence row must be gone after delete_my_data");
  const afterDevice = await rawCount(`select count(*)::int as n from app.device where user_id = '${a.uid}'`);
  assertEquals(afterDevice, 0, "actor A's device rows must be gone after delete_my_data");
  const afterPushToken = await rawCount(`select count(*)::int as n from app.push_token where user_id = '${a.uid}'`);
  assertEquals(afterPushToken, 0, "actor A's push_token rows must be gone after delete_my_data (AT 6: 'deletes push tokens')");

  // Cross-user isolation: actor B's own row must be completely untouched
  // by actor A's deletion.
  const bStillThere = await rawCount(`select count(*)::int as n from app.evidence where source_ref = '${bSourceRef}'`);
  assertEquals(bStillThere, 1, "actor B's own evidence row must be unaffected by actor A's deletion");

  // Idempotent retry (task instruction: "a retry after partial failure
  // completes") — a second call for an already-deleted account must not
  // throw, and must still report success.
  const second = await withOwnership(a.actor, (repo: Repo) => handleMeDelete(repo));
  assertEquals(second.userId, a.uid, "a retry of me-delete for an already-deleted account must still succeed, not throw");

  const stillGone = await rawCount(`select count(*)::int as n from app.evidence where source_ref = '${sourceRef}'`);
  assertEquals(stillGone, 0, "the retry must not have resurrected or duplicated anything");
});

Deno.test("me-delete: an unredeemed special-marker entitlement is voided at once (AT 6)", DT, async () => {
  const a = await withFreshUser("delete-entitlement");
  await adminSql()`set role service_role`;
  const entitlementId = freshUuid();
  await adminSql()`
    insert into app.entitlement (id, user_id, kind, trail_id, roster_version, basis, state)
    values (${entitlementId}, ${a.uid}, 'special_marker', 'trl_t', 1, '{}'::jsonb, 'redeemable')`;

  await withOwnership(a.actor, (repo: Repo) => handleMeDelete(repo));

  const stateRows = await adminSql()`select state from app.entitlement where id = ${entitlementId}`;
  assertEquals(stateRows[0]?.state, "void", "an unredeemed (redeemable) special-marker entitlement must be voided by DELETE /v1/me, at once");
});

// ─────────────────────────────────────────────────────────────────────────
// POST /v1/me/push-token
// ─────────────────────────────────────────────────────────────────────────
Deno.test("me-push-token: registers a new token, then updates it on re-registration (reinstall)", DT, async () => {
  const a = await withFreshUser("push-token");
  const deviceId = freshUuid();

  const first = await withOwnership(a.actor, (repo: Repo) => handlePushTokenRequest({ deviceId, expoToken: "ExponentPushToken[first]", platform: "ios" }, repo));
  assertEquals(first.deviceId, deviceId);

  const rows1 = await adminSql()`select expo_token from app.push_token where user_id = ${a.uid} and device_id = ${deviceId}`;
  assertEquals(rows1[0]?.expo_token, "ExponentPushToken[first]");

  // "Register or update" — a reinstall on the SAME device id replaces
  // the token, never leaving two rows (app.push_token's own PK is
  // (user_id, device_id), 0003_player_core.sql).
  const second = await withOwnership(a.actor, (repo: Repo) => handlePushTokenRequest({ deviceId, expoToken: "ExponentPushToken[second]", platform: "ios" }, repo));
  assertEquals(second.deviceId, deviceId);

  const rows2 = await adminSql()`select expo_token from app.push_token where user_id = ${a.uid} and device_id = ${deviceId}`;
  assertEquals(rows2.length, 1, "a re-registration on the same device must not create a second row");
  assertEquals(rows2[0]?.expo_token, "ExponentPushToken[second]", "the token must be REPLACED, not left stale");
});

Deno.test("me-push-token: device_limit_exceeded once an actor already has MAX_DEVICES_PER_USER devices, and no 21st device row is created", DT, async () => {
  const a = await withFreshUser("push-token-cap");
  await withOwnership(a.actor, async (repo: Repo) => {
    for (let i = 0; i < 20; i++) await repo.device.ensureOwn(freshUuid(), "ios");
  });

  const newDeviceId = freshUuid();
  let caught: unknown;
  try {
    await withOwnership(a.actor, (repo: Repo) => handlePushTokenRequest({ deviceId: newDeviceId, expoToken: "ExponentPushToken[cap]" }, repo));
  } catch (err) {
    caught = err;
  }
  assert(caught instanceof HttpError && caught.code === "device_limit_exceeded", `expected device_limit_exceeded, got ${caught}`);

  const n = await rawCount(`select count(*)::int as n from app.device where id = '${newDeviceId}'`);
  assertEquals(n, 0, "a rejected over-cap push-token registration must never create the device row it's about to reject");
});

// ─────────────────────────────────────────────────────────────────────────
// P3c gate PASS follow-up 13: "503 after a successful commit."
// "Integration test: hold a lock on app.play for 20 s from another
// session. The request must get a 503 (or a mapped error), AND
// afterwards 0 rows are written and the challenge/token is NOT
// consumed."
// ─────────────────────────────────────────────────────────────────────────
Deno.test("follow-up 13: a held lock on app.play makes withOwnership fail with 503 (lock_timeout), well before the lock releases, with 0 rows written", DT, async () => {
  const a = await withFreshUser("followup13-play");
  const courseId = `crs_f13_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const playDate = "2026-07-01";

  // A SEPARATE session (privileged.ts#sql()'s own pool has max:5;
  // adminSql() here is a wholly different, dedicated connection — see
  // _helpers.ts's own doc) holds a real ACCESS EXCLUSIVE lock on
  // app.play for 20s, exactly as the follow-up instruction specifies.
  const HOLD_MS = 20_000;
  const lockAcquired = Promise.withResolvers<void>();
  const lockHeld = adminSql().begin(async (sql) => {
    await sql`set role service_role`;
    await sql`lock table app.play in access exclusive mode`;
    lockAcquired.resolve();
    await new Promise((r) => setTimeout(r, HOLD_MS));
  });
  await lockAcquired.promise;

  const start = Date.now();
  let caught: unknown;
  try {
    await withOwnership(a.actor, (repo: Repo) =>
      repo.play.upsertFromScore({
        courseId,
        facilityId: FAC_X,
        playDate,
        courseDisambiguatedBy: "geometry",
        scoreBadge: 0.6,
        scoreMonetary: 0,
        hardSignal: false,
        presenceSignal: true,
        money: false,
        heldReview: false,
        policyVersion: "v1",
        inputDigest: `digest-${freshUuid()}`,
        evidenceIds: [],
      }),
    );
  } catch (err) {
    caught = err;
  }
  const elapsedMs = Date.now() - start;

  assert(caught instanceof HttpError && caught.status === 503, `expected an HttpError with status 503 (lock_timeout mapped), got ${caught}`);
  assert(elapsedMs < HOLD_MS, `expected the request to fail via lock_timeout (~5s) well before the 20s lock hold ends — took ${elapsedMs}ms`);

  await lockHeld; // let the lock-holding session finish before reading rows back

  const n = await rawCount(`select count(*)::int as n from app.play where user_id = '${a.uid}' and course_id = '${courseId}' and play_date = '${playDate}'`);
  assertEquals(n, 0, "0 rows must be written after the 503 — the transaction that hit lock_timeout must have rolled back completely");
});

Deno.test("follow-up 13: the SAME held lock, through the full evidence-intake pipeline — the checkin token is NOT consumed either", DT, async () => {
  const a = await withFreshUser("followup13-token");
  const courseId = `crs_f13tok_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const deviceId = freshUuid();

  // A FRESH, high catalog_version row, made "current" for THIS
  // submission — never the shared fac_x fixture's version=1 (helpers.sql).
  // By the time this file runs, earlier files in this same Deno test run
  // (handlers.deno.test.ts's own AT 8/AT 15 tests) have already inserted
  // HIGHER catalog_version rows into this SAME live database — unlike
  // the pgTAP matrix files, Deno tests share one live cluster with no
  // per-test rollback, so those rows persist. Submitting the shared
  // fixture's version=1 here would now classify as stale/outside the
  // skew window purely because of an EARLIER, unrelated test file's own
  // inserts — exactly what `insertCatalogVersion`'s own doc (_helpers.ts)
  // warns this pattern avoids.
  await adminSql()`set role service_role`;
  const maxVersionRows = await adminSql()`select coalesce(max(version), 0)::int as m from app.catalog_version`;
  const freshCatalogVersion = Number(maxVersionRows[0]?.m ?? 0) + 1000; // comfortably above anything an earlier test file in this same live run may have inserted
  await insertCatalogVersion(freshCatalogVersion, new Date(), `kid-f13-${freshUuid()}`);

  const challenges = await withOwnership(a.actor, (repo: Repo) => handleChallengeRequest({ deviceId, facilityId: FAC_X }, repo, randomBytes, digestHex));
  const token = await withOwnership(a.actor, (repo: Repo) =>
    handleTokenRequest({ challengeId: challenges[0].id, nonce: challenges[0].nonce, hardwareSupportsAttestation: false }, repo, digestHex),
  );

  const HOLD_MS = 20_000;
  const lockAcquired = Promise.withResolvers<void>();
  const lockHeld = adminSql().begin(async (sql) => {
    await sql`set role service_role`;
    await sql`lock table app.play in access exclusive mode`;
    lockAcquired.resolve();
    await new Promise((r) => setTimeout(r, HOLD_MS));
  });
  await lockAcquired.promise;

  const todayInFacilityTz = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  let caught: unknown;
  try {
    await withOwnership(a.actor, (repo: Repo) =>
      handleEvidenceIntake(
        {
          source: "foreground_checkin",
          deviceId,
          facilityId: FAC_X,
          courseId,
          localDate: todayInFacilityTz,
          catalogVersion: freshCatalogVersion,
          fix: {
            fixId: `fix_${freshUuid()}`,
            lat: NASHVILLE.lat,
            lng: NASHVILLE.lng,
            accuracyMeters: 10,
            capturedAt: Date.now(),
            simulated: false,
            foreground: true,
            fromApp: true,
            checkinTokenJti: token.jti,
          },
        },
        repo,
      ),
    );
  } catch (err) {
    caught = err;
  }
  assert(caught instanceof HttpError && caught.status === 503, `expected 503, got ${caught}`);

  await lockHeld;

  const playRows = await rawCount(`select count(*)::int as n from app.play where user_id = '${a.uid}' and course_id = '${courseId}'`);
  assertEquals(playRows, 0, "0 play rows after the 503 — the whole transaction (including the evidence row) rolled back");
  const evidenceRows = await rawCount(`select count(*)::int as n from app.evidence where device_id = '${deviceId}'`);
  assertEquals(evidenceRows, 0, "0 evidence rows after the 503");
  const consumedRows = await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${token.jti}' and consumed_at is not null`);
  assertEquals(consumedRows, 0, "the checkin token must NOT show as consumed — the whole transaction, including its own consumeForFix UPDATE, rolled back");
});
