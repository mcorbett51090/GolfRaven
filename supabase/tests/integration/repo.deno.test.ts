// supabase/tests/integration/repo.deno.test.ts
//
// P3c gate round 2, item 0: runs the REAL `privileged.ts` — real
// transactions, real `pg_advisory_xact_lock`, real grants, real
// `SET LOCAL ROLE service_role` — against the harness cluster
// `tools/db/test.sh` builds. Every test here calls `withOwnership`
// directly (not through a handler), so a failure points straight at
// `privileged.ts`'s own SQL.
//
// Every `Deno.test` below disables the resource/op sanitizers: every test
// in this process shares ONE underlying `postgres.js` connection pool
// (privileged.ts's own module-level `sql()` singleton) — a pool opened by
// the FIRST test and still open when that test's own assertions finish is
// expected, not a leak; the process exit at the end of `deno test` closes
// every socket.
import { assert, assertEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, createCourseWithRadiusAtFacX, createCourseWithPolygonAtFacX, freshUuid, makeActor, rawCount, FAC_X, NASHVILLE } from "./_helpers.ts";
import { withOwnership } from "../../functions/_shared/privileged.ts";
import type { Repo } from "../../functions/_shared/types.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

async function withFreshUser(label: string): Promise<{ uid: string; actor: ReturnType<typeof makeActor> }> {
  const uid = freshUuid();
  await createTestUser(uid, `repo-${label}-${uid.slice(0, 8)}`);
  return { uid, actor: makeActor(uid) };
}

async function seedDevice(repo: Repo): Promise<string> {
  const d = await repo.device.ensureOwn(null, "ios");
  return d.id;
}

// ─────────────────────────────────────────────────────────────────────────
// item 2: "writes silently lost" — the whole withOwnership callback runs
// in ONE transaction; a throw partway through must roll back EVERYTHING,
// not leave earlier statements durably committed.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 2: a throw inside withOwnership rolls back every write the callback already made", DT, async () => {
  const { actor } = await withFreshUser("txn");
  const sourceRef = `txn-atomicity-${freshUuid()}`;

  await assertRejects(() =>
    withOwnership(actor, async (repo) => {
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
      throw new Error("deliberate failure mid-transaction");
    }),
  );

  const n = await rawCount(`select count(*)::int as n from app.evidence where source_ref = '${sourceRef}'`);
  assertEquals(n, 0, "the evidence row from the FAILED transaction must not exist — the whole callback is one atomic unit");
});

// ─────────────────────────────────────────────────────────────────────────
// item 5: "withOwnership ignores the actor" — every Repo namespace is
// scoped to the closed-over actor.uid; a DIFFERENT actor's Repo can never
// see, count, or touch another actor's rows, even knowing their exact id.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 5: device.findOwn/countForUser are scoped per actor, not shared", DT, async () => {
  const a = await withFreshUser("device-a");
  const b = await withFreshUser("device-b");

  const deviceIdA = await withOwnership(a.actor, (repo) => seedDevice(repo));

  const seenByB = await withOwnership(b.actor, (repo) => repo.device.findOwn(deviceIdA));
  assertEquals(seenByB, null, "actor B's Repo must not find actor A's device by id");

  const countA = await withOwnership(a.actor, (repo) => repo.device.countForUser());
  const countB = await withOwnership(b.actor, (repo) => repo.device.countForUser());
  assertEquals(countA, 1);
  assertEquals(countB, 0, "actor B's device count must not include actor A's device");
});

Deno.test("item 5: evidence.countOpenQueued/listForPlay are scoped per actor", DT, async () => {
  const a = await withFreshUser("evq-a");
  const b = await withFreshUser("evq-b");

  await withOwnership(a.actor, async (repo) => {
    const device = await seedDevice(repo);
    const evqSourceRef = `evq-${freshUuid()}`;
    await repo.evidence.insertIdempotent({
      sourceRef: evqSourceRef,
      inputHash: `hash-${evqSourceRef}`,
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
      catalogVersion: 1, // status is set directly below (not derived from real skew classification) — just needs a REAL catalog_version row to satisfy the FK
      status: "queued_catalog",
      deviceId: device,
    });
  });

  const countA = await withOwnership(a.actor, (repo) => repo.evidence.countOpenQueued());
  const countB = await withOwnership(b.actor, (repo) => repo.evidence.countOpenQueued());
  assertEquals(countA, 1);
  assertEquals(countB, 0, "actor B must never see actor A's queued evidence in their own count");
});

Deno.test("item 5: challenge.getOwn / checkinToken.consumeForFix are scoped per actor", DT, async () => {
  const a = await withFreshUser("chal-a");
  const b = await withFreshUser("chal-b");

  const challengeId = await withOwnership(a.actor, async (repo) => {
    const device = await seedDevice(repo);
    const issued = await repo.challenge.insert({
      staffUserId: null,
      deviceId: device,
      facilityId: FAC_X,
      nonceHash: `nh-${freshUuid()}`,
      kind: "live",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    return issued.id;
  });

  const seenByB = await withOwnership(b.actor, (repo) => repo.challenge.getOwn(challengeId));
  assertEquals(seenByB, null, "actor B must not be able to read actor A's challenge by id");

  const seenByA = await withOwnership(a.actor, (repo) => repo.challenge.getOwn(challengeId));
  assert(seenByA !== null, "actor A (the real owner) must still be able to read their own challenge");
});

// ⛔ FIX found BY this suite (not in the coordinator's list, but the same
// class of bug as item 5): rateLimit.hit's bucket key was never scoped by
// actor at all — see privileged.ts's own fix comment. Proven here with
// TWO real actors hammering the exact same literal bucket key: without
// the fix, actor B would inherit actor A's count and get rate-limited
// far below the real per-user limit.
Deno.test("item 5 (found by this suite): rateLimit.hit is scoped per actor, not a shared global bucket", DT, async () => {
  const a = await withFreshUser("rl-a");
  const b = await withFreshUser("rl-b");
  const bucketKey = `shared-literal-bucket-${freshUuid()}`;

  // Actor A hits the SAME literal bucket key 5 times, max 5 — should be
  // fine on its own.
  for (let i = 0; i < 5; i++) {
    const r = await withOwnership(a.actor, (repo) => repo.rateLimit.hit(bucketKey, 3600, 5));
    assert(r.ok, `actor A's hit ${i} should be ok`);
  }
  // Actor B, using the EXACT SAME bucket key, must start its OWN count
  // from zero — not inherit actor A's 5 hits and immediately fail.
  const bFirstHit = await withOwnership(b.actor, (repo) => repo.rateLimit.hit(bucketKey, 3600, 5));
  assert(bFirstHit.ok, "actor B's first hit on the SAME literal bucket key must not be pre-exhausted by actor A's own hits");
  assertEquals(bFirstHit.count, 1, "actor B's count must start at 1, not continue from actor A's 5");
});

// ─────────────────────────────────────────────────────────────────────────
// item 4: checkin-token consumption — ownership + single-use + device
// match + challenge-window clamp, all in ONE atomic statement.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 4: consumeForFix rejects a device that does not match the token's own device", DT, async () => {
  const a = await withFreshUser("tok-device-mismatch");
  const result = await withOwnership(a.actor, async (repo) => {
    const device = await seedDevice(repo);
    const otherDeviceId = freshUuid(); // not a real device row, but the WHERE clause should reject it regardless
    const challenge = await repo.challenge.insert({
      staffUserId: null,
      deviceId: device,
      facilityId: FAC_X,
      nonceHash: `nh-${freshUuid()}`,
      kind: "live",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const token = await repo.checkinToken.insert({
      challengeId: challenge.id,
      deviceId: device,
      facilityId: FAC_X,
      attestationGrade: "unattestable",
      challengeKind: "live",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    return repo.checkinToken.consumeForFix(token.jti, otherDeviceId, Date.now());
  });
  assertEquals(result, null, "a device mismatch must yield null — never silently consume against the wrong device");
});

Deno.test("item 4: consumeForFix rejects a capturedAt outside [issued_at, expires_at], even with the right device", DT, async () => {
  const a = await withFreshUser("tok-window");
  const result = await withOwnership(a.actor, async (repo) => {
    const device = await seedDevice(repo);
    const challenge = await repo.challenge.insert({
      staffUserId: null,
      deviceId: device,
      facilityId: FAC_X,
      nonceHash: `nh-${freshUuid()}`,
      kind: "live",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const token = await repo.checkinToken.insert({
      challengeId: challenge.id,
      deviceId: device,
      facilityId: FAC_X,
      attestationGrade: "unattestable",
      challengeKind: "live",
      expiresAt: new Date(Date.now() + 60_000).toISOString(), // expires ~60s from now
    });
    // capturedAt an hour in the future — well outside the token's own window.
    return repo.checkinToken.consumeForFix(token.jti, device, Date.now() + 60 * 60 * 1000);
  });
  assertEquals(result, null, "a capturedAt outside the token's own [issued_at, expires_at] window must yield null");
});

Deno.test("item 4: consumeForFix succeeds exactly once (single-use), then fails on a second attempt", DT, async () => {
  const a = await withFreshUser("tok-single-use");
  const { device, jti } = await withOwnership(a.actor, async (repo) => {
    const device = await seedDevice(repo);
    const challenge = await repo.challenge.insert({
      staffUserId: null,
      deviceId: device,
      facilityId: FAC_X,
      nonceHash: `nh-${freshUuid()}`,
      kind: "live",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const token = await repo.checkinToken.insert({
      challengeId: challenge.id,
      deviceId: device,
      facilityId: FAC_X,
      attestationGrade: "attested",
      challengeKind: "live",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    return { device, jti: token.jti };
  });

  const first = await withOwnership(a.actor, (repo) => repo.checkinToken.consumeForFix(jti, device, Date.now()));
  assert(first !== null, "first consumption should succeed");
  assertEquals(first?.attestationGrade, "attested");

  const second = await withOwnership(a.actor, (repo) => repo.checkinToken.consumeForFix(jti, device, Date.now()));
  assertEquals(second, null, "a second consumption of the SAME token must fail — single-use, not unlimited for the TTL");
});

// ─────────────────────────────────────────────────────────────────────────
// item 8: count-then-insert races — pg_advisory_xact_lock inside the
// transaction must serialize concurrent requests for the SAME actor.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 8: concurrent countOpenPrefetched + insert never overshoots the cap (advisory lock holds under real concurrency)", DT, async () => {
  const a = await withFreshUser("prefetch-race");
  const deviceId = await withOwnership(a.actor, (repo) => seedDevice(repo));
  const CAP = 10;

  // 15 concurrent "requests", each: count current open prefetched for this
  // device, and if under CAP, insert one more. This is EXACTLY the shape
  // challenge-handler.ts's own prefetch-cap check follows (see that
  // file's own header) — run here directly against privileged.ts's
  // Repo, with real overlapping transactions, to prove the advisory lock
  // (not merely the handler's own single-threaded arithmetic) is what
  // holds the cap.
  const attempts = Array.from({ length: 15 }, () =>
    withOwnership(a.actor, async (repo) => {
      const open = await repo.challenge.countOpenPrefetched(deviceId);
      if (open >= CAP) return false;
      await repo.challenge.insert({
        staffUserId: null,
        deviceId,
        facilityId: FAC_X,
        nonceHash: `nh-${freshUuid()}`,
        kind: "prefetched",
        expiresAt: new Date(Date.now() + 23 * 60 * 60 * 1000).toISOString(), // < 24h cap, with slack for advisory-lock queueing jitter
      });
      return true;
    }),
  );
  const results = await Promise.all(attempts);
  const succeeded = results.filter(Boolean).length;
  assertEquals(succeeded, CAP, `expected exactly ${CAP} of 15 concurrent prefetch-count-then-insert attempts to succeed (advisory lock serializes them) — got ${succeeded}`);

  const finalOpen = await withOwnership(a.actor, (repo) => repo.challenge.countOpenPrefetched(deviceId));
  assertEquals(finalOpen, CAP, "the final open-prefetched count must match the cap exactly, never over it");
});

Deno.test("item 8: concurrent countOpenQueued + insert never overshoots MAX_OPEN_QUEUED_PER_USER-shaped cap", DT, async () => {
  const a = await withFreshUser("queued-race");
  const deviceId = await withOwnership(a.actor, (repo) => seedDevice(repo));
  const CAP = 5; // a smaller cap than the real 20, purely to keep this test fast

  const attempts = Array.from({ length: 12 }, () =>
    withOwnership(a.actor, async (repo) => {
      const open = await repo.evidence.countOpenQueued();
      if (open >= CAP) return false;
      const queuedRaceSourceRef = `queued-race-${freshUuid()}`;
      await repo.evidence.insertIdempotent({
        sourceRef: queuedRaceSourceRef,
        inputHash: `hash-${queuedRaceSourceRef}`,
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
        catalogVersion: 1, // just needs a REAL catalog_version row to satisfy the FK — status is set directly below
        status: "queued_catalog",
        deviceId,
      });
      return true;
    }),
  );
  const results = await Promise.all(attempts);
  const succeeded = results.filter(Boolean).length;
  assertEquals(succeeded, CAP, `expected exactly ${CAP} of 12 concurrent queued-count-then-insert attempts to succeed — got ${succeeded}`);
});

// ─────────────────────────────────────────────────────────────────────────
// "Conditions on the BYPASSRLS design": SELECT-only on catalog_signing_key,
// no DELETE (and no unexpected INSERT path) on checkin_token for
// service_role — 0019's own narrowed grants, proven as a real permission
// failure under `service_role`, not merely absence-of-row-in-a-listing.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("BYPASSRLS grants: service_role cannot INSERT into app.catalog_signing_key (SELECT-only)", DT, async () => {
  await assertRejects(
    () => adminSql()`insert into app.catalog_signing_key (kid, public_key_b64url) values (${"denied-" + freshUuid()}, 'AAAA')`,
    Error,
    undefined,
    "service_role must not be able to INSERT into catalog_signing_key",
  );
});

Deno.test("BYPASSRLS grants: service_role cannot DELETE from app.checkin_token", DT, async () => {
  await assertRejects(
    () => adminSql()`delete from app.checkin_token where jti = ${freshUuid()}`,
    Error,
    undefined,
    "service_role must not be able to DELETE from checkin_token (only private_definer's delete_my_data path, or the ON DELETE CASCADE from checkin_challenge, may remove a row)",
  );
});

// Sanity: matchFix's real ST_DWithin containment, exercised through the
// Repo method itself (not raw SQL) — proves privileged.ts's own query,
// not just that PostGIS works.
Deno.test("catalog.matchFix: real ST_DWithin containment via the Repo method itself", DT, async () => {
  const courseId = `crs_geom_${freshUuid().slice(0, 8)}`;
  await createCourseWithRadiusAtFacX(courseId, 200);
  const a = await withFreshUser("matchfix");

  const inside = await withOwnership(a.actor, (repo) => repo.catalog.matchFix(courseId, NASHVILLE.lat, NASHVILLE.lng));
  assert(inside !== null);
  assertEquals(inside?.insideBuffer, true, "a fix AT the radius center must be inside the buffer");

  const outside = await withOwnership(a.actor, (repo) => repo.catalog.matchFix(courseId, NASHVILLE.lat + 0.2, NASHVILLE.lng));
  assertEquals(outside?.insideBuffer, false, "a fix ~22km away must NOT be inside the buffer");
});

Deno.test("catalog.matchFix: real ST_DWithin containment against a POLYGON course (geometryKind must read back as 'polygon')", DT, async () => {
  const courseId = `crs_poly_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const a = await withFreshUser("matchfix-polygon");

  const inside = await withOwnership(a.actor, (repo) => repo.catalog.matchFix(courseId, NASHVILLE.lat, NASHVILLE.lng));
  assert(inside !== null);
  assertEquals(inside?.geometryKind, "polygon");
  assertEquals(inside?.verificationTier, "play-verified");
  assertEquals(inside?.insideBuffer, true, "a fix at the polygon's own center must be inside the buffer");
});
