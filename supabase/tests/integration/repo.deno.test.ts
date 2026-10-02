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
import { hitRateLimitForActor, withOwnership } from "../../functions/_shared/privileged.ts";
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
// class of bug as item 5): the bucket key was never scoped by actor at
// all — see privileged.ts's own fix comment. Proven here with TWO real
// actors hammering the exact same literal bucket key: without the fix,
// actor B would inherit actor A's count and get rate-limited far below
// the real per-user limit.
//
// ⛔ P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock
// the pool"): rewritten against `hitRateLimitForActor` directly, NOT
// through `withOwnership`/`Repo` — `Repo` no longer has a `rateLimit`
// member at all (it was exactly the deadlock's own root cause; see
// privileged.ts#hitRateLimitForActor's own doc). This is now a
// standalone function, callable with no transaction open.
Deno.test("item 5 (found by this suite): hitRateLimitForActor is scoped per actor, not a shared global bucket", DT, async () => {
  const a = await withFreshUser("rl-a");
  const b = await withFreshUser("rl-b");
  const bucketKey = `shared-literal-bucket-${freshUuid()}`;

  // Actor A hits the SAME literal bucket key 5 times, max 5 — should be
  // fine on its own.
  for (let i = 0; i < 5; i++) {
    const r = await hitRateLimitForActor(a.actor, bucketKey, 3600, 5);
    assert(r.ok, `actor A's hit ${i} should be ok`);
  }
  // Actor B, using the EXACT SAME bucket key, must start its OWN count
  // from zero — not inherit actor A's 5 hits and immediately fail.
  const bFirstHit = await hitRateLimitForActor(b.actor, bucketKey, 3600, 5);
  assert(bFirstHit.ok, "actor B's first hit on the SAME literal bucket key must not be pre-exhausted by actor A's own hits");
  assertEquals(bFirstHit.count, 1, "actor B's count must start at 1, not continue from actor A's 5");
});

// ─────────────────────────────────────────────────────────────────────────
// P3c gate round 4, blocking HIGH: "5 concurrent requests deadlock the
// pool" — the reviewer's own repro and root-cause diagnosis (a
// rate-limit hit opening a SECOND pooled connection from inside an
// already-open request transaction, against a max: 5 pool).
// ─────────────────────────────────────────────────────────────────────────
Deno.test("P3c gate round 4, blocking HIGH: 2x pool max concurrent withOwnership calls, each ALSO hitting a rate limit, complete within a bound (no deadlock)", DT, async () => {
  const POOL_MAX = 5; // matches privileged.ts#sql()'s own `max: 5`
  const CONCURRENCY = POOL_MAX * 2; // "at least max+1, better 2x max"
  const users = await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => withFreshUser(`deadlock-${i}`)));

  const start = Date.now();
  const attempts = users.map(async (u) => {
    // The EXACT shape a real request now takes: hit its own rate limit
    // FIRST, with NO transaction open at all, THEN open withOwnership.
    // Before this round's fix, the rate-limit hit happened INSIDE the
    // withOwnership callback instead — this ordering is the fix under
    // test, not incidental to it.
    const rl = await hitRateLimitForActor(u.actor, `deadlock-test-${u.uid}`, 3600, 100);
    assert(rl.ok, `rate-limit hit for ${u.uid} should be ok (fresh bucket, well under max)`);
    return withOwnership(u.actor, (repo) => repo.device.ensureOwn(null, "ios"));
  });

  // A generous bound: real, correctly-ordered concurrent traffic should
  // finish in well under a second (the reviewer's own /tmp prototype did
  // 25 concurrent in 197ms) — 20s is the reviewer's own repro threshold
  // for "this hung," used here as the bound a CORRECT implementation
  // must beat by a wide margin, not a tight performance assertion.
  const DEADLOCK_BOUND_MS = 20_000;
  const results = await Promise.race([
    Promise.all(attempts),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`DEADLOCK: ${CONCURRENCY} concurrent requests (2x pool max) did not complete within ${DEADLOCK_BOUND_MS}ms`)), DEADLOCK_BOUND_MS)),
  ]);
  const elapsedMs = Date.now() - start;

  assertEquals(results.length, CONCURRENCY);
  for (const r of results) assert(typeof r.id === "string" && r.id.length > 0);
  assert(elapsedMs < DEADLOCK_BOUND_MS, `expected ${CONCURRENCY} concurrent requests to complete well under ${DEADLOCK_BOUND_MS}ms — took ${elapsedMs}ms`);
  console.log(`P3c gate round 4 deadlock test: ${CONCURRENCY} concurrent requests (2x pool max ${POOL_MAX}) completed in ${elapsedMs}ms`);
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

// ─────────────────────────────────────────────────────────────────────────
// P3d gate round 3, S2 (MEDIUM) / P3d gate round 4, F1 (BLOCKING, this
// round's fix): "make repeated finalize idempotent for fraud signals: no
// duplicate quarantined_evidence_row signal on each retry" — AND (F1,
// found by the round-3 re-review): the dedupe must NOT drop a genuinely
// DIFFERENT quarantine signal on the SAME play. Tests the actual
// mechanism directly (privileged.ts#fraudSignal.insert's own
// `INSERT ... ON CONFLICT (playId, quarantineDigest) ... DO NOTHING`
// against the new partial unique index, 0022), rather than trying to
// force a genuine scorer-level quarantine end to end for this
// mechanism-level proof — a separate, higher-level test
// (evidence-batch.deno.test.ts) proves the real q1-then-q2 repro through
// the actual scorer/handler path.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("P3d gate round 4, F1: repo.fraudSignal.insert is idempotent per (kind, playId, quarantineDigest) — SAME digest on a retry is a no-op, a DIFFERENT digest on the SAME play raises its OWN signal", DT, async () => {
  const a = await withFreshUser("fraud-signal-dedupe");
  const fakePlayId = freshUuid();
  const digestQ1 = "digest-q1-only";
  const digestQ1AndQ2 = "digest-q1-and-q2";

  await withOwnership(a.actor, (repo) =>
    repo.fraudSignal.insert("quarantined_evidence_row", { playId: fakePlayId, quarantineDigest: digestQ1, facilityId: FAC_X, courseId: "crs_dedupe", localDate: "2026-06-01", excludedRows: [{ index: 0, kind: "quarantined", reasons: ["test fixture q1"] }] }),
  );
  // Second call: SAME kind, SAME playId, SAME digest — simulates
  // finalizeScoringForKey running twice for the SAME quarantine set (an
  // interrupted batch's own phase-2b retry, or a live retry through
  // buildReplayResult's finalize path). Must be a no-op.
  await withOwnership(a.actor, (repo) =>
    repo.fraudSignal.insert("quarantined_evidence_row", { playId: fakePlayId, quarantineDigest: digestQ1, facilityId: FAC_X, courseId: "crs_dedupe", localDate: "2026-06-01", excludedRows: [{ index: 0, kind: "quarantined", reasons: ["test fixture q1 (retry)"] }] }),
  );
  const nAfterRetry = await rawCount(`select count(*)::int as n from app.fraud_signal where kind = 'quarantined_evidence_row' and detail ->> 'playId' = '${fakePlayId}'`);
  assertEquals(nAfterRetry, 1, "exactly ONE fraud_signal row after a same-digest retry, even though insert was called twice");

  // P3d gate round 4, F1's own repro: the SAME play, but a DIFFERENT
  // quarantine digest (q2 now also quarantined alongside q1) — this MUST
  // raise its OWN, second signal, never be swallowed by the (playId)-only
  // dedupe round 3 shipped.
  await withOwnership(a.actor, (repo) =>
    repo.fraudSignal.insert("quarantined_evidence_row", { playId: fakePlayId, quarantineDigest: digestQ1AndQ2, facilityId: FAC_X, courseId: "crs_dedupe", localDate: "2026-06-01", excludedRows: [{ index: 0, kind: "quarantined", reasons: ["test fixture q1"] }, { index: 1, kind: "quarantined", reasons: ["test fixture q2"] }] }),
  );
  const nAfterQ2 = await rawCount(`select count(*)::int as n from app.fraud_signal where kind = 'quarantined_evidence_row' and detail ->> 'playId' = '${fakePlayId}'`);
  assertEquals(nAfterQ2, 2, "a DIFFERENT quarantine digest on the SAME play raises its own, second signal — F1's own repro");

  // A DIFFERENT play must still get its own, independent signal.
  const otherPlayId = freshUuid();
  await withOwnership(a.actor, (repo) => repo.fraudSignal.insert("quarantined_evidence_row", { playId: otherPlayId, quarantineDigest: digestQ1, facilityId: FAC_X, courseId: "crs_dedupe", localDate: "2026-06-01", excludedRows: [] }));
  const nOther = await rawCount(`select count(*)::int as n from app.fraud_signal where kind = 'quarantined_evidence_row' and detail ->> 'playId' = '${otherPlayId}'`);
  assertEquals(nOther, 1, "a signal for a DIFFERENT play is never suppressed by the dedupe");

  // A kind with no playId in its detail (e.g. clock_skew, keyed on
  // fixIds instead) has no dedupe key and always inserts — unchanged.
  await withOwnership(a.actor, (repo) => repo.fraudSignal.insert("clock_skew", { fixIds: ["fix_a"], evidenceSource: "foreground_checkin" }));
  await withOwnership(a.actor, (repo) => repo.fraudSignal.insert("clock_skew", { fixIds: ["fix_a"], evidenceSource: "foreground_checkin" }));
  const nClockSkew = await rawCount(`select count(*)::int as n from app.fraud_signal where kind = 'clock_skew' and user_id = '${a.uid}'`);
  assertEquals(nClockSkew, 2, "a kind with no playId in its detail is never deduped — both calls insert their own row");
});

// ─────────────────────────────────────────────────────────────────────────
// P3d gate round 4, F1 requirement: "4 concurrent finalizes give 1." Proves
// the fix is genuinely concurrency-safe, not merely idempotent when called
// sequentially — the round-3 `WHERE NOT EXISTS` version this replaces was
// NOT safe here (two simultaneous transactions could both pass that check
// before either committed); the new `INSERT ... ON CONFLICT ... DO
// NOTHING` is a single atomic statement against a REAL unique index, so
// only one of N concurrent inserts for the SAME (playId, quarantineDigest)
// can ever actually land.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("P3d gate round 4, F1: 4 CONCURRENT inserts for the SAME (playId, quarantineDigest) produce exactly 1 fraud_signal row", DT, async () => {
  const a = await withFreshUser("fraud-signal-concurrent");
  const playId = freshUuid();
  const digest = "digest-concurrent-fixture";

  await Promise.all(
    Array.from({ length: 4 }, (_unused, i) =>
      withOwnership(a.actor, (repo) =>
        repo.fraudSignal.insert("quarantined_evidence_row", {
          playId,
          quarantineDigest: digest,
          facilityId: FAC_X,
          courseId: "crs_concurrent",
          localDate: "2026-06-01",
          excludedRows: [{ index: 0, kind: "quarantined", reasons: [`concurrent attempt ${i}`] }],
        }),
      ),
    ),
  );

  const n = await rawCount(`select count(*)::int as n from app.fraud_signal where kind = 'quarantined_evidence_row' and detail ->> 'playId' = '${playId}'`);
  assertEquals(n, 1, "4 concurrent inserts for the identical (playId, quarantineDigest) must collapse to exactly 1 row, not race into duplicates");
});
