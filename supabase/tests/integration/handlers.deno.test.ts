// supabase/tests/integration/handlers.deno.test.ts
//
// P3c gate round 2, item 0: the REAL `handleEvidenceIntake`/
// `handleChallengeRequest`/`handleTokenRequest` (supabase/functions/
// _shared/evidence/handler.ts, .../checkin/*.ts), running against a REAL
// `Repo` built by the REAL `privileged.ts`, against the harness cluster
// `tools/db/test.sh` builds. Every HIGH/MEDIUM repro from the P3c gate
// round 2 report that is reachable ONLY at the handler+real-DB layer
// (day-2 evidence, forged facility/course pairing, replay-with-changed-
// payload, the full challenge->token->evidence flow, device caps,
// catalog skew against real catalog_version/catalog_signing_key rows) has
// its own test below — `supabase/tests/unit/evidence-handler.test.ts`
// covers the SAME shapes against the in-memory fake Repo; this file is
// what actually caught the class of bug (real transactions, real
// advisory locks, real grants) the fake Repo could not.
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  createTestUser,
  createCourseAtFacX,
  createCourseWithPolygonAtFacX,
  freshUuid,
  makeActor,
  insertCatalogVersion,
  insertSigningKey,
  rawCount,
  FAC_X,
  CRS_X1,
  NASHVILLE,
} from "./_helpers.ts";
import { withOwnership } from "../../functions/_shared/privileged.ts";
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
  await createTestUser(uid, `hdl-${label}-${uid.slice(0, 8)}`);
  return makeActor(uid);
}

function checkinBody(overrides: Record<string, unknown> = {}) {
  return {
    source: "foreground_checkin",
    deviceId: freshUuid(),
    facilityId: FAC_X,
    courseId: CRS_X1,
    localDate: "2026-06-01",
    catalogVersion: 1,
    fix: {
      fixId: `fix_${freshUuid()}`,
      lat: NASHVILLE.lat,
      lng: NASHVILLE.lng,
      accuracyMeters: 10,
      capturedAt: Date.parse("2026-06-01T12:00:00.000Z"),
      simulated: false,
      foreground: true,
      fromApp: true,
    },
    ...overrides,
  };
}

async function evidence(actor: ReturnType<typeof makeActor>, body: unknown) {
  return withOwnership(actor, (repo: Repo) => handleEvidenceIntake(body, repo));
}

// ─────────────────────────────────────────────────────────────────────────
// item 1: day-2 evidence + facility-level visibility to a second course.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 1: a second day's check-in for the SAME course succeeds independently (no 23505, no orphaned play)", DT, async () => {
  const actor = await withFreshUser("day2");
  const day1 = await evidence(actor, checkinBody({ localDate: "2026-06-01" }));
  const day2 = await evidence(actor, checkinBody({ localDate: "2026-06-02", fix: { ...checkinBody().fix as object, capturedAt: Date.parse("2026-06-02T12:00:00.000Z") } }));
  assertEquals(day1.status, "accepted");
  assertEquals(day2.status, "accepted");
  if (day1.status === "accepted" && day2.status === "accepted") {
    assert(day2.play.id !== day1.play.id, "day 1 and day 2 must produce two DISTINCT play rows, not a 23505 collision or a shared/overwritten one");
  }
});

Deno.test("item 1: a facility-level (no courseId) row is visible to a SECOND course's play on the same day", DT, async () => {
  const actor = await withFreshUser("faclevel");
  const secondCourse = `crs_hdl_${freshUuid().slice(0, 8)}`;
  await createCourseAtFacX(secondCourse);

  // P3c gate round 3, blocking MEDIUM 5: a date-only source's (self_report)
  // localDate is now window-checked against the FACILITY-LOCAL "today"
  // (repo.now(), real wall-clock time in this suite — unlike the fake-
  // repo unit tests, which run on a fixed fake clock) — a hardcoded
  // "2026-06-01" fails that check once this suite runs on any OTHER real
  // date. A fix-bearing source's own localDate must independently match
  // ITS OWN capturedAt's server-derived date. Using "today" (facility
  // -local) for all three keeps every row on the SAME shared date this
  // test's own listForPlay assertions depend on, regardless of which
  // real calendar date this suite happens to run on.
  const todayInFacilityTz = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());

  const facLevel = await evidence(actor, { source: "self_report", deviceId: freshUuid(), facilityId: FAC_X, localDate: todayInFacilityTz, catalogVersion: 1 });
  assertEquals(facLevel.status, "accepted");

  const playA = await evidence(actor, checkinBody({ courseId: CRS_X1, localDate: todayInFacilityTz, fix: { ...checkinBody().fix as object, capturedAt: Date.now() } }));
  const playB = await evidence(
    actor,
    checkinBody({ courseId: secondCourse, localDate: todayInFacilityTz, fix: { ...checkinBody().fix as object, fixId: `fix_b_${freshUuid()}`, capturedAt: Date.now() } }),
  );
  assertEquals(playA.status, "accepted");
  assertEquals(playB.status, "accepted");

  if (facLevel.status !== "accepted") throw new Error("unreachable");
  const rowsForA = await withOwnership(actor, (repo) => repo.evidence.listForPlay(FAC_X, CRS_X1, todayInFacilityTz));
  const rowsForB = await withOwnership(actor, (repo) => repo.evidence.listForPlay(FAC_X, secondCourse, todayInFacilityTz));
  assert(rowsForA.some((r) => r.id === facLevel.evidenceId), "the facility-level row must be a listForPlay candidate for course A's play");
  assert(rowsForB.some((r) => r.id === facLevel.evidenceId), "the facility-level row must ALSO be a listForPlay candidate for course B's play, the SAME day");
});

// ─────────────────────────────────────────────────────────────────────────
// item 3: forged facility/course pairing.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 3: 422 facility_course_mismatch for a real course belonging to a DIFFERENT facility", DT, async () => {
  const actor = await withFreshUser("mismatch");
  // fac_y / crs_y1 are both seeded by supabase/tests/helpers.sql, already
  // present in this same live database — crs_x1 (checkinBody's default
  // courseId) genuinely belongs to fac_x, not fac_y.
  let threw: unknown = null;
  try {
    await evidence(actor, checkinBody({ facilityId: "fac_y" }));
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError, "expected an HttpError");
  assertEquals((threw as HttpError).code, "facility_course_mismatch");
});

// ─────────────────────────────────────────────────────────────────────────
// item 6: connect_iq/health_route/file_import rejected end to end, against
// the REAL repo (not just the fake one already covered at unit level).
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 6: connect_iq/health_route/file_import are rejected end to end against the real Repo", DT, async () => {
  const actor = await withFreshUser("rejected-sources");
  for (const source of ["connect_iq", "health_route", "file_import"]) {
    let threw: unknown = null;
    try {
      await evidence(actor, { ...checkinBody(), source, fix: undefined });
    } catch (err) {
      threw = err;
    }
    assert(threw instanceof HttpError, `${source} should be rejected with an HttpError`);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// item 9: replay with a changed payload -> 409, never silently re-scored
// from the fresh (unpersisted) content.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 9: a replay of the SAME fixId with DIFFERENT fix content is rejected (409 evidence_conflict)", DT, async () => {
  const actor = await withFreshUser("replay-conflict");
  const body = checkinBody();
  const first = await evidence(actor, body);
  assertEquals(first.status, "accepted");

  // The change must land in what actually gets PERSISTED (derive-fix.ts's
  // DerivedFix) to be detectable at all — a fix's raw lat/lng are used
  // only transiently to look up matchFix and never stored directly, so
  // varying lat/lng alone (against crs_x1, which has no real geometry
  // configured in this fixture set) produces an IDENTICAL derived summary
  // both times, which is correctly treated as an ordinary idempotent
  // replay, not a conflict. accuracyMeters, by contrast, IS carried
  // straight through into the stored summary.
  const changed = { ...body, fix: { ...(body.fix as object), accuracyMeters: (body.fix as { accuracyMeters: number }).accuracyMeters + 500 } };
  let threw: unknown = null;
  try {
    await evidence(actor, changed);
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError);
  assertEquals((threw as HttpError).code, "evidence_conflict");
});

// ─────────────────────────────────────────────────────────────────────────
// P3c gate round 3, blocking HIGH 1+2 ("replay handling") — against the
// REAL Repo/Postgres, not just the fake one already covered at unit
// level.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("P3c gate round 3, blocking HIGH 1: a replay with the SAME fixId but a DIFFERENT localDate is a 409 conflict, not a rescore under the new content", DT, async () => {
  const actor = await withFreshUser("replay-changed-date");
  const body = checkinBody();
  const first = await evidence(actor, body);
  assertEquals(first.status, "accepted");

  const replayedOnADifferentDay = {
    ...body,
    localDate: "2026-06-02",
    fix: { ...(body.fix as object), capturedAt: Date.parse("2026-06-02T12:00:00.000Z") },
  };
  let threw: unknown = null;
  try {
    await evidence(actor, replayedOnADifferentDay);
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError, "expected an HttpError");
  assertEquals((threw as HttpError).code, "evidence_conflict");

  const n = await rawCount(`select count(*)::int as n from app.evidence where source_ref = 'fix:${(body.fix as { fixId: string }).fixId}'`);
  assertEquals(n, 1, "the changed-date replay must never have inserted a second row");
});

Deno.test("P3c gate round 3, blocking HIGH 2: an IDENTICAL retry of a token-bearing check-in returns the SAME response, without re-consuming the token or double-scoring", DT, async () => {
  const actor = await withFreshUser("replay-identical-token");
  const courseId = `crs_replay_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const deviceId = freshUuid();

  const challenges = await withOwnership(actor, (repo) => handleChallengeRequest({ deviceId, facilityId: FAC_X }, repo, randomBytes, digestHex));
  const token = await withOwnership(actor, (repo) =>
    handleTokenRequest({ challengeId: challenges[0].id, nonce: challenges[0].nonce, hardwareSupportsAttestation: false }, repo, digestHex),
  );

  const todayInFacilityTz = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  const body = checkinBody({
    deviceId,
    courseId,
    localDate: todayInFacilityTz,
    fix: { ...checkinBody().fix as object, checkinTokenJti: token.jti, capturedAt: Date.now() },
  });

  const first = await evidence(actor, body);
  const second = await evidence(actor, body); // identical retry — e.g. a dropped-response outbox retry

  assertEquals(first.status, "accepted");
  assertEquals(second.status, "accepted");
  if (first.status === "accepted" && second.status === "accepted") {
    assertEquals(first.play.presenceSignal, true);
    assertEquals(second.play.presenceSignal, true, "the retry must return the SAME outcome, not a fresh (token-less) rescore");
    assertEquals(second.evidenceId, first.evidenceId);
    assertEquals(second.play.id, first.play.id);
    assertEquals(second.replay, true);
  }

  const evidenceCount = await rawCount(`select count(*)::int as n from app.evidence where facility_id = 'fac_x' and device_id = '${deviceId}'`);
  assertEquals(evidenceCount, 1, "the retry must never have inserted a second evidence row");
  const consumedCount = await rawCount(`select count(*)::int as n from app.checkin_token where jti = '${token.jti}' and consumed_at is not null`);
  assertEquals(consumedCount, 1, "the token must show consumed exactly once — the retry must never re-consume it");
});

// ─────────────────────────────────────────────────────────────────────────
// P3c gate round 3, blocking MEDIUM 5 ("local_date comes from the client
// label, not the server") — against the REAL Repo/Postgres.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("P3c gate round 3, blocking MEDIUM 5: 422 local_date_mismatch when the client's label doesn't match the fix's own server-derived facility-local date", DT, async () => {
  const actor = await withFreshUser("local-date-mismatch");
  let threw: unknown = null;
  try {
    // capturedAt is 2026-06-01T12:00:00Z (07:00 local in America/Chicago)
    // -- the client claims a DIFFERENT calendar date.
    await evidence(actor, checkinBody({ localDate: "2026-06-02" }));
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError);
  assertEquals((threw as HttpError).code, "local_date_mismatch");
});

/** The most recent real occurrence of `hour:minute` UTC — always <24h in
 * the past, so a test anchored to it can never accidentally trip the
 * (unrelated) clock-skew check, on whatever real calendar date this
 * suite actually runs. Chicago is UTC-5 (CDT) -- an instant at 02:00 UTC
 * is always 21:00 the PREVIOUS calendar day in America/Chicago, giving a
 * genuine UTC-vs-local calendar-date mismatch deterministically, without
 * hardcoding a specific date that would itself go stale. */
function mostRecentInstantAtUtcHour(hour: number, minute = 0): Date {
  const now = new Date();
  const candidate = new Date(now);
  candidate.setUTCHours(hour, minute, 0, 0);
  if (candidate.getTime() > now.getTime()) candidate.setUTCDate(candidate.getUTCDate() - 1);
  return candidate;
}

Deno.test("P3c gate round 3, blocking MEDIUM 5: the UTC-date-traveller case gets the correct LOCAL date accepted, not the UTC one", DT, async () => {
  const actor = await withFreshUser("utc-traveller");
  const capturedAtDate = mostRecentInstantAtUtcHour(2);
  const capturedAt = capturedAtDate.getTime();
  const utcDate = capturedAtDate.toISOString().slice(0, 10);
  const localDate = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(capturedAtDate);
  assert(localDate !== utcDate, "test setup invariant: 02:00 UTC must land on the PREVIOUS calendar day in America/Chicago");

  // The facility-LOCAL date is accepted...
  const accepted = await evidence(actor, checkinBody({ localDate, fix: { ...checkinBody().fix as object, capturedAt, fixId: `fix_local_${freshUuid()}` } }));
  assertEquals(accepted.status, "accepted", `expected the facility-local date "${localDate}" to be accepted for a capturedAt of ${capturedAtDate.toISOString()}`);

  // ...but the NAIVE UTC date (what a client that forgot to convert to
  // the facility's own tz would send) is rejected — proving this isn't
  // merely "any date is accepted," but specifically the CORRECT one.
  let threw: unknown = null;
  try {
    await evidence(actor, checkinBody({ localDate: utcDate, fix: { ...checkinBody().fix as object, capturedAt, fixId: `fix_utc_${freshUuid()}` } }));
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError);
  assertEquals((threw as HttpError).code, "local_date_mismatch");
});

Deno.test("P3c gate round 3, blocking MEDIUM 5: 422 local_date_out_of_window for a self_report far outside the facility-local window", DT, async () => {
  const actor = await withFreshUser("self-report-window");
  let threw: unknown = null;
  try {
    await evidence(actor, { source: "self_report", deviceId: freshUuid(), facilityId: FAC_X, localDate: "2020-01-01", catalogVersion: 1 });
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError);
  assertEquals((threw as HttpError).code, "local_date_out_of_window");
});

// ─────────────────────────────────────────────────────────────────────────
// item 4 end to end: the full challenge -> token -> evidence flow, real
// PostGIS containment, real device-cap and window-clamp enforcement.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 4 end to end: a live checkin-token session makes a fix a REAL co-signal (presence_signal true)", DT, async () => {
  const actor = await withFreshUser("e2e-presence");
  const courseId = `crs_e2e_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const deviceId = freshUuid();

  const challenges = await withOwnership(actor, (repo) => handleChallengeRequest({ deviceId, facilityId: FAC_X }, repo, randomBytes, digestHex));
  assertEquals(challenges.length, 1);
  const challenge = challenges[0];

  const token = await withOwnership(actor, (repo) =>
    handleTokenRequest({ challengeId: challenge.id, nonce: challenge.nonce, hardwareSupportsAttestation: false }, repo, digestHex),
  );
  assertEquals(token.attestationGrade, "unattestable");

  // A live challenge's window is anchored to REAL wall-clock time
  // (privileged.ts's own now()/clock_timestamp()) — unlike the fake-repo
  // unit tests, which run on a fixed fake clock, checkinBody()'s own
  // hardcoded 2026-06-01 capturedAt/localDate would fall OUTSIDE a
  // challenge issued at the REAL current time. Both capturedAt AND
  // localDate need to move together: packages/rules' own scorer
  // cross-checks that capturedAt, resolved into the FACILITY's own tz
  // (fac_x = America/Chicago, supabase/tests/helpers.sql), lands on the
  // SAME calendar date the submission claims as localDate — a mismatch
  // quarantines the row (excludedRows, kind: "quarantined") rather than
  // scoring it, which this suite's own first attempt at this test
  // discovered by feeding the exact stored row back into scorePlay
  // directly and reading its own excludedRows reason.
  const todayInFacilityTz = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  const result = await evidence(
    actor,
    checkinBody({
      deviceId,
      courseId,
      localDate: todayInFacilityTz,
      fix: { ...checkinBody().fix as object, checkinTokenJti: token.jti, capturedAt: Date.now() },
    }),
  );
  assertEquals(result.status, "accepted");
  if (result.status === "accepted") {
    assertEquals(result.play.presenceSignal, true, "a real, freshly-consumed live checkin-token + PostGIS-inside fix must be a real co-signal");
  }
});

Deno.test("item 4 end to end: a token issued to DEVICE A cannot be consumed by a fix submitted from DEVICE B", DT, async () => {
  const actor = await withFreshUser("e2e-device-mismatch");
  const courseId = `crs_e2edm_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const deviceA = freshUuid();
  const deviceB = freshUuid();

  const challenges = await withOwnership(actor, (repo) => handleChallengeRequest({ deviceId: deviceA, facilityId: FAC_X }, repo, randomBytes, digestHex));
  const token = await withOwnership(actor, (repo) =>
    handleTokenRequest({ challengeId: challenges[0].id, nonce: challenges[0].nonce, hardwareSupportsAttestation: false }, repo, digestHex),
  );

  // Submit the evidence from a DIFFERENT device than the one the
  // challenge/token session was issued to.
  const result = await evidence(
    actor,
    checkinBody({
      deviceId: deviceB,
      courseId,
      fix: { ...checkinBody().fix as object, checkinTokenJti: token.jti },
    }),
  );
  assertEquals(result.status, "accepted");
  if (result.status === "accepted") {
    assertEquals(result.play.presenceSignal, false, "a token/device mismatch must never become a co-signal, even though the token itself is genuinely valid and unconsumed");
  }
});

// ─────────────────────────────────────────────────────────────────────────
// item 7: device cap enforced end to end, before ANY write.
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 7: device_limit_exceeded end to end once an actor already has 20 devices, and no 21st row is created", DT, async () => {
  const actor = await withFreshUser("device-cap");
  await withOwnership(actor, async (repo) => {
    for (let i = 0; i < 20; i++) await repo.device.ensureOwn(null, "ios");
  });
  const before = await withOwnership(actor, (repo) => repo.device.countForUser());
  assertEquals(before, 20);

  let threw: unknown = null;
  try {
    await evidence(actor, checkinBody({ deviceId: freshUuid() }));
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError);
  assertEquals((threw as HttpError).code, "device_limit_exceeded");

  const after = await withOwnership(actor, (repo) => repo.device.countForUser());
  assertEquals(after, 20, "a rejected over-cap request must never create the 21st device row");
});

// ─────────────────────────────────────────────────────────────────────────
// AT 8 / AT 15: catalog skew against REAL app.catalog_version /
// app.catalog_signing_key rows this suite seeds itself (never perturbing
// fac_x's own catalog_version=1 row from supabase/tests/helpers.sql).
// ─────────────────────────────────────────────────────────────────────────
Deno.test("AT 15: a revoked-kid current version is 422 catalog_stale, against a REAL catalog_signing_key row", DT, async () => {
  const actor = await withFreshUser("revoked-kid");
  const version = 88001;
  const kid = `kid-revoked-${freshUuid()}`;
  await insertSigningKey(kid, new Date()); // revoked now
  await insertCatalogVersion(version, new Date(), kid);

  let threw: unknown = null;
  try {
    await evidence(actor, checkinBody({ catalogVersion: version }));
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError);
  assertEquals((threw as HttpError).code, "catalog_stale");
});

Deno.test("AT 8: a version far behind the real current is 422 catalog_stale", DT, async () => {
  const actor = await withFreshUser("stale-behind");
  const version = 88002;
  const kid = `kid-fresh-${freshUuid()}`;
  await insertSigningKey(kid, null);
  await insertCatalogVersion(version, new Date(), kid);

  let threw: unknown = null;
  try {
    // catalogVersion 1 (the seeded fac_x baseline) is now `version -
    // 899`-ish releases behind this test's own newly-inserted version —
    // well past the 5-version skew window.
    await evidence(actor, checkinBody({ catalogVersion: 1 }));
  } catch (err) {
    threw = err;
  }
  assert(threw instanceof HttpError);
  assertEquals((threw as HttpError).code, "catalog_stale");
});

// ─────────────────────────────────────────────────────────────────────────
// item 8 at the true call site: concurrent handleChallengeRequest
// prefetch-count-then-insert race, through the HTTP-shaped handler (not
// just the raw Repo method — repo.deno.test.ts already covers that).
// ─────────────────────────────────────────────────────────────────────────
Deno.test("item 8 (handler-level): concurrent prefetch challenge requests never exceed the 10-per-device cap", DT, async () => {
  const actor = await withFreshUser("prefetch-handler-race");
  const deviceId = freshUuid();

  // 3 concurrent requests for 5 each (15 total demand) against a cap of
  // 10 — real overlapping HTTP-shaped requests, each its own
  // withOwnership transaction. Once the cap is fully spent, a LATER
  // (still-queued-behind-the-advisory-lock) request legitimately 429s
  // (challenge-handler.ts's own `room <= 0` check) rather than returning
  // an empty array — a real HttpError, not a bug — so this uses
  // allSettled and counts only what actually got ISSUED, exactly the way
  // a real caller handling 3 genuinely concurrent HTTP requests would.
  const attempts = Array.from({ length: 3 }, () =>
    withOwnership(actor, (repo) => handleChallengeRequest({ deviceId, prefetchCount: 5 }, repo, randomBytes, digestHex)),
  );
  const settled = await Promise.allSettled(attempts);
  for (const s of settled) {
    if (s.status === "rejected") assert(s.reason instanceof HttpError && s.reason.code === "rate_limited", `unexpected rejection shape: ${s.reason}`);
  }
  const totalIssued = settled.reduce((sum, s) => sum + (s.status === "fulfilled" ? s.value.length : 0), 0);
  assertEquals(totalIssued, 10, `expected exactly 10 prefetched challenges issued across 3 concurrent requests demanding 15 — got ${totalIssued}`);

  const n = await rawCount(`select count(*)::int as n from app.checkin_challenge where device_id = '${deviceId}' and kind = 'prefetched' and used_at is null`);
  assertEquals(n, 10);
});
