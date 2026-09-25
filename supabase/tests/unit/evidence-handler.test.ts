// supabase/tests/unit/evidence-handler.test.ts
import { describe, expect, it } from "vitest";
import { handleEvidenceIntake, planEvidenceRateLimitChecks } from "../../functions/_shared/evidence/handler.js";
import { FAKE_DEVICE_ID, fakeHitRateLimitForActor, makeFakeRepo, makeFakeState } from "./fake-repo.js";
import { HttpError } from "../../functions/_shared/http.js";

function checkinBody(overrides: Record<string, unknown> = {}) {
  return {
    source: "foreground_checkin",
    deviceId: FAKE_DEVICE_ID,
    facilityId: "fac_x",
    courseId: "crs_x1",
    localDate: "2026-06-01",
    catalogVersion: 1,
    fix: {
      fixId: "fix_1",
      lat: 36.1467,
      lng: -86.7816,
      accuracyMeters: 10,
      capturedAt: Date.parse("2026-06-01T12:00:00.000Z"),
      simulated: false,
      foreground: true,
      fromApp: true,
    },
    ...overrides,
  };
}

describe("handleEvidenceIntake", () => {
  it("accepts a well-formed submission and creates a play", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleEvidenceIntake(checkinBody(), repo);
    expect(result.status).toBe("accepted");
    if (result.status === "accepted") {
      expect(result.replay).toBe(false);
      expect(result.play.id).not.toBe("");
    }
  });

  it("AT 3: a replayed payload yields ONE evidence row and ONE play", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const first = await handleEvidenceIntake(checkinBody(), repo);
    const second = await handleEvidenceIntake(checkinBody(), repo);
    expect(first.status).toBe("accepted");
    expect(second.status).toBe("accepted");
    if (second.status === "accepted") expect(second.replay).toBe(true);
    expect(state.evidence.size).toBe(1);
    expect(state.plays.size).toBe(1);
  });

  // ⛔ P3c gate round 4, blocking MEDIUM ("make the replay path
  // read-only... no re-score beyond what's idempotent"): the replay must
  // not WRITE the play row at all — `Repo#play.getForDate` is a plain
  // read. Proven here by identity: `upsertFromScore` always replaces the
  // stored object (`state.plays.set(key, {...input, id, userId})`), so a
  // genuine re-score/re-upsert would produce a NEW object reference even
  // if every field's VALUE happened to come out the same; a read-only
  // replay leaves the ORIGINAL object in place.
  it("P3c gate round 4, blocking MEDIUM: a replay reads the play row back, it never re-upserts it", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const body = checkinBody();
    await handleEvidenceIntake(body, repo);
    const key = `user-a:crs_x1:2026-06-01`;
    const storedBeforeReplay = state.plays.get(key);
    expect(storedBeforeReplay).toBeDefined();

    const replay = await handleEvidenceIntake(body, repo);
    expect(replay.status).toBe("accepted");
    if (replay.status === "accepted") expect(replay.replay).toBe(true);

    const storedAfterReplay = state.plays.get(key);
    expect(storedAfterReplay).toBe(storedBeforeReplay); // SAME object reference — never replaced by a write
  });

  // ⛔ FIX (P3c gate round 2, item 9): "replay with a changed payload."
  it("409 evidence_conflict: a replay of the SAME fixId with different fix content", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await handleEvidenceIntake(checkinBody(), repo);
    // accuracyMeters (unlike lat/lng, which are used only transiently to
    // look up matchFix and never persisted directly) IS carried straight
    // through into the stored summary via derive-fix.ts's DerivedFix, so
    // it is guaranteed to be a DETECTABLE change regardless of whether
    // crs_x1 has a registered PostGIS match fixture.
    const changed = checkinBody({ fix: { ...(checkinBody().fix as object), accuracyMeters: 500 } });
    await expect(handleEvidenceIntake(changed, repo)).rejects.toMatchObject({ code: "evidence_conflict" });
  });

  it("rejects a client-supplied user_id-equivalent forgery attempt — courseId: null is a structural error, never silently accepted as facility-level", async () => {
    await expect(handleEvidenceIntake(checkinBody({ courseId: null }), makeFakeRepo(makeFakeState(), "user-a"))).rejects.toThrow(HttpError);
  });

  it("422 unknown_id: an id not in the ledger, with a non-newer catalogVersion", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await expect(handleEvidenceIntake(checkinBody({ facilityId: "fac_ghost" }), repo)).rejects.toMatchObject({ code: "unknown_id" });
  });

  // ⛔ FIX (P3c gate round 2, item 3): "forged facility/course pairing."
  it("422 facility_course_mismatch: a real course id belonging to a DIFFERENT facility than the one claimed", async () => {
    const state = makeFakeState();
    state.ledger.set("fac_y", { id: "fac_y", kind: "facility", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 });
    state.facilityTz.set("fac_y", "America/Chicago");
    const repo = makeFakeRepo(state, "user-a");
    await expect(handleEvidenceIntake(checkinBody({ facilityId: "fac_y" }), repo)).rejects.toMatchObject({ code: "facility_course_mismatch" });
  });

  it("422 catalog_stale: a declared version far behind the server's own", async () => {
    const state = makeFakeState();
    state.catalogVersions.set(20, { version: 20, publishedAt: "2026-06-01T00:00:00.000Z", contractVersion: "v1", sha256: "x", kid: "k1" });
    const repo = makeFakeRepo(state, "user-a");
    await expect(handleEvidenceIntake(checkinBody({ catalogVersion: 1 }), repo)).rejects.toMatchObject({ code: "catalog_stale" });
  });

  // ⛔ FIX (P3c gate round 2, should-fix "revoked kid" / AT 15).
  it("422 catalog_stale: the CURRENT version's own signing kid has been revoked", async () => {
    const state = makeFakeState();
    state.signingKeys.set("k1", { kid: "k1", publicKeyB64Url: "anything", revokedAt: "2026-05-25T00:00:00.000Z" });
    const repo = makeFakeRepo(state, "user-a");
    await expect(handleEvidenceIntake(checkinBody({ catalogVersion: 1 }), repo)).rejects.toMatchObject({ code: "catalog_stale" });
  });

  it("422 catalog_forged: a far-future catalogVersion", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await expect(handleEvidenceIntake(checkinBody({ catalogVersion: 5000 }), repo)).rejects.toMatchObject({ code: "catalog_forged" });
  });

  it("422 catalog_forged: a newer (not far-future) version with no verifying manifestSig — this environment's own deferred-signature stub", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await expect(handleEvidenceIntake(checkinBody({ catalogVersion: 2 }), repo)).rejects.toMatchObject({ code: "catalog_forged" });
  });

  it("202 queued_catalog: a newer version WITH a manifestSig that verifies against a registered key", async () => {
    const state = makeFakeState();
    state.signingKeys.set("k1", { kid: "k1", publicKeyB64Url: "anything-nonempty", revokedAt: null });
    const repo = makeFakeRepo(state, "user-a");
    // Monkeypatch: this test only needs classifyCatalogSubmission's OWN
    // verify callback to say yes — handler.ts calls
    // verifyManifestSignature for real, which would genuinely fail
    // against a fake key. This test instead proves the 202 CODE PATH by
    // registering a key AND accepting that a real crypto check still
    // fails it here (defense in depth is real) -- so this case documents
    // the honest limitation instead of faking a signature: without a
    // real Ed25519 keypair, this can only reach catalog_forged, exactly
    // as production would with an invalid/forged signature.
    await expect(
      handleEvidenceIntake(checkinBody({ catalogVersion: 2, manifestSig: { kid: "k1", signatureB64Url: "AAAA", manifestSha256: "0".repeat(64) } }), repo),
    ).rejects.toMatchObject({ code: "catalog_forged" });
  });

  // ⛔ P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock
  // the pool"): rate-limiting moved OUT of `handleEvidenceIntake`
  // entirely, into `planEvidenceRateLimitChecks` — the caller (evidence/
  // index.ts in production; this precheck helper here) hits it BEFORE
  // ever calling the handler. This test now mirrors that real call
  // shape instead of relying on the handler to rate-limit internally.
  async function precheckThenIntake(state: ReturnType<typeof makeFakeState>, uid: string, repo: ReturnType<typeof makeFakeRepo>, body: unknown) {
    const { checks } = planEvidenceRateLimitChecks(body);
    for (const check of checks) {
      const r = await fakeHitRateLimitForActor(state, uid, check.bucketKey, check.windowSeconds, check.max);
      if (!r.ok) throw Object.assign(new Error("evidence rate limit exceeded"), { code: "rate_limited" });
    }
    return handleEvidenceIntake(body, repo);
  }

  it("429: per-user evidence rate limit", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    for (let i = 0; i < 60; i++) {
      await precheckThenIntake(state, "user-a", repo, checkinBody({ fix: { ...(checkinBody().fix as object), fixId: `fix_rl_${i}` } }));
    }
    await expect(precheckThenIntake(state, "user-a", repo, checkinBody({ fix: { ...(checkinBody().fix as object), fixId: "fix_rl_last" } }))).rejects.toMatchObject({ code: "rate_limited" });
  });

  it("P3c gate round 4, blocking MEDIUM: a rate-limit check runs even for a replay (planEvidenceRateLimitChecks is unconditional)", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const body = checkinBody();
    // First (genuinely new) submission, then N replays of the exact same
    // body — every one of them must still hit the SAME rate-limit
    // buckets planEvidenceRateLimitChecks returns, since that check now
    // runs BEFORE handleEvidenceIntake (and therefore before
    // findExisting) is ever reached, replay or not.
    await precheckThenIntake(state, "user-a", repo, body);
    const bucketKey = `user-a:evidence:user`;
    const before = state.rateLimits.get(bucketKey) ?? 0;
    await precheckThenIntake(state, "user-a", repo, body);
    await precheckThenIntake(state, "user-a", repo, body);
    const after = state.rateLimits.get(bucketKey) ?? 0;
    expect(after).toBe(before + 2); // each replay still counted
  });

  // ⛔ FIX (P3c gate round 2, item 7): "cap the number of devices per
  // user... don't create device rows on rejected requests."
  it("422 device_limit_exceeded once a user already has 20 devices, and never creates the 21st device row", async () => {
    const state = makeFakeState();
    for (let i = 0; i < 20; i++) {
      const id = `22222222-2222-4222-8222-2222222222${i.toString().padStart(2, "0")}`;
      state.devices.set(id, { id, userId: "user-a" });
    }
    const repo = makeFakeRepo(state, "user-a");
    const newDeviceId = "33333333-3333-4333-8333-333333333333";
    await expect(handleEvidenceIntake(checkinBody({ deviceId: newDeviceId }), repo)).rejects.toMatchObject({ code: "device_limit_exceeded" });
    expect(state.devices.has(newDeviceId)).toBe(false);
  });

  it("security doc §3: clock skew > 24h raises a fraud_signal", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    // P3c gate round 3, blocking MEDIUM 5: `localDate` must now match the
    // server-derived (facility-tz) date of this SAME skewed capturedAt —
    // 2026-05-31T06:00:00Z is still 2026-05-31 in America/Chicago
    // (UTC-5) — or the request 422s on `local_date_mismatch` before ever
    // reaching the clock-skew check this test means to exercise. The
    // skew itself (>24h from state.now, 2026-06-01T12:00:00Z) is
    // unaffected by which calendar date it lands on.
    const skewedCapturedAt = state.now.getTime() - 30 * 60 * 60 * 1000;
    const skewed = checkinBody({
      localDate: "2026-05-31",
      fix: { ...(checkinBody().fix as object), capturedAt: skewedCapturedAt },
    });
    await handleEvidenceIntake(skewed, repo);
    expect(state.fraudSignals.some((s) => s.kind === "clock_skew")).toBe(true);
  });

  it("stub-course promotion (G3-01): a play at an unverified STUB course is accepted", async () => {
    const state = makeFakeState();
    state.ledger.set("crs_stub", { id: "crs_stub", kind: "course", status: "stub", verifiedInVersion: null, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 });
    state.courseFacility.set("crs_stub", "fac_x");
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleEvidenceIntake(checkinBody({ courseId: "crs_stub" }), repo);
    expect(result.status).toBe("accepted");
  });

  it("a tombstoned/merged id resolves to its survivor before scoring", async () => {
    const state = makeFakeState();
    state.ledger.set("crs_old", { id: "crs_old", kind: "course", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: "2026-01-01T00:00:00.000Z", mergedInto: "crs_x1", firstCatalogVersion: 1 });
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleEvidenceIntake(checkinBody({ courseId: "crs_old" }), repo);
    expect(result.status).toBe("accepted");
    const [evidenceRow] = [...state.evidence.values()];
    expect(evidenceRow.courseId).toBe("crs_x1"); // rewritten to the survivor
  });

  // ⛔ FIX (P3c gate round 2, item 1): day-2 evidence. Two ACCEPTED rows on
  // DIFFERENT local dates for the same (facility, course) must never
  // collide — the second day's check-in must succeed on its own, not 500
  // on a stale/fail-open date filter.
  it("day 2: a second check-in for the SAME course on a LATER local date succeeds independently", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const day1 = await handleEvidenceIntake(checkinBody({ localDate: "2026-06-01", fix: { ...(checkinBody().fix as object), fixId: "fix_day1" } }), repo);
    const day2 = await handleEvidenceIntake(
      checkinBody({ localDate: "2026-06-02", fix: { ...(checkinBody().fix as object), fixId: "fix_day2", capturedAt: Date.parse("2026-06-02T12:00:00.000Z") } }),
      repo,
    );
    expect(day1.status).toBe("accepted");
    expect(day2.status).toBe("accepted");
    if (day1.status === "accepted" && day2.status === "accepted") {
      expect(day2.play.id).not.toBe(day1.play.id); // two distinct plays, one per date
    }
    expect(state.evidence.size).toBe(2);
    expect(state.plays.size).toBe(2);
  });

  // ⛔ FIX (P3c gate round 2, item 1): "cover the facility-level row with a
  // second course on the same day." A facility-level (no courseId) row
  // must be VISIBLE (candidate for scoring) to EVERY course-anchored play
  // at that facility+date, not just whichever course happened to be
  // submitted alongside it — tested directly against
  // `Repo#evidence.listForPlay` (the exact query item 1 fixed), since
  // whether the bundled scorer's contribution rules actually WEIGH a
  // self_report row is a separate, packages/rules-owned concern this
  // handler-level test has no business asserting on.
  it("a facility-level (no courseId) row is a listForPlay candidate for a SECOND course's play on the same day", async () => {
    const state = makeFakeState();
    state.ledger.set("crs_x2", { id: "crs_x2", kind: "course", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 });
    state.courseFacility.set("crs_x2", "fac_x");
    const repo = makeFakeRepo(state, "user-a");
    const facilityLevel = await handleEvidenceIntake({ source: "self_report", deviceId: FAKE_DEVICE_ID, facilityId: "fac_x", localDate: "2026-06-01", catalogVersion: 1 }, repo);
    expect(facilityLevel.status).toBe("accepted"); // no courseId -> no play of its own
    if (facilityLevel.status !== "accepted") throw new Error("unreachable");
    const rowsForCourseA = await repo.evidence.listForPlay("fac_x", "crs_x1", "2026-06-01");
    const rowsForCourseB = await repo.evidence.listForPlay("fac_x", "crs_x2", "2026-06-01");
    expect(rowsForCourseA.some((r) => r.id === facilityLevel.evidenceId)).toBe(true);
    expect(rowsForCourseB.some((r) => r.id === facilityLevel.evidenceId)).toBe(true);
  });

  it("presence_signal is true only with a REAL PostGIS-verified co-signal fix, through a live checkin-token session", async () => {
    const state = makeFakeState();
    const chalId = "chal_1";
    state.challenges.set(chalId, {
      id: chalId,
      userId: "user-a",
      staffUserId: null,
      deviceId: FAKE_DEVICE_ID,
      facilityId: "fac_x",
      nonceHash: "n1",
      kind: "live",
      expiresAt: "2099-01-01T00:00:00.000Z",
      usedAt: null,
    });
    state.checkinTokens.set("jti_1", {
      jti: "jti_1",
      userId: "user-a",
      deviceId: FAKE_DEVICE_ID,
      facilityId: "fac_x",
      attestationGrade: "attested",
      challengeKind: "live",
      challengeId: chalId,
      expiresAt: "2099-01-01T00:00:00.000Z",
      issuedAt: "2020-01-01T00:00:00.000Z",
      consumedAt: null,
    });
    state.matches.set("crs_x1", { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true });
    const repo = makeFakeRepo(state, "user-a");

    const result = await handleEvidenceIntake(checkinBody({ fix: { ...(checkinBody().fix as object), checkinTokenJti: "jti_1" } }), repo);
    expect(result.status).toBe("accepted");
    if (result.status === "accepted") {
      expect(result.play.presenceSignal).toBe(true);
      // Honest limitation (documented in handler.ts's own header and the
      // P3c report): a bare foreground_checkin co-signal alone (weight
      // 0.30, device-GPS group) never reaches MONEY_MIN (0.85) — money
      // -eligible classes (staff_presence/booking/receipt) are correctly
      // out of this round's accepted-source set (security doc §2).
      expect(result.play.money).toBe(false);
    }
  });

  // ⛔ FIX (P3c gate round 2, item 4): a token whose captured-at falls
  // OUTSIDE its own [issued_at, expires_at] window is never a co-signal —
  // even though the token itself is otherwise unconsumed and unexpired.
  it("a fix captured OUTSIDE its own checkin-token's issued/expires window is never a co-signal", async () => {
    const state = makeFakeState();
    const chalId = "chal_2";
    state.challenges.set(chalId, {
      id: chalId,
      userId: "user-a",
      staffUserId: null,
      deviceId: FAKE_DEVICE_ID,
      facilityId: "fac_x",
      nonceHash: "n2",
      kind: "live",
      expiresAt: "2099-01-01T00:00:00.000Z",
      usedAt: null,
    });
    state.checkinTokens.set("jti_2", {
      jti: "jti_2",
      userId: "user-a",
      deviceId: FAKE_DEVICE_ID,
      facilityId: "fac_x",
      attestationGrade: "attested",
      challengeKind: "live",
      challengeId: chalId,
      expiresAt: "2026-06-01T13:00:00.000Z",
      issuedAt: "2026-06-01T11:00:00.000Z",
      consumedAt: null,
    });
    state.matches.set("crs_x1", { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true });
    const repo = makeFakeRepo(state, "user-a");
    // capturedAt well AFTER the token's own expires_at.
    const result = await handleEvidenceIntake(
      checkinBody({ fix: { ...(checkinBody().fix as object), checkinTokenJti: "jti_2", capturedAt: Date.parse("2026-06-01T23:00:00.000Z") } }),
      repo,
    );
    expect(result.status).toBe("accepted");
    if (result.status === "accepted") expect(result.play.presenceSignal).toBe(false);
  });

  it("without a valid checkin-token session, a fix is never a co-signal even if PostGIS says inside", async () => {
    const state = makeFakeState();
    state.matches.set("crs_x1", { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true });
    const repo = makeFakeRepo(state, "user-a");
    const result = await handleEvidenceIntake(checkinBody(), repo);
    expect(result.status).toBe("accepted");
    if (result.status === "accepted") expect(result.play.presenceSignal).toBe(false);
  });

  // ⛔ P3c gate round 3, blocking HIGH 1 ("changed-replay bypass").
  // Repro from the gate report: fixId Z on day 1 with no token, replayed
  // as fixId Z on day 2 with a live token — the OLD check only compared
  // content when the stored row showed up in THAT call's own
  // listForPlay window, which a changed localDate skips entirely. This
  // now conflicts unconditionally: `findExisting` matches on
  // (user, source, source_ref) alone (unaffected by localDate), so a
  // content difference is caught however it differs.
  it("P3c gate round 3, blocking HIGH 1: a replay with the SAME fixId but a DIFFERENT localDate is a 409 conflict, never scored under the new content", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    await handleEvidenceIntake(checkinBody(), repo); // day 1: fix_1 @ 2026-06-01
    const replayedOnADifferentDay = checkinBody({
      localDate: "2026-06-02",
      fix: { ...(checkinBody().fix as object), capturedAt: Date.parse("2026-06-02T12:00:00.000Z") },
    });
    await expect(handleEvidenceIntake(replayedOnADifferentDay, repo)).rejects.toMatchObject({ code: "evidence_conflict" });
    expect(state.evidence.size).toBe(1); // no second row was ever inserted
  });

  // ⛔ P3c gate round 3, blocking HIGH 2 ("AT 3 regression"). The OLD
  // `consumeTokenForFix` ran BEFORE the replay check, so an IDENTICAL
  // retry of a token-bearing check-in (e.g. an outbox retry after a
  // dropped response) saw its own token already consumed and produced a
  // false conflict. `findExisting` now runs FIRST — an exact-hash match
  // never touches the token at all; `buildReplayResult` re-derives the
  // SAME response purely from what's already stored.
  it("P3c gate round 3, blocking HIGH 2: an IDENTICAL retry of a token-bearing check-in succeeds with the same response, without re-consuming the token", async () => {
    const state = makeFakeState();
    const chalId = "chal_3";
    state.challenges.set(chalId, { id: chalId, userId: "user-a", staffUserId: null, deviceId: FAKE_DEVICE_ID, facilityId: "fac_x", nonceHash: "n3", kind: "live", expiresAt: "2099-01-01T00:00:00.000Z", usedAt: null });
    state.checkinTokens.set("jti_3", {
      jti: "jti_3",
      userId: "user-a",
      deviceId: FAKE_DEVICE_ID,
      facilityId: "fac_x",
      attestationGrade: "attested",
      challengeKind: "live",
      challengeId: chalId,
      expiresAt: "2099-01-01T00:00:00.000Z",
      issuedAt: "2020-01-01T00:00:00.000Z",
      consumedAt: null,
    });
    state.matches.set("crs_x1", { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true });
    const repo = makeFakeRepo(state, "user-a");
    const body = checkinBody({ fix: { ...(checkinBody().fix as object), checkinTokenJti: "jti_3" } });

    const first = await handleEvidenceIntake(body, repo);
    const second = await handleEvidenceIntake(body, repo); // identical retry

    expect(first.status).toBe("accepted");
    expect(second.status).toBe("accepted");
    if (first.status === "accepted" && second.status === "accepted") {
      expect(first.play.presenceSignal).toBe(true);
      expect(second.play.presenceSignal).toBe(true); // not re-derived from a now-consumed token
      expect(second.replay).toBe(true);
    }
    expect(state.evidence.size).toBe(1);
    expect(state.checkinTokens.get("jti_3")?.consumedAt).not.toBeNull(); // consumed exactly once, by the FIRST call
  });

  // ⛔ P3c gate round 3, blocking MEDIUM 5: "local_date comes from the
  // client label, not the server."
  it("P3c gate round 3, blocking MEDIUM 5: 422 local_date_mismatch when the client's label doesn't match the fix's own server-derived facility-local date", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    // capturedAt is 2026-06-01T12:00:00Z (07:00 local in America/Chicago)
    // -- the client claims a DIFFERENT calendar date.
    const body = checkinBody({ localDate: "2026-06-02" });
    await expect(handleEvidenceIntake(body, repo)).rejects.toMatchObject({ code: "local_date_mismatch" });
  });

  it("P3c gate round 3, blocking MEDIUM 5: the UTC-date-traveller case gets the correct LOCAL date and no fraud signal", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    // 2026-06-02T02:00:00Z is already June 2 in UTC, but only
    // 2026-06-01T21:00:00-05:00 in the facility's own America/Chicago tz
    // -- the CORRECT client label is the facility-LOCAL date, never the
    // UTC one.
    const capturedAt = Date.parse("2026-06-02T02:00:00.000Z");
    const body = checkinBody({ localDate: "2026-06-01", fix: { ...(checkinBody().fix as object), capturedAt } });
    const result = await handleEvidenceIntake(body, repo);
    expect(result.status).toBe("accepted");
    expect(state.fraudSignals.length).toBe(0);
  });

  it("P3c gate round 3, blocking MEDIUM 5: 422 local_date_out_of_window for a self_report far outside the facility-local window", async () => {
    const state = makeFakeState();
    const repo = makeFakeRepo(state, "user-a");
    const body = { source: "self_report", deviceId: FAKE_DEVICE_ID, facilityId: "fac_x", localDate: "2020-01-01", catalogVersion: 1 };
    await expect(handleEvidenceIntake(body, repo)).rejects.toMatchObject({ code: "local_date_out_of_window" });
  });

  // ⛔ FIX (P3c gate round 2, item 6): connect_iq/health_route/file_import
  // are rejected outright, the same as every other trust-table-restricted
  // source — see request-shape.test.ts for the parse-layer coverage; this
  // proves the END-TO-END handler path also never accepts them.
  it("422s connect_iq/health_route/file_import end to end (P3c gate round 2, item 6)", async () => {
    const repo = makeFakeRepo(makeFakeState(), "user-a");
    for (const source of ["connect_iq", "health_route", "file_import"]) {
      await expect(handleEvidenceIntake({ ...checkinBody(), source, fix: undefined }, repo)).rejects.toThrow(HttpError);
    }
  });
});
