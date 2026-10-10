// supabase/tests/unit/marker-scan-handler.test.ts
//
// POST /v1/marker-scan (_shared/course-qr/scan-handler.ts), the Edge half of the player's course-QR lane, over the in-memory Repo (fake-marker-scan-repo.ts). What is proven HERE is the
// handler's own contract: the ORDER of its steps (the refusals that must commit come before anything is consumed), the Ed25519 verification and the fraud signal, the check-in token's
// consumption, the fix's grading and its single `foreground_checkin` evidence row, the HTTP mapping of every database refusal, and the response the mobile client implements. What is NOT
// provable here is the database: FORCE RLS, the policies, single use under concurrency, a refusal's ROLLBACK, the Vault pepper. Those are the pgTAP matrix 24_* and
// supabase/tests/integration/marker-scan.deno.test.ts, on a real cluster.

import { describe, expect, it } from "vitest";
import { HttpError } from "../../functions/_shared/http.ts";
import { handleMarkerScan, type MarkerScanOutcome } from "../../functions/_shared/course-qr/scan-handler.ts";
import { parseMarkerScanBody } from "../../functions/_shared/course-qr/request-shape.ts";
import { base64UrlEncode } from "../../functions/_shared/course-qr/format.ts";
import { FAKE_DEVICE_ID, makeFakeRepo } from "./fake-repo.ts";
import { generateTestSigningKey, mintPrintedQrSig } from "./course-qr-test-keys.ts";
import { FAC, UID, body, deps, fixAt, seedRotating, seedToken, world, type World } from "./marker-scan-world.ts";

const thrown = async (p: Promise<unknown>): Promise<{ status: number; code: string; details?: unknown }> => {
  try {
    await p;
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, code: e.code, details: e.details };
    throw e;
  }
  throw new Error("expected an HttpError");
};
const ok = (o: MarkerScanOutcome) => {
  if (o.kind !== "ok") throw new Error(`expected ok, got refused ${o.error.status} ${o.error.code}`);
  return o;
};
const refused = (o: MarkerScanOutcome) => {
  if (o.kind !== "refused") throw new Error("expected a refused outcome");
  return o.error;
};
const evidenceRows = (w: World) => [...w.state.evidence.values()];

describe("the response's `outcome` is the WORST state across the purchases", () => {
  const view = (purchaseStatus: "valid" | "pending" | "held_review", creditStatus: "credited" | "pending" | "held_review" | "void", n: number) => ({ purchaseId: `pe${n}`, trailId: `trl${n}`, purchaseStatus, creditId: `mc${n}`, creditStatus });
  async function outcomeOf(purchases: ReturnType<typeof view>[]): Promise<string> {
    const w = await world();
    const t = await seedRotating(w);
    const repo = { ...w.repo, markerScan: { ...w.repo.markerScan, record: async () => ({ status: "accepted" as const, localDate: "2026-06-01", purchases }) } };
    return ok(await handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), repo, deps)).body.outcome;
  }
  it("credited only when EVERY credit is; held_review when any needs a reviewer; otherwise pending", async () => {
    expect(await outcomeOf([view("valid", "credited", 1), view("valid", "credited", 2)])).toBe("credited");
    expect(await outcomeOf([view("valid", "credited", 1), view("pending", "pending", 2)])).toBe("pending");
    expect(await outcomeOf([view("valid", "credited", 1), view("valid", "void", 2)])).toBe("pending");
    expect(await outcomeOf([view("valid", "credited", 1), view("held_review", "held_review", 2)])).toBe("held_review");
    expect(await outcomeOf([view("pending", "pending", 1), view("held_review", "held_review", 2)])).toBe("held_review");
  });
});

describe("a rotating-token scan with a qualifying fix (AT(19))", () => {
  it("is 201 `credited`: one purchase per eligible trail, and the fix is counted ONCE as a facility-level foreground_checkin", async () => {
    const w = await world({ programme: ["trl_a", "trl_b"] });
    const t = await seedRotating(w);
    const jti = seedToken(w);
    const f = fixAt(w);
    const out = ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: f, jti }), w.repo, deps));
    expect(out.status).toBe(201);
    expect(out.body).toMatchObject({ outcome: "credited", facilityId: FAC, localDate: "2026-06-01", cosignal: "counted" });
    expect(out.body.purchases.map((p) => [p.trailId, p.status, p.credit.status])).toEqual([["trl_a", "valid", "credited"], ["trl_b", "valid", "credited"]]);
    // the evidence row: ONE, source foreground_checkin, keyed fix:<fixId>, facility-level (no course), carrying the server-derived fix
    const rows = evidenceRows(w);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ source: "foreground_checkin", sourceRef: `fix:${f.fixId}`, facilityId: FAC, courseId: null, localDate: "2026-06-01", attestationGrade: "attested", status: "accepted", userId: UID });
    expect(rows[0]!.kind).toBe("resolved");
    const derived = (rows[0] as unknown as { summary: { fix: Record<string, unknown> } }).summary.fix;
    expect(derived).toMatchObject({ fixId: f.fixId, facilityId: FAC, challenge: "prefetched", token: { present: true, grade: "attested" }, verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true, localDate: "2026-06-01" });
    // the check-in token was consumed (for this one fix), and the purchase NEVER scored as a play
    expect(w.state.checkinTokens.get(jti)!.consumedAt).not.toBeNull();
    expect(w.state.plays.size).toBe(0);
    // the QR was verified before anything was consumed, and the PIN gate was not involved
    expect(w.ms.calls).toEqual(["publicKey:rotating_token:rk1", "record"]);
  });

  it("the response is exactly the documented shape (what the mobile client implements)", async () => {
    const w = await world();
    const t = await seedRotating(w);
    const out = ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps));
    expect(Object.keys(out.body).sort()).toEqual(["cosignal", "facilityId", "localDate", "outcome", "purchases"]);
    expect(Object.keys(out.body.purchases[0]!).sort()).toEqual(["credit", "purchaseId", "status", "trailId"]);
    expect(Object.keys(out.body.purchases[0]!.credit).sort()).toEqual(["id", "status"]);
    expect(JSON.stringify(out.body)).not.toMatch(/nonce|token|grade|attest/i); // no secret and no trust fact goes back to the client
  });

  it("the SAME token scanned again is 409 qr_used; the SAME fix again is 409 fix_already_used (and consumes nothing)", async () => {
    const w = await world();
    const t = await seedRotating(w);
    const f = fixAt(w);
    const req = body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: f, jti: seedToken(w) });
    ok(await handleMarkerScan(req, w.repo, deps));
    expect(await thrown(handleMarkerScan(req, w.repo, deps))).toMatchObject({ status: 409, code: "fix_already_used" });
    const second = body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: seedToken(w) });
    expect(await thrown(handleMarkerScan(second, w.repo, deps))).toMatchObject({ status: 409, code: "qr_used" });
  });

  it("a token more than 120 s from the FIX time is 422 qr_expired; the same token with a fix inside the window is accepted (the upload time does not matter)", async () => {
    const w = await world();
    const t = await seedRotating(w, { iatOffsetSec: -3 * 86_400 }); // issued three days ago
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w, -10_000), jti: seedToken(w) }), w.repo, deps))).toMatchObject({ status: 422, code: "qr_expired" });
    // a fix taken 20 s after the token was issued, uploaded three days later
    const old = fixAt(w, -3 * 86_400_000 + 20_000);
    const out = ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: old, jti: seedToken(w, { challengeIssuedAgoMs: 4 * 86_400_000 }) }), w.repo, deps));
    expect(out.body.outcome).toBe("credited");
    expect(out.body.localDate).toBe("2026-05-29");
  });

  it("an unattestable fix is `held_review` (the evidence row records the grade); a failed one is no co-signal at all (pending, no evidence row)", async () => {
    const w = await world();
    const t1 = await seedRotating(w);
    const out = ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t1.token }, fix: fixAt(w), jti: seedToken(w, { grade: "unattestable" }) }), w.repo, deps));
    expect(out.body).toMatchObject({ outcome: "held_review", cosignal: "counted" });
    expect(evidenceRows(w)[0]).toMatchObject({ attestationGrade: "unattestable" });
    const t2 = await seedRotating(w);
    const failed = ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t2.token }, fix: fixAt(w), jti: seedToken(w, { grade: "failed" }) }), w.repo, deps));
    expect(failed.body).toMatchObject({ outcome: "pending", cosignal: "none" });
    expect(evidenceRows(w)).toHaveLength(1); // only the unattestable one
  });
});

describe("a scan with no qualifying co-signal is `pending` (AT(3))", () => {
  it("no fix: pending, no evidence row, no check-in token touched", async () => {
    const w = await world();
    const t = await seedRotating(w);
    const out = ok(await handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps));
    expect(out.body).toMatchObject({ outcome: "pending", cosignal: "none" });
    expect(out.body.purchases.every((p) => p.status === "pending" && p.credit.status === "pending")).toBe(true);
    expect(evidenceRows(w)).toHaveLength(0);
  });

  it("a fix with no jti is not a co-signal (no challenge); neither is one outside the facility's polygon, or against another facility's challenge: pending, no evidence row", async () => {
    const w = await world();
    const a = await seedRotating(w);
    expect(ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: a.token }, fix: fixAt(w) }), w.repo, deps)).body.cosignal).toBe("none");
    const b = await seedRotating(w);
    w.state.facilityMatches.set(FAC, { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: false });
    const jtiB = seedToken(w);
    expect(ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: b.token }, fix: fixAt(w), jti: jtiB }), w.repo, deps)).body.cosignal).toBe("none");
    expect(w.state.checkinTokens.get(jtiB)!.consumedAt).not.toBeNull(); // consumed all the same: a token is single use
    w.state.facilityMatches.set(FAC, { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true });
    const c = await seedRotating(w);
    expect(ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: c.token }, fix: fixAt(w), jti: seedToken(w, { facilityId: "fac_elsewhere" }) }), w.repo, deps)).body.cosignal).toBe("none");
    expect(evidenceRows(w)).toHaveLength(0);
  });

  it("a simulated or background fix is not a co-signal either", async () => {
    const w = await world();
    for (const over of [{ simulated: true }, { foreground: false }, { fromApp: false }, { accuracyMeters: 80 }]) {
      const t = await seedRotating(w);
      expect(ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w, -10_000, over), jti: seedToken(w) }), w.repo, deps)).body.cosignal, JSON.stringify(over)).toBe("none");
    }
    expect(evidenceRows(w)).toHaveLength(0);
  });
});

describe("the QR's signature is verified BEFORE anything is consumed; a forged one is an attack signal that commits", () => {
  it("a token signed by another key: a REFUSED outcome (422 invalid_qr), a fraud_signal, and nothing else happened", async () => {
    const w = await world();
    const stranger = await generateTestSigningKey();
    const t = await seedRotating(w, { key: stranger });
    const jti = seedToken(w);
    const out = await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti }), w.repo, deps);
    expect(refused(out)).toMatchObject({ status: 422, code: "invalid_qr" });
    expect(w.state.fraudSignals).toEqual([{ kind: "course_qr_forged", detail: { variant: "rotating", facilityId: FAC, reason: "bad_signature" } }]);
    expect(w.ms.calls).toEqual(["publicKey:rotating_token:rk1"]); // neither the PIN gate nor the scan was reached
    expect(w.state.checkinTokens.get(jti)!.consumedAt).toBeNull();
    expect(evidenceRows(w)).toHaveLength(0);
    expect(w.ms.tokens.get(t.hash)!.used).toBe(false);
  });

  it("an UNKNOWN kid, or a bad signature under a revoked kid, is a forgery (signal, committed); a GENUINE token under a revoked kid is stale, not an attack (422, no signal, nothing committed)", async () => {
    const w = await world();
    const a = await seedRotating(w, { kid: "rk-unknown" });
    expect(refused(await handleMarkerScan(body({ qr: { variant: "rotating", token: a.token } }), w.repo, deps))).toMatchObject({ code: "invalid_qr" });
    w.ms.keys.set("rotating_token:rk1", { publicKeyB64Url: w.rotKey.publicKeyB64Url, revoked: true });
    // a genuine token (signed by the revoked key itself): thrown, no signal
    const b = await seedRotating(w);
    expect(await thrown(handleMarkerScan(body({ qr: { variant: "rotating", token: b.token } }), w.repo, deps))).toMatchObject({ status: 422, code: "invalid_qr" });
    expect(w.state.fraudSignals.map((s) => s.detail.reason)).toEqual(["unknown_kid"]);
    // a token claiming the revoked kid with a signature the key does NOT make is a forgery
    const attacker = await generateTestSigningKey();
    const c = await seedRotating(w, { key: attacker });
    expect(refused(await handleMarkerScan(body({ qr: { variant: "rotating", token: c.token } }), w.repo, deps))).toMatchObject({ code: "invalid_qr" });
    expect(w.state.fraudSignals.map((s) => s.detail.reason)).toEqual(["unknown_kid", "bad_signature"]);
    expect(w.ms.tokens.get(b.hash)!.used).toBe(false);
  });

  it("the same for a revoked PRINTED-QR key: a genuine one is stale (no signal), a forged one is an attack", async () => {
    const w = await world();
    w.ms.keys.set("printed_qr:pq1", { publicKeyB64Url: w.prtKey.publicKeyB64Url, revoked: true });
    const genuine = await mintPrintedQrSig(w.prtKey, FAC, "pq1");
    expect(await thrown(handleMarkerScan(body({ qr: { variant: "static_pin", kid: "pq1", sig: genuine, pin: "4321" } }), w.repo, deps))).toMatchObject({ status: 422, code: "invalid_qr" });
    expect(w.state.fraudSignals).toHaveLength(0);
    const forged = await mintPrintedQrSig(await generateTestSigningKey(), FAC, "pq1");
    expect(refused(await handleMarkerScan(body({ qr: { variant: "static_pin", kid: "pq1", sig: forged, pin: "4321" } }), w.repo, deps))).toMatchObject({ code: "invalid_qr" });
    expect(w.state.fraudSignals).toHaveLength(1);
    expect(w.ms.calls).toEqual(["publicKey:printed_qr:pq1", "publicKey:printed_qr:pq1"]);
  });

  it("a GENUINE token minted for another facility is 422 invalid_qr but is not a forgery (no fraud signal)", async () => {
    const w = await world();
    const t = await seedRotating(w, { facilityId: "fac_other" });
    expect(await thrown(handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps))).toMatchObject({ status: 422, code: "invalid_qr" });
    expect(w.state.fraudSignals).toHaveLength(0);
  });

  it("a malformed token is 422 invalid_qr with no key lookup and no signal", async () => {
    const w = await world();
    expect(await thrown(handleMarkerScan(body({ qr: { variant: "rotating", token: "not.a.token" } }), w.repo, deps))).toMatchObject({ status: 422, code: "invalid_qr" });
    expect(w.ms.calls).toEqual([]);
    expect(w.state.fraudSignals).toHaveLength(0);
  });

  it("AT(19): a forged printed-QR signature is 422 + a fraud_signal, and the PIN gate is never reached (no PIN is spent on a forgery)", async () => {
    const w = await world();
    const stranger = await generateTestSigningKey();
    const sig = await mintPrintedQrSig(stranger, FAC, "pq1");
    const out = await handleMarkerScan(body({ qr: { variant: "static_pin", kid: "pq1", sig, pin: "4321" } }), w.repo, deps);
    expect(refused(out)).toMatchObject({ status: 422, code: "invalid_qr" });
    expect(w.state.fraudSignals).toEqual([{ kind: "course_qr_forged", detail: { variant: "static_pin", facilityId: FAC, reason: "bad_signature" } }]);
    expect(w.ms.calls).toEqual(["publicKey:printed_qr:pq1"]);
  });

  it("AT(19): the printed QR of facility X presented for facility Y is a forgery (the facility is in the signed bytes)", async () => {
    const w = await world();
    w.state.ledger.set("fac_y", { id: "fac_y", kind: "facility", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 });
    w.state.facilityTz.set("fac_y", "America/Chicago");
    const sigForX = await mintPrintedQrSig(w.prtKey, FAC, "pq1");
    const out = await handleMarkerScan({ facilityId: "fac_y", qr: { variant: "static_pin", kid: "pq1", sig: sigForX, pin: "4321" } }, w.repo, deps);
    expect(refused(out)).toMatchObject({ status: 422, code: "invalid_qr" });
    expect(w.state.fraudSignals).toHaveLength(1);
  });
});

describe("the printed QR and today's PIN (Q2)", () => {
  async function printed(w: World, pin: string, extra: Record<string, unknown> = {}) {
    const sig = await mintPrintedQrSig(w.prtKey, FAC, "pq1");
    return body({ qr: { variant: "static_pin", kid: "pq1", sig, pin }, ...extra });
  }

  it("the right PIN with a qualifying fix is 201 credited, ref'd to the facility's day (the PIN gate ran first)", async () => {
    const w = await world();
    const out = ok(await handleMarkerScan(await printed(w, "4321", { deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps));
    expect(out.body).toMatchObject({ outcome: "credited", cosignal: "counted" });
    expect(w.ms.calls).toEqual(["publicKey:printed_qr:pq1", "attemptPin", "record"]);
    expect(w.ms.purchases[0]).toMatchObject({ qrVariant: "static_pin", refId: "pin:fac_x:2026-06-01" });
  });

  it("AT(19): a WRONG PIN is a REFUSED outcome (422 invalid_pin) that commits (it must count), BEFORE the check-in token is consumed", async () => {
    const w = await world();
    const jti = seedToken(w);
    const out = await handleMarkerScan(await printed(w, "0000", { deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti }), w.repo, deps);
    expect(refused(out)).toMatchObject({ status: 422, code: "invalid_pin" });
    expect(w.ms.calls).toEqual(["publicKey:printed_qr:pq1", "attemptPin"]); // `record` was never reached
    expect(w.state.checkinTokens.get(jti)!.consumedAt).toBeNull(); // a typo does not burn the player's challenge
    expect(evidenceRows(w)).toHaveLength(0);
    expect(w.state.fraudSignals).toHaveLength(0);
  });

  it("AT(19): the SIXTH wrong PIN is a REFUSED 429 with a retry hint, whatever its PIN", async () => {
    const w = await world();
    for (let i = 0; i < 5; i++) expect(refused(await handleMarkerScan(await printed(w, "0000"), w.repo, deps)).code).toBe("invalid_pin");
    const sixth = refused(await handleMarkerScan(await printed(w, "0000"), w.repo, deps));
    expect(sixth).toMatchObject({ status: 429, code: "rate_limited", details: { retryAfterSeconds: 3600 } });
    expect(refused(await handleMarkerScan(await printed(w, "4321"), w.repo, deps)).status).toBe(429); // the CORRECT PIN too
    expect(w.ms.purchases).toHaveLength(0);
  });

  it("no programme / unknown facility / printed QR not enabled at the facility are thrown (they roll back) with their own codes", async () => {
    const w = await world({ programme: null });
    expect(await thrown(handleMarkerScan(await printed(w, "4321"), w.repo, deps))).toMatchObject({ status: 422, code: "marker_programme_inactive" });
    const w2 = await world();
    w2.ms.qrMode.set(FAC, "rotating");
    expect(await thrown(handleMarkerScan(await printed(w2, "4321"), w2.repo, deps))).toMatchObject({ status: 422, code: "marker_programme_inactive" });
    const w3 = await world();
    expect(await thrown(handleMarkerScan({ facilityId: "fac_nope", qr: { variant: "static_pin", kid: "pq1", sig: "A".repeat(86), pin: "4321" } }, w3.repo, deps))).toMatchObject({ status: 422, code: "unknown_id" });
  });

  it("a missing PIN pepper is a 503 course_pin_unavailable (fail closed), thrown", async () => {
    const w = await world();
    w.ms.pepperProvisioned = false;
    expect(await thrown(handleMarkerScan(await printed(w, "4321"), w.repo, deps))).toMatchObject({ status: 503, code: "course_pin_unavailable" });
  });

  it("a duplicate scan of the same shop on the same day is 409 duplicate_scan", async () => {
    const w = await world();
    ok(await handleMarkerScan(await printed(w, "4321"), w.repo, deps));
    expect(await thrown(handleMarkerScan(await printed(w, "4321"), w.repo, deps))).toMatchObject({ status: 409, code: "duplicate_scan" });
  });

  it("a replaced printed QR (an old kid that still verifies) is 422 qr_revoked", async () => {
    const w = await world();
    w.ms.facilityQr.set(FAC, "pq2");
    expect(await thrown(handleMarkerScan(await printed(w, "4321"), w.repo, deps))).toMatchObject({ status: 422, code: "qr_revoked" });
  });
});

describe("the player's co-signal intake (no QR)", () => {
  it("a fix + jti completes the player's own pending purchase: 200 credited, the evidence row counted once", async () => {
    const w = await world();
    const t = await seedRotating(w);
    ok(await handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps)); // pending
    const out = ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w, -20_000), jti: seedToken(w) }), w.repo, deps));
    expect(out.status).toBe(200);
    expect(out.body).toMatchObject({ outcome: "credited", localDate: null, cosignal: "counted" });
    expect(evidenceRows(w)).toHaveLength(1);
    expect(w.ms.calls.filter((c) => c === "attemptPin" || c.startsWith("publicKey"))).toEqual(["publicKey:rotating_token:rk1"]); // the intake verifies no QR and counts no PIN
  });

  it("a second fix finds nothing to complete: 422 no_pending_purchase", async () => {
    const w = await world();
    const t = await seedRotating(w);
    ok(await handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps));
    ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps));
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps))).toMatchObject({ status: 422, code: "no_pending_purchase" });
  });

  it("0063: no pending purchase but confirmOfferOffline clears an offline offer → 200 credited with empty purchases", async () => {
    const w = await world();
    w.ms.attachOverride = { status: "no_pending_purchase" };
    w.ms.confirmOverride = { status: "confirmed", cleared: 1 };
    const out = ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps));
    expect(out.status).toBe(200);
    expect(out.body).toMatchObject({ outcome: "credited", localDate: null, cosignal: "counted", purchases: [] });
    expect(w.ms.calls.filter((c) => c === "attachCosignal" || c === "confirmOfferOffline")).toEqual(["attachCosignal", "confirmOfferOffline"]);
  });

  it("a fix that is not a co-signal completes nothing: 422 not_a_cosignal", async () => {
    const w = await world();
    const t = await seedRotating(w);
    ok(await handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps));
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti: seedToken(w, { grade: "failed" }) }), w.repo, deps))).toMatchObject({ status: 422, code: "not_a_cosignal" });
  });

  it("an unattestable fix routes the pending purchase to held_review", async () => {
    const w = await world();
    const t = await seedRotating(w);
    ok(await handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps));
    expect(ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti: seedToken(w, { grade: "unattestable" }) }), w.repo, deps)).body.outcome).toBe("held_review");
  });

  it("another player's pending purchase is not reachable", async () => {
    const w = await world();
    const t = await seedRotating(w);
    ok(await handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps)); // user-a's
    const other = makeFakeRepo(w.state, "user-b");
    w.state.devices.set("22222222-2222-4222-8222-222222222222", { id: "22222222-2222-4222-8222-222222222222", userId: "user-b" });
    const jti = seedToken(w, { uid: "user-b", deviceId: "22222222-2222-4222-8222-222222222222" });
    expect(await thrown(handleMarkerScan(body({ deviceId: "22222222-2222-4222-8222-222222222222", fix: fixAt(w), jti }), other, deps))).toMatchObject({ code: "no_pending_purchase" });
  });
});

describe("request and fix validation", () => {
  it("a fix older than 7 days or dated in the future is 422 fix_out_of_window", async () => {
    const w = await world();
    const t = await seedRotating(w);
    for (const off of [-8 * 86_400_000, 6 * 60_000]) {
      expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w, off), jti: seedToken(w) }), w.repo, deps))).toMatchObject({ status: 422, code: "fix_out_of_window" });
    }
  });

  it("an unknown or retired facility id is 422 unknown_id", async () => {
    const w = await world();
    expect(await thrown(handleMarkerScan({ facilityId: "fac_nope", qr: { variant: "rotating", token: "a.b.c" } }, w.repo, deps))).toMatchObject({ status: 422, code: "unknown_id" });
    w.state.ledger.set("fac_old", { id: "fac_old", kind: "facility", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: "2026-01-01T00:00:00.000Z", mergedInto: FAC, firstCatalogVersion: 1 });
    expect(await thrown(handleMarkerScan({ facilityId: "fac_old", qr: { variant: "rotating", token: "a.b.c" } }, w.repo, deps))).toMatchObject({ status: 422, code: "unknown_id" });
    w.state.ledger.set("crs_only", { id: "crs_only", kind: "course", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 });
    expect(await thrown(handleMarkerScan({ facilityId: "crs_only", qr: { variant: "rotating", token: "a.b.c" } }, w.repo, deps))).toMatchObject({ status: 422, code: "unknown_id" });
  });

  it("a 21st device is refused BEFORE its row is created (the evidence endpoint's cap); a known device is fine", async () => {
    const w = await world();
    for (let i = 0; i < 20; i++) w.state.devices.set(`dev_cap_${i}`, { id: `dev_cap_${i}`, userId: UID });
    const t = await seedRotating(w);
    const newDevice = "33333333-3333-4333-8333-333333333333";
    expect(await thrown(handleMarkerScan(body({ deviceId: newDevice, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: "j" }), w.repo, deps))).toMatchObject({ status: 422, code: "device_limit_exceeded" });
    expect(w.state.devices.has(newDevice)).toBe(false);
  });

  it("a fix's evidence is keyed on the same `fix:<fixId>` a check-in uses, so the SAME fix cannot also be submitted as a check-in (409 there, counted once here)", async () => {
    const w = await world();
    const t = await seedRotating(w);
    const f = fixAt(w);
    ok(await handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: f, jti: seedToken(w) }), w.repo, deps));
    const found = await w.repo.evidence.findExisting("foreground_checkin", `fix:${f.fixId}`);
    expect(found).not.toBeNull();
    expect(found!.courseId).toBeNull();
  });
});

describe("request parsing (strict)", () => {
  const A86 = "A".repeat(86);
  const good = { facilityId: FAC, qr: { variant: "rotating", token: "a.b.c" } };
  const issues = (b: unknown) => {
    const r = parseMarkerScanBody(b);
    if (r.ok) throw new Error("expected issues");
    return r.issues.map((i) => i.path || "(body)");
  };

  it("accepts the three request shapes", () => {
    expect(parseMarkerScanBody(good).ok).toBe(true);
    expect(parseMarkerScanBody({ facilityId: FAC, qr: { variant: "static_pin", kid: "pq1", sig: A86, pin: "0042" } }).ok).toBe(true);
    const fix = { fixId: "abc_DEF-1", lat: 36, lng: -86, accuracyMeters: 5, capturedAt: Date.UTC(2026, 5, 1), simulated: false, foreground: true, fromApp: true };
    expect(parseMarkerScanBody({ facilityId: FAC, deviceId: FAKE_DEVICE_ID, fix, jti: "jti1" }).ok).toBe(true);
    expect(parseMarkerScanBody({ facilityId: FAC, deviceId: FAKE_DEVICE_ID, qr: good.qr, fix }).ok).toBe(true); // a scan whose fix has no jti: pending
  });

  it("refuses unknown keys at every level, a wrong type, and the impossible combinations", () => {
    expect(issues({ ...good, extra: 1 })).toContain("extra");
    expect(issues({ ...good, qr: { ...good.qr, extra: 1 } })).toContain("qr.extra");
    const fix = { fixId: "a", lat: 36, lng: -86, accuracyMeters: 5, capturedAt: Date.UTC(2026, 5, 1), simulated: false, foreground: true, fromApp: true };
    expect(issues({ facilityId: FAC, deviceId: FAKE_DEVICE_ID, fix: { ...fix, checkinTokenJti: "x" }, jti: "j" })).toContain("fix.checkinTokenJti");
    expect(issues({ facilityId: FAC })).toContain("(body)"); // neither a qr nor a fix
    expect(issues({ facilityId: FAC, fix, jti: "j" })).toContain("deviceId"); // a fix needs its device
    expect(issues({ ...good, deviceId: FAKE_DEVICE_ID })).toContain("deviceId"); // a device only with a fix
    expect(issues({ ...good, jti: "j" })).toContain("jti"); // a jti only with a fix
    expect(issues({ facilityId: FAC, deviceId: FAKE_DEVICE_ID, fix })).toContain("jti"); // a co-signal with no qr needs its token
    expect(issues({ facilityId: FAC, qr: { variant: "static_pin", kid: "pq1", sig: A86, pin: "12345" } })).toContain("qr.pin");
    expect(issues({ facilityId: FAC, qr: { variant: "static_pin", kid: "pq1", sig: A86, pin: "abcd" } })).toContain("qr.pin");
    expect(issues({ facilityId: FAC, qr: { variant: "static_pin", kid: "pq1", sig: "short", pin: "1234" } })).toContain("qr.sig");
    expect(issues({ facilityId: FAC, qr: { variant: "carrier_pigeon" } })).toContain("qr.variant");
    expect(issues({ facilityId: "bad id", qr: good.qr })).toContain("facilityId");
    expect(issues({ facilityId: FAC, qr: { variant: "rotating", token: "x".repeat(700) } })).toContain("qr.token");
    expect(issues({ facilityId: FAC, deviceId: "not-a-uuid", fix, jti: "j" })).toContain("deviceId");
    expect(issues({ facilityId: FAC, deviceId: FAKE_DEVICE_ID, fix: { ...fix, lat: 91 }, jti: "j" })).toContain("fix.lat");
    expect(issues({ facilityId: FAC, deviceId: FAKE_DEVICE_ID, fix: { ...fix, capturedAt: 5 }, jti: "j" })).toContain("fix.capturedAt");
    expect(issues({ facilityId: FAC, deviceId: FAKE_DEVICE_ID, fix: { ...fix, simulated: "no" }, jti: "j" })).toContain("fix.simulated");
    expect(issues("nope")).toEqual(["(body)"]);
    expect(issues([1])).toEqual(["(body)"]);
  });

  it("a trust fact is never accepted from the client: no grade, tier, challenge kind, local date or catalog version", () => {
    for (const k of ["attestationGrade", "verificationTier", "challenge", "localDate", "catalogVersion", "userId", "trailId", "status"]) {
      expect(issues({ ...good, [k]: "x" }), k).toContain(k);
    }
  });
});

describe("what the strings cannot carry", () => {
  it("base64url of random bytes never contains a dot (so a token's three parts cannot be re-split)", () => {
    for (let i = 0; i < 50; i++) expect(base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)))).not.toContain(".");
  });
});

describe("the scan's INSTANT is the fix's only when the fix QUALIFIES (review L1)", () => {
  async function printed(w: World, pin: string, extra: Record<string, unknown> = {}) {
    const sig = await mintPrintedQrSig(w.prtKey, FAC, "pq1");
    return body({ qr: { variant: "static_pin", kid: "pq1", sig, pin }, ...extra });
  }
  const YESTERDAY = -26 * 3_600_000;

  it("a photographed rotating token cannot be burned days later: with NO fix, or an UNQUALIFIED one dated inside its window, the instant is now and it is qr_expired", async () => {
    const w = await world();
    const t = await seedRotating(w, { iatOffsetSec: -3 * 86_400 }); // issued three days ago
    expect(await thrown(handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps))).toMatchObject({ status: 422, code: "qr_expired" });
    // a fabricated fix time inside the token's window, but simulated (no co-signal): still judged at NOW
    const fabricated = fixAt(w, -3 * 86_400_000 + 20_000, { simulated: true });
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fabricated, jti: seedToken(w, { challengeIssuedAgoMs: 4 * 86_400_000 }) }), w.repo, deps))).toMatchObject({ status: 422, code: "qr_expired" });
    expect(w.ms.tokens.get(t.hash)!.used).toBe(false);
    expect(w.ms.recordInputs.every((r) => r.at.getTime() === w.nowMs)).toBe(true);
    // ... and a fix with no check-in token at all
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w, -3 * 86_400_000 + 20_000) }), w.repo, deps))).toMatchObject({ status: 422, code: "qr_expired" });
  });

  it("the client cannot pick the printed-QR PIN DATE: a non-qualifying fix dated yesterday is judged at NOW (the PIN gate and the scan both see now)", async () => {
    const w = await world();
    for (const extra of [{}, { deviceId: FAKE_DEVICE_ID, fix: fixAt(w, YESTERDAY) }, { deviceId: FAKE_DEVICE_ID, fix: fixAt(w, YESTERDAY), jti: seedToken(w, { grade: "failed", challengeIssuedAgoMs: 3 * 86_400_000 }) }]) {
      const out = ok(await handleMarkerScan(await printed(w, "4321", extra), w.repo, deps));
      expect(out.body.cosignal).toBe("none");
      w.ms.purchases.length = 0;
    }
    expect(w.ms.attemptAts).toEqual([w.nowMs, w.nowMs, w.nowMs]);
    expect(w.ms.recordInputs.map((r) => r.at.getTime())).toEqual([w.nowMs, w.nowMs, w.nowMs]);
  });

  it("a QUALIFYING fix dated yesterday sets the instant for the PIN gate and the scan (an offline scan uploaded the next day)", async () => {
    const w = await world();
    const fix = fixAt(w, YESTERDAY);
    const out = ok(await handleMarkerScan(await printed(w, "4321", { deviceId: FAKE_DEVICE_ID, fix, jti: seedToken(w, { challengeIssuedAgoMs: 3 * 86_400_000 }) }), w.repo, deps));
    expect(out.body).toMatchObject({ outcome: "credited", cosignal: "counted" });
    expect(w.ms.attemptAts).toEqual([fix.capturedAt]);
    expect(w.ms.recordInputs.map((r) => r.at.getTime())).toEqual([fix.capturedAt]);
  });

  it("the qualification check is READ-ONLY and runs before the PIN gate: a wrong PIN consumes nothing, even for a fix that qualifies", async () => {
    const w = await world();
    const jti = seedToken(w);
    const out = await handleMarkerScan(await printed(w, "0000", { deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti }), w.repo, deps);
    expect(out.kind).toBe("refused");
    expect(w.state.checkinTokens.get(jti)!.consumedAt).toBeNull();
    expect(w.state.evidence.size).toBe(0);
    expect(w.ms.attemptAts).toEqual([w.state.now.getTime() - 10_000]); // the (qualifying) fix's time
  });

  it("a replayed fix id is the same 409 before anything else, and the intake of a fix that does not qualify is refused without touching the token", async () => {
    const w = await world();
    const t = await seedRotating(w);
    const req = body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: seedToken(w) });
    ok(await handleMarkerScan(req, w.repo, deps));
    expect(await thrown(handleMarkerScan(req, w.repo, deps))).toMatchObject({ status: 409, code: "fix_already_used" });
    const jti = seedToken(w);
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w, -10_000, { simulated: true }), jti }), w.repo, deps))).toMatchObject({ status: 422, code: "not_a_cosignal" });
    expect(w.state.checkinTokens.get(jti)!.consumedAt).toBeNull();
  });
});

describe("the database's own refusals of a co-signal and the rotating token's kid (review M2, NIT)", () => {
  it("the Edge passes the kid the signature was verified under for a rotating token, and the database's cosignal_invalid / cosignal_used are 422 invalid_cosignal / 409 fix_already_used", async () => {
    const w = await world();
    const t = await seedRotating(w);
    w.ms.recordOverride = { status: "cosignal_invalid" };
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps))).toMatchObject({ status: 422, code: "invalid_cosignal" });
    expect(w.ms.recordInputs[0]).toMatchObject({ variant: "rotating", qrKid: "rk1" });
    w.ms.recordOverride = { status: "cosignal_used" };
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps))).toMatchObject({ status: 409, code: "fix_already_used" });
    w.ms.recordOverride = null;
    // the intake maps them the same way
    const w2 = await world();
    w2.ms.attachOverride = { status: "cosignal_invalid" };
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w2), jti: seedToken(w2) }), w2.repo, deps))).toMatchObject({ status: 422, code: "invalid_cosignal" });
    w2.ms.attachOverride = { status: "cosignal_used" };
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w2), jti: seedToken(w2) }), w2.repo, deps))).toMatchObject({ status: 409, code: "fix_already_used" });
  });

  it("0051: the database's review_account refusal (record and co-signal intake) is a 403 forbidden, never a 500 and never a success", async () => {
    const w = await world();
    const t = await seedRotating(w);
    w.ms.recordOverride = { status: "review_account" };
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: seedToken(w) }), w.repo, deps))).toMatchObject({ status: 403, code: "forbidden" });
    w.ms.recordOverride = null;
    const w2 = await world();
    w2.ms.attachOverride = { status: "review_account" };
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w2), jti: seedToken(w2) }), w2.repo, deps))).toMatchObject({ status: 403, code: "forbidden" });
  });

  it("a fix that qualified at the read-only check but whose token a concurrent request consumed first is a 409 fix_not_consumable, with nothing written (the scan never goes on at the fix's time without a counted co-signal)", async () => {
    const w = await world();
    const t = await seedRotating(w);
    const repo = { ...w.repo, checkinToken: { ...w.repo.checkinToken, consumeForFix: async () => null } };
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, qr: { variant: "rotating", token: t.token }, fix: fixAt(w), jti: seedToken(w) }), repo, deps))).toMatchObject({ status: 409, code: "fix_not_consumable" });
    expect(w.ms.calls).toEqual(["publicKey:rotating_token:rk1"]);
    expect(w.state.evidence.size).toBe(0);
    // the intake the same way
    expect(await thrown(handleMarkerScan(body({ deviceId: FAKE_DEVICE_ID, fix: fixAt(w), jti: seedToken(w) }), repo, deps))).toMatchObject({ status: 409, code: "fix_not_consumable" });
  });

  it("a token presented under a kid it was not minted under is invalid_qr (the database cross-checks the row's kid)", async () => {
    const w = await world();
    const t = await seedRotating(w);
    w.ms.tokens.get(t.hash)!.kid = "rk0";
    expect(await thrown(handleMarkerScan(body({ qr: { variant: "rotating", token: t.token } }), w.repo, deps))).toMatchObject({ status: 422, code: "invalid_qr" });
  });
});
