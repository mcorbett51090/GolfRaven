// supabase/functions/_shared/course-qr/scan-handler.ts
//
// Pure, DI'd core of the `marker-scan` Edge Function (`POST /v1/marker-scan`; build plan §3.3 "Course QR (O5), the reverse direction", §4.6(q), §7.6 "Offline marker purchase
// (G2-03)", §9.2). The player scans the shop's QR (a rotating token, or the printed QR and today's PIN) and the app sends the scan with a challenge-bound presence fix; or the
// app sends only the fix it captured earlier (the co-signal intake). Every database fact is decided in Postgres (migration 0046); what this module does is the part the
// database cannot: Ed25519 verification of the QR, the check-in token's consumption and the fix's grading, and the fix's evidence row.
//
// THE ORDER, and why it is the order (read with 0046's header):
//   1. validate the facility and the fix's clock window                       (nothing written)
//   1b. decide the scan's INSTANT: does the fix QUALIFY as a co-signal? (a READ-ONLY check of the check-in token, `peekForFix`, and the geometry). Only a qualifying fix's time may drive the
//       120 s rule, the PIN's date and the purchase's local date; without one the instant is NOW (a photographed token cannot be burned days later, and the client cannot pick the PIN date)
//   2. verify the QR's signature                                              (a FORGED one writes a fraud_signal and answers 422: the ONE refusal that commits, with 3)
//   3. Q2 only: the wrong-PIN gate, `private.course_pin_attempt_for_actor`     (a wrong PIN must COUNT, so its refusal commits too: it is RETURNED, never thrown)
//   4. the fix: consume the check-in token, grade it, write its `foreground_checkin` evidence row    (only if it qualifies as a co-signal)
//   5. the scan: `private.marker_scan_for_actor`, or the co-signal join       (every refusal here is THROWN: the request transaction rolls back, so the token the fix
//                                                                              consumed and the evidence row it wrote are undone and the player may retry)
// The database re-checks all of it: the printed-QR scan needs the PIN gate's proof in the same transaction, a co-signal is read back from its evidence row, and a time far from now is refused
// without one.
// A refusal that has to persist (2, 3) is therefore decided BEFORE anything is consumed, which is what makes "throw to roll back" safe for everything after.
//
// THE FIX IS COUNTED ONCE (plan §4.5, A2-20b): a qualifying fix becomes exactly one `foreground_checkin` evidence row, keyed `fix:<fixId>` like a check-in's, facility-level
// (no course: a pro shop is at the facility, and "facility-level evidence never anchors a play on its own", evidence/handler.ts). A later play at the facility on that local date
// picks it up as its presence fact through `listForPlay` (`course_id is null`), exactly like the same fix submitted by the check-in. The PURCHASE never scores as a play: this module
// never touches app.play, and the scorer's corroboration rule (a 0.30 badge boost, only beside independent play evidence) is the only thing a purchase can do to one.

import type { Repo, MarkerPurchaseView } from "../types.ts";
import { Errors, HttpError } from "../http.ts";
import { deriveFix, type DerivedFix } from "../evidence/derive-fix.ts";
import { localDateInTz } from "../evidence/handler.ts";
import { coSignalGrade, type CoSignalGrade } from "./cosignal.ts";
import { nonceHashHex, parsePrintedQr, parseRotatingToken, verifyPrintedQr, verifyRotatingToken } from "./format.ts";
import type { MarkerScanBody, MarkerScanFix } from "./request-shape.ts";
import { COSIGNAL_MAX_AGE_MS, COSIGNAL_MAX_FUTURE_MS, MAX_DEVICES_PER_USER } from "./params.ts";

export interface MarkerScanDeps {
  /** Lower-case hex SHA-256 (WebCrypto in production and in tests). */
  sha256Hex: (bytes: Uint8Array) => Promise<string>;
}

export interface MarkerScanResponse {
  /** The WORST state across the scan's purchases: `credited` only when every one is, `held_review` when a reviewer must look, else `pending` (no qualifying co-signal yet). */
  outcome: "credited" | "pending" | "held_review";
  facilityId: string;
  /** The facility-local date the purchase is on; null for a co-signal intake that completed an earlier scan. */
  localDate: string | null;
  /** Whether this request's fix was counted as a co-signal. */
  cosignal: "counted" | "none";
  purchases: { purchaseId: string; trailId: string; status: "valid" | "pending" | "held_review"; credit: { id: string | null; status: "credited" | "pending" | "held_review" | "void" } }[];
}

/** `ok`: answer with `status` and `body`. `refused`: the request transaction COMMITS (a counter or a fraud signal had to persist) and the answer is `error`. Every other refusal is thrown. */
export type MarkerScanOutcome = { kind: "ok"; status: 200 | 201; body: MarkerScanResponse } | { kind: "refused"; error: HttpError };

const FIX_ID_PREFIX = "fix:";

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) out[key] = canonicalize((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}

interface CountedCoSignal {
  grade: CoSignalGrade;
  fixId: string;
  evidenceId: string;
}

function worstOutcome(purchases: MarkerPurchaseView[]): MarkerScanResponse["outcome"] {
  if (purchases.some((p) => p.creditStatus === "held_review" || p.purchaseStatus === "held_review")) return "held_review";
  if (purchases.every((p) => p.creditStatus === "credited")) return "credited";
  return "pending";
}

function toResponse(facilityId: string, localDate: string | null, cosignal: CountedCoSignal | null, purchases: MarkerPurchaseView[]): MarkerScanResponse {
  return {
    outcome: worstOutcome(purchases),
    facilityId,
    localDate,
    cosignal: cosignal === null ? "none" : "counted",
    purchases: purchases.map((p) => ({ purchaseId: p.purchaseId, trailId: p.trailId, status: p.purchaseStatus, credit: { id: p.creditId, status: p.creditStatus } })),
  };
}

/** The refusals the database returns as a status (never raises), as the HTTP error each is. */
function mapRecordRefusal(status: string): HttpError {
  switch (status) {
    case "qr_unknown":
    case "qr_wrong_facility":
      // one answer for "no such QR" and "a QR for another facility": no oracle on which facilities have tokens
      return Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility");
    case "qr_used":
      return Errors.conflict("qr_used", "this QR code has already been scanned");
    case "qr_expired":
      return Errors.unprocessable("qr_expired", "this QR code had expired when your location was captured");
    case "qr_revoked":
      return Errors.unprocessable("qr_revoked", "this printed QR code has been replaced; use the current one");
    case "pin_wrong":
      return Errors.unprocessable("invalid_pin", "that PIN is not today's PIN for this facility");
    case "duplicate":
      return Errors.conflict("duplicate_scan", "you already recorded a purchase at this facility today");
    case "cosignal_invalid":
      // the database read the co-signal's evidence row back and it does not describe this fix here: an Edge bug or a forged call, never a state the player can fix by retrying
      return Errors.unprocessable("invalid_cosignal", "the location fix does not match its record");
    case "cosignal_used":
      return Errors.conflict("fix_already_used", "this location fix has already been recorded");
    case "no_programme":
      return Errors.unprocessable("marker_programme_inactive", "this facility is not running a marker programme right now");
    case "variant_disabled":
      return Errors.unprocessable("qr_variant_not_enabled", "this facility does not use that kind of QR code");
    case "no_facility":
      return Errors.unprocessable("unknown_id", "no such facility");
    case "review_account":
      // 0051: the app-review account earns no marker credit (plan line 1871). The same 403 the reward activation answers it with.
      return Errors.forbidden("this account cannot record marker purchases");
    default:
      // a status this code does not know is a deploy skew, not a client error
      throw new Error(`marker_scan_for_actor returned an unexpected status "${status}"`);
  }
}

/** Resolves the request's own device row (the check-in token is bound to the device that redeemed it). Same discipline as evidence intake: a request that would exceed the
 * per-account device cap is refused BEFORE the row it would create is written. */
async function resolveDevice(repo: Repo, deviceId: string): Promise<{ id: string }> {
  const known = await repo.device.findOwn(deviceId);
  if (known) return known;
  if ((await repo.device.countForUser()) >= MAX_DEVICES_PER_USER) {
    throw Errors.unprocessable("device_limit_exceeded", `this account already has ${MAX_DEVICES_PER_USER} devices on record`);
  }
  return repo.device.ensureOwn(deviceId, null);
}

/** The derived fix and its co-signal grade for a (possibly absent) consumed token. Pure but for the geometry read (`matchFacilityFix`, a SELECT). */
async function gradeFix(repo: Repo, body: MarkerScanBody, facilityId: string, tz: string, consumed: { facilityId: string | null; attestationGrade: "attested" | "unattestable" | "failed"; challengeKind: "live" | "prefetched" } | null): Promise<{ derived: DerivedFix; grade: CoSignalGrade | null; localDate: string }> {
  const fix = body.fix!;
  // A token bound to ANOTHER facility is not this facility's presence proof (a challenge may be facility-less: then it binds none). It is consumed either way.
  const token = consumed !== null && consumed.facilityId !== null && consumed.facilityId !== facilityId ? null : consumed;
  const match = await repo.catalog.matchFacilityFix(facilityId, fix.lat, fix.lng);
  const localDate = localDateInTz(fix.capturedAt, tz);
  const derived: DerivedFix = deriveFix({
    fix: { fixId: fix.fixId, accuracyMeters: fix.accuracyMeters, capturedAt: fix.capturedAt, simulated: fix.simulated, foreground: fix.foreground, fromApp: fix.fromApp },
    resolvedFacilityId: facilityId,
    localDate,
    match,
    consumedToken: token === null ? null : { attestationGrade: token.attestationGrade, challengeKind: token.challengeKind },
  });
  return { derived, grade: coSignalGrade(derived, facilityId), localDate };
}

/** Step 1b. Would this request's fix qualify as a co-signal? READ-ONLY: nothing is consumed or written, so it can run before the PIN gate commits. A replayed fix id is the same 409 as in
 * `countCoSignal`. `false` when there is no fix, no known device, no token the fix may consume, or a fix that does not qualify. */
async function fixQualifies(repo: Repo, body: MarkerScanBody, facilityId: string, tz: string): Promise<boolean> {
  const fix = body.fix;
  if (fix === undefined) return false;
  if (await repo.evidence.findExisting("foreground_checkin", `${FIX_ID_PREFIX}${fix.fixId}`)) throw Errors.conflict("fix_already_used", "this location fix has already been recorded");
  const device = await repo.device.findOwn(body.deviceId!);
  if (!device) return false; // a device this account has never used holds no token
  const peeked = body.jti ? await repo.checkinToken.peekForFix(body.jti, device.id, fix.capturedAt) : null;
  return (await gradeFix(repo, body, facilityId, tz, peeked)).grade !== null;
}

/** Step 4. `null` when the request carries no fix or the fix does not qualify as a co-signal (including a `failed` grade). */
async function countCoSignal(repo: Repo, deps: MarkerScanDeps, body: MarkerScanBody, facilityId: string, tz: string): Promise<CountedCoSignal | null> {
  const fix = body.fix;
  if (fix === undefined) return null;
  // A fix is counted ONCE: if this fix id already has its row the request is a replay (409, which the outbox treats as accepted), and nothing below runs, so a retry never
  // re-consumes a token or re-writes a row.
  const sourceRef = `${FIX_ID_PREFIX}${fix.fixId}`;
  if (await repo.evidence.findExisting("foreground_checkin", sourceRef)) throw Errors.conflict("fix_already_used", "this location fix has already been recorded");

  const device = await resolveDevice(repo, body.deviceId!);
  const consumed = body.jti ? await repo.checkinToken.consumeForFix(body.jti, device.id, fix.capturedAt) : null;
  const { derived, grade, localDate } = await gradeFix(repo, body, facilityId, tz, consumed);
  if (grade === null) return null;

  const currentVersion = await repo.catalog.currentVersion();
  const inputHash = await deps.sha256Hex(new TextEncoder().encode(JSON.stringify(canonicalize({ v: 1, kind: "marker-scan", facilityId, fix: derived }))));
  const inserted = await repo.evidence.insertIdempotent({
    kind: "resolved",
    sourceRef,
    inputHash,
    source: "foreground_checkin",
    facilityId,
    courseId: null,
    startedAt: null,
    endedAt: null,
    localDate,
    summary: { localDate, fix: derived },
    integrity: {},
    cosignal: {},
    attestationGrade: grade,
    matcherVersion: null,
    catalogVersion: currentVersion?.version ?? null,
    status: "accepted",
    deviceId: device.id,
  });
  // lost a race with an identical request: that one counted the fix
  if (!inserted.wasNew) throw Errors.conflict("fix_already_used", "this location fix has already been recorded");
  return { grade, fixId: fix.fixId, evidenceId: inserted.id };
}

function requireFixWindow(fix: MarkerScanFix, now: Date): void {
  if (fix.capturedAt < now.getTime() - COSIGNAL_MAX_AGE_MS || fix.capturedAt > now.getTime() + COSIGNAL_MAX_FUTURE_MS) {
    throw Errors.unprocessable("fix_out_of_window", "the location fix is older than 7 days or dated in the future");
  }
}

export async function handleMarkerScan(body: MarkerScanBody, repo: Repo, deps: MarkerScanDeps): Promise<MarkerScanOutcome> {
  const now = repo.now();

  // 1. The facility and the fix's clock window. A retired (merged) id is refused: a QR is printed for one id.
  const ledger = await repo.catalog.resolveLedgerId(body.facilityId);
  if (!ledger || ledger.kind !== "facility" || ledger.id !== body.facilityId) throw Errors.unprocessable("unknown_id", `facilityId "${body.facilityId.slice(0, 64)}" is not a known catalog facility id`);
  const facilityId = ledger.id;
  const tz = await repo.catalog.facilityTz(facilityId);
  if (!tz) throw Errors.unprocessable("unknown_id", `facilityId "${facilityId.slice(0, 64)}" has a ledger entry but no catalog_facility row`);
  if (body.fix) requireFixWindow(body.fix, now);
  // 1b. The instant the 120 s rule, the PIN's date and the purchase's local date are judged at: the FIX's time (an offline scan is uploaded days later) ONLY when that fix qualifies as a co-signal,
  // else now. An unqualified fix is a client-chosen number: it must not pick the PIN date or let a photographed token be burned days later. The database refuses the same combination.
  const qualifies = await fixQualifies(repo, body, facilityId, tz);
  const at = qualifies ? new Date(body.fix!.capturedAt) : now;

  // THE CO-SIGNAL INTAKE (no QR): only the fix, tied to the player's own pending purchase.
  if (body.qr === undefined) {
    // a fix that is not a co-signal completes nothing: refuse (nothing was consumed: this is decided read-only, so the check-in token stays usable)
    if (!qualifies) throw Errors.unprocessable("not_a_cosignal", "this location fix does not qualify as a presence co-signal");
    const counted = await countCoSignal(repo, deps, body, facilityId, tz);
    if (counted === null) throw Errors.conflict("fix_not_consumable", "this location fix could not be counted; capture a new one");
    const cosignal = { grade: counted.grade, fixId: counted.fixId, evidenceId: counted.evidenceId };
    const attached = await repo.markerScan.attachCosignal({ facilityId, at, cosignal });
    if (attached.status === "no_pending_purchase") {
      // 0063: the same fix may clear an awaiting offline offer redeem (no pending marker purchase).
      const confirmed = await repo.markerScan.confirmOfferOffline({ facilityId, at, cosignal });
      if (confirmed.status === "confirmed") return { kind: "ok", status: 200, body: toResponse(facilityId, null, counted, []) };
      throw Errors.unprocessable("no_pending_purchase", "no pending marker purchase at this facility is waiting for this location fix");
    }
    if (attached.status !== "attached") throw mapRecordRefusal(attached.status);
    return { kind: "ok", status: 200, body: toResponse(facilityId, null, counted, attached.purchases) };
  }

  // 2. Verify the QR's signature BEFORE anything is consumed. A forged one is an attack signal: it writes a fraud_signal and COMMITS.
  let nonceHash: string | null = null;
  let qrKid: string | null = null;
  let pin: string | null = null;
  if (body.qr.variant === "rotating") {
    const parsed = parseRotatingToken(body.qr.token);
    if (parsed === null) throw Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility");
    const key = await repo.markerScan.publicKey(parsed.claims.kid, "rotating_token");
    const genuine = key !== null && (await verifyRotatingToken(parsed, key.publicKeyB64Url));
    if (!genuine) {
      await repo.fraudSignal.insert("course_qr_forged", { variant: "rotating", facilityId, reason: key === null ? "unknown_kid" : "bad_signature" });
      return { kind: "refused", error: Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility") };
    }
    // a GENUINE token under a kid that has since been revoked is a stale token, not an attack: the same answer, no fraud signal (and nothing committed)
    if (key.revoked) throw Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility");
    qrKid = parsed.claims.kid;
    // a genuine token minted for ANOTHER facility is a mismatch, not a forgery
    if (parsed.claims.fac !== facilityId) throw Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility");
    nonceHash = await nonceHashHex(parsed.claims.nonce, deps.sha256Hex);
  } else {
    const parsed = parsePrintedQr(body.qr.kid, body.qr.sig);
    if (parsed === null) throw Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility");
    const key = await repo.markerScan.publicKey(parsed.kid, "printed_qr");
    const genuine = key !== null && (await verifyPrintedQr(parsed, facilityId, key.publicKeyB64Url));
    if (!genuine) {
      // "a forged printed-QR signature gives 422 plus a fraud_signal" (AT(19)); the facility id is bound into the signed bytes, so the QR of X presented for Y lands here too
      await repo.fraudSignal.insert("course_qr_forged", { variant: "static_pin", facilityId, reason: key === null ? "unknown_kid" : "bad_signature" });
      return { kind: "refused", error: Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility") };
    }
    // a genuine printed QR whose key was revoked (a reprint after a suspected compromise) is a stale QR, not an attack: no fraud signal
    if (key.revoked) throw Errors.unprocessable("invalid_qr", "this QR code is not valid for this facility");
    qrKid = parsed.kid;
    pin = body.qr.pin;

    // 3. The wrong-PIN gate. A wrong PIN must COUNT (5 per user per facility per facility-local date, 30 per facility), so its refusal is RETURNED and the transaction commits.
    const attempt = await repo.markerScan.attemptPin({ facilityId, pin, at });
    switch (attempt.result) {
      case "ok":
        break;
      case "wrong":
        return { kind: "refused", error: Errors.unprocessable("invalid_pin", "that PIN is not today's PIN for this facility") };
      case "locked":
        return { kind: "refused", error: Errors.tooManyRequests("too many wrong PINs at this facility today; try again tomorrow", attempt.retryAfterSeconds ?? undefined) };
      case "no_programme":
        throw Errors.unprocessable("marker_programme_inactive", "this facility is not running a marker programme right now");
      case "no_facility":
        throw Errors.unprocessable("unknown_id", "no such facility");
    }
  }

  // 4. The fix (if any): the check-in token, the grade, the evidence row.
  const counted = await countCoSignal(repo, deps, body, facilityId, tz);
  // the instant above assumed the fix would count: if it did not (a concurrent request consumed the token between the read-only check and now) the scan must not go on at the fix's time
  if (qualifies && counted === null) throw Errors.conflict("fix_not_consumable", "this location fix could not be counted; capture a new one");

  // 5. The scan itself.
  const recorded = await repo.markerScan.record({
    facilityId,
    variant: body.qr.variant,
    nonceHash,
    qrKid,
    pin,
    at,
    cosignal: counted === null ? null : { grade: counted.grade, fixId: counted.fixId, evidenceId: counted.evidenceId },
  });
  if (recorded.status !== "accepted") throw mapRecordRefusal(recorded.status);
  return { kind: "ok", status: 201, body: toResponse(facilityId, recorded.localDate, counted, recorded.purchases) };
}
