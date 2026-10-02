// supabase/functions/_shared/rewards/play-integrity.ts
//
// Play Integrity VERDICT evaluation (build plan §7.5): "Play Integrity standard
// requests with `requestHash = SHA-256(canonical_body ‖ challenge)`. The server
// decodes the token and checks `requestHash`, the package name, the
// certificate digest and `deviceIntegrity`."
//
// PURE: it evaluates an already-decoded verdict payload against expectations
// the caller supplies. Obtaining that payload (Google's `decodeIntegrityToken`,
// which needs a service-account credential and the network) is the production
// adapter's job (play-integrity-client.ts), behind `IntegrityDecoder`.
//
// ⚠ `[unverified — training knowledge of the Play Integrity verdict JSON]`. The
// field names below (`requestDetails.requestHash`, `requestDetails.
// requestPackageName`, `requestDetails.timestampMillis`, `appIntegrity.
// appRecognitionVerdict`, `appIntegrity.certificateSha256Digest`,
// `deviceIntegrity.deviceRecognitionVerdict`) are what this code expects; they
// are exercised only against payloads this repo's tests construct. Device
// recall (spike A20) is deliberately NOT read here: Android's two persistent
// bits are a server-side substitute (rewards activation, `androidInstallSignals`).
// Every check fails CLOSED: a missing or oddly
// typed field is a `failed` verdict with a reason, never a pass.

import { stringsEqualConstantTime } from "./binding.ts";

export interface IntegrityExpectations {
  packageName: string;
  /** base64url (unpadded) SHA-256 digests of the allowed signing certificates,
   * exactly as Play reports them in `appIntegrity.certificateSha256Digest`. */
  certificateSha256Digests: string[];
  /** base64url(SHA-256(canonical_body ‖ challenge)), no padding. */
  expectedRequestHash: string;
  nowMs: number;
  /** A verdict older than this (or in the future by more than the skew) is not
   * a verdict for THIS request. */
  maxAgeMs: number;
  maxFutureSkewMs: number;
}

export type IntegrityEvaluation = { grade: "attested" } | { grade: "failed"; reasons: string[] };

function obj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

export function evaluateIntegrityPayload(payload: unknown, exp: IntegrityExpectations): IntegrityEvaluation {
  const reasons: string[] = [];
  const root = obj(payload);
  if (!root) return { grade: "failed", reasons: ["payload_not_an_object"] };

  const request = obj(root.requestDetails);
  const app = obj(root.appIntegrity);
  const device = obj(root.deviceIntegrity);

  if (!request) {
    reasons.push("missing_requestDetails");
  } else {
    const hash = request.requestHash;
    if (typeof hash !== "string" || !stringsEqualConstantTime(hash, exp.expectedRequestHash)) reasons.push("request_hash_mismatch");
    if (typeof request.requestPackageName !== "string" || request.requestPackageName !== exp.packageName) reasons.push("package_name_mismatch");
    const ts = typeof request.timestampMillis === "string" ? Number(request.timestampMillis) : request.timestampMillis;
    if (typeof ts !== "number" || !Number.isFinite(ts)) {
      reasons.push("missing_timestamp");
    } else if (exp.nowMs - ts > exp.maxAgeMs || ts - exp.nowMs > exp.maxFutureSkewMs) {
      reasons.push("verdict_not_fresh");
    }
  }

  if (!app) {
    reasons.push("missing_appIntegrity");
  } else {
    if (app.appRecognitionVerdict !== "PLAY_RECOGNIZED") reasons.push("app_not_play_recognized");
    const digests = app.certificateSha256Digest;
    if (!Array.isArray(digests) || digests.length === 0 || !digests.every((d) => typeof d === "string")) {
      reasons.push("missing_certificate_digest");
    } else if (!digests.some((d) => exp.certificateSha256Digests.some((allowed) => stringsEqualConstantTime(d as string, allowed)))) {
      reasons.push("certificate_digest_not_allowed");
    }
    if (typeof app.packageName === "string" && app.packageName !== exp.packageName) reasons.push("app_package_name_mismatch");
  }

  if (!device) {
    reasons.push("missing_deviceIntegrity");
  } else {
    const verdicts = device.deviceRecognitionVerdict;
    if (!Array.isArray(verdicts) || !verdicts.includes("MEETS_DEVICE_INTEGRITY")) reasons.push("device_integrity_not_met");
  }

  return reasons.length === 0 ? { grade: "attested" } : { grade: "failed", reasons };
}
