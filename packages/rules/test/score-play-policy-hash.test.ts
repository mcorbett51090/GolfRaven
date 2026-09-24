/**
 * M5 (fifth gate) + F5 (sixth gate): "Add a test that pins a hash of the
 * WEIGHT table, MONEY_MIN and the caps to SCORE_PLAY_POLICY_VERSION" (M5),
 * then "Hoist every inline policy literal into named constants covered by
 * the pinned hash" (F5) — every constant hashed here is the ACTUAL
 * constant the scoring logic reads, not a separately-maintained copy, so
 * this test can only pass by accident if someone changes a VALUE without
 * also changing this file's own expected hash, which is exactly the
 * failure mode this test exists to catch.
 */
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import {
  ACCURACY_METERS_MAX,
  CONNECT_IQ_ROUTE_MIN_DURATION_MINUTES,
  CORROBORATION_ELIGIBLE_THRESHOLD,
  DEVICE_GPS_SUBTOTAL_CAP,
  DWELL_THRESHOLD_9_HOLES_MINUTES,
  DWELL_THRESHOLD_18_HOLES_MINUTES,
  EVIDENCE_ROW_CAP,
  FILE_IMPORT_MATCHED_WEIGHT,
  FILE_IMPORT_UNMATCHED_WEIGHT,
  HEALTH_ROUTE_HIGH_INSIDE_RATIO,
  HEALTH_ROUTE_HIGH_WEIGHT,
  HEALTH_ROUTE_LOW_WEIGHT,
  HEALTH_ROUTE_MID_WEIGHT,
  HEALTH_ROUTE_MIN_INSIDE_RATIO,
  MAX_DWELL_MINUTES,
  OVERALL_SCORE_CAP,
  RADIUS_CAP,
  RECEIPT_PENDING_WEIGHT,
  SIMULATED_PENALTY_MULTIPLIER,
  STAFF_HARD_WINDOW_MS,
  UNATTESTABLE_OR_NO_CHALLENGE_PENALTY_MULTIPLIER,
  USER_PICK_CAP,
  WEIGHT,
} from "../src/internal/classify.js";
import { CORROBORATION_WINDOW_DAYS, MONEY_MIN, ROUND_CORRELATION_WINDOW_MS, SCORE_PLAY_POLICY_VERSION } from "../src/score-play.js";

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

function policyConstants() {
  return {
    WEIGHT,
    MONEY_MIN,
    RADIUS_CAP,
    USER_PICK_CAP,
    DEVICE_GPS_SUBTOTAL_CAP,
    OVERALL_SCORE_CAP,
    CORROBORATION_ELIGIBLE_THRESHOLD,
    EVIDENCE_ROW_CAP,
    MAX_DWELL_MINUTES,
    // F5 (sixth gate) additions:
    ACCURACY_METERS_MAX,
    STAFF_HARD_WINDOW_MS,
    SIMULATED_PENALTY_MULTIPLIER,
    UNATTESTABLE_OR_NO_CHALLENGE_PENALTY_MULTIPLIER,
    RECEIPT_PENDING_WEIGHT,
    HEALTH_ROUTE_MIN_INSIDE_RATIO,
    HEALTH_ROUTE_HIGH_INSIDE_RATIO,
    HEALTH_ROUTE_LOW_WEIGHT,
    HEALTH_ROUTE_MID_WEIGHT,
    HEALTH_ROUTE_HIGH_WEIGHT,
    CONNECT_IQ_ROUTE_MIN_DURATION_MINUTES,
    DWELL_THRESHOLD_9_HOLES_MINUTES,
    DWELL_THRESHOLD_18_HOLES_MINUTES,
    FILE_IMPORT_MATCHED_WEIGHT,
    FILE_IMPORT_UNMATCHED_WEIGHT,
    ROUND_CORRELATION_WINDOW_MS,
    CORROBORATION_WINDOW_DAYS,
  };
}

function hashPolicyConstants(): string {
  return bytesToHex(sha256(utf8ToBytes(JSON.stringify(canonicalize(policyConstants())))));
}

/** The pin: one HARDCODED hash per `SCORE_PLAY_POLICY_VERSION` — a
 * LITERAL string, deliberately NOT computed by calling
 * `hashPolicyConstants()` here (that would make this test compare the
 * live constants to themselves, passing unconditionally no matter what
 * they are — exactly the vacuous-test failure mode this file's own doc
 * warns about). Changing ANY value `policyConstants()` reads — a weight,
 * `MONEY_MIN`, a cap — without ALSO updating this literal (and bumping
 * `SCORE_PLAY_POLICY_VERSION` to a NEW key) fails this test. Computed
 * once, at the time this test was written (fifth gate), via
 * `hashPolicyConstants()` against the real constants — re-derive it the
 * same way for a deliberate, version-bumped change. */
const POLICY_HASHES: Record<number, string> = {
  // Re-pinned twice now:
  //   - sixth gate (F5): widened coverage from WEIGHT/MONEY_MIN/5 caps to
  //     every F5-hoisted literal — a pure refactor (same values, more
  //     coverage), so re-pinned under the SAME version key (1).
  //   - seventh gate (item 9): EVIDENCE_ROW_CAP's VALUE itself changed
  //     (200 -> 1000, "apply the 1000-row absolute cap only to rows that
  //     pass the loose on-play filter") — a genuine policy change, still
  //     re-pinned under version 1 per this gate's own instruction ("Re-pin
  //     the hash"), not a version bump; SCORE_PLAY_POLICY_VERSION stays 1.
  1: "8c0b06afb39be8dc340991b73fcf86b2ba39c1feb1797995ab725cb476ceaa93",
};

describe("M5: the scoring policy's constants are content-hash-pinned to SCORE_PLAY_POLICY_VERSION", () => {
  it("SCORE_PLAY_POLICY_VERSION has a pinned hash", () => {
    expect(POLICY_HASHES[SCORE_PLAY_POLICY_VERSION]).toBeDefined();
  });

  it("the CURRENT policy constants hash to the pinned value for the CURRENT version", () => {
    expect(hashPolicyConstants()).toBe(POLICY_HASHES[SCORE_PLAY_POLICY_VERSION]);
  });

  it("mutation guard: changing a WEIGHT entry changes the hash (proves this test isn't vacuous)", () => {
    const mutated = { ...policyConstants(), WEIGHT: { ...WEIGHT, staff_presence_hard: 0.5 } };
    const mutatedHash = bytesToHex(sha256(utf8ToBytes(JSON.stringify(canonicalize(mutated)))));
    expect(mutatedHash).not.toBe(hashPolicyConstants());
  });

  it("mutation guard: changing MONEY_MIN changes the hash", () => {
    const mutated = { ...policyConstants(), MONEY_MIN: 0.5 };
    const mutatedHash = bytesToHex(sha256(utf8ToBytes(JSON.stringify(canonicalize(mutated)))));
    expect(mutatedHash).not.toBe(hashPolicyConstants());
  });

  it("mutation guard: changing a NEWLY-HOISTED F5 constant (STAFF_HARD_WINDOW_MS) changes the hash too", () => {
    const mutated = { ...policyConstants(), STAFF_HARD_WINDOW_MS: 999 };
    const mutatedHash = bytesToHex(sha256(utf8ToBytes(JSON.stringify(canonicalize(mutated)))));
    expect(mutatedHash).not.toBe(hashPolicyConstants());
  });
});
