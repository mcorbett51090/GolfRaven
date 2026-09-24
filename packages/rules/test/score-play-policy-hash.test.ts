/**
 * M5 (fifth gate): "Add a test that pins a hash of the WEIGHT table,
 * MONEY_MIN and the caps to SCORE_PLAY_POLICY_VERSION, so changing a
 * weight without bumping the version fails CI." Every constant hashed here
 * is the ACTUAL constant the scoring logic reads (`WEIGHT`,
 * `RADIUS_CAP`/`USER_PICK_CAP` inside `applyCourseCaps`,
 * `DEVICE_GPS_SUBTOTAL_CAP`/`OVERALL_SCORE_CAP` inside `combine`,
 * `CORROBORATION_ELIGIBLE_THRESHOLD`/`EVIDENCE_ROW_CAP`/`MAX_DWELL_MINUTES`
 * inside `scorePlay`/`classifyEvidenceRow`, `MONEY_MIN` itself) — not a
 * separately-maintained copy — so this test can only pass by accident if
 * someone changes a VALUE without also changing this file's own expected
 * hash, which is exactly the failure mode this test exists to catch.
 */
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import {
  CORROBORATION_ELIGIBLE_THRESHOLD,
  DEVICE_GPS_SUBTOTAL_CAP,
  EVIDENCE_ROW_CAP,
  MAX_DWELL_MINUTES,
  OVERALL_SCORE_CAP,
  RADIUS_CAP,
  USER_PICK_CAP,
  WEIGHT,
} from "../src/internal/classify.js";
import { MONEY_MIN, SCORE_PLAY_POLICY_VERSION } from "../src/score-play.js";

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
  1: "b8d71eb9873f9113bbbfd7d115e2a0416449c09320b2f7724324ea89ad537845",
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
});
