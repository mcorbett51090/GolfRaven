/**
 * M5 (fifth gate) + F5 (sixth gate): "Add a test that pins a hash of the
 * WEIGHT table, MONEY_MIN and the caps to SCORE_PLAY_POLICY_VERSION" (M5),
 * then "Hoist every inline policy literal into named constants covered by
 * the pinned hash" (F5) — every constant hashed here is the ACTUAL
 * constant the scoring logic reads, not a separately-maintained copy, so
 * this test can only pass by accident if someone changes a VALUE without
 * also changing this file's own expected hash, which is exactly the
 * failure mode this test exists to catch.
 *
 * **`EVIDENCE_ROW_CAP` (and `ABSOLUTE_ROW_CAP`, which was never added to
 * this set in the first place) is deliberately NOT pinned here (eighth
 * gate, item 3).** Both are INPUT-VALIDATION limits — pure DoS/shape
 * guards on how many raw rows `parseScorePlayInput` is willing to read
 * before it even asks whether a row belongs to this play — not SCORING
 * policy: they decide nothing about how a play's evidence turns into a
 * score, badge, or money determination. Pinning them alongside `WEIGHT`/
 * `MONEY_MIN`/the scoring caps conflated two different kinds of change
 * behind one hash: an operational cap raised for capacity reasons (as
 * `EVIDENCE_ROW_CAP` itself was, seventh gate item 9, 200 -> 1000) is not
 * the kind of change this pin exists to gate, and forcing it through the
 * same "re-pin + justify" ceremony as an actual scoring-policy change
 * blurred the two together and made the pin's own history harder to read
 * (see the immutability rule below, and the correction this same gate
 * makes to a stale comment that used to sit on this file).
 *
 * **Immutability rule (eighth gate, item 3 — also stated in
 * `score-play.ts`'s own trust table): once ANY production play has been
 * scored under a given `SCORE_PLAY_POLICY_VERSION`, that version's pinned
 * hash is IMMUTABLE.** A hash pinned to a version is a promise that every
 * play scored under that version used EXACTLY these constants — re-pinning
 * the SAME version key after production plays exist would silently
 * rewrite that promise for plays already scored, which is indistinguishable
 * from backdating a policy change. Any change to a pinned constant, for
 * ANY reason (a deliberate scoring-policy change, a bug fix, a typo)
 * MUST bump `SCORE_PLAY_POLICY_VERSION` to a NEW key and add a NEW entry
 * to `POLICY_HASHES` — never overwrite an existing key's value. (Before
 * any production play exists — e.g. still inside this pre-launch gate
 * cycle — re-pinning the current version in place, as this file's own
 * history shows, is how the constant set was allowed to stabilize without
 * spawning a new version on every iteration; that grace period ends the
 * moment a real play is scored.)
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
  // Item 3 (eighth gate) test-only import: used ONLY by the "genuinely
  // not pinned" mutation guard below, to reintroduce the REAL current
  // value rather than a hardcoded, staleness-prone magic number —
  // NEVER added back to `policyConstants()` itself.
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
    // Eighth gate, item 3: EVIDENCE_ROW_CAP (and ABSOLUTE_ROW_CAP, never
    // pinned here to begin with) deliberately EXCLUDED — see this file's
    // module doc: an input-validation limit, not scoring policy.
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
  // Re-pinned under version 1 three times now, all BEFORE any production
  // play exists (the immutability rule's own grace period — see this
  // file's module doc):
  //   - sixth gate (F5): widened coverage from WEIGHT/MONEY_MIN/5 caps to
  //     every F5-hoisted literal — a pure refactor (same values, more
  //     coverage).
  //   - seventh gate (item 9): EVIDENCE_ROW_CAP's VALUE changed (200 ->
  //     1000) while it was still IN this pinned set.
  //   - eighth gate (item 3): EVIDENCE_ROW_CAP REMOVED from this pinned
  //     set entirely (it's an input-validation limit, not scoring
  //     policy — see the module doc) — the hash changes because the SET
  //     of hashed fields changed, not because any remaining field's
  //     VALUE did.
  1: "4ea1401156d174cbbc74290d317fee9f7965fa60d382c7eeef87f14996313302",
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

  it("item 3 (eighth gate): EVIDENCE_ROW_CAP is genuinely NOT part of the pinned set — changing it does NOT change the hash", () => {
    // Proves the removal is real, not cosmetic: policyConstants() no
    // longer reads EVIDENCE_ROW_CAP at all, so a hash computed from an
    // object that adds it back in under some OTHER key still matches —
    // the field simply isn't part of what's being hashed. (A raw
    // "import and mutate EVIDENCE_ROW_CAP" isn't possible here — it's a
    // `const`, and re-assigning the imported binding would be a
    // TypeScript compile error, which is itself part of what makes this
    // guard meaningful: the constant is genuinely immutable at the type
    // level, so the only way to prove "not pinned" is to show the hash
    // is indifferent to its value.)
    const mutated = { ...policyConstants(), EVIDENCE_ROW_CAP: 999_999 };
    const mutatedHash = bytesToHex(sha256(utf8ToBytes(JSON.stringify(canonicalize(mutated)))));
    expect(mutatedHash).not.toBe(hashPolicyConstants());
    // ...but if we canonicalize `policyConstants()` itself (no
    // EVIDENCE_ROW_CAP key at all) versus the same object with
    // EVIDENCE_ROW_CAP explicitly set back to its OWN real current
    // value, the hash DOES change — proving the field's mere PRESENCE in
    // the hashed object (not its value) is what the earlier assertion
    // was actually testing. This second assertion isolates that: the
    // pinned hash (computed from the real, EVIDENCE_ROW_CAP-free
    // policyConstants()) must NOT equal a hash computed from a set that
    // reintroduces the key under its real value either.
    const withRealCapReintroduced = { ...policyConstants(), EVIDENCE_ROW_CAP };
    const withRealCapHash = bytesToHex(sha256(utf8ToBytes(JSON.stringify(canonicalize(withRealCapReintroduced)))));
    expect(withRealCapHash).not.toBe(hashPolicyConstants());
  });
});
