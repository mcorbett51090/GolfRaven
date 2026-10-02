// supabase/functions/_shared/rewards/decision-table.ts
//
// The §7.5 activation decision table — PURE. No I/O, no clock, no vendor: every
// input is a fact the caller (`activate-handler.ts`) has already established,
// so the whole table is unit-testable row by row and against an independent
// oracle (supabase/tests/unit/decision-table.test.ts).
//
// Build plan §7.5, verbatim. "Rows are checked in order and the first match
// wins. They are ordered most restrictive first (G3-08)":
//
//   # | bit0 | bit1  | activating account / reward                         | outcome
//   1 | any  | set   | any                                                 | held_review + high-priority fraud_signal
//   2 | any  | any   | account has an open fraud_signal(attestation_failed)| held_review
//   3 | any  | any   | reward rests on an unattestable co-signal           | held_review (C5 item 3)
//   4 | set  | clear | has no prior reward                                 | held_review + fraud_signal(multi_account_device)
//   5 | set  | clear | has a prior reward (ledger or own record)           | activate (a repeat user)
//   6 | clear| clear | any                                                 | activate (offer -> issued, entitlement -> redeemable); set bit0
//
// "A reward that rests on an `unattestable` co-signal, activated on a clean
// device, matches rows 3 and 6 and is therefore held" — the precedence is the
// order of the checks below, nothing else.
//
// THREE inputs the plan's table does not name, each of which can only ever make
// the outcome MORE restrictive, never less:
//   - `activatingGrade === "failed"` joins row 2. A failed verdict opens
//     `fraud_signal(attestation_failed)` (§4.5), and "while the signal is open
//     the account's activations are held". The handler raises the signal before
//     asking the DB, so `accountHasOpenAttestationFailed` is normally already
//     true; carrying the grade as well keeps this function correct on its own.
//   - `activatingGrade === "unattestable"` joins row 3. §7.5 "Role": "an
//     `unattestable` device's reward goes to `held_review`".
//   - `bits.kind === "none"` (a platform with no persistent-bit source at all —
//     Play Integrity device recall unavailable, spike A20) is the "7th row":
//     held_review, never activate, never refuse. The plan accepts this weaker
//     Android persistence precisely "because the table routes to review rather
//     than refusing". Rows 4-6 need a bit reading and cannot be answered
//     without one.
// Anything that is not a clear, verified "activate" is a hold. There is no
// outcome called "refused": §7.5 "never silently refused".
//
// FIRST MATCH DECIDES THE OUTCOME; EVERY MATCH RAISES ITS SIGNALS (M2). The
// plan's "first match wins" is about which outcome applies — it never said a
// lower row's fraud signal should be dropped because a higher row also held.
// Row 4's `multi_account_device` is the reviewer's evidence that a second
// account is on this hardware; losing it because the reward ALSO rests on an
// unattestable co-signal (rows 3 and 4 both match) would hand the reviewer a
// hold with the evidence stripped. So `decideActivation` evaluates every row
// independently, reports them all in `matchedRows`, takes `outcome`/`row` from
// the first, and returns the UNION of the matched rows' signals.

import type { Grade } from "./types.ts";

export type BitsInput = { kind: "known"; bit0: boolean; bit1: boolean } | { kind: "none" };

export interface ActivationFacts {
  bits: BitsInput;
  /** The activating device's own attestation grade (§4.5). */
  activatingGrade: Grade;
  /** Row 2: the account has an open `fraud_signal(attestation_failed)`. */
  accountHasOpenAttestationFailed: boolean;
  /** Row 3: the reward rests on an unattestable co-signal. */
  rewardRestsOnUnattestable: boolean;
  /** Row 5: the account has another reward on record (ledger or own record). */
  accountHasPriorReward: boolean;
}

export type DecisionRow = 1 | 2 | 3 | 4 | 5 | 6 | "no_persistent_signal";
export type FraudSignalKind = "flagged_device_activation" | "multi_account_device";

export interface Decision {
  /** The first matching row: the one whose outcome applies. */
  row: DecisionRow;
  /** EVERY row whose conditions hold, in evaluation order (row, then the
   * `no_persistent_signal` row, then 4-6); `matchedRows[0] === row`. */
  matchedRows: DecisionRow[];
  outcome: "activate" | "held_review";
  /** Fraud signals required by ANY matched row (the handler de-duplicates). */
  signals: FraudSignalKind[];
  /** Row 6: bit0 is set on the activating device once the reward is issued. */
  setBit0: boolean;
  /** Server-side diagnostic only — never returned to the client. */
  reason: string;
}

interface RowSpec {
  row: DecisionRow;
  matches: boolean;
  outcome: "activate" | "held_review";
  signals: FraudSignalKind[];
  setBit0: boolean;
  reason: string;
}

export function decideActivation(f: ActivationFacts): Decision {
  const bits = f.bits.kind === "known" ? f.bits : null;
  const bit1 = bits !== null && bits.bit1;
  const bit0 = bits !== null && bits.bit0;

  const specs: RowSpec[] = [
    // Row 1 — bit1 set, any bit0, any account.
    { row: 1, matches: bit1, outcome: "held_review", signals: ["flagged_device_activation"], setBit0: false, reason: "bit1 set: an account voided for fraud has used this device" },
    // Row 2 — an open attestation_failed signal holds the account's activations.
    { row: 2, matches: f.accountHasOpenAttestationFailed || f.activatingGrade === "failed", outcome: "held_review", signals: [], setBit0: false, reason: "open attestation_failed fraud_signal on the account" },
    // Row 3 — the reward (or the activating device) is unattestable.
    {
      row: 3,
      matches: f.rewardRestsOnUnattestable || f.activatingGrade === "unattestable",
      outcome: "held_review",
      signals: [],
      setBit0: false,
      reason: f.rewardRestsOnUnattestable ? "reward rests on an unattestable co-signal" : "activating device is unattestable",
    },
    // No persistent-bit source: rows 4-6 cannot be evaluated.
    { row: "no_persistent_signal", matches: bits === null, outcome: "held_review", signals: [], setBit0: false, reason: "no persistent device signal available for this activation" },
    // Rows 4-6 need a reading, and bit1 clear.
    {
      row: 4,
      matches: bits !== null && !bit1 && bit0 && !f.accountHasPriorReward,
      outcome: "held_review",
      signals: ["multi_account_device"],
      setBit0: false,
      reason: "bit0 set and the account has no prior reward: possible second account on this device",
    },
    { row: 5, matches: bits !== null && !bit1 && bit0 && f.accountHasPriorReward, outcome: "activate", signals: [], setBit0: false, reason: "bit0 set, account has a prior reward: repeat user" },
    { row: 6, matches: bits !== null && !bit1 && !bit0, outcome: "activate", signals: [], setBit0: true, reason: "clean device" },
  ];

  const matched = specs.filter((s) => s.matches);
  // Rows 5 and 6 are only reachable with a reading, rows 1-3 and the
  // no-signal row cover every other case: something always matches.
  const first = matched[0];
  if (!first) throw new Error("decideActivation: no row matched (unreachable)");
  const signals: FraudSignalKind[] = [];
  for (const m of matched) for (const sig of m.signals) if (!signals.includes(sig)) signals.push(sig);
  return {
    row: first.row,
    matchedRows: matched.map((m) => m.row),
    outcome: first.outcome,
    signals,
    setBit0: first.setBit0,
    reason: first.reason,
  };
}
