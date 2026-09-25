/**
 * `@golfraven/rules` — scoring/eligibility rules (build plan §3.1 row E):
 * `RuleExpr`'s static checker and evaluator, §8.2's completion +
 * marker-roster evaluation, and (P3, §4.5) `scorePlay` — the evidence
 * confidence scorer, its money invariant and the A2-05 offer-eligibility
 * validator. Pure TS, no I/O — authoritative on the server, preview-only on
 * device.
 *
 * **M5 (fifth gate): the `POLICY_VERSION = 0` placeholder that used to live
 * here is REMOVED.** It had exactly one consumer — `test/index.test.ts`'s
 * own pin — and existing beside `score-play.ts`'s real, independently
 * versioned `SCORE_PLAY_POLICY_VERSION` (currently 1) was a footgun: two
 * same-package "policy version" constants, one of them permanently frozen
 * at a P0 placeholder value, inviting a future caller to read the wrong
 * one. `SCORE_PLAY_POLICY_VERSION` (`score-play.js`) is the only policy
 * version this package now exports, and it's the one whose CONTENTS are
 * actually pinned — see `test/score-play-policy-hash.test.ts`, which fails
 * CI if the weight table, `MONEY_MIN` or any of the scoring caps change
 * without a matching version bump.
 */

export * from "./rule-expr-check.js";
export * from "./completion.js";
export * from "./aggregates.js";
export * from "./rule-expr-eval.js";
export * from "./score-play.js";
export * from "./offer-eligibility.js";
