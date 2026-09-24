/**
 * `@golfraven/rules` — scoring/eligibility rules (build plan §3.1 row E):
 * `RuleExpr`'s static checker and evaluator, §8.2's completion +
 * marker-roster evaluation, and (P3, §4.5) `scorePlay` — the evidence
 * confidence scorer, its money invariant and the A2-05 offer-eligibility
 * validator. Pure TS, no I/O — authoritative on the server, preview-only on
 * device.
 *
 * **`POLICY_VERSION` below is intentionally left at its P0 value (0),
 * UNCHANGED.** The existing test `test/index.test.ts` pins it there
 * ("exports POLICY_VERSION = 0 until P1/§8 defines real rules") and this
 * task's own Done criterion is "the existing tests are unchanged" — so this
 * placeholder is left exactly as P0/P1 left it rather than reinterpreting
 * its doc comment's "for that later work to land on" as licence to bump it.
 * `scorePlay`'s own `policyVersion` output (§4.5's "policy v1") is instead
 * `score-play.ts`'s own, independent `SCORE_PLAY_POLICY_VERSION` constant —
 * see that file's doc for why the two are kept separate.
 */
export const POLICY_VERSION = 0;

export * from "./rule-expr-check.js";
export * from "./completion.js";
export * from "./aggregates.js";
export * from "./rule-expr-eval.js";
export * from "./score-play.js";
export * from "./offer-eligibility.js";
