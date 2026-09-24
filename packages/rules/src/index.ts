/**
 * `@golfraven/rules` — scoring/eligibility rules (build plan §3.1 row E):
 * `RuleExpr`'s static checker and evaluator, and §8.2's completion +
 * marker-roster evaluation. Pure TS, no I/O — authoritative on the server,
 * preview-only on device. `scorePlay` (`policyVersion`), the evidence
 * scorer and the money golden fixtures are P3 scope, named out of this
 * task ("Out of scope"); `POLICY_VERSION` below is kept as the P0
 * placeholder it always was, for that later work to land on.
 */

/** Bumped whenever a scoring/eligibility rule changes (build plan §3.1 row
 * E: `policyVersion`). Release rosters record it so already-released
 * versions stay immutable (build plan §15). */
export const POLICY_VERSION = 0;

export * from "./rule-expr-check.js";
export * from "./completion.js";
export * from "./aggregates.js";
export * from "./rule-expr-eval.js";
