/**
 * P0 placeholder.
 *
 * `@golfraven/rules` is pure TS: `scorePlay` (`policyVersion`), `RuleExpr`
 * evaluation and eligibility (build plan §3.1 row E, §8). It is
 * authoritative on the server and preview-only on device, and does no I/O.
 * None of that exists yet — P1 defines the `RuleExpr` operator set and the
 * golden fixtures (build plan §15: R-01–R-14 passing, R-F1–R-F7 failing).
 * This module only proves the package builds and typechecks so that work
 * has a workspace to land in.
 */

/** Bumped whenever a scoring/eligibility rule changes (build plan §3.1 row
 * E: `policyVersion`). Release rosters record it so already-released
 * versions stay immutable (build plan §15). */
export const POLICY_VERSION = 0;
