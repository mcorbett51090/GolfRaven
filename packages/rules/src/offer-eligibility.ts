/**
 * A2-05's validator: "`offers-admin` rejects any eligibility `RuleExpr`
 * that contains a confidence or score operand. It checks at the operator's
 * save and again at admin approval... The issuance, activation and
 * redemption functions re-evaluate in `money` mode, whatever the row says."
 * (§4.5 lines 1034-1041.) The task's must-fail fixture: "an operator offer
 * with `minConfidence 0.5` or `score_badge >= 0.5` is rejected at save and
 * at approval, and a row forced into the DB by SQL still issues nothing on
 * a 0.50 play."
 *
 * **Why this is a thin wrapper, not new rejection logic (no double
 * maintenance of one rule).** `@golfraven/catalog`'s `RuleExprSchema` is
 * already the FIRST gate: `minConfidence`/`score_badge` are not aggregate
 * names in the closed `AggregateCallSchema` union at all — "the offer
 * grammar has no operand for it" (`rule-expr.ts`'s own doc, R-F7) — so any
 * eligibility JSON that tries to smuggle a confidence/score comparison in
 * fails `.safeParse` outright, with `path: ["name"]`. `checkRuleExpr` (this
 * package's existing, UNCHANGED static checker — see `rule-expr-check.ts`)
 * is the second gate, for a schema-valid tree that is still unsound in
 * `money` mode (the `==`/`!=`-polarity and unsatisfiability rules). Save,
 * approval AND issuance all call this one function — "whatever the row
 * says" (line 1037) is automatically true for issuance because `RuleExpr`
 * itself has no node shape that COULD encode a confidence threshold; there
 * is nothing for a bypassed validator to have let through that
 * `evaluateRuleExpr(..., 'money')` would then honour. See this module's
 * test file for the exact must-fail fixture, exercised against the real
 * (unmodified) evaluator.
 */
import { RuleExprSchema, type RuleExpr } from "@golfraven/catalog";
import { checkRuleExpr, type RuleExprCheckIssue } from "./rule-expr-check.js";

export type OfferEligibilityCheck =
  | { valid: true; rule: RuleExpr }
  | { valid: false; issues: RuleExprCheckIssue[] };

/**
 * Validates a raw, not-yet-typed eligibility value (exactly what a save/
 * approval/issuance call site holds — JSON from the operator UI, or a row
 * read back from the DB) against BOTH gates, always in `money` mode (every
 * offer's eligibility is money-mode, §4.1 line 631-632 — an offer is never
 * evaluated in `badge` mode). Call this identically at save, at approval,
 * and again at issuance/activation/redemption (A2-05: "re-evaluate...
 * whatever the row says") — it is cheap and pure, so there is no reason to
 * trust a prior check.
 */
export function validateOfferEligibility(raw: unknown): OfferEligibilityCheck {
  const parsed = RuleExprSchema.safeParse(raw);
  if (!parsed.success) {
    const issues: RuleExprCheckIssue[] = parsed.error.issues.map((i) => ({
      code: "RULE_SCHEMA_INVALID",
      path: i.path.join("."),
      message: i.message,
    }));
    return { valid: false, issues };
  }
  const issues = checkRuleExpr(parsed.data, { mode: "money" });
  if (issues.length > 0) return { valid: false, issues };
  return { valid: true, rule: parsed.data };
}

/** Convenience boolean form for a call site that only needs a gate, not the
 * issue list (e.g. a CI pgTAP-equivalent fixture check). */
export function isOfferEligibilityValid(raw: unknown): boolean {
  return validateOfferEligibility(raw).valid;
}
