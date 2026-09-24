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
import { evaluateRuleExpr, type RuleExprEvalContext } from "./rule-expr-eval.js";
import { checkRuleExpr, type RuleExprCheckIssue } from "./rule-expr-check.js";

export type OfferEligibilityCheck =
  | { valid: true; rule: RuleExpr }
  | { valid: false; issues: RuleExprCheckIssue[] };

export interface ValidateOfferEligibilityOptions {
  /** M3 (fifth gate): skip the unconditional/tautology check below. Off by
   * default — a caller must opt in explicitly, and it never overrides the
   * schema/`checkRuleExpr` gates. */
  allowUnconditional?: boolean;
}

/** M3 (fifth gate): the structural bound `withinStructuralBounds` enforces
 * BEFORE `RuleExprSchema.safeParse` ever runs — Zod's own recursive parse
 * (and `checkRuleExpr`'s own recursive walk) would otherwise stack-overflow
 * FIRST on a sufficiently deep adversarial tree, throwing a `RangeError`
 * rather than returning `{valid: false}`. */
const MAX_RULE_DEPTH = 64;
/** A very WIDE tree (e.g. 200k `or` args) is a DIFFERENT DoS shape than a
 * deep one — bounded independently. */
const MAX_RULE_NODES = 5000;

function isPlainRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/**
 * An ITERATIVE (never itself recursive — so it can never throw its own
 * `RangeError` on a malicious deep input) structural size check over a
 * not-yet-typed candidate `RuleExpr`. Generic over ANY plain object/array
 * shape (it doesn't assume `RuleExpr`'s own node shapes — the input is, by
 * definition, not yet known to BE a well-formed `RuleExpr`), and bails
 * immediately once either bound would be exceeded, including mid-array —
 * a single `{args: [...200000 items]}` node is capped WHILE being walked,
 * never after building a 200000-length stack.
 */
function withinStructuralBounds(raw: unknown): boolean {
  const stack: { value: unknown; depth: number }[] = [{ value: raw, depth: 1 }];
  let visited = 0;
  while (stack.length > 0) {
    const frame = stack.pop();
    if (frame === undefined) break;
    visited += 1;
    if (frame.depth > MAX_RULE_DEPTH || visited > MAX_RULE_NODES) return false;
    const children: unknown[] = Array.isArray(frame.value)
      ? frame.value
      : isPlainRecord(frame.value)
        ? Object.values(frame.value)
        : [];
    for (const child of children) {
      if (visited + stack.length >= MAX_RULE_NODES) return false;
      stack.push({ value: child, depth: frame.depth + 1 });
    }
  }
  return true;
}

/** M3 (fifth gate): the "empty play history" context `evaluateRuleExpr`
 * runs the tautology probe against. `plays: []` and a far-past
 * `programmeStartsOn` (needed because ANY positive-occurrence money-mode
 * aggregate requires it, `rule-expr-eval.ts`'s own `requireProgrammeStartsOn`)
 * — with no plays at all, every aggregate reads as its own zero/false
 * baseline, which is exactly what "no data could ever fail this rule"
 * needs to probe. */
const EMPTY_MONEY_CTX: RuleExprEvalContext = {
  plays: [],
  trails: {},
  courses: {},
  programmeStartsOn: "1970-01-01",
};

/**
 * Validates a raw, not-yet-typed eligibility value (exactly what a save/
 * approval/issuance call site holds — JSON from the operator UI, or a row
 * read back from the DB) against every gate, always in `money` mode (every
 * offer's eligibility is money-mode, §4.1 line 631-632 — an offer is never
 * evaluated in `badge` mode). Call this identically at save, at approval,
 * and again at issuance/activation/redemption (A2-05: "re-evaluate...
 * whatever the row says") — it is cheap and pure, so there is no reason to
 * trust a prior check.
 *
 * **Gate order (M3, fifth gate): structural bound → schema → static
 * checker → tautology.** The structural bound runs FIRST because it is
 * the one gate that must never itself recurse (a `RangeError` is not a
 * `{valid: false}`); the tautology check runs LAST because it needs an
 * already schema-valid, already `checkRuleExpr`-clean tree to evaluate.
 */
export function validateOfferEligibility(
  raw: unknown,
  options: ValidateOfferEligibilityOptions = {},
): OfferEligibilityCheck {
  if (!withinStructuralBounds(raw)) {
    return {
      valid: false,
      issues: [
        {
          code: "RULE_TOO_LARGE",
          path: "",
          message: `RuleExpr exceeds the structural bound (max depth ${MAX_RULE_DEPTH}, max nodes ${MAX_RULE_NODES})`,
        },
      ],
    };
  }
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

  // M3: reject any rule that `evaluateRuleExpr(rule, emptyCtx, "money") ===
  // true` — i.e. one that no play history could ever fail — unless the
  // caller explicitly opts out via `{allowUnconditional: true}`. A parse
  // or evaluation error against the EMPTY context is not itself proof of a
  // tautology (it just means this probe couldn't run), so it's swallowed
  // rather than treated as a rejection.
  if (options.allowUnconditional !== true) {
    let alwaysTrue = false;
    try {
      alwaysTrue = evaluateRuleExpr(parsed.data, EMPTY_MONEY_CTX, "money") === true;
    } catch {
      alwaysTrue = false;
    }
    if (alwaysTrue) {
      return {
        valid: false,
        issues: [
          {
            code: "RULE_UNCONDITIONAL_MONEY",
            path: "",
            message:
              "this rule evaluates to true against an EMPTY play history — no data could ever fail it; pass {allowUnconditional: true} if this is deliberate",
          },
        ],
      };
    }
  }
  return { valid: true, rule: parsed.data };
}

/** Convenience boolean form for a call site that only needs a gate, not the
 * issue list (e.g. a CI pgTAP-equivalent fixture check). */
export function isOfferEligibilityValid(raw: unknown): boolean {
  return validateOfferEligibility(raw).valid;
}

/**
 * Should-fix: named exports for each of A2-05's three call sites —
 * `offers-admin`'s save, `offers-admin`'s admin-approval step, and the
 * issuance/activation/redemption functions' re-evaluation. There are no
 * real call sites for any of these yet (that DB-side code is P5 scope,
 * outside `packages/rules`); these three names exist so that, when it IS
 * built, each call site imports the specific name for ITS OWN step rather
 * than reaching for the generic `validateOfferEligibility` and leaving the
 * other two steps to be remembered separately. All three are the exact
 * SAME function — see `identicalAcrossCallSites.test` in
 * `offer-eligibility.test.ts`, which asserts this by reference AND by
 * behaviour, so a future edit that special-cases one of them (e.g.
 * "issuance re-evaluates, but save is more lenient") is caught immediately
 * rather than discovered as a live gap between what was checked at save
 * and what is enforced at issuance.
 */
export const validateOfferEligibilityAtSave = validateOfferEligibility;
export const validateOfferEligibilityAtApproval = validateOfferEligibility;
export const validateOfferEligibilityAtIssuance = validateOfferEligibility;
