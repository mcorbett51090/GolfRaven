/**
 * `RuleExpr`'s static checker (build plan §4.1, §8.1) — the part of "1.
 * RuleExpr: ... a static checker (type signatures, the closed `field`
 * enum, the money-mode polarity rule)" that a single Zod parse cannot
 * express, because it needs WHOLE-TREE context a per-node shape doesn't
 * have:
 *
 * - **the money-mode polarity rule (R-F6).** "`==` and `!=` on an
 *   aggregate have no single polarity. `offers-admin` and the catalog gate
 *   reject them in any money-mode rule" (§4.1 line 642-643). Whether a
 *   `compare` node is even IN a money-mode evaluation is a property of the
 *   *caller*, not the node — "The caller sets the evaluation mode, never
 *   the expression" (§4.1 line 629) — so this check takes `mode` as an
 *   input, the same split `evaluateRuleExpr` (`rule-expr-eval.ts`) uses.
 * - **the "no data could satisfy this" check (R-F4).** "The compiler
 *   rejects a comparison that no data could satisfy, such as
 *   `countDistinct("region", { in: [4 codes] }) >= 5`" (§4.1 line 613).
 *   This needs each aggregate's statically-derivable numeric range
 *   (`trailProgress` ∈ [0,1]; a `countDistinct` restricted by `where.in`
 *   is bounded above by `where.in.length`; every other aggregate is
 *   bounded only below, by 0 — a non-negative count) — a property of the
 *   WHOLE `compare` node (both operands together), not of either operand
 *   read alone.
 *
 * Type signatures and the closed `field` enum are NOT re-checked here —
 * `RuleExprSchema` (`@golfraven/catalog`) already enforces both structurally
 * (a `.safeParse` failure IS that check; see its module doc for why R-F1/
 * R-F2/R-F3/R-F5/R-F7 all fail at the schema layer, before this function is
 * ever called). Callers therefore always run `RuleExprSchema.safeParse`
 * first and only call `checkRuleExpr` on an already-well-typed tree — this
 * module never re-derives the field enum or an aggregate's argument shape.
 */
import {
  REGION_CODES,
  type CompareOp,
  type Field,
  type NotArg,
  type NumericOperand,
  type RuleExpr,
} from "@golfraven/catalog";

export type RuleExprEvalMode = "badge" | "money";

export interface RuleExprCheckIssue {
  /** A short, stable, upper-snake identifier, matching `verify-catalog`'s
   * own `CatalogIssue.code` convention (`tools/catalog/src/verify-catalog.ts`). */
  code: string;
  /** A path into the `RuleExpr` tree (`and.args[1].compare`, …), the same
   * dotted/bracket convention `verify-catalog` uses for catalog paths. */
  path: string;
  message: string;
}

function issue(
  code: string,
  path: string,
  message: string,
): RuleExprCheckIssue {
  return { code, path, message };
}

/* ------------------------------------------------------------------ */
/* R-F4: static numeric range, for the unsatisfiability check          */
/* ------------------------------------------------------------------ */

export interface NumericRange {
  min: number;
  max: number;
}

/**
 * The statically-derivable range of a `NumericOperand`. Every aggregate
 * not named below is bounded only below (a non-negative count, unbounded
 * above) — the plan gives exactly one bounded example (`trailProgress`,
 * "`number in [0, 1]`", §4.1 line 596) and one bounded-by-restriction
 * example (`countDistinct` under `where.in`, line 613); every other
 * aggregate (`played`, `uniqueCourses`, an unrestricted `countDistinct`,
 * `maxCountBy`, `countWhere`, `markerCredits`, `monthlyStreak`) has no
 * plan-stated upper bound, so `Infinity` here means exactly that: "no
 * comparison against it can be rejected as unsatisfiable on range grounds
 * alone" — not a real numeric commitment.
 */
/**
 * S5 (gate review): a `countDistinct` bound is the DOMAIN size, not
 * `where.in.length` verbatim — `country` only ever has 2 possible values
 * regardless of `where`, and `region` is bounded by the pinned ISO 3166-2
 * list size even with no `where` at all. `designer`/`facility`/`trail`
 * have no fixed universe (new ones can always be minted), so they stay
 * unbounded absent a `where` restriction.
 */
function domainBoundForField(field: Field): number {
  switch (field) {
    case "country":
      return 2;
    case "region":
      return REGION_CODES.size;
    case "designer":
    case "facility":
    case "trail":
      return Infinity;
  }
}

/**
 * The statically-derivable range of a `NumericOperand`. Every aggregate
 * not named below is bounded only below (a non-negative count, unbounded
 * above) — the plan gives exactly one bounded example (`trailProgress`,
 * "`number in [0, 1]`", §4.1 line 596); `countDistinct` is bounded by its
 * `field`'s domain size (S5 above), narrowed further by `where.in`'s
 * DISTINCT values (deduped — a repeated code in `where.in` does not add a
 * second possible value, §4.1 line 613's own R-F4 fixture depends on
 * this); every other aggregate (`played`, `uniqueCourses`, `maxCountBy`,
 * `countWhere`, `markerCredits`, `monthlyStreak`) has no plan-stated upper
 * bound, so `Infinity` here means exactly that: "no comparison against it
 * can be rejected as unsatisfiable on range grounds alone" — not a real
 * numeric commitment.
 */
export function numericRangeOf(operand: NumericOperand): NumericRange {
  if (operand.kind === "literal") {
    return { min: operand.value, max: operand.value };
  }
  switch (operand.name) {
    case "trailProgress":
      return { min: 0, max: 1 };
    case "countDistinct": {
      const domainBound = domainBoundForField(operand.field);
      const whereBound = operand.where
        ? new Set(operand.where.in).size
        : Infinity;
      return { min: 0, max: Math.min(domainBound, whereBound) };
    }
    default:
      return { min: 0, max: Infinity };
  }
}

/** Whether ANY pair `(l ∈ leftRange, r ∈ rightRange)` satisfies `l op r`
 * (§4.1 line 613: "a comparison that no data could satisfy"). */
export function isRangeSatisfiable(
  op: CompareOp,
  left: NumericRange,
  right: NumericRange,
): boolean {
  switch (op) {
    case ">=":
      return left.max >= right.min;
    case ">":
      return left.max > right.min;
    case "<=":
      return left.min <= right.max;
    case "<":
      return left.min < right.max;
    case "==":
      return left.min <= right.max && right.min <= left.max;
    case "!=":
      // Unsatisfiable only in the degenerate case where both sides are
      // pinned to the exact same single point — anything else (either
      // side spans more than one value) admits a `!=` witness.
      return !(
        left.min === left.max &&
        right.min === right.max &&
        left.min === right.min
      );
    default:
      return true;
  }
}

/* ------------------------------------------------------------------ */
/* The walk                                                             */
/* ------------------------------------------------------------------ */

export interface CheckRuleExprOptions {
  mode: RuleExprEvalMode;
}

/**
 * Static-checks an already schema-valid `RuleExpr` (§4.1's "static
 * checker" bullet — see this module's doc for the exact two rules it
 * covers). Returns an empty array when the rule is fine for the given
 * mode.
 *
 * `mode: 'badge'` is what every `AchievementDef.rule` runs under
 * (§4.1 line 630: "Achievements evaluate in badge mode ... where polarity
 * makes no difference") — `==`/`!=` are legal there, so only the
 * unsatisfiability check (mode-independent) ever fires. `mode: 'money'`
 * is what an offer's (DB-side) eligibility `RuleExpr` runs under (§4.1
 * line 631-632) — both checks apply.
 */
export function checkRuleExpr(
  expr: RuleExpr,
  options: CheckRuleExprOptions,
): RuleExprCheckIssue[] {
  const issues: RuleExprCheckIssue[] = [];
  walk(expr, "rule", options.mode, false, issues);
  return issues;
}

function walk(
  expr: NotArg,
  path: string,
  mode: RuleExprEvalMode,
  /** N2 (gate review): the parity of enclosing `not`s. An "impossible"
   * comparison (`RULE_UNSATISFIABLE`) under an EVEN number of `not`s truly
   * can never be satisfied — but under an ODD number, `not` flips it into
   * something that is ALWAYS true (vacuous, a different smell entirely,
   * never "unsatisfiable"). The false positive this fixes: `not(countDistinct
   * (region, {in: [4 codes]}) >= 5)` is a perfectly satisfiable rule (it's
   * ALWAYS true, since the inner comparison can never hold) — flagging it
   * UNSATISFIABLE was backwards. */
  negated: boolean,
  issues: RuleExprCheckIssue[],
): void {
  switch (expr.kind) {
    case "and":
    case "or":
      expr.args.forEach((arg, i) =>
        walk(arg, `${path}.args[${i}]`, mode, negated, issues),
      );
      return;
    case "not":
      walk(expr.arg, `${path}.arg`, mode, !negated, issues);
      return;
    case "compare": {
      const leftIsAggregate = expr.left.kind !== "literal";
      const rightIsAggregate = expr.right.kind !== "literal";
      // N2 (gate review): only a comparison that actually involves an
      // aggregate operand has a "polarity" concept at all — a pure
      // literal-vs-literal comparison (`1 == 1`) has none to lack.
      if (
        (expr.op === "==" || expr.op === "!=") &&
        mode === "money" &&
        (leftIsAggregate || rightIsAggregate)
      ) {
        issues.push(
          issue(
            "RULE_MONEY_MODE_NO_POLARITY",
            path,
            `"${expr.op}" on an aggregate has no single polarity and is rejected in any money-mode rule (§4.1 line 642-643, R-F6)`,
          ),
        );
      }
      const left = numericRangeOf(expr.left);
      const right = numericRangeOf(expr.right);
      if (!negated && !isRangeSatisfiable(expr.op, left, right)) {
        issues.push(
          issue(
            "RULE_UNSATISFIABLE",
            path,
            `no data could satisfy "${describeOperand(expr.left)} ${expr.op} ${describeOperand(expr.right)}" — left range [${left.min}, ${left.max === Infinity ? "∞" : left.max}], right range [${right.min}, ${right.max === Infinity ? "∞" : right.max}] (§4.1 line 613, R-F4)`,
          ),
        );
      }
      return;
    }
    // A bare aggregate call — numeric (legal only here, directly under
    // `not`, N1) or boolean (`trailComplete` etc, legal anywhere a
    // `RuleExpr` is). Nothing further to check for either return type:
    // argument SHAPES are already schema-level (R-F1/R-F2/R-F3/R-F5/R-F7),
    // and a bare aggregate has no comparator to have a polarity or a
    // satisfiability question about. `inOrder` is the one exception (N4).
    default:
      if (expr.name === "inOrder" && mode === "money") {
        issues.push(
          issue(
            "RULE_INORDER_NOT_ALLOWED_IN_MONEY_MODE",
            path,
            `"inOrder" is a cosmetic, badge-only aggregate (§8.1 R-05: "cosmetic") and is rejected in any money-mode rule`,
          ),
        );
      }
      return;
  }
}

function describeOperand(operand: NumericOperand): string {
  if (operand.kind === "literal") return String(operand.value);
  return `${operand.name}(...)`;
}
