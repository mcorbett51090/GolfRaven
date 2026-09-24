/**
 * `RuleExpr` evaluation (§4.1's third `RuleExpr` bullet: "an evaluator in
 * packages/rules"). Pure TS, no I/O — walks an already schema-valid (and,
 * for a money-mode rule, already `checkRuleExpr`-clean — see
 * `rule-expr-check.ts`) tree and computes its boolean result against a
 * player's plays/roster data.
 *
 * **Money-mode polarity, evaluated (§4.1 line 635-641).** "The compiler
 * gives each aggregate occurrence a polarity... In money mode a positive
 * occurrence counts only money-rule plays, and a negative occurrence
 * counts every badge-level play." `checkRuleExpr` only needed to REJECT
 * `==`/`!=` in money mode (§4.1 line 642-643) — it never had to compute a
 * real polarity value, because rejection doesn't depend on one. Evaluation
 * does: this is where §9.5's `trailProgress(T) >= 0.5 && !played(F)`
 * example actually produces the effect the plan describes (a badge-level
 * play at F making `!played(F)` false) — `trailProgress` here is a
 * POSITIVE occurrence (0 `not`s, `>=`), so it counts only money-qualifying
 * plays; `played(F)` is a NEGATIVE occurrence (1 `not`, odd), so it counts
 * every badge-level play. In `mode: 'badge'`, polarity is never consulted
 * (§4.1 line 630: "where polarity makes no difference") — every aggregate
 * always counts badge-level plays.
 */
import type { CompareOp, NumericOperand, RosterVersion, RuleExpr } from "@golfraven/catalog";
import {
  countDistinct,
  countWhere,
  markerCredits,
  maxCountBy,
  type AggregateContext,
} from "./aggregates.js";
import {
  inOrder as inOrderOf,
  isTrailComplete,
  markerSetComplete as markerSetCompleteOf,
  monthlyStreak as monthlyStreakOf,
  played,
  trailCompleteWithin as trailCompleteWithinOf,
  trailProgress as trailProgressOf,
  uniqueCourses as uniqueCoursesOf,
  type Play,
} from "./completion.js";
import type { RuleExprEvalMode } from "./rule-expr-check.js";

export interface RuleExprEvalContext extends AggregateContext {
  plays: Play[];
}

/** Whether a `not`-free occurrence of a comparator's LEFT operand is
 * "positive" (larger count helps satisfaction) — `>=`/`>` are positive at
 * baseline, `<=`/`<` are negative, `==`/`!=` have none (§4.1 line 636-643;
 * `==`/`!=` are already excluded from any money-mode rule by
 * `checkRuleExpr`, so this is only ever consulted in `badge` mode for
 * them, where it's moot). */
function baselinePositiveForOp(op: CompareOp, side: "left" | "right"): boolean {
  const leftPositive = op === ">=" || op === ">";
  return side === "left" ? leftPositive : !leftPositive;
}

/** Applies the enclosing `not` parity to a baseline polarity. */
function polarity(baselinePositive: boolean, negated: boolean): boolean {
  return negated ? !baselinePositive : baselinePositive;
}

/**
 * Evaluates the top-level `RuleExpr` (§4.1's closed boolean grammar) to a
 * boolean, under `mode`. `RuleExprSchema.safeParse` (and, for a money-mode
 * rule, `checkRuleExpr`) are assumed to have already run — this function
 * does not re-validate the tree's shape.
 */
export function evaluateRuleExpr(
  expr: RuleExpr,
  ctx: RuleExprEvalContext,
  mode: RuleExprEvalMode,
): boolean {
  return evalBoolean(expr, ctx, mode, false);
}

function evalBoolean(
  expr: RuleExpr,
  ctx: RuleExprEvalContext,
  mode: RuleExprEvalMode,
  negated: boolean,
): boolean {
  switch (expr.kind) {
    case "and":
      return expr.args.every((a) => evalBoolean(a, ctx, mode, negated));
    case "or":
      return expr.args.some((a) => evalBoolean(a, ctx, mode, negated));
    case "not":
      return !evalBoolean(expr.arg, ctx, mode, !negated);
    case "compare": {
      const leftPositive = polarity(baselinePositiveForOp(expr.op, "left"), negated);
      const rightPositive = polarity(baselinePositiveForOp(expr.op, "right"), negated);
      const left = evalNumeric(expr.left, ctx, mode, leftPositive);
      const right = evalNumeric(expr.right, ctx, mode, rightPositive);
      switch (expr.op) {
        case ">=":
          return left >= right;
        case ">":
          return left > right;
        case "<=":
          return left <= right;
        case "<":
          return left < right;
        case "==":
          return left === right;
        case "!=":
          return left !== right;
      }
      return false;
    }
    // A bare aggregate call used directly as a boolean node. A
    // boolean-returning aggregate (trailComplete/trailCompleteWithin/
    // inOrder/markerSetComplete) IS the boolean. A number-returning one
    // (only `played` in practice, per R-14 — §4.1's own worked example)
    // is truthy: nonzero → true (see `@golfraven/catalog`'s `rule-expr.ts`
    // module doc on why this bare-numeric-under-`not` shape is accepted
    // at all). The occurrence is "positive" at baseline (a larger count
    // only ever makes it MORE true), flipped by the enclosing `not`
    // parity — the same rule a comparator's operand gets.
    default: {
      const occurrencePositive = polarity(true, negated);
      const value = evalAggregate(expr, ctx, mode, occurrencePositive);
      return typeof value === "boolean" ? value : value !== 0;
    }
  }
}

function evalNumeric(
  operand: NumericOperand,
  ctx: RuleExprEvalContext,
  mode: RuleExprEvalMode,
  occurrencePositive: boolean,
): number {
  if (operand.kind === "literal") return operand.value;
  const value = evalAggregate(operand, ctx, mode, occurrencePositive);
  if (typeof value === "boolean") {
    throw new Error(
      `evalNumeric: aggregate "${operand.name}" returned a boolean but was used as a numeric operand — RuleExprSchema should have rejected this at parse time`,
    );
  }
  return value;
}

/** `useMoney`: §4.1 line 638-640 — money mode AND a positive occurrence is
 * the only combination that restricts to money-rule-qualifying plays;
 * everything else (badge mode always, or a negative occurrence even in
 * money mode) uses the badge-level threshold. */
function evalAggregate(
  expr: Extract<RuleExpr, { kind: "agg" }>,
  ctx: RuleExprEvalContext,
  mode: RuleExprEvalMode,
  occurrencePositive: boolean,
): number | boolean {
  const useMoney = mode === "money" && occurrencePositive;
  const versionsOf = (trailId: string): RosterVersion[] => ctx.trails[trailId] ?? [];
  switch (expr.name) {
    case "played":
      return played(expr.courseId, ctx.plays, ctx, useMoney);
    case "trailProgress":
      return trailProgressOf(versionsOf(expr.trailId), ctx.plays, ctx, useMoney);
    case "uniqueCourses":
      return uniqueCoursesOf(ctx.plays, ctx, useMoney);
    case "countDistinct":
      return countDistinct(expr.field, ctx, ctx.plays, useMoney, expr.where);
    case "maxCountBy":
      return maxCountBy(expr.field, ctx, ctx.plays, useMoney);
    case "countWhere":
      return countWhere(expr.field, expr.value, ctx, ctx.plays, useMoney);
    case "markerCredits":
      return markerCredits(versionsOf(expr.trailId), ctx.plays, ctx, useMoney);
    case "monthlyStreak":
      return monthlyStreakOf(ctx.plays, useMoney);
    case "trailComplete":
      return isTrailComplete(versionsOf(expr.trailId), ctx.plays, ctx, useMoney);
    case "trailCompleteWithin":
      return trailCompleteWithinOf(versionsOf(expr.trailId), ctx.plays, ctx, expr.days, useMoney);
    case "inOrder":
      return inOrderOf(versionsOf(expr.trailId), ctx.plays, ctx, useMoney);
    case "markerSetComplete":
      return markerSetCompleteOf(versionsOf(expr.trailId), ctx.plays, ctx, useMoney);
  }
}
