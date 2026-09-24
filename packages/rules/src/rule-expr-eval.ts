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
 *
 * **B2 (gate review): `programmeStartsOn` applies ONLY to positive
 * occurrences.** "A backdated badge never backdates an offer or a marker"
 * (§8.2 line ≈1956) — but a NEGATIVE occurrence (e.g. `!played(F)`) must
 * still see every EARLIER badge-level play at F, or an operator's
 * "go play F" offer would wrongly re-issue itself to someone who played F
 * before the programme even started. `ctx.programmeStartsOn` is therefore
 * threaded into `EvalOptions` only on the `useMoney` branch below, never
 * on the negative/badge-level one.
 *
 * **N6 (gate review): the A2-01 user-pick guard is applied HERE**, once,
 * to the whole play list, before any aggregate ever reads it — the same
 * guard `applyUserPickGuard` (`completion.ts`) already exists as a
 * standalone step for direct `packages/rules` callers; the `RuleExpr`
 * evaluator must not skip it just because it goes through a different
 * entry point.
 */
import type {
  AggregateCall,
  CompareOp,
  NotArg,
  NumericAggregateCall,
  NumericOperand,
  RosterVersion,
  RuleExpr,
} from "@golfraven/catalog";
import {
  countDistinct,
  countWhere,
  markerCredits,
  maxCountBy,
  type AggregateContext,
} from "./aggregates.js";
import {
  applyUserPickGuard,
  inOrder as inOrderOf,
  isTrailComplete,
  markerSetComplete as markerSetCompleteOf,
  monthlyStreak as monthlyStreakOf,
  played,
  trailCompleteWithin as trailCompleteWithinOf,
  trailProgress as trailProgressOf,
  uniqueCourses as uniqueCoursesOf,
  type EvalOptions,
  type Play,
} from "./completion.js";
import type { RuleExprEvalMode } from "./rule-expr-check.js";

export interface RuleExprEvalContext extends AggregateContext {
  plays: Play[];
  /** B2: §4.6's `trail_programme.starts_on` — a money-mode-only bound,
   * kept separate from any `RosterVersion.trackingStartsOn`. Applied only
   * on positive occurrences (this module's doc). */
  programmeStartsOn?: string;
  /** S4: `AchievementDef.minConfidence` — the `score_badge` threshold for
   * this evaluation's non-money-mode plays. Defaults to `completion.ts`'s
   * `BADGE_THRESHOLD` (0.50) when omitted. */
  badgeThreshold?: number;
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
  // N6: apply the user-pick guard exactly once, here, before any
  // aggregate reads the play list.
  const guardedCtx: RuleExprEvalContext = { ...ctx, plays: applyUserPickGuard(ctx.plays, ctx) };
  return evalBoolean(expr, guardedCtx, mode, false);
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
      return !evalNotArg(expr.arg, ctx, mode, !negated);
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
    // A bare BOOLEAN aggregate call used directly as a boolean node
    // (trailComplete/trailCompleteWithin/inOrder/markerSetComplete — N1:
    // a bare NUMERIC aggregate can only ever reach this function via
    // `not`'s `arg`, i.e. through `evalNotArg` below, never here).
    default: {
      const occurrencePositive = polarity(true, negated);
      const value = evalAggregate(expr, ctx, mode, occurrencePositive);
      if (typeof value !== "boolean") {
        throw new Error(
          `evalBoolean: aggregate "${expr.name}" returned a number but was used as a bare boolean node — RuleExprSchema should have rejected this at parse time`,
        );
      }
      return value;
    }
  }
}

/** `not`'s `arg` is `NotArg` (`RuleExpr | NumericAggregateCall`, N1) — the
 * one position a bare NUMERIC aggregate can appear, evaluated with
 * numeric truthiness (nonzero → true; R-14's own worked example). */
function evalNotArg(
  arg: NotArg,
  ctx: RuleExprEvalContext,
  mode: RuleExprEvalMode,
  negated: boolean,
): boolean {
  if (arg.kind === "agg" && isNumericAggregateCall(arg)) {
    const occurrencePositive = polarity(true, negated);
    const value = evalAggregate(arg, ctx, mode, occurrencePositive);
    return typeof value === "boolean" ? value : value !== 0;
  }
  return evalBoolean(arg as RuleExpr, ctx, mode, negated);
}

const NUMERIC_NAMES = new Set<string>([
  "played",
  "trailProgress",
  "uniqueCourses",
  "countDistinct",
  "maxCountBy",
  "countWhere",
  "markerCredits",
  "monthlyStreak",
]);
function isNumericAggregateCall(agg: AggregateCall): agg is NumericAggregateCall {
  return NUMERIC_NAMES.has(agg.name);
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
 * money mode) uses the badge-level threshold. B2: `programmeStartsOn` is
 * folded into `EvalOptions` only when `useMoney` — never on the
 * negative-occurrence path. */
function evalAggregate(
  expr: AggregateCall,
  ctx: RuleExprEvalContext,
  mode: RuleExprEvalMode,
  occurrencePositive: boolean,
): number | boolean {
  const useMoney = mode === "money" && occurrencePositive;
  const opts: EvalOptions = {
    money: useMoney,
    ...(useMoney && ctx.programmeStartsOn !== undefined
      ? { programmeStartsOn: ctx.programmeStartsOn }
      : {}),
    ...(ctx.badgeThreshold !== undefined ? { badgeThreshold: ctx.badgeThreshold } : {}),
  };
  const versionsOf = (trailId: string): RosterVersion[] => ctx.trails[trailId] ?? [];
  switch (expr.name) {
    case "played":
      return played(expr.courseId, ctx.plays, ctx, opts);
    case "trailProgress":
      return trailProgressOf(versionsOf(expr.trailId), ctx.plays, ctx, opts);
    case "uniqueCourses":
      return uniqueCoursesOf(ctx.plays, ctx, opts);
    case "countDistinct":
      return countDistinct(expr.field, ctx, ctx.plays, opts, expr.where);
    case "maxCountBy":
      return maxCountBy(expr.field, ctx, ctx.plays, opts);
    case "countWhere":
      return countWhere(expr.field, expr.value, ctx, ctx.plays, opts);
    case "markerCredits":
      return markerCredits(versionsOf(expr.trailId), ctx.plays, ctx, opts);
    case "monthlyStreak":
      return monthlyStreakOf(ctx.plays, ctx, opts);
    case "trailComplete":
      return isTrailComplete(versionsOf(expr.trailId), ctx.plays, ctx, opts);
    case "trailCompleteWithin":
      return trailCompleteWithinOf(versionsOf(expr.trailId), ctx.plays, ctx, expr.days, opts);
    case "inOrder":
      return inOrderOf(versionsOf(expr.trailId), ctx.plays, ctx, opts);
    case "markerSetComplete":
      return markerSetCompleteOf(versionsOf(expr.trailId), ctx.plays, ctx, opts);
  }
}
