/**
 * `RuleExpr` (§4.1, §8.1) and `AchievementDef` (§4.1) — part B of the P1a
 * scope cut that `schema.ts`'s module doc named as not-yet-implemented.
 *
 * `RuleExpr` is "a closed, typed JSON AST: `and/or/not`, the comparators
 * `>= > <= < == !=`, number and string literals, and this fixed list of
 * aggregates" (§4.1 line 588). This file is the Zod type only — "type
 * signatures, the closed `field` enum" per the task's own split. The
 * money-mode polarity rule and the "no data could satisfy this" check are
 * NOT expressible as a single-node Zod shape (both need whole-tree context:
 * polarity depends on how many `not`s enclose a node, and satisfiability
 * depends on an aggregate's derived numeric range) — those live in
 * `@golfraven/rules`'s static checker (`packages/rules/src/rule-expr-check.ts`),
 * per this package's own scope note ("Never does: Hold data or fetch" /
 * cross-node semantic gates live outside `packages/catalog`, the same
 * pattern `schema.ts` already uses for cross-record rules).
 *
 * **AST shape (a design choice, not literal JSON from the plan — §4.1 only
 * describes the grammar in prose).** Every node is `{ kind, ... }`.
 * Boolean nodes: `and`/`or` (`args: RuleExpr[]`, ≥ 2), `not` (`arg:
 * RuleExpr`), `compare` (`op`, `left`/`right`: a number literal or a
 * number-returning aggregate call), and a bare aggregate call used
 * directly as a boolean (see the R-14 note below). `and`/`or` take ≥ 2
 * args because a 1-arg `and`/`or` is always exactly its one argument — the
 * plan's `&&`/`||` shorthand (§9.5's `trailProgress(T) >= 0.5 &&
 * !played(F)`) is always binary in every example the plan writes out, and
 * nothing needs a 1-ary form.
 *
 * **R-14's `!played("crs_F")` (a bare numeric aggregate under `not`, no
 * comparator) is taken literally.** §4.1's own "Type rules" paragraph says
 * "Comparators take numbers. `and`, `or` and `not` take booleans" — read
 * strictly, that would make `!played(F)` (which negates a *number*-typed
 * aggregate) a type error. But §8.1 writes fixture R-14's rule out "in
 * full" as exactly `trailProgress("trl_T") >= 0.5 && !played("crs_F")`,
 * and §4.1's own G3-05 prose walks through this exact expression's money-
 * mode semantics ("a badge-level play at F makes `!played(F)` false"),
 * treating a bare aggregate as JS-style truthy (nonzero → true) when it
 * appears where a boolean is expected. Since the plan gives this exact
 * expression as R-14's canonical, must-pass definition, the most literal
 * reading is that a bare aggregate call — numeric or boolean-returning — is
 * always a valid `RuleExpr` on its own (used with numeric truthiness for a
 * number-returning aggregate), and the "and/or/not take booleans" sentence
 * describes the common case, not an exhaustive ban on this one shape the
 * plan's own fixture exercises. (Plan lines 588, 629–643.)
 */
import { z } from "zod";
import {
  AchievementIdSchema,
  CourseIdSchema,
  DesignerIdSchema,
  FacilityIdSchema,
  TrailIdSchema,
} from "./ids.js";
import { RegionCodeSchema } from "./common.js";

/* ------------------------------------------------------------------ */
/* field enum (§4.1 line 608)                                          */
/* ------------------------------------------------------------------ */

/**
 * "`field` is a closed enum (G3-02): `region` ..., `country`, `designer`
 * ..., `facility`, and `trail`" (§4.1 line 608). Used by `countDistinct`,
 * `maxCountBy` and `countWhere`.
 */
export const FieldSchema = z.enum(["region", "country", "designer", "facility", "trail"]);
export type Field = z.infer<typeof FieldSchema>;

/**
 * "Each value is type-checked: a `region` must exist in `data/regions`,
 * and a `designer` must be a `dsg_` id in `data/designers.json`" (§4.1 line
 * 610-611). This checks the *shape* each field's values must have
 * (`region` against the pinned ISO 3166-2 list via `RegionCodeSchema`,
 * `designer` against the `dsg_` id pattern, etc.) — R-F3 and R-F5's exact
 * failure. Existence of a *specific* id (e.g. "this `dsg_…` is actually in
 * `designers[]`") is a cross-record concern and is checked by
 * `verify-catalog`, the same split `schema.ts` already uses for every
 * other id reference in this package.
 */
export function fieldValueShapeIssue(field: Field, value: string): string | undefined {
  switch (field) {
    case "region":
      return RegionCodeSchema.safeParse(value).success
        ? undefined
        : `"${value}" is not a real ISO 3166-2 US/CA region code (§4.1 line 610)`;
    case "country":
      return value === "US" || value === "CA"
        ? undefined
        : `"${value}" is not "US" or "CA"`;
    case "designer":
      return DesignerIdSchema.safeParse(value).success
        ? undefined
        : `"${value}" is not a dsg_ designer id (§4.1 line 611)`;
    case "facility":
      return FacilityIdSchema.safeParse(value).success
        ? undefined
        : `"${value}" is not a fac_ facility id`;
    case "trail":
      return TrailIdSchema.safeParse(value).success
        ? undefined
        : `"${value}" is not a trl_ trail id`;
  }
}

/* ------------------------------------------------------------------ */
/* Comparators                                                         */
/* ------------------------------------------------------------------ */

/** "the comparators `>= > <= < == !=`" (§4.1 line 588). */
export const CompareOpSchema = z.enum([">=", ">", "<=", "<", "==", "!="]);
export type CompareOp = z.infer<typeof CompareOpSchema>;

/* ------------------------------------------------------------------ */
/* Aggregate calls — the closed list, with typed signatures (§4.1)     */
/* ------------------------------------------------------------------ */

const WhereInSchema = z.strictObject({ in: z.array(z.string().min(1)).min(1) });

export const PlayedCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("played"),
  courseId: CourseIdSchema,
});
export type PlayedCall = z.infer<typeof PlayedCallSchema>;

export const TrailProgressCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("trailProgress"),
  trailId: TrailIdSchema,
});
export type TrailProgressCall = z.infer<typeof TrailProgressCallSchema>;

export const UniqueCoursesCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("uniqueCourses"),
});
export type UniqueCoursesCall = z.infer<typeof UniqueCoursesCallSchema>;

export const CountDistinctCallSchema = z
  .strictObject({
    kind: z.literal("agg"),
    name: z.literal("countDistinct"),
    field: FieldSchema,
    where: WhereInSchema.optional(),
  })
  .superRefine((value, ctx) => {
    if (!value.where) return;
    value.where.in.forEach((v, i) => {
      const msg = fieldValueShapeIssue(value.field, v);
      if (msg) {
        ctx.addIssue({ code: "custom", path: ["where", "in", i], message: msg });
      }
    });
  });
export type CountDistinctCall = z.infer<typeof CountDistinctCallSchema>;

export const MaxCountByCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("maxCountBy"),
  field: FieldSchema,
});
export type MaxCountByCall = z.infer<typeof MaxCountByCallSchema>;

export const CountWhereCallSchema = z
  .strictObject({
    kind: z.literal("agg"),
    name: z.literal("countWhere"),
    field: FieldSchema,
    value: z.string().min(1),
  })
  .superRefine((value, ctx) => {
    const msg = fieldValueShapeIssue(value.field, value.value);
    if (msg) {
      ctx.addIssue({ code: "custom", path: ["value"], message: msg });
    }
  });
export type CountWhereCall = z.infer<typeof CountWhereCallSchema>;

export const MarkerCreditsCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("markerCredits"),
  trailId: TrailIdSchema,
});
export type MarkerCreditsCall = z.infer<typeof MarkerCreditsCallSchema>;

export const MonthlyStreakCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("monthlyStreak"),
});
export type MonthlyStreakCall = z.infer<typeof MonthlyStreakCallSchema>;

/** The number-returning aggregates (§4.1's table "Returns" column) — valid
 * wherever a `NumericOperand` (a comparator's `left`/`right`) is expected,
 * and also valid as a bare boolean node (R-14; numeric truthiness). Kept as
 * its own flat `discriminatedUnion` (not composed later from smaller
 * pieces) purely for the error-path quality documented on
 * `AggregateCallSchema` below. */
export const NumericAggregateCallSchema = z.discriminatedUnion("name", [
  PlayedCallSchema,
  TrailProgressCallSchema,
  UniqueCoursesCallSchema,
  CountDistinctCallSchema,
  MaxCountByCallSchema,
  CountWhereCallSchema,
  MarkerCreditsCallSchema,
  MonthlyStreakCallSchema,
]);
export type NumericAggregateCall = z.infer<typeof NumericAggregateCallSchema>;

export const TrailCompleteCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("trailComplete"),
  trailId: TrailIdSchema,
});
export type TrailCompleteCall = z.infer<typeof TrailCompleteCallSchema>;

export const TrailCompleteWithinCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("trailCompleteWithin"),
  trailId: TrailIdSchema,
  days: z.int().positive(),
});
export type TrailCompleteWithinCall = z.infer<typeof TrailCompleteWithinCallSchema>;

export const InOrderCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("inOrder"),
  trailId: TrailIdSchema,
});
export type InOrderCall = z.infer<typeof InOrderCallSchema>;

export const MarkerSetCompleteCallSchema = z.strictObject({
  kind: z.literal("agg"),
  name: z.literal("markerSetComplete"),
  trailId: TrailIdSchema,
});
export type MarkerSetCompleteCall = z.infer<typeof MarkerSetCompleteCallSchema>;

/** The boolean-returning aggregates. */
export const BooleanAggregateCallSchema = z.discriminatedUnion("name", [
  TrailCompleteCallSchema,
  TrailCompleteWithinCallSchema,
  InOrderCallSchema,
  MarkerSetCompleteCallSchema,
]);
export type BooleanAggregateCall = z.infer<typeof BooleanAggregateCallSchema>;

/**
 * Every aggregate call, either return type. **Not** composed from the two
 * typed sub-unions above via `z.union` — Zod v4's `discriminatedUnion`
 * cannot see through a plain nested `z.union` to find a consistent
 * discriminator value, so that composition throws at schema-construction
 * time ("Invalid discriminated union option"), confirmed against this
 * Zod version directly. This is instead its own single flat
 * `discriminatedUnion("name", [...all 12...])`, which Zod v4 handles
 * cleanly (including nested inside the outer `kind`-discriminated
 * `RuleExprSchema` below) and gives the precise, path-pointing error this
 * package's fixtures need: an unknown `name` (R-F1: `holesInOne()`; R-F7:
 * `minConfidence`/`score_badge`, which the offer grammar has no operand
 * for at all, §4.1 line 633-634) fails with `path: ["name"]` and Zod's own
 * "Invalid discriminator value" message — there is no grammar production
 * for it, the same as any of the 12 real names' own argument-shape
 * mismatches.
 */
export const AggregateCallSchema = z.discriminatedUnion("name", [
  PlayedCallSchema,
  TrailProgressCallSchema,
  UniqueCoursesCallSchema,
  CountDistinctCallSchema,
  MaxCountByCallSchema,
  CountWhereCallSchema,
  MarkerCreditsCallSchema,
  MonthlyStreakCallSchema,
  TrailCompleteCallSchema,
  TrailCompleteWithinCallSchema,
  InOrderCallSchema,
  MarkerSetCompleteCallSchema,
]);
export type AggregateCall = z.infer<typeof AggregateCallSchema>;

/** Names, exported once so callers (the static checker, the evaluator)
 * never re-derive this list. */
export const NUMERIC_AGGREGATE_NAMES = [
  "played",
  "trailProgress",
  "uniqueCourses",
  "countDistinct",
  "maxCountBy",
  "countWhere",
  "markerCredits",
  "monthlyStreak",
] as const;
export const BOOLEAN_AGGREGATE_NAMES = [
  "trailComplete",
  "trailCompleteWithin",
  "inOrder",
  "markerSetComplete",
] as const;

/* ------------------------------------------------------------------ */
/* RuleExpr — the recursive boolean tree                               */
/* ------------------------------------------------------------------ */

export type NumericOperand = { kind: "literal"; value: number } | NumericAggregateCall;

export interface AndNode {
  kind: "and";
  args: RuleExpr[];
}
export interface OrNode {
  kind: "or";
  args: RuleExpr[];
}
export interface NotNode {
  kind: "not";
  arg: RuleExpr;
}
export interface CompareNode {
  kind: "compare";
  op: CompareOp;
  left: NumericOperand;
  right: NumericOperand;
}

/** The closed, typed JSON AST (§4.1 line 588). */
export type RuleExpr = AndNode | OrNode | NotNode | CompareNode | AggregateCall;

const NumberLiteralSchema = z.strictObject({ kind: z.literal("literal"), value: z.number() });

/** `left`/`right` of a `compare` node: a number literal or a number-
 * returning aggregate call. A plain `z.union` (not `discriminatedUnion`,
 * since `NumberLiteralSchema.kind === "literal"` while every aggregate's
 * `kind === "agg"` — that pair IS a valid 2-way discriminant on `kind`,
 * but there is no fixture that needs its error path to be sharper than
 * "matches neither shape", so the simpler `z.union` is kept here). Needs
 * no `z.lazy`: it never refers back to `RuleExprSchema`, so there is no
 * cycle to break. */
export const NumericOperandSchema: z.ZodType<NumericOperand> = z.union([
  NumberLiteralSchema,
  NumericAggregateCallSchema,
]);

/** A `compare` node's operands are `NumericOperand`, never `RuleExpr`
 * itself — also no cycle, also no `z.lazy` needed. */
export const CompareNodeSchema: z.ZodType<CompareNode> = z.strictObject({
  kind: z.literal("compare"),
  op: CompareOpSchema,
  left: NumericOperandSchema,
  right: NumericOperandSchema,
});

/**
 * `and`/`or`/`not` are the only three node shapes that recurse into
 * `RuleExpr` itself. Only the recursive PROPERTY (`args`'s element type,
 * `arg`) is wrapped in `z.lazy` — each node schema itself stays a plain,
 * concrete `strictObject`, which is what lets `RuleExprSchema` below
 * compose all five node schemas into one `discriminatedUnion` on `kind`
 * and still type-check as `z.ZodType<RuleExpr>`. (Wrapping an entire node
 * schema, or the whole top-level union, in `z.lazy` instead was tried
 * first and does not type-check under this `tsconfig`'s
 * `exactOptionalPropertyTypes` — confirmed against this Zod version
 * directly: a `z.lazy`-wrapped schema does not statically expose the
 * `propValues` a `discriminatedUnion` needs from each of its members, so
 * the *member* being lazy is fine, but the *union itself*, or a member
 * that is lazy all the way down, is not.) `RuleExprSchema` is referenced
 * here before its own declaration below — legal because it carries an
 * explicit type annotation (TS resolves a `const`'s *declared* type
 * module-wide) and is only ever reached at parse time inside `z.lazy`'s
 * deferred callback (legal for the same reason `verify-catalog`'s own
 * mutually-recursive helpers are legal — the callback body runs after the
 * whole module has finished evaluating, past any `const` TDZ).
 */
export const AndNodeSchema: z.ZodType<AndNode> = z.strictObject({
  kind: z.literal("and"),
  args: z.array(z.lazy(() => RuleExprSchema)).min(2),
});
export const OrNodeSchema: z.ZodType<OrNode> = z.strictObject({
  kind: z.literal("or"),
  args: z.array(z.lazy(() => RuleExprSchema)).min(2),
});
export const NotNodeSchema: z.ZodType<NotNode> = z.strictObject({
  kind: z.literal("not"),
  arg: z.lazy(() => RuleExprSchema),
});

/**
 * The top-level `RuleExpr` schema — a `discriminatedUnion` on `kind` (not
 * a plain `z.union`), confirmed against this Zod version to nest cleanly
 * with `AggregateCallSchema` (itself a `discriminatedUnion` on `name`) as
 * one of its five branches: Zod resolves the two-level discriminator
 * correctly (`kind: "agg"` at this level, `name: <...>` one level in),
 * which is what gives R-F1/R-F7 their precise `path: ["name"]` "Invalid
 * discriminator value" error instead of a bare, path-less "no union
 * member matched".
 */
export const RuleExprSchema: z.ZodType<RuleExpr> = z.discriminatedUnion("kind", [
  AndNodeSchema,
  OrNodeSchema,
  NotNodeSchema,
  CompareNodeSchema,
  AggregateCallSchema,
]);

/* ------------------------------------------------------------------ */
/* AchievementDef (§4.1 line 523-524)                                   */
/* ------------------------------------------------------------------ */

/** `tier: 'bronze'|'silver'|'gold'|'special'` (§4.1). */
export const AchievementTierSchema = z.enum(["bronze", "silver", "gold", "special"]);
export type AchievementTier = z.infer<typeof AchievementTierSchema>;

/**
 * `AchievementDef { id: 'ach_…', title, titleFr?, tier, rule: RuleExpr,
 * minConfidence, scope: 'verified-only', active }` (§4.1 line 523-524).
 * Every §8.1 badge is `scope: 'verified-only'` — the task's own
 * instruction, matching §8.1's table header ("all `scope: 'verified-only'`")
 * — so `scope` is a single-member enum here rather than a free string,
 * the same "closed-but-single-value" modelling `MarkerUnitSchema` already
 * uses in `schema.ts` for `markerUnit: 'facility'`.
 */
export const AchievementScopeSchema = z.enum(["verified-only"]);
export type AchievementScope = z.infer<typeof AchievementScopeSchema>;

export const AchievementDefSchema = z.strictObject({
  id: AchievementIdSchema,
  title: z.string().min(1),
  titleFr: z.string().optional(),
  tier: AchievementTierSchema,
  rule: RuleExprSchema,
  minConfidence: z.number().min(0).max(1),
  scope: AchievementScopeSchema,
  active: z.boolean(),
});
export type AchievementDef = z.infer<typeof AchievementDefSchema>;
