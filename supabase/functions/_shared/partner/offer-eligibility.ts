// supabase/functions/_shared/partner/offer-eligibility.ts
//
// Edge AT(14) gate for `offers-admin` upsert (docs/security/partner-auth-design.md 4.5 / A2-05; slice S6).
// packages/rules `validateOfferEligibility` is the SSOT for the full gate (schema + checkRuleExpr +
// tautology). The Edge tree cannot import packages/* (service-role-lint bans relative escapes and
// import-map path aliases). This module is the Deno-local twin of the SCHEMA half: the closed
// aggregate name list that makes `minConfidence` / `score_badge` unrepresentable, plus the
// structural DoS bound. Keep MONEY_AGGREGATE_NAMES aligned with packages/catalog/src/rule-expr.ts.

export type OfferEligibilityIssue = { code: string; path: string; message: string };
export type OfferEligibilityCheck =
  | { valid: true; rule: unknown }
  | { valid: false; issues: OfferEligibilityIssue[] };

const MAX_RULE_DEPTH = 64;
const MAX_RULE_NODES = 5000;

/** Closed money-mode aggregate names from packages/catalog RuleExpr (no confidence / score operands). */
const MONEY_AGGREGATE_NAMES = new Set([
  "played",
  "trailProgress",
  "uniqueCourses",
  "countDistinct",
  "maxCountBy",
  "countWhere",
  "markerCredits",
  "monthlyStreak",
  "trailComplete",
  "trailCompleteWithin",
  "inOrder",
  "markerSetComplete",
]);

const COMPARE_OPS = new Set([">=", ">", "<=", "<", "==", "!="]);
const ID_TAIL = /^[0-9A-HJKMNP-TV-Z]{26}$/;

function isPlainRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

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

function issue(path: string, message: string): OfferEligibilityIssue {
  return { code: "RULE_SCHEMA_INVALID", path, message };
}

function isId(prefix: string, value: unknown): boolean {
  return typeof value === "string" && value.startsWith(`${prefix}_`) && ID_TAIL.test(value.slice(prefix.length + 1));
}

function checkAgg(node: Record<string, unknown>, path: string, issues: OfferEligibilityIssue[]): void {
  const name = node.name;
  if (typeof name !== "string" || !MONEY_AGGREGATE_NAMES.has(name)) {
    issues.push(issue(path === "" ? "name" : `${path}.name`, "unknown or non-money aggregate name"));
    return;
  }
  if (name === "played" && !isId("crs", node.courseId)) {
    issues.push(issue(`${path}.courseId`, "played requires a crs_ course id"));
  }
  if ((name === "trailProgress" || name === "markerCredits" || name === "trailComplete" || name === "markerSetComplete") &&
    !isId("trl", node.trailId)) {
    issues.push(issue(`${path}.trailId`, `${name} requires a trl_ trail id`));
  }
  if (name === "trailCompleteWithin") {
    if (!isId("trl", node.trailId)) issues.push(issue(`${path}.trailId`, "trailCompleteWithin requires a trl_ trail id"));
    if (typeof node.days !== "number" || !Number.isInteger(node.days) || node.days <= 0) {
      issues.push(issue(`${path}.days`, "trailCompleteWithin requires a positive integer days"));
    }
  }
  if (name === "inOrder") {
    if (!Array.isArray(node.courseIds) || node.courseIds.length < 2 || !node.courseIds.every((c) => isId("crs", c))) {
      issues.push(issue(`${path}.courseIds`, "inOrder requires at least two crs_ course ids"));
    }
  }
}

function checkOperand(node: unknown, path: string, issues: OfferEligibilityIssue[]): void {
  if (!isPlainRecord(node) || typeof node.kind !== "string") {
    issues.push(issue(path, "operand must be an object with kind"));
    return;
  }
  if (node.kind === "literal") {
    if (typeof node.value !== "number" || !Number.isFinite(node.value)) {
      issues.push(issue(`${path}.value`, "literal value must be a finite number"));
    }
    return;
  }
  if (node.kind === "agg") {
    checkAgg(node, path, issues);
    return;
  }
  issues.push(issue(`${path}.kind`, "operand kind must be literal or agg"));
}

function checkExpr(node: unknown, path: string, issues: OfferEligibilityIssue[]): void {
  if (!isPlainRecord(node) || typeof node.kind !== "string") {
    issues.push(issue(path, "RuleExpr must be an object with kind"));
    return;
  }
  switch (node.kind) {
    case "and":
    case "or": {
      if (!Array.isArray(node.args) || node.args.length < 2) {
        issues.push(issue(`${path}.args`, `${node.kind} requires at least two args`));
        return;
      }
      node.args.forEach((arg, i) => checkExpr(arg, `${path}.args.${i}`, issues));
      return;
    }
    case "not":
      if (isPlainRecord(node.arg) && node.arg.kind === "agg") checkAgg(node.arg, `${path}.arg`, issues);
      else checkExpr(node.arg, `${path}.arg`, issues);
      return;
    case "compare":
      if (typeof node.op !== "string" || !COMPARE_OPS.has(node.op)) {
        issues.push(issue(`${path}.op`, "compare op must be one of >= > <= < == !="));
      }
      checkOperand(node.left, `${path}.left`, issues);
      checkOperand(node.right, `${path}.right`, issues);
      return;
    case "agg":
      checkAgg(node, path, issues);
      return;
    default:
      issues.push(issue(`${path}.kind`, "unknown RuleExpr kind"));
  }
}

/** Validate raw eligibility JSON for an offers-admin upsert (AT(14) schema gate). */
export function validateOfferEligibility(raw: unknown): OfferEligibilityCheck {
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
  const issues: OfferEligibilityIssue[] = [];
  checkExpr(raw, "", issues);
  if (issues.length > 0) return { valid: false, issues };
  return { valid: true, rule: raw };
}
