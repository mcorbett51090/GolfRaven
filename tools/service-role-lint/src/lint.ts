// tools/service-role-lint/src/lint.ts
//
// AST-based check over the TS/JS in supabase/functions/** (build plan
// §4.7.1a, docs/golf-trails/02-build-plan.md:1197-1205): "The lint is an
// AST rule, not a method-name grep (A2-10). It fails on:
//   (a) any construction of a service-role client outside privileged.ts;
//   (b) any call on a privileged handle outside a withOwnership callback.
//       That covers .from() with ANY method (including .upsert()), .rpc(),
//       and storage.from().upload/remove/… ;
//   (c) any reference to the database-URL environment variable
//       (SUPABASE_DB_URL [unverified — training knowledge on the name]),
//       or any Postgres driver import, outside privileged.ts."
//
// Uses a real parser (@typescript-eslint/typescript-estree, pinned) rather
// than a method-name grep, per the plan's own explicit requirement.

import { AST_NODE_TYPES, parse, type TSESTree } from "@typescript-eslint/typescript-estree";

export type RuleId = "service-role-construction" | "privileged-call-outside-withOwnership" | "db-url-or-driver";

export interface Finding {
  rule: RuleId;
  message: string;
  line: number;
  column: number;
}

export interface LintResult {
  filePath: string;
  findings: Finding[];
}

/** The one file allowed to do any of this (build plan line 1189). */
const ALLOWED_PATH_SUFFIX = "_shared/privileged.ts";

/**
 * [unverified — training knowledge on the exact env var name; build plan
 * line 1201-1202 marks this the same way] the database-URL environment
 * variable name the plan's rule (c) names.
 */
const DB_URL_ENV_VAR = "SUPABASE_DB_URL";

/** Postgres driver package specifiers a raw-SQL import would use. */
const POSTGRES_DRIVER_SPECIFIERS = new Set(["pg", "postgres", "postgres.js", "pg-promise"]);

/** Env var name substrings that mark a client as service-role (case-insensitive). */
const SERVICE_ROLE_MARKERS = ["SERVICE_ROLE"];

function isAllowedFile(filePath: string): boolean {
  return filePath.endsWith(ALLOWED_PATH_SUFFIX);
}

function nodeLoc(node: TSESTree.Node): { line: number; column: number } {
  return { line: node.loc?.start.line ?? 0, column: node.loc?.start.column ?? 0 };
}

/** True if this string literal / identifier text names the DB URL env var. */
function mentionsDbUrlEnvVar(text: string): boolean {
  return text.includes(DB_URL_ENV_VAR);
}

/** Walk every string literal in a subtree looking for the service-role marker. */
function subtreeMentionsServiceRole(node: TSESTree.Node): boolean {
  let found = false;
  walk(node, (n) => {
    if (found) return;
    if (n.type === AST_NODE_TYPES.Literal && typeof n.value === "string") {
      if (SERVICE_ROLE_MARKERS.some((m) => n.value!.toString().toUpperCase().includes(m))) {
        found = true;
      }
    }
    if (n.type === AST_NODE_TYPES.Identifier) {
      if (SERVICE_ROLE_MARKERS.some((m) => n.name.toUpperCase().includes(m))) {
        found = true;
      }
    }
  });
  return found;
}

function subtreeMentionsDbUrl(node: TSESTree.Node): boolean {
  let found = false;
  walk(node, (n) => {
    if (found) return;
    if (n.type === AST_NODE_TYPES.Literal && typeof n.value === "string" && mentionsDbUrlEnvVar(n.value)) {
      found = true;
    }
    if (n.type === AST_NODE_TYPES.Identifier && mentionsDbUrlEnvVar(n.name)) {
      found = true;
    }
  });
  return found;
}

/** Minimal generic AST walker (typescript-estree nodes are plain objects). */
function walk(node: TSESTree.Node | null | undefined, visit: (n: TSESTree.Node) => void): void {
  if (!node || typeof node !== "object") return;
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === "parent" || key === "loc" || key === "range") continue;
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === "object" && "type" in item) {
          walk(item as TSESTree.Node, visit);
        }
      }
    } else if (value && typeof value === "object" && "type" in (value as object)) {
      walk(value as TSESTree.Node, visit);
    }
  }
}

function isCreateClientCall(node: TSESTree.Node): node is TSESTree.CallExpression {
  return (
    node.type === AST_NODE_TYPES.CallExpression &&
    node.callee.type === AST_NODE_TYPES.Identifier &&
    node.callee.name === "createClient"
  );
}

export function lintSource(source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  if (isAllowedFile(filePath)) {
    return findings; // privileged.ts is the sanctioned construction site.
  }

  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: true, range: true, jsx: false });
  } catch (err) {
    return [
      {
        rule: "db-url-or-driver",
        message: `failed to parse ${filePath}: ${(err as Error).message}`,
        line: 0,
        column: 0,
      },
    ];
  }

  // Track identifiers bound to a service-role client (rule a's targets for
  // rule b): `const x = createClient(url, SERVICE_ROLE_KEY, ...)`.
  const serviceRoleIdentifiers = new Set<string>();

  // Track the ranges of function bodies passed as the 2nd argument to a
  // `withOwnership(actor, op)` call — code inside these ranges is exempt
  // from rule (b).
  const withOwnershipCallbackRanges: Array<[number, number]> = [];

  walk(ast, (node) => {
    // Rule (a): service-role client construction.
    if (isCreateClientCall(node)) {
      const usesServiceRole = node.arguments.some((arg) => subtreeMentionsServiceRole(arg));
      if (usesServiceRole) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "service-role-construction",
          message:
            "createClient(...) with a service-role key/env-var is constructed outside supabase/functions/_shared/privileged.ts",
          ...loc,
        });
      }
    }

    // Rule (c): raw Postgres driver import.
    if (node.type === AST_NODE_TYPES.ImportDeclaration) {
      const spec = node.source.value;
      if (typeof spec === "string" && POSTGRES_DRIVER_SPECIFIERS.has(spec)) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "db-url-or-driver",
          message: `Postgres driver "${spec}" imported outside supabase/functions/_shared/privileged.ts`,
          ...loc,
        });
      }
    }
    if (node.type === AST_NODE_TYPES.CallExpression && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === "require") {
      const arg = node.arguments[0];
      if (arg && arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string" && POSTGRES_DRIVER_SPECIFIERS.has(arg.value)) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "db-url-or-driver",
          message: `Postgres driver "${arg.value}" required outside supabase/functions/_shared/privileged.ts`,
          ...loc,
        });
      }
    }

    // Rule (c): DB URL env var reference.
    if (
      (node.type === AST_NODE_TYPES.Literal && typeof node.value === "string" && mentionsDbUrlEnvVar(node.value)) ||
      (node.type === AST_NODE_TYPES.Identifier && mentionsDbUrlEnvVar(node.name))
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "db-url-or-driver",
        message: `reference to the ${DB_URL_ENV_VAR} environment variable outside supabase/functions/_shared/privileged.ts`,
        ...loc,
      });
    }

    // Track service-role identifier bindings for rule (b).
    if (
      node.type === AST_NODE_TYPES.VariableDeclarator &&
      node.id.type === AST_NODE_TYPES.Identifier &&
      node.init &&
      isCreateClientCall(node.init) &&
      node.init.arguments.some((arg) => subtreeMentionsServiceRole(arg))
    ) {
      serviceRoleIdentifiers.add(node.id.name);
    }

    // Track withOwnership(actor, op) callback ranges.
    if (
      node.type === AST_NODE_TYPES.CallExpression &&
      node.callee.type === AST_NODE_TYPES.Identifier &&
      node.callee.name === "withOwnership"
    ) {
      const cb = node.arguments[1];
      if (
        cb &&
        (cb.type === AST_NODE_TYPES.ArrowFunctionExpression || cb.type === AST_NODE_TYPES.FunctionExpression) &&
        cb.range
      ) {
        withOwnershipCallbackRanges.push([cb.range[0], cb.range[1]]);
      }
    }
  });

  const insideWithOwnership = (node: TSESTree.Node): boolean => {
    if (!node.range) return false;
    return withOwnershipCallbackRanges.some(([start, end]) => node.range![0] >= start && node.range![1] <= end);
  };

  // Rule (b): any call on a privileged (service-role) handle outside a
  // withOwnership callback — `.from(...)` with any method, `.rpc(...)`,
  // `storage.from().upload/remove/...`.
  walk(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.CallExpression) return;
    if (node.callee.type !== AST_NODE_TYPES.MemberExpression) return;

    const callee = node.callee;
    const methodName =
      callee.property.type === AST_NODE_TYPES.Identifier ? callee.property.name : undefined;

    // Find the root identifier of the member-expression chain
    // (`svc.storage.from(...).upload(...)` -> `svc`).
    let base: TSESTree.Node = callee.object;
    while (
      base.type === AST_NODE_TYPES.MemberExpression ||
      (base.type === AST_NODE_TYPES.CallExpression && base.callee.type === AST_NODE_TYPES.MemberExpression)
    ) {
      base = base.type === AST_NODE_TYPES.MemberExpression ? base.object : base.callee.object;
    }
    if (base.type !== AST_NODE_TYPES.Identifier || !serviceRoleIdentifiers.has(base.name)) return;

    const isPrivilegedMethod =
      methodName === "from" || methodName === "rpc" || methodName === "upload" || methodName === "remove" ||
      methodName === "update" || methodName === "upsert" || methodName === "insert" || methodName === "delete" ||
      methodName === "select";

    if (isPrivilegedMethod && !insideWithOwnership(node)) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "privileged-call-outside-withOwnership",
        message: `.${methodName}(...) called on service-role client "${base.name}" outside a withOwnership() callback`,
        ...loc,
      });
    }
  });

  return findings;
}
