// tools/service-role-lint/src/privileged-lint.ts
//
// THE PRIVILEGED-FILE PASS (edge role PR4b, docs/security/edge-role-design.md section 5 "Code" and section 9).
//
// `supabase/functions/_shared/privileged.ts` is exempt from the lint's general rules (it is the one place a Postgres driver, a
// supabase-js client and raw env reads legitimately live; see `isAllowedFile` in lint.ts). Exempt from the GENERAL rules is not exempt
// from every rule: this pass runs over exactly that file and fails the build on the shapes that would quietly bring back the BYPASSRLS
// path PR4b deleted, or move the actor identity out of the database binding and into something the connection can forge:
//
//   privileged-forbidden-role     a `service_role` literal, or a `SET [LOCAL|SESSION] ROLE <anything but edge_actor | edge_system>`,
//                                 `RESET ROLE`, `SET SESSION AUTHORIZATION`, or a role-switch whose role is not a literal.
//                                 The one exception: the string array `EDGE_FORBIDDEN_MEMBERSHIPS`, the self-check's list of roles the
//                                 edge login must NOT belong to (it names `service_role` in order to refuse it).
//   privileged-db-url             any `SUPABASE_DB_URL` / `DATABASE_URL` / `*DB_URL*` other than `GOLFRAVEN_EDGE_DB_URL`.
//   privileged-service-key        the service-role key (`SERVICE_ROLE` in an env-var name) outside the two functions that may still touch
//                                 it: `adminClient` (GoTrue admin calls) and `isServiceRoleBearer` (a constant-time bearer COMPARISON).
//   privileged-env-access         `Deno.env` used in any shape but `Deno.env.get("<string literal>")`: a computed name could build any
//                                 of the strings above at run time, and `Deno.env.toObject()` reads them all.
//   privileged-stray-transaction  `.begin(` outside `openScopedTx`; `.savepoint(` outside `withOwnershipBatch` (the per-item isolation
//                                 of one batch, itself inside an `openScopedTx` transaction). Every transaction is opened by one function,
//                                 so every transaction has the role, the timeouts, the bind and the post-bind assertions.
//   privileged-stray-pool         a call of the `postgres` driver outside `openPool` (a second pool is a second, unchecked way in).
//   privileged-guc-in-ts          `set_config(` / `current_setting(` in TypeScript. The identity is `private.actor_uid()` (an in-database
//                                 binding), never a session variable the connection could set; the one legitimate read this file once
//                                 made, the server version, reads `pg_settings` instead.
//   privileged-edge-db-mode       any `EDGE_DB_MODE`: the switch is gone, and there is no second mode to switch to.
//
// It reads the AST, not the comments: a comment may say any of these words (this file's own header does). String literals, template
// literals (tagged ones are the SQL), and identifiers are what count. A new shape is added here with a must-fail fixture under
// test/fixtures/privileged/bad/ and a cell in test/privileged-lint.test.ts, and proven by mutating the real file in a /tmp copy.

import { AST_NODE_TYPES, parse, type TSESTree } from "@typescript-eslint/typescript-estree";
import type { Finding } from "./lint.js";

type PrivilegedRuleId =
  | "privileged-forbidden-role"
  | "privileged-db-url"
  | "privileged-service-key"
  | "privileged-env-access"
  | "privileged-stray-transaction"
  | "privileged-stray-pool"
  | "privileged-guc-in-ts"
  | "privileged-edge-db-mode"
  | "parse-error";

export type PrivilegedFinding = Omit<Finding, "rule"> & { rule: PrivilegedRuleId };

/** The only roles a transaction may switch into (the edge roles; the login `edge_gateway` is a member of both with SET). */
const ALLOWED_ROLES = new Set(["edge_actor", "edge_system"]);
/** The only functions that may mention the service-role key (see the file header and the comment above `adminClient` in privileged.ts). */
const SERVICE_KEY_FUNCTIONS = new Set(["adminClient", "isServiceRoleBearer"]);
/** The only function that may open a transaction / a pool / a savepoint. */
const BEGIN_FUNCTIONS = new Set(["openScopedTx"]);
const SAVEPOINT_FUNCTIONS = new Set(["withOwnershipBatch"]);
const POOL_FUNCTIONS = new Set(["openPool"]);
/** The one declaration allowed to NAME `service_role`: the list of memberships the edge login must not have. */
const FORBIDDEN_MEMBERSHIPS_DECL = "EDGE_FORBIDDEN_MEMBERSHIPS";
/** What stands in for a `${...}` hole when a template literal is joined into one string. */
const HOLE = "\u0001";

function loc(node: TSESTree.Node): { line: number; column: number } {
  return { line: node.loc?.start.line ?? 0, column: node.loc?.start.column ?? 0 };
}

function propertyName(node: TSESTree.MemberExpression): string | undefined {
  if (!node.computed && node.property.type === AST_NODE_TYPES.Identifier) return node.property.name;
  if (node.computed && node.property.type === AST_NODE_TYPES.Literal && typeof node.property.value === "string") return node.property.value;
  return undefined;
}

/** The SQL text of a string / template literal, a `${...}` hole shown as HOLE; undefined for any other node. */
function textOf(node: TSESTree.Node): string | undefined {
  if (node.type === AST_NODE_TYPES.Literal && typeof node.value === "string") return node.value;
  if (node.type === AST_NODE_TYPES.TemplateLiteral) {
    return node.quasis.map((q) => q.value.cooked ?? q.value.raw).join(HOLE);
  }
  return undefined;
}

export function lintPrivilegedSource(source: string): PrivilegedFinding[] {
  const findings: PrivilegedFinding[] = [];
  const add = (rule: PrivilegedRuleId, node: TSESTree.Node, message: string) => findings.push({ rule, message, ...loc(node) });

  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: true, range: true, jsx: false });
  } catch (err) {
    return [{ rule: "parse-error", message: `failed to parse the privileged file: ${(err as Error).message}`, line: 0, column: 0 }];
  }

  // The local name of the default import of the `postgres` driver (a call of it is a pool).
  const driverNames = new Set<string>();
  for (const stmt of ast.body) {
    if (stmt.type === AST_NODE_TYPES.ImportDeclaration && stmt.source.value === "postgres") {
      for (const spec of stmt.specifiers) driverNames.add(spec.local.name);
    }
  }

  // Ancestors, nearest last. FunctionDeclaration names are what the allow-lists key on.
  const stack: TSESTree.Node[] = [];
  const inFunction = (names: Set<string>): boolean => stack.some((n) => n.type === AST_NODE_TYPES.FunctionDeclaration && n.id !== null && names.has(n.id.name));
  const inForbiddenMembershipsArray = (): boolean =>
    stack.some((n) => n.type === AST_NODE_TYPES.VariableDeclarator && n.id.type === AST_NODE_TYPES.Identifier && n.id.name === FORBIDDEN_MEMBERSHIPS_DECL);

  const checkText = (node: TSESTree.Node, text: string) => {
    // privileged-edge-db-mode
    if (/EDGE_DB_MODE/i.test(text)) add("privileged-edge-db-mode", node, "EDGE_DB_MODE: the mode switch was deleted (edge role PR4b); there is one database path and nothing may read or name this variable");
    // privileged-db-url
    if (/DATABASE_URL/i.test(text) || /DB_URL/i.test(text.replace(/GOLFRAVEN_EDGE_DB_URL/g, ""))) {
      add("privileged-db-url", node, 'a database-URL variable other than GOLFRAVEN_EDGE_DB_URL (SUPABASE_DB_URL is the old service_role pool\'s input and may not be read): the edge pool is the only connection');
    }
    // privileged-service-key / privileged-forbidden-role
    if (/service_role/i.test(text)) {
      if (/SERVICE_ROLE_KEY/i.test(text)) {
        if (!inFunction(SERVICE_KEY_FUNCTIONS)) add("privileged-service-key", node, "the service-role key outside adminClient / isServiceRoleBearer: the key is for GoTrue admin calls and a bearer comparison only, never for a database path");
      } else if (!inForbiddenMembershipsArray()) {
        add("privileged-forbidden-role", node, "a `service_role` literal: no transaction may run as, name, or switch to the BYPASSRLS role (only edge_actor / edge_system; EDGE_FORBIDDEN_MEMBERSHIPS may list it to refuse it)");
      }
    }
    // privileged-forbidden-role: role switches
    const switches = text.matchAll(/\b(set|reset)\s+(?:(local|session)\s+)?(role|session\s+authorization)\b\s*([A-Za-z_][A-Za-z0-9_]*|"[^"]*"|\u0001)?/gi);
    for (const m of switches) {
      const verb = m[1]!.toLowerCase();
      const what = m[3]!.toLowerCase().replace(/\s+/g, " ");
      if (what !== "role") {
        add("privileged-forbidden-role", node, "SET SESSION AUTHORIZATION: a role-switch that is not `SET LOCAL ROLE edge_actor | edge_system`");
      } else if (verb === "reset") {
        add("privileged-forbidden-role", node, "RESET ROLE: the only role-switch allowed is `SET LOCAL ROLE edge_actor | edge_system`");
      } else if (m[4] !== undefined) {
        const target = m[4] === HOLE ? HOLE : m[4].replace(/^"|"$/g, "").toLowerCase();
        if (target === HOLE) add("privileged-forbidden-role", node, "SET ROLE with a role that is not a literal: the role must be spelled out (edge_actor | edge_system)");
        else if (!ALLOWED_ROLES.has(target)) add("privileged-forbidden-role", node, `SET ROLE ${target}: only edge_actor and edge_system may be switched to`);
      }
    }
    // privileged-guc-in-ts
    if (/\b(set_config|current_setting)\s*\(/i.test(text)) {
      add("privileged-guc-in-ts", node, "set_config( / current_setting( in TypeScript: the actor identity is the database-side binding (private.actor_uid()), never a session variable; read pg_settings for a server setting");
    }
  };

  const visit = (node: TSESTree.Node): void => {
    // ---- text-bearing nodes ----
    const t = textOf(node);
    if (t !== undefined) checkText(node, t);
    if (node.type === AST_NODE_TYPES.Identifier) checkText(node, node.name);

    // ---- privileged-env-access ----
    if (node.type === AST_NODE_TYPES.CallExpression && isDenoEnvGet(node.callee)) {
      const arg = node.arguments[0];
      if (node.arguments.length !== 1 || !arg || !(arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string")) {
        add("privileged-env-access", node, "Deno.env.get(...) with a non-literal argument: a computed variable name can build any forbidden name at run time");
      }
    }
    if (node.type === AST_NODE_TYPES.MemberExpression && isDenoEnv(node)) {
      const parent = stack[stack.length - 1];
      const grand = stack[stack.length - 2];
      const sanctioned =
        parent?.type === AST_NODE_TYPES.MemberExpression && parent.object === node && propertyName(parent) === "get" && grand?.type === AST_NODE_TYPES.CallExpression && grand.callee === parent;
      if (!sanctioned) add("privileged-env-access", node, "Deno.env used in a shape other than Deno.env.get(<string literal>) (toObject(), aliasing, spreading ... read every variable)");
    }

    // ---- privileged-stray-transaction ----
    if (node.type === AST_NODE_TYPES.MemberExpression) {
      const name = propertyName(node);
      if (name === "begin" && !inFunction(BEGIN_FUNCTIONS)) add("privileged-stray-transaction", node, ".begin( outside openScopedTx: every transaction is opened by openScopedTx (role, timeouts, bind, post-bind assertions)");
      if (name === "savepoint" && !inFunction(SAVEPOINT_FUNCTIONS)) add("privileged-stray-transaction", node, ".savepoint( outside withOwnershipBatch: a savepoint belongs to the batch's per-item isolation inside an openScopedTx transaction");
    }
    if (node.type === AST_NODE_TYPES.ObjectPattern) {
      for (const p of node.properties) {
        if (p.type === AST_NODE_TYPES.Property && !p.computed && p.key.type === AST_NODE_TYPES.Identifier) {
          if (p.key.name === "begin" && !inFunction(BEGIN_FUNCTIONS)) add("privileged-stray-transaction", p, "`begin` destructured off a connection outside openScopedTx");
          if (p.key.name === "savepoint" && !inFunction(SAVEPOINT_FUNCTIONS)) add("privileged-stray-transaction", p, "`savepoint` destructured off a transaction outside withOwnershipBatch");
        }
      }
    }

    // ---- privileged-stray-pool ----
    if ((node.type === AST_NODE_TYPES.CallExpression || node.type === AST_NODE_TYPES.NewExpression) && node.callee.type === AST_NODE_TYPES.Identifier && driverNames.has(node.callee.name)) {
      if (!inFunction(POOL_FUNCTIONS)) add("privileged-stray-pool", node, "the postgres driver called outside openPool: a second pool is a second, unchecked way in (the edge self-check and every role assertion are on the one pool)");
    }

    stack.push(node);
    for (const key of Object.keys(node)) {
      if (key === "parent" || key === "loc" || key === "range") continue;
      const value = (node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        for (const item of value) if (item && typeof item === "object" && "type" in item) visit(item as TSESTree.Node);
      } else if (value && typeof value === "object" && "type" in (value as object)) {
        visit(value as TSESTree.Node);
      }
    }
    stack.pop();
  };

  visit(ast);
  return findings;
}

/** `Deno.env` (non-computed, the identifier `Deno`). */
function isDenoEnv(node: TSESTree.MemberExpression): boolean {
  return node.object.type === AST_NODE_TYPES.Identifier && node.object.name === "Deno" && propertyName(node) === "env";
}

/** `Deno.env.get` as a callee. */
function isDenoEnvGet(callee: TSESTree.Node): boolean {
  return callee.type === AST_NODE_TYPES.MemberExpression && propertyName(callee) === "get" && callee.object.type === AST_NODE_TYPES.MemberExpression && isDenoEnv(callee.object);
}
