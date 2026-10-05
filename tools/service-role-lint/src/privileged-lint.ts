// tools/service-role-lint/src/privileged-lint.ts
//
// THE PRIVILEGED-FILE PASS (edge role PR4b, docs/security/edge-role-design.md section 5 "Code" and section 9).
//
// `supabase/functions/_shared/privileged.ts` is exempt from the lint's general rules (it is the one place a Postgres driver, a
// supabase-js client and raw env reads legitimately live; see `isAllowedFile` in lint.ts). Exempt from the GENERAL rules is not exempt
// from every rule: this pass runs over exactly that file and fails the build on the shapes that would quietly bring back the BYPASSRLS
// path PR4b deleted, or move the actor identity out of the database binding and into something the connection can forge:
//
//   privileged-forbidden-role     a `service_role` literal, or a `SET [LOCAL|SESSION] ROLE <anything but edge_actor | edge_system | edge_partner>`,
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
//   privileged-global-access      (edge role PR4c, LOW-1) `globalThis` / `self` / `window` / `eval` / `Function` / `import(...)` in any shape but the one
//                                 the real file has: `globalThis.addEventListener` (the closed-socket containment hook, whose only effect is to add
//                                 a listener). Each of the others reaches `Deno` or builds code with no name to match (`globalThis.Deno.env.get(k)`).
//   privileged-computed-member    (PR4c) a computed member access (`a[k]`, `const { [k]: v } = a`) whose key is not a string / number literal. A key built
//                                 at run time reaches any member by a name no text scan sees (`db["be" + "gin"]`). Allow-list below: none needed.
//   privileged-unsafe-sql         (PR4c) `.unsafe(` with anything but one string literal (a concatenation forms `SET LOCAL ROLE postgres` across two
//                                 literals), and `unsafe` taken off a connection in any other shape (an alias, a destructure).
//
//   privileged-driver-import     (PR #34 gate LOW-1) the driver is imported exactly once, by the specifier `postgres`. Any other import (static, `export ... from`,
//                                 `require(`) whose specifier contains `postgres` / `postgresjs` is a second handle on the driver (`import pg3 from
//                                 "https://deno.land/x/postgresjs@v3.4.5/mod.js"` is the exact URL the import map resolves `postgres` to), a second value import
//                                 of `postgres` is too, and `createRequire` (`createRequire(import.meta.url)("postgres")`) / `node:module` may not appear.
//   privileged-global-access      also (PR #34 LOW-1): any member access whose property name is `Deno` (`x.Deno`, `this.Deno`, `e.currentTarget.Deno`, a
//                                 destructure `{ Deno: d } = x`), wherever it appears: the allowed `addEventListener` hands its listener an event and a `this`
//                                 whose chain reaches the global object.
//   privileged-unsafe-sql         also (PR #34 LOW-1): any `.file(` (postgres.js `sql.file(path)` runs a file as SQL, the same raw-SQL entry as `.unsafe(`).
//   privileged-mint-scope         (edge role PR #35, migration 0041) the minter role `edge_signin_minter` and the `"signin_mint"` kind of `openScopedTx` are
//                                 the ONE capability that can write the email-proof table. The role name may appear only inside `openScopedTx` (the one
//                                 function that switches roles); the kind string only inside `openScopedTx` and `signinEmailProofs` (the one caller);
//                                 every `openScopedTx(` call passes a string-literal kind (so the scope above can be read off the text); and
//                                 `openScopedTx` is only ever called, never aliased or passed.
//                                 (partner auth S1.2, PA-13) The same scope holds for the PARTNER minter: the role `edge_partner_minter` only inside
//                                 `openScopedTx`, the `"partner_mint"` kind only inside `openScopedTx` and `withPartnerMint` (its own caller: the
//                                 sign-in proof minter's caller may not use it, and the other way round). `edge_partner` is an ordinary lane role.
//
// PR4c (LOW-1) also tightened two of the rules above:
//   * `Deno` is now an ALLOW-list, not a shape list: ANY reference to the identifier `Deno` other than the exact chain `Deno.env.get("<one string
//     literal>")` is a privileged-env-access finding (`const { env } = Deno` followed by a computed name no longer slips past, because the destructure is
//     itself a reference to `Deno`). A `declare const Deno: T` ambient declaration has no run-time effect and is not a reference.
//   * the driver: `postgres` may be IMPORTED and CALLED (inside openPool); any other reference (`const pg = postgres; pg(url)`, passing it, spreading it, a
//     namespace import's member) is a privileged-stray-pool finding. `openPool` takes NO parameter and every call of it takes NO argument (the one URL is
//     read inside it from GOLFRAVEN_EDGE_DB_URL), and the driver call inside openPool must be handed exactly the constant read from that variable: a
//     caller can no longer point a pool at another database. Type positions (`typeof postgres`, `postgres.TransactionSql`) are erased and not references.
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
  | "privileged-global-access"
  | "privileged-computed-member"
  | "privileged-unsafe-sql"
  | "privileged-driver-import"
  | "privileged-mint-scope"
  | "parse-error";

export type PrivilegedFinding = Omit<Finding, "rule"> & { rule: PrivilegedRuleId };

/** The roles a transaction may switch into (the edge roles; the login `edge_gateway` is a member of each with SET). The MINTER roles (`edge_signin_minter`, and since partner auth S1.2 `edge_partner_minter`)
 * are allowed only in MINT_ROLE_FUNCTIONS (see `privileged-mint-scope`). `edge_partner` (the partner lane: no table privilege, `bind_partner_session` its one way in) is an ordinary lane role. */
const ALLOWED_ROLES = new Set(["edge_actor", "edge_system", "edge_partner"]);
const MINTER_ROLES = ["edge_signin_minter", "edge_partner_minter"] as const;
/** Each mint KIND of `openScopedTx` and the functions that may name it: the one that implements it (`openScopedTx`) and its ONE caller. `partner_mint` (S1.2, PA-13) is the partner sign-in minter's kind. */
const MINT_KINDS: ReadonlyArray<{ kind: string; callers: Set<string> }> = [
  { kind: "signin_mint", callers: new Set(["openScopedTx", "signinEmailProofs"]) },
  { kind: "partner_mint", callers: new Set(["openScopedTx", "withPartnerMint"]) },
];
/** The only function that may name a minter role (it is the only one that switches roles). */
const MINT_ROLE_FUNCTIONS = new Set(["openScopedTx"]);
/** The one specifier the driver is imported by (supabase/functions/deno.json maps it to a pinned URL). */
const DRIVER_SPECIFIER = "postgres";
const SCOPED_TX_FUNCTION = "openScopedTx";
/** The only functions that may mention the service-role key (see the file header and the comment above `adminClient` in privileged.ts). */
const SERVICE_KEY_FUNCTIONS = new Set(["adminClient", "isServiceRoleBearer"]);
/** The only function that may open a transaction / a pool / a savepoint. */
const BEGIN_FUNCTIONS = new Set(["openScopedTx"]);
const SAVEPOINT_FUNCTIONS = new Set(["withOwnershipBatch"]);
const POOL_FUNCTIONS = new Set(["openPool"]);
/** The one declaration allowed to NAME `service_role`: the list of memberships the edge login must not have. */
const FORBIDDEN_MEMBERSHIPS_DECL = "EDGE_FORBIDDEN_MEMBERSHIPS";
/** The one environment variable that feeds the one pool. */
const POOL_URL_VARIABLE = "GOLFRAVEN_EDGE_DB_URL";
/** What stands in for a `${...}` hole when a template literal is joined into one string. */
const HOLE = "\u0001";

function loc(node: TSESTree.Node): { line: number; column: number } {
  return { line: node.loc?.start.line ?? 0, column: node.loc?.start.column ?? 0 };
}

/** The text of a node that is a compile-time string: a string literal, a template literal with no `${}` hole, or a `+` of two such. Else undefined. */
function constString(node: TSESTree.Node): string | undefined {
  if (node.type === AST_NODE_TYPES.Literal && typeof node.value === "string") return node.value;
  if (node.type === AST_NODE_TYPES.TemplateLiteral && node.expressions.length === 0) return node.quasis.map((q) => q.value.cooked ?? q.value.raw).join("");
  if (node.type === AST_NODE_TYPES.BinaryExpression && node.operator === "+") {
    const l = constString(node.left);
    const r = l === undefined ? undefined : constString(node.right);
    return l !== undefined && r !== undefined ? l + r : undefined;
  }
  return undefined;
}

/** A computed key that is already a plain literal: a string, a number, or a hole-less template (`a["b"]`, `a[0]`, a[`b`]). A `+` of two literals is NOT. */
function isPlainLiteralKey(node: TSESTree.Node): boolean {
  return (node.type === AST_NODE_TYPES.Literal && (typeof node.value === "string" || typeof node.value === "number")) || (node.type === AST_NODE_TYPES.TemplateLiteral && node.expressions.length === 0);
}

/** The member's name when it is statically known: `a.b`, `a["b"]`, a[`b`] and `a["b" + "c"]` (folded, so a built name is still read as the name it spells). */
function propertyName(node: TSESTree.MemberExpression): string | undefined {
  if (!node.computed && node.property.type === AST_NODE_TYPES.Identifier) return node.property.name;
  if (node.computed) return constString(node.property);
  return undefined;
}

/** The SQL text of a string / template literal, a `${...}` hole shown as HOLE; undefined for any other node. (A folded `+` of literals is handled by the caller.) */
function textOf(node: TSESTree.Node): string | undefined {
  if (node.type === AST_NODE_TYPES.Literal && typeof node.value === "string") return node.value;
  if (node.type === AST_NODE_TYPES.TemplateLiteral) {
    return node.quasis.map((q) => q.value.cooked ?? q.value.raw).join(HOLE);
  }
  return undefined;
}

/** `ambient` TS nodes that hold only types: an identifier under one is erased at run time and is not a reference. Expression-bearing TS nodes (`as`, `!`,
 * `satisfies`, `<T>x`, `f<T>`) are deliberately NOT in this set: `(postgres as any)(url)` is a use of the driver. */
const TYPE_ONLY_NODE = (type: string): boolean =>
  type.startsWith("TS") &&
  type !== "TSAsExpression" &&
  type !== "TSNonNullExpression" &&
  type !== "TSTypeAssertion" &&
  type !== "TSSatisfiesExpression" &&
  type !== "TSInstantiationExpression" &&
  type !== "TSParameterProperty" &&
  type !== "TSExportAssignment";

/** Identifiers whose every reference is a way to reach the ambient environment or to build code. */
const GLOBAL_OBJECTS = new Set(["globalThis", "self", "window"]);
const CODE_BUILDERS = new Set(["eval", "Function"]);
/** The one member of `globalThis` the real file touches (privileged.ts' closed-socket containment: `typeof globalThis.addEventListener` and two calls).
 * `addEventListener` only registers a listener; it reads no environment and builds no code. */
const GLOBAL_MEMBER_ALLOWLIST = new Set(["addEventListener"]);

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

  // PR #34 LOW-1: the driver is imported ONCE, by the specifier `postgres`. Every other way to name it is a second, unchecked handle.
  let driverValueImports = 0;
  const looksLikeDriver = (spec: string): boolean => /postgres/i.test(spec);
  for (const stmt of ast.body) {
    if (stmt.type === AST_NODE_TYPES.ImportDeclaration && stmt.importKind !== "type") {
      const spec = String(stmt.source.value);
      if (spec === DRIVER_SPECIFIER) driverValueImports += 1;
      else if (looksLikeDriver(spec)) add("privileged-driver-import", stmt, `an import of \`${spec}\`: the driver is imported once, as "${DRIVER_SPECIFIER}" (the import map's pinned URL); any other specifier that names it is a second handle on the driver`);
      if (spec === "node:module" || spec === "module") add("privileged-driver-import", stmt, `an import of \`${spec}\`: createRequire builds a require() that loads the driver (or anything) by a name no scan sees`);
    }
    if ((stmt.type === AST_NODE_TYPES.ExportAllDeclaration || stmt.type === AST_NODE_TYPES.ExportNamedDeclaration) && stmt.source && looksLikeDriver(String(stmt.source.value))) {
      add("privileged-driver-import", stmt, `a re-export from \`${String(stmt.source.value)}\`: a second handle on the driver`);
    }
  }
  if (driverValueImports > 1) add("privileged-driver-import", ast, `the driver "${DRIVER_SPECIFIER}" is imported ${driverValueImports} times: exactly one import is allowed`);

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
        else if ((MINTER_ROLES as readonly string[]).includes(target)) {
          // allowed only inside openScopedTx; outside it the text scan below reports the role name as a privileged-mint-scope finding
        } else if (!ALLOWED_ROLES.has(target)) add("privileged-forbidden-role", node, `SET ROLE ${target}: only edge_actor, edge_system and edge_partner may be switched to`);
      }
    }
    // privileged-mint-scope: the minter roles and the kinds that use them
    for (const minterRole of MINTER_ROLES) {
      if (new RegExp(minterRole, "i").test(text) && !inFunction(MINT_ROLE_FUNCTIONS)) {
        add("privileged-mint-scope", node, `the minter role \`${minterRole}\` outside ${[...MINT_ROLE_FUNCTIONS].join(" / ")}: only the one function that switches roles may name it (a minter role is a capability no handler may reach by name)`);
      }
    }
    for (const mk of MINT_KINDS) {
      if (new RegExp(`\\b${mk.kind}\\b`).test(text) && !inFunction(mk.callers)) {
        add("privileged-mint-scope", node, `the \`${mk.kind}\` transaction kind outside ${[...mk.callers].join(" / ")}: only the minter path may open a transaction as a minter role`);
      }
    }
    // privileged-guc-in-ts
    if (/\b(set_config|current_setting)\s*\(/i.test(text)) {
      add("privileged-guc-in-ts", node, "set_config( / current_setting( in TypeScript: the actor identity is the database-side binding (private.actor_uid()), never a session variable; read pg_settings for a server setting");
    }
  };

  /** The nearest enclosing function declaration with one of these names (its AST node), if any. */
  const enclosing = (name: string): TSESTree.FunctionDeclaration | undefined =>
    [...stack].reverse().find((n): n is TSESTree.FunctionDeclaration => n.type === AST_NODE_TYPES.FunctionDeclaration && n.id !== null && n.id.name === name);

  /** Is this identifier a REFERENCE (a use of the binding, or a re-declaration of the name), as opposed to a property name, an import binding or a type? */
  const isReference = (node: TSESTree.Identifier): boolean => {
    const parent = stack[stack.length - 1];
    if (!parent) return true;
    if (stack.some((n) => TYPE_ONLY_NODE(n.type))) return false; // inside a type: erased at run time
    switch (parent.type) {
      case AST_NODE_TYPES.MemberExpression:
        return parent.object === node || parent.computed;
      case AST_NODE_TYPES.Property:
        // `{ Deno }` (shorthand) USES the binding; `{ Deno: 1 }` names a key.
        return parent.shorthand || parent.computed || parent.value === node;
      case AST_NODE_TYPES.MethodDefinition:
      case AST_NODE_TYPES.PropertyDefinition:
        return parent.computed;
      case AST_NODE_TYPES.ImportDefaultSpecifier:
      case AST_NODE_TYPES.ImportSpecifier:
      case AST_NODE_TYPES.ImportNamespaceSpecifier:
        return false; // the import's own binding; what is imported is checked as a specifier below
      case AST_NODE_TYPES.ExportSpecifier:
        return parent.local === node;
      case AST_NODE_TYPES.LabeledStatement:
      case AST_NODE_TYPES.BreakStatement:
      case AST_NODE_TYPES.ContinueStatement:
        return false;
      default:
        return true;
    }
  };
  /** `declare const Deno: T` (and `declare const globalThis: T`): an ambient type declaration, nothing at run time. */
  const isAmbientDeclaration = (): boolean => {
    const decl = stack[stack.length - 2];
    return stack[stack.length - 1]?.type === AST_NODE_TYPES.VariableDeclarator && decl?.type === AST_NODE_TYPES.VariableDeclaration && decl.declare === true;
  };

  /** True when `node` (the identifier `Deno`) is the root of exactly `Deno.env.get("<one string literal>")`. */
  const isSanctionedDenoChain = (): boolean => {
    const parent = stack[stack.length - 1];
    const grand = stack[stack.length - 2];
    const great = stack[stack.length - 3];
    return (
      parent?.type === AST_NODE_TYPES.MemberExpression &&
      !parent.computed &&
      propertyName(parent) === "env" &&
      grand?.type === AST_NODE_TYPES.MemberExpression &&
      grand.object === parent &&
      !grand.computed &&
      propertyName(grand) === "get" &&
      great?.type === AST_NODE_TYPES.CallExpression &&
      great.callee === grand &&
      great.arguments.length === 1 &&
      great.arguments[0]!.type === AST_NODE_TYPES.Literal &&
      typeof (great.arguments[0] as TSESTree.Literal).value === "string"
    );
  };

  /** openPool's one input: the const names in its body initialised from exactly `Deno.env.get("GOLFRAVEN_EDGE_DB_URL")`. */
  const poolUrlVariables = (fn: TSESTree.FunctionDeclaration): Set<string> => {
    const names = new Set<string>();
    for (const st of fn.body.body) {
      if (st.type !== AST_NODE_TYPES.VariableDeclaration || st.kind !== "const") continue;
      for (const d of st.declarations) {
        const init = d.init;
        if (
          d.id.type === AST_NODE_TYPES.Identifier &&
          init?.type === AST_NODE_TYPES.CallExpression &&
          isDenoEnvGet(init.callee) &&
          init.arguments.length === 1 &&
          init.arguments[0]!.type === AST_NODE_TYPES.Literal &&
          (init.arguments[0] as TSESTree.Literal).value === POOL_URL_VARIABLE
        ) {
          names.add(d.id.name);
        }
      }
    }
    return names;
  };

  /** A top-most `+` chain of string literals is ONE string (`"SET LOCAL " + "ROLE postgres"`): scan the folded text like any literal. */
  const isFoldedConcatRoot = (node: TSESTree.Node): node is TSESTree.BinaryExpression => {
    if (node.type !== AST_NODE_TYPES.BinaryExpression || constString(node) === undefined) return false;
    const parent = stack[stack.length - 1];
    return !(parent?.type === AST_NODE_TYPES.BinaryExpression && constString(parent) !== undefined);
  };

  const visit = (node: TSESTree.Node): void => {
    // ---- text-bearing nodes ----
    const t = textOf(node);
    if (t !== undefined) checkText(node, t);
    if (isFoldedConcatRoot(node)) checkText(node, constString(node)!);
    if (node.type === AST_NODE_TYPES.Identifier) checkText(node, node.name);

    // ---- privileged-env-access: `Deno` is an allow-list, not a shape list ----
    if (node.type === AST_NODE_TYPES.Identifier && node.name === "Deno" && isReference(node) && !isAmbientDeclaration()) {
      if (!isSanctionedDenoChain()) {
        add("privileged-env-access", node, "a reference to `Deno` other than the exact chain Deno.env.get(\"<string literal>\"): a destructure, an alias, a computed name or toObject() reads any variable (`const { env } = Deno`, `Deno.env.toObject()`)");
      }
    }

    // ---- privileged-global-access ----
    if (node.type === AST_NODE_TYPES.Identifier && isReference(node) && !isAmbientDeclaration()) {
      if (GLOBAL_OBJECTS.has(node.name)) {
        const parent = stack[stack.length - 1];
        const ok = parent?.type === AST_NODE_TYPES.MemberExpression && parent.object === node && !parent.computed && GLOBAL_MEMBER_ALLOWLIST.has(propertyName(parent) ?? "");
        if (!ok) add("privileged-global-access", node, `\`${node.name}\` other than ${[...GLOBAL_MEMBER_ALLOWLIST].map((m) => `${node.name}.${m}`).join(", ")}: the global object reaches \`Deno\` (\`globalThis.Deno.env.get(k)\`) and every other ambient capability by a name no scan sees`);
      } else if (CODE_BUILDERS.has(node.name)) {
        add("privileged-global-access", node, `\`${node.name}\`: it builds and runs code from a string, which can reach \`Deno\` with no name to match`);
      }
    }
    if (node.type === AST_NODE_TYPES.ImportExpression) {
      add("privileged-global-access", node, "dynamic import(): it can load code (a data: URL, another driver) that this pass never sees");
    }

    // ---- privileged-driver-import: createRequire (PR #34 LOW-1), `require(` and a dynamic import of the driver ----
    if (node.type === AST_NODE_TYPES.Identifier && node.name === "createRequire") {
      add("privileged-driver-import", node, "`createRequire`: it builds a require() that can load the driver (`createRequire(import.meta.url)(\"postgres\")`) or any module by a name no scan sees");
    }
    if (node.type === AST_NODE_TYPES.CallExpression && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === "require") {
      const a = node.arguments[0];
      const spec = a === undefined ? undefined : constString(a);
      if (spec === undefined || looksLikeDriver(spec)) add("privileged-driver-import", node, "`require(` of the driver or of a name that is not a literal: a second handle on the driver");
    }

    // ---- privileged-global-access: any `.Deno` member, wherever it appears (PR #34 LOW-1) ----
    if (node.type === AST_NODE_TYPES.MemberExpression && propertyName(node) === "Deno") {
      add("privileged-global-access", node, "a member access named `Deno` (`x.Deno`, `this.Deno`, `e.currentTarget.Deno`): an event's currentTarget or a function's `this` is the global object, which reaches `Deno.env` by a chain the Deno-identifier rule never sees");
    }
    if (node.type === AST_NODE_TYPES.ObjectPattern) {
      for (const p of node.properties) {
        if (p.type === AST_NODE_TYPES.Property && ((!p.computed && p.key.type === AST_NODE_TYPES.Identifier && p.key.name === "Deno") || (p.key.type === AST_NODE_TYPES.Literal && p.key.value === "Deno"))) {
          add("privileged-global-access", p, "a destructure that takes `Deno` off another object (`const { Deno: d } = e.currentTarget`): the same reach as `x.Deno`");
        }
      }
    }

    // ---- privileged-mint-scope: openScopedTx is called with a literal kind, and never aliased ----
    if (node.type === AST_NODE_TYPES.CallExpression && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === SCOPED_TX_FUNCTION) {
      const k = node.arguments[0];
      if (!(k !== undefined && ((k.type === AST_NODE_TYPES.Literal && typeof k.value === "string") || (k.type === AST_NODE_TYPES.TemplateLiteral && k.expressions.length === 0)))) {
        add("privileged-mint-scope", node, "openScopedTx( called with a kind that is not a string literal: the minter scope can only be checked when the kind is spelled out");
      }
    }
    if (node.type === AST_NODE_TYPES.Identifier && node.name === SCOPED_TX_FUNCTION && isReference(node) && !isAmbientDeclaration()) {
      const parent = stack[stack.length - 1];
      const isCallee = parent?.type === AST_NODE_TYPES.CallExpression && parent.callee === node;
      const isDeclaration = parent?.type === AST_NODE_TYPES.FunctionDeclaration && parent.id === node;
      if (!isCallee && !isDeclaration) add("privileged-mint-scope", node, "a reference to openScopedTx that is not a call (an alias, an argument): the literal-kind check cannot follow it");
    }

    // ---- privileged-computed-member ----
    if (node.type === AST_NODE_TYPES.MemberExpression && node.computed && !isPlainLiteralKey(node.property)) {
      add("privileged-computed-member", node, "computed member access with a key that is not a string or number literal: a key built at run time reaches any member (`db[\"be\" + \"gin\"]`) by a name no text scan sees");
    }
    if (node.type === AST_NODE_TYPES.ObjectPattern) {
      for (const p of node.properties) {
        if (p.type === AST_NODE_TYPES.Property && p.computed && !isPlainLiteralKey(p.key)) {
          add("privileged-computed-member", p, "a destructure with a computed key that is not a literal (`const { [k]: v } = obj`): the same run-time-named member access as `obj[k]`");
        }
      }
    }

    // ---- privileged-unsafe-sql ----
    if (node.type === AST_NODE_TYPES.MemberExpression && propertyName(node) === "unsafe") {
      const parent = stack[stack.length - 1];
      const call = parent?.type === AST_NODE_TYPES.CallExpression && parent.callee === node ? parent : undefined;
      const first = call?.arguments[0];
      // exactly the plain-literal shapes: a string literal or a hole-less template. A `+` of two literals is a BinaryExpression and is refused (its folded text is scanned separately).
      const literalCall = first !== undefined && ((first.type === AST_NODE_TYPES.Literal && typeof first.value === "string") || (first.type === AST_NODE_TYPES.TemplateLiteral && first.expressions.length === 0));
      if (!literalCall) {
        add("privileged-unsafe-sql", node, ".unsafe( with anything but a single string literal (or `unsafe` used in another shape): raw SQL assembled at run time (`\"SET LOCAL \" + \"ROLE postgres\"`) is invisible to the SQL-text rules");
      }
    }
    if (node.type === AST_NODE_TYPES.MemberExpression && propertyName(node) === "file") {
      add("privileged-unsafe-sql", node, ".file( : postgres.js runs a file as SQL, a raw-SQL entry point outside every SQL-text rule (the file is read at run time)");
    }
    if (node.type === AST_NODE_TYPES.ObjectPattern) {
      for (const p of node.properties) {
        if (p.type === AST_NODE_TYPES.Property && !p.computed && p.key.type === AST_NODE_TYPES.Identifier && (p.key.name === "unsafe" || p.key.name === "file")) {
          add("privileged-unsafe-sql", p, "`unsafe` destructured off a connection: the raw-SQL entry point, taken out of reach of the .unsafe( literal-argument rule");
        }
      }
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
      if (!inFunction(POOL_FUNCTIONS)) {
        add("privileged-stray-pool", node, "the postgres driver called outside openPool: a second pool is a second, unchecked way in (the edge self-check and every role assertion are on the one pool)");
      } else {
        // inside openPool the URL must be the constant read from GOLFRAVEN_EDGE_DB_URL in openPool itself, nothing a caller or another source supplies
        const first = node.arguments[0];
        const urlVars = poolUrlVariables(enclosing("openPool")!);
        if (!first || first.type !== AST_NODE_TYPES.Identifier || !urlVars.has(first.name)) {
          add("privileged-stray-pool", node, `the postgres driver in openPool is not handed the constant read from Deno.env.get("${POOL_URL_VARIABLE}") inside openPool: the pool's one input is that variable`);
        }
      }
    }
    // a reference to the driver that is not the callee of a call (an alias, an argument, a spread, a namespace member, a re-export): the call-site rule cannot see it
    if (node.type === AST_NODE_TYPES.Identifier && driverNames.has(node.name) && isReference(node) && !isAmbientDeclaration()) {
      const parent = stack[stack.length - 1];
      const isCallee = (parent?.type === AST_NODE_TYPES.CallExpression || parent?.type === AST_NODE_TYPES.NewExpression) && parent.callee === node;
      if (!isCallee) {
        add("privileged-stray-pool", node, `a reference to the postgres driver \`${node.name}\` that is not a call (\`const pg = ${node.name}; pg(url)\`): an alias is a pool the call-site rule never sees`);
      }
    }
    // openPool takes no URL: not in its declaration, not at any call
    if (node.type === AST_NODE_TYPES.FunctionDeclaration && node.id?.name === "openPool" && node.params.length > 0) {
      add("privileged-stray-pool", node, "openPool takes a parameter: it must take none and read GOLFRAVEN_EDGE_DB_URL itself, so no caller can point a pool at another database");
    }
    if ((node.type === AST_NODE_TYPES.CallExpression || node.type === AST_NODE_TYPES.NewExpression) && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === "openPool" && node.arguments.length > 0) {
      add("privileged-stray-pool", node, "openPool called with an argument: it takes none (a URL passed here is a pool opened on a database of the caller's choosing)");
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
  // one finding per (rule, place, message): a shorthand `{ Deno }` is visited as key and as value
  const seen = new Set<string>();
  return findings.filter((f) => {
    const k = `${f.rule}|${f.line}|${f.column}|${f.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** `Deno.env` (non-computed, the identifier `Deno`). */
function isDenoEnv(node: TSESTree.MemberExpression): boolean {
  return node.object.type === AST_NODE_TYPES.Identifier && node.object.name === "Deno" && propertyName(node) === "env";
}

/** `Deno.env.get` as a callee. */
function isDenoEnvGet(callee: TSESTree.Node): boolean {
  return callee.type === AST_NODE_TYPES.MemberExpression && propertyName(callee) === "get" && callee.object.type === AST_NODE_TYPES.MemberExpression && isDenoEnv(callee.object);
}
