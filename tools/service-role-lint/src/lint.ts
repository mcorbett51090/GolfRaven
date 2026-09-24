// tools/service-role-lint/src/lint.ts
//
// AST-based check over the TS/JS in supabase/functions/** (build plan
// §4.7.1a, docs/golf-trails/02-build-plan.md:1197-1205), hardened against
// the bypasses named in the gate-round-2 review (B5):
//   - aliased and namespace imports;
//   - re-exports;
//   - `new SupabaseClient`;
//   - dynamic `import()`;
//   - any specifier ending in `supabase-js`, or naming a Postgres driver
//     (`npm:postgres`, `npm:pg`, `jsr:@db/postgres`, `deno.land/x/postgres`,
//     plain `pg`/`postgres`/`postgres.js`/`pg-promise`);
//   - service keys / DB URLs read through a variable, a template, or
//     concatenation (ANY non-literal env access is flagged, and any
//     literal naming SERVICE_ROLE / DB_URL);
//   - `globalThis` access;
//   - a local `withOwnership` shadowing the real one;
//   - aliasing a client variable (taint propagates through simple
//     identifier-to-identifier assignment, transitively).
//
// The exemption for `supabase/functions/_shared/privileged.ts` is an
// EXACT path-segment match, not an `endsWith` string check — a file named
// e.g. `evil_shared/privileged.ts` must NOT be exempted just because the
// string "_shared/privileged.ts" is a suffix of its path.
//
// Uses a real parser (@typescript-eslint/typescript-estree, pinned) rather
// than a method-name grep, per the plan's own explicit requirement.

import { AST_NODE_TYPES, parse, type TSESTree } from "@typescript-eslint/typescript-estree";

export type RuleId =
  | "service-role-construction"
  | "privileged-call-outside-withOwnership"
  | "db-url-or-driver"
  | "banned-import-specifier"
  | "non-literal-env-access"
  | "literal-secret-env-var"
  | "globalthis-access"
  | "withownership-shadowed"
  | "reexport-of-privileged-symbol"
  | "parse-error";

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

/** The one exact file allowed to do any of this (build plan line 1189). */
const EXEMPT_SEGMENTS = ["supabase", "functions", "_shared", "privileged.ts"];

/** Env var name substrings that mark a client/URL as privileged (case-insensitive). */
const SECRET_ENV_MARKERS = ["SERVICE_ROLE", "DB_URL"];

/** Import specifiers that construct or re-expose a Supabase / raw-Postgres client. */
const BANNED_SPECIFIER_PATTERNS: RegExp[] = [
  /supabase-js$/, // any specifier ending in "supabase-js" (covers esm.sh/jsr/npm: prefixes too)
  /^npm:postgres$/,
  /^npm:pg$/,
  /^jsr:@db\/postgres$/,
  /^deno\.land\/x\/postgres/,
  /^pg$/,
  /^postgres$/,
  /^postgres\.js$/,
  /^pg-promise$/,
];

function isAllowedFile(filePath: string): boolean {
  const segments = filePath.split(/[\\/]/).filter(Boolean);
  if (segments.length < EXEMPT_SEGMENTS.length) return false;
  const tail = segments.slice(-EXEMPT_SEGMENTS.length);
  return tail.every((seg, i) => seg === EXEMPT_SEGMENTS[i]);
}

function nodeLoc(node: TSESTree.Node): { line: number; column: number } {
  return { line: node.loc?.start.line ?? 0, column: node.loc?.start.column ?? 0 };
}

function isBannedSpecifier(spec: string): boolean {
  return BANNED_SPECIFIER_PATTERNS.some((re) => re.test(spec));
}

function mentionsSecretEnvVar(text: string): boolean {
  const upper = text.toUpperCase();
  return SECRET_ENV_MARKERS.some((m) => upper.includes(m));
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

function isCreateClientCallee(callee: TSESTree.Expression, createClientLocalNames: Set<string>, namespaceImportNames: Set<string>): boolean {
  if (callee.type === AST_NODE_TYPES.Identifier) {
    return createClientLocalNames.has(callee.name);
  }
  if (callee.type === AST_NODE_TYPES.MemberExpression && callee.property.type === AST_NODE_TYPES.Identifier) {
    if (callee.object.type === AST_NODE_TYPES.Identifier && namespaceImportNames.has(callee.object.name)) {
      return callee.property.name === "createClient";
    }
  }
  return false;
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
    return [{ rule: "parse-error", message: `failed to parse ${filePath}: ${(err as Error).message}`, line: 0, column: 0 }];
  }

  // ---------------------------------------------------------------------
  // Pass 1: import/re-export/dynamic-import bookkeeping.
  // ---------------------------------------------------------------------
  const createClientLocalNames = new Set<string>(); // e.g. `createClient`, or an alias of it
  const supabaseClientLocalNames = new Set<string>(); // `SupabaseClient` class import, aliased or not
  const namespaceImportNames = new Set<string>(); // `import * as x from "<supabase-js>"`

  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.ImportDeclaration) {
      const spec = node.source.value;
      const banned = typeof spec === "string" && isBannedSpecifier(spec);
      if (typeof spec === "string" && banned) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "banned-import-specifier",
          message: `import from a banned specifier "${spec}" (Supabase client or raw Postgres driver) outside supabase/functions/_shared/privileged.ts`,
          ...loc,
        });
        for (const spec2 of node.specifiers) {
          if (spec2.type === AST_NODE_TYPES.ImportSpecifier) {
            const importedName = spec2.imported.type === AST_NODE_TYPES.Identifier ? spec2.imported.name : String(spec2.imported.value);
            if (importedName === "createClient") createClientLocalNames.add(spec2.local.name);
            if (importedName === "SupabaseClient") supabaseClientLocalNames.add(spec2.local.name);
          } else if (spec2.type === AST_NODE_TYPES.ImportDefaultSpecifier) {
            // `import postgres from "postgres"` — the default export IS the
            // client-constructing function; treat the local binding itself
            // as a createClient-equivalent name.
            createClientLocalNames.add(spec2.local.name);
          } else if (spec2.type === AST_NODE_TYPES.ImportNamespaceSpecifier) {
            namespaceImportNames.add(spec2.local.name);
          }
        }
      } else if (typeof spec === "string") {
        // Not a banned specifier, but still track createClient/SupabaseClient
        // bindings from ANY import (aliasing doesn't require the specifier
        // itself to be banned if re-exported through an intermediate
        // module — best-effort: we still catch the local alias name).
        for (const spec2 of node.specifiers) {
          if (spec2.type === AST_NODE_TYPES.ImportSpecifier) {
            const importedName = spec2.imported.type === AST_NODE_TYPES.Identifier ? spec2.imported.name : String(spec2.imported.value);
            if (importedName === "createClient") createClientLocalNames.add(spec2.local.name);
            if (importedName === "SupabaseClient") supabaseClientLocalNames.add(spec2.local.name);
          }
        }
      }
    }

    // Re-exports: `export { createClient } from "<banned>"` / `export * from "<banned>"`.
    if (
      (node.type === AST_NODE_TYPES.ExportNamedDeclaration || node.type === AST_NODE_TYPES.ExportAllDeclaration) &&
      node.source &&
      typeof node.source.value === "string" &&
      isBannedSpecifier(node.source.value)
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "reexport-of-privileged-symbol",
        message: `re-exports from a banned specifier "${node.source.value}" outside supabase/functions/_shared/privileged.ts`,
        ...loc,
      });
    }

    // Dynamic import(): `import("@supabase/supabase-js")`, `import("npm:pg")`.
    if (node.type === AST_NODE_TYPES.ImportExpression) {
      const arg = node.source;
      if (arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string" && isBannedSpecifier(arg.value)) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "banned-import-specifier",
          message: `dynamic import("${arg.value}") of a banned specifier outside supabase/functions/_shared/privileged.ts`,
          ...loc,
        });
      } else if (arg.type !== AST_NODE_TYPES.Literal) {
        // A dynamic import whose specifier isn't even a literal is
        // inherently unauditable by this static check — flag it too.
        const loc = nodeLoc(node);
        findings.push({
          rule: "banned-import-specifier",
          message: "dynamic import() with a non-literal specifier — cannot verify it isn't a Supabase/Postgres client; flagged outside supabase/functions/_shared/privileged.ts",
          ...loc,
        });
      }
    }

    // require("pg") / require("@supabase/supabase-js") (CJS interop).
    if (node.type === AST_NODE_TYPES.CallExpression && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === "require") {
      const arg = node.arguments[0];
      if (arg && arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string" && isBannedSpecifier(arg.value)) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "banned-import-specifier",
          message: `require("${arg.value}") of a banned specifier outside supabase/functions/_shared/privileged.ts`,
          ...loc,
        });
      }
    }

    // globalThis access, anywhere.
    if (node.type === AST_NODE_TYPES.Identifier && node.name === "globalThis") {
      const loc = nodeLoc(node);
      findings.push({
        rule: "globalthis-access",
        message: "reference to globalThis outside supabase/functions/_shared/privileged.ts",
        ...loc,
      });
    }

    // A local withOwnership shadowing the real helper (function decl, or
    // any variable/const bound to that name).
    if (
      (node.type === AST_NODE_TYPES.FunctionDeclaration && node.id?.name === "withOwnership") ||
      (node.type === AST_NODE_TYPES.VariableDeclarator && node.id.type === AST_NODE_TYPES.Identifier && node.id.name === "withOwnership")
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "withownership-shadowed",
        message: "a local declaration named withOwnership shadows the real helper from supabase/functions/_shared/privileged.ts",
        ...loc,
      });
    }
  });

  // ---------------------------------------------------------------------
  // Pass 2: env var access — non-literal (any) and literal-secret.
  // ---------------------------------------------------------------------
  walk(ast, (node) => {
    // <obj>.env.get(<arg>) — Deno.env.get(...) or an aliased/namespaced form.
    if (
      node.type === AST_NODE_TYPES.CallExpression &&
      node.callee.type === AST_NODE_TYPES.MemberExpression &&
      node.callee.property.type === AST_NODE_TYPES.Identifier &&
      node.callee.property.name === "get" &&
      node.callee.object.type === AST_NODE_TYPES.MemberExpression &&
      node.callee.object.property.type === AST_NODE_TYPES.Identifier &&
      node.callee.object.property.name === "env"
    ) {
      const arg = node.arguments[0];
      const loc = nodeLoc(node);
      if (!arg || arg.type !== AST_NODE_TYPES.Literal || typeof arg.value !== "string") {
        findings.push({
          rule: "non-literal-env-access",
          message: "environment variable read with a non-literal argument (variable, template, or concatenation) — cannot verify which secret this reads",
          ...loc,
        });
      } else if (mentionsSecretEnvVar(arg.value)) {
        findings.push({
          rule: "literal-secret-env-var",
          message: `environment variable read names a service-role/DB-URL secret ("${arg.value}")`,
          ...loc,
        });
      }
    }

    // process.env.FOO (static member) / process.env["FOO"] or process.env[x] (computed).
    if (
      node.type === AST_NODE_TYPES.MemberExpression &&
      node.object.type === AST_NODE_TYPES.MemberExpression &&
      node.object.property.type === AST_NODE_TYPES.Identifier &&
      node.object.property.name === "env"
    ) {
      const loc = nodeLoc(node);
      if (!node.computed && node.property.type === AST_NODE_TYPES.Identifier) {
        if (mentionsSecretEnvVar(node.property.name)) {
          findings.push({
            rule: "literal-secret-env-var",
            message: `process.env.${node.property.name} names a service-role/DB-URL secret`,
            ...loc,
          });
        }
      } else if (node.computed) {
        const prop = node.property;
        if (prop.type === AST_NODE_TYPES.Literal && typeof prop.value === "string") {
          if (mentionsSecretEnvVar(prop.value)) {
            findings.push({
              rule: "literal-secret-env-var",
              message: `process.env["${prop.value}"] names a service-role/DB-URL secret`,
              ...loc,
            });
          }
        } else {
          findings.push({
            rule: "non-literal-env-access",
            message: "process.env[...] accessed with a non-literal key — cannot verify which secret this reads",
            ...loc,
          });
        }
      }
    }
  });

  // ---------------------------------------------------------------------
  // Pass 3: service-role client construction (createClient / new
  // SupabaseClient), with alias-taint propagated transitively.
  // ---------------------------------------------------------------------
  const serviceRoleIdentifiers = new Set<string>();
  const withOwnershipCallbackRanges: Array<[number, number]> = [];

  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.CallExpression && isCreateClientCallee(node.callee, createClientLocalNames, namespaceImportNames)) {
      const usesServiceRole = node.arguments.some((arg) => {
        let found = false;
        walk(arg, (n) => {
          if (found) return;
          if (n.type === AST_NODE_TYPES.Literal && typeof n.value === "string" && mentionsSecretEnvVar(n.value)) found = true;
          if (n.type === AST_NODE_TYPES.Identifier && mentionsSecretEnvVar(n.name)) found = true;
        });
        return found;
      });
      if (usesServiceRole) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "service-role-construction",
          message: "createClient(...) with a service-role key/env-var is constructed outside supabase/functions/_shared/privileged.ts",
          ...loc,
        });
      }
    }

    if (
      node.type === AST_NODE_TYPES.NewExpression &&
      node.callee.type === AST_NODE_TYPES.Identifier &&
      supabaseClientLocalNames.has(node.callee.name)
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "service-role-construction",
        message: "new SupabaseClient(...) constructed outside supabase/functions/_shared/privileged.ts",
        ...loc,
      });
    }

    if (
      node.type === AST_NODE_TYPES.VariableDeclarator &&
      node.id.type === AST_NODE_TYPES.Identifier &&
      node.init &&
      ((node.init.type === AST_NODE_TYPES.CallExpression &&
        isCreateClientCallee(node.init.callee, createClientLocalNames, namespaceImportNames)) ||
        (node.init.type === AST_NODE_TYPES.NewExpression &&
          node.init.callee.type === AST_NODE_TYPES.Identifier &&
          supabaseClientLocalNames.has(node.init.callee.name)))
    ) {
      serviceRoleIdentifiers.add(node.id.name);
    }

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

  // Alias propagation: `const alias = client;` taints `alias` too, for any
  // identifier already known to hold a service-role client. Fixed-point
  // over a few passes (handles chained aliasing: a -> b -> c).
  for (let pass = 0; pass < 5; pass++) {
    let added = false;
    walk(ast, (node) => {
      if (
        node.type === AST_NODE_TYPES.VariableDeclarator &&
        node.id.type === AST_NODE_TYPES.Identifier &&
        node.init &&
        node.init.type === AST_NODE_TYPES.Identifier &&
        serviceRoleIdentifiers.has(node.init.name) &&
        !serviceRoleIdentifiers.has(node.id.name)
      ) {
        serviceRoleIdentifiers.add(node.id.name);
        added = true;
      }
      if (
        node.type === AST_NODE_TYPES.AssignmentExpression &&
        node.left.type === AST_NODE_TYPES.Identifier &&
        node.right.type === AST_NODE_TYPES.Identifier &&
        serviceRoleIdentifiers.has(node.right.name) &&
        !serviceRoleIdentifiers.has(node.left.name)
      ) {
        serviceRoleIdentifiers.add(node.left.name);
        added = true;
      }
    });
    if (!added) break;
  }

  const insideWithOwnership = (node: TSESTree.Node): boolean => {
    if (!node.range) return false;
    return withOwnershipCallbackRanges.some(([start, end]) => node.range![0] >= start && node.range![1] <= end);
  };

  // ---------------------------------------------------------------------
  // Pass 4: any call on a privileged (service-role) handle outside a
  // withOwnership callback.
  // ---------------------------------------------------------------------
  walk(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.CallExpression) return;
    if (node.callee.type !== AST_NODE_TYPES.MemberExpression) return;

    const callee = node.callee;
    const methodName = callee.property.type === AST_NODE_TYPES.Identifier ? callee.property.name : undefined;

    let base: TSESTree.Node = callee.object;
    for (;;) {
      if (base.type === AST_NODE_TYPES.MemberExpression) {
        base = base.object;
        continue;
      }
      if (base.type === AST_NODE_TYPES.CallExpression && base.callee.type === AST_NODE_TYPES.MemberExpression) {
        base = base.callee.object;
        continue;
      }
      break;
    }
    if (base.type !== AST_NODE_TYPES.Identifier || !serviceRoleIdentifiers.has(base.name)) return;

    const isPrivilegedMethod =
      methodName === "from" ||
      methodName === "rpc" ||
      methodName === "upload" ||
      methodName === "remove" ||
      methodName === "update" ||
      methodName === "upsert" ||
      methodName === "insert" ||
      methodName === "delete" ||
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

  // ---------------------------------------------------------------------
  // Pass 5: raw Postgres driver import / SUPABASE_DB_URL reference
  // (independent of the specifier check above — this also catches an
  // in-file textual reference that isn't tied to an import).
  // ---------------------------------------------------------------------
  walk(ast, (node) => {
    if (
      (node.type === AST_NODE_TYPES.Literal && typeof node.value === "string" && node.value.toUpperCase().includes("DB_URL")) ||
      (node.type === AST_NODE_TYPES.Identifier && node.name.toUpperCase().includes("DB_URL"))
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "db-url-or-driver",
        message: "reference to a DB_URL-named environment variable outside supabase/functions/_shared/privileged.ts",
        ...loc,
      });
    }
  });

  return findings;
}
