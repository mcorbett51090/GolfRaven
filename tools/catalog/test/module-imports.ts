/**
 * A real-lexer import enumerator (no regexes over source text), used to hold
 * `src/manifest-core.ts` to its platform-neutral contract.
 *
 * It tokenises with TypeScript's own scanner (`typescript/unstable/ast/scanner`;
 * TypeScript 7 no longer exposes `ts.preProcessFile` / the compiler API from
 * the package root, and this subpath is the scanner TypeScript itself ships —
 * `typescript` is pinned exactly in package.json so an "unstable" change cannot
 * arrive unannounced). Because it works on TOKENS, comments, string contents
 * and whitespace can neither hide an import nor fake one — the failure mode of
 * the line-and-regex check this replaces (a comment before an import, `from "crypto"`
 * with no `node:` prefix, a bare `import "node:fs"`, a dynamic `import()`).
 *
 * It is a lexer, not a parser: it recognises the token shapes of
 *   import … from "x"          import "x"          import("x")
 *   export … from "x"          require("x")        import a = require("x")
 * and records a dynamic `import(expr)` / `require(expr)` whose argument is not
 * a plain string literal with `specifier: null` (unauditable => a violation).
 */
import { SyntaxKind } from "typescript/unstable/ast";
import { createScanner, tokenIsIdentifierOrKeyword } from "typescript/unstable/ast/scanner";

export type ImportKind = "import" | "export-from" | "dynamic-import" | "require";
export interface ImportRef {
  kind: ImportKind;
  /** The module specifier, or `null` when it is not a plain string literal. */
  specifier: string | null;
}
interface Tok {
  kind: SyntaxKind;
  text: string;
  /** The string's value for string-ish tokens. */
  value: string;
}

/** All non-trivia tokens of `text`, with template literals and regex literals
 * re-scanned so their contents are never mistaken for code. */
export function tokenize(text: string): Tok[] {
  const scanner = createScanner(true, undefined, text);
  const out: Tok[] = [];
  /** `true` = a template substitution is open at this depth; `false` = a plain `{`. */
  const braces: boolean[] = [];
  const endsExpression = (k: SyntaxKind | undefined): boolean =>
    k === SyntaxKind.Identifier ||
    k === SyntaxKind.CloseParenToken ||
    k === SyntaxKind.CloseBracketToken ||
    k === SyntaxKind.CloseBraceToken ||
    k === SyntaxKind.NumericLiteral ||
    k === SyntaxKind.StringLiteral ||
    k === SyntaxKind.NoSubstitutionTemplateLiteral ||
    k === SyntaxKind.TemplateTail ||
    k === SyntaxKind.ThisKeyword ||
    k === SyntaxKind.SuperKeyword ||
    k === SyntaxKind.TrueKeyword ||
    k === SyntaxKind.FalseKeyword ||
    k === SyntaxKind.NullKeyword;
  for (;;) {
    let k = scanner.scan();
    if (k === SyntaxKind.EndOfFile) break;
    const prev = out[out.length - 1]?.kind;
    if ((k === SyntaxKind.SlashToken || k === SyntaxKind.SlashEqualsToken) && !endsExpression(prev)) k = scanner.reScanSlashToken();
    if (k === SyntaxKind.CloseBraceToken && braces[braces.length - 1] === true) {
      braces.pop();
      k = scanner.reScanTemplateToken(false); // `}` continues the template: TemplateMiddle | TemplateTail
      if (k === SyntaxKind.TemplateMiddle) braces.push(true);
    } else if (k === SyntaxKind.CloseBraceToken) {
      braces.pop();
    } else if (k === SyntaxKind.OpenBraceToken) {
      braces.push(false);
    } else if (k === SyntaxKind.TemplateHead) {
      braces.push(true);
    }
    out.push({ kind: k, text: scanner.getTokenText(), value: scanner.getTokenValue() });
  }
  return out;
}

/** Every module reference in `text`. */
export function enumerateImports(text: string): ImportRef[] {
  const toks = tokenize(text);
  const refs: ImportRef[] = [];
  const at = (i: number): Tok | undefined => toks[i];
  const isStr = (t: Tok | undefined): t is Tok => t?.kind === SyntaxKind.StringLiteral || t?.kind === SyntaxKind.NoSubstitutionTemplateLiteral;
  const afterDot = (i: number): boolean => at(i - 1)?.kind === SyntaxKind.DotToken || at(i - 1)?.kind === SyntaxKind.QuestionDotToken;

  for (let i = 0; i < toks.length; i += 1) {
    const t = toks[i]!;
    if (afterDot(i)) continue; // `x.import`, `x.require`: a property, not the keyword
    if (t.kind === SyntaxKind.ImportKeyword) {
      const n = at(i + 1);
      if (n?.kind === SyntaxKind.OpenParenToken) {
        const arg = at(i + 2);
        refs.push({ kind: "dynamic-import", specifier: isStr(arg) && at(i + 3)?.kind !== SyntaxKind.PlusToken ? arg.value : null });
      } else if (n?.kind === SyntaxKind.DotToken) {
        // import.meta — not a module reference
      } else if (isStr(n)) {
        refs.push({ kind: "import", specifier: n.value }); // import "x"
      } else {
        // import [type] <clause> from "x"   |   import a = require("x") (caught by the `require` rule)
        for (let j = i + 1; j < toks.length; j += 1) {
          const u = toks[j]!;
          if (u.kind === SyntaxKind.FromKeyword && isStr(at(j + 1))) {
            refs.push({ kind: "import", specifier: at(j + 1)!.value });
            break;
          }
          if (u.kind === SyntaxKind.SemicolonToken || u.kind === SyntaxKind.EqualsToken) break;
        }
      }
    } else if (t.kind === SyntaxKind.ExportKeyword) {
      let j = i + 1;
      if (at(j)?.kind === SyntaxKind.TypeKeyword) j += 1;
      if (at(j)?.kind === SyntaxKind.AsteriskToken) {
        j += 1;
        if (at(j)?.kind === SyntaxKind.AsKeyword) j += 2; // export * as ns
      } else if (at(j)?.kind === SyntaxKind.OpenBraceToken) {
        let depth = 0;
        for (; j < toks.length; j += 1) {
          if (toks[j]!.kind === SyntaxKind.OpenBraceToken) depth += 1;
          if (toks[j]!.kind === SyntaxKind.CloseBraceToken && (depth -= 1) === 0) break;
        }
        j += 1;
      } else {
        continue; // export const / function / class / default …: no module reference
      }
      if (at(j)?.kind === SyntaxKind.FromKeyword && isStr(at(j + 1))) refs.push({ kind: "export-from", specifier: at(j + 1)!.value });
    } else if (tokenIsIdentifierOrKeyword(t.kind) && t.text === "require" && at(i + 1)?.kind === SyntaxKind.OpenParenToken) {
      const arg = at(i + 2);
      refs.push({ kind: "require", specifier: isStr(arg) && at(i + 3)?.kind === SyntaxKind.CloseParenToken ? arg.value : null });
    }
  }
  return refs;
}

/** Identifiers (never inside comments or strings) that must not appear at all. */
export function forbiddenIdentifiers(text: string, names: readonly string[]): string[] {
  const toks = tokenize(text);
  const hits: string[] = [];
  toks.forEach((t, i) => {
    if (!tokenIsIdentifierOrKeyword(t.kind) || !names.includes(t.text)) return;
    const p = toks[i - 1]?.kind;
    if (p === SyntaxKind.DotToken || p === SyntaxKind.QuestionDotToken) return; // `x.process`
    hits.push(t.text);
  });
  return hits;
}

/** The neutrality verdict for one source text: every violation, or `[]`. */
export function neutralityViolations(text: string, allowedSpecifiers: readonly string[]): string[] {
  const out: string[] = [];
  for (const r of enumerateImports(text)) {
    if (r.specifier === null) out.push(`${r.kind} with a non-literal specifier (cannot be audited)`);
    else if (!allowedSpecifiers.includes(r.specifier)) out.push(`${r.kind} of "${r.specifier}" (only ${allowedSpecifiers.map((s) => `"${s}"`).join(", ")} is allowed)`);
    else if (r.kind === "require" || r.kind === "dynamic-import") out.push(`${r.kind} of "${r.specifier}" (only static imports are allowed)`);
  }
  for (const id of forbiddenIdentifiers(text, ["Buffer", "process", "require"])) out.push(`identifier ${id} (a Node global)`);
  return out;
}
