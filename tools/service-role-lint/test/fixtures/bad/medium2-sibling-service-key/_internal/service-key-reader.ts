// ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): the sibling file a real
// function's plain relative import pulls in. This file's OWN content —
// a literal read of the service-role key — is what a directory-based
// exclusion used to hide from the lint entirely, regardless of the
// (perfectly ordinary-looking) import statement in ../index.ts that
// reaches it. Must be flagged (literal-secret-env-var) on its own, by
// the walker discovering this file directly, not by any special-casing
// of the importing file.
declare const Deno: { env: { get(name: string): string | undefined } };

export function readServiceKey(): string | undefined {
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
}
