// MUST-FAIL (MEDIUM 3 re-gate, bypass 1): `(Deno as any).env.get(...)` —
// the TSAsExpression wrapping `Deno` means the call's callee is no longer
// the EXACT `Deno.env.get` shape (the innermost object is a TSAsExpression,
// not a bare Identifier), so the old pattern-matching check never saw it.
export function readSecret() {
  return (Deno as any).env.get("SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
