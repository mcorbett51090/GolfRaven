// MUST-FAIL (MEDIUM 3 re-gate, bypass 8): `(0, Deno.env.get)(...)` — the
// classic "detach this from its receiver" sequence-expression trick. The
// CallExpression's callee is a SequenceExpression wrapping the member
// expression, not the member expression itself, so an exact-callee-shape
// check never matches — but the `Deno` identifier is still right there in
// the source for a reference-based check to find.
export function readSecret() {
  return (0, Deno.env.get)("SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
