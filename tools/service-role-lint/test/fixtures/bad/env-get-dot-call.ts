// MUST-FAIL (MEDIUM 3 re-gate, bypass 5): `Deno.env.get.call(...)` — an
// extra `.call` hop means the outer CallExpression's callee is
// `Deno.env.get.call`, not `Deno.env.get` itself, so an exact-shape check
// on the callee alone misses it.
export function readSecret() {
  return Deno.env.get.call(Deno.env, "SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
