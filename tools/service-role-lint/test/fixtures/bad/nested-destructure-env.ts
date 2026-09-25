// MUST-FAIL (MEDIUM 3 re-gate, bypass 6): nested destructuring pulls the
// getter out from two levels down in one pattern — `const { env: { get: g
// } } = Deno;` — no `.env.get` member-access chain ever appears in the
// source text at all.
const {
  env: { get: g },
} = Deno;

export function readSecret() {
  return g("SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
