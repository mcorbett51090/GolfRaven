// MUST-FAIL (M3(2), post-P3a gate): destructuring `env` off Deno first
// hides the read from a check that only pattern-matches the literal
// shape `Deno.env.get(...)` / `<X>.env.get(...)`.
const { env } = Deno;

export function readSecret() {
  return env.get("SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
