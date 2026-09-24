// MUST-FAIL (MEDIUM 3 re-gate, bypass 4): `Deno["env"]` — computed member
// access instead of `.env`, so a check requiring the literal `.env`
// property never matches, even though `.get(...)` is called right after.
export function readSecret() {
  return Deno["env"].get("SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
