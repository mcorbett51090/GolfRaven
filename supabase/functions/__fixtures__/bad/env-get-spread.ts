// MUST-FAIL (MEDIUM 3 re-gate, bypass 7): the key is passed via a spread
// array, not a plain string literal argument — `Deno.env.get(...args)` —
// so a check requiring `arguments[0]` to BE a Literal never resolves a
// key, and (crucially) still must not silently pass just because the
// argument isn't a recognizable literal.
const args: [string] = ["SUPABASE_SERVICE_ROLE_KEY"];

export function readSecret() {
  return Deno.env.get(...args);
}

declare const Deno: { env: { get(name: string): string | undefined } };
