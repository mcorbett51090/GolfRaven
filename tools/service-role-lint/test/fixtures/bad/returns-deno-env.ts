// MUST-FAIL (MEDIUM 3 re-gate, bypass 2): a function that returns
// `Deno.env` itself, handing the caller the whole env object instead of
// a single .get() call — never matches a ".env.get(...)" call-shaped
// check at all.
export function grabEnv() {
  return Deno.env;
}

export function readSecret() {
  return grabEnv().get("SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
