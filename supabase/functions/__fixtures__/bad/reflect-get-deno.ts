// MUST-FAIL (MEDIUM 3 re-gate, bypass 3): `Reflect.get(Deno, "env")` reads
// the env object off Deno without ever writing a `.env` member access at
// all — `Deno` appears only as a plain call argument.
export function readSecret() {
  const env = Reflect.get(Deno, "env") as { get(name: string): string | undefined };
  return env.get("SUPABASE_SERVICE_ROLE_KEY");
}

declare const Deno: { env: { get(name: string): string | undefined } };
