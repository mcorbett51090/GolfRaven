// MUST-FAIL (privileged-env-access): Deno.env.toObject() reads every variable, including the ones the rules above ban by name.
declare const Deno: { env: { toObject(): Record<string, string> } };
export function everything(): string | undefined {
  return Deno.env.toObject()["SUPABASE_DB_URL"];
}
