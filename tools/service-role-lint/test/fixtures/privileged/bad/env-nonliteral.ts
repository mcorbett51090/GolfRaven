// MUST-FAIL (privileged-env-access): a computed variable name could build SUPABASE_DB_URL or the service-role key at run time.
declare const Deno: { env: { get(name: string): string | undefined } };
export function computed(which: string): string | undefined {
  return Deno.env.get("SUPABASE_" + which);
}
