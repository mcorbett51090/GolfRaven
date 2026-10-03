// MUST-FAIL (privileged-env-access): `Deno` taken apart. `const { env } = Deno` is itself a reference to `Deno` (no `Deno.env.get("<literal>")` chain), and the name that
// follows it can be computed, so the SUPABASE_DB_URL / service-role-key rules never see the string. (edge role PR4c, LOW-1)
declare const Deno: { env: { get(name: string): string | undefined } };
export function viaDestructure(suffix: string): string | undefined {
  const { env } = Deno;
  return env.get("SUPABASE_" + suffix);
}
