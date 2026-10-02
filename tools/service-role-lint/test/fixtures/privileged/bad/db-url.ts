// MUST-FAIL (privileged-db-url): a read of SUPABASE_DB_URL, the old service_role pool's only input.
declare const Deno: { env: { get(name: string): string | undefined } };
export function legacyUrl(): string | undefined {
  return Deno.env.get("SUPABASE_DB_URL");
}
