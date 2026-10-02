// MUST-FAIL (privileged-service-key): the service-role key read in a function that is neither adminClient nor isServiceRoleBearer.
declare const Deno: { env: { get(name: string): string | undefined } };
export function leak(): string {
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
}
