// MUST-FAIL (M3(4), post-P3a gate): a raw fetch() built by hand, carrying
// a service-role key read straight from env as a Bearer token -- no
// createClient/SupabaseClient construction at all, so the existing
// service-role-construction rule never sees it.
export async function callInternalApi() {
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  return fetch("https://internal.example.com/admin", {
    headers: { Authorization: `Bearer ${key}` },
  });
}

declare const Deno: { env: { get(name: string): string | undefined } };
declare function fetch(url: string, init?: unknown): Promise<unknown>;
