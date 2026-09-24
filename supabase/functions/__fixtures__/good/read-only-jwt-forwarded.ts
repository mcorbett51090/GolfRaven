// Clean fixture: a plain, JWT-forwarded read (RLS applies as it would for
// the app, §4.7.1a: "Reads inside functions use a JWT-forwarded client, so
// RLS applies to them as it does to the app"). No service-role client, no
// privileged call, no withOwnership needed.
import { createClient } from "@supabase/supabase-js";

export function readOwnProfile(jwt: string) {
  const client = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_ANON_KEY") ?? "",
    { global: { headers: { Authorization: `Bearer ${jwt}` } } },
  );
  return client.from("profile").select("*");
}

declare const Deno: { env: { get(name: string): string | undefined } };
