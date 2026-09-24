// MUST-FAIL (MEDIUM 3 re-gate, bypass 11): `@supabase/postgrest-js` is
// its own package under the @supabase scope — the old BANNED_PACKAGE_NAMES
// set only named "@supabase/supabase-js" specifically (plus an
// endsWith("supabase-js") catch-all, which "@supabase/postgrest-js" does
// not match either), so this whole other client-construction surface
// sailed through. The fix bans the WHOLE @supabase/* scope.
import { PostgrestClient } from "@supabase/postgrest-js";

const client = new PostgrestClient("https://example.supabase.co/rest/v1", {
  headers: { Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}` },
});

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
