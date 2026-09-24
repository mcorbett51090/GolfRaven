// MUST-FAIL: `new SupabaseClient(...)` instead of the `createClient(...)`
// factory function — the SAME client class, constructed a different way.
import { SupabaseClient } from "@supabase/supabase-js";

const client = new SupabaseClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
