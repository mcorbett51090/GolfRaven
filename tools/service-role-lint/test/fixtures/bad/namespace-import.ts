// MUST-FAIL: a NAMESPACE import — `supa.createClient(...)` never appears
// as a bare `createClient(...)` call anywhere in this file.
import * as supa from "@supabase/supabase-js";

const client = supa.createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
