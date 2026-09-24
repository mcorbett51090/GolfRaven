// MUST-FAIL: the service-role client is constructed once, then assigned
// to a SECOND variable — a lint that only tracks the ORIGINAL binding
// name would miss every privileged call made through the alias.
import { createClient } from "@supabase/supabase-js";

const rawClient = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
const db = rawClient; // alias
const handle = db; // alias of an alias — must still be tracked (transitive)

export async function voidPlay(playId: string) {
  return handle.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
