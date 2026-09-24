// MUST-FAIL: an ALIASED import of createClient — `cc` is not the literal
// name "createClient", so a naive name-grep (or a lint that only tracks
// the literal identifier "createClient") would miss this.
import { createClient as cc } from "@supabase/supabase-js";

const client = cc(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
