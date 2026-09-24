// MUST-FAIL (post-P3a re-gate M1, case g2a): an unlisted host (ga.jspm.io)
// carrying an embedded "npm:" scheme after the host, not at the start of
// the specifier string.
import { createClient } from "https://ga.jspm.io/npm:@supabase/supabase-js@2.45.0/dist/module/index.js";

const client = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
