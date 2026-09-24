// MUST-FAIL (post-P3a re-gate M1, case g2b): esm.sh's "*" (external all
// deps) marker sits directly before "@supabase", shifting normalization.
import { createClient } from "https://esm.sh/*@supabase/supabase-js@2";

const client = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
