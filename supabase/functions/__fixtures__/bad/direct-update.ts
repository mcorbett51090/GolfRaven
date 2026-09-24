// MUST-FAIL fixture: a service-role client constructed OUTSIDE
// privileged.ts (rule a), then a `.from().update()` call made OUTSIDE any
// withOwnership() callback (rule b).
import { createClient } from "@supabase/supabase-js";

const client = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
);

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
