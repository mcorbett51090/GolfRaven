// MUST-FAIL (post-P3a re-gate M1, case g5): a relative import that walks
// OUTSIDE supabase/functions entirely — never caught by a check that only
// inspects each import's own specifier text for banned package names.
import { admin } from "../../../outside/admin.ts";

export async function voidPlay(playId: string) {
  return admin.from("play").update({ status: "void" }).eq("id", playId);
}
