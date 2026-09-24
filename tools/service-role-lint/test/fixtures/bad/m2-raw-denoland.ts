// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a direct deno.land/x/
// specifier for an unreviewed, attacker-named module -- deno.land was on
// the OLD host allow-list, so a package-name-only check never looked at
// it either. M2: every direct URL specifier is banned, full stop.
import { adminUpdate } from "https://deno.land/x/attacker_admin@v1/mod.ts";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
