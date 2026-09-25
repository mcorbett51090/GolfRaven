// MUST-FAIL (post-P3a re-gate M1, case g6): a remote import from a host
// that is not `@supabase/anything` and not a named Postgres driver by
// package name — only a HOST allow-list (not a package-name deny-list)
// catches this.
import { adminUpdate } from "https://example.com/evil/mod.ts";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
