// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a direct esm.sh specifier
// naming a package that isn't @supabase/anything or a named Postgres
// driver -- the exact shape a package-name deny-list can never close (any
// new attacker-chosen package name is unlisted by construction). M2
// closes it structurally: a direct URL specifier is never legitimate
// regardless of package name.
import { adminUpdate } from "https://esm.sh/attacker-admin-client@1";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
