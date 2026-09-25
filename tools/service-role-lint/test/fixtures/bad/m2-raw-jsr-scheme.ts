// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a direct jsr: scheme
// specifier outside any reviewed import map.
import { adminUpdate } from "jsr:@attacker/admin";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
