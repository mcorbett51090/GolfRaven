// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a direct npm: scheme
// specifier outside any reviewed import map.
import { adminUpdate } from "npm:attacker-admin-client@1";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
