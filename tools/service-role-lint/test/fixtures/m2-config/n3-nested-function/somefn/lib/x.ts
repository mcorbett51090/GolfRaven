// MUST-FAIL (M2 BLOCKING, post-P3a re-gate, case n3): imports "admin"
// from TWO directory levels below the functions root -- the per-function
// somefn/deno.json (one level up from this file) must still be found by
// walking UP, not just checking this file's own directory merged with
// the functions root.
import { adminUpdate } from "admin";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
