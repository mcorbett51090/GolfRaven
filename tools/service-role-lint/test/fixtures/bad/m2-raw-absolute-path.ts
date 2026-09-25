// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a bare absolute filesystem
// path, reaching outside supabase/functions with no scheme at all.
import { adminUpdate } from "/tmp/outside/admin.ts";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
