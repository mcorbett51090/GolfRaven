// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a direct file: URL reaching
// outside supabase/functions entirely.
import { adminUpdate } from "file:///tmp/outside/admin.ts";

export async function voidPlay(playId: string) {
  return adminUpdate(playId);
}
