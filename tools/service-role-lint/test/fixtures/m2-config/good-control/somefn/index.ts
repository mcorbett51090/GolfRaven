// Clean fixture (M2, post-P3a re-gate): a per-function deno.json whose
// ONLY import-map target is on the committed pinned-import-targets.json
// allow-list. Nothing here should ever be flagged.
import { z } from "zod";

export function validate(input: unknown) {
  return z.object({ id: z.string() }).parse(input);
}
