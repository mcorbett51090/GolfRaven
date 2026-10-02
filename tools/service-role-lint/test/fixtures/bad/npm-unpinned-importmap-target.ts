// MUST-FAIL (esm.sh stub -> `npm:` migration follow-up): a bare specifier
// that resolves, through the reviewed import map, to an `npm:` target
// that is NOT an exact version pin (`npm:zod`, `npm:zod@^4`, `npm:zod@4`,
// `npm:zod@latest`, ...). The source itself looks identical to the clean
// control (good/legit-remote-import.ts) -- only the import-map TARGET
// differs, which is why lint.test.ts drives this fixture with a map per
// unpinned shape, and with the shape ALSO listed on the pinned allow-list
// (an unpinned npm: target must fail even then). See config.test.ts for
// the same shapes at the deno.json (config-file) level.
import { z } from "zod";

export function validate(input: unknown) {
  return z.object({ id: z.string() }).parse(input);
}
