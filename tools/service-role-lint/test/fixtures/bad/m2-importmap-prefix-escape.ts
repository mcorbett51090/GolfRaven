// MUST-FAIL (M2 BLOCKING, post-P3a re-gate): a bare specifier that would
// have resolved through a PREFIX import-map entry (e.g.
// `"lib/": "../../../outside/"`) under the OLD prefix/scope-resolution
// model -- M2 drops prefix resolution entirely (exact-key-only), so
// "lib/admin.ts" resolves to nothing (there is no EXACT key
// "lib/admin.ts" in the map, only the prefix key "lib/") and is banned as
// "not an exact key", never reaching the escaped path at all. Exercised
// at the unit level in lint.test.ts with an explicit importMap; this file
// documents the shape for the directory-walk/index.test.ts path too (no
// real deno.json in this fixture tree defines "lib/", so under a real
// lintDirectory run it already fails as an unmapped bare specifier).
import { admin } from "lib/admin.ts";

export async function voidPlay(playId: string) {
  return admin.from("play").update({ status: "void" }).eq("id", playId);
}
