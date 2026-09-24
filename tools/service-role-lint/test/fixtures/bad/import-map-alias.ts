// MUST-FAIL (MEDIUM 3 re-gate, bypass 10): an import-map alias — this
// file imports from the bare specifier "supabase", which is NOT itself a
// banned name; only a deno.json/import_map.json entry resolves it to the
// real "@supabase/supabase-js" package. A specifier check that only looks
// at the literal string written in the `import ... from "..."` line, with
// no import-map resolution, sees nothing wrong here. See
// index.test.ts's "import-map alias resolution (MEDIUM 3)" suite for the
// end-to-end version of this fixture (with a real, adjacent deno.json).
import { createClient } from "supabase";

const client = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

export async function voidPlay(playId: string) {
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
