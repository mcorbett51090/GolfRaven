// Clean fixture (post-P3a re-gate M1 — negative control): a legitimate
// remote import from an ALLOW-LISTED host, naming a package that is
// neither "@supabase/anything" nor a Postgres driver, plus a relative
// import that stays INSIDE supabase/functions, plus an allow-listed
// Deno.env.get read. None of the M1 rules should ever flag ordinary code
// shaped like this.
import { z } from "https://esm.sh/zod@3.23.8";
import { helper } from "../_shared/generic-helper.ts";

export function validate(input: unknown) {
  const schema = z.object({ id: z.string() });
  const url = Deno.env.get("SUPABASE_URL");
  return { parsed: schema.parse(input), url, helper: helper(input) };
}

declare const Deno: { env: { get(name: string): string | undefined } };
