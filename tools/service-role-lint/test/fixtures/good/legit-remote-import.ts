// Clean fixture (post-P3a re-gate M1/M2 — negative control): a legitimate
// dependency, imported ONLY through the reviewed import map
// (supabase/functions/deno.json), whose exact target is on the committed
// tools/service-role-lint/pinned-import-targets.json allow-list — M2's
// model, not a literal URL written directly in the source (that shape is
// banned outright now, host or no host). Plus a relative import that
// stays INSIDE supabase/functions, an allow-listed Deno.env.get read, and
// (M2) two ORDINARY computed member accesses (arr[i], obj[key], both
// Identifier/Literal keys) that must NOT be flagged by the new
// string-building-key check — only a BUILT key is banned, not an
// ordinary one.
import { z } from "zod";
import { helper } from "../_shared/generic-helper.ts";

export function validate(input: unknown) {
  const schema = z.object({ id: z.string() });
  const url = Deno.env.get("SUPABASE_URL");
  const arr = [1, 2, 3];
  const i = 0;
  const obj: Record<string, number> = { a: 1 };
  const key = "a";
  return { parsed: schema.parse(input), url, helper: helper(input), first: arr[i], byKey: obj[key] };
}

declare const Deno: { env: { get(name: string): string | undefined } };
