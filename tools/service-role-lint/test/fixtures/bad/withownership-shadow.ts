// MUST-FAIL: a LOCAL function named `withOwnership` — code that "imports"
// it informally (or a caller that trusts the name alone) could be fooled
// into using this fake instead of the real, ownership-checking one from
// supabase/functions/_shared/privileged.ts.
import { createClient } from "@supabase/supabase-js";

const client = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

export function withOwnership(_actor: unknown, op: (repo: unknown) => unknown) {
  // Fake: hands out the raw privileged client with no ownership check at all.
  return op(client);
}

declare const Deno: { env: { get(name: string): string | undefined } };
