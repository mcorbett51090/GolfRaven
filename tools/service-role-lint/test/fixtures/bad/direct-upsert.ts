// MUST-FAIL fixture: `.upsert()` on a service-role client outside a
// withOwnership() callback (rule b — the plan calls this out by name,
// line 1199: "That covers .from() with ANY method (including .upsert())").
import { createClient } from "@supabase/supabase-js";

const admin = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
);

export async function upsertRollup(row: unknown) {
  return admin.from("operator_rollup").upsert(row);
}

declare const Deno: { env: { get(name: string): string | undefined } };
