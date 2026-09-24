// MUST-FAIL fixture: `.rpc()` on a service-role client outside a
// withOwnership() callback (rule b).
import { createClient } from "@supabase/supabase-js";

const svc = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
);

export async function runDelete(userId: string) {
  return svc.rpc("delete_my_data", { p_user_id: userId });
}

declare const Deno: { env: { get(name: string): string | undefined } };
