// MUST-FAIL fixture: a Storage `.upload()` call on a service-role client
// outside a withOwnership() callback (rule b: "storage.from().upload/
// remove/... outside a withOwnership callback").
import { createClient } from "@supabase/supabase-js";

const admin = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
);

export async function saveReceipt(userId: string, bytes: Uint8Array) {
  return admin.storage
    .from("receipts")
    .upload(`receipts/${userId}/x.jpg`, bytes);
}

declare const Deno: { env: { get(name: string): string | undefined } };
