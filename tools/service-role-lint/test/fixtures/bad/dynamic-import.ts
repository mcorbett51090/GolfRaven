// MUST-FAIL: a dynamic import() of the banned specifier — never appears
// as a static `import ... from "@supabase/supabase-js"` line at all.
export async function voidPlay(playId: string) {
  const { createClient } = await import("@supabase/supabase-js");
  const client = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
  return client.from("play").update({ status: "void" }).eq("id", playId);
}

declare const Deno: { env: { get(name: string): string | undefined } };
