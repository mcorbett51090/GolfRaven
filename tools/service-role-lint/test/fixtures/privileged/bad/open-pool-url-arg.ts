// MUST-FAIL (privileged-stray-pool): openPool(anyUrl). openPool takes NO argument and reads GOLFRAVEN_EDGE_DB_URL itself, so a call that hands it a URL
// (from another function, another variable, another environment variable) is a pool on a database of the caller's choosing. The declaration here is the
// CORRECT one, so the call is the only finding (a mutation of the call-site rule alone is therefore visible).
import postgres from "postgres";

declare const Deno: { env: { get(name: string): string | undefined } };

function openPool() {
  const dbUrl = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
  if (!dbUrl) throw new Error("not set");
  return postgres(dbUrl, { max: 5 });
}
export function elsewhere(anyUrl: string) {
  return openPool(anyUrl as never);
}
