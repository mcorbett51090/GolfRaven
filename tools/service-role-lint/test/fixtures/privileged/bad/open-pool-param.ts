// MUST-FAIL (privileged-stray-pool): an openPool DECLARATION with a parameter (the old shape was `openPool(dbUrl: string)`). The body here still feeds the driver
// the constant read from GOLFRAVEN_EDGE_DB_URL, so the parameter is the only finding (a mutation of the declaration rule alone is therefore visible).
import postgres from "postgres";

declare const Deno: { env: { get(name: string): string | undefined } };

function openPool(overrideUrl?: string) {
  const dbUrl = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
  if (!dbUrl) throw new Error("not set");
  return postgres(dbUrl, { max: 5 });
}
export { openPool };
