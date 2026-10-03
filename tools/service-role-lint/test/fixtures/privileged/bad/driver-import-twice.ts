// MUST-FAIL (privileged-driver-import): a second value import of the one specifier is a second binding on the driver.
import postgres from "postgres";
import postgres2 from "postgres";

export function openPool() {
  const dbUrl = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
  return postgres(dbUrl);
}
declare const Deno: { env: { get(name: string): string | undefined } };
