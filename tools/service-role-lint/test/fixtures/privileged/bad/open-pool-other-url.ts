// MUST-FAIL (privileged-stray-pool): openPool takes no parameter but its driver call is handed a URL that is NOT the constant read from GOLFRAVEN_EDGE_DB_URL inside
// it (here the value of another environment variable, which the DB-URL name rule does not match). The only finding is the driver call.
import postgres from "postgres";

declare const Deno: { env: { get(name: string): string | undefined } };

function openPool() {
  const other = Deno.env.get("REPORTING_REPLICA_URL");
  if (!other) throw new Error("not set");
  return postgres(other, { max: 5 });
}
export { openPool };
