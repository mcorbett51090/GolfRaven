// MUST-FAIL fixture: a Postgres driver import AND a reference to the
// database-URL environment variable outside privileged.ts (rule c).
import postgres from "postgres";

const sql = postgres(Deno.env.get("SUPABASE_DB_URL") ?? "");

export async function rawDelete(userId: string) {
  return sql`DELETE FROM app.evidence WHERE user_id = ${userId}`;
}

declare const Deno: { env: { get(name: string): string | undefined } };
