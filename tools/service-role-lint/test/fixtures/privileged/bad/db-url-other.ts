// MUST-FAIL (privileged-db-url): any other database URL variable (the edge pool's GOLFRAVEN_EDGE_DB_URL is the only one).
declare const Deno: { env: { get(name: string): string | undefined } };
export function second(): string | undefined {
  return Deno.env.get("DATABASE_URL") ?? Deno.env.get("POOLER_DB_URL");
}
